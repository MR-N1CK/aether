//go:build yara

package yara

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	yrx "github.com/VirusTotal/yara-x/go"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/safeopen"
)

var defaultGlobals = map[string]any{
	"filename":  "",
	"filepath":  "",
	"extension": "",
	"filetype":  "",
	"owner":     "",
}

// YaraXEngine implements the Engine interface using official YARA-X CGO bindings.
type YaraXEngine struct {
	cfg           *config.Config
	logger        *slog.Logger
	devRpath      bool
	rules         *yrx.Rules
	rulesLoaded   int
	rulesFailed   int
	failedFiles   []string
	demoRulesOnly bool
	notRunReason  string

	filesScanned    atomic.Int64
	ruleFilesSeen   atomic.Int64
	skippedOversize atomic.Int64
	skippedTimeout  atomic.Int64
	skippedError    atomic.Int64

	mu sync.RWMutex
}

// NewYaraXEngine creates a new YaraXEngine instance.
func NewYaraXEngine(cfg *config.Config, logger *slog.Logger, devRpath bool) *YaraXEngine {
	return &YaraXEngine{
		cfg:      cfg,
		logger:   logger,
		devRpath: devRpath,
	}
}

// LoadRules compiles and caches YARA rule files from disk or embedded defaults.
func (e *YaraXEngine) LoadRules(rulePaths []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// 0. Library trust verification for root execution
	mapsBytes, _ := os.ReadFile("/proc/self/maps")
	trusted, trustReason := EvaluateLibraryTrust(
		uint32(os.Geteuid()),
		e.devRpath,
		"/proc/self/exe",
		DefaultElfParser,
		string(mapsBytes),
		os.Getenv,
		os.Stat,
		filepath.EvalSymlinks,
	)
	if !trusted {
		e.notRunReason = "library path not trusted"
		if e.logger != nil {
			e.logger.Warn("refusing to run YARA: library path not trusted", slog.String("reason", trustReason))
		}
		return nil
	}

	mainCompiler, err := yrx.NewCompiler(yrx.Globals(defaultGlobals))
	if err != nil {
		return fmt.Errorf("failed to create YARA-X compiler: %w", err)
	}
	defer mainCompiler.Destroy()

	validCount := 0

	// 1. Process provided rule paths
	for _, path := range rulePaths {
		content, err := safeopen.ReadFileReadOnly(path, 10*1024*1024)
		if err != nil {
			msg := fmt.Sprintf("failed to read rule file %s: %v", path, err)
			if e.logger != nil {
				e.logger.Warn(msg)
			}
			e.rulesFailed++
			e.failedFiles = append(e.failedFiles, path)
			continue
		}

		// Validate with an isolated throwaway compiler
		tCompiler, err := yrx.NewCompiler(yrx.Globals(defaultGlobals))
		if err != nil {
			msg := fmt.Sprintf("failed to create validator compiler for %s: %v", path, err)
			if e.logger != nil {
				e.logger.Warn(msg)
			}
			e.rulesFailed++
			e.failedFiles = append(e.failedFiles, path)
			continue
		}

		vErr := tCompiler.AddSource(string(content), yrx.WithOrigin(path))
		tCompiler.Destroy()

		if vErr != nil {
			errMsg := fmt.Sprintf("failed to compile rule file %s: %v", path, vErr)
			if strings.Contains(strings.ToLower(vErr.Error()), "unsupported module") || strings.Contains(strings.ToLower(vErr.Error()), "import") {
				errMsg = fmt.Sprintf("rule file %s uses unsupported module or import: %v", path, vErr)
			}
			if e.logger != nil {
				e.logger.Warn(errMsg)
			}
			e.rulesFailed++
			e.failedFiles = append(e.failedFiles, path)
			continue
		}

		// Compile into main compiler in its own namespace
		ns := GetRuleNamespace(path)
		mainCompiler.NewNamespace(ns)
		if err := mainCompiler.AddSource(string(content), yrx.WithOrigin(path)); err != nil {
			if e.logger != nil {
				e.logger.Warn("failed to add verified rule to main compiler", slog.String("file", path), slog.Any("error", err))
			}
			e.rulesFailed++
			e.failedFiles = append(e.failedFiles, path)
			continue
		}
		validCount++
	}

	loadDemo := e.cfg != nil && e.cfg.Scan.DemoRules

	// 2. Handle failure and demo rules scenarios
	if validCount == 0 && len(rulePaths) > 0 {
		e.notRunReason = fmt.Sprintf("%d rule files failed to compile", e.rulesFailed)
		if e.logger != nil {
			e.logger.Warn("YARA rule compilation failed for all provided files", slog.Int("failed_files", e.rulesFailed))
		}
		return nil
	} else if loadDemo && validCount == 0 && len(rulePaths) == 0 {
		mainCompiler.NewNamespace("demo_eicar")
		_ = mainCompiler.AddSource(DemoRuleEICAR, yrx.WithOrigin("embedded:demo_eicar.yar"))
		mainCompiler.NewNamespace("demo_marker")
		_ = mainCompiler.AddSource(DemoRuleMarker, yrx.WithOrigin("embedded:demo_marker.yar"))
		e.demoRulesOnly = true
		e.notRunReason = ""
	} else if validCount == 0 && len(rulePaths) == 0 {
		// Load embedded core Linux threat rules when no external rules provided
		mainCompiler.NewNamespace("embedded_core_linux")
		_ = mainCompiler.AddSource(EmbeddedCoreLinuxRules, yrx.WithOrigin("embedded:core_linux_rules.yar"))
		if loadDemo {
			mainCompiler.NewNamespace("demo_eicar")
			_ = mainCompiler.AddSource(DemoRuleEICAR, yrx.WithOrigin("embedded:demo_eicar.yar"))
			mainCompiler.NewNamespace("demo_marker")
			_ = mainCompiler.AddSource(DemoRuleMarker, yrx.WithOrigin("embedded:demo_marker.yar"))
		}
		e.demoRulesOnly = false
		e.notRunReason = ""
	} else {
		if loadDemo {
			mainCompiler.NewNamespace("demo_eicar")
			_ = mainCompiler.AddSource(DemoRuleEICAR, yrx.WithOrigin("embedded:demo_eicar.yar"))
			mainCompiler.NewNamespace("demo_marker")
			_ = mainCompiler.AddSource(DemoRuleMarker, yrx.WithOrigin("embedded:demo_marker.yar"))
		}
		e.demoRulesOnly = false
		e.notRunReason = ""
	}

	e.rules = mainCompiler.Build()
	if e.rules != nil {
		e.rulesLoaded = e.rules.Count()
	}

	if e.logger != nil {
		e.logger.Info("YARA-X rules loaded",
			slog.Int("loaded_rules", e.rulesLoaded),
			slog.Int("failed_files", e.rulesFailed),
			slog.Bool("demo_only", e.demoRulesOnly),
		)
	}

	return nil
}

// NewScanner creates a goroutine-isolated worker scanner.
func (e *YaraXEngine) NewScanner() Scanner {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.rules == nil || e.rulesLoaded == 0 {
		return &noopScanner{}
	}

	yrxScanner := yrx.NewScanner(e.rules)
	if e.cfg != nil {
		if e.cfg.Scan.FileTimeout > 0 {
			yrxScanner.SetTimeout(e.cfg.Scan.FileTimeout)
		} else if e.cfg.Scan.YaraTimeoutMs > 0 {
			yrxScanner.SetTimeout(time.Duration(e.cfg.Scan.YaraTimeoutMs) * time.Millisecond)
		}
	}

	return &yaraxWorkerScanner{
		engine:  e,
		scanner: yrxScanner,
	}
}

// RecordSkipOversize records a file skipped due to exceeding max filesize.
func (e *YaraXEngine) RecordSkipOversize() {
	e.skippedOversize.Add(1)
}

// RecordRuleFileSeen records a discovered YARA rule file.
func (e *YaraXEngine) RecordRuleFileSeen() {
	e.ruleFilesSeen.Add(1)
}

// Coverage returns detailed rule and scan metrics.
func (e *YaraXEngine) Coverage() events.YARACoverageStats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return events.YARACoverageStats{
		CompiledIn:      true,
		Version:         "1.21.0",
		RulesLoaded:     e.rulesLoaded,
		RulesFailed:     e.rulesFailed,
		FailedFiles:     e.failedFiles,
		FilesScanned:    e.filesScanned.Load(),
		RuleFilesSeen:   e.ruleFilesSeen.Load(),
		SkippedOversize: e.skippedOversize.Load(),
		SkippedTimeout:  e.skippedTimeout.Load(),
		SkippedError:    e.skippedError.Load(),
		DemoRulesOnly:   e.demoRulesOnly,
		NotRunReason:    e.notRunReason,
	}
}

// Enabled returns true if rules were successfully loaded and no trust failure occurred.
func (e *YaraXEngine) Enabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rulesLoaded > 0 && e.notRunReason == ""
}

// Close releases compiled rule resources.
func (e *YaraXEngine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.rules != nil {
		e.rules.Destroy()
		e.rules = nil
	}
	return nil
}

type yaraxWorkerScanner struct {
	engine  *YaraXEngine
	scanner *yrx.Scanner
}

func (s *yaraxWorkerScanner) Scan(target ScanTarget) ([]RuleMatch, error) {
	if s.scanner == nil {
		return nil, nil
	}

	// Set external globals for this target
	_ = s.scanner.SetGlobal("filename", target.Filename)
	_ = s.scanner.SetGlobal("filepath", target.Path)
	_ = s.scanner.SetGlobal("extension", target.Extension)
	_ = s.scanner.SetGlobal("filetype", target.FileType)
	_ = s.scanner.SetGlobal("owner", target.Owner)

	res, err := s.scanner.Scan(target.Data)
	if err != nil {
		if errors.Is(err, yrx.ErrTimeout) {
			s.engine.skippedTimeout.Add(1)
			return nil, err
		}
		s.engine.skippedError.Add(1)
		return nil, err
	}

	s.engine.filesScanned.Add(1)
	if res == nil {
		return nil, nil
	}

	matchingRules := res.MatchingRules()
	if len(matchingRules) == 0 {
		return nil, nil
	}

	cfg := s.engine.cfg
	var matches []RuleMatch

	for _, r := range matchingRules {
		rID := r.Identifier()
		tags := r.Tags()

		// Check disabled rules
		if cfg != nil && isStringInSlice(rID, cfg.Scan.DisabledRules) {
			continue
		}
		// Check disabled tags
		if cfg != nil && hasAnyStringInSlice(tags, cfg.Scan.DisabledTags) {
			continue
		}

		// Parse metadata
		metaMap := make(map[string]interface{})
		for _, m := range r.Metadata() {
			metaMap[m.Identifier()] = m.Value()
		}

		warningScore := config.DefaultScoreYaraWarning
		strongScore := config.DefaultScoreYaraStrong
		alertScore := config.DefaultScoreYaraAlert
		if cfg != nil {
			if cfg.Scan.YaraWarningScore > 0 {
				warningScore = cfg.Scan.YaraWarningScore
			}
			if cfg.Scan.YaraStrongScore > 0 {
				strongScore = cfg.Scan.YaraStrongScore
			}
			if cfg.Scan.YaraAlertScore > 0 {
				alertScore = cfg.Scan.YaraAlertScore
			}
		}

		score, sev, isStrong, conf := ScoreFromMeta(metaMap, 50, warningScore, strongScore, alertScore)

		// Collect matched string identifiers (capped at 20, never content or offsets)
		var matchedStrings []string
		for _, p := range r.Patterns() {
			if len(p.Matches()) > 0 {
				matchedStrings = append(matchedStrings, p.Identifier())
				if len(matchedStrings) >= 20 {
					break
				}
			}
		}

		matches = append(matches, RuleMatch{
			RuleName:       rID,
			Namespace:      r.Namespace(),
			Tags:           tags,
			MatchedStrings: matchedStrings,
			Score:          score,
			Severity:       sev,
			IsStrong:       isStrong,
			Confidence:     conf,
			Metadata:       metaMap,
		})
	}

	return matches, nil
}

func (s *yaraxWorkerScanner) Destroy() {
	if s.scanner != nil {
		s.scanner.Destroy()
		s.scanner = nil
	}
}

func isStringInSlice(val string, list []string) bool {
	for _, item := range list {
		if strings.EqualFold(item, val) {
			return true
		}
	}
	return false
}

func hasAnyStringInSlice(items []string, list []string) bool {
	for _, item := range items {
		if isStringInSlice(item, list) {
			return true
		}
	}
	return false
}

// YaraXVersionInfo returns detailed version info for the version command.
func YaraXVersionInfo() string {
	return "YARA-X v1.21.0 (static)"
}

// YaraXValidateRulesDir compiles all *.yar and *.yara files in dir and returns validation results.
func YaraXValidateRulesDir(dir string) (*ValidationResult, error) {
	cleanDir := filepath.Clean(dir)
	fi, err := os.Stat(cleanDir)
	if err != nil {
		return nil, fmt.Errorf("cannot access rules directory %s: %w", cleanDir, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", cleanDir)
	}

	var ruleFiles []string
	err = filepath.WalkDir(cleanDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yar" || ext == ".yara" {
			ruleFiles = append(ruleFiles, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed walking rules directory %s: %w", cleanDir, err)
	}
	sort.Strings(ruleFiles)

	res := &ValidationResult{
		TotalFilesFound: len(ruleFiles),
	}

	if len(ruleFiles) == 0 {
		return res, nil
	}

	mainCompiler, err := yrx.NewCompiler(yrx.Globals(defaultGlobals))
	if err != nil {
		return nil, fmt.Errorf("failed to create YARA-X compiler: %w", err)
	}
	defer mainCompiler.Destroy()

	for _, path := range ruleFiles {
		content, err := safeopen.ReadFileReadOnly(path, 10*1024*1024)
		if err != nil {
			res.FilesFailed++
			res.Failures = append(res.Failures, RuleFailure{
				Path:  path,
				Error: fmt.Sprintf("cannot read file: %v", err),
			})
			continue
		}

		// Validate with isolated compiler
		tCompiler, err := yrx.NewCompiler(yrx.Globals(defaultGlobals))
		if err != nil {
			res.FilesFailed++
			res.Failures = append(res.Failures, RuleFailure{
				Path:  path,
				Error: fmt.Sprintf("cannot create validator compiler: %v", err),
			})
			continue
		}

		vErr := tCompiler.AddSource(string(content), yrx.WithOrigin(path))
		tCompiler.Destroy()

		if vErr != nil {
			res.FilesFailed++
			res.Failures = append(res.Failures, RuleFailure{
				Path:  path,
				Error: vErr.Error(),
			})
			continue
		}

		ns := GetRuleNamespace(path)
		mainCompiler.NewNamespace(ns)
		if err := mainCompiler.AddSource(string(content), yrx.WithOrigin(path)); err != nil {
			res.FilesFailed++
			res.Failures = append(res.Failures, RuleFailure{
				Path:  path,
				Error: err.Error(),
			})
			continue
		}

		res.FilesCompiled++
		sCount, sevCount, alertCount, defCount := parseRuleMetadataStats(string(content))
		res.RulesWithExplicitScore += sCount
		res.RulesWithExplicitSev += sevCount
		res.RulesWithAlertOrCritical += alertCount
		res.RulesWithDefaultMetadata += defCount
	}

	if res.FilesCompiled > 0 {
		rules := mainCompiler.Build()
		if rules != nil {
			res.TotalRulesLoaded = rules.Count()
			rules.Destroy()
		}
	}

	return res, nil
}

func parseRuleMetadataStats(content string) (scores, sevs, alerts, defaults int) {
	ruleBlocks := strings.Split(content, "\nrule ")
	for i, block := range ruleBlocks {
		if i == 0 && !strings.HasPrefix(strings.TrimSpace(block), "rule ") {
			continue
		}
		metaIdx := strings.Index(block, "meta:")
		if metaIdx == -1 {
			defaults++
			continue
		}
		metaSection := block[metaIdx:]
		if endIdx := strings.Index(metaSection, "strings:"); endIdx != -1 {
			metaSection = metaSection[:endIdx]
		} else if endIdx := strings.Index(metaSection, "condition:"); endIdx != -1 {
			metaSection = metaSection[:endIdx]
		} else if endIdx := strings.Index(metaSection, "}"); endIdx != -1 {
			metaSection = metaSection[:endIdx]
		}

		hasScore := false
		hasSev := false
		isAlert := false

		for _, line := range strings.Split(metaSection, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "score") && strings.Contains(trimmed, "=") {
				hasScore = true
				parts := strings.SplitN(trimmed, "=", 2)
				if len(parts) == 2 {
					valStr := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
					if n, err := strconv.Atoi(valStr); err == nil && n >= 90 {
						isAlert = true
					}
				}
			}
			if strings.HasPrefix(trimmed, "severity") && strings.Contains(trimmed, "=") {
				hasSev = true
				parts := strings.SplitN(trimmed, "=", 2)
				if len(parts) == 2 {
					valStr := strings.ToUpper(strings.Trim(strings.TrimSpace(parts[1]), `"'`))
					if valStr == "ALERT" || valStr == "CRITICAL" {
						isAlert = true
					}
				}
			}
		}

		if hasScore {
			scores++
		}
		if hasSev {
			sevs++
		}
		if isAlert {
			alerts++
		}
		if !hasScore && !hasSev {
			defaults++
		}
	}
	return
}
