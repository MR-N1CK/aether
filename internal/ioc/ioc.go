package ioc

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"aether/internal/config"
	"aether/internal/report"
)

// IOCType indicates the category of indicator of compromise.
type IOCType string

const (
	TypeMD5       IOCType = "MD5"
	TypeSHA1      IOCType = "SHA1"
	TypeSHA256    IOCType = "SHA256"
	TypeFilePath  IOCType = "FILE_PATH"
	TypeIPAddress IOCType = "IP_ADDRESS"
	TypeDomain    IOCType = "DOMAIN"
)

// MatchResult represents an indicator hit against a file.
type MatchResult struct {
	RuleName    string
	Reason      string
	Score       int
	Severity    report.Severity
	IsHashMatch bool
}

// Engine defines the lookup and match contract for IOC indicators.
type Engine interface {
	LoadDirectory(dir string) error
	LoadBuiltin() error
	LoadAllowlist(path string) error
	CheckHash(hashVal string) *MatchResult
	CheckPath(path string) *MatchResult
	IsAllowlisted(sha256Hash string) (bool, string)
	IsKnownBenign(path string, ownerUID uint32) (bool, string)
	HashRuleCount() int
	PatternRuleCount() int
	BenignRuleCount() int
}

// RealEngine implements high-performance O(1) hash matching and compiled regex path matching.
type RealEngine struct {
	mu           sync.RWMutex
	hashRules    map[string]HashRule // lowercase hash -> rule
	patternRules []PatternRule
	benignRules  []BenignRule
	allowlist    *Allowlist
	logger       *slog.Logger
}

// NewEngine initializes an IOC engine and loads built-in demo rules, discovered IOC dirs,
// and configured allowlists.
func NewEngine(cfg *config.Config, logger *slog.Logger) (*RealEngine, error) {
	if logger == nil {
		logger = slog.Default()
	}

	eng := &RealEngine{
		hashRules:    make(map[string]HashRule),
		patternRules: make([]PatternRule, 0),
		benignRules:  make([]BenignRule, 0),
		allowlist:    NewAllowlist(),
		logger:       logger,
	}

	// 1. Load built-in benign demo rules and suppression rules
	if err := eng.LoadBuiltin(); err != nil {
		logger.Warn("failed to load built-in demo IOCs", slog.Any("error", err))
	}

	// 2. Discover and load IOCs from standard directories
	for _, dir := range config.DefaultIOCDirs() {
		if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
			if err := eng.LoadDirectory(dir); err != nil {
				logger.Warn("error loading standard IOC dir", slog.String("dir", dir), slog.Any("error", err))
			}
		}
	}

	// 3. Load known_benign.yaml from standard configuration paths if present
	for _, p := range []string{
		"configs/known_benign.yaml",
		filepath.Join(os.Getenv("HOME"), ".config", config.ToolName, "known_benign.yaml"),
		filepath.Join("/etc", config.ToolName, "known_benign.yaml"),
	} {
		if data, err := os.ReadFile(p); err == nil {
			if bRules, bErr := ParseBenignFile(data, p, logger); bErr == nil {
				eng.mu.Lock()
				eng.benignRules = append(eng.benignRules, bRules...)
				eng.mu.Unlock()
				logger.Debug("loaded known benign patterns", slog.String("file", p), slog.Int("count", len(bRules)))
			}
		}
	}

	// 4. Load custom IOC directory if specified
	if cfg != nil && cfg.Scan.IOCDir != "" {
		if err := eng.LoadDirectory(cfg.Scan.IOCDir); err != nil {
			return nil, fmt.Errorf("failed to load custom IOC directory %q: %w", cfg.Scan.IOCDir, err)
		}
	}

	// 5. Load allowlist if configured
	if cfg != nil && cfg.Scan.AllowlistPath != "" {
		if err := eng.LoadAllowlist(cfg.Scan.AllowlistPath); err != nil {
			return nil, fmt.Errorf("failed to load allowlist %q: %w", cfg.Scan.AllowlistPath, err)
		}
	}

	return eng, nil
}

// LoadBuiltin parses embedded benign rules.
func (e *RealEngine) LoadBuiltin() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	hashRules, err := ParseHashFile(strings.NewReader(builtinDemoHashes), "builtin_hashes.txt")
	if err != nil {
		return err
	}
	for _, hr := range hashRules {
		e.hashRules[hr.Hash] = hr
	}

	patRules, err := ParsePatternFile([]byte(builtinDemoPatterns), "builtin_patterns.yaml", e.logger)
	if err != nil {
		return err
	}
	e.patternRules = append(e.patternRules, patRules...)

	benignRules, err := ParseBenignFile([]byte(builtinKnownBenignPatterns), "builtin_known_benign.yaml", e.logger)
	if err != nil {
		return err
	}
	e.benignRules = append(e.benignRules, benignRules...)
	return nil
}

// LoadDirectory walks a directory and compiles all .txt/.hashes/.yaml IOC files.
func (e *RealEngine) LoadDirectory(dir string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}

		base := strings.ToLower(filepath.Base(path))
		ext := strings.ToLower(filepath.Ext(path))

		// Check for known_benign.yaml / known_benign.yml
		if (ext == ".yaml" || ext == ".yml") && strings.Contains(base, "known_benign") {
			data, err := os.ReadFile(path)
			if err != nil {
				e.logger.Warn("cannot read known_benign file", slog.String("path", path), slog.Any("error", err))
				return nil
			}
			bRules, err := ParseBenignFile(data, filepath.Base(path), e.logger)
			if err != nil {
				e.logger.Warn("error parsing known_benign file", slog.String("path", path), slog.Any("error", err))
				return nil
			}
			e.benignRules = append(e.benignRules, bRules...)
			e.logger.Debug("loaded known benign patterns", slog.String("file", path), slog.Int("count", len(bRules)))
			return nil
		}

		switch ext {
		case ".txt", ".hashes", ".ioc":
			f, err := os.Open(path)
			if err != nil {
				e.logger.Warn("cannot read hash IOC file", slog.String("path", path), slog.Any("error", err))
				return nil
			}
			defer f.Close()

			rules, err := ParseHashFile(f, filepath.Base(path))
			if err != nil {
				e.logger.Warn("error parsing hash file", slog.String("path", path), slog.Any("error", err))
				return nil
			}
			for _, r := range rules {
				e.hashRules[r.Hash] = r
			}
			e.logger.Debug("loaded hash IOCs", slog.String("file", path), slog.Int("count", len(rules)))

		case ".yaml", ".yml":
			data, err := os.ReadFile(path)
			if err != nil {
				e.logger.Warn("cannot read pattern IOC file", slog.String("path", path), slog.Any("error", err))
				return nil
			}

			rules, err := ParsePatternFile(data, filepath.Base(path), e.logger)
			if err != nil {
				e.logger.Warn("error parsing pattern file", slog.String("path", path), slog.Any("error", err))
				return nil
			}
			e.patternRules = append(e.patternRules, rules...)
			e.logger.Debug("loaded path IOCs", slog.String("file", path), slog.Int("count", len(rules)))
		}

		return nil
	})
}

// LoadAllowlist loads a known-good SHA256 allowlist file.
func (e *RealEngine) LoadAllowlist(path string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.allowlist.LoadFile(path)
}

// CheckHash evaluates a single hash (MD5, SHA1, or SHA256) in O(1) time.
func (e *RealEngine) CheckHash(hashVal string) *MatchResult {
	if hashVal == "" {
		return nil
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	key := strings.ToLower(strings.TrimSpace(hashVal))
	if rule, found := e.hashRules[key]; found {
		return &MatchResult{
			RuleName:    rule.ThreatName,
			Reason:      fmt.Sprintf("Matched %s hash indicator: %s (%s)", rule.Type, rule.Hash, rule.Description),
			Score:       rule.Score,
			Severity:    rule.Severity,
			IsHashMatch: true,
		}
	}
	return nil
}

// CheckPath evaluates path and filename against compiled regex rules.
func (e *RealEngine) CheckPath(path string) *MatchResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.patternRules {
		if rule.Regex.MatchString(path) {
			return &MatchResult{
				RuleName:    rule.RuleName,
				Reason:      fmt.Sprintf("Matched path pattern %q: %s", rule.Pattern, rule.Reason),
				Score:       rule.Score,
				Severity:    rule.Severity,
				IsHashMatch: false,
			}
		}
	}
	return nil
}

// IsAllowlisted checks if the SHA256 hash is in the known-good allowlist.
func (e *RealEngine) IsAllowlisted(sha256Hash string) (bool, string) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.allowlist.Contains(sha256Hash)
}

// IsKnownBenign checks if the path matches known-benign patterns (e.g. tool caches).
// If the matching rule specifies OwnerMatchesNameUID, the UID is extracted from a
// regex capture group and verified against ownerUID.
func (e *RealEngine) IsKnownBenign(path string, ownerUID uint32) (bool, string) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.benignRules {
		matches := rule.Regex.FindStringSubmatch(path)
		if len(matches) == 0 {
			matches = rule.Regex.FindStringSubmatch(filepath.Base(path))
			if len(matches) == 0 {
				continue
			}
		}

		if rule.OwnerMatchesNameUID {
			if len(matches) < 2 {
				// Regex requires owner UID match but did not have a capture group
				continue
			}
			parsedUID, err := strconv.ParseUint(matches[1], 10, 32)
			if err != nil || uint32(parsedUID) != ownerUID {
				// UID in filename does not match the actual file owner UID!
				continue
			}
		}

		return true, rule.Reason
	}
	return false, ""
}

// HashRuleCount returns total registered hash signatures.
func (e *RealEngine) HashRuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.hashRules)
}

// PatternRuleCount returns total registered regex path rules.
func (e *RealEngine) PatternRuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.patternRules)
}

// BenignRuleCount returns total registered known-benign suppression rules.
func (e *RealEngine) BenignRuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.benignRules)
}

// StubEngine fallback for minimal testing.
type StubEngine struct{}

func NewStubEngine() Engine { return &StubEngine{} }
func (s *StubEngine) LoadDirectory(dir string) error { return nil }
func (s *StubEngine) LoadBuiltin() error { return nil }
func (s *StubEngine) LoadAllowlist(path string) error { return nil }
func (s *StubEngine) CheckHash(hashVal string) *MatchResult { return nil }
func (s *StubEngine) CheckPath(path string) *MatchResult { return nil }
func (s *StubEngine) IsAllowlisted(sha256Hash string) (bool, string) { return false, "" }
func (s *StubEngine) IsKnownBenign(path string, ownerUID uint32) (bool, string) { return false, "" }
func (s *StubEngine) HashRuleCount() int { return 0 }
func (s *StubEngine) PatternRuleCount() int { return 0 }
func (s *StubEngine) BenignRuleCount() int { return 0 }

