package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/ioc"
	"aether/internal/modules"
	"aether/internal/modules/kernel"
	"aether/internal/modules/network"
	"aether/internal/modules/persistence"
	"aether/internal/modules/process"
	"aether/internal/modules/users"
	"aether/internal/report"
	"aether/internal/safeopen"
	"aether/internal/triage"
	"aether/internal/yara"
)

// InodeKey uniquely identifies a physical file across filesystems for hardlink deduplication.
type InodeKey struct {
	Dev uint64
	Ino uint64
}

// Scanner orchestrates the threat hunting process across filesystem targets,
// specialized inspection modules, IOC checks, and YARA rules.
type Scanner struct {
	cfg          *config.Config
	logger       *slog.Logger
	reporter     report.Reporter
	bus          *events.EventBus
	iocEngine      ioc.Engine
	yaraEngine     yara.Engine
	modules        []modules.Module
	accumulator    *findingAccumulator
	memoryBudget   *MemoryBudget
	devRpath       bool
	startupNotices []string
	version        string
	buildDate      string
	binaryName     string

	// Hardlink deduplication cache: InodeKey -> *HashStreamResult
	hashCache sync.Map
}

type findingRuleKey struct {
	path string
	rule string
}

// busReporter bridges Module.Run(..., rep) to publish FindingRaised events to the bus and record emitted findings.
type busReporter struct {
	bus          *events.EventBus
	triageEngine *triage.Engine
	count        atomic.Int64
	mu           sync.Mutex
	findings     map[findingRuleKey]string // (path, rule) -> module
	all          []report.Finding
}

func (r *busReporter) Report(f report.Finding) {
	if r.triageEngine != nil {
		r.triageEngine.Evaluate(&f, "")
	}

	r.count.Add(1)
	r.mu.Lock()
	if r.findings == nil {
		r.findings = make(map[findingRuleKey]string)
	}
	key := findingRuleKey{path: f.Path, rule: f.RuleName}
	r.findings[key] = f.Module
	r.all = append(r.all, f)
	r.mu.Unlock()

	if r.bus != nil {
		r.bus.Publish(events.FindingRaised{
			Time:    time.Now(),
			Finding: f,
		})
	}
}

func (r *busReporter) Findings() []report.Finding {
	r.mu.Lock()
	defer r.mu.Unlock()
	res := make([]report.Finding, len(r.all))
	copy(res, r.all)
	return res
}
func (r *busReporter) Summary() (int, int, int, int, int) { return 0, 0, 0, 0, 0 }
func (r *busReporter) Close() error { return nil }

type groupKey struct {
	rule     string
	severity report.Severity
	dir      string
}

type findingGroup struct {
	key        groupKey
	paths      []string
	count      int
	highestSev report.Severity
	totalScore int
	baseReason string
	sampleHash report.Finding
}

type findingAccumulator struct {
	mu       sync.Mutex
	tempDirs []string
	groups   map[groupKey]*findingGroup
	order    []groupKey
}

func getGroupDir(path string, tempDirs []string) string {
	cleaned := filepath.Clean(path)
	for _, td := range tempDirs {
		tdClean := filepath.Clean(td)
		if cleaned == tdClean {
			return tdClean
		}
		if strings.HasPrefix(cleaned, tdClean+string(filepath.Separator)) {
			rel, err := filepath.Rel(tdClean, cleaned)
			if err == nil {
				parts := strings.Split(rel, string(filepath.Separator))
				if len(parts) > 1 {
					// Top-level subtree directly under temp dir, e.g. /tmp/yara-x
					return filepath.Join(tdClean, parts[0])
				}
				return tdClean
			}
		}
	}
	return filepath.Dir(cleaned)
}

func newFindingAccumulator(cfg *config.Config) *findingAccumulator {
	var tempDirs []string
	if cfg != nil && len(cfg.Scan.TempDirs) > 0 {
		tempDirs = cfg.Scan.TempDirs
	} else {
		tempDirs = []string{"/tmp", "/var/tmp", "/dev/shm"}
	}
	return &findingAccumulator{
		tempDirs: tempDirs,
		groups:   make(map[groupKey]*findingGroup),
		order:    make([]groupKey, 0),
	}
}

func (a *findingAccumulator) Add(path, ruleName, baseReason string, sev report.Severity, score int, f report.Finding) {
	a.mu.Lock()
	defer a.mu.Unlock()

	dir := getGroupDir(path, a.tempDirs)
	key := groupKey{rule: ruleName, severity: sev, dir: dir}
	g, exists := a.groups[key]
	if !exists {
		g = &findingGroup{
			key:        key,
			paths:      []string{path},
			count:      1,
			highestSev: sev,
			totalScore: score,
			baseReason: baseReason,
			sampleHash: f,
		}
		a.groups[key] = g
		a.order = append(a.order, key)
		return
	}

	g.paths = append(g.paths, path)
	g.count++
	if score > g.totalScore {
		g.totalScore = score
	}
	if sev == report.SeverityAlert || (sev == report.SeverityWarning && g.highestSev != report.SeverityAlert) {
		g.highestSev = sev
	}
}

func (a *findingAccumulator) Flush() []report.Finding {
	a.mu.Lock()
	defer a.mu.Unlock()

	var out []report.Finding
	for _, key := range a.order {
		g := a.groups[key]
		f := g.sampleHash
		f.Timestamp = time.Now()
		f.Severity = g.highestSev
		f.Count = g.count
		f.Paths = g.paths

		if g.count == 1 {
			f.Path = g.paths[0]
			f.Reason = g.baseReason
			f.Metadata["count"] = 1
			f.Metadata["paths"] = g.paths
		} else {
			f.Path = g.key.dir
			var sampleStr string
			if len(g.paths) <= 3 {
				sampleStr = strings.Join(g.paths, ", ")
			} else {
				sampleStr = fmt.Sprintf("%s, %s, %s (and %d more)", g.paths[0], g.paths[1], g.paths[2], len(g.paths)-3)
			}
			f.Reason = fmt.Sprintf("%s [%d occurrences in %s: %s]", g.baseReason, g.count, g.key.dir, sampleStr)
			f.Metadata["count"] = g.count
			f.Metadata["paths"] = g.paths
		}
		out = append(out, f)
	}
	return out
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ScannerOption configures optional behaviors and dependency injections for Scanner.
type ScannerOption func(*Scanner)

// WithModules configures the specific inspection modules for the scan (e.g. nil for hermetic file scans).
func WithModules(mods []modules.Module) ScannerOption {
	return func(s *Scanner) {
		s.modules = mods
	}
}

// WithDevRpath specifies whether the scanner was built with dev rpaths.
func WithDevRpath(devRpath bool) ScannerOption {
	return func(s *Scanner) {
		s.devRpath = devRpath
	}
}

// WithYARAEngine overrides the YARA engine (for testing or custom compilation).
func WithYARAEngine(eng yara.Engine) ScannerOption {
	return func(s *Scanner) {
		s.yaraEngine = eng
	}
}

// WithIOCEngine overrides the IOC engine.
func WithIOCEngine(eng ioc.Engine) ScannerOption {
	return func(s *Scanner) {
		s.iocEngine = eng
	}
}

// WithStartupNotices provides explicit startup notices (e.g. for testing).
func WithStartupNotices(notices []string) ScannerOption {
	return func(s *Scanner) {
		s.startupNotices = notices
	}
}

// WithBuildInfo configures version and binary metadata for scan lifecycle events.
func WithBuildInfo(version, buildDate, binaryName string) ScannerOption {
	return func(s *Scanner) {
		s.version = version
		s.buildDate = buildDate
		s.binaryName = binaryName
	}
}

// NewScanner constructs a threat scanner ready for execution.
func NewScanner(cfg *config.Config, bus *events.EventBus, rep report.Reporter, logger *slog.Logger, opts ...ScannerOption) *Scanner {
	if logger == nil {
		logger = slog.Default()
	}
	if bus == nil {
		bus = events.NewEventBus()
	}
	if rep != nil {
		bus.AttachReporter(rep)
	}

	// Clamp YaraMaxFileSize to MemoryBudgetBytes
	if cfg.Scan.MemoryBudgetBytes <= 0 {
		cfg.Scan.MemoryBudgetBytes = config.DefaultMemoryBudget
	}
	if cfg.Scan.YaraMaxFileSize > cfg.Scan.MemoryBudgetBytes {
		cfg.Scan.YaraMaxFileSize = cfg.Scan.MemoryBudgetBytes
	}

	// Initialize IOC engine
	iocEng, err := ioc.NewEngine(cfg, logger)
	if err != nil {
		logger.Warn("could not initialize IOC engine, falling back to stub", slog.Any("error", err))
		iocEng = &ioc.RealEngine{}
	}

	procMod := process.NewModule(iocEng, bus, logger)
	persistMod := persistence.NewModule(iocEng, bus, logger)
	usersMod := users.NewModule(iocEng, bus, logger)
	netMod := network.NewModule(iocEng, bus, logger)
	kernelMod := kernel.NewModule(iocEng, bus, logger)

	isCustom := cfg.Scan.ExplicitPaths || (len(cfg.Scan.Paths) > 0 && !slicesEqual(cfg.Scan.Paths, config.DefaultScanPaths()))
	if cfg.Scan.Quick || cfg.Scan.Full {
		isCustom = false
	}

	var defaultMods []modules.Module
	if len(cfg.Scan.Modules) > 0 {
		for _, mName := range cfg.Scan.Modules {
			switch mName {
			case "process":
				defaultMods = append(defaultMods, procMod)
			case "persistence":
				defaultMods = append(defaultMods, persistMod)
			case "users":
				defaultMods = append(defaultMods, usersMod)
			case "network":
				defaultMods = append(defaultMods, netMod)
			case "kernel":
				defaultMods = append(defaultMods, kernelMod)
			}
		}
	} else if isCustom {
		// With --path (custom mode), run only the filesystem module by default.
		defaultMods = []modules.Module{}
	} else {
		defaultMods = []modules.Module{procMod, persistMod, usersMod, netMod, kernelMod}
	}

	s := &Scanner{
		cfg:          cfg,
		logger:       logger,
		reporter:     rep,
		bus:          bus,
		iocEngine:    iocEng,
		modules:      defaultMods,
		accumulator:  newFindingAccumulator(cfg),
		memoryBudget: NewMemoryBudget(cfg.Scan.MemoryBudgetBytes),
		devRpath:     false,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}

	if s.yaraEngine == nil {
		yEng := yara.New(cfg, logger, s.devRpath)
		var rulesDirs []string
		if cfg.Scan.RulesDir != "" {
			rulesDirs = append(rulesDirs, cfg.Scan.RulesDir)
		}
		rulesDirs = append(rulesDirs, config.DefaultRulesDirs()...)

		isRoot := os.Geteuid() == 0
		uid := uint32(os.Getuid())
		ruleFiles, _ := yara.DiscoverRuleFiles(rulesDirs, isRoot, uid, logger)
		if err := yEng.LoadRules(ruleFiles); err != nil {
			logger.Warn("failed loading YARA rules", slog.Any("error", err))
		}
		s.yaraEngine = yEng
	}

	return s
}

// ResolveTargets expands target paths based on scan mode (--quick, --full, custom) and safely resolves globs.
// Explicit --path restrictions take precedence over QuickScanTargets.
func (s *Scanner) ResolveTargets() []string {
	var rawTargets []string

	if s.cfg.Scan.ExplicitPaths || (len(s.cfg.Scan.Paths) > 0 && !slicesEqual(s.cfg.Scan.Paths, config.DefaultScanPaths())) {
		rawTargets = s.cfg.Scan.Paths
	} else if s.cfg.Scan.Quick {
		rawTargets = config.QuickScanTargets()
	} else if s.cfg.Scan.Full {
		rawTargets = []string{"/"}
	} else {
		rawTargets = s.cfg.Scan.Paths
	}

	var resolved []string
	seen := make(map[string]bool)

	for _, target := range rawTargets {
		// Safely expand globs (e.g. /home/*/.ssh, /etc/cron*)
		if strings.ContainsAny(target, "*?[") {
			matches, err := filepath.Glob(target)
			if err == nil {
				for _, m := range matches {
					cleaned := filepath.Clean(m)
					if !seen[cleaned] {
						seen[cleaned] = true
						resolved = append(resolved, cleaned)
					}
				}
			}
		} else {
			cleaned := filepath.Clean(target)
			if _, err := os.Stat(cleaned); err == nil && !seen[cleaned] {
				seen[cleaned] = true
				resolved = append(resolved, cleaned)
			}
		}
	}

	return resolved
}

// Run executes the hunt scan with worker pool concurrency, module execution, and coverage tracking.
func (s *Scanner) Run(ctx context.Context) error {
	startTime := time.Now()
	mode := "custom"
	if s.cfg.Scan.Quick {
		mode = "quick"
	} else if s.cfg.Scan.Full {
		mode = "full"
	}

	// Resolve targets
	scanTargets := s.ResolveTargets()
	if len(scanTargets) == 0 {
		scanTargets = s.cfg.Scan.Paths
	}

	// One filesystem isolation: default on for --full
	oneFS := s.cfg.Scan.OneFileSystem
	if s.cfg.Scan.Full {
		oneFS = true
	}

	s.logger.Info("starting threat hunting scan",
		slog.String("mode", mode),
		slog.Int("threads", s.cfg.Scan.Threads),
		slog.Int("nice", s.cfg.Scan.Nice),
		slog.Int64("max_filesize", s.cfg.Scan.MaxFileSize),
		slog.Bool("one_file_system", oneFS),
		slog.Any("paths", scanTargets),
		slog.Any("excludes", s.cfg.Scan.Excludes),
	)

	var startupNotices []string
	if len(s.startupNotices) > 0 {
		startupNotices = append(startupNotices, s.startupNotices...)
	} else if os.Geteuid() == 0 {
		exePath, _ := os.Executable()
		startupNotices = CollectRootStartupNotices(uint32(os.Geteuid()), os.Getenv("SUDO_USER"), exePath, os.Stat, filepath.EvalSymlinks)
	}

	if s.yaraEngine != nil {
		cov := s.yaraEngine.Coverage()
		if cov.NotRunReason != "" && cov.NotRunReason != "YARA not compiled in" && cov.NotRunReason != "no rules loaded" {
			startupNotices = append(startupNotices, fmt.Sprintf("YARA not run: %s", cov.NotRunReason))
		}
	}

	binName := s.binaryName
	if binName == "" {
		if exe, err := os.Executable(); err == nil {
			binName = filepath.Base(exe)
		} else {
			binName = "aether"
		}
	}
	ver := s.version
	if ver == "" {
		ver = "0.1.0-dev"
	}
	bDate := s.buildDate
	if bDate == "" {
		bDate = "unknown"
	}

	// Publish initial scan event
	s.bus.Publish(events.ScanStarted{
		Time:        startTime,
		Version:     ver,
		BuildDate:   bDate,
		BinaryName:  binName,
		Paths:       scanTargets,
		Excludes:    s.cfg.Scan.Excludes,
		Mode:        mode,
		Threads:     s.cfg.Scan.Threads,
		MaxFileSize: s.cfg.Scan.MaxFileSize,
		Notices:     startupNotices,
	})

	// Load triage engine
	triageEng, err := triage.LoadEngine(s.cfg.Scan.AcknowledgedPath, "")
	if err != nil {
		s.logger.Warn("failed to load acknowledgment engine", slog.String("error", err.Error()))
	}

	// 1. Run registered threat-hunting modules
	var modulesNotRun []string
	moduleRep := &busReporter{bus: s.bus, triageEngine: triageEng}
	for _, mod := range s.modules {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			modStart := time.Now()
			s.logger.Debug("running hunting module", slog.String("module", mod.Name()))
			s.bus.Publish(events.ModuleStarted{
				Time:        modStart,
				ModuleName:  mod.Name(),
				Description: mod.Description(),
			})

			findingsBefore := moduleRep.count.Load()
			err := mod.Run(ctx, s.cfg, moduleRep)
			findingsCount := int(moduleRep.count.Load() - findingsBefore)

			status := "OK"
			if errors.Is(err, modules.ErrNotImplemented) {
				status = "NOT IMPLEMENTED"
				modulesNotRun = append(modulesNotRun, fmt.Sprintf("%s (not implemented)", mod.Name()))
			} else if err != nil {
				status = "FAILED"
				modulesNotRun = append(modulesNotRun, fmt.Sprintf("%s (failed)", mod.Name()))
				s.logger.Warn("module execution returned error",
					slog.String("module", mod.Name()),
					slog.Any("error", err),
				)
			}

			var inspectedCount int64
			if pMod, ok := mod.(*process.Module); ok {
				inspectedCount = pMod.Coverage().Inspected
			} else if permMod, ok := mod.(*persistence.Module); ok {
				inspectedCount = permMod.Coverage().TotalInspected
			} else if uMod, ok := mod.(*users.Module); ok {
				inspectedCount = uMod.Coverage().AccountsInspected
			} else if nMod, ok := mod.(*network.Module); ok {
				inspectedCount = nMod.Coverage().SocketsInspected
			} else if kMod, ok := mod.(*kernel.Module); ok {
				inspectedCount = kMod.Coverage().LoadedModulesInspected
			}

			s.bus.Publish(events.ModuleFinished{
				Time:           time.Now(),
				ModuleName:     mod.Name(),
				Duration:       time.Since(modStart),
				FindingsCount:  findingsCount,
				InspectedCount: inspectedCount,
				Err:            err,
				Status:         status,
			})
		}
	}

	// 2. Coverage Tracking Counters
	var filesScanned atomic.Int64
	var skippedOversize atomic.Int64
	var skippedPermission atomic.Int64
	var skippedVanished atomic.Int64
	var skippedNotRegular atomic.Int64
	var skippedExcluded atomic.Int64
	var skippedSuppressed atomic.Int64

	runFS := true
	if len(s.cfg.Scan.Modules) > 0 {
		runFS = false
		for _, m := range s.cfg.Scan.Modules {
			if m == "filesystem" {
				runFS = true
				break
			}
		}
	}

	var fsFindings []report.Finding
	var (
		dirMu          sync.Mutex
		totalDirCounts = make(map[string]int64)
		oversizeMu     sync.Mutex
		oversizeFiles  []events.OversizeFile
		walkErr        error
	)

	if runFS {
		fsStart := time.Now()
		s.bus.Publish(events.ModuleStarted{
			Time:        fsStart,
			ModuleName:  "filesystem",
			Description: "Scans filesystem locations for suspicious scripts, web shells, and suid anomalies",
		})

		fileChan := make(chan string, s.cfg.Scan.Threads*10)

		// Worker pool for scanning files

	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Scan.Threads; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			yScanner := s.yaraEngine.NewScanner()
			defer yScanner.Destroy()

			localDirCounts := make(map[string]int64)
			defer func() {
				dirMu.Lock()
				for d, c := range localDirCounts {
					totalDirCounts[d] += c
				}
				dirMu.Unlock()
			}()

			for path := range fileChan {
				select {
				case <-ctx.Done():
					return
				default:
					fileStart := time.Now()
					scanned, err := s.inspectFile(ctx, path, yScanner, &skippedSuppressed)
					if err != nil {
						var oversizeErr *safeopen.ErrOversizeFile
						if errors.As(err, &oversizeErr) {
							skippedOversize.Add(1)
							oversizeMu.Lock()
							oversizeFiles = append(oversizeFiles, events.OversizeFile{
								Path: oversizeErr.Path,
								Size: oversizeErr.Size,
							})
							oversizeMu.Unlock()
						} else if errors.Is(err, ErrFileTooLarge) {
							skippedOversize.Add(1)
						} else if errors.Is(err, ErrPermission) {
							skippedPermission.Add(1)
							s.bus.Publish(events.Error{
								Time:    time.Now(),
								Module:  "filesystem",
								Path:    path,
								Err:     err,
								IsFatal: false,
							})
						} else if errors.Is(err, ErrVanished) {
							skippedVanished.Add(1)
							s.bus.Publish(events.Error{
								Time:    time.Now(),
								Module:  "filesystem",
								Path:    path,
								Err:     err,
								IsFatal: false,
							})
						} else if errors.Is(err, ErrNotRegularFile) {
							skippedNotRegular.Add(1)
						}
						continue
					}

					if scanned {
						localDirCounts[filepath.Dir(path)]++
						count := filesScanned.Add(1)
						s.bus.Publish(events.FileScanned{
							Time:     time.Now(),
							Path:     path,
							Duration: time.Since(fileStart),
						})

						if count%100 == 0 {
							elapsed := time.Since(startTime)
							rate := float64(count) / elapsed.Seconds()
							s.bus.Publish(events.Progress{
								Time:         time.Now(),
								CurrentFiles: count,
								FilesPerSec:  rate,
								Elapsed:      elapsed,
							})
						}
					}
				}
			}
		}(i)
	}

	// Walk paths and feed the worker channel
	var walkErr error
	for _, rootPath := range scanTargets {
		if s.isExcluded(rootPath) {
			skippedExcluded.Add(1)
			s.logger.Debug("skipping excluded root path", slog.String("path", rootPath))
			continue
		}

		// Determine root filesystem device ID if one-filesystem mode is active
		var rootDev uint64
		if oneFS {
			var rootStat unix.Stat_t
			if err := unix.Stat(rootPath, &rootStat); err == nil {
				rootDev = uint64(rootStat.Dev)
			}
		}

		err := filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if os.IsPermission(err) {
					skippedPermission.Add(1)
					s.bus.Publish(events.Error{Time: time.Now(), Module: "filesystem", Path: path, Err: err, IsFatal: false})
				} else if os.IsNotExist(err) {
					skippedVanished.Add(1)
					s.bus.Publish(events.Error{Time: time.Now(), Module: "filesystem", Path: path, Err: err, IsFatal: false})
				}
				return nil
			}

			// Do NOT follow symlinks!
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}

			if s.isExcluded(path) {
				skippedExcluded.Add(1)
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			// One filesystem boundary check
			if oneFS && d.IsDir() && rootDev != 0 {
				var dirStat unix.Stat_t
				if lErr := unix.Lstat(path, &dirStat); lErr == nil {
					if uint64(dirStat.Dev) != rootDev {
						s.logger.Debug("skipping foreign filesystem mount", slog.String("path", path))
						return filepath.SkipDir
					}
				}
			}

			// Only regular files enter the scan pipeline
			if d.Type().IsRegular() {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case fileChan <- path:
				}
			} else if !d.IsDir() {
				// Sockets, FIFOs, devices skipped
				skippedNotRegular.Add(1)
			}

			return nil
		})

		if err != nil && walkErr == nil && !os.IsNotExist(err) {
			walkErr = err
		}
	}

		close(fileChan)
		wg.Wait()

		// Flush and deduplicate filesystem findings
		rawFSFindings := s.accumulator.Flush()
		for _, f := range rawFSFindings {
			// Dedupe findings by (path, rule) across modules; persistence wins over filesystem
			if f.Count <= 1 {
				key := findingRuleKey{path: f.Path, rule: f.RuleName}
				moduleRep.mu.Lock()
				owningMod := moduleRep.findings[key]
				moduleRep.mu.Unlock()
				if owningMod == "persistence" {
					continue // persistence wins over filesystem for the same file
				}
				fsFindings = append(fsFindings, f)
			} else {
				var filteredPaths []string
				moduleRep.mu.Lock()
				for _, p := range f.Paths {
					key := findingRuleKey{path: p, rule: f.RuleName}
					if moduleRep.findings[key] != "persistence" {
						filteredPaths = append(filteredPaths, p)
					}
				}
				moduleRep.mu.Unlock()

				if len(filteredPaths) == 0 {
					continue
				}
				f.Paths = filteredPaths
				f.Count = len(filteredPaths)
				fsFindings = append(fsFindings, f)
			}
		}

		for _, f := range fsFindings {
			if triageEng != nil {
				triageEng.Evaluate(&f, "")
			}
			s.bus.Publish(events.FindingRaised{
				Time:    time.Now(),
				Finding: f,
			})
		}

		s.bus.Publish(events.ModuleFinished{
			Time:           time.Now(),
			ModuleName:     "filesystem",
			Duration:       time.Since(fsStart),
			FindingsCount:  len(fsFindings),
			InspectedCount: filesScanned.Load(),
			Status:         "OK",
		})
	}

	// 3. Final Summary & Verdict Calculation
	totalDuration := time.Since(startTime)
	var totalFindings, alerts, warnings, notices, infos, affectedFiles int
	allEmitted := append(moduleRep.all, fsFindings...)

	var acknowledgedWarnings []report.Finding
	var acknowledgedCount int64

	if triageEng != nil {
		for i := range allEmitted {
			f := &allEmitted[i]
			origSev := f.Severity
			if origSevStr, ok := f.Metadata["original_severity"].(string); ok && origSevStr != "" {
				origSev = report.Severity(origSevStr)
			}
			if triageEng.Evaluate(f, "") {
				acknowledgedCount++
				if origSev == report.SeverityWarning {
					acknowledgedWarnings = append(acknowledgedWarnings, *f)
				}
			}
		}
	}

	totalFindings = len(allEmitted)
	for _, f := range allEmitted {
		count := f.Count
		if count <= 0 {
			count = 1
		}
		affectedFiles += count
		switch f.Severity {
		case report.SeverityAlert:
			alerts++
		case report.SeverityWarning:
			warnings++
		case report.SeverityNotice:
			notices++
		case report.SeverityInfo:
			infos++
		}
	}

	var topDirs []events.DirCount
	for d, c := range totalDirCounts {
		topDirs = append(topDirs, events.DirCount{Dir: d, Count: c})
	}
	sort.Slice(topDirs, func(i, j int) bool {
		if topDirs[i].Count != topDirs[j].Count {
			return topDirs[i].Count > topDirs[j].Count
		}
		return topDirs[i].Dir < topDirs[j].Dir
	})
	if len(topDirs) > 10 {
		topDirs = topDirs[:10]
	}

	sort.Slice(oversizeFiles, func(i, j int) bool {
		return oversizeFiles[i].Path < oversizeFiles[j].Path
	})

	coverage := events.CoverageStats{
		FilesScanned:      filesScanned.Load(),
		SkippedOversize:   skippedOversize.Load(),
		SkippedPermission: skippedPermission.Load(),
		SkippedVanished:   skippedVanished.Load(),
		SkippedNotRegular: skippedNotRegular.Load(),
		SkippedExcluded:   skippedExcluded.Load(),
		Suppressed:        skippedSuppressed.Load(),
		Acknowledged:      acknowledgedCount,
		TopInspectedDirs:  topDirs,
		OversizeFiles:     oversizeFiles,
	}

	// Aggregate top rules (splitting composite rules by ", ")
	type topRuleKey struct {
		ruleName string
		isAck    bool
	}
	ruleMap := make(map[topRuleKey]*report.RuleSummary)
	for _, f := range allEmitted {
		rName := f.RuleName
		if rName == "" {
			rName = "Unknown"
		}
		isAck := false
		if ack, ok := f.Metadata["acknowledged"].(bool); ok && ack {
			isAck = true
		}
		ruleSevs, _ := f.Metadata["rule_severities"].(map[string]string)
		subRules := strings.Split(rName, ", ")
		for _, sub := range subRules {
			sub = strings.TrimSpace(sub)
			if sub == "" {
				continue
			}
			var sev report.Severity
			if isAck {
				sev = f.Severity // Effective severity after acknowledgment (INFO)
			} else {
				sev = f.Severity
				if ruleSevs != nil {
					if sStr, ok := ruleSevs[sub]; ok {
						switch strings.ToUpper(sStr) {
						case "ALERT":
							sev = report.SeverityAlert
						case "WARNING", "WARN":
							sev = report.SeverityWarning
						case "NOTICE":
							sev = report.SeverityNotice
						case "INFO":
							sev = report.SeverityInfo
						}
					}
				}
			}
			key := topRuleKey{ruleName: sub, isAck: isAck}
			if existing, ok := ruleMap[key]; ok {
				existing.Count++
				existing.Severity = maxFindingSeverity(existing.Severity, sev)
			} else {
				ruleMap[key] = &report.RuleSummary{
					RuleName:     sub,
					Severity:     sev,
					Count:        1,
					Acknowledged: isAck,
				}
			}
		}
	}
	var topRules []report.RuleSummary
	for _, rs := range ruleMap {
		topRules = append(topRules, *rs)
	}
	sort.Slice(topRules, func(i, j int) bool {
		if topRules[i].Count != topRules[j].Count {
			return topRules[i].Count > topRules[j].Count
		}
		sevI := rankSeverity(topRules[i].Severity)
		sevJ := rankSeverity(topRules[j].Severity)
		if sevI != sevJ {
			return sevI > sevJ
		}
		if topRules[i].RuleName != topRules[j].RuleName {
			return topRules[i].RuleName < topRules[j].RuleName
		}
		return !topRules[i].Acknowledged && topRules[j].Acknowledged
	})

	verdict, verdictReason := events.ComputeVerdict(allEmitted, alerts, warnings, notices, s.cfg.Scan.VerdictNoticesThreshold)
	partial := coverage.HasPartialCoverage() || len(modulesNotRun) > 0 || (os.Geteuid() != 0)

	var procCov *events.ProcessCoverageStats
	var persistCov *events.PersistenceCoverageStats
	var usersCov *events.UsersCoverageStats
	var netCov *events.NetworkCoverageStats
	var kernelCov *events.KernelCoverageStats

	for _, mod := range s.modules {
		if pMod, ok := mod.(*process.Module); ok {
			c := pMod.Coverage()
			procCov = &events.ProcessCoverageStats{
				Inspected:         c.Inspected,
				Limited:           c.Limited,
				SkippedPermission: c.SkippedPermission,
				SkippedVanished:   c.SkippedVanished,
				KernelThreads:     c.KernelThreadsSkipped,
				Zombies:           c.ZombiesSkipped,
				NonRootLimited:    c.NonRootLimited,
				HiddenPIDRange:    c.HiddenPIDRange,
				NotHashed:         c.NotHashed,
				DurationBreakdown: c.DurationBreakdown,
			}
		} else if permMod, ok := mod.(*persistence.Module); ok {
			c := permMod.Coverage()
			persistCov = &events.PersistenceCoverageStats{
				TotalInspected:  c.TotalInspected,
				TotalUnreadable: c.TotalUnreadable,
				NotPresent:      c.NotPresent,
				TotalMissing:    c.TotalMissing,
				TotalMasked:     c.TotalMasked,
				MaskedPaths:     c.MaskedPaths,
				NonRootLimited:  c.NonRootLimited,
				PkgDBAvailable:  c.PkgDBAvailable,
				PkgDBNote:       c.PkgDBNote,
				UnreadablePaths: c.UnreadablePaths,
			}
		} else if uMod, ok := mod.(*users.Module); ok {
			c := uMod.Coverage()
			usersCov = &events.UsersCoverageStats{
				AccountsInspected:      c.AccountsInspected,
				SystemAccounts:         c.SystemAccounts,
				ShadowReadable:         c.ShadowReadable,
				ShadowGapNonRoot:       c.ShadowGapNonRoot,
				DuplicateUIDs:          c.DuplicateUIDs,
				PrivilegedGroupMembers: c.PrivilegedGroupMembers,
				DockerLXDMembers:       c.DockerLXDMembers,
				NonRootLimited:         c.NonRootLimited,
			}
		} else if nMod, ok := mod.(*network.Module); ok {
			c := nMod.Coverage()
			netCov = &events.NetworkCoverageStats{
				SocketsInspected:       c.SocketsInspected,
				TCPListeners:           c.TCPListeners,
				UDPListeners:           c.UDPListeners,
				EstablishedConnections: c.EstablishedConnections,
				RawPacketSockets:       c.RawPacketSockets,
				KernelOwnedSockets:     c.KernelOwnedSockets,
				UnmappedSocketsNonRoot: c.UnmappedSocketsNonRoot,
				NonRootLimited:         c.NonRootLimited,
				NamespaceNote:          c.NamespaceNote,
			}
		} else if kMod, ok := mod.(*kernel.Module); ok {
			c := kMod.Coverage()
			kernelCov = &events.KernelCoverageStats{
				LoadedModulesInspected: c.LoadedModulesInspected,
				SysfsLoadableEntries:   c.SysfsLoadableEntries,
				TaintValue:             c.TaintValue,
				TaintFlags:             c.TaintFlags,
				TaintSeverity:          c.TaintSeverity,
				ModprobeFilesInspected: c.ModprobeFilesInspected,
				GapsNote:               c.GapsNote,
			}
		}
	}

	yCov := s.yaraEngine.Coverage()
	if !yCov.CompiledIn {
		modulesNotRun = append(modulesNotRun, "yara (not compiled in)")
	} else if yCov.NotRunReason != "" {
		modulesNotRun = append(modulesNotRun, fmt.Sprintf("yara (%s)", yCov.NotRunReason))
	} else if yCov.DemoRulesOnly {
		modulesNotRun = append(modulesNotRun, "yara (demo rules only, no real rule set loaded)")
	}

	s.bus.Publish(events.ScanFinished{
		Time:                 time.Now(),
		TotalDuration:        totalDuration,
		FilesScanned:         filesScanned.Load(),
		Coverage:             coverage,
		TotalFindings:        totalFindings,
		Alerts:               alerts,
		Warnings:             warnings,
		Notices:              notices,
		Infos:                infos,
		AffectedFiles:        affectedFiles,
		Verdict:              verdict,
		VerdictReason:        verdictReason,
		TopRules:             topRules,
		Partial:              partial,
		ModulesNotRun:        modulesNotRun,
		StartupNotices:       startupNotices,
		ProcessCoverage:      procCov,
		PersistenceCoverage:  persistCov,
		UsersCoverage:        usersCov,
		NetworkCoverage:      netCov,
		KernelCoverage:       kernelCov,
		YARACoverage:         &yCov,
		AcknowledgedWarnings: acknowledgedWarnings,
	})

	s.logger.Info("threat hunting scan completed",
		slog.Int64("files_inspected", filesScanned.Load()),
		slog.Int64("skipped_total", coverage.TotalSkipped()),
		slog.Int("total_findings", totalFindings),
		slog.Int("alerts", alerts),
		slog.Int("warnings", warnings),
		slog.Int("notices", notices),
		slog.Int("infos", infos),
		slog.String("verdict", string(verdict)),
		slog.Bool("partial_coverage", partial),
	)

	return walkErr
}

// inspectFile opens a file race-safely, computes/caches hashes per (dev, ino),
// evaluates heuristics, IOCs, and YARA rules from the in-memory buffer.
func (s *Scanner) inspectFile(ctx context.Context, path string, yScanner yara.Scanner, skippedSuppressed *atomic.Int64) (bool, error) {
	desc, err := OpenRegularReadOnly(path, s.cfg.Scan.MaxFileSize)
	if err != nil {
		return false, err
	}
	defer desc.Close()

	// Hardlink deduplication: cache & reuse hashing result per (dev, ino)
	inoKey := InodeKey{
		Dev: uint64(desc.Stat.Dev),
		Ino: uint64(desc.Stat.Ino),
	}

	var fileData []byte
	var hashRes *HashStreamResult
	statSize := desc.Stat.Size

	if val, found := s.hashCache.Load(inoKey); found {
		hashRes = val.(*HashStreamResult)
		if s.yaraEngine != nil && s.yaraEngine.Enabled() && yScanner != nil && statSize <= s.cfg.Scan.YaraMaxFileSize && statSize >= 0 {
			buf, capSize, bErr := s.memoryBudget.Acquire(ctx, statSize)
			if bErr == nil {
				defer s.memoryBudget.Release(buf, capSize)
				n, _ := io.ReadFull(desc.File, buf)
				fileData = buf[:n]
			}
		}
	} else {
		if statSize > s.cfg.Scan.YaraMaxFileSize {
			// Stream hash file without buffering entire content
			sRes, sErr := StreamHashAndHeader(desc.File)
			if sErr != nil {
				return false, sErr
			}
			hashRes = sRes
			s.hashCache.Store(inoKey, hashRes)
			if s.yaraEngine != nil && s.yaraEngine.Enabled() {
				if yEngine, ok := s.yaraEngine.(interface{ RecordSkipOversize() }); ok {
					yEngine.RecordSkipOversize()
				}
				oversizeFinding := report.NewFinding(
					"yara",
					report.SeverityInfo,
					path,
					fmt.Sprintf("file size (%d bytes) exceeds YARA max filesize limit (%d bytes); YARA scan skipped (stream-hashed for IOCs)", statSize, s.cfg.Scan.YaraMaxFileSize),
					"YARA_Skipped_Oversize",
				)
				oversizeFinding.Hashes["MD5"] = hashRes.Hashes.MD5
				oversizeFinding.Hashes["SHA1"] = hashRes.Hashes.SHA1
				oversizeFinding.Hashes["SHA256"] = hashRes.Hashes.SHA256
				oversizeFinding.Metadata["size"] = statSize
				oversizeFinding.Metadata["oversize"] = true
				oversizeFinding.Metadata["score"] = 0
				s.accumulator.Add(path, "YARA_Skipped_Oversize", oversizeFinding.Reason, report.SeverityInfo, 0, oversizeFinding)
			}
		} else {
			buf, capSize, bErr := s.memoryBudget.Acquire(ctx, statSize)
			if bErr != nil {
				return false, bErr
			}
			defer s.memoryBudget.Release(buf, capSize)

			n, rErr := io.ReadFull(desc.File, buf)
			if rErr != nil && rErr != io.EOF && rErr != io.ErrUnexpectedEOF {
				return false, rErr
			}
			data := buf[:n]
			hashRes = HashFromBytes(data)
			s.hashCache.Store(inoKey, hashRes)
			if s.yaraEngine != nil && s.yaraEngine.Enabled() {
				fileData = data
			}
		}
	}

	// 1. Evaluate Hash IOC matches
	var hashMatch *ioc.MatchResult
	if m := s.iocEngine.CheckHash(hashRes.Hashes.SHA256); m != nil {
		hashMatch = m
	} else if m := s.iocEngine.CheckHash(hashRes.Hashes.SHA1); m != nil {
		hashMatch = m
	} else if m := s.iocEngine.CheckHash(hashRes.Hashes.MD5); m != nil {
		hashMatch = m
	}

	// 2. Check for known benign path suppression
	mode := uint32(desc.Stat.Mode)
	uid := uint32(desc.Stat.Uid)
	isBenign, benignReason := s.iocEngine.IsKnownBenign(path, uid)

	// 3. Evaluate Path/Filename IOC matches (run for EVERY path)
	pathMatch := s.iocEngine.CheckPath(path)

	// 4. Evaluate Heuristics (run for EVERY path)
	hasOtherSignal := (hashMatch != nil) || (pathMatch != nil)
	base := filepath.Base(path)
	isSUIDorSGID := (mode & (unix.S_ISUID | unix.S_ISGID)) != 0
	isHiddenAndExec := strings.HasPrefix(base, ".") && (mode&0111 != 0)

	// Suppression never applies if the file is SUID/SGID, hidden AND executable, or matched by a hash/path IOC
	canSuppress := isBenign && !isSUIDorSGID && !isHiddenAndExec && !hasOtherSignal

	var hELF *HeuristicMatch
	if !canSuppress {
		hELF = CheckELFInTempOrDev(path, hashRes.Header, mode, uid, hasOtherSignal, s.cfg)
	} else {
		// Suppressed files are downgraded to INFO and recorded (counted in CoverageStats.Suppressed, listed with --verbose)
		if rawELF := CheckELFInTempOrDev(path, hashRes.Header, mode, uid, false, s.cfg); rawELF != nil {
			if skippedSuppressed != nil {
				skippedSuppressed.Add(1)
			}
			suppressedFinding := report.NewFinding(
				"filesystem",
				report.SeverityInfo,
				path,
				fmt.Sprintf("Suppressed benign ELF file (%s)", benignReason),
				"Benign_Suppressed_File",
			)
			suppressedFinding.Hashes["MD5"] = hashRes.Hashes.MD5
			suppressedFinding.Hashes["SHA1"] = hashRes.Hashes.SHA1
			suppressedFinding.Hashes["SHA256"] = hashRes.Hashes.SHA256
			suppressedFinding.Metadata["suppressed"] = true
			suppressedFinding.Metadata["suppress_reason"] = benignReason
			suppressedFinding.Metadata["score"] = 0
			s.accumulator.Add(path, "Benign_Suppressed_File", suppressedFinding.Reason, report.SeverityInfo, 0, suppressedFinding)
		}
		s.logger.Debug("suppressing ELF-in-temp heuristic for known benign path",
			slog.String("path", path),
			slog.String("reason", benignReason),
		)
	}

	hHidden := CheckHiddenExecutableInSystemDirs(path, mode, s.cfg)
	hSUID := CheckSuspiciousSUID(path, mode, s.cfg)
	hWorldWritable := CheckWorldWritableInEtc(path, mode, s.cfg)

	if hELF != nil || hHidden != nil || hSUID != nil || hWorldWritable != nil {
		hasOtherSignal = true
	}

	// 5. Known-good allowlist check:
	isAllowlisted, _ := s.iocEngine.IsAllowlisted(hashRes.Hashes.SHA256)
	if isAllowlisted {
		hELF = nil
		hHidden = nil
		hSUID = nil
		hWorldWritable = nil
		pathMatch = nil // Suppress path heuristics if known-good hash matches
	}

	// 6. YARA scanning from buffer
	var yaraMatches []yara.RuleMatch
	if s.yaraEngine != nil && s.yaraEngine.Enabled() && yScanner != nil && statSize <= s.cfg.Scan.YaraMaxFileSize {
		if len(fileData) > 0 || statSize == 0 {
			target := yara.ScanTarget{
				Path:      path,
				Filename:  base,
				Extension: filepath.Ext(path),
				FileType:  "",
				Owner:     fmt.Sprint(uid),
				Data:      fileData,
			}
			matches, yErr := yScanner.Scan(target)
			if yErr == nil && len(matches) > 0 {
				yaraMatches = matches
			}
		}
	}

	// 7. Check if this file qualifies as a YARA rule file
	if s.yaraEngine != nil && s.yaraEngine.Enabled() && len(yaraMatches) > 0 && looksLikeYaraRuleFile(path, fileData, hasOtherSignal, statSize) {
		if yEngine, ok := s.yaraEngine.(interface{ RecordRuleFileSeen() }); ok {
			yEngine.RecordRuleFileSeen()
		}
		ruleFinding := report.NewFinding(
			"yara",
			report.SeverityInfo,
			path,
			"looks like a YARA rule file",
			"YARA_Rule_File",
		)
		ruleFinding.Hashes["MD5"] = hashRes.Hashes.MD5
		ruleFinding.Hashes["SHA1"] = hashRes.Hashes.SHA1
		ruleFinding.Hashes["SHA256"] = hashRes.Hashes.SHA256
		ruleFinding.Metadata["score"] = 0
		ruleFinding.Metadata["is_rule_file"] = true
		ruleFinding.Metadata["yara_rule"] = yaraMatches[0].RuleName
		s.accumulator.Add(path, "YARA_Rule_File", ruleFinding.Reason, report.SeverityInfo, 0, ruleFinding)
		yaraMatches = nil
	}

	// 8. Consolidate into findings
	var matchedReasons []string
	var matchedRules []string
	totalScore := 0
	highestSeverity := report.SeverityInfo
	var hasConfidenceHigh bool

	updateSeverity := func(sev report.Severity) {
		switch sev {
		case report.SeverityAlert:
			highestSeverity = report.SeverityAlert
		case report.SeverityWarning:
			if highestSeverity != report.SeverityAlert {
				highestSeverity = report.SeverityWarning
			}
		case report.SeverityNotice:
			if highestSeverity != report.SeverityAlert && highestSeverity != report.SeverityWarning {
				highestSeverity = report.SeverityNotice
			}
		}
	}

	ruleSeverities := make(map[string]string)

	if hashMatch != nil {
		matchedReasons = append(matchedReasons, hashMatch.Reason)
		matchedRules = append(matchedRules, hashMatch.RuleName)
		ruleSeverities[hashMatch.RuleName] = hashMatch.Severity.String()
		totalScore += hashMatch.Score
		updateSeverity(hashMatch.Severity)
	}

	if pathMatch != nil {
		matchedReasons = append(matchedReasons, pathMatch.Reason)
		matchedRules = append(matchedRules, pathMatch.RuleName)
		ruleSeverities[pathMatch.RuleName] = pathMatch.Severity.String()
		totalScore += pathMatch.Score
		updateSeverity(pathMatch.Severity)
	}

	for _, hm := range []*HeuristicMatch{hELF, hHidden, hSUID, hWorldWritable} {
		if hm != nil {
			matchedReasons = append(matchedReasons, hm.Reason)
			matchedRules = append(matchedRules, hm.Name)
			ruleSeverities[hm.Name] = hm.Severity.String()
			totalScore += hm.Score
			updateSeverity(hm.Severity)
		}
	}

	for _, ym := range yaraMatches {
		if isAllowlisted && ym.Severity < report.SeverityAlert {
			if skippedSuppressed != nil {
				skippedSuppressed.Add(1)
			}
			suppressedFinding := report.NewFinding(
				"yara",
				report.SeverityInfo,
				path,
				fmt.Sprintf("Allowlisted file (YARA match %s suppressed)", ym.RuleName),
				ym.RuleName,
			)
			suppressedFinding.Hashes["MD5"] = hashRes.Hashes.MD5
			suppressedFinding.Hashes["SHA1"] = hashRes.Hashes.SHA1
			suppressedFinding.Hashes["SHA256"] = hashRes.Hashes.SHA256
			suppressedFinding.Metadata["suppressed"] = true
			suppressedFinding.Metadata["suppress_reason"] = "allowlisted"
			suppressedFinding.Metadata["score"] = 0
			suppressedFinding.Metadata["yara_rule"] = ym.RuleName
			suppressedFinding.Metadata["yara_tags"] = ym.Tags
			s.accumulator.Add(path, ym.RuleName, suppressedFinding.Reason, report.SeverityInfo, 0, suppressedFinding)
			continue
		}

		reasonStr := fmt.Sprintf("YARA match: %s", ym.RuleName)
		if len(ym.MatchedStrings) > 0 {
			reasonStr = fmt.Sprintf("YARA match: %s (%s)", ym.RuleName, strings.Join(ym.MatchedStrings, ", "))
		}
		matchedReasons = append(matchedReasons, reasonStr)
		matchedRules = append(matchedRules, ym.RuleName)
		ruleSeverities[ym.RuleName] = ym.Severity.String()
		totalScore += ym.Score
		updateSeverity(ym.Severity)
		if strings.EqualFold(ym.Confidence, "high") {
			hasConfidenceHigh = true
		}
	}

	// If any matches occurred, add to accumulator for grouping by (rule, parentDir)
	if len(matchedReasons) > 0 {
		ruleName := strings.Join(matchedRules, ", ")
		reason := strings.Join(matchedReasons, " | ")

		f := report.NewFinding("filesystem", highestSeverity, path, reason, ruleName)
		f.Hashes["MD5"] = hashRes.Hashes.MD5
		f.Hashes["SHA1"] = hashRes.Hashes.SHA1
		f.Hashes["SHA256"] = hashRes.Hashes.SHA256
		f.Metadata["score"] = totalScore
		f.Metadata["size"] = hashRes.BytesRead
		f.Metadata["rule_severities"] = ruleSeverities
		if hasConfidenceHigh {
			f.Metadata["confidence"] = "high"
		}

		s.accumulator.Add(path, ruleName, reason, highestSeverity, totalScore, f)
	}

	return true, nil
}

// looksLikeYaraRuleFile determines if a file qualifies as a YARA rule file.
func looksLikeYaraRuleFile(path string, data []byte, hasOtherSignal bool, descSize int64) bool {
	if hasOtherSignal {
		return false
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".yar" && ext != ".yara" {
		return false
	}
	if descSize > 2*1024*1024 || len(data) == 0 {
		return false
	}
	// Reject files with NUL bytes (binary files)
	if bytes.IndexByte(data, 0) != -1 {
		return false
	}
	// Reject ELF files
	if bytes.HasPrefix(data, []byte("\x7fELF")) {
		return false
	}
	// Reject scripts with shebang
	if bytes.HasPrefix(data, []byte("#!")) {
		return false
	}
	strData := string(data)
	if !strings.Contains(strData, "rule ") || !strings.Contains(strData, "{") || !strings.Contains(strData, "}") {
		return false
	}
	return true
}

// isExcluded determines whether a path matches any configured exclude prefixes.
func (s *Scanner) isExcluded(path string) bool {
	cleaned := filepath.Clean(path)
	for _, exc := range s.cfg.Scan.Excludes {
		excClean := filepath.Clean(exc)
		if cleaned == excClean || strings.HasPrefix(cleaned, excClean+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// CollectRootStartupNotices collects startup diagnostic notices for privileged root executions.
func CollectRootStartupNotices(euid uint32, sudoUser string, exePath string, statFn yara.StatFunc, evalSymlinksFn yara.EvalSymlinksFunc) []string {
	if euid != 0 {
		return nil
	}

	var notices []string

	// 1. Binary trust check
	if exePath != "" {
		if trusted, _ := yara.VerifyRootOwnedPath(exePath, statFn, evalSymlinksFn); !trusted {
			notices = append(notices, "running as root from a user-writable location; copy the binary to a root-owned path for privileged scans")
		}
	}

	// 2. Ignored user acks check
	var candidatePaths []string
	if sudoUser != "" {
		if u, err := user.Lookup(sudoUser); err == nil && u.HomeDir != "" {
			candidatePaths = append(candidatePaths, filepath.Join(u.HomeDir, ".config/aether/acknowledged.yaml"))
		}
	}
	if homeDir, err := os.UserHomeDir(); err == nil && homeDir != "" && homeDir != "/root" {
		candidatePaths = append(candidatePaths, filepath.Join(homeDir, ".config/aether/acknowledged.yaml"))
	}
	if matches, err := filepath.Glob("/home/*/.config/aether/acknowledged.yaml"); err == nil {
		candidatePaths = append(candidatePaths, matches...)
	}

	seen := make(map[string]bool)
	for _, p := range candidatePaths {
		p = filepath.Clean(p)
		if seen[p] {
			continue
		}
		seen[p] = true

		if count, err := triage.CountAckEntries(p); err == nil && count > 0 {
			notices = append(notices, fmt.Sprintf("%d acknowledgments in %s ignored because running as root (use `aether ack --system`)", count, p))
		}
	}

	return notices
}

func rankSeverity(s report.Severity) int {
	switch s {
	case report.SeverityAlert:
		return 4
	case report.SeverityWarning:
		return 3
	case report.SeverityNotice:
		return 2
	case report.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func maxFindingSeverity(a, b report.Severity) report.Severity {
	if rankSeverity(a) >= rankSeverity(b) {
		return a
	}
	return b
}
