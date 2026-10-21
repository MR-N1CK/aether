package scanner

import (
	"context"
	"errors"
	"flag"
	"fmt"
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
	"aether/internal/modules/persistence"
	"aether/internal/pkgdb"
	"aether/internal/report"
	htmlreport "aether/internal/report/html"
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
	cfg            *config.Config
	logger         *slog.Logger
	reporter       report.Reporter
	bus            *events.EventBus
	iocEngine      ioc.Engine
	pkgDB          pkgdb.PackageDB
	yaraEngine     yara.Engine
	modules        []modules.Module
	accumulator    *findingAccumulator
	memoryBudget   *MemoryBudget
	devRpath       bool
	rootFS         string
	startupNotices []string
	version        string
	commit         string
	buildDate      string
	binaryName     string

	executiveAssessmentFn func(findings []report.Finding, sf events.ScanFinished) (string, string, []htmlreport.RemediationAction, map[string]string)

	// Hardlink deduplication cache: InodeKey -> *HashStreamResult
	hashCache sync.Map
}

type workerSlot struct {
	id         int
	activePath string
	startTime  time.Time
	abandoned  atomic.Bool
	doneCalled atomic.Bool
}

type workerPoolTracker struct {
	mu            sync.Mutex
	slots         map[int]*workerSlot
	activeWorkers int
	abandoned     int
	feedingDone   bool
	doneChan      chan struct{}
	closedDone    bool
	lastProgress  time.Time
}

func newWorkerPoolTracker() *workerPoolTracker {
	return &workerPoolTracker{
		slots:        make(map[int]*workerSlot),
		doneChan:     make(chan struct{}),
		lastProgress: time.Now(),
	}
}

// registerSlot registers a worker slot if not already present.
func (t *workerPoolTracker) registerSlot(id int) *workerSlot {
	t.mu.Lock()
	defer t.mu.Unlock()
	slot, exists := t.slots[id]
	if !exists {
		slot = &workerSlot{id: id}
		t.slots[id] = slot
		t.activeWorkers++
	}
	return slot
}

// startWorker registers a worker slot and increments active worker count.
// Returns false if feeding is already closed or id is already registered.
func (t *workerPoolTracker) startWorker(id int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.feedingDone {
		return false
	}
	if _, exists := t.slots[id]; exists {
		return false
	}
	t.slots[id] = &workerSlot{id: id}
	t.activeWorkers++
	return true
}

// workerFinished records worker exit. It decrements activeWorkers only once per slot.
// If feeding is done and activeWorkers reaches 0, it closes doneChan.
func (t *workerPoolTracker) workerFinished(id int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	slot, ok := t.slots[id]
	if !ok {
		return
	}
	if slot.doneCalled.CompareAndSwap(false, true) {
		t.activeWorkers--
		if t.feedingDone && t.activeWorkers == 0 && !t.closedDone {
			t.closedDone = true
			close(t.doneChan)
		}
	}
}

// abandonWorker attempts to logically abandon a worker slot that timed out.
// Returns abandoned=true only if this call successfully marked the worker as abandoned
// and decremented activeWorkers. If the worker already exited or was already abandoned,
// abandoned returns false.
func (t *workerPoolTracker) abandonWorker(id int, nextID *atomic.Int64) (newID int, spawn bool, capExceeded bool, path string, abandoned bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	slot, ok := t.slots[id]
	if !ok {
		return 0, false, false, "", false
	}

	if slot.abandoned.Swap(true) {
		return 0, false, false, "", false
	}

	if !slot.doneCalled.CompareAndSwap(false, true) {
		return 0, false, false, "", false
	}

	path = slot.activePath
	t.activeWorkers--
	t.abandoned++

	if t.feedingDone && t.activeWorkers == 0 && !t.closedDone {
		t.closedDone = true
		close(t.doneChan)
	}

	capExceeded = t.abandoned > 8
	// Spawn a replacement worker if feeding is still active AND
	// either the abandonment cap has not been exceeded OR activeWorkers would otherwise drop to 0.
	if !t.feedingDone && (t.abandoned <= 8 || t.activeWorkers == 0) {
		newID = int(nextID.Add(1))
		t.slots[newID] = &workerSlot{id: newID}
		t.activeWorkers++
		return newID, true, capExceeded, path, true
	}

	return 0, false, capExceeded, path, true
}

// CloseFeeding marks feeding as complete, closes fileChan, and closes doneChan if activeWorkers is 0.
// Must be called exactly once by the main scanner goroutine when directory traversal finishes.
func (t *workerPoolTracker) CloseFeeding(fileChan chan string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.feedingDone = true
	close(fileChan)
	if t.activeWorkers == 0 && !t.closedDone {
		t.closedDone = true
		close(t.doneChan)
	}
}

// Done returns the channel that is closed when feeding is complete and all active workers have finished or been abandoned.
func (t *workerPoolTracker) Done() <-chan struct{} {
	return t.doneChan
}

func (t *workerPoolTracker) setActive(id int, path string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if slot, ok := t.slots[id]; ok {
		slot.activePath = path
		slot.startTime = time.Now()
	}
}

func (t *workerPoolTracker) clearActive(id int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if slot, ok := t.slots[id]; ok {
		slot.activePath = ""
		slot.startTime = time.Time{}
	}
	t.lastProgress = time.Now()
}

func (t *workerPoolTracker) getActivePaths() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var paths []string
	for _, slot := range t.slots {
		if !slot.abandoned.Load() && slot.activePath != "" {
			paths = append(paths, slot.activePath)
		}
	}
	sort.Strings(paths)
	return paths
}

func (t *workerPoolTracker) checkTimeouts(timeout time.Duration) []*workerSlot {
	t.mu.Lock()
	defer t.mu.Unlock()
	var stuck []*workerSlot
	now := time.Now()
	for _, slot := range t.slots {
		if !slot.abandoned.Load() && slot.activePath != "" && !slot.startTime.IsZero() {
			if now.Sub(slot.startTime) >= timeout {
				stuck = append(stuck, slot)
			}
		}
	}
	return stuck
}

func isSwapFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base == "swapfile" || strings.HasPrefix(base, "swapfile") {
		return true
	}
	clean := filepath.Clean(path)
	if clean == "/swap" || clean == "/swapfile" || strings.HasPrefix(clean, "/var/swap") {
		return true
	}
	return false
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
	redactHosts  bool
	hostname     string
}

func (r *busReporter) Report(f report.Finding) {
	if r.redactHosts {
		report.RedactFinding(&f, r.hostname)
	}
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
func (r *busReporter) Close() error                       { return nil }

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

// WithPackageDB overrides the package database (for testing).
func WithPackageDB(db pkgdb.PackageDB) ScannerOption {
	return func(s *Scanner) {
		s.pkgDB = db
	}
}

// WithBuildInfo configures version, commit, buildDate, and binaryName metadata for scan lifecycle events.
func WithBuildInfo(version string, info ...string) ScannerOption {
	return func(s *Scanner) {
		s.version = version
		if len(info) == 2 {
			s.buildDate = info[0]
			s.binaryName = info[1]
		} else if len(info) >= 3 {
			s.commit = info[0]
			s.buildDate = info[1]
			s.binaryName = info[2]
		}
	}
}

// WithExecutiveAssessment registers a synthesizer callback that generates executive posture, rationale,
// prioritized remediation actions, and duration timing for HTML and executive reports.
func WithExecutiveAssessment(fn func(findings []report.Finding, sf events.ScanFinished) (string, string, []htmlreport.RemediationAction, map[string]string)) ScannerOption {
	return func(s *Scanner) {
		s.executiveAssessmentFn = fn
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

	rootFS := ""
	cleanRoot := filepath.Clean(cfg.Scan.Root)
	if cleanRoot != "" && cleanRoot != "/" {
		rootFS = cleanRoot
	}

	defaultMods := buildDefaultModules(cfg, rootFS, iocEng, bus, logger)

	s := &Scanner{
		cfg:          cfg,
		logger:       logger,
		reporter:     rep,
		bus:          bus,
		iocEngine:    iocEng,
		pkgDB:        pkgdb.New(rootFS),
		modules:      defaultMods,
		accumulator:  newFindingAccumulator(cfg),
		memoryBudget: NewMemoryBudget(cfg.Scan.MemoryBudgetBytes),
		devRpath:     false,
		rootFS:       rootFS,
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
		if !cfg.Scan.DemoRules && flag.Lookup("test.v") == nil {
			rulesDirs = append(rulesDirs, config.DefaultRulesDirs()...)
		}

		isRoot := os.Geteuid() == 0
		uid := uint32(os.Getuid())
		ruleFiles, _ := yara.DiscoverRuleFiles(rulesDirs, isRoot, uid, cfg.Scan.TrustRulesDir, logger)
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
	cleanRoot := filepath.Clean(s.cfg.Scan.Root)
	isOffline := cleanRoot != "" && cleanRoot != "/"

	if s.cfg.Scan.ExplicitPaths || (len(s.cfg.Scan.Paths) > 0 && !slicesEqual(s.cfg.Scan.Paths, config.DefaultScanPaths())) {
		rawTargets = s.cfg.Scan.Paths
	} else if s.cfg.Scan.Quick {
		rawTargets = config.QuickScanTargets()
	} else if s.cfg.Scan.Full {
		if isOffline {
			rawTargets = []string{cleanRoot}
		} else {
			rawTargets = []string{"/"}
		}
	} else {
		if isOffline {
			rawTargets = []string{cleanRoot}
		} else {
			rawTargets = s.cfg.Scan.Paths
		}
	}

	var resolved []string
	seen := make(map[string]bool)

	for _, target := range rawTargets {
		hostTarget := target
		if isOffline && !strings.HasPrefix(target, cleanRoot) {
			hostTarget = filepath.Join(cleanRoot, strings.TrimPrefix(target, "/"))
		}

		// Safely expand globs (e.g. /home/*/.ssh, /etc/cron*)
		if strings.ContainsAny(hostTarget, "*?[") {
			matches, err := filepath.Glob(hostTarget)
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
			cleaned := filepath.Clean(hostTarget)
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

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}

	// 1. Run registered threat-hunting modules
	var modulesNotRun []string
	var modulesFinishedList []events.ModuleFinished
	moduleRep := &busReporter{
		bus:          s.bus,
		triageEngine: triageEng,
		redactHosts:  s.cfg.Scan.RedactHosts,
		hostname:     hostname,
	}
	cleanRoot := filepath.Clean(s.cfg.Scan.Root)
	isOffline := cleanRoot != "" && cleanRoot != "/"

	if err := s.runModules(ctx, moduleRep, isOffline, &modulesNotRun, &modulesFinishedList); err != nil {
		return err
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

	var (
		dirMu               sync.Mutex
		totalDirCounts      = make(map[string]int64)
		oversizeMu          sync.Mutex
		oversizeFiles       []events.OversizeFile
		hashedOversizeFiles []events.OversizeFile
		walkErr             error
		skippedTimeout      atomic.Int64
		hashedOversize      atomic.Int64
		fsFindings          []report.Finding
	)

	if runFS {
		fsStart := time.Now()
		s.bus.Publish(events.ModuleStarted{
			Time:        fsStart,
			ModuleName:  "filesystem",
			Description: "Scans filesystem locations for suspicious scripts, web shells, and suid anomalies",
		})

		fileChan := make(chan string, s.cfg.Scan.Threads*10)
		tracker := newWorkerPoolTracker()

		var nextWorkerID atomic.Int64
		nextWorkerID.Store(int64(s.cfg.Scan.Threads - 1))

		var runWorker func(workerID int)
		runWorker = func(workerID int) {
			tracker.mu.Lock()
			slot := tracker.slots[workerID]
			tracker.mu.Unlock()
			if slot == nil {
				return
			}
			defer tracker.workerFinished(workerID)

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
					if slot.abandoned.Load() {
						return
					}

					tracker.setActive(workerID, path)
					fileStart := time.Now()
					scanned, isHashedOversize, err := s.inspectFileWithOversize(ctx, path, yScanner, &skippedSuppressed)
					tracker.clearActive(workerID)

					if slot.abandoned.Load() {
						return
					}

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

					if isHashedOversize {
						var sz int64
						if st, sErr := os.Stat(path); sErr == nil {
							sz = st.Size()
						}
						oversizeMu.Lock()
						hashedOversizeFiles = append(hashedOversizeFiles, events.OversizeFile{
							Path: path,
							Size: sz,
						})
						oversizeMu.Unlock()
						hashedOversize.Add(1)
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
								Time:          time.Now(),
								CurrentFiles:  count,
								FilesPerSec:   rate,
								Elapsed:       elapsed,
								ActiveModules: []string{"filesystem"},
								ActivePaths:   tracker.getActivePaths(),
							})
						}
					}
				}
			}
		}

		for i := 0; i < s.cfg.Scan.Threads; i++ {
			if tracker.startWorker(i) {
				go runWorker(i)
			}
		}

		watchdogCtx, watchdogCancel := context.WithCancel(ctx)
		defer watchdogCancel()

		fileTimeout := s.cfg.Scan.FileTimeout
		if fileTimeout <= 0 {
			fileTimeout = config.DefaultFileTimeout
		}

		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			heartbeatTicker := time.NewTicker(5 * time.Second)
			defer heartbeatTicker.Stop()

			lastProgressWarn := time.Now()

			for {
				select {
				case <-watchdogCtx.Done():
					return
				case <-heartbeatTicker.C:
					count := filesScanned.Load()
					elapsed := time.Since(startTime)
					rate := float64(count) / elapsed.Seconds()
					s.bus.Publish(events.Progress{
						Time:          time.Now(),
						CurrentFiles:  count,
						FilesPerSec:   rate,
						Elapsed:       elapsed,
						ActiveModules: []string{"filesystem"},
						ActivePaths:   tracker.getActivePaths(),
					})
				case <-ticker.C:
					stuckSlots := tracker.checkTimeouts(fileTimeout)
					for _, ws := range stuckSlots {
						newID, spawn, capExceeded, path, abandoned := tracker.abandonWorker(ws.id, &nextWorkerID)
						if !abandoned {
							continue
						}
						skippedTimeout.Add(1)
						s.logger.Warn("file read timed out",
							slog.String("path", path),
							slog.Duration("timeout", fileTimeout),
						)
						s.bus.Publish(events.Error{
							Time:    time.Now(),
							Module:  "filesystem",
							Path:    path,
							Err:     fmt.Errorf("file read timed out after %v", fileTimeout),
							IsFatal: false,
						})

						if spawn {
							go runWorker(newID)
						} else if capExceeded {
							s.logger.Warn("abandoned worker cap reached (8); scanning capacity and coverage are degraded")
							s.bus.Publish(events.Error{
								Time:    time.Now(),
								Module:  "filesystem",
								Err:     errors.New("abandoned worker cap reached (8); coverage is degraded"),
								IsFatal: false,
							})
						}
					}

					tracker.mu.Lock()
					timeSinceProgress := time.Since(tracker.lastProgress)
					tracker.mu.Unlock()

					if timeSinceProgress >= 60*time.Second && time.Since(lastProgressWarn) >= 60*time.Second {
						lastProgressWarn = time.Now()
						activePaths := tracker.getActivePaths()
						if len(activePaths) > 0 {
							s.logger.Warn("no scan progress for 60s", slog.Any("active_worker_paths", activePaths))
							fmt.Fprintf(os.Stderr, "[AETHER] [WARNING] No scan progress for 60s. Active worker paths: %v\n", activePaths)
						}
					}
				}
			}
		}()

		// Walk paths and feed the worker channel
		isPathExcluded := func(p string) bool {
			if s.isExcluded(p) {
				return true
			}
			if isOffline {
				if rel, err := filepath.Rel(cleanRoot, p); err == nil {
					virt := "/" + strings.TrimPrefix(filepath.ToSlash(rel), "/")
					if s.isExcluded(virt) {
						return true
					}
				}
			}
			return false
		}

		// Assignments below must hit the outer `walkErr` declared in the Run-scope
		// var block, which is returned at the end of Run. Re-declaring it here would
		// shadow it and silently discard walk failures from the error contract.
		for _, rootPath := range scanTargets {
			if isPathExcluded(rootPath) {
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

				if isPathExcluded(path) {
					skippedExcluded.Add(1)
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}

				// Default --full scan exclusions (when --path is not explicitly provided)
				if !s.cfg.Scan.ExplicitPaths && d.IsDir() {
					dirBase := d.Name()
					if dirBase == "testdata" {
						return filepath.SkipDir
					}
					cleanPath := filepath.Clean(path)
					if strings.HasSuffix(cleanPath, "/Downloads/Aether") || strings.Contains(cleanPath, "/Downloads/Aether/") {
						return filepath.SkipDir
					}
					goModPath := filepath.Join(path, "go.mod")
					if isOffline {
						goModPath = filepath.Join(cleanRoot, strings.TrimPrefix(path, "/"), "go.mod")
					}
					if fi, gErr := os.Stat(goModPath); gErr == nil && !fi.IsDir() {
						// Anti-evasion guard: Never skip go.mod if planted in critical system/volatile directories
						isCritSystem := cleanPath == "/etc" || strings.HasPrefix(cleanPath, "/etc/") ||
							cleanPath == "/boot" || strings.HasPrefix(cleanPath, "/boot/") ||
							cleanPath == "/var/log" || strings.HasPrefix(cleanPath, "/var/log/") ||
							cleanPath == "/dev/shm" || strings.HasPrefix(cleanPath, "/dev/shm/") ||
							cleanPath == "/run" || strings.HasPrefix(cleanPath, "/run/")
						if !isCritSystem {
							return filepath.SkipDir
						}
					}
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

		tracker.CloseFeeding(fileChan)
		select {
		case <-tracker.Done():
		case <-ctx.Done():
			if walkErr == nil {
				walkErr = ctx.Err()
			}
		}
		watchdogCancel()

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

		for i := range fsFindings {
			if s.cfg.Scan.RedactHosts {
				report.RedactFinding(&fsFindings[i], hostname)
			}
			f := fsFindings[i]
			if triageEng != nil {
				triageEng.Evaluate(&f, "")
			}
			s.bus.Publish(events.FindingRaised{
				Time:    time.Now(),
				Finding: f,
			})
		}

		fsMF := events.ModuleFinished{
			Time:           time.Now(),
			ModuleName:     "filesystem",
			Duration:       time.Since(fsStart),
			FindingsCount:  len(fsFindings),
			InspectedCount: filesScanned.Load(),
			Status:         "OK",
		}
		modulesFinishedList = append(modulesFinishedList, fsMF)
		s.bus.Publish(fsMF)
	}

	// 3. Final Summary & Verdict Calculation
	totalDuration := time.Since(startTime)
	var totalFindings, alerts, warnings, notices, infos, affectedFiles int
	allEmitted := append(moduleRep.all, fsFindings...)

	// Post-scan systemd correlation: annotate findings whose paths are
	// launched by boot-enabled units. Annotation-only (metadata); the
	// cross-domain correlator below remains the sole escalation authority.
	if len(s.modules) > 0 {
		if annotated := persistence.AnnotateEnabledUnitRefs(s.rootFS, allEmitted); annotated > 0 {
			s.logger.Info("correlated findings with boot-enabled systemd units", slog.Int("findings", annotated))
		}
	}
	allEmitted = report.CorrelateFindings(allEmitted)

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
	sort.Slice(hashedOversizeFiles, func(i, j int) bool {
		return hashedOversizeFiles[i].Path < hashedOversizeFiles[j].Path
	})

	coverage := events.CoverageStats{
		FilesScanned:        filesScanned.Load(),
		SkippedOversize:     skippedOversize.Load(),
		SkippedPermission:   skippedPermission.Load(),
		SkippedVanished:     skippedVanished.Load(),
		SkippedNotRegular:   skippedNotRegular.Load(),
		SkippedExcluded:     skippedExcluded.Load(),
		SkippedTimeout:      skippedTimeout.Load(),
		HashedOversize:      hashedOversize.Load(),
		Suppressed:          skippedSuppressed.Load(),
		Acknowledged:        acknowledgedCount,
		TopInspectedDirs:    topDirs,
		OversizeFiles:       oversizeFiles,
		HashedOversizeFiles: hashedOversizeFiles,
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

	verdict, verdictReason := events.ComputeVerdict(allEmitted, alerts, warnings, notices, s.cfg.Scan.VerdictNoticesThreshold, s.cfg.Scan.WeakRules)
	partial := coverage.HasPartialCoverage() || len(modulesNotRun) > 0 || (os.Geteuid() != 0)

	procCov, persistCov, usersCov, netCov, kernelCov := s.collectModuleCoverage(isOffline)

	yCov := s.yaraEngine.Coverage()
	if !yCov.CompiledIn {
		modulesNotRun = append(modulesNotRun, "yara (not compiled in)")
	} else if yCov.NotRunReason != "" {
		modulesNotRun = append(modulesNotRun, fmt.Sprintf("yara (%s)", yCov.NotRunReason))
	} else if yCov.DemoRulesOnly {
		modulesNotRun = append(modulesNotRun, "yara (demo rules only, no real rule set loaded)")
	}

	if s.cfg.Scan.RedactHosts {
		for i := range coverage.OversizeFiles {
			coverage.OversizeFiles[i].Path = report.RedactHostsAndUsers(coverage.OversizeFiles[i].Path, hostname)
		}
		for i := range coverage.TopInspectedDirs {
			coverage.TopInspectedDirs[i].Dir = report.RedactHostsAndUsers(coverage.TopInspectedDirs[i].Dir, hostname)
		}
		if persistCov != nil {
			for i := range persistCov.UnreadablePaths {
				persistCov.UnreadablePaths[i].Path = report.RedactHostsAndUsers(persistCov.UnreadablePaths[i].Path, hostname)
				persistCov.UnreadablePaths[i].Reason = report.RedactHostsAndUsers(persistCov.UnreadablePaths[i].Reason, hostname)
			}
			for i := range persistCov.MaskedPaths {
				persistCov.MaskedPaths[i] = report.RedactHostsAndUsers(persistCov.MaskedPaths[i], hostname)
			}
		}
		if usersCov != nil {
			for i := range usersCov.PrivilegedGroupMembers {
				usersCov.PrivilegedGroupMembers[i] = report.RedactHostsAndUsers(usersCov.PrivilegedGroupMembers[i], hostname)
			}
			for i := range usersCov.DockerLXDMembers {
				usersCov.DockerLXDMembers[i] = report.RedactHostsAndUsers(usersCov.DockerLXDMembers[i], hostname)
			}
		}
		for i := range startupNotices {
			startupNotices[i] = report.RedactHostsAndUsers(startupNotices[i], hostname)
		}
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

	if s.cfg.Scan.HTMLOut != "" {
		var posture, rationale string
		var actions []htmlreport.RemediationAction
		var timing map[string]string
		if s.executiveAssessmentFn != nil {
			posture, rationale, actions, timing = s.executiveAssessmentFn(allEmitted, events.ScanFinished{
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
		}

		reportData := htmlreport.HTMLReportData{
			Version:              ver,
			Commit:               s.commit,
			BuildDate:            bDate,
			BinaryName:           binName,
			Hostname:             hostname,
			ScanMode:             mode,
			StartTime:            startTime,
			Duration:             totalDuration,
			TargetPaths:          scanTargets,
			Excludes:             s.cfg.Scan.Excludes,
			Threads:              s.cfg.Scan.Threads,
			MaxFileSize:          s.cfg.Scan.MaxFileSize,
			Verdict:              verdict,
			VerdictReason:        verdictReason,
			Partial:              partial,
			RedactHosts:          s.cfg.Scan.RedactHosts,
			MaxReportFindings:    s.cfg.Scan.MaxReportFindings,
			TotalFindings:        totalFindings,
			Alerts:               alerts,
			Warnings:             warnings,
			Notices:              notices,
			Infos:                infos,
			FilesScanned:         filesScanned.Load(),
			AffectedFiles:        affectedFiles,
			Coverage:             coverage,
			ModulesRun:           modulesFinishedList,
			ModulesNotRun:        modulesNotRun,
			StartupNotices:       startupNotices,
			ProcessCoverage:      procCov,
			PersistenceCoverage:  persistCov,
			UsersCoverage:        usersCov,
			NetworkCoverage:      netCov,
			KernelCoverage:       kernelCov,
			YARACoverage:         &yCov,
			TopRules:             topRules,
			Findings:             allEmitted,
			AcknowledgedWarnings: acknowledgedWarnings,
			SystemPosture:        posture,
			PostureRationale:     rationale,
			RemediationPlan:      actions,
			DurationBreakdown:    timing,
		}
		if err := htmlreport.WriteHTMLReport(s.cfg.Scan.HTMLOut, reportData); err != nil {
			s.logger.Warn("failed to write HTML report", slog.Any("error", err), slog.String("path", s.cfg.Scan.HTMLOut))
			s.bus.Publish(events.Error{Time: time.Now(), Module: "report", Path: s.cfg.Scan.HTMLOut, Err: err, IsFatal: false})
		} else {
			s.logger.Info("wrote HTML report", slog.String("path", s.cfg.Scan.HTMLOut))
		}
	}

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

// isExcluded determines whether a path matches any configured exclude prefixes or configured rules directories.
func (s *Scanner) isExcluded(path string) bool {
	cleaned := filepath.Clean(path)
	for _, exc := range s.cfg.Scan.Excludes {
		excClean := filepath.Clean(exc)
		if cleaned == excClean || strings.HasPrefix(cleaned, excClean+string(filepath.Separator)) {
			return true
		}
	}
	if s.cfg != nil {
		for _, rDir := range s.cfg.Scan.ConfiguredRulesDirs() {
			if rDir == "" {
				continue
			}
			rClean := filepath.Clean(rDir)
			if cleaned == rClean || strings.HasPrefix(cleaned, rClean+string(filepath.Separator)) {
				return true
			}
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
	case report.SeverityCritical:
		return 6
	case report.SeverityAlert:
		return 5
	case report.SeverityHigh:
		return 4
	case report.SeverityWarning:
		return 3
	case report.SeverityMedium:
		return 2
	case report.SeverityNotice:
		return 2
	case report.SeverityLow:
		return 1
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
