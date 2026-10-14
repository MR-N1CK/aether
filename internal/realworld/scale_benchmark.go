package realworld

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/pkgdb"
	"aether/internal/report"
)

// MemoryStats holds snapshot metrics of resident set size and Go heap allocations.
type MemoryStats struct {
	RSSBytes       int64   `json:"rss_bytes"`
	RSSMB          float64 `json:"rss_mb"`
	AllocBytes     uint64  `json:"alloc_bytes"`
	AllocMB        float64 `json:"alloc_mb"`
	SysBytes       uint64  `json:"sys_bytes"`
	SysMB          float64 `json:"sys_mb"`
	HeapAllocBytes uint64  `json:"heap_alloc_bytes"`
	HeapAllocMB    float64 `json:"heap_alloc_mb"`
	NumGC          uint32  `json:"num_gc"`
}

// ReadCurrentRSS reads the resident set size of the current process via /proc/self/statm.
// On non-Linux or DAC-restricted environments, it gracefully falls back to runtime.MemStats.Sys.
func ReadCurrentRSS() (int64, error) {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		return int64(ms.Sys), nil
	}

	fields := strings.Fields(string(data))
	if len(fields) >= 2 {
		pages, err := strconv.ParseInt(fields[1], 10, 64)
		if err == nil && pages > 0 {
			pageSize := int64(os.Getpagesize())
			return pages * pageSize, nil
		}
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return int64(ms.Sys), nil
}

// ReadMemoryStats captures a comprehensive memory profile of the current process.
func ReadMemoryStats() MemoryStats {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	rss, err := ReadCurrentRSS()
	if err != nil || rss <= 0 {
		rss = int64(ms.Sys)
	}

	toMB := func(b uint64) float64 {
		return float64(b) / (1024 * 1024)
	}

	return MemoryStats{
		RSSBytes:       rss,
		RSSMB:          float64(rss) / (1024 * 1024),
		AllocBytes:     ms.Alloc,
		AllocMB:        toMB(ms.Alloc),
		SysBytes:       ms.Sys,
		SysMB:          toMB(ms.Sys),
		HeapAllocBytes: ms.HeapAlloc,
		HeapAllocMB:    toMB(ms.HeapAlloc),
		NumGC:          ms.NumGC,
	}
}

// MemoryTracker samples process memory periodically to determine peak RSS.
type MemoryTracker struct {
	mu           sync.Mutex
	interval     time.Duration
	stopCh       chan struct{}
	doneCh       chan struct{}
	baseline     MemoryStats
	peak         MemoryStats
	peakRSSBytes int64
}

// NewMemoryTracker creates an active memory sampler.
func NewMemoryTracker(interval time.Duration) *MemoryTracker {
	if interval <= 0 {
		interval = 20 * time.Millisecond
	}
	return &MemoryTracker{
		interval: interval,
	}
}

// Start begins periodic memory sampling in a background goroutine.
func (mt *MemoryTracker) Start() {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	mt.baseline = ReadMemoryStats()
	mt.peak = mt.baseline
	mt.peakRSSBytes = mt.baseline.RSSBytes
	mt.stopCh = make(chan struct{})
	mt.doneCh = make(chan struct{})

	go func() {
		defer close(mt.doneCh)
		ticker := time.NewTicker(mt.interval)
		defer ticker.Stop()

		for {
			select {
			case <-mt.stopCh:
				return
			case <-ticker.C:
				curr := ReadMemoryStats()
				mt.mu.Lock()
				if curr.RSSBytes > mt.peakRSSBytes {
					mt.peakRSSBytes = curr.RSSBytes
					mt.peak = curr
				}
				mt.mu.Unlock()
			}
		}
	}()
}

// Stop terminates sampling, takes a final sample, and returns the peak memory recorded.
func (mt *MemoryTracker) Stop() MemoryStats {
	mt.mu.Lock()
	if mt.stopCh != nil {
		select {
		case <-mt.stopCh:
			// already stopped
		default:
			close(mt.stopCh)
		}
		mt.mu.Unlock()
		<-mt.doneCh
	} else {
		mt.mu.Unlock()
	}

	final := ReadMemoryStats()
	mt.mu.Lock()
	defer mt.mu.Unlock()
	if final.RSSBytes > mt.peakRSSBytes {
		mt.peakRSSBytes = final.RSSBytes
		mt.peak = final
	}
	return mt.peak
}

// PeakRSSMB returns the peak recorded Resident Set Size in megabytes.
func (mt *MemoryTracker) PeakRSSMB() float64 {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	return float64(mt.peakRSSBytes) / (1024 * 1024)
}

// Baseline returns the memory profile captured at Start().
func (mt *MemoryTracker) Baseline() MemoryStats {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	return mt.baseline
}

// ScaleHierarchyResult represents the generated dense file tree on disk.
type ScaleHierarchyResult struct {
	RootDir            string        `json:"root_dir"`
	FileCount          int           `json:"file_count"`
	DirCount           int           `json:"dir_count"`
	TotalBytes         int64         `json:"total_bytes"`
	GenerationDuration time.Duration `json:"generation_duration"`
}

// Cleanup removes the generated directory tree.
func (r *ScaleHierarchyResult) Cleanup() error {
	if r.RootDir != "" && r.RootDir != "/" {
		return os.RemoveAll(r.RootDir)
	}
	return nil
}

// Realistic file templates representing varied content in Linux environments.
var scaleTemplates = [][]byte{
	[]byte("#!/bin/sh\n# System daemon worker\necho \"Service initialized\"\nexit 0\n"),
	[]byte("{\n  \"status\": \"healthy\",\n  \"workers\": 4,\n  \"timeout_sec\": 30\n}\n"),
	[]byte("[service]\nname=systemd-helper\nuser=daemon\nrestart=on-failure\n"),
	append([]byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00>\x00\x01\x00\x00\x00"), make([]byte, 128)...),
	[]byte("# Configuration file for Linux workstation\nDEBUG=0\nLOG_LEVEL=info\nCACHE_DIR=/var/cache\n"),
	[]byte("Aether scale benchmark synthetic asset verification record. Benign operational payload.\n"),
}

// GenerateScaleHierarchy creates a dense multi-level hierarchy of fileCount realistic files.
// Files are distributed across realistic directories with varied content types.
func GenerateScaleHierarchy(targetDir string, fileCount int) (*ScaleHierarchyResult, error) {
	start := time.Now()
	if targetDir == "" {
		tmp, err := os.MkdirTemp("", "aether-scale-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp scale dir: %w", err)
		}
		targetDir = tmp
	}

	// Base directories
	subdirs := []string{
		"usr/bin",
		"usr/sbin",
		"usr/lib",
		"usr/share/doc",
		"etc/default",
		"etc/conf.d",
		"var/log",
		"var/cache",
		"home/developer/projects",
		"home/developer/.config",
		"opt/tools",
		"tmp/build",
	}

	// Calculate how many sub-directories we need to distribute files evenly (e.g. ~100 files/dir)
	filesPerDir := 100
	numDirs := fileCount / filesPerDir
	if numDirs < len(subdirs) {
		numDirs = len(subdirs)
	}

	allDirs := make([]string, 0, numDirs)
	for i := 0; i < numDirs; i++ {
		base := subdirs[i%len(subdirs)]
		d := filepath.Join(targetDir, fmt.Sprintf("%s/pkg_%04d", base, i))
		allDirs = append(allDirs, d)
	}

	// Pre-create directories
	for _, d := range allDirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", d, err)
		}
	}

	// Generate files concurrently across workers
	numWorkers := runtime.NumCPU()
	if numWorkers < 4 {
		numWorkers = 4
	}
	if numWorkers > 16 {
		numWorkers = 16
	}

	var totalBytes atomic.Int64
	var completed atomic.Int64
	var wg sync.WaitGroup

	chunkSize := (fileCount + numWorkers - 1) / numWorkers

	for w := 0; w < numWorkers; w++ {
		startIdx := w * chunkSize
		endIdx := startIdx + chunkSize
		if endIdx > fileCount {
			endIdx = fileCount
		}
		if startIdx >= endIdx {
			break
		}

		wg.Add(1)
		go func(sIdx, eIdx int) {
			defer wg.Done()
			var localBytes int64

			for i := sIdx; i < eIdx; i++ {
				dir := allDirs[i%len(allDirs)]
				tmpl := scaleTemplates[i%len(scaleTemplates)]
				var ext string
				switch i % 6 {
				case 0:
					ext = ".sh"
				case 1:
					ext = ".json"
				case 2:
					ext = ".conf"
				case 3:
					ext = ".bin"
				case 4:
					ext = ".env"
				default:
					ext = ".txt"
				}

				fname := filepath.Join(dir, fmt.Sprintf("asset_%06d%s", i, ext))
				if err := os.WriteFile(fname, tmpl, 0644); err == nil {
					localBytes += int64(len(tmpl))
					completed.Add(1)
				}
			}
			totalBytes.Add(localBytes)
		}(startIdx, endIdx)
	}

	wg.Wait()

	return &ScaleHierarchyResult{
		RootDir:            targetDir,
		FileCount:          int(completed.Load()),
		DirCount:           len(allDirs),
		TotalBytes:         totalBytes.Load(),
		GenerationDuration: time.Since(start),
	}, nil
}

// ScannerRunner defines a pluggable scanner executor function to avoid package dependency cycles.
type ScannerRunner func(ctx context.Context, cfg *config.Config, bus *events.EventBus, rep report.Reporter, pkgDB pkgdb.PackageDB) error

var (
	defaultScannerRunnerMu sync.RWMutex
	defaultScannerRunner   ScannerRunner
)

// SetDefaultScannerRunner registers a default scanner executor for benchmark runs.
func SetDefaultScannerRunner(runner ScannerRunner) {
	defaultScannerRunnerMu.Lock()
	defer defaultScannerRunnerMu.Unlock()
	defaultScannerRunner = runner
}

func getDefaultScannerRunner() ScannerRunner {
	defaultScannerRunnerMu.RLock()
	defer defaultScannerRunnerMu.RUnlock()
	return defaultScannerRunner
}

// ScaleBenchmarkConfig specifies configuration parameters for a scale test run.
type ScaleBenchmarkConfig struct {
	FileCount     int           `json:"file_count"`
	TargetDir     string        `json:"target_dir"`
	MaxMemoryMB   float64       `json:"max_memory_mb"`  // default 250.0 MB
	MinThroughput float64       `json:"min_throughput"` // default 2500 files/sec
	SampleRate    time.Duration `json:"sample_rate"`    // default 20ms
	Threads       int           `json:"threads"`        // 0 = default NumCPU
	Runner        ScannerRunner `json:"-"`
}

// ScaleBenchmarkResult contains performance and memory metrics from a scale benchmark run.
type ScaleBenchmarkResult struct {
	FileCount             int               `json:"file_count"`
	FilesScanned          int64             `json:"files_scanned"`
	Duration              DurationBreakdown `json:"duration"`
	TotalDuration         time.Duration     `json:"total_duration"`
	ThroughputFilesPerSec float64           `json:"throughput_files_per_sec"`
	PeakMemoryMB          float64           `json:"peak_memory_mb"`
	BaselineMemoryMB      float64           `json:"baseline_memory_mb"`
	MemoryWithinBudget    bool              `json:"memory_within_budget"`
	ThroughputTargetMet   bool              `json:"throughput_target_met"`
	FindingsCount         int               `json:"findings_count"`
	AlertsCount           int               `json:"alerts_count"`
}

// RunScaleBenchmark executes Aether scanning over a scale hierarchy while actively tracking
// RSS memory and throughput bounds.
func RunScaleBenchmark(ctx context.Context, cfg ScaleBenchmarkConfig) (*ScaleBenchmarkResult, error) {
	if cfg.MaxMemoryMB <= 0 {
		cfg.MaxMemoryMB = 250.0
	}
	if cfg.MinThroughput <= 0 {
		cfg.MinThroughput = 2500.0
	}
	if cfg.SampleRate <= 0 {
		cfg.SampleRate = 20 * time.Millisecond
	}

	var hierarchy *ScaleHierarchyResult
	targetDir := cfg.TargetDir
	if targetDir == "" {
		if cfg.FileCount <= 0 {
			cfg.FileCount = 10000
		}
		var err error
		hierarchy, err = GenerateScaleHierarchy("", cfg.FileCount)
		if err != nil {
			return nil, fmt.Errorf("failed to generate scale hierarchy: %w", err)
		}
		defer hierarchy.Cleanup()
		targetDir = hierarchy.RootDir
	}

	// Setup memory tracking
	tracker := NewMemoryTracker(cfg.SampleRate)
	tracker.Start()
	defer tracker.Stop()

	// Setup metrics collector
	collector := NewSubsystemMetricsCollector()

	// Configure Aether scan
	scanCfg := config.NewDefaultConfig()
	scanCfg.Scan.Root = "/"
	scanCfg.Scan.Paths = []string{targetDir}
	scanCfg.Scan.ExplicitPaths = true
	scanCfg.Scan.DemoRules = true
	scanCfg.Scan.RulesDir = ""
	scanCfg.Scan.TrustRulesDir = false
	if cfg.Threads > 0 {
		scanCfg.Scan.Threads = cfg.Threads
	}

	bus := events.NewEventBus()
	sub := collector.AttachBus(bus)
	defer bus.Unsubscribe(sub)

	rep, err := report.NewConcurrentReporter("")
	if err != nil {
		return nil, fmt.Errorf("failed to create reporter: %w", err)
	}
	bus.AttachReporter(rep)

	pkgDB := pkgdb.New("")

	var scanFin *events.ScanFinished
	var mu sync.Mutex
	doneCh := make(chan struct{})
	scanSub := bus.Subscribe()

	go func() {
		defer close(doneCh)
		for ev := range scanSub.Events() {
			if sf, ok := ev.(events.ScanFinished); ok {
				mu.Lock()
				scanFin = &sf
				mu.Unlock()
			}
		}
	}()

	runner := cfg.Runner
	if runner == nil {
		runner = getDefaultScannerRunner()
	}
	if runner == nil {
		return nil, fmt.Errorf("no ScannerRunner configured for scale benchmark")
	}

	start := time.Now()
	scanErr := runner(ctx, scanCfg, bus, rep, pkgDB)
	totalDur := time.Since(start)

	peakMem := tracker.Stop()
	bus.Unsubscribe(scanSub)
	bus.Close()
	<-doneCh

	if scanErr != nil {
		return nil, fmt.Errorf("scanner execution failed: %w", scanErr)
	}

	mu.Lock()
	defer mu.Unlock()

	var filesScanned int64
	var findingsCount, alertsCount int
	if scanFin != nil {
		filesScanned = scanFin.FilesScanned
		findingsCount = scanFin.TotalFindings
		alertsCount = scanFin.Alerts
	} else if hierarchy != nil {
		filesScanned = int64(hierarchy.FileCount)
	}

	breakdown := collector.CalculateBreakdown(totalDur)
	throughput := collector.CalculateThroughput(filesScanned, totalDur)

	return &ScaleBenchmarkResult{
		FileCount:             cfg.FileCount,
		FilesScanned:          filesScanned,
		Duration:              breakdown,
		TotalDuration:         totalDur,
		ThroughputFilesPerSec: throughput,
		PeakMemoryMB:          peakMem.RSSMB,
		BaselineMemoryMB:      tracker.Baseline().RSSMB,
		MemoryWithinBudget:    peakMem.RSSMB <= cfg.MaxMemoryMB,
		ThroughputTargetMet:   throughput >= cfg.MinThroughput,
		FindingsCount:         findingsCount,
		AlertsCount:           alertsCount,
	}, nil
}
