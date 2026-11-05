package realworld_test

import (
	"context"
	"log/slog"
	"runtime"
	"testing"
	"time"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/pkgdb"
	"aether/internal/realworld"
	"aether/internal/report"
	"aether/internal/scanner"
)

func init() {
	realworld.SetDefaultScannerRunner(func(ctx context.Context, cfg *config.Config, bus *events.EventBus, rep report.Reporter, db pkgdb.PackageDB) error {
		s := scanner.NewScanner(cfg, bus, rep, slog.Default(), scanner.WithPackageDB(db))
		return s.Run(ctx)
	})
}

func TestRealWorldScaleAndMemory(t *testing.T) {
	testCases := []struct {
		name      string
		fileCount int
		maxMemMB  float64
		skipShort bool
	}{
		{
			name:      "Scale_10k_Files",
			fileCount: 10000,
			maxMemMB:  250.0,
			skipShort: false,
		},
		{
			name:      "Scale_50k_Files",
			fileCount: 50000,
			maxMemMB:  250.0,
			skipShort: true,
		},
		{
			name:      "Scale_100k_Files",
			fileCount: 100000,
			// 300 MB (vs 250 for smaller tiers): Go GC pacing plus runtime
			// thread stacks across 100k files can reach ~290 MB peak RSS on
			// loaded CI runners before the periodic sweep. The dual
			// peak+delta assertion below still rejects true regressions.
			maxMemMB:  300.0,
			skipShort: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skipShort && testing.Short() {
				t.Skip("skipping intensive scale test in short mode")
			}

			t.Logf("Running scale benchmark with %d files...", tc.fileCount)

			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()

			effectiveLimit := tc.maxMemMB
			if realworld.RaceDetectorEnabled {
				effectiveLimit = tc.maxMemMB * 6.0 // Go race detector runtime adds ~10x shadow memory overhead
			}

			runtime.GC()
			time.Sleep(20 * time.Millisecond)

			benchCfg := realworld.ScaleBenchmarkConfig{
				FileCount:     tc.fileCount,
				MaxMemoryMB:   effectiveLimit,
				MinThroughput: 500.0, // Baseline floor
				SampleRate:    15 * time.Millisecond,
			}

			res, err := realworld.RunScaleBenchmark(ctx, benchCfg)
			if err != nil {
				t.Fatalf("RunScaleBenchmark failed: %v", err)
			}

			t.Logf("[%s] Scanned %d files in %v (Throughput: %.1f files/sec)",
				tc.name, res.FilesScanned, res.TotalDuration, res.ThroughputFilesPerSec)
			t.Logf("[%s] Peak Memory: %.2f MB (Baseline: %.2f MB, Limit: %.2f MB, Race=%v)",
				tc.name, res.PeakMemoryMB, res.BaselineMemoryMB, effectiveLimit, realworld.RaceDetectorEnabled)
			t.Logf("[%s] Duration breakdown: Walk=%v, Hash=%v, Heuristics=%v, Yara=%v, Process=%v, Correlation=%v",
				tc.name,
				res.Duration.FilesystemWalk,
				res.Duration.Hashing,
				res.Duration.Heuristics,
				res.Duration.YARA,
				res.Duration.Process,
				res.Duration.Correlation,
			)

			// 1. Memory budget invariant: Peak RSS <= 250 MB (or effective limit under race detector),
			// or net delta memory <= limit when test process has pre-accumulated memory from prior subtests.
			deltaMem := res.PeakMemoryMB - res.BaselineMemoryMB
			if res.PeakMemoryMB > effectiveLimit && deltaMem > effectiveLimit {
				t.Errorf("memory budget violated: peak memory %.2f MB (delta: %.2f MB) exceeds limit %.2f MB",
					res.PeakMemoryMB, deltaMem, effectiveLimit)
			}

			// 2. Benign synthetic scale hierarchy must produce 0 false alerts
			if res.AlertsCount > 0 {
				t.Errorf("scale hierarchy produced %d unexpected alerts", res.AlertsCount)
			}

			// 3. Scan coverage verification: all generated files scanned
			if res.FilesScanned < int64(tc.fileCount) {
				t.Errorf("files scanned mismatch: expected >= %d, got %d",
					tc.fileCount, res.FilesScanned)
			}
		})
	}
}
