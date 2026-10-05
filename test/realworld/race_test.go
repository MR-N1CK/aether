package realworld_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/ioc"
	"aether/internal/modules"
	"aether/internal/modules/network"
	"aether/internal/modules/process"
	"aether/internal/pkgdb"
	"aether/internal/realworld"
	"aether/internal/report"
	"aether/internal/scanner"
)

func TestRuntimeRaceStress(t *testing.T) {
	tempDir := t.TempDir()
	scanRoot := filepath.Join(tempDir, "scan_root")
	if err := os.MkdirAll(scanRoot, 0755); err != nil {
		t.Fatalf("MkdirAll scanRoot: %v", err)
	}

	// Populate some baseline harmless files in scanRoot
	for i := 0; i < 20; i++ {
		fpath := filepath.Join(scanRoot, "base_"+string(rune('a'+i))+".txt")
		_ = os.WriteFile(fpath, []byte("benign text content\n"), 0644)
	}

	harness := realworld.NewRaceHarness(tempDir)
	harnessCtx, harnessCancel := context.WithCancel(context.Background())
	defer harnessCancel()

	harness.Start(harnessCtx)

	cfg := config.NewDefaultConfig()
	cfg.Scan.DemoRules = true
	cfg.Scan.Root = "/"
	cfg.Scan.Paths = []string{scanRoot}
	cfg.Scan.ExplicitPaths = true
	cfg.Scan.Threads = 4

	logger := slog.Default()
	iocEng, _ := ioc.NewEngine(cfg, logger)
	pkgDB := pkgdb.New("")

	// Execute 50 rapid inspection passes while active churn is ongoing (10 in short mode)
	iterations := 50
	if testing.Short() {
		iterations = 10
	}
	t.Logf("Executing %d concurrent race stress iterations...", iterations)

	for iter := 1; iter <= iterations; iter++ {
		bus := events.NewEventBus()
		rep, err := report.NewConcurrentReporter("")
		if err != nil {
			t.Fatalf("NewConcurrentReporter: %v", err)
		}
		bus.AttachReporter(rep)

		procMod := process.NewModule(iocEng, bus, logger)
		netMod := network.NewModule(iocEng, bus, logger)

		sc := scanner.NewScanner(cfg, bus, rep, logger,
			scanner.WithPackageDB(pkgDB),
			scanner.WithModules([]modules.Module{procMod, netMod}),
		)

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err = sc.Run(ctx)
		cancel()
		bus.Close()
		_ = rep.Close()

		if err != nil {
			t.Fatalf("Iteration %d failed with error: %v", iter, err)
		}

		findings := rep.Findings()
		for _, f := range findings {
			if f.Severity == report.SeverityAlert || f.Verdict == report.VerdictMalicious {
				t.Fatalf("Iteration %d produced false ALERT on benign churn: %s (%s)",
					iter, f.RuleName, f.Reason)
			}
		}
	}

	harness.Stop()
	procs, sockets, files := harness.Metrics()
	t.Logf("Race stress completed successfully across %d iterations.", iterations)
	t.Logf("Churn stats: %d processes spawned, %d sockets cycled, %d files unlinked.",
		procs, sockets, files)

	if procs == 0 && sockets == 0 {
		t.Errorf("Expected active churn to have occurred, but stats were 0")
	}
}
