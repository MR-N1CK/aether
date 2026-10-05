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
	"aether/internal/pkgdb"
	"aether/internal/realworld"
	"aether/internal/report"
	"aether/internal/scanner"
)

func findRegressionsDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for i := 0; i < 5; i++ {
		candidate := filepath.Join(dir, "testdata", "realworld_corpus", "regressions")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not find testdata/realworld_corpus/regressions")
	return ""
}

func seedDefaultRegressions(t *testing.T, regDir string) {
	t.Helper()
	writer := realworld.NewRegressionWriter(regDir)

	fixtures := []realworld.RegressionFixture{
		{
			AnomalyID:        "REG-FP-001",
			RuleName:         "Heuristic_Suspicious_Script",
			Category:         realworld.TaxonomyMissingContext,
			TargetPath:       "usr/share/ros/env.sh",
			ExpectedVerdict:  "SAFE",
			ExpectedSeverity: "INFO",
			Description:      "ROS robotics environment init script lacking package database entry",
			FileContents: map[string]string{
				"usr/share/ros/env.sh": "#!/bin/bash\nexport ROS_DISTRO=humble\nexport AMENT_PREFIX_PATH=/opt/ros/humble\n",
			},
		},
		{
			AnomalyID:        "REG-FP-002",
			RuleName:         "Heuristic_Dev_Server_Loopback",
			Category:         realworld.TaxonomyMissingContext,
			TargetPath:       "home/user/project/scripts/serve.py",
			ExpectedVerdict:  "SAFE",
			ExpectedSeverity: "INFO",
			Description:      "Local development HTTP server script in user workspace",
			FileContents: map[string]string{
				"home/user/project/scripts/serve.py": "import http.server\ndef run():\n    server = http.server.HTTPServer(('127.0.0.1', 8080), http.server.SimpleHTTPRequestHandler)\n",
			},
		},
	}

	for _, fix := range fixtures {
		fixPath := filepath.Join(regDir, fix.AnomalyID, "regression.json")
		if _, err := os.Stat(fixPath); os.IsNotExist(err) {
			if _, err := writer.WriteFixture(fix); err != nil {
				t.Fatalf("failed to seed regression fixture %s: %v", fix.AnomalyID, err)
			}
		}
	}
}

func TestFalsePositiveTaxonomyRegression(t *testing.T) {
	regDir := findRegressionsDir(t)
	seedDefaultRegressions(t, regDir)

	entries, err := os.ReadDir(regDir)
	if err != nil {
		t.Fatalf("ReadDir %s: %v", regDir, err)
	}

	writer := realworld.NewRegressionWriter(regDir)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		fixtureID := entry.Name()
		t.Run(fixtureID, func(t *testing.T) {
			fixDir := filepath.Join(regDir, fixtureID)
			fix, err := writer.LoadFixture(fixDir)
			if err != nil {
				t.Fatalf("LoadFixture failed for %s: %v", fixtureID, err)
			}

			t.Logf("[%s] Testing regression: Rule=%s Cat=%s ExpectedVerdict=%s",
				fix.AnomalyID, fix.RuleName, fix.Category, fix.ExpectedVerdict)

			rootFS := filepath.Join(fixDir, "rootfs")
			if _, err := os.Stat(rootFS); os.IsNotExist(err) {
				t.Fatalf("missing rootfs for regression fixture %s", fix.AnomalyID)
			}

			cfg := config.NewDefaultConfig()
			cfg.Scan.DemoRules = true
			cfg.Scan.Root = "/"
			cfg.Scan.Paths = []string{rootFS}
			cfg.Scan.ExplicitPaths = true
			cfg.Scan.Threads = 2
			cfg.Scan.Nice = 0

			bus := events.NewEventBus()
			defer bus.Close()
			rep, err := report.NewConcurrentReporter("")
			if err != nil {
				t.Fatalf("NewConcurrentReporter: %v", err)
			}
			defer rep.Close()
			bus.AttachReporter(rep)

			logger := slog.Default()
			pkgDB := pkgdb.New(rootFS)

			sc := scanner.NewScanner(cfg, bus, rep, logger,
				scanner.WithPackageDB(pkgDB),
			)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			if err := sc.Run(ctx); err != nil {
				t.Fatalf("Scanner.Run failed on regression fixture %s: %v", fix.AnomalyID, err)
			}

			findings := rep.Findings()

			// Invariant: Ingested field anomalies must NEVER produce false ALERT findings
			for _, f := range findings {
				if f.Severity == report.SeverityAlert || f.Verdict == report.VerdictMalicious {
					t.Errorf("[%s] Regression violated! False ALERT emitted: rule=%s, reason=%s",
						fix.AnomalyID, f.RuleName, f.Reason)
				}
			}

			// Validate category classification
			for _, f := range findings {
				cat := realworld.CategorizeAnomaly(f.RuleName, f.Path, f.Reason, string(f.Verdict), fix.ExpectedVerdict)
				t.Logf("[%s] Emitted finding: %s -> categorized as: %s", fix.AnomalyID, f.RuleName, cat)
			}
		})
	}
}
