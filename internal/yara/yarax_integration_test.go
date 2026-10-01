//go:build yara

package yara

import (
	"os"
	"path/filepath"
	"testing"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/report"
)

func TestYaraX_EmbeddedDemoRules(t *testing.T) {
	cfg := config.NewDefaultConfig()
	cfg.Scan.DemoRules = true
	engine := NewYaraXEngine(cfg, nil, false)
	defer engine.Close()

	if err := engine.LoadRules(nil); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	cov := engine.Coverage()
	if !cov.CompiledIn {
		t.Fatalf("expected CompiledIn = true")
	}
	if !cov.DemoRulesOnly {
		t.Fatalf("expected DemoRulesOnly = true")
	}
	if cov.RulesLoaded < 2 {
		t.Fatalf("expected at least 2 demo rules loaded, got %d", cov.RulesLoaded)
	}

	scanner := engine.NewScanner()
	defer scanner.Destroy()

	// 1. Scan EICAR payload
	eicarPayload := []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	matches, err := scanner.Scan(ScanTarget{
		Path:      "/tmp/eicar.com",
		Filename:  "eicar.com",
		Extension: ".com",
		Data:      eicarPayload,
	})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("expected match for EICAR payload")
	}
	m := matches[0]
	if m.RuleName != "Aether_Demo_EICAR" {
		t.Errorf("expected rule Aether_Demo_EICAR, got %s", m.RuleName)
	}
	if m.Score != 85 {
		t.Errorf("expected score 85, got %d", m.Score)
	}
	if !m.IsStrong {
		t.Errorf("expected IsStrong=true for score 85")
	}
	if m.Confidence != "high" {
		t.Errorf("expected confidence=high, got %s", m.Confidence)
	}
	if len(m.MatchedStrings) == 0 || m.MatchedStrings[0] != "$eicar" {
		t.Errorf("expected matched pattern identifier $eicar, got %v", m.MatchedStrings)
	}

	// 2. Scan Marker payload
	markerPayload := []byte("prefix AETHER_DEMO_TEST_MARKER_STRING suffix")
	mMatches, err := scanner.Scan(ScanTarget{
		Path:     "/tmp/test.txt",
		Filename: "test.txt",
		Data:     markerPayload,
	})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(mMatches) == 0 {
		t.Fatalf("expected match for marker payload")
	}
	if mMatches[0].RuleName != "Aether_Demo_Marker" {
		t.Errorf("expected rule Aether_Demo_Marker, got %s", mMatches[0].RuleName)
	}
	if mMatches[0].Score != 30 {
		t.Errorf("expected score 30, got %d", mMatches[0].Score)
	}
	if mMatches[0].Severity != report.SeverityNotice {
		t.Errorf("expected severity NOTICE for score 30, got %s", mMatches[0].Severity)
	}
}

func TestYaraX_Score60CannotAlertAlone(t *testing.T) {
	tempDir := t.TempDir()
	_ = os.Chmod(tempDir, 0755)

	ruleContent := `rule Weak_Threat {
    meta:
        score = 60
    strings:
        $s = "weak_threat_payload"
    condition:
        $s
}`
	ruleFile := filepath.Join(tempDir, "weak.yar")
	_ = os.WriteFile(ruleFile, []byte(ruleContent), 0644)

	cfg := config.NewDefaultConfig()
	engine := NewYaraXEngine(cfg, nil, false)
	defer engine.Close()

	if err := engine.LoadRules([]string{ruleFile}); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	scanner := engine.NewScanner()
	defer scanner.Destroy()

	matches, err := scanner.Scan(ScanTarget{
		Path: "/tmp/file.bin",
		Data: []byte("contains weak_threat_payload here"),
	})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Severity == report.SeverityAlert {
		t.Fatalf("score 60 must NOT be ALERT, got ALERT")
	}
	if matches[0].Severity != report.SeverityWarning {
		t.Errorf("expected WARNING for score 60, got %s", matches[0].Severity)
	}
	if matches[0].IsStrong {
		t.Errorf("expected IsStrong=false for score 60")
	}
}

func TestYaraX_ConfidenceHighRequiredForCompromised(t *testing.T) {
	tempDir := t.TempDir()
	_ = os.Chmod(tempDir, 0755)

	ruleNoConf := `rule Alert_No_Confidence {
    meta:
        score = 90
    strings:
        $s = "trigger_alert_1"
    condition:
        $s
}`
	ruleWithConf := `rule Alert_High_Confidence {
    meta:
        score = 90
        confidence = "high"
    strings:
        $s = "trigger_alert_2"
    condition:
        $s
}`
	file1 := filepath.Join(tempDir, "noconf.yar")
	file2 := filepath.Join(tempDir, "withconf.yar")
	_ = os.WriteFile(file1, []byte(ruleNoConf), 0644)
	_ = os.WriteFile(file2, []byte(ruleWithConf), 0644)

	cfg := config.NewDefaultConfig()
	engine := NewYaraXEngine(cfg, nil, false)
	defer engine.Close()

	_ = engine.LoadRules([]string{file1, file2})
	scanner := engine.NewScanner()
	defer scanner.Destroy()

	// 1. Without confidence="high"
	m1, _ := scanner.Scan(ScanTarget{Data: []byte("trigger_alert_1")})
	if len(m1) != 1 || m1[0].Severity != report.SeverityAlert {
		t.Fatalf("expected ALERT match for m1")
	}
	f1 := report.NewFinding("yara", m1[0].Severity, "/tmp/f1", "alert", m1[0].RuleName)
	f1.Metadata["confidence"] = m1[0].Confidence
	v1, _ := events.ComputeVerdict([]report.Finding{f1}, 1, 0, 0, 0)
	if v1 != events.VerdictSuspicious {
		t.Errorf("ALERT without confidence=high must result in SUSPICIOUS, got %s", v1)
	}

	// 2. With confidence="high"
	m2, _ := scanner.Scan(ScanTarget{Data: []byte("trigger_alert_2")})
	if len(m2) != 1 || m2[0].Severity != report.SeverityAlert {
		t.Fatalf("expected ALERT match for m2")
	}
	f2 := report.NewFinding("yara", m2[0].Severity, "/tmp/f2", "alert", m2[0].RuleName)
	f2.Metadata["confidence"] = m2[0].Confidence
	v2, _ := events.ComputeVerdict([]report.Finding{f2}, 1, 0, 0, 0)
	if v2 != events.VerdictCompromised {
		t.Errorf("ALERT with confidence=high must result in COMPROMISED, got %s", v2)
	}
}

func TestYaraX_TwoFilesSameRuleNameNamespaces(t *testing.T) {
	tempDir := t.TempDir()
	_ = os.Chmod(tempDir, 0755)

	ruleContent1 := `rule Duplicate_Name {
    meta:
        score = 60
    strings:
        $a = "test_dup_1"
    condition:
        $a
}`
	ruleContent2 := `rule Duplicate_Name {
    meta:
        score = 70
    strings:
        $a = "test_dup_2"
    condition:
        $a
}`

	file1 := filepath.Join(tempDir, "first.yar")
	file2 := filepath.Join(tempDir, "second.yar")
	_ = os.WriteFile(file1, []byte(ruleContent1), 0644)
	_ = os.WriteFile(file2, []byte(ruleContent2), 0644)

	cfg := config.NewDefaultConfig()
	engine := NewYaraXEngine(cfg, nil, false)
	defer engine.Close()

	if err := engine.LoadRules([]string{file1, file2}); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	cov := engine.Coverage()
	if cov.RulesLoaded != 2 {
		t.Fatalf("expected 2 rules loaded across namespaces, got %d", cov.RulesLoaded)
	}
	if cov.RulesFailed != 0 {
		t.Errorf("expected 0 failed rules, got %d", cov.RulesFailed)
	}
}

func TestYaraX_OneBrokenFileAmongGood(t *testing.T) {
	tempDir := t.TempDir()
	_ = os.Chmod(tempDir, 0755)

	goodRule := `rule Valid_Rule {
    strings:
        $v = "valid_content"
    condition:
        $v
}`
	brokenRule := `rule Broken_Rule {
    strings:
        $b = "broken"
    condition:
        syntax_error_here === ???
}`

	fileGood := filepath.Join(tempDir, "good.yar")
	fileBad := filepath.Join(tempDir, "bad.yar")
	_ = os.WriteFile(fileGood, []byte(goodRule), 0644)
	_ = os.WriteFile(fileBad, []byte(brokenRule), 0644)

	cfg := config.NewDefaultConfig()
	engine := NewYaraXEngine(cfg, nil, false)
	defer engine.Close()

	if err := engine.LoadRules([]string{fileGood, fileBad}); err != nil {
		t.Fatalf("LoadRules should not return fatal error when bad file is skipped: %v", err)
	}

	cov := engine.Coverage()
	if cov.RulesLoaded != 1 {
		t.Errorf("expected 1 valid rule loaded, got %d", cov.RulesLoaded)
	}
	if cov.RulesFailed != 1 {
		t.Errorf("expected 1 rule failed, got %d", cov.RulesFailed)
	}
	if len(cov.FailedFiles) != 1 || cov.FailedFiles[0] != fileBad {
		t.Errorf("expected failed file %s, got %v", fileBad, cov.FailedFiles)
	}
}

func TestYaraX_ExternalVariableFilename(t *testing.T) {
	tempDir := t.TempDir()
	_ = os.Chmod(tempDir, 0755)

	rule := `rule Filename_Check {
    strings:
        $payload = "trigger_payload"
    condition:
        $payload and filename == "special_exec.sh"
}`
	file := filepath.Join(tempDir, "ext_var.yar")
	_ = os.WriteFile(file, []byte(rule), 0644)

	cfg := config.NewDefaultConfig()
	engine := NewYaraXEngine(cfg, nil, false)
	defer engine.Close()

	if err := engine.LoadRules([]string{file}); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	scanner := engine.NewScanner()
	defer scanner.Destroy()

	payload := []byte("trigger_payload inside file")

	// 1. Scan with matching filename
	matches1, err := scanner.Scan(ScanTarget{
		Path:     "/tmp/special_exec.sh",
		Filename: "special_exec.sh",
		Data:     payload,
	})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(matches1) != 1 {
		t.Errorf("expected match when filename == special_exec.sh, got %d", len(matches1))
	}

	// 2. Scan with non-matching filename
	matches2, err := scanner.Scan(ScanTarget{
		Path:     "/tmp/other.sh",
		Filename: "other.sh",
		Data:     payload,
	})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(matches2) != 0 {
		t.Errorf("expected 0 matches when filename != special_exec.sh, got %d", len(matches2))
	}
}

func TestYaraX_DisabledRulesAndTags(t *testing.T) {
	tempDir := t.TempDir()
	_ = os.Chmod(tempDir, 0755)

	rule := `rule Disabled_Target : noise apt {
    strings:
        $t = "test_pattern"
    condition:
        $t
}`
	file := filepath.Join(tempDir, "rule.yar")
	_ = os.WriteFile(file, []byte(rule), 0644)

	// 1. Test disabled rule by name
	cfg1 := config.NewDefaultConfig()
	cfg1.Scan.DisabledRules = []string{"Disabled_Target"}
	engine1 := NewYaraXEngine(cfg1, nil, false)
	_ = engine1.LoadRules([]string{file})
	scanner1 := engine1.NewScanner()
	matches1, _ := scanner1.Scan(ScanTarget{Data: []byte("test_pattern")})
	if len(matches1) != 0 {
		t.Errorf("expected 0 matches when rule is disabled by name, got %d", len(matches1))
	}
	scanner1.Destroy()
	engine1.Close()

	// 2. Test disabled rule by tag
	cfg2 := config.NewDefaultConfig()
	cfg2.Scan.DisabledTags = []string{"noise"}
	engine2 := NewYaraXEngine(cfg2, nil, false)
	_ = engine2.LoadRules([]string{file})
	scanner2 := engine2.NewScanner()
	matches2, _ := scanner2.Scan(ScanTarget{Data: []byte("test_pattern")})
	if len(matches2) != 0 {
		t.Errorf("expected 0 matches when rule is disabled by tag, got %d", len(matches2))
	}
	scanner2.Destroy()
	engine2.Close()
}
