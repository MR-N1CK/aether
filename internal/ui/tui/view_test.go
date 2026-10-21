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
