package plain

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"aether/internal/events"
	"aether/internal/report"
	"aether/internal/ui/theme"
)

func TestRenderScanHeader(t *testing.T) {
	var buf bytes.Buffer
	th := theme.NewTheme(false)

	ev := events.ScanStarted{
		Time:       time.Now(),
		Version:    "0.2.0-hunt",
		Mode:       "full",
		Threads:    8,
		Paths:      []string{"/"},
		BinaryName: "aether",
	}

	RenderScanHeader(&buf, ev, th)
	out := buf.String()

	if !strings.Contains(out, "A E T H E R") {
		t.Errorf("header output missing AETHER branding, got:\n%s", out)
	}
	if !strings.Contains(out, "0.2.0-hunt") {
		t.Errorf("header output missing version, got:\n%s", out)
	}
}

func TestRenderFindingCard(t *testing.T) {
	var buf bytes.Buffer
	th := theme.NewTheme(false)

	f := report.NewFinding("persistence", report.SeverityAlert, "/var/www/shell.php", "Dynamic eval webshell detected", "SIGNATURE_BASE_WEBSHELL_PHP_Generic_Eval")
	f.LineNumber = 14
	f.Evidence = "eval(base64_decode($_POST['cmd']))"

	RenderFindingCard(&buf, f, th)
	out := buf.String()

	if !strings.Contains(out, "ALERT") {
		t.Errorf("card output missing severity ALERT, got:\n%s", out)
	}
	if !strings.Contains(out, "/var/www/shell.php:14") {
		t.Errorf("card output missing path with line number, got:\n%s", out)
	}
	if !strings.Contains(out, "T1505.003") {
		t.Errorf("card output missing MITRE technique, got:\n%s", out)
	}
}

func TestRenderFindingCard_VerdictAndRationale(t *testing.T) {
	var buf bytes.Buffer
	th := theme.NewTheme(false)

	f := report.Finding{
		Module:              "scanner",
		Severity:            report.SeverityAlert,
		Verdict:             report.VerdictMalicious,
		Confidence:          report.ConfidenceHigh,
		Title:               "Direct Trojan Binary",
		Path:                "/tmp/trojan",
		Reason:              "Reverse shell payload detected",
		RuleName:            "Script_Reverse_Shell_Interactive",
		ConfidenceRationale: "Direct high-confidence signature on unowned executable",
		EvidenceRecord: &report.EvidenceRecord{
			DetectorType:          "heuristic",
			RuleName:              "Script_Reverse_Shell_Interactive",
			ContributingDetectors: []string{"YARA_Reverse_Shell"},
		},
	}

	RenderFindingCard(&buf, f, th)
	out := buf.String()

	if !strings.Contains(out, "MALICIOUS") {
		t.Errorf("card output missing MALICIOUS verdict, got:\n%s", out)
	}
	if !strings.Contains(out, "Direct high-confidence signature on unowned executable") {
		t.Errorf("card output missing confidence rationale, got:\n%s", out)
	}
	if !strings.Contains(out, "YARA_Reverse_Shell") {
		t.Errorf("card output missing contributing detector corroboration, got:\n%s", out)
	}
}

func TestRiskLevelFromCounts(t *testing.T) {
	cases := []struct {
		name               string
		alerts, warn, notc int
		want               string
	}{
		{"alerts imply CRITICAL", 1, 0, 0, "CRITICAL"},
		{"alerts+many warnings imply CRITICAL", 2, 30, 40, "CRITICAL"},
		{"warnings alone are ELEVATED (not CRITICAL)", 0, 29, 20, "ELEVATED"},
		{"one warning is ELEVATED", 0, 1, 0, "ELEVATED"},
		{"notices alone are MODERATE", 0, 0, 9, "MODERATE"},
		{"nothing is LOW", 0, 0, 0, "LOW"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RiskLevelFromCounts(tc.alerts, tc.warn, tc.notc)
			if got != tc.want {
				t.Errorf("RiskLevelFromCounts(%d, %d, %d) = %q; want %q", tc.alerts, tc.warn, tc.notc, got, tc.want)
			}
		})
	}
}

func TestRenderExecutiveVerdict(t *testing.T) {
	var buf bytes.Buffer
	th := theme.NewTheme(false)

	ev := events.ScanFinished{
		TotalDuration: 2 * time.Second,
		TotalFindings: 5,
		Alerts:        1,
		Warnings:      2,
		Notices:       2,
		Infos:         10,
		Verdict:       events.VerdictCompromised,
		VerdictReason: "High-confidence threat detected",
		TopRules: []report.RuleSummary{
			{RuleName: "SIGNATURE_BASE_WEBSHELL_PHP_Generic_Eval", Severity: report.SeverityAlert, Count: 1},
			{RuleName: "File_Suspicious_Private_Key_Location", Severity: report.SeverityWarning, Count: 2},
		},
		Coverage: events.CoverageStats{
			FilesScanned: 50000,
		},
	}

	RenderExecutiveVerdict(&buf, ev, th)
	out := buf.String()

	if !strings.Contains(out, "CRITICAL") {
		t.Errorf("verdict output missing CRITICAL level, got:\n%s", out)
	}
	if !strings.Contains(out, "Score:") {
		t.Errorf("verdict output missing threat score, got:\n%s", out)
	}
	if !strings.Contains(out, "Top Triggered Detection Rules") {
		t.Errorf("verdict output missing top rules, got:\n%s", out)
	}
}
