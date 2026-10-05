package realworld_test

import (
	"encoding/json"
	"testing"

	"aether/internal/realworld"
	"aether/internal/report"
)

func TestAssessmentSynthesizer_PostureTransitions(t *testing.T) {
	synth := realworld.NewAssessmentSynthesizer()

	// 1. Clean findings -> SAFE
	assSafe := synth.Synthesize(nil, nil)
	if assSafe.Posture != realworld.PostureSafe {
		t.Errorf("Expected posture SAFE, got %s", assSafe.Posture)
	}

	// 2. Alert findings -> HIGH_RISK
	alertFindings := []report.Finding{
		{
			RuleName: "Ransomware_LockBit",
			Severity: report.SeverityAlert,
			Verdict:  report.VerdictMalicious,
			Path:     "/opt/crypt.sh",
		},
	}
	assAlert := synth.Synthesize(alertFindings, nil)
	if assAlert.Posture != realworld.PostureHighRisk {
		t.Errorf("Expected posture HIGH_RISK, got %s", assAlert.Posture)
	}
	if len(assAlert.CriticalFindings) != 1 {
		t.Errorf("Expected 1 critical finding, got %d", len(assAlert.CriticalFindings))
	}

	// 3. Warning findings without alerts -> ATTENTION_REQUIRED
	warnFindings := []report.Finding{
		{
			RuleName: "Process_Deleted_Binary_Replaced",
			Severity: report.SeverityWarning,
			Verdict:  report.VerdictSuspicious,
			Path:     "/proc/123/exe",
		},
	}
	assWarn := synth.Synthesize(warnFindings, nil)
	if assWarn.Posture != realworld.PostureAttentionRequired {
		t.Errorf("Expected posture ATTENTION_REQUIRED, got %s", assWarn.Posture)
	}
	if len(assWarn.SuspiciousFindings) != 1 {
		t.Errorf("Expected 1 suspicious finding, got %d", len(assWarn.SuspiciousFindings))
	}

	// 4. Coverage gaps without warnings/alerts -> LIMITED_VISIBILITY
	gaps := []realworld.CoverageGap{
		{
			Subsystem:   "process",
			TargetPath:  "/proc/1/exe",
			Reason:      "EACCES",
			Remediation: "Run with sudo",
		},
	}
	assGaps := synth.Synthesize(nil, gaps)
	if assGaps.Posture != realworld.PostureLimitedVisibility {
		t.Errorf("Expected posture LIMITED_VISIBILITY, got %s", assGaps.Posture)
	}
	if len(assGaps.VisibilityGaps) != 1 {
		t.Errorf("Expected 1 visibility gap, got %d", len(assGaps.VisibilityGaps))
	}
}

func TestAssessmentSynthesizer_SchemaCompliance(t *testing.T) {
	synth := realworld.NewAssessmentSynthesizer()

	findings := []report.Finding{
		{
			RuleName: "Process_Deleted_Binary_Replaced",
			Severity: report.SeverityNotice,
			Verdict:  report.VerdictSafe,
			Path:     "/usr/sbin/nginx",
			Reason:   "Process binary was replaced on disk (restart needed)",
		},
	}
	gaps := []realworld.CoverageGap{
		{
			Subsystem:   "users",
			TargetPath:  "/etc/shadow",
			Reason:      "EACCES: permission denied",
			Remediation: "Run with sudo",
		},
	}

	ass := synth.Synthesize(findings, gaps)

	data, err := json.Marshal(ass)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	requiredFields := []string{
		"posture",
		"summary_rationale",
		"total_findings",
		"alerts_count",
		"warnings_count",
		"notices_count",
		"infos_count",
		"unknowns_count",
		"next_actions",
	}

	for _, field := range requiredFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("missing required field in assessment schema: %s", field)
		}
	}
}
