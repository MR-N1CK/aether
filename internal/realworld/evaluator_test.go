package realworld_test

import (
	"testing"

	"aether/internal/realworld"
	"aether/internal/report"
)

func TestComplianceEvaluator_PassCleanProfile(t *testing.T) {
	manifest := &realworld.ProfileManifest{
		ProfileID:             realworld.ProfileDesktopStandard,
		Version:               "1.0.0",
		ExpectedStatus:        realworld.PostureSafe,
		MaxAcceptableAlerts:   0,
		MaxAcceptableWarnings: 1,
		AcceptableFindings: []realworld.AcceptableFindingRule{
			{
				RuleName:         "Network_Loopback_Listener",
				PathPattern:      "/proc/*/fd/*",
				ExpectedSeverity: "INFO",
				ExpectedVerdict:  "SAFE",
				Reason:           "Desktop loopback socket",
			},
		},
		ForbiddenFindings: []realworld.ForbiddenFindingRule{
			{
				RulePattern: "Ransomware_*",
				Reason:      "No ransomware on clean desktop",
			},
		},
		DualUseSoftware: []realworld.DualUseSoftwareCatalogEntry{
			{
				ToolName:               "wireshark",
				PrimaryBinary:          "wireshark",
				ExpectedPassiveVerdict: "SAFE",
			},
		},
	}

	findings := []report.Finding{
		{
			RuleName: "Network_Loopback_Listener",
			Severity: report.SeverityInfo,
			Verdict:  report.VerdictSafe,
			Path:     "/proc/1000/fd/3",
		},
		{
			RuleName: "Package_Verified",
			Severity: report.SeverityInfo,
			Verdict:  report.VerdictSafe,
			Path:     "/usr/bin/wireshark",
		},
	}

	evaluator := realworld.NewComplianceEvaluator()
	result := evaluator.Evaluate(manifest, findings, realworld.PostureSafe)

	if !result.Compliant {
		t.Fatalf("Expected evaluation to pass, got violations: %v", result.Violations)
	}
	if result.AlertsObserved != 0 {
		t.Errorf("Expected 0 alerts, got %d", result.AlertsObserved)
	}
	if result.InfosObserved != 2 {
		t.Errorf("Expected 2 infos, got %d", result.InfosObserved)
	}
}

func TestComplianceEvaluator_FailAlertThreshold(t *testing.T) {
	manifest := &realworld.ProfileManifest{
		ProfileID:           realworld.ProfileServerMinimal,
		Version:             "1.0.0",
		ExpectedStatus:      realworld.PostureSafe,
		MaxAcceptableAlerts: 0,
	}

	findings := []report.Finding{
		{
			RuleName: "Script_Reverse_Shell_Interactive",
			Severity: report.SeverityAlert,
			Verdict:  report.VerdictMalicious,
			Path:     "/tmp/shell.sh",
		},
	}

	evaluator := realworld.NewComplianceEvaluator()
	result := evaluator.Evaluate(manifest, findings, realworld.PostureHighRisk)

	if result.Compliant {
		t.Fatalf("Expected evaluation to fail due to alert threshold violation")
	}
	if len(result.Violations) == 0 {
		t.Errorf("Expected violations, got 0")
	}
}

func TestComplianceEvaluator_FailForbiddenFinding(t *testing.T) {
	manifest := &realworld.ProfileManifest{
		ProfileID:           realworld.ProfileServerWeb,
		Version:             "1.0.0",
		ExpectedStatus:      realworld.PostureSafe,
		MaxAcceptableAlerts: 1, // Alert permitted by count, but forbidden by rule
		ForbiddenFindings: []realworld.ForbiddenFindingRule{
			{
				RulePattern: "Ransomware_*",
				Reason:      "Ransomware signature strictly forbidden",
			},
		},
	}

	findings := []report.Finding{
		{
			RuleName: "Ransomware_LockBit_Note",
			Severity: report.SeverityAlert,
			Verdict:  report.VerdictMalicious,
			Path:     "/var/www/README_TO_DECRYPT.txt",
		},
	}

	evaluator := realworld.NewComplianceEvaluator()
	result := evaluator.Evaluate(manifest, findings, realworld.PostureHighRisk)

	if result.Compliant {
		t.Fatalf("Expected evaluation to fail due to forbidden finding")
	}
	if len(result.ForbiddenTriggers) != 1 {
		t.Errorf("Expected 1 forbidden trigger, got %d", len(result.ForbiddenTriggers))
	}
}

func TestComplianceEvaluator_FailDualUseFalseAlert(t *testing.T) {
	manifest := &realworld.ProfileManifest{
		ProfileID:           realworld.ProfileWorkstationPentest,
		Version:             "1.0.0",
		ExpectedStatus:      realworld.PostureSafe,
		MaxAcceptableAlerts: 5,
		DualUseSoftware: []realworld.DualUseSoftwareCatalogEntry{
			{
				ToolName:                      "nmap",
				PrimaryBinary:                 "nmap",
				ExpectedPassiveVerdict:        "SAFE",
				CorroboratingAttackIndicators: []string{"active_scan_loop"},
			},
		},
	}

	// Finding flags nmap as malicious without any attack indicator
	findings := []report.Finding{
		{
			RuleName: "Suspicious_Tool_Nmap",
			Severity: report.SeverityAlert,
			Verdict:  report.VerdictMalicious,
			Path:     "/usr/bin/nmap",
			Reason:   "Port scanner binary present on disk",
		},
	}

	evaluator := realworld.NewComplianceEvaluator()
	result := evaluator.Evaluate(manifest, findings, realworld.PostureSafe)

	if result.Compliant {
		t.Fatalf("Expected evaluation to fail because passive nmap should not be malicious")
	}
}
