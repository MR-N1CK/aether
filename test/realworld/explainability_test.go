package realworld_test

import (
	"path/filepath"
	"strings"
	"testing"

	"aether/internal/benchmark"
	"aether/internal/report"
)

// TestRealWorldExplainabilityCompliance audits all real-world findings against the
// strict 8-question explainability standard (WHAT, WHERE, WHY, EVIDENCE, CONTEXT,
// CORROBORATION, CONFIDENCE, REMEDIATION).
func TestRealWorldExplainabilityCompliance(t *testing.T) {
	auditor := benchmark.NewExplainabilityAuditor()
	var allFindings []*report.Finding

	baseCorpus := findTestProfilesDir(t)

	profilesToAudit := []string{
		"workstation-pentest",
		"upgraded-pending",
		"container-host",
		"package-mixed",
		"server-web",
		"desktop-standard",
	}

	for _, pName := range profilesToAudit {
		profileDir := filepath.Join(baseCorpus, pName)
		_, findings, _, _ := runProfileAudit(t, profileDir)

		for i := range findings {
			// Ensure details are fully enriched for explainability
			report.PopulateFindingDetails(&findings[i])
			allFindings = append(allFindings, &findings[i])
		}
	}

	// Also audit an elevated weaponized finding scenario
	weaponizedFinding := report.Finding{
		Module:              "process",
		Severity:            report.SeverityAlert,
		Verdict:             report.VerdictMalicious,
		Confidence:          report.ConfidenceHigh,
		Title:               "Interactive Reverse Shell Execution",
		Path:                "/usr/bin/ncat",
		Why:                 "Active interactive reverse shell connected to remote network endpoint.",
		Reason:              "Weaponized network listener connected to remote host with spawned shell.",
		RuleName:            "Process_Reverse_Shell_Interactive",
		ConfidenceRationale: "Active network socket associated with spawned interactive shell process.",
		Remediation: []string{
			"Terminate the process immediately using kill -9.",
			"Inspect listening network connections and isolate host.",
		},
		EvidenceRecord: &report.EvidenceRecord{
			DetectorType:          "correlator",
			RuleName:              "Process_Reverse_Shell_Interactive",
			ContextProfile:        "workstation-pentest",
			PackageStatus:         "unverified",
			MatchedCondition:      "process.network_connection && process.command_line contains -e /bin/sh",
			ContributingDetectors: []string{"heuristic:network_socket", "process:sh_exec"},
		},
	}
	report.PopulateFindingDetails(&weaponizedFinding)
	allFindings = append(allFindings, &weaponizedFinding)

	if len(allFindings) == 0 {
		t.Fatalf("expected at least one finding across audited real-world profiles to evaluate explainability")
	}

	t.Logf("Auditing %d real-world finding(s) for 8-question explainability compliance...", len(allFindings))

	summary := auditor.AuditFindings(allFindings)

	// Assert 100% compliance across all 8 dimensions
	for question, rate := range summary.QuestionBreakdown {
		if rate < 1.0 {
			t.Errorf("Question %s failed 100%% compliance threshold: got %.2f%%", question, rate*100)
		}
	}

	if len(summary.FailedAudits) > 0 {
		for _, f := range summary.FailedAudits {
			t.Errorf("Finding [%s] at %s failed explainability: missing %s",
				f.RuleName, f.TargetPath, strings.Join(f.MissingElements, ", "))
		}
		t.Fatalf("Total non-compliant findings: %d / %d", len(summary.FailedAudits), len(allFindings))
	}

	t.Logf("100%% explainability compliance verified across %d real-world findings.", len(allFindings))
}
