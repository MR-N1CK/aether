package benchmark_test

import (
	"testing"

	"aether/internal/benchmark"
	"aether/internal/report"
)

func TestExplainabilityAuditor_CompliantFinding(t *testing.T) {
	auditor := benchmark.NewExplainabilityAuditor()

	f := report.NewFinding("scanner", report.SeverityAlert, "/tmp/rev.sh", "Bash reverse shell", "Script_Reverse_Shell_Interactive")
	report.PopulateFindingDetails(&f)
	report.DetermineVerdict(&f, nil, true, false, false, nil)

	audit := auditor.AuditFinding(&f)
	if !audit.IsCompliant {
		t.Fatalf("Expected finding to be compliant, but failed on: %v", audit.MissingElements)
	}

	summary := auditor.AuditFindings([]*report.Finding{&f})
	if summary.ComplianceRate != 1.0 {
		t.Errorf("Expected compliance rate 1.0, got %.2f", summary.ComplianceRate)
	}
}

func TestExplainabilityAuditor_NonCompliantFinding(t *testing.T) {
	auditor := benchmark.NewExplainabilityAuditor()

	// Finding with missing remediation, rationale, and why
	f := &report.Finding{
		ID:       "TEST-001",
		Path:     "/etc/test",
		RuleName: "Test_Rule",
	}

	audit := auditor.AuditFinding(f)
	if audit.IsCompliant {
		t.Fatalf("Expected incomplete finding to fail compliance audit")
	}

	if len(audit.MissingElements) == 0 {
		t.Fatalf("Expected missing elements to be recorded")
	}
}
