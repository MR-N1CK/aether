package benchmark

import (
	"testing"

	"aether/internal/report"
)

func TestEvaluator_MaliciousMatch(t *testing.T) {
	eval := NewEvaluator()
	c := BenchmarkCorpusCase{
		ID:          "MAL-001",
		Category:    CategoryMalicious,
		TargetPath:  "malicious/revshell.sh",
		Expected: ExpectedOutcome{
			ExpectedVerdict:   report.VerdictMalicious,
			AllowedSeverities: []report.Severity{report.SeverityAlert},
			MinConfidence:     report.ConfidenceHigh,
			ExpectedRules:     []string{"Script_Reverse_Shell"},
		},
	}

	finding := &report.Finding{
		Verdict:    report.VerdictMalicious,
		Severity:   report.SeverityAlert,
		Confidence: report.ConfidenceHigh,
		RuleName:   "Script_Reverse_Shell",
		EvidenceRecord: &report.EvidenceRecord{
			EvidenceStrength: report.StrengthDirect,
		},
		ConfidenceRationale: "Direct reverse shell detected",
	}

	res := eval.EvaluateCase(c, []*report.Finding{finding}, 10)
	if !res.Passed {
		t.Errorf("Expected case to pass, failed with: %s", res.FailureReason)
	}
	if res.ActualVerdict != report.VerdictMalicious {
		t.Errorf("Expected ActualVerdict MALICIOUS, got %s", res.ActualVerdict)
	}
}

func TestEvaluator_OverEscalation(t *testing.T) {
	eval := NewEvaluator()
	c := BenchmarkCorpusCase{
		ID:          "SUSP-001",
		Category:    CategorySuspicious,
		TargetPath:  "suspicious/installer.sh",
		Expected: ExpectedOutcome{
			ExpectedVerdict:   report.VerdictSuspicious,
			AllowedSeverities: []report.Severity{report.SeverityWarning},
		},
	}

	finding := &report.Finding{
		Verdict:    report.VerdictMalicious,
		Severity:   report.SeverityAlert,
		Confidence: report.ConfidenceHigh,
		RuleName:   "Script_Download_And_Execute",
	}

	res := eval.EvaluateCase(c, []*report.Finding{finding}, 10)
	if res.Passed {
		t.Errorf("Expected case to fail on over-escalation, but passed")
	}
	if res.FailureClassification != "OVER_ESCALATION" {
		t.Errorf("Expected failure classification OVER_ESCALATION, got %s", res.FailureClassification)
	}
}

func TestEvaluator_Abstention(t *testing.T) {
	eval := NewEvaluator()
	c := BenchmarkCorpusCase{
		ID:          "PARTIAL-001",
		Category:    CategoryPartialVisibility,
		TargetPath:  "partial_visibility/shadow",
		Expected: ExpectedOutcome{
			ExpectedVerdict:   report.VerdictUnknown,
			AllowedSeverities: []report.Severity{report.SeverityInfo},
		},
	}

	finding := &report.Finding{
		Verdict:    report.VerdictUnknown,
		Severity:   report.SeverityInfo,
		Confidence: report.ConfidenceLow,
		RuleName:   "Permission_Denied",
		Reason:     "Permission denied",
	}

	res := eval.EvaluateCase(c, []*report.Finding{finding}, 5)
	if !res.Passed {
		t.Errorf("Expected abstention case to pass, failed with: %s", res.FailureReason)
	}
}
