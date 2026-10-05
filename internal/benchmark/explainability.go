package benchmark

import (
	"strings"

	"aether/internal/report"
)

// ExplainabilityQuestion tracks an individual compliance question in the 8-question standard.
type ExplainabilityQuestion string

const (
	QuestionWhat          ExplainabilityQuestion = "WHAT"
	QuestionWhere         ExplainabilityQuestion = "WHERE"
	QuestionWhy           ExplainabilityQuestion = "WHY"
	QuestionEvidence      ExplainabilityQuestion = "EVIDENCE"
	QuestionContext       ExplainabilityQuestion = "CONTEXT"
	QuestionCorroboration ExplainabilityQuestion = "CORROBORATION"
	QuestionConfidence    ExplainabilityQuestion = "CONFIDENCE"
	QuestionRemediation   ExplainabilityQuestion = "REMEDIATION"
)

// ExplainabilityFindingAudit records the 8-question audit results for a single finding.
type ExplainabilityFindingAudit struct {
	FindingID       string                             `json:"finding_id"`
	RuleName        string                             `json:"rule_name"`
	TargetPath      string                             `json:"target_path"`
	IsCompliant     bool                               `json:"is_compliant"`
	QuestionsPassed map[ExplainabilityQuestion]bool    `json:"questions_passed"`
	MissingElements []string                           `json:"missing_elements,omitempty"`
}

// ExplainabilitySummary aggregates compliance across all emitted scan findings.
type ExplainabilitySummary struct {
	TotalFindings      int                                `json:"total_findings"`
	CompliantFindings  int                                `json:"compliant_findings"`
	ComplianceRate     float64                            `json:"compliance_rate"`
	QuestionBreakdown  map[ExplainabilityQuestion]float64 `json:"question_breakdown"`
	FailedAudits       []ExplainabilityFindingAudit       `json:"failed_audits,omitempty"`
}

// ExplainabilityAuditor verifies that findings satisfy the Aether 8-question explainability standard.
type ExplainabilityAuditor struct{}

// NewExplainabilityAuditor creates a new explainability auditor.
func NewExplainabilityAuditor() *ExplainabilityAuditor {
	return &ExplainabilityAuditor{}
}

// AuditFinding evaluates whether a single finding answers all 8 mandatory diagnostic questions.
func (a *ExplainabilityAuditor) AuditFinding(f *report.Finding) ExplainabilityFindingAudit {
	if f == nil {
		return ExplainabilityFindingAudit{
			IsCompliant: false,
			MissingElements: []string{"nil finding provided"},
		}
	}

	passed := make(map[ExplainabilityQuestion]bool)
	var missing []string

	// 1. WHAT: Clear title and rule name
	if strings.TrimSpace(f.Title) != "" && strings.TrimSpace(f.RuleName) != "" {
		passed[QuestionWhat] = true
	} else {
		missing = append(missing, "WHAT: missing Title or RuleName")
	}

	// 2. WHERE: Clear target path or paths
	targetPath := f.Path
	if targetPath == "" && len(f.Paths) > 0 {
		targetPath = f.Paths[0]
	}
	if strings.TrimSpace(targetPath) != "" {
		passed[QuestionWhere] = true
	} else {
		missing = append(missing, "WHERE: missing Path or Paths")
	}

	// 3. WHY: Plain-English explanation of security significance
	if strings.TrimSpace(f.Why) != "" && len(strings.TrimSpace(f.Why)) >= 10 {
		passed[QuestionWhy] = true
	} else {
		missing = append(missing, "WHY: missing or too brief Why explanation")
	}

	// 4. EVIDENCE: Matched condition, snippet, or reason
	hasEvidence := strings.TrimSpace(f.Reason) != "" || strings.TrimSpace(f.Evidence) != "" ||
		(f.EvidenceRecord != nil && strings.TrimSpace(f.EvidenceRecord.MatchedCondition) != "")
	if hasEvidence {
		passed[QuestionEvidence] = true
	} else {
		missing = append(missing, "EVIDENCE: missing forensic snippet, reason, or matched condition")
	}

	// 5. CONTEXT: Context profile and package status
	if f.EvidenceRecord != nil && strings.TrimSpace(f.EvidenceRecord.ContextProfile) != "" && strings.TrimSpace(f.EvidenceRecord.PackageStatus) != "" {
		passed[QuestionContext] = true
	} else if f.Context != "" {
		passed[QuestionContext] = true
	} else {
		missing = append(missing, "CONTEXT: missing EvidenceRecord with ContextProfile and PackageStatus")
	}

	// 6. CORROBORATION: Explicit corroborating signals structure
	if f.EvidenceRecord != nil {
		passed[QuestionCorroboration] = true
	} else {
		missing = append(missing, "CORROBORATION: missing EvidenceRecord structure")
	}

	// 7. CONFIDENCE: Confidence rating and plain-English rationale
	hasConfidence := (f.Confidence == report.ConfidenceHigh || f.Confidence == report.ConfidenceMedium || f.Confidence == report.ConfidenceLow) &&
		strings.TrimSpace(f.ConfidenceRationale) != ""
	if hasConfidence {
		passed[QuestionConfidence] = true
	} else {
		missing = append(missing, "CONFIDENCE: missing Confidence level or ConfidenceRationale")
	}

	// 8. REMEDIATION: Actionable containment steps
	if len(f.Remediation) > 0 && strings.TrimSpace(f.Remediation[0]) != "" {
		passed[QuestionRemediation] = true
	} else {
		missing = append(missing, "REMEDIATION: missing actionable remediation steps")
	}

	isCompliant := len(missing) == 0

	return ExplainabilityFindingAudit{
		FindingID:       f.ID,
		RuleName:        f.RuleName,
		TargetPath:      targetPath,
		IsCompliant:     isCompliant,
		QuestionsPassed: passed,
		MissingElements: missing,
	}
}

// AuditFindings evaluates a collection of findings and generates an aggregated summary.
func (a *ExplainabilityAuditor) AuditFindings(findings []*report.Finding) ExplainabilitySummary {
	if len(findings) == 0 {
		return ExplainabilitySummary{
			TotalFindings:     0,
			CompliantFindings: 0,
			ComplianceRate:    1.0,
			QuestionBreakdown: map[ExplainabilityQuestion]float64{
				QuestionWhat:          1.0,
				QuestionWhere:         1.0,
				QuestionWhy:           1.0,
				QuestionEvidence:      1.0,
				QuestionContext:       1.0,
				QuestionCorroboration: 1.0,
				QuestionConfidence:    1.0,
				QuestionRemediation:   1.0,
			},
		}
	}

	compliantCount := 0
	questionPassCounts := make(map[ExplainabilityQuestion]int)
	var failed []ExplainabilityFindingAudit

	for _, f := range findings {
		audit := a.AuditFinding(f)
		if audit.IsCompliant {
			compliantCount++
		} else {
			failed = append(failed, audit)
		}

		for q, p := range audit.QuestionsPassed {
			if p {
				questionPassCounts[q]++
			}
		}
	}

	breakdown := make(map[ExplainabilityQuestion]float64)
	questions := []ExplainabilityQuestion{
		QuestionWhat, QuestionWhere, QuestionWhy, QuestionEvidence,
		QuestionContext, QuestionCorroboration, QuestionConfidence, QuestionRemediation,
	}

	for _, q := range questions {
		breakdown[q] = float64(questionPassCounts[q]) / float64(len(findings))
	}

	rate := float64(compliantCount) / float64(len(findings))

	return ExplainabilitySummary{
		TotalFindings:     len(findings),
		CompliantFindings: compliantCount,
		ComplianceRate:    rate,
		QuestionBreakdown: breakdown,
		FailedAudits:      failed,
	}
}
