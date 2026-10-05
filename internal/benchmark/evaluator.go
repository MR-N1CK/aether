package benchmark

import (
	"fmt"
	"strings"

	"aether/internal/report"
)

// Evaluator compares findings produced by Aether against immutable ExpectedOutcome contracts.
type Evaluator struct{}

// NewEvaluator creates a new decision evaluator instance.
func NewEvaluator() *Evaluator {
	return &Evaluator{}
}

// EvaluateCase compares actual findings for a corpus case against its expected contract.
func (e *Evaluator) EvaluateCase(c BenchmarkCorpusCase, findings []*report.Finding, durationMs int64) BenchmarkResult {
	res := BenchmarkResult{
		CaseID:         c.ID,
		NormalizedPath: c.TargetPath,
		DurationMs:     durationMs,
	}

	// Consolidate findings for the case
	var topFinding *report.Finding
	var allRules []string
	var allCorroboration []string
	var highestSeverity report.Severity = report.SeverityInfo
	var highestConfidence report.Confidence = report.ConfidenceLow
	overallVerdict := report.VerdictSafe

	if len(findings) == 0 {
		// 0 findings defaults to SAFE with INFO severity
		overallVerdict = report.VerdictSafe
		highestSeverity = report.SeverityInfo
		highestConfidence = report.ConfidenceLow
	} else {
		// Evaluate top finding
		for _, f := range findings {
			if f == nil {
				continue
			}
			if f.RuleName != "" {
				allRules = append(allRules, f.RuleName)
			}
			if f.EvidenceRecord != nil {
				allCorroboration = append(allCorroboration, f.EvidenceRecord.CorroboratingSignals...)
			}

			// Prioritize MALICIOUS > SUSPICIOUS > UNKNOWN > SAFE
			if topFinding == nil || verdictRank(f.Verdict) > verdictRank(topFinding.Verdict) {
				topFinding = f
				overallVerdict = f.Verdict
			}
			if severityRank(f.Severity) > severityRank(highestSeverity) {
				highestSeverity = f.Severity
			}
			if confidenceRank(f.Confidence) > confidenceRank(highestConfidence) {
				highestConfidence = f.Confidence
			}
		}
	}

	res.ActualVerdict = overallVerdict
	res.ActualSeverity = highestSeverity
	res.ActualConfidence = highestConfidence
	res.ActualRules = deduplicateStrings(allRules)
	res.ActualCorroboration = deduplicateStrings(allCorroboration)

	if topFinding != nil {
		if topFinding.EvidenceRecord != nil {
			res.ActualStrength = string(topFinding.EvidenceRecord.EvidenceStrength)
		}
		res.ActualRationale = topFinding.ConfidenceRationale
	}

	// Perform assertions against ExpectedOutcome contract
	var failureReasons []string
	var failureClass string

	exp := c.Expected

	// 1. Verdict Assertion
	if exp.ExpectedVerdict != "" && exp.ExpectedVerdict != overallVerdict {
		failureReasons = append(failureReasons, fmt.Sprintf("Verdict mismatch: expected %s, got %s", exp.ExpectedVerdict, overallVerdict))

		switch {
		case exp.ExpectedVerdict == report.VerdictMalicious && overallVerdict != report.VerdictMalicious:
			failureClass = "FALSE_NEGATIVE"
		case exp.ExpectedVerdict == report.VerdictSafe && overallVerdict == report.VerdictMalicious:
			failureClass = "FALSE_POSITIVE"
		case exp.ExpectedVerdict == report.VerdictSuspicious && overallVerdict == report.VerdictMalicious:
			failureClass = "OVER_ESCALATION"
		case exp.ExpectedVerdict == report.VerdictSuspicious && overallVerdict == report.VerdictSafe:
			failureClass = "UNDER_CLASSIFICATION"
		case exp.ExpectedVerdict == report.VerdictUnknown && overallVerdict == report.VerdictSafe:
			failureClass = "FALSE_CLEAN"
		case exp.ExpectedVerdict == report.VerdictUnknown && overallVerdict != report.VerdictUnknown:
			failureClass = "ABSTENTION_FAILURE"
		default:
			failureClass = "WRONG_VERDICT"
		}
	}

	// 2. Allowed Severities Assertion
	if len(exp.AllowedSeverities) > 0 {
		matchedSev := false
		for _, s := range exp.AllowedSeverities {
			if s == highestSeverity {
				matchedSev = true
				break
			}
		}
		if !matchedSev {
			failureReasons = append(failureReasons, fmt.Sprintf("Severity mismatch: %s not in allowed %v", highestSeverity, exp.AllowedSeverities))
			if failureClass == "" {
				failureClass = "SEVERITY_MISMATCH"
			}
		}
	}

	// 3. Minimum Confidence Assertion
	if exp.MinConfidence != "" && confidenceRank(highestConfidence) < confidenceRank(exp.MinConfidence) {
		failureReasons = append(failureReasons, fmt.Sprintf("Confidence too low: expected min %s, got %s", exp.MinConfidence, highestConfidence))
		if failureClass == "" {
			failureClass = "CONFIDENCE_TOO_LOW"
		}
	}

	// 4. Expected Rules Assertion
	if len(exp.ExpectedRules) > 0 {
		for _, reqRule := range exp.ExpectedRules {
			found := false
			for _, r := range res.ActualRules {
				if strings.EqualFold(r, reqRule) {
					found = true
					break
				}
			}
			if !found {
				failureReasons = append(failureReasons, fmt.Sprintf("Missing expected rule: %s", reqRule))
				if failureClass == "" {
					failureClass = "MISSING_RULE"
				}
			}
		}
	}

	// 5. Expected Rationale Contains Assertion (only if findings were generated or non-empty rationale)
	if exp.ExpectedRationaleContains != "" && (len(findings) > 0 || res.ActualRationale != "") {
		if !strings.Contains(strings.ToLower(res.ActualRationale), strings.ToLower(exp.ExpectedRationaleContains)) {
			// For 0 findings on SAFE targets, clean pass is valid
			if len(findings) > 0 || exp.ExpectedVerdict != report.VerdictSafe {
				failureReasons = append(failureReasons, fmt.Sprintf("Rationale does not contain %q", exp.ExpectedRationaleContains))
				if failureClass == "" {
					failureClass = "RATIONALE_MISMATCH"
				}
			}
		}
	}

	if len(failureReasons) == 0 {
		res.Passed = true
	} else {
		res.Passed = false
		res.FailureReason = strings.Join(failureReasons, "; ")
		res.FailureClassification = failureClass
	}

	return res
}

func verdictRank(v report.Verdict) int {
	switch v {
	case report.VerdictMalicious:
		return 4
	case report.VerdictSuspicious:
		return 3
	case report.VerdictUnknown:
		return 2
	case report.VerdictSafe:
		return 1
	default:
		return 0
	}
}

func severityRank(s report.Severity) int {
	switch s {
	case report.SeverityCritical, report.SeverityAlert:
		return 4
	case report.SeverityHigh, report.SeverityWarning:
		return 3
	case report.SeverityMedium, report.SeverityNotice:
		return 2
	case report.SeverityLow, report.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func confidenceRank(c report.Confidence) int {
	switch c {
	case report.ConfidenceHigh:
		return 3
	case report.ConfidenceMedium:
		return 2
	case report.ConfidenceLow:
		return 1
	default:
		return 0
	}
}

func deduplicateStrings(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
