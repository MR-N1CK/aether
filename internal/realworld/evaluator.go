package realworld

import (
	"fmt"
	"path/filepath"
	"strings"

	"aether/internal/report"
)

// ComplianceResult holds the detailed outcome of verifying actual scan findings against an independent manifest.
type ComplianceResult struct {
	ProfileID         string           `json:"profile_id"`
	Compliant         bool             `json:"compliant"`
	Violations        []string         `json:"violations,omitempty"`
	AlertsObserved    int              `json:"alerts_observed"`
	WarningsObserved  int              `json:"warnings_observed"`
	NoticesObserved   int              `json:"notices_observed"`
	InfosObserved     int              `json:"infos_observed"`
	UnknownsObserved  int              `json:"unknowns_observed"`
	TotalObserved     int              `json:"total_observed"`
	ExpectedStatus    SystemPosture    `json:"expected_status"`
	EvaluatedStatus   SystemPosture    `json:"evaluated_status"`
	ForbiddenTriggers []report.Finding `json:"forbidden_triggers,omitempty"`
}

// ComplianceEvaluator compares actual scan findings against ProfileManifest expectations without mutating detection state.
type ComplianceEvaluator struct{}

// NewComplianceEvaluator constructs an initialized ComplianceEvaluator.
func NewComplianceEvaluator() *ComplianceEvaluator {
	return &ComplianceEvaluator{}
}

// Evaluate compares observed findings against manifest ground truth and returns a detailed ComplianceResult.
func (e *ComplianceEvaluator) Evaluate(manifest *ProfileManifest, findings []report.Finding, evaluatedPosture SystemPosture) *ComplianceResult {
	res := &ComplianceResult{
		ProfileID:       manifest.ProfileID,
		Compliant:       true,
		ExpectedStatus:  manifest.ExpectedStatus,
		EvaluatedStatus: evaluatedPosture,
		TotalObserved:   len(findings),
	}

	// 1. Tally finding severities
	for _, f := range findings {
		switch f.Severity {
		case report.SeverityAlert, report.SeverityCritical:
			res.AlertsObserved++
		case report.SeverityWarning, report.SeverityHigh, report.SeverityMedium:
			res.WarningsObserved++
		case report.SeverityNotice, report.SeverityLow:
			res.NoticesObserved++
		case report.SeverityInfo:
			res.InfosObserved++
		}

		if f.Verdict == report.VerdictUnknown {
			res.UnknownsObserved++
		}
	}

	// 2. Validate alert ceiling
	if res.AlertsObserved > manifest.MaxAcceptableAlerts {
		res.Violations = append(res.Violations,
			fmt.Sprintf("observed %d alerts, exceeds manifest maximum of %d", res.AlertsObserved, manifest.MaxAcceptableAlerts))
	}

	// 3. Validate warning ceiling
	if res.WarningsObserved > manifest.MaxAcceptableWarnings {
		res.Violations = append(res.Violations,
			fmt.Sprintf("observed %d warnings, exceeds manifest maximum of %d", res.WarningsObserved, manifest.MaxAcceptableWarnings))
	}

	// 4. Validate forbidden findings
	for _, f := range findings {
		for _, forbidden := range manifest.ForbiddenFindings {
			if matchesRulePattern(forbidden.RulePattern, f.RuleName) {
				if forbidden.Severity == "" || strings.EqualFold(forbidden.Severity, string(f.Severity)) {
					res.ForbiddenTriggers = append(res.ForbiddenTriggers, f)
					res.Violations = append(res.Violations,
						fmt.Sprintf("forbidden finding triggered: rule %q on %s (severity %s, verdict %s): %s",
							f.RuleName, f.Path, f.Severity, f.Verdict, forbidden.Reason))
				}
			}
		}
	}

	// 5. Validate dual-use tool expectations
	for _, tool := range manifest.DualUseSoftware {
		for _, f := range findings {
			if isToolFinding(tool, f) {
				// Passive dual-use tools should remain safe / low severity
				if tool.ExpectedPassiveVerdict != "" && string(f.Verdict) != tool.ExpectedPassiveVerdict {
					// Check if this finding was elevated by attack indicators
					hasAttackSignal := false
					for _, indicator := range tool.CorroboratingAttackIndicators {
						if strings.Contains(strings.ToLower(f.Reason), strings.ToLower(indicator)) ||
							strings.Contains(strings.ToLower(f.RuleName), strings.ToLower(indicator)) {
							hasAttackSignal = true
							break
						}
					}

					if !hasAttackSignal {
						res.Violations = append(res.Violations,
							fmt.Sprintf("dual-use tool %s produced unexpected verdict %s (expected %s) without attack corroboration",
								tool.ToolName, f.Verdict, tool.ExpectedPassiveVerdict))
					}
				}
			}
		}
	}

	// 6. Validate evaluated system posture against manifest expectation
	if evaluatedPosture != "" && manifest.ExpectedStatus != "" && evaluatedPosture != manifest.ExpectedStatus {
		res.Violations = append(res.Violations,
			fmt.Sprintf("posture mismatch: evaluated %s, manifest expected %s", evaluatedPosture, manifest.ExpectedStatus))
	}

	if len(res.Violations) > 0 {
		res.Compliant = false
	}

	return res
}

func matchesRulePattern(pattern, ruleName string) bool {
	if pattern == ruleName {
		return true
	}
	matched, err := filepath.Match(pattern, ruleName)
	if err == nil && matched {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		if strings.HasPrefix(ruleName, prefix) {
			return true
		}
	}
	return false
}

func isToolFinding(tool DualUseSoftwareCatalogEntry, f report.Finding) bool {
	if strings.Contains(strings.ToLower(f.Path), strings.ToLower(tool.PrimaryBinary)) ||
		strings.Contains(strings.ToLower(f.RuleName), strings.ToLower(tool.ToolName)) {
		return true
	}
	for _, p := range tool.StandardPaths {
		if strings.HasPrefix(f.Path, p) {
			return true
		}
	}
	return false
}
