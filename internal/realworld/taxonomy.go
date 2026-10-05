package realworld

import "strings"

// AnomalyTaxonomyCategory defines the structured root cause for a validation anomaly.
type AnomalyTaxonomyCategory string

const (
	// False-Positive Root Causes
	TaxonomyMissingContext     AnomalyTaxonomyCategory = "FP_MISSING_CONTEXT"
	TaxonomyWeakHeuristic      AnomalyTaxonomyCategory = "FP_WEAK_HEURISTIC"
	TaxonomyDualUseTool        AnomalyTaxonomyCategory = "FP_DUAL_USE_TOOL"
	TaxonomyPackageMismatch    AnomalyTaxonomyCategory = "FP_PACKAGE_MISMATCH"
	TaxonomyRuntimeRace        AnomalyTaxonomyCategory = "FP_RUNTIME_RACE"
	TaxonomyNamespaceIsolation AnomalyTaxonomyCategory = "FP_NAMESPACE_ISOLATION"
	TaxonomyEnvironmental      AnomalyTaxonomyCategory = "FP_ENVIRONMENTAL"

	// False-Negative Root Causes
	TaxonomyCollectionGap      AnomalyTaxonomyCategory = "FN_COLLECTION_GAP"
	TaxonomyDetectorGap        AnomalyTaxonomyCategory = "FN_DETECTOR_GAP"
	TaxonomyOverSuppression    AnomalyTaxonomyCategory = "FN_CONTEXT_SUPPRESSION"
	TaxonomyCorrelationGap     AnomalyTaxonomyCategory = "FN_CORRELATION_GAP"
	TaxonomyPermissionBoundary AnomalyTaxonomyCategory = "FN_PERMISSION_LIMITATION"
)

func (c AnomalyTaxonomyCategory) String() string {
	return string(c)
}

// FalsePositiveTaxonomyRecord documents and categorizes a field anomaly to drive deterministic regression prevention.
type FalsePositiveTaxonomyRecord struct {
	AnomalyID          string                  `json:"anomaly_id"`
	RuleName           string                  `json:"rule_name"`
	TargetPath         string                  `json:"target_path"`
	Category           AnomalyTaxonomyCategory `json:"category"`
	ObservedVerdict    string                  `json:"observed_verdict"`
	ExpectedVerdict    string                  `json:"expected_verdict"`
	RootCauseAnalysis  string                  `json:"root_cause_analysis"`
	ProposedMitigation string                  `json:"proposed_mitigation"`
	RegressionFixture  string                  `json:"regression_fixture"` // Path to regression fixture
}

// CoverageGap documents an inaccessible subsystem or target due to permission boundaries.
type CoverageGap struct {
	Subsystem   string `json:"subsystem"`             // "process", "filesystem", "users", "network"
	TargetPath  string `json:"target_path"`
	Reason      string `json:"reason"`                // e.g. "EACCES: permission denied"
	Remediation string `json:"remediation,omitempty"` // e.g. "Run with sudo or CAP_DAC_OVERRIDE"
}

// PrioritizedAction represents an actionable executive containment or remediation step.
type PrioritizedAction struct {
	Priority    int    `json:"priority"`              // 1 = Critical, 2 = High, 3 = Moderate, 4 = Low
	Title       string `json:"title"`
	Description string `json:"description"`
	Command     string `json:"command,omitempty"`
}

// CategorizeAnomaly performs automated categorization of an observed anomaly into the taxonomy.
func CategorizeAnomaly(ruleName, targetPath, reason, observedVerdict, expectedVerdict string) AnomalyTaxonomyCategory {
	lowerRule := strings.ToLower(ruleName)
	lowerPath := strings.ToLower(targetPath)
	lowerReason := strings.ToLower(reason)

	// Permission limitations
	if strings.Contains(lowerReason, "eacces") || strings.Contains(lowerReason, "permission denied") {
		return TaxonomyPermissionBoundary
	}

	// Runtime races (vanished proc/fd)
	if strings.Contains(lowerReason, "vanished") || strings.Contains(lowerReason, "no such process") || strings.Contains(lowerReason, "enoent") {
		return TaxonomyRuntimeRace
	}

	// Dual-use tools
	if strings.Contains(lowerPath, "metasploit") || strings.Contains(lowerPath, "nmap") ||
		strings.Contains(lowerPath, "wireshark") || strings.Contains(lowerPath, "exploitdb") ||
		strings.Contains(lowerPath, "gdb") || strings.Contains(lowerRule, "dual_use") {
		return TaxonomyDualUseTool
	}

	// Namespace isolation
	if strings.Contains(lowerPath, "docker") || strings.Contains(lowerPath, "containerd") ||
		strings.Contains(lowerReason, "namespace") || strings.Contains(lowerReason, "container") {
		return TaxonomyNamespaceIsolation
	}

	// Package mismatch / replaced inode
	if strings.Contains(lowerReason, "package") || strings.Contains(lowerReason, "replaced") ||
		strings.Contains(lowerRule, "package") {
		return TaxonomyPackageMismatch
	}

	// Missing context (e.g. dev server, build tree, test file)
	if strings.Contains(lowerPath, "node_modules") || strings.Contains(lowerPath, "target/debug") ||
		strings.Contains(lowerPath, ".venv") || strings.Contains(lowerPath, "build_tree") ||
		strings.Contains(lowerReason, "loopback") || strings.Contains(lowerReason, "localhost") {
		return TaxonomyMissingContext
	}

	// If observed is false alert on benign heuristic
	if (observedVerdict == "MALICIOUS" || observedVerdict == "SUSPICIOUS") && expectedVerdict == "SAFE" {
		return TaxonomyWeakHeuristic
	}

	return TaxonomyEnvironmental
}
