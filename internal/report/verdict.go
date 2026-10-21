package report

import (
	"path/filepath"
	"strings"

	"aether/internal/pkgdb"
)

// ClassifyContextProfile determines whether an inspected path belongs to a known
// benign context profile such as doc metadata, package unit tests, or build trees.
func ClassifyContextProfile(path string, isExec bool, pkgOwned bool) string {
	lower := strings.ToLower(filepath.ToSlash(path))

	// Documentation & Metadata: .dist-info, .egg-info, METADATA, PKG-INFO, markdown, rst, text docs, readme
	if !isExec {
		base := filepath.Base(lower)
		if strings.Contains(lower, ".dist-info") || strings.Contains(lower, ".egg-info") ||
			strings.Contains(lower, "dist_info") || strings.Contains(lower, "egg_info") ||
			base == "metadata" || base == "pkg-info" ||
			strings.HasSuffix(lower, ".md") || strings.HasSuffix(lower, ".rst") ||
			strings.HasSuffix(lower, ".txt") || strings.Contains(lower, "readme") {
			return "doc_metadata"
		}
	}

	// Package Unit Test Fixtures: /test/, /tests/, test_*.py, *_test.py inside package trees
	if pkgOwned || strings.Contains(lower, "/usr/lib/") || strings.Contains(lower, "/usr/share/") {
		base := filepath.Base(lower)
		if strings.Contains(lower, "/test/") || strings.Contains(lower, "/tests/") ||
			strings.Contains(lower, "/testing/") ||
			strings.HasPrefix(base, "test_") ||
			strings.Contains(base, "_test.") {
			return "package_test"
		}
	}

	return "standard"
}

// EvaluateEvidenceStrength categorizes the intrinsic weight of detection evidence.
func EvaluateEvidenceStrength(ruleName, reason string, isPermissionDenied bool, corroboration []string) EvidenceStrength {
	if isPermissionDenied || strings.EqualFold(ruleName, "Permission_Denied") {
		return StrengthIncomplete
	}

	if len(corroboration) > 0 {
		return StrengthCorroborated
	}

	if meta, ok := LookupRuleMeta(ruleName); ok && meta.EvidenceStrength != "" {
		return meta.EvidenceStrength
	}

	rule := strings.ToLower(ruleName)
	reasonLower := strings.ToLower(reason)

	// Direct Strong Evidence rules
	if strings.Contains(rule, "reverse_shell") || strings.Contains(rule, "revshell") ||
		strings.Contains(rule, "netcat") || strings.Contains(rule, "socat") ||
		strings.Contains(rule, "ransomware") || strings.Contains(rule, "ransom") || strings.Contains(rule, "locker") ||
		strings.Contains(rule, "rootkit") || strings.Contains(rule, "ld_preload") ||
		strings.Contains(rule, "proc_hiding") || strings.Contains(rule, "process_hiding") ||
		strings.Contains(rule, "redteam") || strings.Contains(rule, "ghostshell") || strings.Contains(rule, "kali_master") ||
		strings.Contains(rule, "webshell") || strings.Contains(rule, "trojan") || strings.Contains(rule, "trojaned") ||
		strings.Contains(rule, "uid0") || strings.Contains(rule, "extra_uid0") ||
		strings.Contains(rule, "memfd") || strings.Contains(rule, "fileless") ||
		strings.Contains(rule, "volatile_path") || strings.Contains(rule, "authorized_key") ||
		strings.Contains(rule, "ioc") || strings.Contains(reasonLower, "ioc match") {
		return StrengthDirect
	}

	// Contextual / Dual-Use / Weak Anomaly
	return StrengthContextual
}

// DetermineVerdict evaluates findings against package ownership, context profiles,
// tiered evidence strength, and corroborating signals to compute the defensible Verdict.
func DetermineVerdict(f *Finding, pkgDB pkgdb.PackageDB, isExec bool, isDoc bool, isTestFixture bool, corroboration []string) Verdict {
	if f == nil {
		return VerdictUnknown
	}

	path := f.Path
	if path == "" && len(f.Paths) > 0 {
		path = f.Paths[0]
	}

	var pkgName string
	var pkgOwned bool
	if pkgDB != nil && path != "" {
		pkgName, pkgOwned = pkgDB.Owner(path)
	}

	packageStatus := "unowned"
	if pkgOwned {
		packageStatus = "verified_package"
	}

	// Classify context profile
	contextProfile := "standard"
	if isDoc {
		contextProfile = "doc_metadata"
	} else if isTestFixture {
		contextProfile = "package_test"
	} else if f.EvidenceRecord != nil && f.EvidenceRecord.ContextProfile != "" && f.EvidenceRecord.ContextProfile != "standard" {
		contextProfile = f.EvidenceRecord.ContextProfile
	} else {
		contextProfile = ClassifyContextProfile(path, isExec, pkgOwned)
	}

	// Check if this is a permission-denied / incomplete observation
	isPermissionDenied := strings.Contains(strings.ToLower(f.Reason), "permission denied") ||
		strings.EqualFold(f.RuleName, "Permission_Denied") ||
		strings.Contains(strings.ToLower(f.Reason), "eacces")

	evidenceStrength := f.EvidenceStrength
	if evidenceStrength == "" {
		evidenceStrength = EvaluateEvidenceStrength(f.RuleName, f.Reason, isPermissionDenied, corroboration)
	} else if isPermissionDenied || strings.EqualFold(f.RuleName, "Permission_Denied") {
		evidenceStrength = StrengthIncomplete
	} else if len(corroboration) > 0 {
		evidenceStrength = StrengthCorroborated
	}
	f.EvidenceStrength = evidenceStrength

	// Ensure EvidenceRecord is allocated
	if f.EvidenceRecord == nil {
		f.EvidenceRecord = &EvidenceRecord{
			DetectorType:     "heuristic",
			RuleName:         f.RuleName,
			TargetPath:       path,
			LineNumber:       f.LineNumber,
			MatchedCondition: f.Reason,
		}
	}
	f.EvidenceRecord.PackageName = pkgName
	f.EvidenceRecord.PackageStatus = packageStatus
	f.EvidenceRecord.ContextProfile = contextProfile
	f.EvidenceRecord.EvidenceStrength = evidenceStrength
	f.EvidenceRecord.CorroboratingSignals = corroboration

	var verdict Verdict
	var rationale string

	switch {
	case evidenceStrength == StrengthIncomplete || isPermissionDenied:
		verdict = VerdictUnknown
		f.Severity = SeverityInfo
		f.Confidence = ConfidenceLow
		rationale = "Insufficient visibility due to permission constraints (requires elevated root / CAP_DAC_OVERRIDE)."

	case f.Metadata != nil && f.Metadata["pentest_tool_path"] == true:
		verdict = VerdictSafe
		f.Severity = SeverityInfo
		f.Confidence = ConfidenceLow
		rationale = "Authorized penetration testing tool located in standard pentest package path."

	case strings.Contains(strings.ToLower(f.RuleName), "loopback_listener"):
		verdict = VerdictSafe
		f.Severity = SeverityInfo
		f.Confidence = ConfidenceLow
		rationale = "Local loopback listener for inter-process communication."

	case contextProfile == "doc_metadata":
		verdict = VerdictSafe
		f.Severity = SeverityNotice
		f.Confidence = ConfidenceLow
		rationale = "Inert documentation or package wheel metadata; not an executable payload."

	case contextProfile == "package_test":
		ruleLower := strings.ToLower(f.RuleName)
		// Package test fixtures with mock servers/listeners are safe
		if evidenceStrength != StrengthDirect || strings.Contains(ruleLower, "server") ||
			strings.Contains(ruleLower, "listener") || strings.Contains(ruleLower, "exfil") {
			verdict = VerdictSafe
			f.Severity = SeverityNotice
			f.Confidence = ConfidenceLow
			rationale = "Verified package unit test fixture or test mock."
		} else {
			// Direct strong payload in test directory
			if pkgOwned {
				verdict = VerdictSafe
				f.Severity = SeverityNotice
				f.Confidence = ConfidenceLow
				rationale = "Package-owned test asset; treated as non-active test mock."
			} else {
				verdict = VerdictMalicious
				f.Severity = SeverityAlert
				f.Confidence = ConfidenceHigh
				rationale = "Direct malware signature in unowned path."
			}
		}

	case contextProfile == "build_tree":
		verdict = VerdictSafe
		f.Severity = SeverityNotice
		f.Confidence = ConfidenceLow
		rationale = "Non-executable intermediate compilation artifact within verified build tree."

	case contextProfile == "container_namespace":
		if evidenceStrength == StrengthDirect {
			verdict = VerdictMalicious
			f.Severity = SeverityAlert
			f.Confidence = ConfidenceHigh
			rationale = "Direct malware signature or cryptographic IOC detected inside container namespace."
		} else if evidenceStrength == StrengthCorroborated {
			verdict = VerdictMalicious
			f.Severity = SeverityAlert
			f.Confidence = ConfidenceHigh
			rationale = "Multi-vector threat corroborated inside container namespace (" + strings.Join(corroboration, ", ") + ")."
		} else {
			verdict = VerdictSafe
			f.Severity = SeverityNotice
			f.Confidence = ConfidenceLow
			rationale = "Path-based operational anomaly within private container mount namespace."
		}

	case evidenceStrength == StrengthDirect:
		if pkgOwned {
			// Direct strong malware signature on package file (possible package trojan/compromise)
			verdict = VerdictMalicious
			f.Severity = SeverityAlert
			f.Confidence = ConfidenceHigh
			f.EvidenceRecord.PackageStatus = "modified_package"
			rationale = "Direct high-confidence malware signature detected on package-owned binary (possible trojan or compromise)."
		} else {
			// Direct strong malware signature on unowned file
			verdict = VerdictMalicious
			f.Severity = SeverityAlert
			f.Confidence = ConfidenceHigh
			rationale = "Direct unambiguous malware signature or cryptographic IOC match on unowned artifact."
		}

	case evidenceStrength == StrengthCorroborated:
		verdict = VerdictMalicious
		f.Severity = SeverityAlert
		f.Confidence = ConfidenceHigh
		rationale = "Suspicious behavior confirmed by independent operational corroboration (" + strings.Join(corroboration, ", ") + ")."

	case evidenceStrength == StrengthContextual:
		ruleLower := strings.ToLower(f.RuleName)
		if pkgOwned {
			if strings.Contains(ruleLower, "deleted_binary") {
				verdict = VerdictSuspicious
				f.Severity = SeverityNotice
				f.Confidence = ConfidenceLow
				rationale = "Package-managed binary running from unlinked image (likely pending service restart after package upgrade)."
			} else if strings.Contains(ruleLower, "listener") || strings.Contains(ruleLower, "socket") {
				verdict = VerdictSafe
				f.Severity = SeverityInfo
				f.Confidence = ConfidenceLow
				rationale = "Standard system daemon listening on authorized port."
			} else if f.Severity == SeverityWarning || (f.Metadata != nil && f.Metadata["original_severity"] == "ALERT") {
				verdict = VerdictSuspicious
				f.Severity = SeverityWarning
				f.Confidence = ConfidenceMedium
				rationale = "Package-owned script matching suspicious patterns; severity downgraded from ALERT to WARNING."
			} else {
				verdict = VerdictSafe
				f.Severity = SeverityNotice
				f.Confidence = ConfidenceLow
				rationale = "Contextual pattern on verified package file without corroborating execution signals."
			}
		} else {
			// Unowned contextual pattern
			verdict = VerdictSuspicious
			f.Severity = SeverityWarning
			f.Confidence = ConfidenceMedium
			rationale = "Contextual anomaly without independent corroborating execution or persistence signals."
		}

	default:
		verdict = VerdictSuspicious
		f.Severity = SeverityWarning
		f.Confidence = ConfidenceMedium
		rationale = "Uncorroborated anomaly requiring analyst review."
	}

	f.Verdict = verdict
	f.ConfidenceRationale = rationale
	f.EvidenceRecord.ConfidenceRationale = rationale

	return verdict
}
