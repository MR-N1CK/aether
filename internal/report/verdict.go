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

	// Third-party application & vendor trees. /opt is vendor add-on software
	// by FHS convention (Electron IDEs, browser components, JVM runtimes);
	// node_modules bundles, webapps, and shipped docs embed network debugging
	// snippets, shell one-liners in test fixtures, and security-tooling
	// strings as a matter of course. String-level evidence from these trees
	// is demoted pending runtime corroboration; hash IOCs never are.
	inVendorTree := strings.HasPrefix(lower, "/opt/") ||
		strings.Contains(lower, "/node_modules/") ||
		strings.Contains(lower, "/resources/app") ||
		strings.HasPrefix(lower, "/usr/share/nodejs/") ||
		strings.HasPrefix(lower, "/usr/lib/node_modules/") ||
		strings.HasPrefix(lower, "/usr/share/webapps/") ||
		strings.HasPrefix(lower, "/usr/share/doc/") ||
		strings.Contains(lower, "/vendor/")
	if inVendorTree {
		return "vendor_app_tree"
	}

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

		// Historical artifacts: shell/interpreter command histories and
		// non-executable log files are passive records. Attack patterns inside
		// them reflect previously typed or logged activity, not live payloads,
		// so they must never reach MALICIOUS on content alone. Executable files
		// (possible masquerading) and volatile staging paths stay "standard".
		inVolatile := strings.HasPrefix(lower, "/tmp/") || strings.HasPrefix(lower, "/var/tmp/") ||
			strings.HasPrefix(lower, "/dev/shm/") || strings.HasPrefix(lower, "/run/user/")
		isHistory := strings.HasSuffix(base, "_history") || base == ".sh_history" ||
			strings.HasSuffix(base, ".history") || base == "histfile"
		isLog := strings.HasSuffix(lower, ".log")
		isConf := strings.HasSuffix(lower, ".conf") || strings.HasSuffix(lower, ".cfg") ||
			strings.HasSuffix(lower, ".ini")
		if !inVolatile && (isHistory || isLog || isConf) {
			return "historical_artifact"
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

// isCryptographicMatch reports whether the finding's evidence is a hash IOC
// match — cryptographic certainty that no path context can soften.
func isCryptographicMatch(f *Finding) bool {
	if v, ok := f.Metadata["is_ioc_match"].(bool); ok && v {
		return true
	}
	if v, ok := f.Metadata["hash_match"].(bool); ok && v {
		return true
	}
	return strings.Contains(strings.ToLower(f.RuleName), "ioc") || strings.Contains(strings.ToLower(f.RuleName), "hash")
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

	// Unregistered rules default strictly to StrengthContextual
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

	case contextProfile == "historical_artifact":
		verdict = VerdictUnknown
		f.Severity = SeverityNotice
		f.Confidence = ConfidenceLow
		rationale = "Passive history or log record (non-executable); the matched pattern reflects previously recorded commands or logged activity rather than an active payload. Manually review the recorded command if the context is suspicious."

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

	case contextProfile == "vendor_app_tree" &&
		(evidenceStrength == StrengthDirect || evidenceStrength == StrengthCorroborated) &&
		!isCryptographicMatch(f):
		// String-level signatures (script one-liners, YARA strings) inside
		// third-party application trees are demoted pending corroboration:
		// embedded tooling, docs, and test fixtures are the common cause.
		// Cryptographic IOC hash matches keep full strength everywhere.
		verdict = VerdictSuspicious
		f.Severity = SeverityWarning
		f.Confidence = ConfidenceMedium
		rationale = "Direct content signature inside a third-party application or vendor tree; demoted pending independent corroboration (embedded network tooling, documentation, and test fixtures are the common benign cause)."

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
