package realworld

import (
	"fmt"
	"strings"

	"aether/internal/events"
	"aether/internal/report"
)

// AssessmentSynthesizer creates executive system assessments from findings and visibility gaps.
type AssessmentSynthesizer struct{}

// NewAssessmentSynthesizer constructs an AssessmentSynthesizer.
func NewAssessmentSynthesizer() *AssessmentSynthesizer {
	return &AssessmentSynthesizer{}
}

// Synthesize produces a ComprehensiveSystemAssessment adhering strictly to the contract schema and invariants.
func (s *AssessmentSynthesizer) Synthesize(findings []report.Finding, gaps []CoverageGap) ComprehensiveSystemAssessment {
	var alerts, warnings, notices, infos, unknowns int
	critical := make([]report.Finding, 0)
	suspicious := make([]report.Finding, 0)

	for _, f := range findings {
		switch f.Severity {
		case report.SeverityAlert, report.SeverityCritical:
			alerts++
			critical = append(critical, f)
		case report.SeverityWarning, report.SeverityHigh, report.SeverityMedium:
			warnings++
			suspicious = append(suspicious, f)
		case report.SeverityNotice, report.SeverityLow:
			notices++
		case report.SeverityInfo:
			infos++
		}

		if f.Verdict == report.VerdictUnknown {
			unknowns++
		}
	}

	var posture SystemPosture
	var rationale string

	hasOperationalNotice := false
	for _, f := range findings {
		if f.Severity == report.SeverityNotice && (f.RuleName == "Process_Deleted_Binary_Replaced" || strings.Contains(strings.ToLower(f.Reason), "restart needed")) {
			hasOperationalNotice = true
			break
		}
	}

	// Invariant:
	// 1. Alerts > 0 -> HIGH_RISK
	// 2. Unknowns > 0 or CoverageGaps > 0 without alerts -> LIMITED_VISIBILITY
	// 3. Warnings > 0 or hasOperationalNotice -> ATTENTION_REQUIRED
	// 4. Else -> SAFE
	if alerts > 0 {
		posture = PostureHighRisk
		rationale = fmt.Sprintf("High risk detected: %d confirmed alert(s) requiring immediate containment.", alerts)
	} else if len(gaps) > 0 || unknowns > 0 {
		posture = PostureLimitedVisibility
		totalHidden := len(gaps) + unknowns
		rationale = fmt.Sprintf("Limited visibility: %d target(s) uninspected due to DAC or capability boundaries; re-run with sudo for full visibility.", totalHidden)
	} else if warnings > 0 || hasOperationalNotice {
		posture = PostureAttentionRequired
		if hasOperationalNotice && warnings == 0 {
			rationale = "Attention required: pending daemon restart detected post-package upgrade."
		} else {
			rationale = fmt.Sprintf("Attention required: %d suspicious anomaly/warning(s) detected.", warnings)
		}
	} else {
		posture = PostureSafe
		rationale = "System posture is healthy. All inspected subsystems verified safe."
	}

	var actions []PrioritizedAction
	if alerts > 0 {
		actions = append(actions, PrioritizedAction{
			Priority:    1,
			Title:       "Isolate and Contain Active Threats",
			Description: "Immediate containment required for identified malicious processes and scripts.",
			Command:     "aether scan --full --plain",
		})
	}
	if posture == PostureLimitedVisibility || len(gaps) > 0 || unknowns > 0 {
		actions = append(actions, PrioritizedAction{
			Priority:    2,
			Title:       "Re-run with Root Privileges",
			Description: "Re-run Aether with sudo or grant CAP_DAC_OVERRIDE for complete system visibility.",
			Command:     "sudo aether scan --full",
		})
	}
	if (warnings > 0 || hasOperationalNotice) && alerts == 0 {
		actions = append(actions, PrioritizedAction{
			Priority:    3,
			Title:       "Review Anomalies and Pending Daemons",
			Description: "Investigate flagged warnings, unmapped sockets, or restart services running replaced executables.",
			Command:     "systemctl daemon-reload && systemctl restart <service>",
		})
	}
	if len(actions) == 0 {
		actions = append(actions, PrioritizedAction{
			Priority:    4,
			Title:       "Maintain Standard Baseline Monitoring",
			Description: "System is in a clean operational state. Continue routine auditing sweeps.",
			Command:     "aether scan --quick",
		})
	}

	return ComprehensiveSystemAssessment{
		Posture:            posture,
		SummaryRationale:   rationale,
		TotalFindings:      len(findings),
		AlertsCount:        alerts,
		WarningsCount:      warnings,
		NoticesCount:       notices,
		InfosCount:         infos,
		UnknownsCount:      unknowns,
		CriticalFindings:   critical,
		SuspiciousFindings: suspicious,
		VisibilityGaps:     gaps,
		NextActions:        actions,
	}
}

// CollectCoverageGaps derives standardized CoverageGap records from subsystem coverage statistics.
func CollectCoverageGaps(
	cov *events.CoverageStats,
	procCov *events.ProcessCoverageStats,
	usersCov *events.UsersCoverageStats,
	persistCov *events.PersistenceCoverageStats,
	netCov *events.NetworkCoverageStats,
	kernelCov *events.KernelCoverageStats,
) []CoverageGap {
	var gaps []CoverageGap

	if cov != nil && cov.SkippedPermission > 0 {
		gaps = append(gaps, CoverageGap{
			Subsystem:   "filesystem",
			TargetPath:  "filesystem paths",
			Reason:      fmt.Sprintf("EACCES: %d file(s) skipped due to permission denial", cov.SkippedPermission),
			Remediation: "Re-run scan with elevated root or CAP_DAC_OVERRIDE permissions.",
		})
	}

	if procCov != nil {
		if procCov.SkippedPermission > 0 || procCov.Limited > 0 {
			gaps = append(gaps, CoverageGap{
				Subsystem:   "process",
				TargetPath:  "/proc",
				Reason:      fmt.Sprintf("EACCES: %d process(es) had unreadable /proc/<pid>/exe or memory maps", procCov.SkippedPermission+procCov.Limited),
				Remediation: "Execute scan as root (or CAP_SYS_PTRACE) to inspect processes owned by other users.",
			})
		}
	}

	if usersCov != nil {
		if !usersCov.ShadowReadable || usersCov.ShadowGapNonRoot {
			gaps = append(gaps, CoverageGap{
				Subsystem:   "users",
				TargetPath:  "/etc/shadow",
				Reason:      "EACCES: password hash database (/etc/shadow) is unreadable by non-root user",
				Remediation: "Execute scan with sudo to verify password hashes and legacy algorithms.",
			})
		}
	}

	if persistCov != nil {
		for _, up := range persistCov.UnreadablePaths {
			gaps = append(gaps, CoverageGap{
				Subsystem:   "persistence",
				TargetPath:  up.Path,
				Reason:      up.Reason,
				Remediation: "Execute scan with sudo to inspect privileged persistence definitions.",
			})
		}
	}

	if netCov != nil {
		if netCov.UnmappedSocketsNonRoot > 0 {
			gaps = append(gaps, CoverageGap{
				Subsystem:   "network",
				TargetPath:  "/proc/net",
				Reason:      fmt.Sprintf("EACCES: %d socket(s) could not be mapped to process owners", netCov.UnmappedSocketsNonRoot),
				Remediation: "Execute scan as root to resolve socket inode ownership across users.",
			})
		}
	}

	if kernelCov != nil {
		if kernelCov.GapsNote != "" {
			gaps = append(gaps, CoverageGap{
				Subsystem:   "kernel",
				TargetPath:  "/sys/module",
				Reason:      kernelCov.GapsNote,
				Remediation: "Execute scan with elevated privileges for complete sysfs module inspection.",
			})
		}
	}

	return gaps
}

// SynthesizeFromScan compiles a ComprehensiveSystemAssessment directly from an events.ScanFinished event.
func (s *AssessmentSynthesizer) SynthesizeFromScan(findings []report.Finding, sf events.ScanFinished) ComprehensiveSystemAssessment {
	gaps := CollectCoverageGaps(
		&sf.Coverage,
		sf.ProcessCoverage,
		sf.UsersCoverage,
		sf.PersistenceCoverage,
		sf.NetworkCoverage,
		sf.KernelCoverage,
	)

	if len(findings) == 0 {
		for i := 0; i < sf.Alerts; i++ {
			findings = append(findings, report.Finding{Severity: report.SeverityAlert})
		}
		for i := 0; i < sf.Warnings; i++ {
			findings = append(findings, report.Finding{Severity: report.SeverityWarning})
		}
		for i := 0; i < sf.Notices; i++ {
			findings = append(findings, report.Finding{Severity: report.SeverityNotice})
		}
		for i := 0; i < sf.Infos; i++ {
			findings = append(findings, report.Finding{Severity: report.SeverityInfo})
		}
	}

	return s.Synthesize(findings, gaps)
}
