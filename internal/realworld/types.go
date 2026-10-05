package realworld

import (
	"encoding/json"
	"fmt"
	"time"

	"aether/internal/report"
)

// Standard environment profile IDs.
const (
	ProfileDesktopStandard     = "desktop-standard"
	ProfileWorkstationDev      = "workstation-dev"
	ProfileWorkstationPentest   = "workstation-pentest"
	ProfileServerWeb           = "server-web"
	ProfileServerMinimal       = "server-minimal"
	ProfileContainerHost       = "container-host"
	ProfilePackageMixed        = "package-mixed"
	ProfileUpgradedPending     = "upgraded-pending"
	ProfilePrivilegeRestricted = "privilege-restricted"
)

// SystemPosture represents the high-level security posture of an inspected host.
type SystemPosture string

const (
	PostureSafe              SystemPosture = "SAFE"
	PostureAttentionRequired SystemPosture = "ATTENTION_REQUIRED"
	PostureHighRisk          SystemPosture = "HIGH_RISK"
	PostureLimitedVisibility SystemPosture = "LIMITED_VISIBILITY"
)

func (p SystemPosture) String() string {
	return string(p)
}

// RealWorldEnvironmentProfile represents an environment class specification used to validate
// Aether under realistic Linux system conditions.
type RealWorldEnvironmentProfile struct {
	ProfileID             string        `json:"profile_id"`              // e.g. "desktop-standard", "workstation-pentest"
	Name                  string        `json:"name"`                    // Human-readable title
	Description           string        `json:"description"`             // Detailed environment description
	TargetDistribution    string        `json:"target_distribution"`     // "debian", "ubuntu", "fedora", "rhel", "arch"
	HasDualUseTools       bool          `json:"has_dual_use_tools"`      // True if pentest/debug tools are present
	HasActiveListeners    bool          `json:"has_active_listeners"`    // True if network services listen
	HasContainerWorkloads bool          `json:"has_container_workloads"` // True if Docker/Podman is active
	HasPendingUpgrades    bool          `json:"has_pending_upgrades"`    // True if replaced binaries exist
	ExpectedSystemStatus  SystemPosture `json:"expected_system_status"`  // Expected Posture (SAFE, ATTENTION, etc.)
}

// AcceptableFindingRule specifies a benign or operational finding allowed in a profile.
type AcceptableFindingRule struct {
	RuleName         string `json:"rule_name"`
	PathPattern      string `json:"path_pattern,omitempty"`
	ExpectedSeverity string `json:"expected_severity"`
	ExpectedVerdict  string `json:"expected_verdict"`
	Reason           string `json:"reason"`
}

// ForbiddenFindingRule specifies a finding rule that must never trigger on a profile.
type ForbiddenFindingRule struct {
	RulePattern string `json:"rule_pattern"` // Exact rule name or glob/regex
	Severity    string `json:"severity,omitempty"`
	Reason      string `json:"reason"`
}

// DualUseSoftwareCatalogEntry defines an authorized dual-use tool and expected behaviors.
type DualUseSoftwareCatalogEntry struct {
	ToolName                      string   `json:"tool_name"`
	PrimaryBinary                 string   `json:"primary_binary"`
	StandardPaths                 []string `json:"standard_paths,omitempty"`
	ExpectedPassiveSeverity       string   `json:"expected_passive_severity,omitempty"`
	ExpectedPassiveVerdict        string   `json:"expected_passive_verdict"`
	CorroboratingAttackIndicators []string `json:"corroborating_attack_indicators,omitempty"`
}

// ProfileManifest is the external, independent ground truth contract for an environment profile.
type ProfileManifest struct {
	ProfileID              string                        `json:"profile_id"`
	Version                string                        `json:"version"`
	ExpectedStatus         SystemPosture                 `json:"expected_status"`
	MaxAcceptableAlerts    int                           `json:"max_acceptable_alerts"`
	MaxAcceptableWarnings  int                           `json:"max_acceptable_warnings"`
	AcceptableFindings     []AcceptableFindingRule       `json:"acceptable_findings,omitempty"`
	ForbiddenFindings      []ForbiddenFindingRule        `json:"forbidden_findings,omitempty"`
	ExpectedCoverageLimits []string                      `json:"expected_coverage_limits,omitempty"`
	DualUseSoftware        []DualUseSoftwareCatalogEntry `json:"dual_use_software,omitempty"`
}

// DurationBreakdown captures granular timing telemetry across inspection subsystems.
type DurationBreakdown struct {
	FilesystemWalk time.Duration `json:"filesystem_walk"`
	Hashing        time.Duration `json:"hashing"`
	Heuristics     time.Duration `json:"heuristics"`
	YARA           time.Duration `json:"yara"`
	Process        time.Duration `json:"process"`
	Network        time.Duration `json:"network"`
	Persistence    time.Duration `json:"persistence"`
	Users          time.Duration `json:"users"`
	Kernel         time.Duration `json:"kernel"`
	Correlation    time.Duration `json:"correlation"`
	Reporting      time.Duration `json:"reporting"`
	Total          time.Duration `json:"total"`
}

type durationBreakdownJSON struct {
	FilesystemWalk string `json:"filesystem_walk,omitempty"`
	Hashing        string `json:"hashing,omitempty"`
	Heuristics     string `json:"heuristics,omitempty"`
	YARA           string `json:"yara,omitempty"`
	Process        string `json:"process,omitempty"`
	Network        string `json:"network,omitempty"`
	Persistence    string `json:"persistence,omitempty"`
	Users          string `json:"users,omitempty"`
	Kernel         string `json:"kernel,omitempty"`
	Correlation    string `json:"correlation,omitempty"`
	Reporting      string `json:"reporting,omitempty"`
	Total          string `json:"total"`
}

func (d DurationBreakdown) MarshalJSON() ([]byte, error) {
	formatDur := func(dur time.Duration) string {
		if dur == 0 {
			return "0s"
		}
		return dur.String()
	}

	raw := durationBreakdownJSON{
		FilesystemWalk: formatDur(d.FilesystemWalk),
		Hashing:        formatDur(d.Hashing),
		Heuristics:     formatDur(d.Heuristics),
		YARA:           formatDur(d.YARA),
		Process:        formatDur(d.Process),
		Network:        formatDur(d.Network),
		Persistence:    formatDur(d.Persistence),
		Users:          formatDur(d.Users),
		Kernel:         formatDur(d.Kernel),
		Correlation:    formatDur(d.Correlation),
		Reporting:      formatDur(d.Reporting),
		Total:          formatDur(d.Total),
	}
	return json.Marshal(raw)
}

func (d *DurationBreakdown) UnmarshalJSON(b []byte) error {
	var raw durationBreakdownJSON
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}

	parseDur := func(s string) (time.Duration, error) {
		if s == "" {
			return 0, nil
		}
		return time.ParseDuration(s)
	}

	var err error
	if d.FilesystemWalk, err = parseDur(raw.FilesystemWalk); err != nil {
		return fmt.Errorf("invalid filesystem_walk duration: %w", err)
	}
	if d.Hashing, err = parseDur(raw.Hashing); err != nil {
		return fmt.Errorf("invalid hashing duration: %w", err)
	}
	if d.Heuristics, err = parseDur(raw.Heuristics); err != nil {
		return fmt.Errorf("invalid heuristics duration: %w", err)
	}
	if d.YARA, err = parseDur(raw.YARA); err != nil {
		return fmt.Errorf("invalid yara duration: %w", err)
	}
	if d.Process, err = parseDur(raw.Process); err != nil {
		return fmt.Errorf("invalid process duration: %w", err)
	}
	if d.Network, err = parseDur(raw.Network); err != nil {
		return fmt.Errorf("invalid network duration: %w", err)
	}
	if d.Persistence, err = parseDur(raw.Persistence); err != nil {
		return fmt.Errorf("invalid persistence duration: %w", err)
	}
	if d.Users, err = parseDur(raw.Users); err != nil {
		return fmt.Errorf("invalid users duration: %w", err)
	}
	if d.Kernel, err = parseDur(raw.Kernel); err != nil {
		return fmt.Errorf("invalid kernel duration: %w", err)
	}
	if d.Correlation, err = parseDur(raw.Correlation); err != nil {
		return fmt.Errorf("invalid correlation duration: %w", err)
	}
	if d.Reporting, err = parseDur(raw.Reporting); err != nil {
		return fmt.Errorf("invalid reporting duration: %w", err)
	}
	if d.Total, err = parseDur(raw.Total); err != nil {
		return fmt.Errorf("invalid total duration: %w", err)
	}
	return nil
}

// ComprehensiveSystemAssessment represents the high-level system assessment for executive reporting.
type ComprehensiveSystemAssessment struct {
	Posture            SystemPosture       `json:"posture"`
	SummaryRationale   string              `json:"summary_rationale"`
	TotalFindings      int                 `json:"total_findings"`
	AlertsCount        int                 `json:"alerts_count"`
	WarningsCount      int                 `json:"warnings_count"`
	NoticesCount       int                 `json:"notices_count"`
	InfosCount         int                 `json:"infos_count"`
	UnknownsCount      int                 `json:"unknowns_count"`
	CriticalFindings   []report.Finding    `json:"critical_findings,omitempty"`
	SuspiciousFindings []report.Finding    `json:"suspicious_findings,omitempty"`
	VisibilityGaps     []CoverageGap       `json:"visibility_gaps,omitempty"`
	NextActions        []PrioritizedAction `json:"next_actions"`
}

// RealWorldValidationRun captures the complete audit and performance profile of a validation run.
type RealWorldValidationRun struct {
	RunID                 string                        `json:"run_id"`
	Timestamp             time.Time                     `json:"timestamp"`
	ProfileID             string                        `json:"profile_id"`
	IsElevated            bool                          `json:"is_elevated"`
	FilesInspected        int64                         `json:"files_inspected"`
	ProcessesInspected    int64                         `json:"processes_inspected"`
	SocketsInspected      int64                         `json:"sockets_inspected"`
	PeakMemoryMB          float64                       `json:"peak_memory_mb"`
	ThroughputFilesPerSec float64                       `json:"throughput_files_per_sec"`
	Duration              DurationBreakdown             `json:"duration"`
	Assessment            ComprehensiveSystemAssessment `json:"assessment"`
	ManifestCompliance    bool                          `json:"manifest_compliance"`
	ComplianceViolations  []string                      `json:"compliance_violations,omitempty"`
}
