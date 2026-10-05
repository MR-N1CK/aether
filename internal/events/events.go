package events

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"aether/internal/report"
)

// EventType identifies the event category.
type EventType string

const (
	TypeScanStarted    EventType = "ScanStarted"
	TypeModuleStarted  EventType = "ModuleStarted"
	TypeModuleFinished EventType = "ModuleFinished"
	TypeFileScanned    EventType = "FileScanned"
	TypeFindingRaised  EventType = "FindingRaised"
	TypeProgress       EventType = "Progress"
	TypeScanFinished   EventType = "ScanFinished"
	TypeError          EventType = "Error"
)

// Verdict defines the overall scan outcome computed by the scanner.
type Verdict string

const (
	VerdictClean       Verdict = "CLEAN"
	VerdictSuspicious  Verdict = "SUSPICIOUS"
	VerdictCompromised Verdict = "COMPROMISED"
)

// Event is the common interface implemented by all scan lifecycle events.
type Event interface {
	Type() EventType
	Timestamp() time.Time
	// IsCritical returns true if this event must be delivered losslessly (never dropped).
	IsCritical() bool
}

// ScanStarted indicates the beginning of a hunt scan.
type ScanStarted struct {
	Time        time.Time `json:"timestamp"`
	Version     string    `json:"version,omitempty"`
	BuildDate   string    `json:"build_date,omitempty"`
	BinaryName  string    `json:"binary_name,omitempty"`
	Paths       []string  `json:"paths"`
	Excludes    []string  `json:"excludes"`
	Mode        string    `json:"mode"` // "quick", "full", "custom"
	Threads     int       `json:"threads"`
	MaxFileSize int64     `json:"max_filesize"`
	Notices     []string  `json:"notices,omitempty"`
}

func (e ScanStarted) Type() EventType     { return TypeScanStarted }
func (e ScanStarted) Timestamp() time.Time { return e.Time }
func (e ScanStarted) IsCritical() bool    { return true }

// ModuleStarted indicates that an inspection module has begun execution.
type ModuleStarted struct {
	Time        time.Time `json:"timestamp"`
	ModuleName  string    `json:"module_name"`
	Description string    `json:"description"`
}

func (e ModuleStarted) Type() EventType     { return TypeModuleStarted }
func (e ModuleStarted) Timestamp() time.Time { return e.Time }
func (e ModuleStarted) IsCritical() bool    { return true }

// ModuleFinished indicates that an inspection module has concluded.
type ModuleFinished struct {
	Time           time.Time     `json:"timestamp"`
	ModuleName     string        `json:"module_name"`
	Duration       time.Duration `json:"duration"`
	FindingsCount  int           `json:"findings_count"`
	InspectedCount int64         `json:"inspected_count"`
	Err            error         `json:"error,omitempty"`
	Status         string        `json:"status,omitempty"` // "OK", "NOT IMPLEMENTED", "FAILED"
}

func (e ModuleFinished) Type() EventType     { return TypeModuleFinished }
func (e ModuleFinished) Timestamp() time.Time { return e.Time }
func (e ModuleFinished) IsCritical() bool    { return true }

// ProcessDurationBreakdown captures per-phase durations of process hunting.
type ProcessDurationBreakdown struct {
	Procfs      time.Duration `json:"procfs"`
	Hashing     time.Duration `json:"hashing"`
	HiddenPass1 time.Duration `json:"hidden_pass1"`
	HiddenPass2 time.Duration `json:"hidden_pass2"`
	Total       time.Duration `json:"total"`
}

// ProcessCoverageStats captures metrics from the process inspection module.
type ProcessCoverageStats struct {
	Inspected         int64                     `json:"inspected"`
	Limited           int64                     `json:"limited"`
	SkippedPermission int64                     `json:"skipped_permission"`
	SkippedVanished   int64                     `json:"skipped_vanished"`
	KernelThreads     int64                     `json:"kernel_threads"`
	Zombies           int64                     `json:"zombies"`
	NonRootLimited    bool                      `json:"non_root_limited"`
	HiddenPIDRange    string                    `json:"hidden_pid_range"` // "fast" or "full"
	NotHashed         int64                     `json:"not_hashed"`
	DurationBreakdown *ProcessDurationBreakdown `json:"duration_breakdown,omitempty"`
}

// UnreadablePersistencePath details an inaccessible persistence hook path.
type UnreadablePersistencePath struct {
	Path   string `json:"path"`
	Reason string `json:"reason"` // e.g. "permission denied", "symlink target refused", "not regular", "size cap"
}

// PersistenceCoverageStats captures metrics from the persistence inspection module.
type PersistenceCoverageStats struct {
	TotalInspected  int64                       `json:"total_inspected"`
	TotalUnreadable int64                       `json:"total_unreadable"`
	NotPresent      int64                       `json:"not_present"`
	TotalMissing    int64                       `json:"total_missing,omitempty"`
	TotalMasked     int64                       `json:"total_masked,omitempty"`
	MaskedPaths     []string                    `json:"masked_paths,omitempty"`
	NonRootLimited  bool                        `json:"non_root_limited"`
	PkgDBAvailable  bool                        `json:"pkgdb_available"`
	PkgDBNote       string                      `json:"pkgdb_note,omitempty"`
	UnreadablePaths []UnreadablePersistencePath `json:"unreadable_paths,omitempty"`
}

// UsersCoverageStats captures metrics from the users inspection module.
type UsersCoverageStats struct {
	AccountsInspected      int64    `json:"accounts_inspected"`
	SystemAccounts         int64    `json:"system_accounts"`
	ShadowReadable         bool     `json:"shadow_readable"`
	ShadowGapNonRoot       bool     `json:"shadow_gap_non_root"`
	DuplicateUIDs          int64    `json:"duplicate_uids"`
	PrivilegedGroupMembers []string `json:"privileged_group_members,omitempty"`
	DockerLXDMembers       []string `json:"docker_lxd_members,omitempty"`
	NonRootLimited         bool     `json:"non_root_limited"`
}

// NetworkCoverageStats captures metrics from the network inspection module.
type NetworkCoverageStats struct {
	SocketsInspected       int64  `json:"sockets_inspected"`
	TCPListeners           int64  `json:"tcp_listeners"`
	UDPListeners           int64  `json:"udp_listeners"`
	EstablishedConnections int64  `json:"established_connections"`
	RawPacketSockets       int64  `json:"raw_packet_sockets"`
	KernelOwnedSockets     int64  `json:"kernel_owned_sockets"`
	UnmappedSocketsNonRoot int64  `json:"unmapped_sockets_non_root"`
	NonRootLimited         bool   `json:"non_root_limited"`
	NamespaceNote          string `json:"namespace_note,omitempty"`
}

// KernelCoverageStats captures metrics from the kernel inspection module.
type KernelCoverageStats struct {
	LoadedModulesInspected int64    `json:"loaded_modules_inspected"`
	SysfsLoadableEntries   int64    `json:"sysfs_loadable_entries"`
	TaintValue             uint64   `json:"taint_value"`
	TaintFlags             []string `json:"taint_flags,omitempty"`
	TaintSeverity          string   `json:"taint_severity,omitempty"`
	ModprobeFilesInspected int64    `json:"modprobe_files_inspected"`
	GapsNote               string   `json:"gaps_note,omitempty"`
}

// YARACoverageStats captures metrics and rule compiler health from YARA-X scanning.
type YARACoverageStats struct {
	CompiledIn      bool     `json:"compiled_in"`
	Version         string   `json:"version,omitempty"`
	RulesLoaded     int      `json:"rules_loaded"`
	RulesFailed     int      `json:"rules_failed"`
	FailedFiles     []string `json:"failed_files,omitempty"`
	FilesScanned    int64    `json:"files_scanned"`
	RuleFilesSeen   int64    `json:"rule_files_seen"`
	SkippedOversize int64    `json:"skipped_oversize"`
	SkippedTimeout  int64    `json:"skipped_timeout"`
	SkippedError    int64    `json:"skipped_error"`
	DemoRulesOnly   bool     `json:"demo_rules_only"`
	NotRunReason    string   `json:"not_run_reason,omitempty"`
}

// FileScanned is an ephemeral high-frequency event emitted per inspected file.
type FileScanned struct {
	Time     time.Time     `json:"timestamp"`
	Path     string        `json:"path"`
	Size     int64         `json:"size"`
	Duration time.Duration `json:"duration"`
}

func (e FileScanned) Type() EventType     { return TypeFileScanned }
func (e FileScanned) Timestamp() time.Time { return e.Time }
func (e FileScanned) IsCritical() bool    { return false } // Ephemeral: can be dropped/coalesced

// FindingRaised is a critical event emitted whenever a threat or anomaly is flagged.
type FindingRaised struct {
	Time    time.Time      `json:"timestamp"`
	Finding report.Finding `json:"finding"`
}

func (e FindingRaised) Type() EventType     { return TypeFindingRaised }
func (e FindingRaised) Timestamp() time.Time { return e.Time }
func (e FindingRaised) IsCritical() bool    { return true }

// Progress provides scanning velocity and progress estimation.
type Progress struct {
	Time          time.Time     `json:"timestamp"`
	CurrentFiles  int64         `json:"current_files"`
	FilesPerSec   float64       `json:"files_per_sec"`
	Elapsed       time.Duration `json:"elapsed"`
	ActiveModules []string      `json:"active_modules"`
	ActivePaths   []string      `json:"active_paths,omitempty"`
}

func (e Progress) Type() EventType     { return TypeProgress }
func (e Progress) Timestamp() time.Time { return e.Time }
func (e Progress) IsCritical() bool    { return false } // Ephemeral: can be dropped/coalesced

// DirCount represents an inspected directory and the count of files scanned within it.
type DirCount struct {
	Dir   string `json:"dir"`
	Count int64  `json:"count"`
}

// OversizeFile tracks a file skipped because its size exceeded limits or hashed oversize.
type OversizeFile struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// CoverageStats tracks scan totals and skipped items for forensic transparency.
type CoverageStats struct {
	FilesScanned        int64          `json:"files_scanned"`
	SkippedOversize     int64          `json:"skipped_oversize"`
	SkippedPermission   int64          `json:"skipped_permission"`
	SkippedVanished     int64          `json:"skipped_vanished"`
	SkippedNotRegular   int64          `json:"skipped_not_regular"`
	SkippedExcluded     int64          `json:"skipped_excluded"`
	SkippedTimeout      int64          `json:"skipped_timeout"`
	HashedOversize      int64          `json:"hashed_oversize"`
	Suppressed          int64          `json:"suppressed"`
	Acknowledged        int64          `json:"acknowledged"`
	TopInspectedDirs    []DirCount     `json:"top_inspected_dirs,omitempty"`
	OversizeFiles       []OversizeFile `json:"oversize_files,omitempty"`
	HashedOversizeFiles []OversizeFile `json:"hashed_oversize_files,omitempty"`
}

// TotalSkipped returns the aggregate number of files skipped during scanning.
func (s CoverageStats) TotalSkipped() int64 {
	return s.SkippedOversize + s.SkippedPermission + s.SkippedVanished + s.SkippedNotRegular + s.SkippedExcluded + s.SkippedTimeout
}

// HasPartialCoverage returns true if any files were skipped during scanning.
func (s CoverageStats) HasPartialCoverage() bool {
	return s.TotalSkipped() > 0
}

// ScanFinished indicates the completion of the entire hunt operation.
type ScanFinished struct {
	Time                 time.Time                 `json:"timestamp"`
	TotalDuration        time.Duration             `json:"total_duration"`
	FilesScanned         int64                     `json:"files_scanned"`
	Coverage             CoverageStats             `json:"coverage"`
	TotalFindings        int                       `json:"total_findings"`
	Alerts               int                       `json:"alerts"`
	Warnings             int                       `json:"warnings"`
	Notices              int                       `json:"notices"`
	Infos                int                       `json:"infos"`
	AffectedFiles        int                       `json:"affected_files"`
	Verdict              Verdict                   `json:"verdict"`
	VerdictReason        string                    `json:"verdict_reason,omitempty"`
	TopRules             []report.RuleSummary      `json:"top_rules,omitempty"`
	Partial              bool                      `json:"partial_coverage"`
	ModulesNotRun        []string                  `json:"modules_not_run,omitempty"`
	StartupNotices       []string                  `json:"startup_notices,omitempty"`
	ProcessCoverage      *ProcessCoverageStats     `json:"process_coverage,omitempty"`
	PersistenceCoverage  *PersistenceCoverageStats `json:"persistence_coverage,omitempty"`
	UsersCoverage        *UsersCoverageStats       `json:"users_coverage,omitempty"`
	NetworkCoverage      *NetworkCoverageStats     `json:"network_coverage,omitempty"`
	KernelCoverage       *KernelCoverageStats      `json:"kernel_coverage,omitempty"`
	YARACoverage         *YARACoverageStats        `json:"yara_coverage,omitempty"`
	AcknowledgedWarnings []report.Finding          `json:"acknowledged_warnings,omitempty"`
}

func (e ScanFinished) Type() EventType     { return TypeScanFinished }
func (e ScanFinished) Timestamp() time.Time { return e.Time }
func (e ScanFinished) IsCritical() bool    { return true }

// Error captures an operational error encountered during the scan.
type Error struct {
	Time    time.Time `json:"timestamp"`
	Module  string    `json:"module,omitempty"`
	Path    string    `json:"path,omitempty"`
	Err     error     `json:"error"`
	IsFatal bool      `json:"is_fatal"`
}

func (e Error) Type() EventType     { return TypeError }
func (e Error) Timestamp() time.Time { return e.Time }
func (e Error) IsCritical() bool    { return true }

// isWeakFinding checks if a finding matches any of the weak rules.
func isWeakFinding(f report.Finding, weakRules []string) bool {
	if len(weakRules) == 0 {
		return false
	}
	rules := strings.Split(f.RuleName, ",")
	if len(rules) == 0 {
		return false
	}
	for _, r := range rules {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		matched := false
		for _, w := range weakRules {
			w = strings.TrimSpace(w)
			if w == "" {
				continue
			}
			if r == w {
				matched = true
				break
			}
			if strings.Contains(w, "*") {
				if ok, _ := filepath.Match(w, r); ok {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// ComputeVerdict calculates the overall verdict and explanation reason from findings.
// - COMPROMISED requires >= 1 high-confidence indicator (IOC match, reverse shell primitive, symlink escape, or strong+strong ALERT).
// - If alerts > 0 or warnings > 0: SUSPICIOUS with reason.
// - If noticesThreshold > 0 and non-weak notices >= noticesThreshold: SUSPICIOUS with reason.
// - Otherwise: CLEAN (with notice count annotation if notices > 0). Weak notices never trigger SUSPICIOUS alone.
func ComputeVerdict(findings []report.Finding, alerts, warnings, notices, noticesThreshold int, weakRulesOpt ...[]string) (Verdict, string) {
	var weakRules []string
	if len(weakRulesOpt) > 0 {
		weakRules = weakRulesOpt[0]
	}

	hasHighConfidence := false
	var highConfidenceRule string

	for _, f := range findings {
		if f.Severity == report.SeverityAlert {
			isHC := false
			if hc, ok := f.Metadata["high_confidence"].(bool); ok && hc {
				isHC = true
			} else if conf, ok := f.Metadata["confidence"].(string); ok && strings.EqualFold(conf, "high") {
				isHC = true
			} else if f.Confidence == report.ConfidenceHigh {
				isHC = true
			} else if ioc, ok := f.Metadata["is_ioc_match"].(bool); ok && ioc {
				isHC = true
			} else if strings.Contains(f.RuleName, "IOC") ||
				strings.Contains(f.RuleName, "Reverse_Shell") ||
				strings.Contains(f.RuleName, "RevShell") ||
				strings.Contains(f.RuleName, "OpenSSL") ||
				strings.Contains(f.RuleName, "Socat") ||
				strings.Contains(f.RuleName, "Netcat") ||
				strings.Contains(f.RuleName, "RedTeam") ||
				strings.Contains(f.RuleName, "GhostShell") ||
				strings.Contains(f.RuleName, "Webshell") ||
				strings.Contains(f.RuleName, "Symlink_Escape") ||
				strings.Contains(f.RuleName, "LDPRELOAD") {
				isHC = true
			} else if strongCount, ok := f.Metadata["distinct_strong_classes"].(int); ok && strongCount >= 2 {
				isHC = true
			}
			if isHC {
				hasHighConfidence = true
				highConfidenceRule = f.RuleName
				break
			}
		}
	}

	if hasHighConfidence {
		reason := fmt.Sprintf("COMPROMISED: high-confidence threat indicator detected (%s)", highConfidenceRule)
		return VerdictCompromised, reason
	}

	if alerts > 0 {
		return VerdictSuspicious, fmt.Sprintf("SUSPICIOUS: %d alerts, no high-confidence indicators", alerts)
	}

	if warnings > 0 {
		return VerdictSuspicious, fmt.Sprintf("SUSPICIOUS: %d warnings, no high-confidence indicators", warnings)
	}

	nonWeakNotices := 0
	if len(findings) > 0 {
		for _, f := range findings {
			if f.Severity == report.SeverityNotice {
				if !isWeakFinding(f, weakRules) {
					nonWeakNotices++
				}
			}
		}
	} else {
		nonWeakNotices = notices
	}

	if noticesThreshold > 0 && nonWeakNotices >= noticesThreshold {
		return VerdictSuspicious, fmt.Sprintf("SUSPICIOUS: %d notices (%d non-weak), threshold (%d) exceeded", notices, nonWeakNotices, noticesThreshold)
	}

	if notices > 0 {
		return VerdictClean, fmt.Sprintf("CLEAN, %d notices to review", notices)
	}

	return VerdictClean, "CLEAN: no threats detected"
}
