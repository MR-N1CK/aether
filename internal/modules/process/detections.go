package process

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"aether/internal/config"
	"aether/internal/report"
)

// ProcessSignal represents an anomaly detected on a running process.
type ProcessSignal struct {
	RuleName    string
	Reason      string
	Score       int
	Severity    report.Severity
	IsPathBased bool
	IsIOCMatch  bool
	IsStrong    bool
}

var standardSystemDirs = []string{
	"/bin",
	"/sbin",
	"/usr/bin",
	"/usr/sbin",
	"/usr/lib",
	"/usr/libexec",
	"/lib",
	"/lib64",
}

var knownSystemDaemons = map[string]bool{
	"sshd":             true,
	"cron":             true,
	"crond":            true,
	"systemd":          true,
	"systemd-journald": true,
	"systemd-resolved": true,
	"systemd-logind":   true,
	"systemd-udevd":    true,
	"rsyslogd":         true,
	"auditd":           true,
	"udevd":            true,
}

func statInProcessNamespace(pid int, absPath string) (os.FileInfo, error) {
	if pid > 0 {
		procRoot := fmt.Sprintf("/proc/%d/root", pid)
		target := filepath.Join(procRoot, absPath)
		if fi, err := os.Stat(target); err == nil {
			return fi, nil
		}
	}
	return os.Stat(absPath)
}

// CheckDeletedExe inspects whether the executable has been unlinked from the filesystem.
func CheckDeletedExe(info *ProcessInfo, cfg *config.Config) *ProcessSignal {
	if info.Exe == "" || !strings.HasSuffix(info.Exe, " (deleted)") {
		return nil
	}

	origPath := strings.TrimSuffix(info.Exe, " (deleted)")
	cleanPath := filepath.Clean(origPath)

	// 1. Evaluate temp locations FIRST:
	// /tmp, /var/tmp, /dev/shm, regular files in /dev, cfg.Scan.TempDirs.
	// In those, "replaced on disk" NEVER downgrades.
	tempDirs := []string{"/tmp", "/var/tmp", "/dev/shm"}
	if cfg != nil && len(cfg.Scan.TempDirs) > 0 {
		tempDirs = cfg.Scan.TempDirs
	}

	isTempDir := false
	for _, dir := range tempDirs {
		cleanDir := filepath.Clean(dir)
		if cleanPath == cleanDir || strings.HasPrefix(cleanPath, cleanDir+"/") {
			isTempDir = true
			break
		}
	}
	if strings.HasPrefix(cleanPath, "/dev/") && !strings.HasPrefix(cleanPath, "/dev/pts") {
		isTempDir = true
	}

	if isTempDir {
		score := config.DefaultScoreProcDeletedExeSusp
		if cfg != nil && cfg.Scan.ScoreProcDeletedExeSusp > 0 {
			score = cfg.Scan.ScoreProcDeletedExeSusp
		}
		return &ProcessSignal{
			RuleName:    "Process_Deleted_Binary_Suspicious_Location",
			Reason:      fmt.Sprintf("Process running with deleted binary from temporary or suspicious location %s", origPath),
			Score:       score,
			Severity:    report.SeverityAlert,
			IsPathBased: true,
			IsStrong:    true,
		}
	}

	// 2. Outside temp dirs: check if original path exists again as a regular file
	// with a different inode from the running exe (binary replaced by package manager / updater).
	// Checked via /proc/<pid>/root/<path> to judge containers in their own namespace.
	isReplaced := false
	if newFi, err := statInProcessNamespace(info.PID, cleanPath); err == nil && newFi.Mode().IsRegular() {
		if sys, ok := newFi.Sys().(*syscall.Stat_t); ok {
			if info.ExeStat == nil || sys.Ino != info.ExeStat.Ino || sys.Dev != info.ExeStat.Dev {
				isReplaced = true
			}
		} else {
			isReplaced = true
		}
	}

	if isReplaced {
		score := config.DefaultScoreProcDeletedExePkg
		if cfg != nil && cfg.Scan.ScoreProcDeletedExePkg > 0 {
			score = cfg.Scan.ScoreProcDeletedExePkg
		}
		return &ProcessSignal{
			RuleName:    "Process_Deleted_Binary_Replaced",
			Reason:      fmt.Sprintf("Process binary was replaced on disk; process is running the old version (restart needed) (%s)", origPath),
			Score:       score,
			Severity:    report.SeverityNotice,
			IsPathBased: true,
			IsStrong:    false,
		}
	}

	// 3. Package directories (/usr, /bin, /sbin, /lib, /lib64, /opt)
	isPkgDir := false
	for _, dir := range []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt"} {
		if cleanPath == dir || strings.HasPrefix(cleanPath, dir+"/") {
			isPkgDir = true
			break
		}
	}
	if isPkgDir {
		score := config.DefaultScoreProcDeletedExePkg
		if cfg != nil && cfg.Scan.ScoreProcDeletedExePkg > 0 {
			score = cfg.Scan.ScoreProcDeletedExePkg
		}
		return &ProcessSignal{
			RuleName:    "Process_Deleted_Binary_Package_Upgrade",
			Reason:      fmt.Sprintf("Process binary was deleted from %s (restart needed: likely package upgrade)", origPath),
			Score:       score,
			Severity:    report.SeverityNotice,
			IsPathBased: true,
			IsStrong:    false,
		}
	}

	// 4. Under /home (and cfg.Scan.HomeDirs)
	homeDirs := []string{"/home", "/root"}
	if cfg != nil && len(cfg.Scan.HomeDirs) > 0 {
		homeDirs = cfg.Scan.HomeDirs
	}
	isHome := false
	for _, dir := range homeDirs {
		cleanDir := filepath.Clean(dir)
		if cleanPath == cleanDir || strings.HasPrefix(cleanPath, cleanDir+"/") {
			isHome = true
			break
		}
	}

	if isHome {
		// Well-known app-managed locations under home:
		// .local/share, .local/*.app, .cache, snap, flatpak, AppImage dirs
		isAppManaged := false
		lowerPath := strings.ToLower(cleanPath)
		if strings.Contains(cleanPath, "/.local/share/") || strings.HasSuffix(cleanPath, "/.local/share") ||
			strings.Contains(cleanPath, "/.cache/") || strings.HasSuffix(cleanPath, "/.cache") ||
			strings.Contains(cleanPath, "/snap/") || strings.HasPrefix(cleanPath, "/snap/") ||
			strings.Contains(cleanPath, "/flatpak/") || strings.Contains(lowerPath, "appimage") {
			isAppManaged = true
		} else if strings.Contains(cleanPath, "/.local/") {
			parts := strings.Split(cleanPath, "/")
			for _, part := range parts {
				if strings.HasSuffix(part, ".app") {
					isAppManaged = true
					break
				}
			}
		}

		if isAppManaged {
			score := config.DefaultScoreProcDeletedExePkg
			if cfg != nil && cfg.Scan.ScoreProcDeletedExePkg > 0 {
				score = cfg.Scan.ScoreProcDeletedExePkg
			}
			return &ProcessSignal{
				RuleName:    "Process_Deleted_Binary_App_Managed",
				Reason:      fmt.Sprintf("Process binary was deleted from app-managed location %s", origPath),
				Score:       score,
				Severity:    report.SeverityNotice,
				IsPathBased: true,
				IsStrong:    false,
			}
		}

		return &ProcessSignal{
			RuleName:    "Process_Deleted_Binary_Home",
			Reason:      fmt.Sprintf("Process running with unlinked/deleted binary from user directory %s", origPath),
			Score:       60,
			Severity:    report.SeverityWarning,
			IsPathBased: true,
			IsStrong:    false,
		}
	}

	// 5. Other locations
	score := config.DefaultScoreProcDeletedExeOther
	if cfg != nil && cfg.Scan.ScoreProcDeletedExeOther > 0 {
		score = cfg.Scan.ScoreProcDeletedExeOther
	}
	return &ProcessSignal{
		RuleName:    "Process_Deleted_Binary",
		Reason:      fmt.Sprintf("Process running with unlinked/deleted binary from %s", origPath),
		Score:       score,
		Severity:    report.SeverityWarning,
		IsPathBased: true,
		IsStrong:    false,
	}
}

// CheckExeOrCwdInTemp detects processes running from temporary or suspicious directories.
func CheckExeOrCwdInTemp(info *ProcessInfo, cfg *config.Config) *ProcessSignal {
	suspDirs := []string{"/tmp", "/var/tmp", "/dev/shm"}

	isUnder := func(p string) (bool, string) {
		if p == "" {
			return false, ""
		}
		cleaned := filepath.Clean(strings.TrimSuffix(p, " (deleted)"))
		for _, dir := range suspDirs {
			if cleaned == dir || strings.HasPrefix(cleaned, dir+"/") {
				return true, cleaned
			}
		}
		if strings.HasPrefix(cleaned, "/dev/") && !strings.HasPrefix(cleaned, "/dev/pts") {
			return true, cleaned
		}
		return false, ""
	}

	exeSusp, exeLoc := isUnder(info.Exe)
	cwdSusp, cwdLoc := isUnder(info.Cwd)

	if exeSusp || cwdSusp {
		score := cfg.Scan.ScoreProcExeInTemp
		if score == 0 {
			score = config.DefaultScoreProcExeInTemp
		}
		var desc []string
		if exeSusp {
			desc = append(desc, fmt.Sprintf("exe: %s", exeLoc))
		}
		if cwdSusp {
			desc = append(desc, fmt.Sprintf("cwd: %s", cwdLoc))
		}
		return &ProcessSignal{
			RuleName:    "Process_Exe_Or_Cwd_In_Temp",
			Reason:      fmt.Sprintf("Process operating in temporary directory (%s)", strings.Join(desc, ", ")),
			Score:       score,
			Severity:    report.SeverityWarning,
			IsPathBased: true,
		}
	}

	return nil
}

// CheckFilelessExecution inspects /proc/<pid>/maps for executable memfd or anonymous-deleted mappings.
// CheckFilelessExecution inspects /proc/<pid>/maps for executable memfd or anonymous-deleted mappings.
// Plain JIT mappings (empty pathname or [anon:...]) are intentionally skipped.
// Returns all matching signals deduped per memfd inode.
func CheckFilelessExecution(info *ProcessInfo, cfg *config.Config) []*ProcessSignal {
	var signals []*ProcessSignal
	seenInodes := make(map[uint64]bool)

	for _, m := range info.Maps {
		if !strings.Contains(m.Perms, "x") {
			continue
		}

		path := strings.TrimSpace(m.Pathname)
		// Plain JIT mappings have empty pathname or "[anon:..." -> must NOT be flagged
		if path == "" || strings.HasPrefix(path, "[anon") || path == "[heap]" || path == "[stack]" || path == "[vdso]" || path == "[vsyscall]" {
			continue
		}

		isFilelessCandidate := false
		if strings.Contains(path, "memfd:") || strings.HasPrefix(path, "/memfd") {
			isFilelessCandidate = true
		} else if strings.HasSuffix(path, " (deleted)") && !strings.HasPrefix(path, "/") {
			isFilelessCandidate = true
		}

		if !isFilelessCandidate {
			continue
		}

		// Dedupe per inode if non-zero
		if m.Inode != 0 && seenInodes[m.Inode] {
			continue
		}
		if m.Inode != 0 {
			seenInodes[m.Inode] = true
		}

		// Check if mapping starts with ELF magic (\x7fELF)
		// Read via /proc/<pid>/map_files or exe inode, never ptrace or writes.
		// If unreadable, record a coverage gap instead of generating a speculative finding.
		var exeInode uint64
		if info.ExeStat != nil {
			exeInode = uint64(info.ExeStat.Ino)
		}

		magic, err := ReadMappingHeader(info.PID, m.StartAddr, m.EndAddr, exeInode, m.Inode)
		if err != nil {
			info.CoverageGaps = append(info.CoverageGaps, fmt.Sprintf("unreadable fileless mapping %q (0x%x-0x%x)", path, m.StartAddr, m.EndAddr))
			continue
		}

		hasELFMagic := len(magic) == 4 && bytes.Equal(magic, []byte("\x7fELF"))
		if hasELFMagic {
			score := cfg.Scan.ScoreProcFilelessELF
			if score == 0 {
				score = config.DefaultScoreProcFilelessELF
			}
			signals = append(signals, &ProcessSignal{
				RuleName:    "Process_Fileless_Memory_ELF",
				Reason:      fmt.Sprintf("Executable memory mapping %q begins with ELF header (in-memory payload execution)", path),
				Score:       score,
				Severity:    report.SeverityWarning,
				IsPathBased: false,
				IsStrong:    true,
			})
			continue
		}

		score := cfg.Scan.ScoreProcFilelessLow
		if score == 0 {
			score = config.DefaultScoreProcFilelessLow
		}
		signals = append(signals, &ProcessSignal{
			RuleName:    "Process_Fileless_Memory_Mapping",
			Reason:      fmt.Sprintf("Executable memory mapping %q detected", path),
			Score:       score,
			Severity:    report.SeverityNotice,
			IsPathBased: false,
			IsStrong:    false,
		})
	}
	return signals
}

// CheckMasquerading detects processes masquerading as kernel threads or system daemons.
func CheckMasquerading(info *ProcessInfo, cfg *config.Config) *ProcessSignal {
	score := cfg.Scan.ScoreProcMasquerade
	if score == 0 {
		score = config.DefaultScoreProcMasquerade
	}

	// 1. Check bracketed kernel thread name masquerading:
	// Only flag when exe is non-empty (real kernel threads have none)
	isBracketed := (strings.HasPrefix(info.Comm, "[") && strings.HasSuffix(info.Comm, "]"))
	if !isBracketed && len(info.Cmdline) > 0 {
		arg0 := info.Cmdline[0]
		if strings.HasPrefix(arg0, "[") && strings.HasSuffix(arg0, "]") {
			isBracketed = true
		}
	}

	if isBracketed && info.Exe != "" {
		return &ProcessSignal{
			RuleName:    "Process_Kernel_Thread_Masquerade",
			Reason:      fmt.Sprintf("Userland process (exe: %s) masquerading as kernel thread with bracketed name %q", info.Exe, info.Comm),
			Score:       score,
			Severity:    report.SeverityWarning,
			IsPathBased: false,
			IsStrong:    true,
		}
	}

	// 2. Check system daemon masquerading:
	// If comm matches standard system daemon but exe is outside standard system dirs
	if knownSystemDaemons[info.Comm] && info.Exe != "" {
		cleanExe := filepath.Clean(strings.TrimSuffix(info.Exe, " (deleted)"))
		isStandard := false
		for _, dir := range standardSystemDirs {
			if cleanExe == dir || strings.HasPrefix(cleanExe, dir+"/") {
				isStandard = true
				break
			}
		}

		if !isStandard {
			return &ProcessSignal{
				RuleName:    "Process_System_Daemon_Masquerade",
				Reason:      fmt.Sprintf("Process name %q matches system daemon but executable is outside standard system directories (%s)", info.Comm, info.Exe),
				Score:       score,
				Severity:    report.SeverityWarning,
				IsPathBased: true,
				IsStrong:    true,
			}
		}
	}

	return nil
}

// CheckRootWritableExe checks for root (UID 0) processes whose binary is in a user-writable directory.
func CheckRootWritableExe(info *ProcessInfo, cfg *config.Config) *ProcessSignal {
	if info.Euid != 0 || info.Exe == "" {
		return nil
	}

	cleanExe := filepath.Clean(strings.TrimSuffix(info.Exe, " (deleted)"))

	// High-risk writable directories: /tmp, /var/tmp, /dev/shm, /home
	for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm", "/home"} {
		if cleanExe == dir || strings.HasPrefix(cleanExe, dir+"/") {
			score := cfg.Scan.ScoreProcRootWritable
			if score == 0 {
				score = config.DefaultScoreProcRootWritable
			}
			return &ProcessSignal{
				RuleName:    "Process_Root_User_Writable_Exe",
				Reason:      fmt.Sprintf("Root process (UID 0) running executable from user-writable directory %s (%s)", dir, cleanExe),
				Score:       score,
				Severity:    report.SeverityWarning,
				IsPathBased: true,
				IsStrong:    true,
			}
		}
	}

	// Check if parent directory is world-writable
	parentDir := filepath.Dir(cleanExe)
	if parentStat, err := os.Stat(parentDir); err == nil {
		if parentStat.Mode()&0002 != 0 {
			score := cfg.Scan.ScoreProcRootWritable
			if score == 0 {
				score = config.DefaultScoreProcRootWritable
			}
			return &ProcessSignal{
				RuleName:    "Process_Root_World_Writable_Parent_Dir",
				Reason:      fmt.Sprintf("Root process (UID 0) running executable in world-writable directory %s (%s)", parentDir, cleanExe),
				Score:       score,
				Severity:    report.SeverityWarning,
				IsPathBased: true,
				IsStrong:    true,
			}
		}
	}

	// Non-root owned executable elsewhere is a separate low-score signal, NOT ALERT
	if info.ExeStat != nil && info.ExeStat.Uid != 0 {
		score := cfg.Scan.ScoreProcRootNonRootOwner
		if score == 0 {
			score = config.DefaultScoreProcRootNonRootOwner
		}
		return &ProcessSignal{
			RuleName:    "Process_Root_NonRoot_Owned_Exe",
			Reason:      fmt.Sprintf("Root process (UID 0) running executable owned by non-root UID %d (%s)", info.ExeStat.Uid, cleanExe),
			Score:       score,
			Severity:    report.SeverityNotice,
			IsPathBased: true,
			IsStrong:    false,
		}
	}

	return nil
}

var interactiveShellOrTools = map[string]bool{
	"sh":      true,
	"bash":    true,
	"dash":    true,
	"zsh":     true,
	"ash":     true,
	"csh":     true,
	"tcsh":    true,
	"ksh":     true,
	"fish":    true,
	"python":  true,
	"python2": true,
	"python3": true,
	"perl":    true,
	"ruby":    true,
	"php":     true,
	"lua":     true,
	"nc":      true,
	"netcat":  true,
	"ncat":    true,
	"socat":   true,
}

// CheckProcessReverseShell checks if an interactive shell, script interpreter, or networking
// tool has its standard input or output redirected to a network socket.
func CheckProcessReverseShell(info *ProcessInfo, cfg *config.Config) *ProcessSignal {
	if info == nil {
		return nil
	}

	comm := strings.ToLower(strings.TrimSpace(info.Comm))
	exeBase := ""
	if info.Exe != "" {
		cleanExe := strings.TrimSuffix(info.Exe, " (deleted)")
		exeBase = strings.ToLower(filepath.Base(cleanExe))
	}

	if !interactiveShellOrTools[comm] && !interactiveShellOrTools[exeBase] {
		return nil
	}

	stdinIsSocket := strings.HasPrefix(info.StdinTarget, "socket:[")
	stdoutIsSocket := strings.HasPrefix(info.StdoutTarget, "socket:[")

	if stdinIsSocket || stdoutIsSocket {
		var redirected []string
		if stdinIsSocket {
			redirected = append(redirected, fmt.Sprintf("stdin: %s", info.StdinTarget))
		}
		if stdoutIsSocket {
			redirected = append(redirected, fmt.Sprintf("stdout: %s", info.StdoutTarget))
		}

		return &ProcessSignal{
			RuleName:    "Process_Interactive_Reverse_Shell",
			Reason:      fmt.Sprintf("Interactive process %s (PID %d) standard I/O redirected to network socket (%s)", info.Comm, info.PID, strings.Join(redirected, ", ")),
			Score:       95,
			Severity:    report.SeverityAlert,
			IsPathBased: false,
			IsStrong:    true,
		}
	}

	return nil
}

// CheckContainerCapabilities detects processes running inside container namespaces with
// dangerous Linux capabilities that enable container breakouts.
func CheckContainerCapabilities(info *ProcessInfo, selfMntNs string, cfg *config.Config) *ProcessSignal {
	if info == nil || info.MntNs == "" || selfMntNs == "" || info.MntNs == selfMntNs {
		return nil
	}

	// Dangerous Linux capability bitmasks:
	// CAP_DAC_READ_SEARCH = bit 2 (0x4)
	// CAP_SYS_MODULE      = bit 16 (0x10000)
	// CAP_SYS_RAWIO       = bit 17 (0x20000)
	// CAP_SYS_PTRACE      = bit 19 (0x80000)
	// CAP_SYS_ADMIN       = bit 21 (0x200000)
	dangerousMask := uint64(1<<2 | 1<<16 | 1<<17 | 1<<19 | 1<<21)

	matchedCaps := info.CapEff & dangerousMask
	if matchedCaps != 0 {
		var capNames []string
		if (matchedCaps & (1 << 21)) != 0 {
			capNames = append(capNames, "CAP_SYS_ADMIN")
		}
		if (matchedCaps & (1 << 19)) != 0 {
			capNames = append(capNames, "CAP_SYS_PTRACE")
		}
		if (matchedCaps & (1 << 16)) != 0 {
			capNames = append(capNames, "CAP_SYS_MODULE")
		}
		if (matchedCaps & (1 << 17)) != 0 {
			capNames = append(capNames, "CAP_SYS_RAWIO")
		}
		if (matchedCaps & (1 << 2)) != 0 {
			capNames = append(capNames, "CAP_DAC_READ_SEARCH")
		}

		return &ProcessSignal{
			RuleName:    "Container_Dangerous_Capability_Overprivilege",
			Reason:      fmt.Sprintf("Container process %s (PID %d) has dangerous breakout capabilities: %s (CapEff: 0x%x)", info.Comm, info.PID, strings.Join(capNames, ", "), info.CapEff),
			Score:       75,
			Severity:    report.SeverityWarning,
			IsPathBased: false,
			IsStrong:    true,
		}
	}

	return nil
}

// ApplyContainerScoreAdjustment adjusts path-based detection scores if the process
// is in a different mount namespace (container).
func ApplyContainerScoreAdjustment(signals []*ProcessSignal, info *ProcessInfo, selfMntNs string, reduction int) bool {
	if info.MntNs == "" || selfMntNs == "" || info.MntNs == selfMntNs {
		return false
	}

	if reduction <= 0 {
		reduction = config.DefaultContainerScoreReduction
	}

	for _, sig := range signals {
		if sig.IsPathBased && !sig.IsIOCMatch {
			sig.Score -= reduction
			if sig.Score < 10 {
				sig.Score = 10
			}
			if sig.Score < 50 && sig.Severity == report.SeverityWarning {
				sig.Severity = report.SeverityNotice
			}
		}
	}
	return true
}

// ConsolidateProcessSignals aggregates all signals for a PID into one Finding.
// Escalate to ALERT only when two or more independent strong signals fire on the same process,
// or an IOC match occurs. Weak signals never count as corroboration for ALERT.
func ConsolidateProcessSignals(signals []*ProcessSignal, info *ProcessInfo, isContainer bool) *report.Finding {
	if len(signals) == 0 {
		return nil
	}

	totalScore := 0
	strongCount := 0
	var ruleNames []string
	var reasons []string
	hasIOCMatch := false

	ruleSeverities := make(map[string]string)
	for _, s := range signals {
		totalScore += s.Score
		ruleNames = append(ruleNames, s.RuleName)
		reasons = append(reasons, s.Reason)
		ruleSeverities[s.RuleName] = s.Severity.String()
		if s.IsIOCMatch {
			hasIOCMatch = true
		}
		if s.IsStrong {
			strongCount++
		}
	}

	// Severity calculation:
	// A finding may be ALERT only with strong+strong, an IOC hit, or a high-confidence primitive.
	// Weak signals never count as corroboration. Strong + weak = WARNING (raised score, capped below ALERT).
	var severity report.Severity
	if hasIOCMatch {
		severity = report.SeverityAlert
	} else if strongCount >= 2 && totalScore >= 80 {
		severity = report.SeverityAlert
	} else if totalScore >= 50 {
		severity = report.SeverityWarning
	} else {
		severity = report.SeverityNotice
	}

	targetPath := info.Exe
	if targetPath == "" {
		targetPath = fmt.Sprintf("[%s]", info.Comm)
	}
	pathLabel := fmt.Sprintf("/proc/%d/exe -> %s", info.PID, targetPath)

	ruleStr := strings.Join(ruleNames, ", ")
	reasonStr := strings.Join(reasons, " | ")

	finding := report.NewFinding("process", severity, pathLabel, reasonStr, ruleStr)
	finding.Metadata["pid"] = info.PID
	finding.Metadata["comm"] = info.Comm
	finding.Metadata["euid"] = info.Euid
	finding.Metadata["score"] = totalScore
	finding.Metadata["signals_count"] = len(signals)
	finding.Metadata["rule_severities"] = ruleSeverities
	if len(info.Cmdline) > 0 {
		finding.Metadata["cmdline"] = strings.Join(info.Cmdline, " ")
	}
	if finding.EvidenceRecord != nil {
		finding.EvidenceRecord.PID = info.PID
		finding.EvidenceRecord.Comm = info.Comm
		if len(info.Cmdline) > 0 {
			finding.EvidenceRecord.Cmdline = strings.Join(info.Cmdline, " ")
		}
		finding.EvidenceRecord.MountNamespace = info.MntNs
		if isContainer {
			finding.EvidenceRecord.ContextProfile = "container_namespace"
		}
		if len(ruleNames) == 1 && (ruleNames[0] == "Process_Deleted_Binary_Package_Upgrade" || ruleNames[0] == "Process_Deleted_Binary_Replaced") {
			finding.EvidenceRecord.PackageStatus = "verified_package"
		}
	}

	return &finding
}

// CheckProcessEnviron inspects the runtime environment variables for rootkit hooks,
// anti-forensics history suppression, and C2 framework indicators.
func CheckProcessEnviron(info *ProcessInfo, cfg *config.Config) []*ProcessSignal {
	if info == nil || len(info.Environ) == 0 {
		return nil
	}

	var signals []*ProcessSignal

	// 1. LD_PRELOAD injection hook
	if ldp, ok := info.Environ["LD_PRELOAD"]; ok {
		clean := strings.TrimSpace(ldp)
		if clean != "" {
			signals = append(signals, &ProcessSignal{
				RuleName: "Process_Environ_LDPreload",
				Reason:   fmt.Sprintf("Process running with active LD_PRELOAD environment variable (%s)", clean),
				Score:    90,
				Severity: report.SeverityAlert,
				IsStrong: true,
			})
		}
	}

	// 2. Anti-forensic bash history suppression
	histfile, hasHF := info.Environ["HISTFILE"]
	histsize, hasHS := info.Environ["HISTSIZE"]
	if (hasHF && (histfile == "/dev/null" || histfile == "")) || (hasHS && histsize == "0") {
		signals = append(signals, &ProcessSignal{
			RuleName: "Process_Environ_AntiForensic",
			Reason:   "Process running with shell history suppression (HISTFILE=/dev/null or HISTSIZE=0)",
			Score:    70,
			Severity: report.SeverityWarning,
			IsStrong: true,
		})
	}

	// 3. Known offensive C2 frameworks or anonymous proxy markers
	c2Prefixes := []string{"SLIVER_", "METERPRETER_", "PUPY_", "COBALT_STRIKE", "HAVOC_", "EMPIRE_"}
	c2ExactKeys := []string{"TOR_SKIP_LAUNCH", "MYSTERY_HASH", "PROXYCHAINS_CONF_FILE"}

	foundC2Key := ""
	for k := range info.Environ {
		upper := strings.ToUpper(k)
		for _, exact := range c2ExactKeys {
			if upper == exact {
				foundC2Key = k
				break
			}
		}
		if foundC2Key != "" {
			break
		}
		for _, prefix := range c2Prefixes {
			if strings.HasPrefix(upper, prefix) {
				foundC2Key = k
				break
			}
		}
		if foundC2Key != "" {
			break
		}
	}

	if foundC2Key != "" {
		signals = append(signals, &ProcessSignal{
			RuleName: "Process_Environ_C2_Artifact",
			Reason:   fmt.Sprintf("Process environment contains C2 framework indicator (%s)", foundC2Key),
			Score:    75,
			Severity: report.SeverityWarning,
			IsStrong: true,
		})
	}

	return signals
}
