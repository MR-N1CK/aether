package scanner

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"aether/internal/config"
	"aether/internal/report"
)

// HeuristicMatch represents an anomaly detected by structural/heuristic analysis.
type HeuristicMatch struct {
	Name     string
	Reason   string
	Score    int
	Severity report.Severity
}

// IsELF returns true if the buffer starts with the 4-byte ELF magic: \x7fELF.
func IsELF(header []byte) bool {
	return len(header) >= 4 && bytes.Equal(header[:4], []byte{0x7f, 'E', 'L', 'F'})
}

// CheckELFInTempOrDev checks for ELF binaries located in volatile/temporary/shared memory
// locations (/tmp, /var/tmp, /dev/shm) or regular files in /dev.
//
// Scoring & Escalation:
// - Under /dev (regular file, excluding /dev/shm and /dev/pts): Score = ScoreELFInDev (85, ALERT).
// - Under /tmp, /var/tmp, /dev/shm:
//   - Escalates to ScoreELFInTempEscalated (85, ALERT) if combined with another signal:
//     (executable bit + hidden filename, or an IOC signal passed via otherSignal).
//   - Lowered to ScoreELFInTempNonExec (25, NOTICE) if owned by the invoking non-root user
//     and has no executable bit (mode & 0111 == 0).
//   - Default Score = ScoreELFInTemp (55, WARNING).
func CheckELFInTempOrDev(path string, header []byte, mode uint32, uid uint32, otherSignal bool, cfg *config.Config) *HeuristicMatch {
	if !IsELF(header) {
		return nil
	}

	cleaned := filepath.Clean(path)
	scoreInTemp := config.DefaultScoreELFInTemp
	scoreInTempEsc := config.DefaultScoreELFInTempEscalated
	scoreInTempNonExec := config.DefaultScoreELFInTempNonExec
	scoreInDev := config.DefaultScoreELFInDev

	if cfg != nil {
		if cfg.Scan.ScoreELFInTemp > 0 {
			scoreInTemp = cfg.Scan.ScoreELFInTemp
		}
		if cfg.Scan.ScoreELFInTempEscalated > 0 {
			scoreInTempEsc = cfg.Scan.ScoreELFInTempEscalated
		}
		if cfg.Scan.ScoreELFInTempNonExec > 0 {
			scoreInTempNonExec = cfg.Scan.ScoreELFInTempNonExec
		}
		if cfg.Scan.ScoreELFInDev > 0 {
			scoreInDev = cfg.Scan.ScoreELFInDev
		}
	}

	// 1. Regular file under /dev (excluding pseudo-fs /dev/shm and /dev/pts)
	if strings.HasPrefix(cleaned, "/dev/") && !strings.HasPrefix(cleaned, "/dev/shm/") && !strings.HasPrefix(cleaned, "/dev/pts/") {
		return &HeuristicMatch{
			Name:     "Heuristic_ELF_In_Dev",
			Reason:   "ELF executable discovered as regular file under /dev directory tree",
			Score:    scoreInDev,
			Severity: report.SeverityAlert,
		}
	}

	// 2. Under volatile temporary dirs
	isTemp := strings.HasPrefix(cleaned, "/tmp/") || strings.HasPrefix(cleaned, "/var/tmp/") || strings.HasPrefix(cleaned, "/dev/shm/")
	if !isTemp {
		return nil
	}

	isExec := (mode & 0111) != 0
	base := filepath.Base(cleaned)
	isHidden := strings.HasPrefix(base, ".") && base != "." && base != ".."

	shouldEscalate := otherSignal || (isExec && isHidden)

	if shouldEscalate {
		return &HeuristicMatch{
			Name:     "Heuristic_ELF_In_Temp_Escalated",
			Reason:   fmt.Sprintf("ELF executable in %s (Escalated to ALERT: combined with hidden name/executable bit or IOC match)", filepath.Dir(cleaned)),
			Score:    scoreInTempEsc,
			Severity: report.SeverityAlert,
		}
	}

	// Check if owned by current invoking non-root user and has no executable bit
	if os.Geteuid() != 0 && uid == uint32(os.Getuid()) && !isExec {
		return &HeuristicMatch{
			Name:     "Heuristic_ELF_In_Temp_NonExec",
			Reason:   fmt.Sprintf("Non-executable ELF file owned by current non-root user in volatile location %s", filepath.Dir(cleaned)),
			Score:    scoreInTempNonExec,
			Severity: report.SeverityNotice,
		}
	}

	if isBuildTree, treeRoot := CheckBuildTree(path, mode, uid, shouldEscalate, cfg); isBuildTree {
		return &HeuristicMatch{
			Name:     "Heuristic_ELF_In_Temp_BuildTree",
			Reason:   fmt.Sprintf("ELF binary in volatile location looks like a build tree (%s)", treeRoot),
			Score:    scoreInTempNonExec,
			Severity: report.SeverityNotice,
		}
	}

	return &HeuristicMatch{
		Name:     "Heuristic_ELF_In_Temp",
		Reason:   fmt.Sprintf("ELF binary discovered in volatile/world-writable location %s", filepath.Dir(cleaned)),
		Score:    scoreInTemp,
		Severity: report.SeverityWarning,
	}
}

// CheckBuildTree evaluates if an ELF in a temp directory qualifies as a benign build tree artifact.
// Requires ALL of:
// - A marker among Cargo.toml, CMakeCache.txt, go.mod (from cfg.Scan.BuildMarkers);
// - The ELF lies inside a recognized build output dir (target, build, deps, out, dist) below the marker's directory;
// - ELF and marker have the same non-root owner (uid != 0 && markerUid == elfUid);
// - Path is NOT under /dev/shm;
// - File is not SUID/SGID, not hidden+executable, and has no IOC/YARA/other signal.
func CheckBuildTree(path string, mode uint32, elfUid uint32, otherSignal bool, cfg *config.Config) (bool, string) {
	if otherSignal {
		return false, ""
	}
	cleaned := filepath.Clean(path)
	// Must NOT be under /dev/shm
	if strings.HasPrefix(cleaned, "/dev/shm/") || cleaned == "/dev/shm" {
		return false, ""
	}
	// Must be non-root owned
	if elfUid == 0 {
		return false, ""
	}
	// Must not be SUID/SGID
	if (mode & (unix.S_ISUID | unix.S_ISGID)) != 0 {
		return false, ""
	}
	// Must not be hidden + executable
	isExec := (mode & 0111) != 0
	base := filepath.Base(cleaned)
	if strings.HasPrefix(base, ".") && base != "." && base != ".." && isExec {
		return false, ""
	}

	markers := config.DefaultBuildMarkers
	outputDirs := config.DefaultBuildOutputDirs
	if cfg != nil {
		if len(cfg.Scan.BuildMarkers) > 0 {
			markers = cfg.Scan.BuildMarkers
		}
		if len(cfg.Scan.BuildOutputDirs) > 0 {
			outputDirs = cfg.Scan.BuildOutputDirs
		}
	}

	// Determine temp roots
	tempRoots := []string{"/tmp", "/var/tmp"}
	if cfg != nil && len(cfg.Scan.TempDirs) > 0 {
		tempRoots = nil
		for _, td := range cfg.Scan.TempDirs {
			tdClean := filepath.Clean(td)
			if tdClean != "/dev/shm" && !strings.HasPrefix(tdClean, "/dev/shm/") {
				tempRoots = append(tempRoots, tdClean)
			}
		}
	}

	var matchedTempRoot string
	for _, tr := range tempRoots {
		if strings.HasPrefix(cleaned, tr+string(filepath.Separator)) {
			matchedTempRoot = tr
			break
		}
	}
	if matchedTempRoot == "" {
		return false, ""
	}

	// Walk up ancestor directories from filepath.Dir(cleaned) until matchedTempRoot
	cur := filepath.Dir(cleaned)
	for cur != matchedTempRoot && strings.HasPrefix(cur, matchedTempRoot+string(filepath.Separator)) {
		for _, marker := range markers {
			markerPath := filepath.Join(cur, marker)
			mStat, err := os.Lstat(markerPath)
			if err == nil && !mStat.IsDir() {
				var markerUid uint32
				if sysStat, ok := mStat.Sys().(*syscall.Stat_t); ok {
					markerUid = sysStat.Uid
				} else {
					continue
				}

				if markerUid == 0 || markerUid != elfUid {
					// Owner mismatch or root-owned marker -> do not downgrade
					return false, ""
				}

				// Verify the ELF lies inside a recognized build output directory below cur
				rel, rErr := filepath.Rel(cur, cleaned)
				if rErr != nil {
					continue
				}
				parts := strings.Split(rel, string(filepath.Separator))
				// parts has at least 2 components (subdirs... + filename)
				if len(parts) >= 2 {
					hasBuildOutDir := false
					for _, part := range parts[:len(parts)-1] {
						for _, bod := range outputDirs {
							if part == bod {
								hasBuildOutDir = true
								break
							}
						}
						if hasBuildOutDir {
							break
						}
					}
					if hasBuildOutDir {
						return true, cur
					}
				}
			}
		}
		cur = filepath.Dir(cur)
	}

	return false, ""
}

// CheckHiddenExecutableInSystemDirs checks if an executable file has a hidden filename
// (starting with '.') located in standard system directories.
func CheckHiddenExecutableInSystemDirs(path string, mode uint32, cfg *config.Config) *HeuristicMatch {
	isExec := (mode & 0111) != 0
	if !isExec {
		return nil
	}

	cleaned := filepath.Clean(path)
	base := filepath.Base(cleaned)
	if !strings.HasPrefix(base, ".") || base == "." || base == ".." {
		return nil
	}

	systemDirs := []string{
		"/bin",
		"/sbin",
		"/usr/bin",
		"/usr/sbin",
		"/usr/local/bin",
		"/usr/local/sbin",
		"/etc",
	}

	inSystemDir := false
	for _, sysDir := range systemDirs {
		if strings.HasPrefix(cleaned, sysDir+"/") {
			inSystemDir = true
			break
		}
	}

	if !inSystemDir {
		return nil
	}

	score := config.DefaultScoreHiddenExe
	if cfg != nil && cfg.Scan.ScoreHiddenExe > 0 {
		score = cfg.Scan.ScoreHiddenExe
	}

	return &HeuristicMatch{
		Name:     "Heuristic_Hidden_Executable_In_System_Dir",
		Reason:   fmt.Sprintf("Executable file with hidden filename %q located in system directory %s", base, filepath.Dir(cleaned)),
		Score:    score,
		Severity: report.SeverityWarning,
	}
}

// CheckSuspiciousSUID checks for SUID or SGID permissions on files located outside
// standard system binary locations.
func CheckSuspiciousSUID(path string, mode uint32, cfg *config.Config) *HeuristicMatch {
	hasSUID := (mode & unix.S_ISUID) != 0
	hasSGID := (mode & unix.S_ISGID) != 0
	isExec := (mode & 0111) != 0

	if (!hasSUID && !hasSGID) || !isExec {
		return nil
	}

	cleaned := filepath.Clean(path)
	standardDirs := []string{
		"/bin",
		"/sbin",
		"/usr/bin",
		"/usr/sbin",
		"/usr/lib",
		"/usr/libexec",
	}

	isStandard := false
	for _, stdDir := range standardDirs {
		if strings.HasPrefix(cleaned, stdDir+"/") {
			isStandard = true
			break
		}
	}

	if isStandard {
		return nil
	}

	score := config.DefaultScoreSuspiciousSUID
	if cfg != nil && cfg.Scan.ScoreSuspiciousSUID > 0 {
		score = cfg.Scan.ScoreSuspiciousSUID
	}

	return &HeuristicMatch{
		Name:     "Heuristic_Suspicious_SUID_SGID",
		Reason:   fmt.Sprintf("Privileged SUID/SGID executable located outside standard binary paths: %s", cleaned),
		Score:    score,
		Severity: report.SeverityAlert,
	}
}

// CheckWorldWritableInEtc checks for world-writable configuration files inside /etc.
func CheckWorldWritableInEtc(path string, mode uint32, cfg *config.Config) *HeuristicMatch {
	cleaned := filepath.Clean(path)
	if !strings.HasPrefix(cleaned, "/etc/") {
		return nil
	}

	isWorldWritable := (mode & unix.S_IWOTH) != 0
	if !isWorldWritable {
		return nil
	}

	score := config.DefaultScoreWorldWritableEtc
	if cfg != nil && cfg.Scan.ScoreWorldWritableEtc > 0 {
		score = cfg.Scan.ScoreWorldWritableEtc
	}

	return &HeuristicMatch{
		Name:     "Heuristic_World_Writable_In_Etc",
		Reason:   fmt.Sprintf("World-writable system configuration file discovered in /etc: %s", cleaned),
		Score:    score,
		Severity: report.SeverityWarning,
	}
}
