package scanner

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"aether/internal/config"
	"aether/internal/pkgdb"
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

var privateKeyHeaders = [][]byte{
	[]byte("-----BEGIN OPENSSH PRIVATE KEY-----"),
	[]byte("-----BEGIN RSA PRIVATE KEY-----"),
	[]byte("-----BEGIN EC PRIVATE KEY-----"),
	[]byte("-----BEGIN DSA PRIVATE KEY-----"),
	[]byte("-----BEGIN PRIVATE KEY-----"),
	[]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
	[]byte("PuTTY-User-Key-File-"),
}

// IsPrivateKeyMaterial checks if the leading bytes contain known private key headers.
func IsPrivateKeyMaterial(data []byte) bool {
	head := data
	if len(head) > 2048 {
		head = head[:2048]
	}
	for _, hdr := range privateKeyHeaders {
		if bytes.Contains(head, hdr) {
			return true
		}
	}
	return false
}

// CheckSuspiciousPrivateKeyMaterial evaluates if a file contains private key material
// stored in a hidden or non-standard system directory.
func CheckSuspiciousPrivateKeyMaterial(path string, data []byte, pkgDB pkgdb.PackageDB, cfg *config.Config) *HeuristicMatch {
	if !IsPrivateKeyMaterial(data) {
		return nil
	}

	cleaned := filepath.Clean(path)

	// Standard legitimate key locations (standard system keys or standard user .ssh)
	if strings.HasPrefix(cleaned, "/etc/ssh/") ||
		strings.HasPrefix(cleaned, "/etc/ssl/") ||
		strings.HasPrefix(cleaned, "/etc/pki/") ||
		strings.HasPrefix(cleaned, "/etc/letsencrypt/") ||
		strings.HasPrefix(cleaned, "/etc/ipsec") ||
		strings.HasPrefix(cleaned, "/etc/openvpn/") ||
		strings.HasPrefix(cleaned, "/etc/wireguard/") ||
		strings.HasPrefix(cleaned, "/var/lib/puppet/") ||
		strings.HasPrefix(cleaned, "/var/lib/acme/") {
		dir := filepath.Dir(cleaned)
		if !strings.Contains(dir, "/.") {
			return nil
		}
	} else if strings.HasPrefix(cleaned, "/root/.ssh/") || (strings.HasPrefix(cleaned, "/home/") && strings.Contains(cleaned, "/.ssh/")) {
		dir := filepath.Dir(cleaned)
		base := filepath.Base(cleaned)
		if strings.HasSuffix(dir, "/.ssh") && !strings.HasPrefix(base, ".") {
			return nil
		}
	}

	// Skip package-owned files
	if pkgDB != nil && pkgDB.IsAvailable() {
		if _, ok := pkgDB.Owner(cleaned); ok {
			return nil
		}
	}

	// Flag if located in system directories (/usr, /lib, /etc, /var, /opt, /srv, /tmp, /dev) or in hidden paths
	isSuspiciousTree := strings.HasPrefix(cleaned, "/usr/") ||
		strings.HasPrefix(cleaned, "/lib") ||
		strings.HasPrefix(cleaned, "/etc/") ||
		strings.HasPrefix(cleaned, "/var/") ||
		strings.HasPrefix(cleaned, "/opt/") ||
		strings.HasPrefix(cleaned, "/srv/") ||
		strings.HasPrefix(cleaned, "/tmp/") ||
		strings.HasPrefix(cleaned, "/var/tmp/") ||
		strings.HasPrefix(cleaned, "/dev/shm/") ||
		strings.Contains(cleaned, "/.")

	if !isSuspiciousTree {
		return nil
	}

	score := config.DefaultScoreSuspiciousPrivateKey
	if cfg != nil && cfg.Scan.ScoreSuspiciousPrivateKey > 0 {
		score = cfg.Scan.ScoreSuspiciousPrivateKey
	}

	return &HeuristicMatch{
		Name:     "File_Suspicious_Private_Key_Location",
		Reason:   fmt.Sprintf("Private key material in suspicious location (%s)", cleaned),
		Score:    score,
		Severity: report.SeverityWarning,
	}
}

var (
	reRevShellInteractive = regexp.MustCompile(`(?i)(?:(?:/(?:usr/)?bin/)?(?:ba)?sh|dash|zsh)\s+-i\s+>&?\s*/dev/(?:tcp|udp)/\S+|/dev/(?:tcp|udp)/\S+\s+0>&1|exec\s+\d+<>/dev/(?:tcp|udp)/\S+|0<&196;\s*exec\s+196<>/dev/(?:tcp|udp)/`)
	reOpenSSLRevShell     = regexp.MustCompile(`(?i)openssl\s+s_client\s+(?:-[a-zA-Z0-9_-]+\s+)*-connect\s+\S+[\s\S]*\|\s*(?:/(?:usr/)?bin/)?(?:ba)?sh|openssl\s+s_client\s+.*-connect\s+<\s*/tmp/`)
	reSocatRevShell      = regexp.MustCompile(`(?i)socat\s+.*(?:exec|pty|system|openssl-connect)\s*:\s*['"]?(?:/(?:usr/)?bin/)?(?:ba)?sh|socat\s+openssl-connect:\S+`)
	reProcHiding         = regexp.MustCompile(`(?i)mount\s+-t\s+tmpfs\s+(?:-o\s+\S+\s+)?(?:tmpfs\s+)?['"]?/proc/(?:\$\{[a-zA-Z0-9_]+\}|\$[a-zA-Z0-9_]+|\d+)`)
	reRedTeamFramework   = regexp.MustCompile(`(?i)GHOST-SHELL|KALI-MASTER.*PERSISTENCE|TIER-1\s+RED\s+TEAM\s+IMPLANT|systemd-resolved-updater`)
	reNetcatRevShell     = regexp.MustCompile(`(?i)(?:nc|ncat|netcat)(?:\.traditional)?\s+(?:-\S*\s+)*-[ec]\s+(?:/(?:usr/)?bin/)?(?:ba)?sh|mkfifo\s+\S+;\s*(?:/(?:usr/)?bin/)?(?:ba)?sh.*\|\s*(?:nc|ncat|netcat)\s+`)
	reInlineScriptRev    = regexp.MustCompile(`(?i)(?:python[23]?|perl|php|ruby)\s+-[a-zA-Z0-9]*[cer]\s+[\s\S]*(?:socket\.(?:socket|connect)|use\s+Socket|fsockopen|TCPSocket|pty\.spawn)|(?:import\s+(?:ssl,\s*)?socket[\s\S]*socket\.socket[\s\S]*\.connect\s*\(\s*\([\s\S]*,\s*\S+\s*\)[\s\S]*(?:os\.dup2|subprocess|pty\.spawn|send\(b?['"]\+))`)
	reWebshellGeneric    = regexp.MustCompile(`(?i)(?:eval|assert|passthru|shell_exec|system|popen|proc_open)\s*\(\s*(?:(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(\s*)?\$_(?:POST|GET|REQUEST|COOKIE)\[`)
	reDownloadAndExec    = regexp.MustCompile(`(?i)(?:curl\s+-[a-zA-Z]*s[a-zA-Z]*|wget\s+-[a-zA-Z]*q[a-zA-Z]*)\s+https?://\S+\s*\|\s*(?:ba)?sh`)
	reRansomwareScript   = regexp.MustCompile(`(?i)(?:from\s+cryptography\.fernet\s+import\s+Fernet|Crypto\.Cipher|AES\.new|Fernet\()[\s\S]*(?:os\.walk|os\.scandir|rglob|glob\.glob)[\s\S]*(?:\.encrypt\(|os\.remove|\.locked|\.enc\b|ransom|RESCUE|DECRYPT|victim|TARGET_DIR)`)
	reDataExfiltration   = regexp.MustCompile(`(?i)(?:(?:socket\.socket|socket\.create_connection|requests\.post|urllib\.request)[\s\S]*(?:os\.walk|os\.listdir|os\.scandir|iter_files|rglob|TARGET_DIR)[\s\S]*(?:sendall|send\(|socket\.send)|(?:exfil|exfiltrat|stealer)[\s\S]*(?:socket|requests|urllib|sendall|b64encode)|(?:zlib\.compress|base64\.b64encode)[\s\S]*(?:sendall|send\(|socket\.send))`)
	reExfilServer        = regexp.MustCompile(`(?i)socket\.socket[\s\S]*\.bind\s*\(\s*\([\s\S]*\.listen[\s\S]*\.accept[\s\S]*(?:zlib\.decompress|base64\.b64decode|exfil|stolen|victim|tree\.json|dump_payload)`)
)

// CheckSuspiciousScriptContent evaluates file bytes for malicious script patterns,
// including interactive/encrypted reverse shells, netcat/socat listeners, procfs manipulation,
// red-team persistence frameworks, webshells, and download droppers.
func CheckSuspiciousScriptContent(path string, data []byte, pkgDB pkgdb.PackageDB, cfg *config.Config) *HeuristicMatch {
	if len(data) == 0 {
		return nil
	}

	cleaned := filepath.Clean(path)

	// Documentation metadata (.dist-info, .egg-info, markdown, rst) contains benign example setup commands
	isDoc := strings.Contains(cleaned, ".dist-info/") || strings.Contains(cleaned, ".egg-info/") ||
		strings.HasSuffix(cleaned, ".md") || strings.HasSuffix(cleaned, ".rst") || strings.HasSuffix(cleaned, ".txt")
	isTest := strings.Contains(cleaned, "/test/") || strings.Contains(cleaned, "/tests/") ||
		strings.HasPrefix(filepath.Base(cleaned), "test_") || strings.Contains(filepath.Base(cleaned), "_test.")

	// If documentation metadata, suppress non-critical dropper/server/exfil text examples
	if isDoc {
		if !reRedTeamFramework.Match(data) && !reProcHiding.Match(data) && !reOpenSSLRevShell.Match(data) &&
			!reRevShellInteractive.Match(data) && !reNetcatRevShell.Match(data) && !reSocatRevShell.Match(data) &&
			!reRansomwareScript.Match(data) {
			return nil
		}
	}

	// If unit test file, mock server listeners are benign test fixtures
	if isTest && reExfilServer.Match(data) && !reRevShellInteractive.Match(data) && !reRansomwareScript.Match(data) && !reRedTeamFramework.Match(data) {
		return nil
	}

	// 1. Red-team persistence framework / implant markers
	if reRedTeamFramework.Match(data) {
		return &HeuristicMatch{
			Name:     "Script_RedTeam_Persistence_Framework",
			Reason:   fmt.Sprintf("Red-team persistence framework signature or implant markers in %s", filepath.Base(cleaned)),
			Score:    95,
			Severity: report.SeverityAlert,
		}
	}

	// 2. Process hiding via procfs mount manipulation
	if reProcHiding.Match(data) {
		return &HeuristicMatch{
			Name:     "Script_Process_Hiding_Procfs",
			Reason:   fmt.Sprintf("Stealth process hiding via procfs tmpfs mount manipulation in %s", filepath.Base(cleaned)),
			Score:    90,
			Severity: report.SeverityAlert,
		}
	}

	// 3. Encrypted OpenSSL reverse shell
	if reOpenSSLRevShell.Match(data) {
		return &HeuristicMatch{
			Name:     "Script_OpenSSL_Reverse_Shell",
			Reason:   fmt.Sprintf("Encrypted OpenSSL interactive reverse shell payload in %s", filepath.Base(cleaned)),
			Score:    95,
			Severity: report.SeverityAlert,
		}
	}

	// 4. Interactive bash/sh /dev/tcp or /dev/udp reverse shell
	if reRevShellInteractive.Match(data) {
		return &HeuristicMatch{
			Name:     "Script_Reverse_Shell_Interactive",
			Reason:   fmt.Sprintf("Interactive reverse shell command payload (/dev/tcp redirection) in script %s", filepath.Base(cleaned)),
			Score:    90,
			Severity: report.SeverityAlert,
		}
	}

	// 5. Netcat reverse shell
	if reNetcatRevShell.Match(data) {
		return &HeuristicMatch{
			Name:     "Script_Netcat_Reverse_Shell",
			Reason:   fmt.Sprintf("Netcat interactive reverse shell payload (-e /bin/sh) in script %s", filepath.Base(cleaned)),
			Score:    90,
			Severity: report.SeverityAlert,
		}
	}

	// 6. Socat reverse shell (including openssl-connect)
	if reSocatRevShell.Match(data) {
		return &HeuristicMatch{
			Name:     "Script_Socat_Reverse_Shell",
			Reason:   fmt.Sprintf("Socat interactive reverse shell payload in script %s", filepath.Base(cleaned)),
			Score:    90,
			Severity: report.SeverityAlert,
		}
	}

	// 7. Inline interpreter reverse shell (Python, Perl, PHP)
	if reInlineScriptRev.Match(data) {
		return &HeuristicMatch{
			Name:     "Script_Reverse_Shell_Inline",
			Reason:   fmt.Sprintf("Inline interpreter network reverse shell payload in script %s", filepath.Base(cleaned)),
			Score:    85,
			Severity: report.SeverityAlert,
		}
	}

	// 8. Generic PHP webshell / backdoor evaluation
	if reWebshellGeneric.Match(data) {
		return &HeuristicMatch{
			Name:     "Webshell_PHP_Generic_Backdoor",
			Reason:   fmt.Sprintf("Dynamic evaluation webshell backdoor payload in %s", filepath.Base(cleaned)),
			Score:    90,
			Severity: report.SeverityAlert,
		}
	}

	// 9. Download and execute dropper (curl | sh)
	if reDownloadAndExec.Match(data) {
		return &HeuristicMatch{
			Name:     "Script_Download_And_Execute",
			Reason:   fmt.Sprintf("Remote download-and-pipe execution payload (curl/wget | sh) in script %s", filepath.Base(cleaned)),
			Score:    65,
			Severity: report.SeverityWarning,
		}
	}

	// 10. Python / Script Ransomware Encryptor (Fernet/AES + file walking + locking/deletion)
	if reRansomwareScript.Match(data) {
		return &HeuristicMatch{
			Name:     "Script_Python_Ransomware_Encryptor",
			Reason:   fmt.Sprintf("Automated file encryption and ransomware locker routine in script %s", filepath.Base(cleaned)),
			Score:    95,
			Severity: report.SeverityAlert,
		}
	}

	// 11. Data Exfiltration Stealer (socket/HTTP + directory traversal + compression/encoding)
	if reDataExfiltration.Match(data) {
		return &HeuristicMatch{
			Name:     "Script_Data_Exfiltration_Stealer",
			Reason:   fmt.Sprintf("Automated filesystem harvesting and network exfiltration routine in script %s", filepath.Base(cleaned)),
			Score:    90,
			Severity: report.SeverityAlert,
		}
	}

	// 12. C2 Data Exfiltration Collection Server
	if reExfilServer.Match(data) {
		return &HeuristicMatch{
			Name:     "Script_C2_Exfiltration_Server",
			Reason:   fmt.Sprintf("Command-and-control exfiltration listener and data collection server in script %s", filepath.Base(cleaned)),
			Score:    75,
			Severity: report.SeverityWarning,
		}
	}

	return nil
}


