package persistence

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"aether/internal/config"
	"aether/internal/ioc"
	"aether/internal/pkgdb"
	"aether/internal/report"
	"aether/internal/safeopen"
)

var (
	reUdevRun    = regexp.MustCompile(`RUN(?:\+?=)\s*["']?([^"'\n]+)`)
	reSudoNoPass = regexp.MustCompile(`(?i)NOPASSWD\s*:\s*ALL`)
	reSudoNoAuth = regexp.MustCompile(`(?i)!authenticate`)
	reAptHook    = regexp.MustCompile(`(?i)(?:Pre-Invoke|Post-Invoke|Pre-Install-Pkgs)\s*\{[^}]*["']([^"']+)["']`)
)

// CheckOtherHooks inspects rc.local, init.d, rc*.d, udev rules, sudoers, motd, apt hooks, and autostart.
func CheckOtherHooks(ctx context.Context, rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, iocEng ioc.Engine, cov *CheckCoverage) ([]report.Finding, error) {
	cov.Name = "hooks"
	var findings []report.Finding

	// 1. /etc/rc.local
	inspectRcLocal(rootFS, cfg, pkgDB, cov, &findings)

	// 2. /etc/init.d/ scripts
	inspectInitD(rootFS, cfg, pkgDB, cov, &findings)

	// 3. /etc/rc*.d/ runlevel scripts and symlinks
	inspectRCD(rootFS, cfg, pkgDB, cov, &findings)

	// 4. /etc/udev/rules.d/
	inspectUdevRules(rootFS, cfg, pkgDB, cov, &findings)

	// 5. /etc/sudoers and /etc/sudoers.d/
	inspectSudoers(rootFS, cfg, cov, &findings)

	// 6. /etc/update-motd.d/
	inspectUpdateMotd(rootFS, cfg, pkgDB, cov, &findings)

	// 7. /etc/apt/apt.conf.d/
	inspectAptHooks(rootFS, cfg, pkgDB, cov, &findings)

	// 8. XDG autostart
	inspectXDGAutostart(rootFS, cfg, pkgDB, cov, &findings)

	// 9. binfmt_misc handler registrations
	inspectBinfmtMisc(rootFS, cfg, pkgDB, cov, &findings)

	return findings, nil
}

func inspectRcLocal(rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, cov *CheckCoverage, findings *[]report.Finding) {
	virtPath := "/etc/rc.local"
	cov.Inspected++
	data, isSymlink, err := SafeReadRegularFile(rootFS, virtPath, 256*1024)
	if err != nil {
		if os.IsNotExist(err) {
			cov.Missing++
		} else {
			cov.RecordUnreadable(virtPath, err)
		}
		return
	}

	var signals []*PersistenceSignal
	if isSymlink {
		if symSig := AssessSymlink(rootFS, virtPath, pkgDB, false, "", 0); symSig != nil {
			signals = append(signals, symSig)
		}
	}

	fileGuards := ExtractGuardedPaths(string(data))
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	var allExecTargets []string
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || line == "exit 0" {
			continue
		}
		cmdSignals := CheckSuspiciousCommand(line, lineNum, cfg, rootFS, true, pkgDB, fileGuards)
		if len(cmdSignals) > 0 {
			execTargets, _ := ExtractExecTargets(line)
			allExecTargets = append(allExecTargets, execTargets...)
		}
		signals = append(signals, cmdSignals...)
	}

	if len(signals) > 0 {
		meta := map[string]any{"artifact": "rc.local", "file": virtPath, "exec_targets": dedupeSlice(allExecTargets)}
		if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
			*findings = append(*findings, *f)
		}
	}
}

func inspectInitD(rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, cov *CheckCoverage, findings *[]report.Finding) {
	initDir := "/etc/init.d"
	hostDir := initDir
	if rootFS != "" {
		hostDir = filepath.Join(rootFS, "etc/init.d")
	}

	entries, err := os.ReadDir(hostDir)
	if err != nil {
		return
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		virtPath := filepath.Join(initDir, e.Name())
		cov.Inspected++

		var signals []*PersistenceSignal
		isPackageOwned := false
		if pkgDB != nil && pkgDB.IsAvailable() {
			if _, ok := pkgDB.Owner(virtPath); !ok {
				signals = append(signals, &PersistenceSignal{
					Class:      ClassUnowned,
					RuleName:   "Persistence_InitD_Unowned_Script",
					Reason:     fmt.Sprintf("Init script %s is not owned by any OS package", virtPath),
					Score:      20,
					Severity:   report.SeverityNotice,
					LineNumber: 0,
					Snippet:    virtPath,
				})
			} else {
				isPackageOwned = true
			}
		}

		var allExecTargets []string
		data, _, rErr := SafeReadRegularFile(rootFS, virtPath, 256*1024)
		if rErr == nil {
			fileGuards := ExtractGuardedPaths(string(data))
			scanner := bufio.NewScanner(bytes.NewReader(data))
			lineNum := 0
			inHeredoc := false
			heredocDelim := ""
			prevContinuation := false

			for scanner.Scan() {
				lineNum++
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				if inHeredoc {
					if line == heredocDelim {
						inHeredoc = false
						heredocDelim = ""
					}
					continue
				}
				if strings.Contains(line, "<<") {
					idx := strings.Index(line, "<<")
					rem := strings.TrimSpace(line[idx+2:])
					rem = strings.TrimPrefix(rem, "-")
					rem = strings.TrimSpace(rem)
					delim := strings.Fields(rem)
					if len(delim) > 0 {
						heredocDelim = strings.Trim(delim[0], `"'`)
						inHeredoc = true
					}
				}

				if prevContinuation {
					prevContinuation = strings.HasSuffix(line, "\\")
					continue
				}
				prevContinuation = strings.HasSuffix(line, "\\")

				cmdSignals := CheckSuspiciousCommand(line, lineNum, cfg, rootFS, true, pkgDB, fileGuards)
				if len(cmdSignals) > 0 {
					execTargets, _ := ExtractExecTargets(line)
					allExecTargets = append(allExecTargets, execTargets...)
				}
				for _, cs := range cmdSignals {
					if isPackageOwned && (cs.Class == ClassMissingTarget || cs.Class == ClassUnowned) {
						continue
					}
					signals = append(signals, cs)
				}
			}
		}

		if len(signals) > 0 {
			meta := map[string]any{"artifact": "init.d", "file": virtPath, "exec_targets": dedupeSlice(allExecTargets)}
			if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
				*findings = append(*findings, *f)
			}
		}
	}
}

func inspectRCD(rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, cov *CheckCoverage, findings *[]report.Finding) {
	rcDirs := []string{
		"/etc/rc0.d",
		"/etc/rc1.d",
		"/etc/rc2.d",
		"/etc/rc3.d",
		"/etc/rc4.d",
		"/etc/rc5.d",
		"/etc/rc6.d",
		"/etc/rcS.d",
		"/etc/rc.local.d",
	}

	for _, rcDir := range rcDirs {
		hostDir, _, _, err := safeopen.ResolveUnderRoot(rootFS, rcDir)
		if err != nil {
			continue
		}

		entries, err := os.ReadDir(hostDir)
		if err != nil {
			continue
		}

		for _, e := range entries {
			if e.IsDir() {
				continue
			}

			virtPath := filepath.Join(rcDir, e.Name())
			cov.Inspected++

			var signals []*PersistenceSignal
			hostEntry := filepath.Join(hostDir, e.Name())
			lst, lErr := os.Lstat(hostEntry)
			if lErr != nil {
				continue
			}

			isSymlink := (lst.Mode() & os.ModeSymlink) != 0
			isPackageOwned := false
			if pkgDB != nil && pkgDB.IsAvailable() {
				if _, ok := pkgDB.Owner(virtPath); ok {
					isPackageOwned = true
				}
			}

			if isSymlink {
				if symSig := AssessSymlink(rootFS, virtPath, pkgDB, false, "", 0); symSig != nil {
					signals = append(signals, symSig)
				}
			}

			var allExecTargets []string
			// Read script content (following symlink within root if valid)
			_, targetVirt, _, rErr := safeopen.ResolveUnderRoot(rootFS, virtPath)
			if rErr == nil {
				if pkgDB != nil && pkgDB.IsAvailable() && !isPackageOwned {
					if _, ok := pkgDB.Owner(targetVirt); ok {
						isPackageOwned = true
					}
				}

				if !isPackageOwned && !isSymlink {
					signals = append(signals, &PersistenceSignal{
						Class:      ClassUnowned,
						RuleName:   "Persistence_RCD_Unowned_Script",
						Reason:     fmt.Sprintf("Runlevel script %s is not owned by any OS package", virtPath),
						Score:      20,
						Severity:   report.SeverityNotice,
						LineNumber: 0,
						Snippet:    virtPath,
					})
				}

				data, _, readErr := SafeReadRegularFile(rootFS, targetVirt, 256*1024)
				if readErr == nil {
					fileGuards := ExtractGuardedPaths(string(data))
					scanner := bufio.NewScanner(bytes.NewReader(data))
					lineNum := 0
					for scanner.Scan() {
						lineNum++
						line := strings.TrimSpace(scanner.Text())
						if line == "" || strings.HasPrefix(line, "#") {
							continue
						}
						cmdSignals := CheckSuspiciousCommand(line, lineNum, cfg, rootFS, true, pkgDB, fileGuards)
						if len(cmdSignals) > 0 {
							execTargets, _ := ExtractExecTargets(line)
							allExecTargets = append(allExecTargets, execTargets...)
						}
						for _, cs := range cmdSignals {
							if isPackageOwned && (cs.Class == ClassMissingTarget || cs.Class == ClassUnowned) {
								continue
							}
							signals = append(signals, cs)
						}
					}
				}
			}

			if len(signals) > 0 {
				meta := map[string]any{"artifact": "rc.d", "file": virtPath, "exec_targets": dedupeSlice(allExecTargets)}
				if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
					*findings = append(*findings, *f)
				}
			}
		}
	}
}

func inspectUdevRules(rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, cov *CheckCoverage, findings *[]report.Finding) {
	udevDir := "/etc/udev/rules.d"
	hostDir, _, _, uErr := safeopen.ResolveUnderRoot(rootFS, udevDir)
	if uErr != nil {
		if rootFS != "" {
			hostDir = filepath.Join(rootFS, "etc/udev/rules.d")
		} else {
			hostDir = udevDir
		}
	}

	entries, err := os.ReadDir(hostDir)
	if err != nil {
		return
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rules") {
			continue
		}
		virtPath := filepath.Join(udevDir, e.Name())
		cov.Inspected++

		data, _, rErr := SafeReadRegularFile(rootFS, virtPath, 256*1024)
		if rErr != nil {
			continue
		}

		var signals []*PersistenceSignal
		scanner := bufio.NewScanner(bytes.NewReader(data))
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			if matches := reUdevRun.FindStringSubmatch(line); len(matches) > 1 {
				cmd := strings.TrimSpace(matches[1])
				isTemp := strings.HasPrefix(cmd, "/tmp/") || strings.HasPrefix(cmd, "/var/tmp/") || strings.HasPrefix(cmd, "/dev/shm/")
				if isTemp {
					signals = append(signals, &PersistenceSignal{
						Class:      ClassExecFromTemp,
						RuleName:   "Persistence_Udev_Exec_Temp",
						Reason:     fmt.Sprintf("Udev rule executes program from volatile directory: %s", cmd),
						Score:      85,
						Severity:   report.SeverityAlert,
						IsStrong:   true,
						LineNumber: lineNum,
						Snippet:    RedactSnippet(cmd),
					})
				} else {
					cmdSignals := CheckSuspiciousCommand(cmd, lineNum, cfg, rootFS, true, pkgDB)
					signals = append(signals, cmdSignals...)
				}
			}
		}

		if len(signals) > 0 {
			meta := map[string]any{"artifact": "udev", "file": virtPath}
			if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
				*findings = append(*findings, *f)
			}
		}
	}
}

func inspectSudoers(rootFS string, cfg *config.Config, cov *CheckCoverage, findings *[]report.Finding) {
	files := []string{"/etc/sudoers"}

	dDir := "/etc/sudoers.d"
	if hostD, _, _, err := safeopen.ResolveUnderRoot(rootFS, dDir); err == nil {
		if entries, err := os.ReadDir(hostD); err == nil {
			for _, e := range entries {
				if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") && !strings.HasSuffix(e.Name(), "~") {
					files = append(files, filepath.Join(dDir, e.Name()))
				}
			}
		}
	}

	for _, virtFile := range files {
		cov.Inspected++
		data, _, err := SafeReadRegularFile(rootFS, virtFile, 256*1024)
		if err != nil {
			if os.IsNotExist(err) {
				cov.Missing++
			} else {
				cov.RecordUnreadable(virtFile, err)
			}
			continue
		}

		var signals []*PersistenceSignal
		scanner := bufio.NewScanner(bytes.NewReader(data))
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Requirement: !authenticate = WARNING
			if reSudoNoAuth.MatchString(line) {
				signals = append(signals, &PersistenceSignal{
					Class:      ClassPrivilegeAbuse,
					RuleName:   "Persistence_Sudoers_No_Authenticate",
					Reason:     "Sudoers directive disables authentication (!authenticate)",
					Score:      65,
					Severity:   report.SeverityWarning,
					LineNumber: lineNum,
					Snippet:    RedactSnippet(line),
				})
			}

			// Requirement: NOPASSWD ALL = NOTICE, raise only with another signal
			if reSudoNoPass.MatchString(line) {
				signals = append(signals, &PersistenceSignal{
					Class:      ClassPrivilegeAbuse,
					RuleName:   "Persistence_Sudoers_NOPASSWD_ALL",
					Reason:     "Sudoers grants passwordless root execution (NOPASSWD: ALL)",
					Score:      20,
					Severity:   report.SeverityNotice,
					LineNumber: lineNum,
					Snippet:    RedactSnippet(line),
				})
			}

			// Check for commands executed or included from temp
			if strings.Contains(line, "/tmp") || strings.Contains(line, "/var/tmp") || strings.Contains(line, "/dev/shm") {
				signals = append(signals, &PersistenceSignal{
					Class:      ClassExecFromTemp,
					RuleName:   "Persistence_Sudoers_Temp_Path",
					Reason:     "Sudoers references temporary directory",
					Score:      75,
					Severity:   report.SeverityWarning,
					LineNumber: lineNum,
					Snippet:    RedactSnippet(line),
				})
			}
		}

		// Accuracy rule for sudoers:
		// "NOPASSWD ALL = NOTICE, raise only with another signal"
		// If the ONLY signal is NOPASSWD_ALL, do not raise a finding (standard in cloud images).
		if len(signals) == 1 && signals[0].RuleName == "Persistence_Sudoers_NOPASSWD_ALL" {
			continue
		}

		if len(signals) > 0 {
			meta := map[string]any{"artifact": "sudoers", "file": virtFile}
			if f := ConsolidateSignals(signals, virtFile, meta); f != nil {
				*findings = append(*findings, *f)
			}
		}
	}
}

func inspectUpdateMotd(rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, cov *CheckCoverage, findings *[]report.Finding) {
	motdDir := "/etc/update-motd.d"
	hostDir, _, _, err := safeopen.ResolveUnderRoot(rootFS, motdDir)
	if err != nil {
		return
	}

	entries, err := os.ReadDir(hostDir)
	if err != nil {
		return
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		virtPath := filepath.Join(motdDir, e.Name())
		cov.Inspected++

		var signals []*PersistenceSignal
		if pkgDB != nil && pkgDB.IsAvailable() {
			if _, ok := pkgDB.Owner(virtPath); !ok {
				signals = append(signals, &PersistenceSignal{
					Class:      ClassUnowned,
					RuleName:   "Persistence_MOTD_Unowned_Script",
					Reason:     fmt.Sprintf("Update-MOTD script %s is not owned by any OS package", virtPath),
					Score:      20,
					Severity:   report.SeverityNotice,
					LineNumber: 0,
					Snippet:    virtPath,
				})
			}
		}

		var allExecTargets []string
		data, _, rErr := SafeReadRegularFile(rootFS, virtPath, 256*1024)
		if rErr == nil {
			fileGuards := ExtractGuardedPaths(string(data))
			scanner := bufio.NewScanner(bytes.NewReader(data))
			lineNum := 0
			for scanner.Scan() {
				lineNum++
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				cmdSignals := CheckSuspiciousCommand(line, lineNum, cfg, rootFS, true, pkgDB, fileGuards)
				if len(cmdSignals) > 0 {
					execTargets, _ := ExtractExecTargets(line)
					allExecTargets = append(allExecTargets, execTargets...)
				}
				signals = append(signals, cmdSignals...)
			}
		}

		if len(signals) > 0 {
			meta := map[string]any{"artifact": "update-motd", "file": virtPath, "exec_targets": dedupeSlice(allExecTargets)}
			if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
				*findings = append(*findings, *f)
			}
		}
	}
}

func inspectAptHooks(rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, cov *CheckCoverage, findings *[]report.Finding) {
	aptDir := "/etc/apt/apt.conf.d"
	hostDir, _, _, err := safeopen.ResolveUnderRoot(rootFS, aptDir)
	if err != nil {
		return
	}

	entries, err := os.ReadDir(hostDir)
	if err != nil {
		return
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		virtPath := filepath.Join(aptDir, e.Name())
		cov.Inspected++

		data, _, rErr := SafeReadRegularFile(rootFS, virtPath, 256*1024)
		if rErr != nil {
			continue
		}

		fileGuards := ExtractGuardedPaths(string(data))
		var signals []*PersistenceSignal
		content := string(data)
		matches := reAptHook.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) > 1 {
				cmd := strings.TrimSpace(m[1])
				isTemp := strings.Contains(cmd, "/tmp") || strings.Contains(cmd, "/var/tmp") || strings.Contains(cmd, "/dev/shm")
				if isTemp {
					signals = append(signals, &PersistenceSignal{
						Class:      ClassExecFromTemp,
						RuleName:   "Persistence_APT_Hook_Temp",
						Reason:     fmt.Sprintf("APT invocation hook points to volatile path: %s", cmd),
						Score:      85,
						Severity:   report.SeverityAlert,
						IsStrong:   true,
						LineNumber: 0,
						Snippet:    RedactSnippet(cmd),
					})
				} else {
					cmdSignals := CheckSuspiciousCommand(cmd, 0, cfg, rootFS, true, pkgDB, fileGuards)
					signals = append(signals, cmdSignals...)
				}
			}
		}

		if len(signals) > 0 {
			meta := map[string]any{"artifact": "apt_hook", "file": virtPath}
			if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
				*findings = append(*findings, *f)
			}
		}
	}
}

func inspectXDGAutostart(rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, cov *CheckCoverage, findings *[]report.Finding) {
	searchDirs := []string{"/etc/xdg/autostart"}

	// Also per-user autostart
	users := parsePasswd(rootFS, cov)
	if len(users) == 0 {
		homeBase := "/home"
		if hostHome, _, _, err := safeopen.ResolveUnderRoot(rootFS, homeBase); err == nil {
			if entries, err := os.ReadDir(hostHome); err == nil {
				for _, e := range entries {
					if e.IsDir() {
						users = append(users, passwdUser{
							Username: e.Name(),
							Home:     "/home/" + e.Name(),
						})
					}
				}
			}
		}
	}
	for _, u := range users {
		if u.Home != "" {
			searchDirs = append(searchDirs, filepath.Join(u.Home, ".config/autostart"))
		}
	}

	for _, dir := range searchDirs {
		hostDir, _, _, err := safeopen.ResolveUnderRoot(rootFS, dir)
		if err != nil {
			continue
		}

		entries, err := os.ReadDir(hostDir)
		if err != nil {
			continue
		}

		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".desktop") {
				continue
			}
			virtPath := filepath.Join(dir, e.Name())
			cov.Inspected++

			isPackageOwned := false
			if pkgDB != nil && pkgDB.IsAvailable() {
				if _, ok := pkgDB.Owner(virtPath); ok {
					isPackageOwned = true
				}
			}

			data, _, rErr := SafeReadRegularFile(rootFS, virtPath, 256*1024)
			if rErr != nil {
				continue
			}

			fileGuards := ExtractGuardedPaths(string(data))
			var signals []*PersistenceSignal
			scanner := bufio.NewScanner(bytes.NewReader(data))
			lineNum := 0
			var lastSuspiciousLine string
			var allExecTargets []string
			isUserAutostart := strings.Contains(virtPath, "/home/") || strings.Contains(virtPath, "/root/")
			for scanner.Scan() {
				lineNum++
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "Exec=") {
					cmd := strings.TrimPrefix(line, "Exec=")
					cmdSignals := CheckSuspiciousCommand(cmd, lineNum, cfg, rootFS, !isUserAutostart, pkgDB, fileGuards)
					if len(cmdSignals) > 0 {
						lastSuspiciousLine = line
						execTargets, _ := ExtractExecTargets(cmd)
						allExecTargets = append(allExecTargets, execTargets...)
					}
					for _, cs := range cmdSignals {
						if isPackageOwned && (cs.Class == ClassMissingTarget || cs.Class == ClassUnowned) {
							continue
						}
						signals = append(signals, cs)
					}
				}
			}

			if len(signals) > 0 {
				meta := map[string]any{
					"artifact":     "xdg_autostart",
					"file":         virtPath,
					"line_content": lastSuspiciousLine,
					"exec_targets": dedupeSlice(allExecTargets),
				}
				if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
					*findings = append(*findings, *f)
				}
			}
		}
	}
}

func inspectBinfmtMisc(rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, cov *CheckCoverage, findings *[]report.Finding) {
	binfmtDirs := []string{
		"/etc/binfmt.d",
		"/usr/lib/binfmt.d",
		"/run/binfmt.d",
	}

	seenFiles := make(map[string]bool)

	for _, bDir := range binfmtDirs {
		hostDir, _, _, err := safeopen.ResolveUnderRoot(rootFS, bDir)
		if err != nil {
			continue
		}

		entries, err := os.ReadDir(hostDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
				continue
			}
			virtPath := filepath.Join(bDir, entry.Name())
			if seenFiles[virtPath] {
				continue
			}
			seenFiles[virtPath] = true
			cov.Inspected++

			var signals []*PersistenceSignal

			isOwned := false
			if pkgDB != nil && pkgDB.IsAvailable() {
				if _, ok := pkgDB.Owner(virtPath); ok {
					isOwned = true
				}
			}

			data, _, rErr := SafeReadRegularFile(rootFS, virtPath, 64*1024)
			var interpList []string
			if rErr == nil && len(data) > 0 {
				scanner := bufio.NewScanner(bytes.NewReader(data))
				lineNum := 0
				for scanner.Scan() {
					lineNum++
					line := strings.TrimSpace(scanner.Text())
					if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
						continue
					}
					// Format: :name:type:offset:magic:mask:interpreter:flags
					parts := strings.Split(line, ":")
					if len(parts) >= 7 {
						interp := strings.TrimSpace(parts[6])
						if interp != "" {
							interpList = append(interpList, interp)
							cleanInterp := filepath.Clean(interp)
							if strings.HasPrefix(cleanInterp, "/tmp/") ||
								strings.HasPrefix(cleanInterp, "/dev/shm/") ||
								strings.HasPrefix(cleanInterp, "/var/tmp/") ||
								strings.HasPrefix(cleanInterp, "/home/") ||
								strings.HasPrefix(cleanInterp, "/root/") {
								signals = append(signals, &PersistenceSignal{
									Class:      ClassExecFromTemp,
									RuleName:   "Persistence_Binfmt_Suspicious_Interpreter",
									Reason:     fmt.Sprintf("Binfmt registration specifies interpreter in suspicious or volatile location (%s)", interp),
									Score:      85,
									Severity:   report.SeverityAlert,
									IsStrong:   true,
									LineNumber: lineNum,
									Snippet:    line,
								})
							}
						}
					}
				}
			}

			if !isOwned && strings.HasPrefix(virtPath, "/etc/binfmt.d") {
				signals = append(signals, &PersistenceSignal{
					Class:      ClassUnowned,
					RuleName:   "Persistence_Binfmt_Unowned_Registration",
					Reason:     fmt.Sprintf("Binfmt handler registration %s is not owned by any OS package", virtPath),
					Score:      40,
					Severity:   report.SeverityNotice,
					IsStrong:   false,
					LineNumber: 0,
				})
			}

			if len(signals) > 0 {
				meta := map[string]any{
					"artifact":     "binfmt",
					"file":         virtPath,
					"is_owned":     isOwned,
					"interpreters": dedupeSlice(interpList),
				}
				if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
					*findings = append(*findings, *f)
				}
			}
		}
	}
}
