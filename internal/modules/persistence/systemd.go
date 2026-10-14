package persistence

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aether/internal/config"
	"aether/internal/ioc"
	"aether/internal/pkgdb"
	"aether/internal/report"
	"aether/internal/safeopen"
)

// CheckSystemd inspects systemd unit files, timers, and wants/requires symlinks.
func CheckSystemd(ctx context.Context, rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, iocEng ioc.Engine, cov *CheckCoverage) ([]report.Finding, error) {
	cov.Name = "systemd"
	var findings []report.Finding

	searchDirs := []string{
		"/etc/systemd/system",
		"/lib/systemd/system",
		"/usr/lib/systemd/system",
		"/usr/local/lib/systemd/system",
		"/run/systemd/system",
		"/run/systemd/generator",
		"/run/systemd/generator.early",
		"/run/systemd/generator.late",
	}

	// Also check user systemd units under /home/*/.config/systemd/user and /root/.config/systemd/user
	userDirs := findUserSystemdDirs(rootFS)
	searchDirs = append(searchDirs, userDirs...)

	seenPaths := make(map[string]bool)
	wantsSymlinks := make(map[string]string)

	for _, dir := range searchDirs {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		hostDir, _, _, err := safeopen.ResolveUnderRoot(rootFS, dir)
		if err != nil {
			continue
		}

		_ = filepath.WalkDir(hostDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					cov.Missing++
				} else {
					cov.RecordUnreadable(path, err)
				}
				return nil
			}

			// Handle files and symlinks
			virtPath := path
			if rootFS != "" {
				cleanRoot := filepath.Clean(rootFS)
				rel, _ := filepath.Rel(cleanRoot, path)
				virtPath = "/" + strings.TrimPrefix(rel, "/")
			}

			if d.IsDir() {
				return nil
			}

			resolvedVirt := ResolveVirtualPath(rootFS, virtPath)
			if seenPaths[resolvedVirt] {
				return nil
			}
			seenPaths[resolvedVirt] = true

			// Check if this is a wants or requires symlink
			isWantsOrRequires := strings.Contains(virtPath, ".wants/") || strings.Contains(virtPath, ".requires/")
			if isWantsOrRequires {
				hostTarget := path
				lst, lErr := os.Lstat(hostTarget)
				if lErr == nil && (lst.Mode()&os.ModeSymlink) != 0 {
					resolvedVirt, _, sErr := SafeResolveSymlink(rootFS, virtPath)
					if sErr == nil {
						resolvedHost := resolvedVirt
						if rootFS != "" {
							resolvedHost = filepath.Join(rootFS, strings.TrimPrefix(resolvedVirt, "/"))
						}
						if _, err := os.Stat(resolvedHost); err == nil {
							// Target unit exists on disk!
							wantsSymlinks[resolvedVirt] = virtPath
							// If finding already emitted for resolvedVirt, attach wants_symlink
							for i := range findings {
								if findings[i].Path == resolvedVirt {
									findings[i].Metadata["wants_symlink"] = virtPath
									break
								}
							}
							// Skip inspecting unit content under the wants symlink;
							// only inspect target unit if not already scanned.
							if !seenPaths[resolvedVirt] {
								seenPaths[resolvedVirt] = true
								inspectSystemdUnit(resolvedVirt, rootFS, cfg, pkgDB, iocEng, cov, &findings, virtPath)
							}
							return nil
						}
					}
				}
			}

			wantsLink := wantsSymlinks[virtPath]
			inspectSystemdUnit(virtPath, rootFS, cfg, pkgDB, iocEng, cov, &findings, wantsLink)
			return nil
		})
	}

	inspectSystemdGenerators(ctx, rootFS, cfg, pkgDB, iocEng, cov, &findings)

	return findings, nil
}

func inspectSystemdGenerators(ctx context.Context, rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, iocEng ioc.Engine, cov *CheckCoverage, findings *[]report.Finding) {
	generatorDirs := []string{
		"/etc/systemd/system-generators",
		"/usr/local/lib/systemd/system-generators",
		"/lib/systemd/system-generators",
		"/usr/lib/systemd/system-generators",
		"/etc/systemd/user-generators",
		"/usr/lib/systemd/user-generators",
	}

	seenGenerators := make(map[string]bool)

	for _, gDir := range generatorDirs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		hostDir, _, _, err := safeopen.ResolveUnderRoot(rootFS, gDir)
		if err != nil {
			continue
		}

		entries, err := os.ReadDir(hostDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			virtPath := filepath.Join(gDir, entry.Name())
			if seenGenerators[virtPath] {
				continue
			}
			seenGenerators[virtPath] = true
			cov.Inspected++

			var signals []*PersistenceSignal

			// Check symlink targeting
			hostEntry := filepath.Join(hostDir, entry.Name())
			lst, lErr := os.Lstat(hostEntry)
			if lErr != nil {
				continue
			}

			if (lst.Mode() & os.ModeSymlink) != 0 {
				resolved, _, sErr := SafeResolveSymlink(rootFS, virtPath)
				if sErr == nil {
					cleanRes := filepath.Clean(resolved)
					if strings.HasPrefix(cleanRes, "/tmp/") || strings.HasPrefix(cleanRes, "/dev/shm/") || strings.HasPrefix(cleanRes, "/var/tmp/") {
						signals = append(signals, &PersistenceSignal{
							Class:      ClassSymlinkHijack,
							RuleName:   "Persistence_Systemd_Generator_Suspicious_Target",
							Reason:     fmt.Sprintf("Systemd early-boot generator symlink targets volatile or temporary directory (%s)", cleanRes),
							Score:      90,
							Severity:   report.SeverityAlert,
							IsStrong:   true,
							LineNumber: 0,
						})
					}
				}
			}

			// Check package ownership
			isOwned := false
			if pkgDB != nil && pkgDB.IsAvailable() {
				if _, ok := pkgDB.Owner(virtPath); ok {
					isOwned = true
				}
			}

			// Read file content for suspicious commands / reverse shells
			data, _, rErr := SafeReadRegularFile(rootFS, virtPath, 256*1024)
			var allExecTargets []string
			if rErr == nil && len(data) > 0 {
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
						targets, _ := ExtractExecTargets(line)
						allExecTargets = append(allExecTargets, targets...)
					}
					signals = append(signals, cmdSignals...)
				}
			}

			// If unowned generator in /etc or /usr/local/lib
			if !isOwned && (strings.HasPrefix(virtPath, "/etc/systemd/") || strings.HasPrefix(virtPath, "/usr/local/lib/systemd/")) {
				signals = append(signals, &PersistenceSignal{
					Class:      ClassUnowned,
					RuleName:   "Persistence_Systemd_Generator_Unowned",
					Reason:     fmt.Sprintf("Systemd early-boot generator %s is not owned by any OS package", virtPath),
					Score:      65,
					Severity:   report.SeverityWarning,
					IsStrong:   false,
					LineNumber: 0,
				})
			}

			if len(signals) > 0 {
				meta := map[string]any{
					"artifact":     "systemd-generator",
					"file":         virtPath,
					"is_owned":     isOwned,
					"exec_targets": dedupeSlice(allExecTargets),
				}
				if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
					*findings = append(*findings, *f)
				}
			}
		}
	}
}

func inspectSystemdUnit(virtPath, rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, iocEng ioc.Engine, cov *CheckCoverage, findings *[]report.Finding, wantsSymlink string) {
	cov.Inspected++

	hostPath := virtPath
	if rootFS != "" {
		hostPath = filepath.Join(rootFS, strings.TrimPrefix(virtPath, "/"))
	}

	lst, lErr := os.Lstat(hostPath)
	if lErr != nil {
		if os.IsNotExist(lErr) {
			cov.Missing++
		} else {
			cov.RecordUnreadable(virtPath, lErr)
		}
		return
	}

	var signals []*PersistenceSignal

	targetVirtPath := virtPath
	isSymlink := (lst.Mode() & os.ModeSymlink) != 0
	isUserUnit := strings.Contains(virtPath, "/systemd/user")
	isSystemContext := !isUserUnit

	if isSymlink {
		rawTarget, rErr := os.Readlink(hostPath)
		if rErr == nil && (rawTarget == "/dev/null" || filepath.Clean(rawTarget) == "/dev/null") {
			cov.RecordMasked(ResolveVirtualPath(rootFS, virtPath))
			return
		}

		resolvedVirt, _, sErr := SafeResolveSymlink(rootFS, virtPath)
		if sErr == nil && (resolvedVirt == "/dev/null" || resolvedVirt == "null") {
			cov.RecordMasked(ResolveVirtualPath(rootFS, virtPath))
			return
		}

		if symSig := AssessSymlink(rootFS, virtPath, pkgDB, isUserUnit, "", 0); symSig != nil {
			signals = append(signals, symSig)
		}
		if sErr != nil {
			if errors.Is(sErr, ErrSymlinkEscapesRoot) || errors.Is(sErr, safeopen.ErrSymlinkEscapesRoot) {
				if len(signals) == 0 {
					signals = append(signals, &PersistenceSignal{
						Class:      ClassSymlinkHijack,
						RuleName:   "Persistence_Systemd_Symlink_Escape",
						Reason:     "Systemd unit symlink target escapes root filesystem boundary",
						Score:      85,
						Severity:   report.SeverityAlert,
						IsStrong:   true,
						LineNumber: 0,
					})
				}
				meta := map[string]any{
					"artifact": "systemd",
					"file":     virtPath,
					"target":   targetVirtPath,
					"is_owned": false,
				}
				if wantsSymlink != "" {
					meta["wants_symlink"] = wantsSymlink
				}
				if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
					*findings = append(*findings, *f)
				}
			} else {
				if len(signals) > 0 {
					meta := map[string]any{
						"artifact": "systemd",
						"file":     virtPath,
						"target":   targetVirtPath,
						"is_owned": false,
					}
					if wantsSymlink != "" {
						meta["wants_symlink"] = wantsSymlink
					}
					if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
						*findings = append(*findings, *f)
					}
				} else if !os.IsNotExist(sErr) && !errors.Is(sErr, safeopen.ErrVanished) {
					cov.RecordUnreadable(virtPath, sErr)
				}
			}
			return
		}
		targetVirtPath = resolvedVirt
	}

	// Check package ownership of unit target
	isPackageOwned := false
	if pkgDB != nil && pkgDB.IsAvailable() {
		if _, ok := pkgDB.Owner(targetVirtPath); ok {
			isPackageOwned = true
		} else if _, ok := pkgDB.Owner(virtPath); ok {
			isPackageOwned = true
		}
	}

	// If it is a symlink pointing to a package-owned unit, do not flag the symlink itself
	if isSymlink && isPackageOwned {
		// Enabled unit symlink to standard service is completely benign
		return
	}

	// If unowned and package DB is available: low score signal only
	if pkgDB != nil && pkgDB.IsAvailable() && !isPackageOwned {
		// Only check unowned for top-level unit definitions
		if strings.HasSuffix(virtPath, ".service") || strings.HasSuffix(virtPath, ".timer") || strings.HasSuffix(virtPath, ".socket") {
			ruleName := "Persistence_Systemd_Unowned_Unit"
			if strings.HasSuffix(virtPath, ".socket") {
				ruleName = "Persistence_Systemd_Unowned_Socket"
			}
			signals = append(signals, &PersistenceSignal{
				Class:      ClassUnowned,
				RuleName:   ruleName,
				Reason:     fmt.Sprintf("Systemd unit file (%s) is not owned by any installed OS package", filepath.Base(virtPath)),
				Score:      cfg.Scan.ScorePersistSystemdUnowned,
				Severity:   report.SeverityNotice,
				IsStrong:   false,
				LineNumber: 0,
			})
		}
	}

	// Check mtime: only flag if NOT package-owned
	recentDays := cfg.Scan.ScorePersistRecentMtimeDays
	if recentDays <= 0 {
		recentDays = config.DefaultScorePersistRecentMtimeDays
	}
	cutoff := time.Now().Add(-time.Duration(recentDays) * 24 * time.Hour)
	if !isPackageOwned && lst.ModTime().After(cutoff) {
		signals = append(signals, &PersistenceSignal{
			Class:      ClassRecentMod,
			RuleName:   "Persistence_Systemd_Recently_Modified",
			Reason:     fmt.Sprintf("Non-package-owned systemd unit modified recently (%s)", lst.ModTime().Format(time.RFC3339)),
			Score:      15,
			Severity:   report.SeverityNotice,
			LineNumber: 0,
		})
	}

	// Read unit content
	data, _, rErr := SafeReadRegularFile(rootFS, targetVirtPath, 1024*1024)
	if rErr != nil {
		if len(signals) > 0 {
			meta := map[string]any{
				"artifact": "systemd",
				"file":     virtPath,
				"target":   targetVirtPath,
				"is_owned": isPackageOwned,
			}
			if wantsSymlink != "" {
				meta["wants_symlink"] = wantsSymlink
			}
			if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
				*findings = append(*findings, *f)
			}
		} else if !os.IsNotExist(rErr) && !errors.Is(rErr, safeopen.ErrVanished) {
			cov.RecordUnreadable(virtPath, rErr)
		}
		return
	}

	fileGuards := ExtractGuardedPaths(string(data))
	// Parse Exec directives
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	var allExecTargets []string
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "ExecStart=") ||
			strings.HasPrefix(line, "ExecStartPre=") ||
			strings.HasPrefix(line, "ExecStartPost=") ||
			strings.HasPrefix(line, "ExecStop=") ||
			strings.HasPrefix(line, "ExecReload=") {

			idx := strings.Index(line, "=")
			cmd := strings.TrimSpace(line[idx+1:])
			// Strip leading '-' or '@' modifiers in systemd
			cmd = strings.TrimPrefix(cmd, "-")
			cmd = strings.TrimPrefix(cmd, "@")

			cmdSignals := CheckSuspiciousCommand(cmd, lineNum, cfg, rootFS, isSystemContext, pkgDB, fileGuards)
			execTargets, _ := ExtractExecTargets(cmd)
			allExecTargets = append(allExecTargets, execTargets...)
			for _, cs := range cmdSignals {
				if isPackageOwned && (cs.Class == ClassMissingTarget || cs.Class == ClassUnowned) {
					continue
				}
				signals = append(signals, cs)
			}
		}

		if strings.HasPrefix(line, "ListenStream=") ||
			strings.HasPrefix(line, "ListenDatagram=") ||
			strings.HasPrefix(line, "ListenSequentialPacket=") ||
			strings.HasPrefix(line, "ListenFIFO=") {

			idx := strings.Index(line, "=")
			listenVal := strings.TrimSpace(line[idx+1:])

			if strings.HasPrefix(listenVal, "/tmp/") ||
				strings.HasPrefix(listenVal, "/var/tmp/") ||
				strings.HasPrefix(listenVal, "/dev/shm/") {
				signals = append(signals, &PersistenceSignal{
					Class:      ClassExecFromTemp,
					RuleName:   "Persistence_Systemd_Socket_Activation",
					Reason:     fmt.Sprintf("Systemd socket listening on volatile/temporary FIFO: %s", listenVal),
					Score:      75,
					Severity:   report.SeverityWarning,
					IsStrong:   true,
					LineNumber: lineNum,
				})
			} else if !isPackageOwned {
				signals = append(signals, &PersistenceSignal{
					Class:      ClassConfigDeviation,
					RuleName:   "Persistence_Systemd_Socket_Activation",
					Reason:     fmt.Sprintf("Non-package-owned systemd socket listening on endpoint: %s", listenVal),
					Score:      70,
					Severity:   report.SeverityWarning,
					IsStrong:   true,
					LineNumber: lineNum,
				})
			}
		}
	}

	if len(signals) > 0 {
		meta := map[string]any{
			"artifact":     "systemd",
			"file":         virtPath,
			"target":       targetVirtPath,
			"is_owned":     isPackageOwned,
			"exec_targets": dedupeSlice(allExecTargets),
		}
		if wantsSymlink != "" {
			meta["wants_symlink"] = wantsSymlink
		}
		if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
			*findings = append(*findings, *f)
		}
	}
}

func findUserSystemdDirs(rootFS string) []string {
	var dirs []string
	homeDir := "/home"
	if hostHome, _, _, err := safeopen.ResolveUnderRoot(rootFS, homeDir); err == nil {
		if entries, err := os.ReadDir(hostHome); err == nil {
			for _, e := range entries {
				if e.IsDir() {
					dirs = append(dirs, filepath.Join("/home", e.Name(), ".config/systemd/user"))
					dirs = append(dirs, filepath.Join("/home", e.Name(), ".local/share/systemd/user"))
				}
			}
		}
	}
	dirs = append(dirs, "/root/.config/systemd/user", "/root/.local/share/systemd/user")
	return dirs
}
