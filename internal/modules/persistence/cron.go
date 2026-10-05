package persistence

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"aether/internal/config"
	"aether/internal/ioc"
	"aether/internal/pkgdb"
	"aether/internal/report"
	"aether/internal/safeopen"
)

// CheckCron inspects system and user crontabs, cron directories, and at jobs.
func CheckCron(ctx context.Context, rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, iocEng ioc.Engine, cov *CheckCoverage) ([]report.Finding, error) {
	cov.Name = "cron"
	var findings []report.Finding

	cronPaths := []string{
		"/etc/crontab",
	}

	cronDirs := []string{
		"/etc/cron.d",
		"/etc/cron.hourly",
		"/etc/cron.daily",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
		"/var/spool/cron/crontabs",
		"/var/spool/cron",
		"/var/spool/at",
		"/var/spool/cron/atjobs",
	}

	seenFiles := make(map[string]bool)

	// 1. Inspect direct files
	for _, p := range cronPaths {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		seenFiles[p] = true
		inspectCronFile(p, rootFS, cfg, pkgDB, iocEng, cov, &findings)
	}

	// 2. Inspect directories
	for _, dir := range cronDirs {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		hostDir, _, _, err := safeopen.ResolveUnderRoot(rootFS, dir)
		if err != nil {
			if os.IsNotExist(err) || errors.Is(err, safeopen.ErrVanished) || errors.Is(err, os.ErrNotExist) {
				cov.Missing++
			} else {
				cov.RecordUnreadable(dir, err)
			}
			continue
		}

		entries, err := os.ReadDir(hostDir)
		if err != nil {
			if os.IsNotExist(err) || errors.Is(err, safeopen.ErrVanished) || errors.Is(err, os.ErrNotExist) {
				cov.Missing++
			} else {
				cov.RecordUnreadable(dir, err)
			}
			continue
		}

		for _, entry := range entries {
			// Skip subdirectories inside cron dirs (e.g. /var/spool/cron/crontabs inside /var/spool/cron)
			if entry.IsDir() {
				continue
			}

			// Skip standard debian package state files or dotfiles
			name := entry.Name()
			if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".dpkg-old") || strings.HasSuffix(name, ".dpkg-dist") || name == "placeholder" {
				continue
			}

			virtPath := filepath.Join(dir, name)
			if seenFiles[virtPath] {
				continue
			}
			seenFiles[virtPath] = true
			inspectCronFile(virtPath, rootFS, cfg, pkgDB, iocEng, cov, &findings)
		}
	}

	return findings, nil
}

func inspectCronFile(virtPath, rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, iocEng ioc.Engine, cov *CheckCoverage, findings *[]report.Finding) {
	base := filepath.Base(virtPath)
	if base == ".placeholder" || base == "placeholder" {
		return
	}

	hostPath := virtPath
	if rootFS != "" {
		hostPath = filepath.Join(rootFS, strings.TrimPrefix(virtPath, "/"))
	}

	lst, err := os.Lstat(hostPath)
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, safeopen.ErrVanished) || errors.Is(err, os.ErrNotExist) {
			cov.Missing++
		} else {
			cov.RecordUnreadable(virtPath, err)
		}
		return
	}

	if lst.IsDir() {
		// Directory encountered; do not count as file inspection or unreadable error
		return
	}

	cov.Inspected++

	var signals []*PersistenceSignal
	isUserCrontab := strings.HasPrefix(virtPath, "/var/spool/cron") || strings.HasPrefix(virtPath, "/var/spool/at")
	isSystemContext := !isUserCrontab

	// Check if the cron file itself is a symlink
	if (lst.Mode() & os.ModeSymlink) != 0 {
		if symSig := AssessSymlink(rootFS, virtPath, pkgDB, isUserCrontab, "", 0); symSig != nil {
			signals = append(signals, symSig)
		}
	}

	// Safe read up to 1MB
	data, isSymlink, rErr := SafeReadRegularFile(rootFS, virtPath, 1024*1024)
	if rErr != nil {
		cov.RecordUnreadable(virtPath, rErr)
		return
	}
	if isSymlink {
		// Evaluated above by AssessSymlink; do not duplicate
		if len(signals) > 0 {
			meta := map[string]any{
				"artifact": "cron",
				"file":     virtPath,
			}
			if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
				*findings = append(*findings, *f)
			}
		}
		return
	}

	// Check for binary or oversized file in cron directory (only system cron drops)
	if !isUserCrontab && len(data) > 0 {
		// If data contains NULL bytes or ELF magic, it is a binary file in cron.d
		if bytes.Contains(data, []byte{0x00}) || bytes.HasPrefix(data, []byte("\x7fELF")) {
			signals = append(signals, &PersistenceSignal{
				Class:       ClassObfuscation,
				RuleName:    "Persistence_Cron_Binary_File",
				Reason:      "Cron file contains binary/non-text content (malformed cron drop)",
				Score:       75,
				Severity:    report.SeverityWarning,
				IsStrong:    true,
				LineNumber:  0,
			})
		}
	}

	fileGuards := ExtractGuardedPaths(string(data))
	// Parse lines
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	var lastSuspiciousLine string
	var allExecTargets []string
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check environment overrides like PATH=/tmp:... or LD_PRELOAD=
		if strings.HasPrefix(line, "PATH=") && (strings.Contains(line, "/tmp") || strings.Contains(line, "/var/tmp") || strings.Contains(line, "/dev/shm")) {
			signals = append(signals, &PersistenceSignal{
				Class:       ClassExecFromTemp,
				RuleName:    "Persistence_Cron_Temp_Path",
				Reason:      "Cron PATH environment variable prepends volatile directory",
				Score:       70,
				Severity:    report.SeverityWarning,
				IsStrong:    true,
				LineNumber:  lineNum,
				Snippet:     RedactSnippet(line),
			})
		}

		// Check command patterns (strip cron schedule first so command/exec targets are extracted properly)
		cmdText := stripCronSchedule(line, isUserCrontab)
		cmdSignals := CheckSuspiciousCommand(cmdText, lineNum, cfg, rootFS, isSystemContext, pkgDB, fileGuards)
		if len(cmdSignals) > 0 {
			lastSuspiciousLine = line
			execTargets, _ := ExtractExecTargets(cmdText)
			allExecTargets = append(allExecTargets, execTargets...)
		}
		signals = append(signals, cmdSignals...)
	}

	if len(signals) > 0 {
		meta := map[string]any{
			"artifact":     "cron",
			"file":         virtPath,
			"line_content": lastSuspiciousLine,
			"exec_targets": dedupeSlice(allExecTargets),
		}
		if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
			*findings = append(*findings, *f)
		}
	}
}

func stripCronSchedule(line string, isUserCrontab bool) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return line
	}
	if strings.HasPrefix(fields[0], "@") {
		// e.g. @reboot [user] command in /etc/crontab or @reboot command in user crontab
		if !isUserCrontab {
			if len(fields) >= 3 && !strings.Contains(fields[1], "/") && !strings.Contains(fields[1], "=") {
				return strings.Join(fields[2:], " ")
			}
		}
		if len(fields) > 1 {
			return strings.Join(fields[1:], " ")
		}
		return line
	}
	isCronSpec := func(s string) bool {
		for _, r := range s {
			if !((r >= '0' && r <= '9') || r == '*' || r == '/' || r == '-' || r == ',') {
				return false
			}
		}
		return len(s) > 0
	}

	if len(fields) >= 6 && isCronSpec(fields[0]) && isCronSpec(fields[1]) && isCronSpec(fields[2]) && isCronSpec(fields[3]) && isCronSpec(fields[4]) {
		if isUserCrontab {
			// User crontab: 5 time fields, command starts at fields[5]
			return strings.Join(fields[5:], " ")
		}
		// System crontab: 5 time fields + 1 username field
		if len(fields) >= 7 && !strings.Contains(fields[5], "/") && !strings.Contains(fields[5], ";") && !strings.Contains(fields[5], "|") {
			return strings.Join(fields[6:], " ")
		}
		return strings.Join(fields[5:], " ")
	}
	return line
}
