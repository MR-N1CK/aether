package persistence

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"aether/internal/config"
	"aether/internal/ioc"
	"aether/internal/pkgdb"
	"aether/internal/report"
)

var reAliasPriv = regexp.MustCompile(`(?i)^\s*alias\s+(sudo|su|ssh)\s*=`)

// CheckProfiles inspects system-wide and user shell startup scripts and environment files.
func CheckProfiles(ctx context.Context, rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, iocEng ioc.Engine, cov *CheckCoverage) ([]report.Finding, error) {
	cov.Name = "profiles"
	var findings []report.Finding

	systemFiles := []string{
		"/etc/profile",
		"/etc/bash.bashrc",
		"/etc/environment",
		"/etc/zsh/zprofile",
		"/etc/zsh/zshrc",
	}

	// 1. Inspect system files
	for _, p := range systemFiles {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
		inspectProfileFile(p, rootFS, cfg, pkgDB, iocEng, cov, &findings)
	}

	// 2. Inspect /etc/profile.d/*
	profileD := "/etc/profile.d"
	hostProfileD := profileD
	if rootFS != "" {
		hostProfileD = filepath.Join(rootFS, "etc/profile.d")
	}
	if entries, err := os.ReadDir(hostProfileD); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				virtPath := filepath.Join(profileD, e.Name())
				inspectProfileFile(virtPath, rootFS, cfg, pkgDB, iocEng, cov, &findings)
			}
		}
	} else if os.IsNotExist(err) {
		cov.Missing++
	} else {
		cov.RecordUnreadable(profileD, err)
	}

	// 3. Inspect user shell files
	users := parsePasswd(rootFS, cov)
	hasRoot := false
	for _, u := range users {
		if u.Username == "root" || u.UID == 0 {
			hasRoot = true
			break
		}
	}
	if !hasRoot {
		users = append(users, passwdUser{Username: "root", UID: 0, Home: "/root", Shell: "/bin/bash"})
	}

	userFiles := []string{
		".bashrc",
		".bash_profile",
		".profile",
		".zshrc",
		".zprofile",
		".bash_logout",
	}

	for _, user := range users {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		if user.Home == "" {
			continue
		}

		for _, uf := range userFiles {
			virtPath := filepath.Join(user.Home, uf)
			inspectProfileFile(virtPath, rootFS, cfg, pkgDB, iocEng, cov, &findings)
		}
	}

	return findings, nil
}

func inspectProfileFile(virtPath, rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, iocEng ioc.Engine, cov *CheckCoverage, findings *[]report.Finding) {
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

	cov.Inspected++
	var signals []*PersistenceSignal

	isSystemProfile := strings.HasPrefix(virtPath, "/etc/")
	userHome := ""
	if !isSystemProfile {
		if strings.HasPrefix(virtPath, "/home/") {
			parts := strings.Split(virtPath, "/")
			if len(parts) >= 3 {
				userHome = "/home/" + parts[2]
			}
		} else if strings.HasPrefix(virtPath, "/root/") {
			userHome = "/root"
		}
	}

	// Check if symlink
	if (lst.Mode() & os.ModeSymlink) != 0 {
		if symSig := AssessSymlink(rootFS, virtPath, pkgDB, !isSystemProfile, userHome, 0); symSig != nil {
			signals = append(signals, symSig)
		}
	}

	data, isSymlink, rErr := SafeReadRegularFile(rootFS, virtPath, 1024*1024)
	if rErr != nil {
		cov.RecordUnreadable(virtPath, rErr)
		return
	}
	if isSymlink {
		if len(signals) > 0 {
			meta := map[string]any{
				"artifact": "profile",
				"file":     virtPath,
			}
			if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
				*findings = append(*findings, *f)
			}
		}
		return
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	var lastSuspiciousLine string
	var allExecTargets []string
	var accumulatedLine string
	accumulatedStartLine := 0

	processLine := func(line string, effectiveLineNum int) {
		if line == "" || strings.HasPrefix(line, "#") {
			return
		}

		// 1. Check for LD_PRELOAD injection
		if strings.HasPrefix(line, "LD_PRELOAD=") || strings.HasPrefix(line, "export LD_PRELOAD=") {
			lastSuspiciousLine = line
			signals = append(signals, &PersistenceSignal{
				Class:       ClassObfuscation,
				RuleName:    "Persistence_Profile_LD_PRELOAD",
				Reason:      "Shell startup file defines LD_PRELOAD dynamic linker interceptor",
				Score:       cfg.Scan.ScorePersistLoaderPreload,
				Severity:    report.SeverityWarning,
				IsStrong:    true,
				LineNumber:  effectiveLineNum,
				Snippet:     RedactSnippet(line),
			})
		}

		// 2. Check for PATH prepend to volatile or hidden directories
		if strings.HasPrefix(line, "PATH=") || strings.HasPrefix(line, "export PATH=") {
			if strings.Contains(line, "/tmp") || strings.Contains(line, "/var/tmp") || strings.Contains(line, "/dev/shm") {
				lastSuspiciousLine = line
				signals = append(signals, &PersistenceSignal{
					Class:       ClassExecFromTemp,
					RuleName:    "Persistence_Profile_Temp_PATH",
					Reason:      "PATH variable prepends volatile directory (binary hijacking risk)",
					Score:       cfg.Scan.ScorePersistProfileTemp,
					Severity:    report.SeverityWarning,
					IsStrong:    true,
					LineNumber:  effectiveLineNum,
					Snippet:     RedactSnippet(line),
				})
			}
		}

		// 3. Check for alias hijacking sudo/su/ssh
		if reAliasPriv.MatchString(line) {
			lastSuspiciousLine = line
			signals = append(signals, &PersistenceSignal{
				Class:       ClassPrivilegeAbuse,
				RuleName:    "Persistence_Profile_Privileged_Alias",
				Reason:      "Alias overrides critical security command (sudo/su/ssh credential harvesting risk)",
				Score:       cfg.Scan.ScorePersistProfileAlias,
				Severity:    report.SeverityWarning,
				IsStrong:    true,
				LineNumber:  effectiveLineNum,
				Snippet:     RedactSnippet(line),
			})
		}

		// 4. Check general command patterns (curl|sh, reverse shells, base64)
		cmdSignals := CheckSuspiciousCommand(line, effectiveLineNum, cfg, rootFS, isSystemProfile, pkgDB)
		if len(cmdSignals) > 0 {
			lastSuspiciousLine = line
			execTargets, _ := ExtractExecTargets(line)
			allExecTargets = append(allExecTargets, execTargets...)
		}
		signals = append(signals, cmdSignals...)
	}

	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			if accumulatedLine == "" {
				continue
			}
		}

		if strings.HasSuffix(trimmed, "\\") {
			linePart := strings.TrimSpace(strings.TrimSuffix(trimmed, "\\"))
			if accumulatedLine == "" {
				accumulatedStartLine = lineNum
				accumulatedLine = linePart
			} else {
				accumulatedLine += " " + linePart
			}
			continue
		}

		currLine := trimmed
		currLineNum := lineNum
		if accumulatedLine != "" {
			currLine = accumulatedLine + " " + trimmed
			currLineNum = accumulatedStartLine
			accumulatedLine = ""
		}
		processLine(currLine, currLineNum)
	}
	if accumulatedLine != "" {
		processLine(accumulatedLine, accumulatedStartLine)
	}

	if len(signals) > 0 {
		meta := map[string]any{
			"artifact":     "profile",
			"file":         virtPath,
			"line_content": lastSuspiciousLine,
			"exec_targets": allExecTargets,
		}
		if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
			*findings = append(*findings, *f)
		}
	}
}
