package persistence

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"aether/internal/config"
	"aether/internal/ioc"
	"aether/internal/pkgdb"
	"aether/internal/report"
	"aether/internal/safeopen"
)

type passwdUser struct {
	Username string
	UID      int
	Home     string
	Shell    string
}

func isDummyHome(home string) bool {
	h := filepath.Clean(home)
	return h == "" || h == "/" || h == "/nonexistent" || h == "/dev" || h == "/proc" ||
		h == "/bin" || h == "/sbin" || h == "/usr/sbin" || h == "/usr/bin" ||
		h == "/var/empty" || h == "/dev/null" || h == "/run/systemd"
}

// CheckSSH inspects authorized_keys across users and sshd_config.
func CheckSSH(ctx context.Context, rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, iocEng ioc.Engine, cov *CheckCoverage) ([]report.Finding, error) {
	cov.Name = "ssh"
	var findings []report.Finding

	// 1. Parse /etc/passwd to find all users, home dirs, and shells
	users := parsePasswd(rootFS, cov)

	// Ensure root is in the list
	hasRoot := false
	for _, u := range users {
		if u.Username == "root" || u.UID == 0 {
			hasRoot = true
			break
		}
	}
	if !hasRoot {
		users = append(users, passwdUser{
			Username: "root",
			UID:      0,
			Home:     "/root",
			Shell:    "/bin/bash",
		})
	}

	for _, user := range users {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		if isDummyHome(user.Home) {
			continue
		}

		hostHome, _, _, err := safeopen.ResolveUnderRoot(rootFS, user.Home)
		if err != nil {
			cov.Missing++
			continue
		}
		if fi, sErr := os.Stat(hostHome); sErr != nil || !fi.IsDir() {
			cov.Missing++
			continue
		}

		for _, kf := range []string{".ssh/authorized_keys", ".ssh/authorized_keys2"} {
			virtPath := filepath.Join(user.Home, kf)
			inspectAuthorizedKeys(virtPath, user, rootFS, cfg, pkgDB, cov, &findings)
		}
	}

	// 2. Check sshd_config and sshd_config.d/*.conf
	inspectSSHDConfig(rootFS, cfg, cov, &findings)

	return findings, nil
}

func parsePasswd(rootFS string, cov *CheckCoverage) []passwdUser {
	data, err := safeopen.ReadFileReadOnlyUnderRoot(rootFS, "/etc/passwd", 1024*1024)
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, safeopen.ErrVanished) || errors.Is(err, os.ErrNotExist) {
			cov.Missing++
		} else {
			cov.RecordUnreadable("/etc/passwd", err)
		}
		return nil
	}

	var users []passwdUser
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) >= 7 {
			uid, _ := strconv.Atoi(parts[2])
			users = append(users, passwdUser{
				Username: parts[0],
				UID:      uid,
				Home:     parts[5],
				Shell:    parts[6],
			})
		}
	}
	return users
}

func isNologinShell(shell string) bool {
	s := strings.TrimSpace(shell)
	return strings.HasSuffix(s, "/nologin") ||
		strings.HasSuffix(s, "/false") ||
		strings.HasSuffix(s, "/true") ||
		s == "/usr/bin/false" ||
		s == "/bin/false"
}

func inspectAuthorizedKeys(virtPath string, user passwdUser, rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, cov *CheckCoverage, findings *[]report.Finding) {
	hostPath, _, isSymlink, err := safeopen.ResolveUnderRoot(rootFS, virtPath)
	if err != nil {
		if !isSymlink {
			if os.IsNotExist(err) || errors.Is(err, safeopen.ErrVanished) || errors.Is(err, os.ErrNotExist) {
				cov.Missing++
			} else {
				cov.RecordUnreadable(virtPath, err)
			}
			return
		}
	}

	cov.Inspected++
	var signals []*PersistenceSignal

	// 1. Symlinked authorized_keys file: assess symlink safely
	// IMPORTANT: Never read or quote target contents for foreign/cross-boundary symlinks
	if isSymlink {
		if symSig := AssessSymlink(rootFS, virtPath, pkgDB, true, user.Home, uint32(user.UID)); symSig != nil {
			signals = append(signals, symSig)
		} else {
			signals = append(signals, &PersistenceSignal{
				Class:      ClassSymlinkHijack,
				RuleName:   "Persistence_SSH_Symlink_Key",
				Reason:     "SSH authorized_keys is a symlink",
				Score:      25,
				Severity:   report.SeverityNotice,
				IsStrong:   false,
				LineNumber: 0,
			})
		}
		// Stop here: never read or quote target contents when user file is a symlink
		if len(signals) > 0 {
			meta := map[string]any{
				"artifact": "ssh",
				"user":     user.Username,
				"uid":      user.UID,
				"file":     virtPath,
			}
			if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
				*findings = append(*findings, *f)
			}
		}
		return
	}

	// 2. Permissions check on file and parent .ssh directory
	lst, lErr := os.Lstat(hostPath)
	if lErr == nil {
		mode := lst.Mode()
		if mode&0022 != 0 { // group or world writable
			signals = append(signals, &PersistenceSignal{
				Class:      ClassPrivilegeAbuse,
				RuleName:   "Persistence_SSH_Insecure_Permissions",
				Reason:     fmt.Sprintf("SSH authorized_keys file has insecure permissions (%04o)", mode.Perm()),
				Score:      cfg.Scan.ScorePersistSSHPerms,
				Severity:   report.SeverityWarning,
				LineNumber: 0,
			})
		}
	}

	dotSSHDir := filepath.Dir(virtPath)
	if hostDotSSHDir, _, _, dErr := safeopen.ResolveUnderRoot(rootFS, dotSSHDir); dErr == nil {
		if dirStat, dErr := os.Stat(hostDotSSHDir); dErr == nil {
			if dirStat.Mode()&0022 != 0 {
				signals = append(signals, &PersistenceSignal{
					Class:      ClassPrivilegeAbuse,
					RuleName:   "Persistence_SSH_Insecure_Dir_Permissions",
					Reason:     fmt.Sprintf("Parent .ssh directory has insecure permissions (%04o)", dirStat.Mode().Perm()),
					Score:      cfg.Scan.ScorePersistSSHPerms,
					Severity:   report.SeverityWarning,
					LineNumber: 0,
				})
			}
		}
	}

	// 3. Mtime check
	recentDays := cfg.Scan.ScorePersistRecentMtimeDays
	if recentDays <= 0 {
		recentDays = config.DefaultScorePersistRecentMtimeDays
	}
	cutoff := time.Now().Add(-time.Duration(recentDays) * 24 * time.Hour)
	if lst.ModTime().After(cutoff) {
		signals = append(signals, &PersistenceSignal{
			Class:      ClassRecentMod,
			RuleName:   "Persistence_SSH_Recently_Modified",
			Reason:     fmt.Sprintf("SSH authorized_keys file modified recently (%s)", lst.ModTime().Format(time.RFC3339)),
			Score:      15,
			Severity:   report.SeverityNotice,
			LineNumber: 0,
		})
	}

	// Read file safely
	data, _, rErr := SafeReadRegularFile(rootFS, virtPath, 1024*1024)
	if rErr != nil {
		cov.RecordUnreadable(virtPath, rErr)
		return
	}

	var allTargets []string
	hasKeys := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		hasKeys = true
		keyType, comment, fingerprint, forcedCmd := parseAuthorizedKeyLine(line)

		// 4. Forced command parsing
		if forcedCmd != "" {
			signals = append(signals, &PersistenceSignal{
				Class:      ClassPrivilegeAbuse,
				RuleName:   "Persistence_SSH_Forced_Command",
				Reason:     fmt.Sprintf("SSH key enforces command execution: %s", RedactSnippet(forcedCmd)),
				Score:      cfg.Scan.ScorePersistSSHForcedCmd,
				Severity:   report.SeverityWarning,
				LineNumber: lineNum,
				Snippet:    RedactSnippet(forcedCmd),
			})
			cmdSignals := CheckSuspiciousCommand(forcedCmd, lineNum, cfg, rootFS, user.UID == 0, pkgDB)
			signals = append(signals, cmdSignals...)
		}

		// 5. Privileged account key with no comment
		if user.UID == 0 && comment == "" {
			signals = append(signals, &PersistenceSignal{
				Class:      ClassPrivilegeAbuse,
				RuleName:   "Persistence_SSH_Privileged_Key_No_Comment",
				Reason:     fmt.Sprintf("SSH key on privileged account (%s) has no comment or identifier [%s fp:%s]", user.Username, keyType, fingerprint),
				Score:      cfg.Scan.ScorePersistSSHNoCommentPriv,
				Severity:   report.SeverityNotice,
				LineNumber: lineNum,
				Snippet:    fmt.Sprintf("%s fp:%s", keyType, fingerprint),
			})
		}

		// 6. Keys referencing non-standard or hidden key locations
		for _, refPath := range extractPathsFromKeyLine(line, comment) {
			if !isStandardSSHKeyPath(refPath) {
				signals = append(signals, &PersistenceSignal{
					Class:      ClassPrivilegeAbuse,
					RuleName:   "Persistence_SSH_Key_Non_Standard_Location",
					Reason:     fmt.Sprintf("SSH key entry [%s fp:%s] references key or path outside standard locations (%s)", keyType, fingerprint, refPath),
					Score:      70,
					Severity:   report.SeverityWarning,
					IsStrong:   true,
					LineNumber: lineNum,
					Snippet:    fmt.Sprintf("%s fp:%s comment:%q", keyType, fingerprint, RedactSnippet(comment)),
				})
				allTargets = append(allTargets, refPath)
			}
		}
	}

	// 7. Keys present on system accounts with nologin shell
	if hasKeys && isNologinShell(user.Shell) {
		signals = append(signals, &PersistenceSignal{
			Class:      ClassPrivilegeAbuse,
			RuleName:   "Persistence_SSH_Key_On_Nologin_Account",
			Reason:     fmt.Sprintf("System account %q has shell %s but possesses active authorized_keys", user.Username, user.Shell),
			Score:      cfg.Scan.ScorePersistSSHSystemNologin,
			Severity:   report.SeverityWarning,
			LineNumber: 0,
		})
	}

	if len(signals) > 0 {
		meta := map[string]any{
			"artifact":     "ssh",
			"user":         user.Username,
			"uid":          user.UID,
			"file":         virtPath,
			"exec_targets": allTargets,
		}
		if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
			*findings = append(*findings, *f)
		}
	}
}

// parseAuthorizedKeyLine safely extracts key type, comment, short fingerprint, and forced command.
// Never returns full key blob.
func parseAuthorizedKeyLine(line string) (keyType, comment, fingerprint, forcedCmd string) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return
	}

	startIdx := 0
	// Check for leading options (e.g. command="...",no-pty)
	if !strings.HasPrefix(fields[0], "ssh-") && !strings.HasPrefix(fields[0], "ecdsa-") {
		// First field has options
		optPart := fields[0]
		if strings.Contains(line, "command=") {
			// Extract command="..." value
			cmdIdx := strings.Index(line, "command=\"")
			if cmdIdx != -1 {
				cmdRest := line[cmdIdx+9:]
				endQuote := strings.Index(cmdRest, "\"")
				if endQuote != -1 {
					forcedCmd = cmdRest[:endQuote]
				}
			}
		}

		// Find where the key type begins
		for i, f := range fields {
			if strings.HasPrefix(f, "ssh-") || strings.HasPrefix(f, "ecdsa-") {
				startIdx = i
				break
			}
		}
		if startIdx == 0 && len(fields) > 1 {
			startIdx = 1
		}
		_ = optPart
	}

	if startIdx < len(fields) {
		keyType = fields[startIdx]
	}

	if startIdx+1 < len(fields) {
		blob := fields[startIdx+1]
		if decoded, err := base64.StdEncoding.DecodeString(blob); err == nil && len(decoded) > 0 {
			h := sha256.Sum256(decoded)
			fingerprint = hex.EncodeToString(h[:])[:12]
		}
	}

	if startIdx+2 < len(fields) {
		comment = strings.Join(fields[startIdx+2:], " ")
	}

	return
}

func inspectSSHDConfig(rootFS string, cfg *config.Config, cov *CheckCoverage, findings *[]report.Finding) {
	configFiles := []string{"/etc/ssh/sshd_config"}

	dDir := "/etc/ssh/sshd_config.d"
	hostDDir := dDir
	if rootFS != "" {
		hostDDir = filepath.Join(rootFS, "etc/ssh/sshd_config.d")
	}
	if entries, err := os.ReadDir(hostDDir); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".conf") && !e.IsDir() {
				configFiles = append(configFiles, filepath.Join(dDir, e.Name()))
			}
		}
	}

	for _, virtFile := range configFiles {
		cov.Inspected++
		data, _, err := SafeReadRegularFile(rootFS, virtFile, 512*1024)
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

			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "permitrootlogin") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && strings.ToLower(fields[1]) == "yes" {
					signals = append(signals, &PersistenceSignal{
						Class:      ClassConfigDeviation,
						RuleName:   "Persistence_SSHD_PermitRootLogin_Yes",
						Reason:     "sshd_config allows direct root login with password (PermitRootLogin yes)",
						Score:      cfg.Scan.ScorePersistSSHConfig,
						Severity:   report.SeverityNotice,
						LineNumber: lineNum,
						Snippet:    line,
					})
				}
			}

			if strings.HasPrefix(lower, "authorizedkeyscommand") {
				signals = append(signals, &PersistenceSignal{
					Class:      ClassConfigDeviation,
					RuleName:   "Persistence_SSHD_AuthorizedKeysCommand",
					Reason:     "sshd_config specifies external AuthorizedKeysCommand (key retrieval hook)",
					Score:      cfg.Scan.ScorePersistSSHConfig,
					Severity:   report.SeverityNotice,
					LineNumber: lineNum,
					Snippet:    RedactSnippet(line),
				})
			}

			if strings.HasPrefix(lower, "authorizedkeysfile") {
				fields := strings.Fields(line)
				for _, fld := range fields[1:] {
					if !strings.HasPrefix(fld, ".ssh/") && !strings.HasPrefix(fld, "%h/.ssh/") && !strings.HasPrefix(fld, "/etc/ssh/") {
						signals = append(signals, &PersistenceSignal{
							Class:      ClassConfigDeviation,
							RuleName:   "Persistence_SSHD_Non_Standard_AuthorizedKeysFile",
							Reason:     fmt.Sprintf("sshd_config specifies non-standard AuthorizedKeysFile location (%s)", fld),
							Score:      70,
							Severity:   report.SeverityWarning,
							LineNumber: lineNum,
							Snippet:    line,
						})
					}
				}
			}
		}

		if len(signals) > 0 {
			meta := map[string]any{
				"artifact": "sshd_config",
				"file":     virtFile,
			}
			if f := ConsolidateSignals(signals, virtFile, meta); f != nil {
				*findings = append(*findings, *f)
			}
		}
	}
}

func isStandardSSHKeyPath(p string) bool {
	clean := filepath.Clean(p)
	if strings.HasPrefix(clean, "/root/.ssh/") ||
		(strings.HasPrefix(clean, "/home/") && strings.Contains(clean, "/.ssh/")) ||
		strings.HasPrefix(clean, "/etc/ssh/") ||
		strings.HasPrefix(clean, "/etc/ssl/") ||
		strings.HasPrefix(clean, "~/.ssh/") ||
		strings.HasPrefix(clean, "$HOME/.ssh/") {
		return true
	}
	return false
}

func extractPathsFromKeyLine(line, comment string) []string {
	var paths []string
	seen := make(map[string]bool)

	addPath := func(raw string) {
		raw = strings.TrimSpace(raw)
		raw = strings.Trim(raw, `"'(),;`)
		if atIdx := strings.Index(raw, "@"); atIdx != -1 && strings.HasPrefix(raw[atIdx+1:], "/") {
			raw = raw[atIdx+1:]
		}
		if strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "~/") || strings.HasPrefix(raw, "$HOME/") {
			clean := filepath.Clean(raw)
			if !seen[clean] && len(clean) > 1 {
				seen[clean] = true
				paths = append(paths, clean)
			}
		}
	}

	for _, token := range strings.Fields(comment) {
		addPath(token)
	}
	for _, token := range strings.Fields(line) {
		if strings.HasPrefix(token, "/") || strings.Contains(token, "=/") {
			if eqIdx := strings.Index(token, "="); eqIdx != -1 {
				addPath(token[eqIdx+1:])
			} else {
				addPath(token)
			}
		}
	}

	return paths
}

