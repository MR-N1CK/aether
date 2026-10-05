package users

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"aether/internal/config"
	"aether/internal/pkgdb"
	"aether/internal/report"
	"aether/internal/safeopen"
)

// PasswdEntry holds parsed fields from /etc/passwd.
type PasswdEntry struct {
	Username string
	UID      uint32
	GID      uint32
	GECOS    string
	Home     string
	Shell    string
}

// readLoginDefsUIDMin reads UID_MIN from /etc/login.defs, defaulting to 1000 if not found.
func readLoginDefsUIDMin(rootFS string) uint32 {
	data, err := safeopen.ReadFileReadOnlyUnderRoot(rootFS, "/etc/login.defs", 256*1024)
	if err != nil {
		return 1000
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "UID_MIN" {
			if val, err := strconv.ParseUint(fields[1], 10, 32); err == nil {
				return uint32(val)
			}
		}
	}
	return 1000
}

// loadValidShells reads /etc/shells.
func loadValidShells(rootFS string) map[string]bool {
	shells := make(map[string]bool)
	data, err := safeopen.ReadFileReadOnlyUnderRoot(rootFS, "/etc/shells", 256*1024)
	if err != nil {
		// Standard fallbacks
		return map[string]bool{
			"/bin/sh":       true,
			"/bin/bash":     true,
			"/usr/bin/sh":   true,
			"/usr/bin/bash": true,
			"/bin/zsh":      true,
			"/usr/bin/zsh":  true,
		}
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			shells[line] = true
		}
	}
	return shells
}

// isNonLoginShell returns true if shell is a standard non-interactive stub.
func isNonLoginShell(shell string) bool {
	clean := filepath.Clean(shell)
	base := filepath.Base(clean)
	return base == "nologin" || base == "false" || base == "null" ||
		clean == "/bin/false" || clean == "/usr/sbin/nologin" || clean == "/bin/nologin" || clean == "/dev/null"
}

// hasAccountAuthorizedKeys checks if THAT SPECIFIC account has an authorized_keys file.
func hasAccountAuthorizedKeys(rootFS, homeDir string) bool {
	if homeDir == "" || homeDir == "/" || homeDir == "/nonexistent" {
		return false
	}
	sshDir := filepath.Join(homeDir, ".ssh")

	for _, name := range []string{"authorized_keys", "authorized_keys2"} {
		keyPath := filepath.Join(sshDir, name)
		hostPath, _, _, err := safeopen.ResolveUnderRoot(rootFS, keyPath)
		if err == nil {
			if fi, err := os.Stat(hostPath); err == nil && fi.Mode().IsRegular() && fi.Size() > 0 {
				return true
			}
		}
	}
	return false
}

// CheckPasswd inspects /etc/passwd entries for extra UID 0 accounts, duplicate UIDs, and system account anomalies.
func CheckPasswd(ctx context.Context, rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, shadowEntries map[string]ShadowEntry, cov *UsersCoverage) []report.Finding {
	var findings []report.Finding

	passwdPath := "/etc/passwd"
	data, err := safeopen.ReadFileReadOnlyUnderRoot(rootFS, passwdPath, 1024*1024)
	if err != nil {
		return findings
	}

	uidMin := readLoginDefsUIDMin(rootFS)
	validShells := loadValidShells(rootFS)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	var entries []PasswdEntry
	uidToUsers := make(map[uint32][]string)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}

		uid64, err := strconv.ParseUint(strings.TrimSpace(parts[2]), 10, 32)
		if err != nil {
			continue
		}
		gid64, _ := strconv.ParseUint(strings.TrimSpace(parts[3]), 10, 32)

		entry := PasswdEntry{
			Username: strings.TrimSpace(parts[0]),
			UID:      uint32(uid64),
			GID:      uint32(gid64),
			GECOS:    strings.TrimSpace(parts[4]),
			Home:     strings.TrimSpace(parts[5]),
			Shell:    strings.TrimSpace(parts[6]),
		}
		entries = append(entries, entry)
		uidToUsers[entry.UID] = append(uidToUsers[entry.UID], entry.Username)
	}

	cov.AccountsInspected = int64(len(entries))

	// Track standard allowed system binaries/accounts
	standardSystemBinaries := map[string]bool{
		"/bin/sync":      true,
		"/usr/bin/sync":  true,
		"/sbin/shutdown": true,
		"/sbin/halt":     true,
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		// 1. Check Extra UID 0 Account
		if entry.UID == 0 && entry.Username != "root" {
			// Check if THIS SPECIFIC extra UID 0 account has an empty shadow password or active authorized_keys
			hasEmptyPass := false
			if s, ok := shadowEntries[entry.Username]; ok && s.IsEmpty {
				hasEmptyPass = true
			}
			hasAuthKeys := hasAccountAuthorizedKeys(rootFS, entry.Home)

			sev := report.SeverityWarning
			score := 85
			var reasons []string
			reasons = append(reasons, fmt.Sprintf("Non-root user %q has UID 0 (root privileges)", entry.Username))

			if hasEmptyPass {
				sev = report.SeverityAlert
				score = 95
				reasons = append(reasons, "account has empty password in /etc/shadow")
			}
			if hasAuthKeys {
				sev = report.SeverityAlert
				score = 95
				reasons = append(reasons, fmt.Sprintf("account has active SSH authorized_keys in %s", entry.Home))
			}

			f := report.Finding{
				Timestamp: time.Now(),
				Module:    "users",
				Severity:  sev,
				Path:      passwdPath,
				Reason:    strings.Join(reasons, "; "),
				RuleName:  "Users_Extra_UID0_Account",
				Count:     1,
				Paths:     []string{passwdPath},
				Metadata: map[string]interface{}{
					"username":        entry.Username,
					"uid":             0,
					"has_empty_pass":  hasEmptyPass,
					"has_auth_keys":   hasAuthKeys,
					"high_confidence": sev == report.SeverityAlert,
					"score":           score,
				},
			}
			findings = append(findings, f)
		}

		// 2. System Accounts Check (UID < UID_MIN, excluding root)
		if entry.UID > 0 && entry.UID < uidMin {
			cov.SystemAccounts++

			// Exclude legitimate stubs and standard system binaries (sync, shutdown, halt)
			if !isNonLoginShell(entry.Shell) && !standardSystemBinaries[entry.Shell] {
				// Judge if shell is interactive login shell
				isInteractiveShell := validShells[entry.Shell] || strings.HasSuffix(entry.Shell, "/sh") || strings.HasSuffix(entry.Shell, "/bash") || strings.HasSuffix(entry.Shell, "/zsh")

				if isInteractiveShell {
					// Check second signals: temp dir home or hidden path home
					homeInTemp := strings.HasPrefix(entry.Home, "/tmp") || strings.HasPrefix(entry.Home, "/var/tmp") || strings.HasPrefix(entry.Home, "/dev/shm")
					homeIsHidden := false
					for _, part := range strings.Split(entry.Home, "/") {
						if strings.HasPrefix(part, ".") && part != "." && part != ".." {
							homeIsHidden = true
							break
						}
					}

					// Never flag for shell alone without a second signal!
					if homeInTemp || homeIsHidden {
						reason := fmt.Sprintf("System account %q (UID %d) has interactive shell %q and suspicious home directory %q", entry.Username, entry.UID, entry.Shell, entry.Home)
						f := report.Finding{
							Timestamp: time.Now(),
							Module:    "users",
							Severity:  report.SeverityNotice,
							Path:      passwdPath,
							Reason:    reason,
							RuleName:  "Users_System_Account_Interactive_Shell",
							Count:     1,
							Paths:     []string{passwdPath},
							Metadata: map[string]interface{}{
								"username":   entry.Username,
								"uid":        entry.UID,
								"shell":      entry.Shell,
								"home":       entry.Home,
								"is_weak":    true,
								"score":      35,
							},
						}
						findings = append(findings, f)
					}
				}
			}
		}
	}

	// 3. Duplicate UIDs Check (excluding UID 0 which is handled above)
	for uid, users := range uidToUsers {
		if uid == 0 {
			continue
		}
		if len(users) > 1 {
			cov.DuplicateUIDs++
			f := report.Finding{
				Timestamp: time.Now(),
				Module:    "users",
				Severity:  report.SeverityNotice,
				Path:      passwdPath,
				Reason:    fmt.Sprintf("Multiple accounts share UID %d: %s", uid, strings.Join(users, ", ")),
				RuleName:  "Users_Duplicate_UID",
				Count:     len(users),
				Paths:     []string{passwdPath},
				Metadata: map[string]interface{}{
					"uid":       uid,
					"usernames": users,
					"score":     30,
				},
			}
			findings = append(findings, f)
		}
	}

	return findings
}
