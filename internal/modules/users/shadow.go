package users

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aether/internal/config"
	"aether/internal/report"
	"aether/internal/safeopen"
)

// ShadowEntry holds non-sensitive metadata parsed from an /etc/shadow record.
type ShadowEntry struct {
	Username       string
	IsEmpty        bool
	IsLocked       bool
	IsLegacyMD5    bool
	IsLegacyDES    bool
	HashType       string // e.g. "sha512", "yescrypt", "md5", "des", "empty", "locked"
}

// CheckShadow inspects /etc/shadow for empty password fields and legacy weak hashes.
// Forensic rule: Password hashes are NEVER stored, printed, logged, or emitted in findings.
func CheckShadow(rootFS string, cfg *config.Config, isNonRoot bool, cov *UsersCoverage) (map[string]ShadowEntry, []report.Finding) {
	entries := make(map[string]ShadowEntry)
	var findings []report.Finding

	shadowPath := "/etc/shadow"
	hostPath := shadowPath
	if rootFS != "" {
		hostPath = filepath.Join(rootFS, "etc/shadow")
	}

	if isNonRoot {
		cov.ShadowGapNonRoot = true
		cov.ShadowReadable = false
		return entries, findings
	}

	// Safe read /etc/shadow
	data, err := safeopen.ReadFileReadOnly(hostPath, 1024*1024)
	if err != nil {
		if os.IsNotExist(err) {
			return entries, findings
		}
		cov.ShadowReadable = false
		cov.ShadowGapNonRoot = true
		return entries, findings
	}

	cov.ShadowReadable = true
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}

		user := strings.TrimSpace(parts[0])
		passField := strings.TrimSpace(parts[1])

		entry := ShadowEntry{
			Username: user,
		}

		// Check if locked
		if passField == "!" || passField == "*" || passField == "!!" || strings.HasPrefix(passField, "!$") || strings.HasPrefix(passField, "*") {
			entry.IsLocked = true
			entry.HashType = "locked"
			entries[user] = entry
			continue
		}

		if passField == "" {
			entry.IsEmpty = true
			entry.HashType = "empty"
			entries[user] = entry

			f := report.Finding{
				Timestamp: time.Now(),
				Module:    "users",
				Severity:  report.SeverityWarning,
				Path:      shadowPath,
				Reason:    fmt.Sprintf("Account %q has an empty password field in /etc/shadow", user),
				RuleName:  "Users_Shadow_Empty_Password",
				Count:     1,
				Paths:     []string{shadowPath},
				Metadata: map[string]interface{}{
					"username": user,
					"score":    75,
				},
			}
			findings = append(findings, f)
			continue
		}

		// Detect legacy weak hashes (only when not locked)
		if strings.HasPrefix(passField, "$1$") {
			entry.IsLegacyMD5 = true
			entry.HashType = "md5"
			f := report.Finding{
				Timestamp: time.Now(),
				Module:    "users",
				Severity:  report.SeverityNotice,
				Path:      shadowPath,
				Reason:    fmt.Sprintf("Account %q uses deprecated MD5 password hash format ($1$) in /etc/shadow", user),
				RuleName:  "Users_Shadow_Legacy_Hash_Format",
				Count:     1,
				Paths:     []string{shadowPath},
				Metadata: map[string]interface{}{
					"username":  user,
					"hash_type": "md5",
					"score":     30,
				},
			}
			findings = append(findings, f)
		} else if len(passField) == 13 && !strings.HasPrefix(passField, "$") {
			// Traditional 13-character crypt(3) DES hash
			entry.IsLegacyDES = true
			entry.HashType = "des"
			f := report.Finding{
				Timestamp: time.Now(),
				Module:    "users",
				Severity:  report.SeverityNotice,
				Path:      shadowPath,
				Reason:    fmt.Sprintf("Account %q uses deprecated DES password hash format in /etc/shadow", user),
				RuleName:  "Users_Shadow_Legacy_Hash_Format",
				Count:     1,
				Paths:     []string{shadowPath},
				Metadata: map[string]interface{}{
					"username":  user,
					"hash_type": "des",
					"score":     30,
				},
			}
			findings = append(findings, f)
		}

		entries[user] = entry
	}

	return entries, findings
}
