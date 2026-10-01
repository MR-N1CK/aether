package ioc

import (
	"bufio"
	"io"
	"strings"

	"aether/internal/report"
)

// HashRule defines a signature hash match entry.
type HashRule struct {
	Hash        string
	Type        IOCType
	ThreatName  string
	Description string
	Score       int
	Severity    report.Severity
}

// ParseHashFile parses lines formatted as: "<hash> # <description>"
// Comments and blank lines are ignored. Hashes are detected by hexadecimal length:
// 32 chars = MD5, 40 chars = SHA1, 64 chars = SHA256.
func ParseHashFile(r io.Reader, filename string) ([]HashRule, error) {
	scanner := bufio.NewScanner(r)
	var rules []HashRule

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var hashStr, desc string
		parts := strings.SplitN(line, "#", 2)
		hashStr = strings.ToLower(strings.TrimSpace(parts[0]))
		if len(parts) > 1 {
			desc = strings.TrimSpace(parts[1])
		} else {
			desc = "Known malicious hash indicator"
		}

		var iocType IOCType
		switch len(hashStr) {
		case 32:
			iocType = TypeMD5
		case 40:
			iocType = TypeSHA1
		case 64:
			iocType = TypeSHA256
		default:
			// Skip unsupported hash lengths
			continue
		}

		ruleName := "IOC_Hash_" + string(iocType)
		if desc != "" && !strings.Contains(desc, " ") && len(desc) < 32 {
			ruleName = desc
		}

		rules = append(rules, HashRule{
			Hash:        hashStr,
			Type:        iocType,
			ThreatName:  ruleName,
			Description: desc,
			Score:       100, // Hash IOC matches are high-confidence ALERTs
			Severity:    report.SeverityAlert,
		})
	}

	return rules, scanner.Err()
}
