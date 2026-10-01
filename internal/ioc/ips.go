package ioc

import (
	"bufio"
	"io"
	"net"
	"strings"

	"aether/internal/report"
)

// IPRule defines an IP or CIDR indicator rule.
type IPRule struct {
	IP                net.IP
	IPNet             *net.IPNet
	Comment           string
	Confidence        string // "high", "medium", "low"
	Source            string
	IsExplicitSpecial bool // true if the rule explicitly targeted a private/loopback/CGNAT address
}

// IPMatchResult represents an indicator hit on an IP address.
type IPMatchResult struct {
	RuleName   string
	Reason     string
	Score      int
	Severity   report.Severity
	IsHighConf bool
	Comment    string
}

// IsSpecialIP returns true if the IP is loopback, RFC1918 private, link-local, CGNAT (100.64.0.0/10), or unspecified.
func IsSpecialIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return true
	}
	// Check CGNAT: 100.64.0.0/10
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && (ip4[1]&0xC0) == 64 {
			return true
		}
	}
	return false
}

// ParseIPFile parses plain text IP IOC files formatted as: "<ip_or_cidr> # comment [confidence=high]"
func ParseIPFile(r io.Reader, filename string) ([]IPRule, error) {
	scanner := bufio.NewScanner(r)
	var rules []IPRule

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "#", 2)
		targetStr := strings.TrimSpace(parts[0])
		if targetStr == "" {
			continue
		}

		var comment string
		if len(parts) > 1 {
			comment = strings.TrimSpace(parts[1])
		}

		confidence := "medium"
		lowerComment := strings.ToLower(comment)
		if strings.Contains(lowerComment, "confidence=high") || strings.Contains(lowerComment, "confidence:high") {
			confidence = "high"
		}

		if strings.Contains(targetStr, "/") {
			_, ipNet, err := net.ParseCIDR(targetStr)
			if err == nil && ipNet != nil {
				rules = append(rules, IPRule{
					IPNet:             ipNet,
					Comment:           comment,
					Confidence:        confidence,
					Source:            filename,
					IsExplicitSpecial: IsSpecialIP(ipNet.IP),
				})
			}
		} else {
			ip := net.ParseIP(targetStr)
			if ip != nil {
				rules = append(rules, IPRule{
					IP:                ip,
					Comment:           comment,
					Confidence:        confidence,
					Source:            filename,
					IsExplicitSpecial: IsSpecialIP(ip),
				})
			}
		}
	}

	return rules, scanner.Err()
}
