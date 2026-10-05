package report

import (
	"net"
	"os"
	"regexp"
	"strings"
)

var (
	// IPv4 regex (matching valid 0-255 octets)
	reIPv4 = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	// IPv6 regex
	reIPv6 = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,7}:|:(?::[0-9a-f]{1,4}){1,7}\b|\b(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}\b`)
	// user@host pattern (e.g. user@host, root@10.0.0.1, user@[REDACTED_HOST])
	reUserAtHost = regexp.MustCompile(`\b([a-zA-Z0-9_.-]+)@(\[[A-Z_]+\]|[a-zA-Z0-9_.-]+)\b`)
	// SSH -l user or --login user or -l=user
	reSSHLUser = regexp.MustCompile(`(?i)(^|[\s"'])(?:-l|--login)(?:\s+|=)([a-zA-Z0-9_.-]+)`)
	// /home/<username> pattern -> /home/[user]
	reHomeUser = regexp.MustCompile(`(?i)/home/([a-zA-Z0-9_.-]+)(/|\b|$)`)
)

// RedactHostsAndUsers masks IP addresses, usernames, hostnames, and /home/<user> path segments.
func RedactHostsAndUsers(s string, hostname string) string {
	if s == "" {
		return s
	}

	// 1. Redact -l user / --login user
	s = reSSHLUser.ReplaceAllString(s, "$1-l [REDACTED_USER]")

	// 2. Redact /home/<username>
	s = reHomeUser.ReplaceAllString(s, "/home/[user]$2")

	// 3. Redact user@host
	s = reUserAtHost.ReplaceAllStringFunc(s, func(match string) string {
		parts := strings.SplitN(match, "@", 2)
		if len(parts) == 2 {
			return "[REDACTED_USER]@[REDACTED_HOST]"
		}
		return match
	})

	// 4. Redact explicit machine hostname if supplied and not localhost/empty
	if hostname != "" && !strings.EqualFold(hostname, "localhost") && hostname != "127.0.0.1" && hostname != "::1" {
		reHost := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(hostname) + `\b`)
		s = reHost.ReplaceAllString(s, "[REDACTED_HOST]")
	}

	// 5. Redact IPv4 addresses
	s = reIPv4.ReplaceAllStringFunc(s, func(ipStr string) string {
		if ip := net.ParseIP(ipStr); ip != nil {
			return "[REDACTED_IP]"
		}
		return ipStr
	})

	// 6. Redact IPv6 addresses
	s = reIPv6.ReplaceAllStringFunc(s, func(ipStr string) string {
		if ip := net.ParseIP(ipStr); ip != nil {
			return "[REDACTED_IP]"
		}
		return ipStr
	})

	return s
}

// RedactValue recursively redacts string values within arbitrary data structures (maps, slices).
func RedactValue(v interface{}, hostname string) interface{} {
	switch val := v.(type) {
	case string:
		return RedactHostsAndUsers(val, hostname)
	case []string:
		out := make([]string, len(val))
		for i, s := range val {
			out[i] = RedactHostsAndUsers(s, hostname)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, item := range val {
			out[i] = RedactValue(item, hostname)
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, item := range val {
			out[k] = RedactValue(item, hostname)
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(val))
		for k, s := range val {
			out[k] = RedactHostsAndUsers(s, hostname)
		}
		return out
	default:
		return v
	}
}

// RedactFinding applies host and user redactions to all fields of a finding in place.
func RedactFinding(f *Finding, hostname string) {
	if f == nil {
		return
	}
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	f.Path = RedactHostsAndUsers(f.Path, hostname)
	f.Reason = RedactHostsAndUsers(f.Reason, hostname)

	if len(f.Paths) > 0 {
		redactedPaths := make([]string, len(f.Paths))
		for i, p := range f.Paths {
			redactedPaths[i] = RedactHostsAndUsers(p, hostname)
		}
		f.Paths = redactedPaths
	}

	if f.Metadata != nil {
		redactedMeta := make(map[string]interface{}, len(f.Metadata))
		for k, v := range f.Metadata {
			redactedMeta[k] = RedactValue(v, hostname)
		}
		f.Metadata = redactedMeta
	}
}

// FormatRedactedHostname returns "[REDACTED_HOST]" if redacted, or the given hostname.
func FormatRedactedHostname(hostname string, redact bool) string {
	if redact {
		return "[REDACTED_HOST]"
	}
	if hostname == "" {
		h, err := os.Hostname()
		if err == nil && h != "" {
			return h
		}
		return "localhost"
	}
	return hostname
}
