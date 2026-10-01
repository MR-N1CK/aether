package network

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"aether/internal/config"
	"aether/internal/ioc"
	"aether/internal/report"
)

// Default allowed raw/packet socket processes
var defaultRawSocketAllowlist = map[string]bool{
	"tcpdump":          true,
	"wireshark":        true,
	"tshark":           true,
	"dumpcap":          true,
	"dhclient":         true,
	"NetworkManager":   true,
	"systemd-networkd": true,
	"wpa_supplicant":   true,
	"avahi-daemon":     true,
	"lldpd":            true,
	"arping":           true,
}

// isWildcardIP checks if an IP is 0.0.0.0 or ::
func isWildcardIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 0 && ip4[1] == 0 && ip4[2] == 0 && ip4[3] == 0
	}
	return false
}

// isLoopbackIP checks if an IP is 127.0.0.1 or ::1
func isLoopbackIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// EvaluateNetworkDetections applies detection rules across parsed socket entries.
func EvaluateNetworkDetections(
	ctx context.Context,
	sockets []SocketEntry,
	isRoot bool,
	cfg *config.Config,
	iocEng ioc.Engine,
	cov *NetworkCoverage,
	logger *slog.Logger,
) []report.Finding {
	var findings []report.Finding

	listenerAllowlist := make(map[string]bool)
	if cfg != nil && len(cfg.Scan.ListenerAllowlist) > 0 {
		for _, a := range cfg.Scan.ListenerAllowlist {
			listenerAllowlist[strings.ToLower(strings.TrimSpace(a))] = true
		}
	} else {
		for _, a := range config.DefaultListenerAllowlist {
			listenerAllowlist[strings.ToLower(strings.TrimSpace(a))] = true
		}
	}

	for _, s := range sockets {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		cov.SocketsInspected++

		// Track socket types for coverage
		isListener := s.State == "LISTEN" || (strings.HasPrefix(s.Protocol, "udp") && s.LocalPort > 0)
		if strings.HasPrefix(s.Protocol, "tcp") && s.State == "LISTEN" {
			cov.TCPListeners++
		} else if strings.HasPrefix(s.Protocol, "udp") {
			cov.UDPListeners++
		} else if s.State == "ESTABLISHED" {
			cov.EstablishedConnections++
		} else if s.Protocol == "raw" || s.Protocol == "raw6" || s.Protocol == "packet" {
			cov.RawPacketSockets++
		}

		// Check kernel-owned sockets
		if s.Owner != nil && s.Owner.IsKernel {
			cov.KernelOwnedSockets++
			continue
		}

		// Handle unmapped sockets
		if s.Owner == nil {
			if !isRoot {
				cov.UnmappedSocketsNonRoot++
			}
			// As non-root or unmapped, never raise standalone listener findings
			// Also evaluate IP IOCs if remote IP is valid
		}

		// 1. IP IOC Matching on active / connecting states (ESTABLISHED, SYN_SENT, TIME_WAIT)
		if s.RemIP != nil && (s.State == "ESTABLISHED" || s.State == "SYN_SENT" || s.State == "TIME_WAIT") {
			if iocEng != nil {
				if match := iocEng.CheckIP(s.RemIP); match != nil {
					procDesc := "unknown process"
					if s.Owner != nil && s.Owner.Comm != "" {
						procDesc = fmt.Sprintf("%s (PID %d)", s.Owner.Comm, s.Owner.PID)
					}
					reason := fmt.Sprintf("%s [active %s %s connection from %s:%d to %s:%d by %s]",
						match.Reason, s.Protocol, s.State, s.LocalIP, s.LocalPort, s.RemIP, s.RemPort, procDesc)

					f := report.Finding{
						Timestamp: time.Now(),
						Module:    "network",
						Severity:  match.Severity,
						Path:      fmt.Sprintf("/proc/net/%s", s.Protocol),
						Reason:    reason,
						RuleName:  match.RuleName,
						Count:     1,
						Paths:     []string{fmt.Sprintf("/proc/net/%s", s.Protocol)},
						Metadata: map[string]interface{}{
							"remote_ip":       s.RemIP.String(),
							"remote_port":     s.RemPort,
							"local_ip":        s.LocalIP.String(),
							"local_port":      s.LocalPort,
							"state":           s.State,
							"protocol":        s.Protocol,
							"is_ioc_match":    true,
							"high_confidence": match.IsHighConf,
							"score":           match.Score,
						},
					}
					if s.Owner != nil {
						f.Metadata["pid"] = s.Owner.PID
						f.Metadata["comm"] = s.Owner.Comm
						f.Metadata["exe"] = s.Owner.ExePath
					}
					findings = append(findings, f)
				}
			}
		}

		// 2. Loopback Listeners (INFO inventory)
		if isListener && isLoopbackIP(s.LocalIP) {
			procDesc := "system service"
			if s.Owner != nil && s.Owner.Comm != "" {
				procDesc = fmt.Sprintf("%s (PID %d)", s.Owner.Comm, s.Owner.PID)
			}
			findings = append(findings, report.Finding{
				Timestamp: time.Now(),
				Module:    "network",
				Severity:  report.SeverityInfo,
				Path:      fmt.Sprintf("/proc/net/%s", s.Protocol),
				Reason:    fmt.Sprintf("Loopback-bound %s listener on %s:%d by %s", s.Protocol, s.LocalIP, s.LocalPort, procDesc),
				RuleName:  "Network_Loopback_Listener",
				Count:     1,
				Paths:     []string{fmt.Sprintf("/proc/net/%s", s.Protocol)},
				Metadata: map[string]interface{}{
					"protocol":   s.Protocol,
					"local_ip":   s.LocalIP.String(),
					"local_port": s.LocalPort,
					"score":      10,
				},
			})
			continue
		}

		// 3. Wildcard Listeners:
		// Rule: NOTICE only as root, ONLY when a process owns the socket and it is NOT in the allowlist; NEVER as non-root. Show process name in notice.
		if isListener && isWildcardIP(s.LocalIP) && isRoot && s.Owner != nil && !s.Owner.IsKernel {
			commLower := strings.ToLower(s.Owner.Comm)
			if !listenerAllowlist[commLower] {
				findings = append(findings, report.Finding{
					Timestamp: time.Now(),
					Module:    "network",
					Severity:  report.SeverityNotice,
					Path:      fmt.Sprintf("/proc/net/%s", s.Protocol),
					Reason:    fmt.Sprintf("Wildcard network listener on %s:%d owned by process %q (PID %d) is not in the listener allowlist", s.LocalIP, s.LocalPort, s.Owner.Comm, s.Owner.PID),
					RuleName:  "Network_Wildcard_Listener_Unrecognized_Process",
					Count:     1,
					Paths:     []string{fmt.Sprintf("/proc/net/%s", s.Protocol)},
					Metadata: map[string]interface{}{
						"protocol":   s.Protocol,
						"local_ip":   s.LocalIP.String(),
						"local_port": s.LocalPort,
						"pid":        s.Owner.PID,
						"comm":       s.Owner.Comm,
						"exe":        s.Owner.ExePath,
						"score":      35,
					},
				})
			}
		}

		// 4. Raw and Packet Socket Inspection
		if s.Protocol == "raw" || s.Protocol == "raw6" || s.Protocol == "packet" {
			if s.Owner != nil && !s.Owner.IsKernel {
				commLower := strings.ToLower(s.Owner.Comm)
				if !defaultRawSocketAllowlist[commLower] {
					findings = append(findings, report.Finding{
						Timestamp: time.Now(),
						Module:    "network",
						Severity:  report.SeverityNotice,
						Path:      fmt.Sprintf("/proc/net/%s", s.Protocol),
						Reason:    fmt.Sprintf("Process %q (PID %d) opened raw/packet socket (%s) outside standard network tools allowlist", s.Owner.Comm, s.Owner.PID, s.Protocol),
						RuleName:  "Network_Suspicious_Raw_Packet_Socket",
						Count:     1,
						Paths:     []string{fmt.Sprintf("/proc/net/%s", s.Protocol)},
						Metadata: map[string]interface{}{
							"protocol": s.Protocol,
							"pid":      s.Owner.PID,
							"comm":     s.Owner.Comm,
							"exe":      s.Owner.ExePath,
							"score":    35,
						},
					})
				}
			}
		}
	}

	return findings
}
