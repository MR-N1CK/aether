package network

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strings"

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
	"networkmanager":   true,
	"systemd-networkd": true,
	"wpa_supplicant":   true,
	"avahi-daemon":     true,
	"lldpd":            true,
	"arping":           true,
}

var interactiveShellBinaries = map[string]bool{
	"sh":   true,
	"bash": true,
	"dash": true,
	"zsh":  true,
	"ksh":  true,
	"csh":  true,
	"tcsh": true,
	"ash":  true,
	"fish": true,
}

func isInteractiveShellProcess(owner *ProcessSocketOwner) bool {
	if owner == nil || owner.IsKernel {
		return false
	}
	comm := strings.ToLower(strings.TrimSpace(owner.Comm))
	if interactiveShellBinaries[comm] {
		return true
	}
	if owner.ExePath != "" {
		exeBase := strings.ToLower(filepath.Base(owner.ExePath))
		if interactiveShellBinaries[exeBase] {
			return true
		}
	}
	return false
}

func isRawSocketAllowed(owner *ProcessSocketOwner) bool {
	if owner == nil {
		return false
	}
	if owner.IsKernel {
		return true
	}
	comm := strings.ToLower(strings.TrimSpace(owner.Comm))
	if defaultRawSocketAllowlist[comm] {
		return true
	}
	if owner.ExePath != "" {
		exeBase := strings.ToLower(filepath.Base(owner.ExePath))
		if defaultRawSocketAllowlist[exeBase] {
			return true
		}
	}
	return false
}

func isListenerAllowed(owner *ProcessSocketOwner, allowlist map[string]bool) bool {
	if owner == nil {
		return false
	}
	if owner.IsKernel {
		return true
	}
	comm := strings.ToLower(strings.TrimSpace(owner.Comm))
	if allowlist[comm] {
		return true
	}
	if owner.ExePath != "" {
		exeBase := strings.ToLower(filepath.Base(owner.ExePath))
		if allowlist[exeBase] {
			return true
		}
	}
	return false
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

type loopbackListenerEntry struct {
	process  string
	port     int
	protocol string
	ip       string
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
	var loopbackListeners []loopbackListenerEntry

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

					f := report.NewFinding("network", match.Severity, fmt.Sprintf("/proc/net/%s", s.Protocol), reason, match.RuleName)
					f.Metadata["remote_ip"] = s.RemIP.String()
					f.Metadata["remote_port"] = s.RemPort
					f.Metadata["local_ip"] = s.LocalIP.String()
					f.Metadata["local_port"] = s.LocalPort
					f.Metadata["state"] = s.State
					f.Metadata["protocol"] = s.Protocol
					f.Metadata["is_ioc_match"] = true
					f.Metadata["high_confidence"] = match.IsHighConf
					f.Metadata["score"] = match.Score
					if s.Owner != nil {
						f.Metadata["pid"] = s.Owner.PID
						f.Metadata["comm"] = s.Owner.Comm
						f.Metadata["exe"] = s.Owner.ExePath
						if f.EvidenceRecord != nil {
							f.EvidenceRecord.PID = s.Owner.PID
							f.EvidenceRecord.Comm = s.Owner.Comm
							f.EvidenceRecord.TargetPath = s.Owner.ExePath
							f.EvidenceRecord.SocketInfo = fmt.Sprintf("%s:%d", s.LocalIP, s.LocalPort)
							f.EvidenceRecord.MountNamespace = s.Owner.MntNs
						}
					}
					findings = append(findings, f)
				}
			}
		}

		// 1b. Active Outbound Interactive Reverse Shell Connection
		if s.RemIP != nil && s.State == "ESTABLISHED" && !isLoopbackIP(s.RemIP) && isInteractiveShellProcess(s.Owner) {
			reason := fmt.Sprintf("Interactive shell process %q (PID %d, %s) maintains active outbound network connection to %s:%d (active reverse shell)",
				s.Owner.Comm, s.Owner.PID, s.Owner.ExePath, s.RemIP, s.RemPort)
			f := report.NewFinding("network", report.SeverityAlert, fmt.Sprintf("/proc/net/%s", s.Protocol), reason, "Network_Outbound_Interactive_Shell_Connection")
			f.Metadata["remote_ip"] = s.RemIP.String()
			f.Metadata["remote_port"] = s.RemPort
			f.Metadata["local_ip"] = s.LocalIP.String()
			f.Metadata["local_port"] = s.LocalPort
			f.Metadata["state"] = s.State
			f.Metadata["protocol"] = s.Protocol
			f.Metadata["pid"] = s.Owner.PID
			f.Metadata["comm"] = s.Owner.Comm
			f.Metadata["exe"] = s.Owner.ExePath
			f.Metadata["score"] = 95
			if f.EvidenceRecord != nil {
				f.EvidenceRecord.PID = s.Owner.PID
				f.EvidenceRecord.Comm = s.Owner.Comm
				f.EvidenceRecord.TargetPath = s.Owner.ExePath
				f.EvidenceRecord.SocketInfo = fmt.Sprintf("%s:%d -> %s:%d", s.LocalIP, s.LocalPort, s.RemIP, s.RemPort)
				f.EvidenceRecord.MountNamespace = s.Owner.MntNs
				f.EvidenceRecord.EvidenceStrength = report.StrengthDirect
			}
			findings = append(findings, f)
		}

		// 2. Loopback Listeners (Grouped into one INFO finding)
		if isListener && isLoopbackIP(s.LocalIP) {
			procDesc := "system service"
			if s.Owner != nil && s.Owner.Comm != "" {
				procDesc = fmt.Sprintf("%s (PID %d)", s.Owner.Comm, s.Owner.PID)
			}
			loopbackListeners = append(loopbackListeners, loopbackListenerEntry{
				process:  procDesc,
				port:     s.LocalPort,
				protocol: s.Protocol,
				ip:       s.LocalIP.String(),
			})
			continue
		}

		// 3. Wildcard Listeners:
		// Rule: NOTICE only as root, ONLY when a process owns the socket and it is NOT in the allowlist; NEVER as non-root. Show process name in notice.
		if isListener && isWildcardIP(s.LocalIP) && isRoot && s.Owner != nil && !s.Owner.IsKernel {
			if !isListenerAllowed(s.Owner, listenerAllowlist) {
				f := report.NewFinding(
					"network",
					report.SeverityNotice,
					fmt.Sprintf("/proc/net/%s", s.Protocol),
					fmt.Sprintf("Wildcard network listener on %s:%d owned by process %q (PID %d) is not in the listener allowlist", s.LocalIP, s.LocalPort, s.Owner.Comm, s.Owner.PID),
					"Network_Wildcard_Listener_Unrecognized_Process",
				)
				f.Metadata["protocol"] = s.Protocol
				f.Metadata["local_ip"] = s.LocalIP.String()
				f.Metadata["local_port"] = s.LocalPort
				f.Metadata["pid"] = s.Owner.PID
				f.Metadata["comm"] = s.Owner.Comm
				f.Metadata["exe"] = s.Owner.ExePath
				f.Metadata["score"] = 35
				if f.EvidenceRecord != nil {
					f.EvidenceRecord.PID = s.Owner.PID
					f.EvidenceRecord.Comm = s.Owner.Comm
					f.EvidenceRecord.TargetPath = s.Owner.ExePath
					f.EvidenceRecord.SocketInfo = fmt.Sprintf("%s:%d", s.LocalIP, s.LocalPort)
					f.EvidenceRecord.MountNamespace = s.Owner.MntNs
					f.EvidenceRecord.EvidenceStrength = report.StrengthContextual
				}
				findings = append(findings, f)
			}
		}

		// 4. Raw and Packet Socket Inspection (match both comm and exe basename)
		if s.Protocol == "raw" || s.Protocol == "raw6" || s.Protocol == "packet" {
			if s.Owner != nil && !s.Owner.IsKernel {
				if !isRawSocketAllowed(s.Owner) {
					f := report.NewFinding(
						"network",
						report.SeverityNotice,
						fmt.Sprintf("/proc/net/%s", s.Protocol),
						fmt.Sprintf("Process %q (PID %d) opened raw/packet socket (%s) outside standard network tools allowlist", s.Owner.Comm, s.Owner.PID, s.Protocol),
						"Network_Suspicious_Raw_Packet_Socket",
					)
					f.Metadata["protocol"] = s.Protocol
					f.Metadata["pid"] = s.Owner.PID
					f.Metadata["comm"] = s.Owner.Comm
					f.Metadata["exe"] = s.Owner.ExePath
					f.Metadata["score"] = 35
					if f.EvidenceRecord != nil {
						f.EvidenceRecord.PID = s.Owner.PID
						f.EvidenceRecord.Comm = s.Owner.Comm
						f.EvidenceRecord.TargetPath = s.Owner.ExePath
						f.EvidenceRecord.SocketInfo = fmt.Sprintf("%s:%d", s.LocalIP, s.LocalPort)
						f.EvidenceRecord.MountNamespace = s.Owner.MntNs
						f.EvidenceRecord.EvidenceStrength = report.StrengthContextual
					}
					findings = append(findings, f)
				}
			}
		}
	}

	// Emit grouped loopback listeners finding if any were collected
	if len(loopbackListeners) > 0 {
		var listItems []map[string]interface{}
		var descParts []string
		for _, ll := range loopbackListeners {
			listItems = append(listItems, map[string]interface{}{
				"process":  ll.process,
				"port":     ll.port,
				"protocol": ll.protocol,
				"ip":       ll.ip,
			})
			descParts = append(descParts, fmt.Sprintf("%s (port %d)", ll.process, ll.port))
		}
		sampleStr := strings.Join(descParts, ", ")
		if len(descParts) > 3 {
			sampleStr = fmt.Sprintf("%s, %s, %s (and %d more)", descParts[0], descParts[1], descParts[2], len(descParts)-3)
		}
		f := report.NewFinding(
			"network",
			report.SeverityInfo,
			"/proc/net/tcp",
			fmt.Sprintf("Found %d loopback listener(s): %s", len(loopbackListeners), sampleStr),
			"Network_Loopback_Listener",
		)
		f.Count = len(loopbackListeners)
		f.Paths = []string{"/proc/net/tcp", "/proc/net/udp"}
		f.Metadata["count"] = len(loopbackListeners)
		f.Metadata["listeners"] = listItems
		f.Metadata["score"] = 10
		if f.EvidenceRecord != nil {
			f.EvidenceRecord.EvidenceStrength = report.StrengthContextual
			f.EvidenceRecord.PackageStatus = "verified_package"
		}
		findings = append(findings, f)
	}

	return findings
}
