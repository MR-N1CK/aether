package network_test

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aether/internal/config"
	"aether/internal/ioc"
	"aether/internal/modules/network"
	"aether/internal/report"
)

type memoryReporter struct {
	findings []report.Finding
}

func (r *memoryReporter) Report(f report.Finding) {
	r.findings = append(r.findings, f)
}
func (r *memoryReporter) Findings() []report.Finding         { return r.findings }
func (r *memoryReporter) Summary() (int, int, int, int, int) { return 0, 0, 0, 0, 0 }
func (r *memoryReporter) Close() error                       { return nil }

func TestNetwork_HexParsing(t *testing.T) {
	// Test IPv4 hex decoding (0100007F -> 127.0.0.1)
	ip4, err := network.ParseHexIPv4("0100007F")
	if err != nil {
		t.Fatalf("unexpected error parsing hex IPv4: %v", err)
	}
	if ip4.String() != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1, got %s", ip4.String())
	}

	// Test IPv4 hex decoding (FB0000E0 -> 224.0.0.251)
	ip4Mcast, err := network.ParseHexIPv4("FB0000E0")
	if err != nil {
		t.Fatalf("unexpected error parsing hex IPv4: %v", err)
	}
	if ip4Mcast.String() != "224.0.0.251" {
		t.Errorf("expected 224.0.0.251, got %s", ip4Mcast.String())
	}

	// Test IPv6 hex decoding
	// D64009244ECA5411BC83DFF562197214 -> 2409:40d6:1154:ca4e:f5df:83bc:1472:1962
	ip6, err := network.ParseHexIPv6("D64009244ECA5411BC83DFF562197214")
	if err != nil {
		t.Fatalf("unexpected error parsing hex IPv6: %v", err)
	}
	expectedIP6 := "2409:40d6:1154:ca4e:f5df:83bc:1472:1962"
	if ip6.String() != expectedIP6 {
		t.Errorf("expected %s, got %s", expectedIP6, ip6.String())
	}

	// Test hex port decoding (9A5F -> 39519)
	port, err := network.ParseHexPort("9A5F")
	if err != nil {
		t.Fatalf("unexpected error parsing hex port: %v", err)
	}
	if port != 39519 {
		t.Errorf("expected 39519, got %d", port)
	}
}

func setupCleanProc(t *testing.T) (string, string) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	procNet := filepath.Join(proc, "net")
	_ = os.MkdirAll(procNet, 0755)

	// Clean /proc/net/tcp fixture:
	// 0: 127.0.0.1:39519 (LISTEN) by pid 1001 (systemd-resolved)
	// 1: 0.0.0.0:22 (LISTEN) by pid 1002 (sshd)
	tcpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 0100007F:9A5F 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 69862 1 0000000083791369 100 0 0 10 0                     
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 65472 1 000000006c7e55aa 100 0 0 10 0                     
`
	_ = os.WriteFile(filepath.Join(procNet, "tcp"), []byte(tcpContent), 0644)

	// Clean /proc/net/udp fixture
	udpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops            
 1457: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 90430 2 00000000b93ee564 0         
`
	_ = os.WriteFile(filepath.Join(procNet, "udp"), []byte(udpContent), 0644)

	// Set up process dirs
	// PID 1001: systemd-resolved (inode 69862)
	pid1001 := filepath.Join(proc, "1001")
	_ = os.MkdirAll(filepath.Join(pid1001, "fd"), 0755)
	_ = os.WriteFile(filepath.Join(pid1001, "comm"), []byte("systemd-resolved\n"), 0644)
	_ = os.WriteFile(filepath.Join(pid1001, "cmdline"), []byte("/lib/systemd/systemd-resolved\x00"), 0644)
	_ = os.Symlink("socket:[69862]", filepath.Join(pid1001, "fd/3"))

	// PID 1002: sshd (inode 65472)
	pid1002 := filepath.Join(proc, "1002")
	_ = os.MkdirAll(filepath.Join(pid1002, "fd"), 0755)
	_ = os.WriteFile(filepath.Join(pid1002, "comm"), []byte("sshd\n"), 0644)
	_ = os.WriteFile(filepath.Join(pid1002, "cmdline"), []byte("/usr/sbin/sshd\x00-D\x00"), 0644)
	_ = os.Symlink("socket:[65472]", filepath.Join(pid1002, "fd/3"))

	return root, proc
}

func TestNetwork_CleanBaseline(t *testing.T) {
	root, proc := setupCleanProc(t)
	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := network.NewModuleWithRoots(root, proc, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error running network module: %v", err)
	}

	for _, f := range rep.findings {
		if f.Severity == report.SeverityAlert || f.Severity == report.SeverityWarning {
			t.Errorf("unexpected WARNING or ALERT in clean baseline: %s (%s)", f.RuleName, f.Reason)
		}
	}

	cov := mod.Coverage()
	if cov.SocketsInspected < 2 {
		t.Errorf("expected >= 2 sockets inspected, got %d", cov.SocketsInspected)
	}
}

func TestNetwork_IOC_EstablishedConnection(t *testing.T) {
	root, proc := setupCleanProc(t)
	procNet := filepath.Join(proc, "net")

	// 198.51.100.55:443 in hex:
	// 198 (0xC6), 51 (0x33), 100 (0x64), 55 (0x37) -> in little-endian: 376433C6
	// Port 443 -> 01BB
	// Established connection to 198.51.100.55:443
	tcpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 0100007F:9A5F 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 69862 1 0000000083791369 100 0 0 10 0                     
   1: 0100007F:C001 376433C6:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 99999 1 000000006c7e55aa 100 0 0 10 0                     
`
	_ = os.WriteFile(filepath.Join(procNet, "tcp"), []byte(tcpContent), 0644)

	// PID 2001: evil_downloader (inode 99999)
	pid2001 := filepath.Join(proc, "2001")
	_ = os.MkdirAll(filepath.Join(pid2001, "fd"), 0755)
	_ = os.WriteFile(filepath.Join(pid2001, "comm"), []byte("evil_downloader\n"), 0644)
	_ = os.Symlink("socket:[99999]", filepath.Join(pid2001, "fd/3"))

	// Create IOC engine with 198.51.100.55 listed
	iocDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(iocDir, "c2.ips"), []byte("198.51.100.55 # Known Cobalt Strike C2 confidence=high\n"), 0644)

	cfg := config.NewDefaultConfig()
	logger := report.SetupLogger("error", false)
	iocEng, err := ioc.NewEngine(cfg, logger)
	if err != nil {
		t.Fatalf("failed creating IOC engine: %v", err)
	}
	_ = iocEng.LoadDirectory(iocDir)

	rep := &memoryReporter{}
	mod := network.NewModuleWithRoots(root, proc, iocEng, nil, logger)

	err = mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error running network module: %v", err)
	}

	var foundAlert bool
	for _, f := range rep.findings {
		if strings.Contains(f.RuleName, "Cobalt") || strings.Contains(f.RuleName, "IOC") {
			if f.Severity == report.SeverityAlert {
				foundAlert = true
			}
		}
	}
	if !foundAlert {
		t.Errorf("expected ALERT for established connection to high-confidence IOC IP")
	}
}

func TestNetwork_SpecialIPs_NeverMatchPublicIOC(t *testing.T) {
	// Verify that private / loopback IPs never trigger public IOC hits
	iocDir := t.TempDir()
	// Broad rule in public list: 0.0.0.0/0
	_ = os.WriteFile(filepath.Join(iocDir, "public.ips"), []byte("192.0.2.0/24 # Malicious range\n"), 0644)

	cfg := config.NewDefaultConfig()
	iocEng, _ := ioc.NewEngine(cfg, nil)
	_ = iocEng.LoadDirectory(iocDir)

	// Check loopback and private IP
	if match := iocEng.CheckIP(net.ParseIP("127.0.0.1")); match != nil {
		t.Errorf("loopback IP 127.0.0.1 must never match non-explicit IOC rule")
	}
	if match := iocEng.CheckIP(net.ParseIP("10.0.0.1")); match != nil {
		t.Errorf("private IP 10.0.0.1 must never match non-explicit IOC rule")
	}
	if match := iocEng.CheckIP(net.ParseIP("100.64.0.5")); match != nil {
		t.Errorf("CGNAT IP 100.64.0.5 must never match non-explicit IOC rule")
	}
}

func TestNetwork_WildcardListener_RootWithNonAllowlistedProcess(t *testing.T) {
	root, proc := setupCleanProc(t)
	procNet := filepath.Join(proc, "net")

	// 0.0.0.0:4444 (LISTEN) by pid 3333 (netcat)
	// 4444 in hex -> 115C
	tcpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 00000000:115C 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 77777 1 000000006c7e55aa 100 0 0 10 0                     
`
	_ = os.WriteFile(filepath.Join(procNet, "tcp"), []byte(tcpContent), 0644)

	pid3333 := filepath.Join(proc, "3333")
	_ = os.MkdirAll(filepath.Join(pid3333, "fd"), 0755)
	_ = os.WriteFile(filepath.Join(pid3333, "comm"), []byte("nc\n"), 0644)
	_ = os.Symlink("socket:[77777]", filepath.Join(pid3333, "fd/3"))

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := network.NewModuleWithRoots(root, proc, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error running network module: %v", err)
	}

	var foundNotice bool
	for _, f := range rep.findings {
		if f.RuleName == "Network_Wildcard_Listener_Unrecognized_Process" {
			foundNotice = true
			if !strings.Contains(f.Reason, "nc") {
				t.Errorf("expected process name \"nc\" in notice reason, got: %s", f.Reason)
			}
		}
	}
	if !foundNotice {
		t.Errorf("expected NOTICE for wildcard listener with unallowlisted process nc")
	}
}

func TestNetwork_SuspiciousRawSocket(t *testing.T) {
	root, proc := setupCleanProc(t)
	procNet := filepath.Join(proc, "net")

	rawContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 00000000:0000 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 88888 2 000000008dbfecbb 0
`
	_ = os.WriteFile(filepath.Join(procNet, "raw"), []byte(rawContent), 0644)

	pid4444 := filepath.Join(proc, "4444")
	_ = os.MkdirAll(filepath.Join(pid4444, "fd"), 0755)
	_ = os.WriteFile(filepath.Join(pid4444, "comm"), []byte("custom_sniffer\n"), 0644)
	_ = os.Symlink("socket:[88888]", filepath.Join(pid4444, "fd/3"))

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := network.NewModuleWithRoots(root, proc, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundRawNotice bool
	for _, f := range rep.findings {
		if f.RuleName == "Network_Suspicious_Raw_Packet_Socket" {
			foundRawNotice = true
			if !strings.Contains(f.Reason, "custom_sniffer") {
				t.Errorf("expected process name in raw socket notice, got: %s", f.Reason)
			}
		}
	}
	if !foundRawNotice {
		t.Errorf("expected NOTICE for raw socket opened by custom_sniffer")
	}
}

func TestNetwork_KernelOwnedSockets_SkippedAndCounted(t *testing.T) {
	root, proc := setupCleanProc(t)
	procNet := filepath.Join(proc, "net")

	// Kernel thread socket: inode 55555
	tcpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 55555 1 0000000083791369 100 0 0 10 0                     
`
	_ = os.WriteFile(filepath.Join(procNet, "tcp"), []byte(tcpContent), 0644)

	// PID 2: [kthreadd]
	pid2 := filepath.Join(proc, "2")
	_ = os.MkdirAll(filepath.Join(pid2, "fd"), 0755)
	_ = os.WriteFile(filepath.Join(pid2, "comm"), []byte("kthreadd\n"), 0644)
	_ = os.WriteFile(filepath.Join(pid2, "stat"), []byte("2 (kthreadd) S 0 0 0 0 -1 2097152 ..."), 0644)
	_ = os.Symlink("socket:[55555]", filepath.Join(pid2, "fd/3"))

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := network.NewModuleWithRoots(root, proc, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cov := mod.Coverage()
	if cov.KernelOwnedSockets < 1 {
		t.Errorf("expected KernelOwnedSockets >= 1, got %d", cov.KernelOwnedSockets)
	}

	for _, f := range rep.findings {
		if f.Severity == report.SeverityWarning || f.Severity == report.SeverityAlert {
			t.Errorf("kernel-owned socket must not trigger findings: %s (%s)", f.RuleName, f.Reason)
		}
	}
}

func TestNetwork_ListenerAlone_NeverRaisesFinding(t *testing.T) {
	root, proc := setupCleanProc(t)
	procNet := filepath.Join(proc, "net")

	// Unmapped listener socket: inode 44444 (no process associated)
	tcpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 44444 1 0000000083791369 100 0 0 10 0                     
`
	_ = os.WriteFile(filepath.Join(procNet, "tcp"), []byte(tcpContent), 0644)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := network.NewModuleWithRoots(root, proc, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range rep.findings {
		if f.Severity == report.SeverityWarning || f.Severity == report.SeverityAlert {
			t.Errorf("unmapped listener alone must never raise warning/alert: %s", f.RuleName)
		}
	}
}

func TestNetwork_NonRoot_UnknownOwnerSocketsSummary(t *testing.T) {
	_, proc := setupCleanProc(t)
	procNet := filepath.Join(proc, "net")

	// 2 unmapped sockets
	tcpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0000000083791369 100 0 0 10 0                     
   1: 00000000:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0000000083791369 100 0 0 10 0                     
`
	_ = os.WriteFile(filepath.Join(procNet, "tcp"), []byte(tcpContent), 0644)
	_ = os.Remove(filepath.Join(procNet, "udp"))

	cov := network.NetworkCoverage{}
	sockets, _ := network.ParseAllSockets(proc, make(map[uint64]*network.ProcessSocketOwner), nil)
	findings := network.EvaluateNetworkDetections(context.Background(), sockets, false, nil, nil, &cov, nil)

	if cov.UnmappedSocketsNonRoot != 2 {
		t.Errorf("expected 2 unmapped sockets recorded in coverage, got %d", cov.UnmappedSocketsNonRoot)
	}

	// No per-socket findings for unmapped listeners
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for unmapped listeners as non-root, got %d", len(findings))
	}
}

func TestNetwork_RawPacketSocket_Allowlist_RealNames(t *testing.T) {
	root, proc := setupCleanProc(t)
	procNet := filepath.Join(proc, "net")

	// Packet socket entries for NetworkManager, systemd-networkd, dhclient, tcpdump
	packetContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 00000000:0000 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 10001 2 000000008dbfecbb 0
   1: 00000000:0000 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 10002 2 000000008dbfecbb 0
   2: 00000000:0000 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 10003 2 000000008dbfecbb 0
   3: 00000000:0000 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 10004 2 000000008dbfecbb 0
`
	_ = os.WriteFile(filepath.Join(procNet, "packet"), []byte(packetContent), 0644)

	// PID 789: NetworkManager (/usr/sbin/NetworkManager)
	pid789 := filepath.Join(proc, "789")
	_ = os.MkdirAll(filepath.Join(pid789, "fd"), 0755)
	_ = os.WriteFile(filepath.Join(pid789, "comm"), []byte("NetworkManager\n"), 0644)
	_ = os.Symlink("/usr/sbin/NetworkManager", filepath.Join(pid789, "exe"))
	_ = os.Symlink("socket:[10001]", filepath.Join(pid789, "fd/3"))

	// PID 790: systemd-networkd (/lib/systemd/systemd-networkd)
	pid790 := filepath.Join(proc, "790")
	_ = os.MkdirAll(filepath.Join(pid790, "fd"), 0755)
	_ = os.WriteFile(filepath.Join(pid790, "comm"), []byte("systemd-network\n"), 0644) // truncated comm
	_ = os.Symlink("/lib/systemd/systemd-networkd", filepath.Join(pid790, "exe"))
	_ = os.Symlink("socket:[10002]", filepath.Join(pid790, "fd/3"))

	// PID 791: dhclient (/sbin/dhclient)
	pid791 := filepath.Join(proc, "791")
	_ = os.MkdirAll(filepath.Join(pid791, "fd"), 0755)
	_ = os.WriteFile(filepath.Join(pid791, "comm"), []byte("dhclient\n"), 0644)
	_ = os.Symlink("/sbin/dhclient", filepath.Join(pid791, "exe"))
	_ = os.Symlink("socket:[10003]", filepath.Join(pid791, "fd/3"))

	// PID 792: tcpdump (/usr/bin/tcpdump)
	pid792 := filepath.Join(proc, "792")
	_ = os.MkdirAll(filepath.Join(pid792, "fd"), 0755)
	_ = os.WriteFile(filepath.Join(pid792, "comm"), []byte("tcpdump\n"), 0644)
	_ = os.Symlink("/usr/bin/tcpdump", filepath.Join(pid792, "exe"))
	_ = os.Symlink("socket:[10004]", filepath.Join(pid792, "fd/3"))

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := network.NewModuleWithRoots(root, proc, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range rep.findings {
		if f.RuleName == "Network_Suspicious_Raw_Packet_Socket" {
			t.Errorf("allowlisted tool was incorrectly flagged: %s (%s)", f.RuleName, f.Reason)
		}
	}
}

func TestNetwork_LoopbackListeners_GroupedIntoOneFinding(t *testing.T) {
	root, proc := setupCleanProc(t)
	procNet := filepath.Join(proc, "net")

	// 3 loopback listeners (127.0.0.1:5432, 127.0.0.1:6379, 127.0.0.1:53)
	tcpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 30001 1 0000000083791369 100 0 0 10 0                     
   1: 0100007F:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 30002 1 0000000083791369 100 0 0 10 0                     
   2: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 30003 1 0000000083791369 100 0 0 10 0                     
`
	_ = os.WriteFile(filepath.Join(procNet, "tcp"), []byte(tcpContent), 0644)
	_ = os.Remove(filepath.Join(procNet, "udp"))

	pid5001 := filepath.Join(proc, "5001")
	_ = os.MkdirAll(filepath.Join(pid5001, "fd"), 0755)
	_ = os.WriteFile(filepath.Join(pid5001, "comm"), []byte("postgres\n"), 0644)
	_ = os.Symlink("socket:[30001]", filepath.Join(pid5001, "fd/3"))

	pid5002 := filepath.Join(proc, "5002")
	_ = os.MkdirAll(filepath.Join(pid5002, "fd"), 0755)
	_ = os.WriteFile(filepath.Join(pid5002, "comm"), []byte("redis-server\n"), 0644)
	_ = os.Symlink("socket:[30002]", filepath.Join(pid5002, "fd/3"))

	pid5003 := filepath.Join(proc, "5003")
	_ = os.MkdirAll(filepath.Join(pid5003, "fd"), 0755)
	_ = os.WriteFile(filepath.Join(pid5003, "comm"), []byte("systemd-resolved\n"), 0644)
	_ = os.Symlink("socket:[30003]", filepath.Join(pid5003, "fd/3"))

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := network.NewModuleWithRoots(root, proc, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var loopbackFindings []report.Finding
	for _, f := range rep.findings {
		if f.RuleName == "Network_Loopback_Listener" {
			loopbackFindings = append(loopbackFindings, f)
		}
	}

	if len(loopbackFindings) != 1 {
		t.Fatalf("expected exactly 1 grouped finding for loopback listeners, got %d", len(loopbackFindings))
	}

	lf := loopbackFindings[0]
	if lf.Count != 3 {
		t.Errorf("expected Count 3, got %d", lf.Count)
	}
	if lf.Severity != report.SeverityInfo {
		t.Errorf("expected Severity INFO, got %s", lf.Severity)
	}

	listenersList, ok := lf.Metadata["listeners"].([]map[string]interface{})
	if !ok || len(listenersList) != 3 {
		t.Errorf("expected 3 listener entries in metadata, got: %v", lf.Metadata["listeners"])
	}
}

func TestNetwork_OutboundInteractiveShellConnection(t *testing.T) {
	cfg := config.NewDefaultConfig()
	cov := &network.NetworkCoverage{}

	sockets := []network.SocketEntry{
		// 1. Normal daemon connection: established connection to external IP
		{
			Protocol:  "tcp",
			LocalIP:   net.ParseIP("192.168.1.50"),
			LocalPort: 45678,
			RemIP:     net.ParseIP("93.184.216.34"),
			RemPort:   443,
			State:     "ESTABLISHED",
			Owner: &network.ProcessSocketOwner{
				PID:     1200,
				Comm:    "curl",
				ExePath: "/usr/bin/curl",
			},
		},
		// 2. Interactive bash reverse shell: established connection to external IP
		{
			Protocol:  "tcp",
			LocalIP:   net.ParseIP("192.168.1.50"),
			LocalPort: 34567,
			RemIP:     net.ParseIP("198.51.100.22"),
			RemPort:   4444,
			State:     "ESTABLISHED",
			Owner: &network.ProcessSocketOwner{
				PID:     1337,
				Comm:    "bash",
				ExePath: "/usr/bin/bash",
			},
		},
		// 3. Interactive sh shell connection to loopback: not flagged as external reverse shell
		{
			Protocol:  "tcp",
			LocalIP:   net.ParseIP("127.0.0.1"),
			LocalPort: 54321,
			RemIP:     net.ParseIP("127.0.0.1"),
			RemPort:   8080,
			State:     "ESTABLISHED",
			Owner: &network.ProcessSocketOwner{
				PID:     1338,
				Comm:    "sh",
				ExePath: "/bin/sh",
			},
		},
	}

	findings := network.EvaluateNetworkDetections(
		context.Background(),
		sockets,
		true,
		cfg,
		nil,
		cov,
		slog.Default(),
	)

	var revShellFindings []report.Finding
	for _, f := range findings {
		if f.RuleName == "Network_Outbound_Interactive_Shell_Connection" {
			revShellFindings = append(revShellFindings, f)
		}
	}

	if len(revShellFindings) != 1 {
		t.Fatalf("expected 1 reverse shell finding, got %d", len(revShellFindings))
	}

	rf := revShellFindings[0]
	if rf.Severity != report.SeverityAlert {
		t.Errorf("expected ALERT severity, got %v", rf.Severity)
	}
	if rf.Metadata["pid"] != 1337 || rf.Metadata["comm"] != "bash" {
		t.Errorf("expected PID 1337 and comm bash, got PID %v comm %v", rf.Metadata["pid"], rf.Metadata["comm"])
	}
	if rf.Metadata["score"] != 95 {
		t.Errorf("expected score 95, got %v", rf.Metadata["score"])
	}
}
