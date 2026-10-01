package network_test

import (
	"context"
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
func (r *memoryReporter) Findings() []report.Finding      { return r.findings }
func (r *memoryReporter) Summary() (int, int, int, int, int) { return 0, 0, 0, 0, 0 }
func (r *memoryReporter) Close() error                     { return nil }

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
