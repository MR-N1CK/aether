package realworld_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"aether/internal/realworld"
)

func findProfilesDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd failed: %v", err)
	}

	for i := 0; i < 5; i++ {
		candidate := filepath.Join(dir, "testdata", "realworld_corpus", "profiles")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("Could not locate testdata/realworld_corpus/profiles from working dir")
	return ""
}

func TestGenerateAllProfiles(t *testing.T) {
	baseDir := findProfilesDir(t)

	createDesktopStandard(t, filepath.Join(baseDir, "desktop-standard"))
	createServerWeb(t, filepath.Join(baseDir, "server-web"))
	createServerMinimal(t, filepath.Join(baseDir, "server-minimal"))
	createUpgradedPending(t, filepath.Join(baseDir, "upgraded-pending"))
	createWorkstationPentest(t, filepath.Join(baseDir, "workstation-pentest"))
	createWorkstationDev(t, filepath.Join(baseDir, "workstation-dev"))
	createContainerHost(t, filepath.Join(baseDir, "container-host"))
	createPackageMixed(t, filepath.Join(baseDir, "package-mixed"))
	createPrivilegeRestricted(t, filepath.Join(baseDir, "privilege-restricted"))

	// Validate all 9 profiles can be loaded by ProfileLoader
	loader := realworld.NewProfileLoader()
	profiles := []string{
		"desktop-standard",
		"server-web",
		"server-minimal",
		"upgraded-pending",
		"workstation-pentest",
		"workstation-dev",
		"container-host",
		"package-mixed",
		"privilege-restricted",
	}

	for _, p := range profiles {
		snap, err := loader.LoadSnapshot(filepath.Join(baseDir, p))
		if err != nil {
			t.Fatalf("Profile %s failed to load: %v", p, err)
		}
		if snap.ProfileID != p {
			t.Errorf("Profile %s loaded wrong ID: %s", p, snap.ProfileID)
		}
	}
}

func writeManifestT(t *testing.T, path string, m realworld.ProfileManifest) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("MkdirAll %s: %v", filepath.Dir(path), err)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("Marshal manifest: %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
		t.Fatalf("WriteFile manifest: %v", err)
	}
}

func writeFileT(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("MkdirAll %s: %v", filepath.Dir(path), err)
	}
	_ = os.Remove(path)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
}

func writeSymlinkT(t *testing.T, linkPath, target string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(linkPath), 0755); err != nil {
		t.Fatalf("MkdirAll %s: %v", filepath.Dir(linkPath), err)
	}
	_ = os.Remove(linkPath)
	if err := os.Symlink(target, linkPath); err != nil {
		t.Fatalf("Symlink %s -> %s: %v", linkPath, target, err)
	}
}

func setupProcPIDT(t *testing.T, procDir string, pid int, comm, exeTarget string, cmdline []string, uid, ppid int, mntNs string, sockets []uint64) {
	t.Helper()
	pidDir := filepath.Join(procDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		t.Fatalf("MkdirAll %s: %v", pidDir, err)
	}

	writeFileT(t, filepath.Join(pidDir, "comm"), comm+"\n")

	status := fmt.Sprintf("Name:\t%s\nUid:\t%d\t%d\t%d\t%d\nGid:\t%d\t%d\t%d\t%d\nPPid:\t%d\n", comm, uid, uid, uid, uid, uid, uid, uid, uid, ppid)
	writeFileT(t, filepath.Join(pidDir, "status"), status)

	stat := fmt.Sprintf("%d (%s) S %d %d %d 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", pid, comm, ppid, pid, pid)
	writeFileT(t, filepath.Join(pidDir, "stat"), stat)

	var cmdlineBytes []byte
	for _, arg := range cmdline {
		cmdlineBytes = append(cmdlineBytes, []byte(arg)...)
		cmdlineBytes = append(cmdlineBytes, 0)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), cmdlineBytes, 0644); err != nil {
		t.Fatalf("Write cmdline: %v", err)
	}

	if exeTarget != "" {
		writeSymlinkT(t, filepath.Join(pidDir, "exe"), exeTarget)
	}

	if mntNs != "" {
		writeSymlinkT(t, filepath.Join(pidDir, "ns", "mnt"), mntNs)
	}

	fdDir := filepath.Join(pidDir, "fd")
	if err := os.MkdirAll(fdDir, 0755); err != nil {
		t.Fatalf("MkdirAll fd: %v", err)
	}
	for i, sock := range sockets {
		writeSymlinkT(t, filepath.Join(fdDir, fmt.Sprintf("%d", 3+i)), fmt.Sprintf("socket:[%d]", sock))
	}

	mapsContent := fmt.Sprintf("00400000-00452000 r-xp 00000000 08:02 345678 %s\n", exeTarget)
	writeFileT(t, filepath.Join(pidDir, "maps"), mapsContent)
}

func createDesktopStandard(t *testing.T, dir string) {
	manifest := realworld.ProfileManifest{
		ProfileID:             realworld.ProfileDesktopStandard,
		Version:               "1.0.0",
		ExpectedStatus:        realworld.PostureSafe,
		MaxAcceptableAlerts:   0,
		MaxAcceptableWarnings: 2,
		AcceptableFindings: []realworld.AcceptableFindingRule{
			{
				RuleName:         "Network_Loopback_Listener",
				PathPattern:      "/proc/*/fd/*",
				ExpectedSeverity: "INFO",
				ExpectedVerdict:  "SAFE",
				Reason:           "PulseAudio / PipeWire / systemd desktop loopback listeners",
			},
		},
		ForbiddenFindings: []realworld.ForbiddenFindingRule{
			{
				RulePattern: "Ransomware_*",
				Severity:    "ALERT",
				Reason:      "No ransomware on clean desktop",
			},
			{
				RulePattern: "*Reverse_Shell*",
				Severity:    "ALERT",
				Reason:      "No reverse shells on clean desktop",
			},
		},
	}
	writeManifestT(t, filepath.Join(dir, "profile_manifest.json"), manifest)

	rootfs := filepath.Join(dir, "rootfs")
	writeFileT(t, filepath.Join(rootfs, "var/lib/dpkg/info/systemd.list"), "/lib/systemd/systemd-resolved\n/usr/bin/pulseaudio\n/usr/bin/pipewire\n/usr/bin/Xorg\n")
	writeFileT(t, filepath.Join(rootfs, "lib/systemd/systemd-resolved"), "#!/bin/sh\nexit 0\n")
	writeFileT(t, filepath.Join(rootfs, "usr/bin/pulseaudio"), "#!/bin/sh\nexit 0\n")
	writeFileT(t, filepath.Join(rootfs, "usr/bin/pipewire"), "#!/bin/sh\nexit 0\n")
	writeFileT(t, filepath.Join(rootfs, "usr/bin/Xorg"), "#!/bin/sh\nexit 0\n")

	proc := filepath.Join(dir, "proc")
	setupProcPIDT(t, proc, 101, "systemd-resolved", "/lib/systemd/systemd-resolved", []string{"/lib/systemd/systemd-resolved"}, 101, 1, "mnt:[4026531840]", []uint64{10101})
	setupProcPIDT(t, proc, 1000, "pulseaudio", "/usr/bin/pulseaudio", []string{"/usr/bin/pulseaudio", "--daemonize=no"}, 1000, 1, "mnt:[4026531840]", []uint64{10001})
	setupProcPIDT(t, proc, 1001, "pipewire", "/usr/bin/pipewire", []string{"/usr/bin/pipewire"}, 1000, 1, "mnt:[4026531840]", nil)
	setupProcPIDT(t, proc, 1002, "Xorg", "/usr/bin/Xorg", []string{"/usr/bin/Xorg", ":0", "-seat", "seat0"}, 0, 1, "mnt:[4026531840]", nil)

	netTCP := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 10101 1 0000000083791369 100 0 0 10 0
   1: 0100007F:1234 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 10001 1 0000000083791370 100 0 0 10 0
`
	writeFileT(t, filepath.Join(proc, "net/tcp"), netTCP)
}

func createServerWeb(t *testing.T, dir string) {
	manifest := realworld.ProfileManifest{
		ProfileID:             realworld.ProfileServerWeb,
		Version:               "1.0.0",
		ExpectedStatus:        realworld.PostureSafe,
		MaxAcceptableAlerts:   0,
		MaxAcceptableWarnings: 1,
		AcceptableFindings: []realworld.AcceptableFindingRule{
			{
				RuleName:         "Network_Wildcard_Listener",
				ExpectedSeverity: "INFO",
				ExpectedVerdict:  "SAFE",
				Reason:           "Authorized web ports 80/443 and SSH port 22 owned by verified packages",
			},
		},
		ForbiddenFindings: []realworld.ForbiddenFindingRule{
			{
				RulePattern: "*Reverse_Shell*",
				Severity:    "ALERT",
				Reason:      "No reverse shells on clean web server",
			},
			{
				RulePattern: "Webshell_*",
				Severity:    "ALERT",
				Reason:      "No webshells on clean web server",
			},
		},
	}
	writeManifestT(t, filepath.Join(dir, "profile_manifest.json"), manifest)

	rootfs := filepath.Join(dir, "rootfs")
	writeFileT(t, filepath.Join(rootfs, "var/lib/dpkg/info/nginx.list"), "/usr/sbin/nginx\n/etc/nginx/nginx.conf\n")
	writeFileT(t, filepath.Join(rootfs, "var/lib/dpkg/info/postgresql.list"), "/usr/lib/postgresql/16/bin/postgres\n/etc/postgresql/postgresql.conf\n")
	writeFileT(t, filepath.Join(rootfs, "var/lib/dpkg/info/openssh-server.list"), "/usr/sbin/sshd\n/etc/ssh/sshd_config\n")

	writeFileT(t, filepath.Join(rootfs, "usr/sbin/nginx"), "#!/bin/sh\nexit 0\n")
	writeFileT(t, filepath.Join(rootfs, "usr/lib/postgresql/16/bin/postgres"), "#!/bin/sh\nexit 0\n")
	writeFileT(t, filepath.Join(rootfs, "usr/sbin/sshd"), "#!/bin/sh\nexit 0\n")
	writeFileT(t, filepath.Join(rootfs, "etc/nginx/nginx.conf"), "events {}\nhttp { server { listen 80; listen 443 ssl; } }\n")

	proc := filepath.Join(dir, "proc")
	setupProcPIDT(t, proc, 2001, "nginx", "/usr/sbin/nginx", []string{"nginx", "-g", "daemon on;"}, 0, 1, "mnt:[4026531840]", []uint64{20011, 20012})
	setupProcPIDT(t, proc, 2002, "postgres", "/usr/lib/postgresql/16/bin/postgres", []string{"postgres", "-D", "/var/lib/postgresql/data"}, 105, 1, "mnt:[4026531840]", []uint64{20021})
	setupProcPIDT(t, proc, 2003, "sshd", "/usr/sbin/sshd", []string{"/usr/sbin/sshd", "-D"}, 0, 1, "mnt:[4026531840]", []uint64{20031})

	netTCP := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 20011 1 0000000083791371 100 0 0 10 0
   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 20012 1 0000000083791372 100 0 0 10 0
   2: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   105        0 20021 1 0000000083791373 100 0 0 10 0
   3: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 20031 1 0000000083791374 100 0 0 10 0
`
	writeFileT(t, filepath.Join(proc, "net/tcp"), netTCP)
}

func createServerMinimal(t *testing.T, dir string) {
	manifest := realworld.ProfileManifest{
		ProfileID:             realworld.ProfileServerMinimal,
		Version:               "1.0.0",
		ExpectedStatus:        realworld.PostureSafe,
		MaxAcceptableAlerts:   0,
		MaxAcceptableWarnings: 0,
		AcceptableFindings: []realworld.AcceptableFindingRule{
			{
				RuleName:         "Network_Wildcard_Listener",
				ExpectedSeverity: "INFO",
				ExpectedVerdict:  "SAFE",
				Reason:           "Authorized SSH port 22 listener",
			},
		},
	}
	writeManifestT(t, filepath.Join(dir, "profile_manifest.json"), manifest)

	rootfs := filepath.Join(dir, "rootfs")
	writeFileT(t, filepath.Join(rootfs, "var/lib/dpkg/info/openssh-server.list"), "/usr/sbin/sshd\n")
	writeFileT(t, filepath.Join(rootfs, "usr/sbin/sshd"), "#!/bin/sh\nexit 0\n")

	proc := filepath.Join(dir, "proc")
	setupProcPIDT(t, proc, 1001, "sshd", "/usr/sbin/sshd", []string{"/usr/sbin/sshd", "-D"}, 0, 1, "mnt:[4026531840]", []uint64{10011})

	netTCP := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 10011 1 0000000083791375 100 0 0 10 0
`
	writeFileT(t, filepath.Join(proc, "net/tcp"), netTCP)
}

func createUpgradedPending(t *testing.T, dir string) {
	manifest := realworld.ProfileManifest{
		ProfileID:             realworld.ProfileUpgradedPending,
		Version:               "1.0.0",
		ExpectedStatus:        realworld.PostureAttentionRequired,
		MaxAcceptableAlerts:   0,
		MaxAcceptableWarnings: 2,
		AcceptableFindings: []realworld.AcceptableFindingRule{
			{
				RuleName:         "Process_Deleted_Binary_Replaced",
				PathPattern:      "/proc/*/exe",
				ExpectedSeverity: "NOTICE",
				ExpectedVerdict:  "SUSPICIOUS",
				Reason:           "Daemon holds replaced unlinked binary in memory post-upgrade",
			},
		},
	}
	writeManifestT(t, filepath.Join(dir, "profile_manifest.json"), manifest)

	rootfs := filepath.Join(dir, "rootfs")
	writeFileT(t, filepath.Join(rootfs, "var/lib/dpkg/info/nginx.list"), "/usr/sbin/nginx\n")
	writeFileT(t, filepath.Join(rootfs, "usr/sbin/nginx"), "#!/bin/sh\necho upgraded\nexit 0\n")

	proc := filepath.Join(dir, "proc")
	setupProcPIDT(t, proc, 3001, "nginx", "/usr/sbin/nginx (deleted)", []string{"nginx", "-g", "daemon on;"}, 0, 1, "mnt:[4026531840]", []uint64{30011})

	netTCP := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 30011 1 0000000083791376 100 0 0 10 0
`
	writeFileT(t, filepath.Join(proc, "net/tcp"), netTCP)
}

func createWorkstationPentest(t *testing.T, dir string) {
	manifest := realworld.ProfileManifest{
		ProfileID:             realworld.ProfileWorkstationPentest,
		Version:               "1.0.0",
		ExpectedStatus:        realworld.PostureSafe,
		MaxAcceptableAlerts:   0,
		MaxAcceptableWarnings: 5,
		DualUseSoftware: []realworld.DualUseSoftwareCatalogEntry{
			{
				ToolName:                "metasploit-framework",
				PrimaryBinary:           "msfconsole",
				StandardPaths:           []string{"/usr/share/metasploit-framework"},
				ExpectedPassiveSeverity: "INFO",
				ExpectedPassiveVerdict:  "SAFE",
			},
			{
				ToolName:                "nmap",
				PrimaryBinary:           "nmap",
				StandardPaths:           []string{"/usr/bin/nmap"},
				ExpectedPassiveSeverity: "INFO",
				ExpectedPassiveVerdict:  "SAFE",
			},
			{
				ToolName:                "wireshark",
				PrimaryBinary:           "wireshark",
				StandardPaths:           []string{"/usr/bin/wireshark"},
				ExpectedPassiveSeverity: "INFO",
				ExpectedPassiveVerdict:  "SAFE",
			},
			{
				ToolName:                "gdb",
				PrimaryBinary:           "gdb",
				StandardPaths:           []string{"/usr/bin/gdb"},
				ExpectedPassiveSeverity: "INFO",
				ExpectedPassiveVerdict:  "SAFE",
			},
			{
				ToolName:                "exploitdb",
				PrimaryBinary:           "searchsploit",
				StandardPaths:           []string{"/usr/share/exploitdb"},
				ExpectedPassiveSeverity: "INFO",
				ExpectedPassiveVerdict:  "SAFE",
			},
		},
	}
	writeManifestT(t, filepath.Join(dir, "profile_manifest.json"), manifest)

	rootfs := filepath.Join(dir, "rootfs")
	writeFileT(t, filepath.Join(rootfs, "var/lib/dpkg/info/metasploit-framework.list"), "/usr/bin/msfconsole\n/usr/share/metasploit-framework/msfconsole\n/usr/share/metasploit-framework/modules/exploits/test_exploit.rb\n")
	writeFileT(t, filepath.Join(rootfs, "var/lib/dpkg/info/nmap.list"), "/usr/bin/nmap\n")
	writeFileT(t, filepath.Join(rootfs, "var/lib/dpkg/info/wireshark.list"), "/usr/bin/wireshark\n")
	writeFileT(t, filepath.Join(rootfs, "var/lib/dpkg/info/gdb.list"), "/usr/bin/gdb\n")
	writeFileT(t, filepath.Join(rootfs, "var/lib/dpkg/info/exploitdb.list"), "/usr/bin/searchsploit\n/usr/share/exploitdb/exploits/linux/remote/test.py\n")

	writeFileT(t, filepath.Join(rootfs, "usr/bin/msfconsole"), "#!/bin/sh\nexit 0\n")
	writeFileT(t, filepath.Join(rootfs, "usr/bin/nmap"), "#!/bin/sh\nexit 0\n")
	writeFileT(t, filepath.Join(rootfs, "usr/bin/wireshark"), "#!/bin/sh\nexit 0\n")
	writeFileT(t, filepath.Join(rootfs, "usr/bin/gdb"), "#!/bin/sh\nexit 0\n")
	writeFileT(t, filepath.Join(rootfs, "usr/bin/searchsploit"), "#!/bin/sh\nexit 0\n")
	writeFileT(t, filepath.Join(rootfs, "usr/share/metasploit-framework/modules/exploits/test_exploit.rb"), "# Msf exploit sample module\nclass MetasploitModule\nend\n")
	writeFileT(t, filepath.Join(rootfs, "usr/share/exploitdb/exploits/linux/remote/test.py"), "# Exploit-DB PoC snippet\nimport socket\n")

	proc := filepath.Join(dir, "proc")
	setupProcPIDT(t, proc, 6001, "gdb", "/usr/bin/gdb", []string{"gdb", "--quiet"}, 1000, 1, "mnt:[4026531840]", nil)
	setupProcPIDT(t, proc, 6002, "wireshark", "/usr/bin/wireshark", []string{"wireshark"}, 1000, 1, "mnt:[4026531840]", nil)

	writeFileT(t, filepath.Join(proc, "net/tcp"), "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
}

func createWorkstationDev(t *testing.T, dir string) {
	manifest := realworld.ProfileManifest{
		ProfileID:             realworld.ProfileWorkstationDev,
		Version:               "1.0.0",
		ExpectedStatus:        realworld.PostureSafe,
		MaxAcceptableAlerts:   0,
		MaxAcceptableWarnings: 2,
		AcceptableFindings: []realworld.AcceptableFindingRule{
			{
				RuleName:         "Network_Loopback_Listener",
				ExpectedSeverity: "INFO",
				ExpectedVerdict:  "SAFE",
				Reason:           "Python loopback dev server on 127.0.0.1:8000",
			},
		},
	}
	writeManifestT(t, filepath.Join(dir, "profile_manifest.json"), manifest)

	rootfs := filepath.Join(dir, "rootfs")
	writeFileT(t, filepath.Join(rootfs, "var/lib/dpkg/info/python3.list"), "/usr/bin/python3\n")
	writeFileT(t, filepath.Join(rootfs, "usr/bin/python3"), "#!/bin/sh\nexit 0\n")
	writeFileT(t, filepath.Join(rootfs, "home/developer/projects/webapp/target/debug/app_build"), "\x7fELF\x02\x01\x01\x00dev-binary-stub")
	writeFileT(t, filepath.Join(rootfs, "home/developer/projects/webapp/node_modules/testpkg/index.js"), "module.exports = {};\n")

	proc := filepath.Join(dir, "proc")
	setupProcPIDT(t, proc, 4001, "python3", "/usr/bin/python3", []string{"python3", "-m", "http.server", "8000"}, 1000, 1, "mnt:[4026531840]", []uint64{40011})

	netTCP := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 40011 1 0000000083791377 100 0 0 10 0
`
	writeFileT(t, filepath.Join(proc, "net/tcp"), netTCP)
}

func createContainerHost(t *testing.T, dir string) {
	manifest := realworld.ProfileManifest{
		ProfileID:             realworld.ProfileContainerHost,
		Version:               "1.0.0",
		ExpectedStatus:        realworld.PostureSafe,
		MaxAcceptableAlerts:   0,
		MaxAcceptableWarnings: 2,
		AcceptableFindings: []realworld.AcceptableFindingRule{
			{
				RuleName:         "Process_Container_Mount_Namespace",
				ExpectedSeverity: "INFO",
				ExpectedVerdict:  "SAFE",
				Reason:           "Container workload in isolated mount namespace",
			},
		},
	}
	writeManifestT(t, filepath.Join(dir, "profile_manifest.json"), manifest)

	rootfs := filepath.Join(dir, "rootfs")
	writeFileT(t, filepath.Join(rootfs, "var/lib/dpkg/info/docker.list"), "/usr/bin/dockerd\n/usr/bin/containerd\n")
	writeFileT(t, filepath.Join(rootfs, "usr/bin/dockerd"), "#!/bin/sh\nexit 0\n")
	writeFileT(t, filepath.Join(rootfs, "usr/bin/containerd"), "#!/bin/sh\nexit 0\n")

	proc := filepath.Join(dir, "proc")
	setupProcPIDT(t, proc, 5001, "dockerd", "/usr/bin/dockerd", []string{"dockerd"}, 0, 1, "mnt:[4026531840]", nil)
	setupProcPIDT(t, proc, 5002, "containerd-shim", "/usr/bin/containerd", []string{"containerd-shim"}, 0, 5001, "mnt:[4026531840]", nil)
	setupProcPIDT(t, proc, 5003, "nginx", "/usr/sbin/nginx", []string{"nginx", "-g", "daemon off;"}, 0, 5002, "mnt:[4026532999]", nil)

	writeFileT(t, filepath.Join(proc, "net/tcp"), "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
}

func createPackageMixed(t *testing.T, dir string) {
	manifest := realworld.ProfileManifest{
		ProfileID:             realworld.ProfilePackageMixed,
		Version:               "1.0.0",
		ExpectedStatus:        realworld.PostureSafe,
		MaxAcceptableAlerts:   0,
		MaxAcceptableWarnings: 2,
	}
	writeManifestT(t, filepath.Join(dir, "profile_manifest.json"), manifest)

	rootfs := filepath.Join(dir, "rootfs")
	writeFileT(t, filepath.Join(rootfs, "var/lib/dpkg/info/coreutils.list"), "/usr/bin/ls\n/usr/bin/cat\n")
	writeFileT(t, filepath.Join(rootfs, "usr/bin/ls"), "#!/bin/sh\nexit 0\n")
	writeFileT(t, filepath.Join(rootfs, "usr/bin/cat"), "#!/bin/sh\nexit 0\n")
	writeFileT(t, filepath.Join(rootfs, "home/user/.local/bin/user_tool.sh"), "#!/bin/sh\necho my utility\n")
	writeFileT(t, filepath.Join(rootfs, "var/lib/flatpak/app/org.mozilla.Firefox/metadata"), "[Application]\nname=org.mozilla.Firefox\n")

	proc := filepath.Join(dir, "proc")
	setupProcPIDT(t, proc, 7001, "user_tool.sh", "/home/user/.local/bin/user_tool.sh", []string{"/bin/sh", "/home/user/.local/bin/user_tool.sh"}, 1000, 1, "mnt:[4026531840]", nil)

	writeFileT(t, filepath.Join(proc, "net/tcp"), "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
}

func createPrivilegeRestricted(t *testing.T, dir string) {
	manifest := realworld.ProfileManifest{
		ProfileID:             realworld.ProfilePrivilegeRestricted,
		Version:               "1.0.0",
		ExpectedStatus:        realworld.PostureLimitedVisibility,
		MaxAcceptableAlerts:   0,
		MaxAcceptableWarnings: 2,
		ExpectedCoverageLimits: []string{
			"SkippedPermission",
			"UnreadablePaths",
			"NonRootLimited",
		},
		ForbiddenFindings: []realworld.ForbiddenFindingRule{
			{
				RulePattern: "Ransomware_*",
				Reason:      "Privilege boundary test contains no ransomware",
			},
			{
				RulePattern: "ReverseShell_*",
				Reason:      "Privilege boundary test contains no active reverse shell",
			},
		},
	}
	writeManifestT(t, filepath.Join(dir, "profile_manifest.json"), manifest)

	rootfs := filepath.Join(dir, "rootfs")
	writeFileT(t, filepath.Join(rootfs, "etc/passwd"), "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nuser:x:1000:1000:user:/home/user:/bin/bash\n")

	// Create permission-restricted /etc/shadow with mode 0000
	shadowPath := filepath.Join(rootfs, "etc/shadow")
	writeFileT(t, shadowPath, "root:$6$rounds=50000$dummyhash:19000:0:99999:7:::\n")
	_ = os.Chmod(shadowPath, 0000)

	proc := filepath.Join(dir, "proc")
	setupProcPIDT(t, proc, 1, "systemd", "/usr/lib/systemd/systemd", []string{"/usr/lib/systemd/systemd"}, 0, 0, "mnt:[4026531840]", nil)

	// Simulated root-only process with restricted memory maps (mode 0000)
	setupProcPIDT(t, proc, 1001, "rootdaemon", "/usr/sbin/rootdaemon", []string{"/usr/sbin/rootdaemon"}, 0, 1, "mnt:[4026531840]", nil)
	_ = os.Chmod(filepath.Join(proc, "1001/maps"), 0000)

	writeFileT(t, filepath.Join(proc, "net/tcp"), "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
}
