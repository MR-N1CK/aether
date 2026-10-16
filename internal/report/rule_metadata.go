package report

// Rule metadata registry: one init() registration per detector rule.
// Every rule that emits a Finding must be registered here so reports carry
// a Title, plain-English Why, MITRE ATT&CK mapping, and Remediation steps.

func init() {
	// ---- Multi-vector / correlation ----
	mustRegister("Persistence_Multi_Vector_Persistence",
		"Multi-Vector Persistence Payload",
		"The same executable or hidden directory payload is wired into multiple independent persistence hooks (e.g. systemd, cron, shell profiles, or SSH), indicating an intentional multi-stage persistence setup.",
		[]MITREMapping{
			{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"},
			{Tactic: "Defense Evasion", Technique: "T1564.001", TechniqueName: "Hidden Files and Directories"},
		},
		[]string{
			"Inspect all linked persistence configurations identified in the finding.",
			"Quarantine the referenced payload binary and remove the autostart entries.",
			"Check process tree for active instances spawned by these persistence mechanisms.",
		},
		ConfidenceHigh)

	mustRegister("Persistence_Mixed",
		"Mixed Persistence Mechanisms Detected",
		"Multiple unrelated persistence hooks changed or appeared in the same scan window, which can indicate staged adversary persistence setup.",
		[]MITREMapping{
			{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"},
		},
		[]string{
			"Review each persistence configuration flagged in the finding.",
			"Correlate modification times with authentication logs.",
		},
		ConfidenceMedium)

	// ---- File content heuristics ----
	mustRegister("File_Suspicious_Private_Key_Location",
		"Private Key Material in Suspicious Location",
		"Cryptographic private key headers (OpenSSH/PEM/RSA/EC) were identified in an unowned, temporary, or hidden directory outside standard SSH/SSL configuration paths.",
		[]MITREMapping{
			{Tactic: "Credential Access", Technique: "T1552.004", TechniqueName: "Private Keys"},
		},
		[]string{
			"Verify if this key was intentionally generated or placed for automated tooling.",
			"Check whether the key matches any entry in ~/.ssh/authorized_keys or server configs.",
			"If unauthorized, revoke the key pair across all servers and remove the file.",
		},
		ConfidenceHigh)

	mustRegister("Script_RedTeam_Persistence_Framework",
		"Red-Team Stealth Implant & Persistence Framework",
		"The script contains signatures of an automated red-team persistence framework, including stealth procfs process hiding, fake systemd/cron hooks, and persistent reverse shell listeners.",
		[]MITREMapping{
			{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"},
			{Tactic: "Defense Evasion", Technique: "T1564.001", TechniqueName: "Hidden Files and Directories"},
			{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"},
		},
		[]string{
			"Immediately isolate the affected endpoint and inspect /proc mounts for hidden processes.",
			"Quarantine the framework script and inspect systemd service directories and cron tabs for installed implants.",
			"Audit system authentication logs to determine initial intrusion vector.",
		},
		ConfidenceHigh)

	mustRegister("Script_Process_Hiding_Procfs",
		"Stealth Process Hiding via Procfs Manipulation",
		"The file mounts a tmpfs layer over /proc/<PID> entries to conceal malicious background processes and backdoors from tools like ps, top, and lsof.",
		[]MITREMapping{
			{Tactic: "Defense Evasion", Technique: "T1564.001", TechniqueName: "Hidden Files and Directories"},
			{Tactic: "Defense Evasion", Technique: "T1014", TechniqueName: "Rootkit"},
		},
		[]string{
			"Unmount unauthorized tmpfs filesystems from /proc mountpoints (`umount -l /proc/<PID>`).",
			"Check running processes and kernel task list for rogue concealed PIDs.",
		},
		ConfidenceHigh)

	mustRegister("Script_Python_Ransomware_Encryptor",
		"Ransomware File Encryptor & Locker",
		"The script performs automated recursive filesystem encryption (Fernet/AES), locks target files (.locked/.enc), destroys original copies, and generates ransom demand notes.",
		[]MITREMapping{
			{Tactic: "Impact", Technique: "T1486", TechniqueName: "Data Encrypted for Impact"},
			{Tactic: "Defense Evasion", Technique: "T1070.004", TechniqueName: "File Deletion"},
		},
		[]string{
			"Immediately quarantine or remove the script payload.",
			"Verify if any files in target directories were encrypted or deleted.",
			"Check for locally backed-up session recovery keys in temporary locations.",
		},
		ConfidenceHigh)

	mustRegister("Script_Data_Exfiltration_Stealer",
		"Automated Data Exfiltration / File Stealer",
		"The script recursively crawls directories, compresses and encodes document data, and exfiltrates files outbound over network sockets to a remote C2 server.",
		[]MITREMapping{
			{Tactic: "Exfiltration", Technique: "T1041", TechniqueName: "Exfiltration Over C2 Channel"},
			{Tactic: "Collection", Technique: "T1005", TechniqueName: "Data from Local System"},
		},
		[]string{
			"Inspect network connections and firewall logs for traffic to the exfiltration destination IP/port.",
			"Audit file access timestamps to identify what confidential documents were staged or exfiltrated.",
			"Quarantine the exfiltration client script.",
		},
		ConfidenceHigh)

	mustRegister("Script_C2_Exfiltration_Server",
		"C2 Data Exfiltration Collection Server",
		"The script configures a listening network server to receive, decompress, and reconstruct exfiltrated directory trees and stolen credentials.",
		[]MITREMapping{
			{Tactic: "Command and Control", Technique: "T1071.001", TechniqueName: "Web Protocols"},
			{Tactic: "Exfiltration", Technique: "T1041", TechniqueName: "Exfiltration Over C2 Channel"},
		},
		[]string{
			"Terminate the listening process and block the configured port.",
			"Inspect exfiltrated data dumps to identify compromised client endpoints.",
		},
		ConfidenceHigh)

	mustRegister("Script_Reverse_Shell_Interactive",
		"Interactive Reverse Shell Socket Redirection",
		"Process standard input (stdin) or output (stdout) is redirected to an active network socket, establishing an interactive shell session with an external host.",
		[]MITREMapping{
			{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"},
			{Tactic: "Command and Control", Technique: "T1071", TechniqueName: "Application Layer Protocol"},
		},
		[]string{
			"Immediately terminate the rogue process PID (`kill -9 <PID>`).",
			"Trace process parentage (PPID) and inspect open sockets (/proc/<PID>/net or /proc/net/tcp).",
			"Isolate the host from the network to sever C2 communications.",
		},
		ConfidenceHigh)

	mustRegister("Container_Dangerous_Capability_Overprivilege",
		"Container Process with Dangerous Host Breakout Capabilities",
		"A container process runs with elevated Linux capabilities (e.g. CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH), allowing potential container breakout and host compromise.",
		[]MITREMapping{
			{Tactic: "Privilege Escalation", Technique: "T1611", TechniqueName: "Escape to Host"},
			{Tactic: "Privilege Escalation", Technique: "T1548", TechniqueName: "Abuse Elevation Control Mechanism"},
		},
		[]string{
			"Drop unnecessary Linux capabilities in container runtime configuration (use `cap_drop: [ALL]`).",
			"Avoid running containers with `--privileged` flag in Docker or Podman.",
			"Enable Seccomp and AppArmor profiles to restrict container system calls.",
		},
		ConfidenceHigh)

	mustRegister("Script_Reverse_Shell_Inline",
		"Interactive Reverse Shell Script / Backdoor (Inline Interpreter)",
		"The file contains automated network socket redirection code (inline Python/Perl/PHP/Ruby sockets) designed to connect outbound and grant an interactive remote command shell.",
		[]MITREMapping{
			{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"},
			{Tactic: "Command and Control", Technique: "T1071.001", TechniqueName: "Web Protocols"},
		},
		[]string{
			"Quarantine the script file and review authentication and bash history logs.",
			"Inspect network connections and firewall logs for active or outbound traffic to the target host/port.",
			"Check the process tree for any spawned interactive shells.",
		},
		ConfidenceHigh)

	mustRegister("Script_OpenSSL_Reverse_Shell",
		"Encrypted OpenSSL Reverse Shell Backdoor",
		"The file tunnels an interactive shell through an OpenSSL s_client session, hiding interactive C2 traffic inside TLS to defeat plain-network monitoring.",
		[]MITREMapping{
			{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"},
			{Tactic: "Command and Control", Technique: "T1573.002", TechniqueName: "Asymmetric Cryptography"},
		},
		[]string{
			"Quarantine the script file and review authentication and bash history logs.",
			"Inspect TLS egress logs for the destination host and block the endpoint.",
			"Check the process tree for any spawned interactive shells.",
		},
		ConfidenceHigh)

	mustRegister("Script_Socat_Reverse_Shell",
		"Socat Relay Reverse Shell Backdoor",
		"The file uses socat to relay an interactive shell (exec/pty/system) over the network, frequently wrapped in openssl-connect for encryption.",
		[]MITREMapping{
			{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"},
			{Tactic: "Command and Control", Technique: "T1071", TechniqueName: "Application Layer Protocol"},
		},
		[]string{
			"Quarantine the script file and review authentication and bash history logs.",
			"Inspect network connections for outbound traffic to the socat target.",
		},
		ConfidenceHigh)

	mustRegister("Script_Netcat_Reverse_Shell",
		"Netcat Reverse Shell Backdoor",
		"The file uses netcat/ncat in execute mode (-e/-c) or a mkfifo redirection to grant an interactive remote shell over the network.",
		[]MITREMapping{
			{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"},
			{Tactic: "Command and Control", Technique: "T1071", TechniqueName: "Application Layer Protocol"},
		},
		[]string{
			"Quarantine the script file and review authentication and bash history logs.",
			"Inspect network connections and firewall logs for active or outbound traffic to the target host/port.",
		},
		ConfidenceHigh)

	mustRegister("Script_Download_And_Execute",
		"Remote Download and Pipe Execution Dropper",
		"The script downloads arbitrary code over HTTP/HTTPS and pipes it directly into an interpreter (e.g., curl | bash), which is a common staging pattern for malware droppers.",
		[]MITREMapping{
			{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"},
			{Tactic: "Command and Control", Technique: "T1105", TechniqueName: "Ingress Tool Transfer"},
		},
		[]string{
			"Verify whether the remote URL is a trusted official software installer.",
			"Inspect the downloaded URL content in an isolated environment before executing.",
		},
		ConfidenceHigh)

	mustRegister("Script_PowerShell_Encoded_Execution",
		"Encoded PowerShell Command Execution",
		"A script executes PowerShell Core with Base64 encoded payload flags (-e, -enc, -EncodedCommand), which is frequently used by cross-platform malware to evade string detection.",
		[]MITREMapping{
			{Tactic: "Execution", Technique: "T1059.001", TechniqueName: "PowerShell"},
			{Tactic: "Defense Evasion", Technique: "T1027", TechniqueName: "Obfuscated Files or Information"},
		},
		[]string{
			"Decode the Base64 command payload using `echo <base64> | base64 -d | iconv -f utf-16le`.",
			"Identify the processes and network connections spawned by the PowerShell interpreter.",
			"Quarantine or remove the invoking script.",
		},
		ConfidenceHigh)

	mustRegister("Script_Cloud_Exfiltration_Tool",
		"Automated Cloud Storage Exfiltration Tool",
		"A script invokes cloud synchronization tools (e.g., rclone, mega, aws s3, gsutil, azcopy) or anonymous file transfer endpoints with sensitive system directories or archives.",
		[]MITREMapping{
			{Tactic: "Exfiltration", Technique: "T1567.002", TechniqueName: "Exfiltration to Cloud Storage"},
			{Tactic: "Collection", Technique: "T1005", TechniqueName: "Data from Local System"},
		},
		[]string{
			"Review the cloud destination credentials and remote storage endpoints in the script.",
			"Check network egress logs for large volume data transfers to the target cloud provider.",
			"Revoke compromised cloud storage access tokens immediately.",
		},
		ConfidenceMedium)

	mustRegister("Persistence_Linker_Audit_Hijack",
		"Dynamic Linker Hook Hijack (LD_PRELOAD / LD_AUDIT)",
		"A script or service configures a dynamic linker hook (LD_PRELOAD or LD_AUDIT) pointing at a volatile directory, a relative path, a missing library, or a location outside the standard linker directories. Adversaries use these hooks to intercept library resolution and execute code in every subsequent process before startup.",
		[]MITREMapping{
			{Tactic: "Persistence", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"},
			{Tactic: "Defense Evasion", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"},
		},
		[]string{
			"Inspect /etc/ld.so.preload, /etc/ld.so.audit, and system-wide environment files for rogue library references.",
			"Verify the integrity and package ownership of any preloaded or audit library; delete-or-restore entries referencing volatile paths.",
			"Remove unauthorized LD_PRELOAD / LD_AUDIT entries from shell profiles and systemd service environments.",
		},
		ConfidenceHigh)

	mustRegister("Persistence_PAM_Exec_Suspicious",
		"Suspicious PAM Authentication Hook (pam_exec / pam_script)",
		"A Pluggable Authentication Module (PAM) configuration contains a pam_exec.so or pam_script.so directive pointing to a volatile, user-writable, or hidden path, allowing persistence and credential harvesting upon authentication.",
		[]MITREMapping{
			{Tactic: "Persistence", Technique: "T1556.004", TechniqueName: "Pluggable Authentication Modules"},
			{Tactic: "Credential Access", Technique: "T1556", TechniqueName: "Modify Authentication Process"},
		},
		[]string{
			"Inspect the referenced executable script in /etc/pam.d/ for unauthorized commands.",
			"Verify whether the script was placed by a legitimate administrative package.",
			"Quarantine the rogue script and remove the pam_exec directive from the PAM configuration.",
		},
		ConfidenceHigh)

	mustRegister("Webshell_PHP_Generic_Backdoor",
		"PHP Web Shell / Dynamic Code Execution Backdoor",
		"The PHP file contains dynamic code execution patterns (eval/assert over decoded superglobals, system command wrappers) typical of backdoor web shells.",
		[]MITREMapping{
			{Tactic: "Persistence", Technique: "T1505.003", TechniqueName: "Web Shell"},
			{Tactic: "Execution", Technique: "T1059", TechniqueName: "Command and Scripting Interpreter"},
		},
		[]string{
			"Review the web server document root access logs around the file's modification time.",
			"Quarantine the file and check for unauthorized administrative web sessions.",
		},
		ConfidenceHigh)

	// ---- Filesystem heuristics ----
	mustRegister("Heuristic_Suspicious_SUID_SGID",
		"Elevated SUID/SGID Binary in Non-Standard Path",
		"A privileged binary with the SUID/SGID permission bit is located in a user-writable or non-standard directory, which presents privilege escalation risk.",
		[]MITREMapping{
			{Tactic: "Privilege Escalation", Technique: "T1548.001", TechniqueName: "Setuid and Setgid"},
		},
		[]string{
			"Confirm package ownership using dpkg/rpm.",
			"Remove the SUID bit using `chmod u-s <path>` if elevated privilege is unnecessary.",
		},
		ConfidenceMedium)

	mustRegister("Process_Memfd_Execution",
		"Memory Execution / Unlinked Binary",
		"A running process executable has been unlinked from disk or executed entirely out of an anonymous in-memory file descriptor (memfd_create).",
		[]MITREMapping{
			{Tactic: "Defense Evasion", Technique: "T1620", TechniqueName: "Reflective Code Loading"},
			{Tactic: "Defense Evasion", Technique: "T1070.004", TechniqueName: "File Deletion"},
		},
		[]string{
			"Inspect /proc/<pid>/exe and /proc/<pid>/fd to extract the in-memory binary image.",
			"Terminate the process and investigate how it was launched.",
		},
		ConfidenceHigh)

	// ---- Users ----
	mustRegister("Users_Extra_UID0_Account",
		"Rogue Non-Root UID 0 Account",
		"A non-root user account in /etc/passwd has been assigned UID 0, giving it unconstrained root administrative privileges.",
		[]MITREMapping{
			{Tactic: "Persistence", Technique: "T1136.001", TechniqueName: "Local Account"},
			{Tactic: "Privilege Escalation", Technique: "T1078.003", TechniqueName: "Local Accounts"},
		},
		[]string{
			"Audit /etc/passwd and /etc/shadow for unauthorized accounts.",
			"Remove or lock the rogue UID 0 account immediately.",
			"Review authentication logs to trace account creation.",
		},
		ConfidenceHigh)

	// ---- Kernel / rootkit ----
	mustRegister("Kernel_Hidden_LKM_Module",
		"Kernel Rootkit / Hidden LKM Module",
		"A kernel module visible in sysfs but absent from /proc/modules (or vice versa) indicates module-list hiding, a hallmark of Loadable Kernel Module rootkits (e.g. Diamorphine).",
		[]MITREMapping{
			{Tactic: "Defense Evasion", Technique: "T1014", TechniqueName: "Rootkit"},
			{Tactic: "Persistence", Technique: "T1547.006", TechniqueName: "Kernel Modules and Extensions"},
		},
		[]string{
			"Inspect loaded kernel modules using `lsmod` and audit `/lib/modules/`.",
			"Reboot into a trusted live forensics environment to inspect rootkit hooks.",
			"Quarantine any malicious kernel object (.ko) files.",
		},
		ConfidenceHigh)

	// ---- IOC ----
	// NOTE: hash-IOC rule names are dynamic ("IOC_Hash_<TYPE>" or a custom
	// description-derived name); those resolve through the legacy substring
	// fallback in PopulateFindingDetails. The static names are registered here.
	mustRegister("IOC_Hash_SHA256",
		"Cryptographic Threat Intelligence IOC Match (SHA-256)",
		"The file SHA-256 hash matches a known high-confidence threat indicator of compromise (IOC).",
		[]MITREMapping{
			{Tactic: "Execution", Technique: "T1204.002", TechniqueName: "Malicious File"},
		},
		[]string{
			"Immediately isolate the affected system.",
			"Quarantine the matching IOC payload file.",
			"Correlate the IOC across enterprise endpoint telemetry.",
		},
		ConfidenceHigh)

	mustRegister("IOC_Hash_SHA1",
		"Cryptographic Threat Intelligence IOC Match (SHA-1)",
		"The file SHA-1 hash matches a known threat indicator of compromise (IOC).",
		[]MITREMapping{
			{Tactic: "Execution", Technique: "T1204.002", TechniqueName: "Malicious File"},
		},
		[]string{
			"Immediately isolate the affected system.",
			"Quarantine the matching IOC payload file.",
			"Correlate the IOC across enterprise endpoint telemetry.",
		},
		ConfidenceHigh)

	mustRegister("IOC_Hash_MD5",
		"Cryptographic Threat Intelligence IOC Match (MD5)",
		"The file MD5 hash matches a known threat indicator of compromise (IOC).",
		[]MITREMapping{
			{Tactic: "Execution", Technique: "T1204.002", TechniqueName: "Malicious File"},
		},
		[]string{
			"Immediately isolate the affected system.",
			"Quarantine the matching IOC payload file.",
			"Correlate the IOC across enterprise endpoint telemetry.",
		},
		ConfidenceHigh)

	mustRegister("Network_IOC_IP_Connection",
		"Connection to Known Malicious IP Indicator",
		"A running process maintains a network connection to an IP address present in the loaded threat-intelligence indicator set.",
		[]MITREMapping{
			{Tactic: "Command and Control", Technique: "T1071", TechniqueName: "Application Layer Protocol"},
		},
		[]string{
			"Identify and terminate the process holding the malicious connection.",
			"Block the destination IP at the perimeter firewall.",
			"Review proxy/netflow history for the destination to scope the compromise.",
		},
		ConfidenceHigh)

	// ---- SSH persistence ----
	mustRegister("Persistence_SSH_Key_Non_Standard_Location",
		"SSH Key Material in Non-Standard Location",
		"SSH key material was found outside standard ~/.ssh paths, which may indicate staged credentials or persistence setup.",
		[]MITREMapping{
			{Tactic: "Persistence", Technique: "T1098.004", TechniqueName: "SSH Authorized Keys"},
			{Tactic: "Credential Access", Technique: "T1552.004", TechniqueName: "Private Keys"},
		},
		[]string{
			"Verify the key's legitimacy with the system owner.",
			"If unauthorized, remove the key and rotate any credentials it protected.",
		},
		ConfidenceMedium)

	mustRegister("Persistence_Reverse_Shell_Primitive",
		"Reverse Shell Primitive in Persistence Hook",
		"A persistence configuration embeds a shell redirection primitive (/dev/tcp, mkfifo, or socket exec) that spawns an outbound interactive shell when triggered.",
		[]MITREMapping{
			{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"},
			{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"},
		},
		[]string{
			"Remove the persistence entry and quarantine the referenced script.",
			"Trace the hook's creation time against authentication logs.",
		},
		ConfidenceHigh)

	// ---- De-obfuscation & Entropy heuristics ----
	mustRegister("Script_Obfuscated_Payload",
		"Obfuscated Malicious Script Payload",
		"An obfuscated payload was discovered that, once decoded (Base64, Hex, or Gzip), contains active reverse shells, ransomware, or dropper instructions.",
		[]MITREMapping{
			{Tactic: "Defense Evasion", Technique: "T1027", TechniqueName: "Obfuscated Files or Information"},
			{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"},
		},
		[]string{
			"Quarantine the file and analyze the decoded payload stream.",
			"Review process execution logs for instances executing de-obfuscated commands.",
			"Inspect cron and startup scripts for persistence of the dropper.",
		},
		ConfidenceHigh)

	mustRegister("High_Entropy_ELF_In_Tmp",
		"High-Entropy Packed Binary in Volatile Directory",
		"An executable ELF binary with unusually high Shannon entropy (> 7.0) was identified in a temporary or world-writable directory, indicating software packing, compression, or encryption typical of Linux trojans and cryptominers.",
		[]MITREMapping{
			{Tactic: "Defense Evasion", Technique: "T1027.002", TechniqueName: "Software Packing"},
			{Tactic: "Defense Evasion", Technique: "T1070.004", TechniqueName: "File Deletion"},
		},
		[]string{
			"Immediately isolate or quarantine the suspicious ELF binary.",
			"Check running processes (/proc/<pid>/exe) to see if the packed binary is actively running.",
			"Identify the user account and network connection that downloaded the binary.",
		},
		ConfidenceHigh)

	mustRegister("High_Entropy_Script",
		"High-Entropy Script / Encrypted Payload",
		"The script contains large contiguous high-entropy byte blocks (> 7.5) characteristic of embedded shellcode or encrypted second-stage payloads.",
		[]MITREMapping{
			{Tactic: "Defense Evasion", Technique: "T1027", TechniqueName: "Obfuscated Files or Information"},
		},
		[]string{
			"Inspect the script for dynamic evaluation wrappers (e.g. eval, exec, base64_decode).",
			"Quarantine the script payload and verify if target services were compromised.",
		},
		ConfidenceMedium)

	mustRegister("Script_Webshell_Traits",
		"Webshell Backdoor Behavioral Traits",
		"The script contains structural characteristics typical of web-based administrative backdoors, file managers, or remote command execution portals.",
		[]MITREMapping{
			{Tactic: "Persistence", Technique: "T1505.003", TechniqueName: "Server Software Component: Web Shell"},
			{Tactic: "Execution", Technique: "T1059", TechniqueName: "Command and Scripting Interpreter"},
		},
		[]string{
			"Examine web server access logs for anomalous requests accessing this file.",
			"Isolate or quarantine the webshell script immediately.",
			"Audit file upload endpoints and web application permissions for unauthorized writes.",
		},
		ConfidenceMedium)
}
