package report

// Rule metadata for persistence, process, network, kernel, users, and
// scanner infra rules. Split from rule_metadata.go to keep files sized for review.

func init() {
	registerPersistenceRules()
	registerProcessRules()
	registerNetworkRules()
	registerKernelRules()
	registerUsersRules()
	registerScannerRules()
}

func registerPersistenceRules() {
	m := func(name, title, why string, mitre []MITREMapping, remediation []string, c Confidence) {
		mustRegister(name, title, why, mitre, remediation, c)
	}

	m("Persistence_Systemd_Unowned_Unit",
		"Unowned Systemd Unit File (Persistence Hook)",
		"A systemd unit file is owned by a non-root user or world-writable, allowing persistence without root package-manager provenance.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1543.002", TechniqueName: "Systemd Service"}},
		[]string{"Verify package ownership (dpkg -S / systemctl cat <unit>).", "Remove or correct ownership to root:root 0644 if unauthorized."},
		ConfidenceHigh)

	m("Persistence_Systemd_Symlink_Escape",
		"Systemd Unit Symlink Escape",
		"A systemd unit is a symlink escaping the canonical unit directory, which can redirect service startup to an attacker-controlled binary.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1543.002", TechniqueName: "Systemd Service"}},
		[]string{"Resolve the symlink target and verify it is inside the vendor/unit directory.", "Remove unexpected symlinks."},
		ConfidenceHigh)

	m("Persistence_Systemd_Recently_Modified",
		"Recently Modified Systemd Unit",
		"A systemd unit file was modified very recently outside the last package upgrade window, suggesting ad-hoc persistence tampering.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1543.002", TechniqueName: "Systemd Service"}},
		[]string{"Correlate mtime with auth logs and package manager history.", "Restore the vendor unit file if tampering is confirmed."},
		ConfidenceMedium)

	m("Persistence_Cron_Temp_Path",
		"Suspicious Cron Entry Referencing Temporary Path",
		"A cron entry executes a binary or script from /tmp, /dev/shm, or another world-writable staging directory.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1053.003", TechniqueName: "Cron"}},
		[]string{"Inspect the cron entry and the referenced payload.", "Remove unauthorized cron jobs; audit cron spool ownership."},
		ConfidenceHigh)

	m("Persistence_Cron_Temp_Target",
		"Cron Job Pointing to Temporary Executable",
		"A cron job's executable target lives in a temporary or volatile path.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1053.003", TechniqueName: "Cron"}},
		[]string{"Verify whether the cron job is expected; check package ownership.", "Remove or relocate the target to a trusted path."},
		ConfidenceHigh)

	m("Persistence_Cron_Binary_File",
		"Cron File Is a Binary, Not a Script",
		"A cron file is an ELF binary rather than a shell script, which is highly unusual for legitimate cron infrastructure.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1053.003", TechniqueName: "Cron"}},
		[]string{"Identify how the binary was placed in cron.", "Remove it and check for companion persistence."},
		ConfidenceHigh)

	m("Persistence_Cron_Suspicious",
		"Suspicious Cron Entry",
		"A cron entry exhibits suspicious traits (temporary paths, download primitives, or anomalous permissions).",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1053.003", TechniqueName: "Cron"}},
		[]string{"Review the cron schedule and target for legitimacy.", "Harden cron file permissions to root-owned 0600/0644."},
		ConfidenceMedium)

	m("Persistence_Exec_From_Temp",
		"Persistence Hook Executes from Temporary Directory",
		"A persistence hook (systemd/cron/profile) executes a payload from a world-writable temporary directory.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"}},
		[]string{"Quarantine the payload and remove the autostart entry.", "Check process tree for active instances."},
		ConfidenceHigh)

	m("Persistence_Exec_From_Hidden_Path",
		"Persistence Hook Executes Hidden File",
		"A persistence hook executes a dotfile (hidden) payload.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"}, {Tactic: "Defense Evasion", Technique: "T1564.001", TechniqueName: "Hidden Files and Directories"}},
		[]string{"Inspect the hidden payload and its persistence hook.", "Remove unauthorized dotfile executables from autostart."},
		ConfidenceHigh)

	m("Persistence_Exec_From_Home_Hidden_Path",
		"Persistence Hook Executes Hidden File in Home",
		"A persistence entry in the home tree executes a hidden executable, typical of user-level persistence.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547.001", TechniqueName: "Registry Run Keys / Startup Folder"}},
		[]string{"Review ~/.config/autostart, shell rcs, and cron for the entry.", "Remove unauthorized hidden executables."},
		ConfidenceHigh)

	m("Persistence_Exec_From_Home_Cache_Path",
		"Persistence Hook Executes from Home Cache Path",
		"A persistence hook executes a payload from ~/.cache or similar volatile home directory.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"}},
		[]string{"Verify whether the cache-path binary is legitimate.", "Remove unauthorized entries."},
		ConfidenceMedium)

	m("Persistence_APT_Hook_Temp",
		"APT Hook Script in Temporary Path",
		"An APT hook references a script in a temporary or world-writable path, risking package-manager-time code execution.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"}},
		[]string{"Inspect /etc/apt/apt.conf.d/ hooks.", "Move hook scripts to root-owned paths under /usr or /etc."},
		ConfidenceHigh)

	m("Persistence_Autostart_Tunnel",
		"Autostart Tunnel / Proxy Configuration",
		"A desktop autostart entry configures a tunnel or proxy that could exfiltrate traffic.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547.001", TechniqueName: "Registry Run Keys / Startup Folder"}, {Tactic: "Command and Control", Technique: "T1090", TechniqueName: "Proxy"}},
		[]string{"Inspect the autostart desktop file and its Exec target.", "Remove unauthorized tunnel/proxy autostart entries."},
		ConfidenceHigh)

	m("Persistence_Download_And_Execute",
		"Persistence Hook Downloads and Executes Remote Payload",
		"A persistence hook fetches code over HTTP and pipes it to a shell, a classic dropper persistence pattern.",
		[]MITREMapping{{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"}, {Tactic: "Command and Control", Technique: "T1105", TechniqueName: "Ingress Tool Transfer"}},
		[]string{"Verify whether the remote URL is a trusted installer.", "Remove the hook and block the URL."},
		ConfidenceHigh)

	m("Persistence_Dev_TCP_Reference",
		"Persistence Hook References /dev/tcp (Reverse Shell Primitive)",
		"A persistence configuration references bash's /dev/tcp pseudo-device, indicating an embedded reverse shell primitive.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"}, {Tactic: "Command and Control", Technique: "T1071", TechniqueName: "Application Layer Protocol"}},
		[]string{"Remove the persistence entry and investigate the referenced host/port.", "Hunt for active reverse shells (check /proc/<pid>/fd and sockets)."},
		ConfidenceHigh)

	m("Persistence_Eval_Decode_Obfuscation",
		"Persistence Payload Uses Eval/Decode Obfuscation",
		"A persistence payload uses eval with base64/hex decoding to hide its true behavior.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1027", TechniqueName: "Obfuscated Files or Information"}},
		[]string{"Decode the payload in an isolated environment to reveal intent.", "Remove the hook if malicious."},
		ConfidenceHigh)

	m("Persistence_Piped_Decode_Execute",
		"Persistence Payload Pipes Decoded Content to Execution",
		"A persistence entry decodes data (base64/hex/gzip) and pipes the result to execution, hiding the executed payload.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1027", TechniqueName: "Obfuscated Files or Information"}, {Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"}},
		[]string{"Capture the decoded stream offline and classify it.", "Remove the persistence hook."},
		ConfidenceHigh)

	m("Persistence_Insecure_SSH_Options",
		"Authorized Keys with Insecure SSH Options",
		"An authorized_keys line grants excessive capabilities (e.g. no-port-forwarding bypass, forced command) or lacks required restrictions.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1098.004", TechniqueName: "SSH Authorized Keys"}},
		[]string{"Harden authorized_keys options (restrict command, from=, no-port-forwarding).", "Re-issue keys without insecure options."},
		ConfidenceMedium)

	m("Persistence_Loader_Symlink_Preload",
		"LD Preload Persistence via Symlink",
		"/etc/ld.so.preload or a preload library is a symlink, which can redirect dynamic linking to an attacker-controlled shared object.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"}},
		[]string{"Resolve the symlink target and verify it is a trusted library path.", "Remove unauthorized preload symlinks."},
		ConfidenceHigh)

	m("Persistence_Loader_Preload_Active",
		"LD Preload Persistence Is Active",
		"/etc/ld.so.preload exists and will interpose attacker code into every dynamically linked process at startup.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"}},
		[]string{"Inspect /etc/ld.so.preload contents and referenced libraries.", "Remove unauthorized preload entries and libraries."},
		ConfidenceHigh)

	m("Persistence_Loader_Preload_Temp_Library",
		"LD Preload Library in Temporary Directory",
		"A preload library lives in /tmp, /dev/shm, or another volatile path — a strong indicator of staged userland rootkit installation.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"}, {Tactic: "Defense Evasion", Technique: "T1014", TechniqueName: "Rootkit"}},
		[]string{"Quarantine the library and remove the preload entry.", "Reboot from trusted media to inspect for persistence."},
		ConfidenceHigh)

	m("Persistence_Loader_Preload_Missing_Library",
		"LD Preload Library Missing on Disk",
		"A preload entry references a shared object that does not exist on disk (broken persistence or staged implant not yet dropped).",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"}},
		[]string{"Remove the dangling preload entry.", "Hunt for how it was created (audit logs, shell history)."},
		ConfidenceMedium)

	m("Persistence_Loader_Preload_Unowned_Library",
		"LD Preload Library Not Package-Owned",
		"A preload library is not owned by any OS package, suggesting manually installed interposition code.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"}},
		[]string{"Verify provenance of the library (build it yourself or reinstall the package).", "Remove unowned preload libraries."},
		ConfidenceHigh)

	m("Persistence_Loader_Insecure_Library_Directory",
		"LD Library Directory Is Insecurely Writable",
		"A directory on the dynamic linker's search path is world-writable, allowing shared-object planting attacks.",
		[]MITREMapping{{Tactic: "Privilege Escalation", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"}},
		[]string{"Correct permissions on the library directory (root:root 0755).", "Audit for planted .so files in the directory."},
		ConfidenceHigh)

	m("Persistence_Loader_World_Writable_Directory",
		"LD Configuration Directory Is World-Writable",
		"An ld.so configuration directory is world-writable, permitting attacker-writable library search paths.",
		[]MITREMapping{{Tactic: "Privilege Escalation", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"}},
		[]string{"Fix directory permissions and ownership.", "Review ld.so.conf and conf.d entries."},
		ConfidenceHigh)

	m("Persistence_Loader_Environment_Preload",
		"Environment-Injected LD Preload Persistence",
		"An environment file (e.g. /etc/environment, systemd environment) injects LD_PRELOAD, interposing code at process startup.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"}},
		[]string{"Inspect the environment file and the referenced library.", "Remove unauthorized LD_PRELOAD injections."},
		ConfidenceHigh)

	m("Persistence_Loader_Environment_Preload_Temp",
		"Environment LD Preload Points to Temporary Library",
		"An environment-injected LD_PRELOAD references a library in a volatile path — a staged userland rootkit indicator.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"}, {Tactic: "Defense Evasion", Technique: "T1014", TechniqueName: "Rootkit"}},
		[]string{"Quarantine the library and remove the environment injection.", "Investigate the infection vector."},
		ConfidenceHigh)

	m("Persistence_Missing_Target_File",
		"Persistence Hook References Missing Target",
		"A persistence configuration references an executable that does not exist on disk.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"}},
		[]string{"Verify whether the target belongs to an uninstalled package.", "Remove dead startup entries to prevent binary-path hijacking."},
		ConfidenceLow)

	m("Persistence_MOTD_Unowned_Script",
		"Unowned MOTD / Update-Motd Script",
		"A message-of-the-day script is not owned by a distribution package, allowing logon-time code execution as root.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"}},
		[]string{"Verify script ownership; remove unauthorized MOTD scripts.", "Harden /etc/update-motd.d permissions."},
		ConfidenceMedium)

	m("Persistence_PAM_Exec_Temp_Script",
		"PAM Exec Module References Temporary Script",
		"A PAM stack executes a script from /tmp or another volatile path at authentication time.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"}},
		[]string{"Move PAM exec targets to root-owned paths and re-audit PAM stacks.", "Remove unauthorized PAM entries."},
		ConfidenceHigh)

	m("Persistence_PAM_Exec_Non_System_Script",
		"PAM Exec Module References Non-System Script",
		"A PAM configuration executes a script outside standard system paths (/lib, /usr/lib, /etc).",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"}},
		[]string{"Relocate the script to a trusted system path or remove the PAM entry.", "Review auth logs for the hook's creation."},
		ConfidenceMedium)

	m("Persistence_PAM_Nonstandard_Module",
		"PAM Configuration References Non-Standard Module Path",
		"A PAM stack loads a module from outside the distribution module directory.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"}},
		[]string{"Verify the module path against the distribution's PAM layout.", "Remove non-standard module entries."},
		ConfidenceMedium)

	m("Persistence_PAM_Unowned_Module_Binary",
		"PAM Module Binary Not Package-Owned",
		"A PAM module shared object on disk is not owned by any installed package.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"}},
		[]string{"Reinstall the owning package or verify the module's provenance.", "Remove unowned PAM modules."},
		ConfidenceHigh)

	m("Persistence_Profile_LD_PRELOAD",
		"Shell Profile Injects LD_PRELOAD",
		"A shell startup file (profile/rc) exports LD_PRELOAD, interposing code into every shell session.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547.001", TechniqueName: "Registry Run Keys / Startup Folder"}, {Tactic: "Persistence", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"}},
		[]string{"Inspect the shell rc/profile file and the referenced library.", "Remove the LD_PRELOAD export if unauthorized."},
		ConfidenceHigh)

	m("Persistence_Profile_Privileged_Alias",
		"Shell Profile Defines Privileged Alias",
		"A shell profile defines an alias that wraps a privileged command (e.g. sudo, su) — a credential-interception risk.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"}, {Tactic: "Credential Access", Technique: "T1056.002", TechniqueName: "GUI Input Capture"}},
		[]string{"Remove the alias and review shell history for credential capture.", "Audit who modified the profile file."},
		ConfidenceHigh)

	m("Persistence_Profile_Temp_PATH",
		"Shell Profile Prepends Temporary Directory to PATH",
		"A shell profile prepends a world-writable or temporary directory to PATH, enabling binary-planting attacks.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"}},
		[]string{"Remove the PATH manipulation and harden the referenced directory.", "Check for planted binaries shadowing system commands."},
		ConfidenceMedium)

	m("Persistence_RCD_Unowned_Script",
		"Unowned rc.local / rc.d Script",
		"A legacy init script (rc.local, rc.d) is not package-owned and executes at boot as root.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1037", TechniqueName: "Boot or Logon Initialization Scripts"}},
		[]string{"Verify the script's purpose or remove it.", "Migrate to systemd units for auditable boot ordering."},
		ConfidenceMedium)

	m("Persistence_SSHD_AuthorizedKeysCommand",
		"SSHD AuthorizedKeysCommand Executes External Program",
		"sshd_config's AuthorizedKeysCommand executes an external program to resolve public keys, which if compromised yields persistent backdoor access.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1098.004", TechniqueName: "SSH Authorized Keys"}},
		[]string{"Verify the AuthorizedKeysCommand target is a trusted, package-owned binary.", "Remove or restrict the directive if unnecessary."},
		ConfidenceHigh)

	m("Persistence_SSHD_Non_Standard_AuthorizedKeysFile",
		"SSHD AuthorizedKeysFile Outside Standard Path",
		"sshd_config points AuthorizedKeysFile outside ~/.ssh/authorized_keys, which can hide persistence keys.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1098.004", TechniqueName: "SSH Authorized Keys"}},
		[]string{"Review the custom AuthorizedKeysFile path for legitimacy.", "Revert to the standard path or audit the custom file's contents and permissions."},
		ConfidenceMedium)

	m("Persistence_SSHD_PermitRootLogin_Yes",
		"SSHD PermitRootLogin Is Enabled",
		"sshd_config permits direct root login, expanding the blast radius of any compromised SSH key.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1098.004", TechniqueName: "SSH Authorized Keys"}},
		[]string{"Set PermitRootLogin to prohibit-password or no.", "Require non-root login with sudo for privilege escalation."},
		ConfidenceLow)

	m("Persistence_SSH_Forced_Command",
		"SSH Authorized Key with Forced Command",
		"An authorized_keys entry carries a forced command, which constrains access but must be audited for command injection.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1098.004", TechniqueName: "SSH Authorized Keys"}},
		[]string{"Audit the forced command for safety (no shell escapes).", "Restrict source IPs with from= where possible."},
		ConfidenceLow)

	m("Persistence_SSH_Insecure_Dir_Permissions",
		"SSH Directory Has Insecure Permissions",
		"An .ssh directory is group- or world-writable, allowing another local user to plant authorized keys.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1098.004", TechniqueName: "SSH Authorized Keys"}},
		[]string{"Fix permissions: chmod 0700 ~/.ssh; chown <user>:<group> ~/.ssh.", "Audit authorized_keys for planted entries."},
		ConfidenceMedium)

	m("Persistence_SSH_Insecure_Permissions",
		"SSH Key File Has Insecure Permissions",
		"An SSH key or authorized_keys file is group- or world-readable/writable, risking credential theft or planting.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1098.004", TechniqueName: "SSH Authorized Keys"}},
		[]string{"Fix permissions: chmod 0600 ~/.ssh/authorized_keys.", "Re-issue keys if exposure is suspected."},
		ConfidenceMedium)

	m("Persistence_SSH_Key_On_Nologin_Account",
		"SSH Key on Nologin / Locked Account",
		"An authorized key is installed for an account with nologin/false shell, bypassing the shell restriction via SSH.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1098.004", TechniqueName: "SSH Authorized Keys"}},
		[]string{"Remove unauthorized keys from nologin accounts.", "Verify whether the account should have shell access at all."},
		ConfidenceHigh)

	m("Persistence_SSH_Privileged_Key_No_Comment",
		"Privileged SSH Key Lacks Identifying Comment",
		"A root/service-account authorized key has no trailing comment, hindering auditability and incident response.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1098.004", TechniqueName: "SSH Authorized Keys"}},
		[]string{"Add identifying comments to all authorized keys.", "Inventory keys across hosts for centralized audit."},
		ConfidenceLow)

	m("Persistence_SSH_Recently_Modified",
		"SSH Authorized Keys Recently Modified",
		"A key file was modified very recently, suggesting possible key-planting activity in the current window.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1098.004", TechniqueName: "SSH Authorized Keys"}},
		[]string{"Correlate mtime with authentication and shell history.", "Diff against the last known-good authorized_keys snapshot."},
		ConfidenceMedium)

	m("Persistence_SSH_Symlink_Key",
		"SSH Key File Is a Symlink",
		"An SSH key or authorized_keys file is a symlink, which can redirect trust to an attacker-controlled key store.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1098.004", TechniqueName: "SSH Authorized Keys"}},
		[]string{"Resolve the symlink target and verify it is inside the user's .ssh directory.", "Replace symlink keys with regular files."},
		ConfidenceMedium)

	m("Persistence_Sudoers_No_Authenticate",
		"Sudoers Allows No-Authenticate Execution",
		"A sudoers rule allows execution without re-authentication (NOPASSWD or !authenticate), enabling passwordless privilege escalation.",
		[]MITREMapping{{Tactic: "Privilege Escalation", Technique: "T1548.003", TechniqueName: "Sudo and Sudo Caching"}},
		[]string{"Require authentication for sudo rules (remove NOPASSWD).", "Restrict allowed commands to the minimum set."},
		ConfidenceHigh)

	m("Persistence_Sudoers_NOPASSWD_ALL",
		"Sudoers Grants Passwordless ALL Commands",
		"A sudoers entry grants NOPASSWD for ALL commands, which is equivalent to passwordless root.",
		[]MITREMapping{{Tactic: "Privilege Escalation", Technique: "T1548.003", TechniqueName: "Sudo and Sudo Caching"}},
		[]string{"Remove NOPASSWD: ALL and scope allowed commands narrowly.", "Require re-authentication for privilege escalation."},
		ConfidenceHigh)

	m("Persistence_Sudoers_Temp_Path",
		"Sudoers References Temporary Path",
		"A sudoers rule allows execution of a binary in a temporary or world-writable directory as another user (often root).",
		[]MITREMapping{{Tactic: "Privilege Escalation", Technique: "T1548.003", TechniqueName: "Sudo and Sudo Caching"}},
		[]string{"Move allowed binaries to root-owned system paths.", "Remove temporary-path sudoers entries."},
		ConfidenceHigh)

	m("Persistence_InitD_Unowned_Script",
		"Unowned SysV Init Script",
		"A SysV init script under /etc/init.d is not owned by a distribution package and executes at boot as root.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1037", TechniqueName: "Boot or Logon Initialization Scripts"}},
		[]string{"Verify script provenance or remove it.", "Migrate to systemd units for auditable boot sequencing."},
		ConfidenceMedium)

	m("Persistence_System_Broken_Symlink",
		"System Persistence Symlink Is Broken",
		"A system-level persistence entry is a broken symlink (dangling target), indicating a removed package or incomplete tampering.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"}},
		[]string{"Remove broken symlinks or reinstall the owning package."},
		ConfidenceLow)

	m("Persistence_System_Suspicious_Symlink",
		"System Directory Contains Suspicious Symlink",
		"A file in a system directory is a symlink to an unexpected target, potentially redirecting service startup.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"}},
		[]string{"Resolve the symlink and verify the target path is trusted.", "Remove hijacking symlinks."},
		ConfidenceMedium)

	m("Persistence_System_Vendor_Symlink",
		"System Vendor Symlink",
		"A system persistence entry is a vendor-managed symlink. Informational; verify it points to the expected vendor unit.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"}},
		[]string{"No action required if the link resolves to the expected vendor location."},
		ConfidenceLow)

	m("Persistence_System_Exec_User_Hidden_Path",
		"System Service Executes Hidden Path in User Home",
		"A system-wide service unit executes a hidden file in a user home directory, bridging user write access to root execution.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1543.002", TechniqueName: "Systemd Service"}, {Tactic: "Privilege Escalation", Technique: "T1548", TechniqueName: "Abuse Elevation Control Mechanism"}},
		[]string{"Move service executables to root-owned system paths.", "Audit which user can write the hidden path."},
		ConfidenceHigh)

	m("Persistence_Udev_Exec_Temp",
		"Udev Rule Executes Binary from Temporary Path",
		"A udev rule executes a binary from /tmp or another volatile path when a device event fires — a hardware-triggered persistence primitive.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"}},
		[]string{"Move udev RUN targets to root-owned system paths.", "Re-audit udev rules under /etc/udev/rules.d and /lib/udev/rules.d."},
		ConfidenceHigh)

	m("Persistence_User_Symlink_Foreign_Owner",
		"User Autostart Symlink Owned by Another User",
		"A per-user autostart symlink is owned by a different UID, indicating cross-user persistence planting.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547.001", TechniqueName: "Registry Run Keys / Startup Folder"}},
		[]string{"Verify symlink ownership and remove cross-user planted entries.", "Harden autostart directory permissions."},
		ConfidenceHigh)

	m("Persistence_User_Symlink_Cross_Boundary",
		"User Symlink Crosses User Boundary",
		"A per-user persistence symlink points outside the owning user's home directory.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547.001", TechniqueName: "Registry Run Keys / Startup Folder"}},
		[]string{"Resolve the symlink target ownership and remove if unauthorized."},
		ConfidenceMedium)

	m("Persistence_Symlink_Escape",
		"Persistence Symlink Escapes Unit Directory",
		"A persistence unit symlink escapes its canonical directory via path traversal.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1543.002", TechniqueName: "Systemd Service"}},
		[]string{"Resolve and verify the symlink target is inside the expected directory tree.", "Remove escaping symlinks."},
		ConfidenceHigh)
}

func registerProcessRules() {
	m := func(name, title, why string, mitre []MITREMapping, remediation []string, c Confidence) {
		mustRegister(name, title, why, mitre, remediation, c)
	}

	m("Process_Hidden_PID",
		"Hidden Process (Rootkit Evasion Indicator)",
		"A process is accessible via direct /proc/<PID> stat but absent from the /proc directory listing, indicating procfs-level hiding typical of LKM rootkits.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1014", TechniqueName: "Rootkit"}, {Tactic: "Defense Evasion", Technique: "T1564.001", TechniqueName: "Hidden Files and Directories"}},
		[]string{"Dump the hidden process's /proc/<pid>/exe, cmdline, and maps via direct PID access.", "Compare /proc listing vs direct stat from trusted live media."},
		ConfidenceHigh)

	m("Process_Interactive_Reverse_Shell",
		"Interactive Reverse Shell Socket Redirection",
		"Process stdin/stdout is redirected to a network socket, establishing an interactive shell session with an external host.",
		[]MITREMapping{{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"}, {Tactic: "Command and Control", Technique: "T1071", TechniqueName: "Application Layer Protocol"}},
		[]string{"Terminate the rogue PID (kill -9 <PID>).", "Trace PPID and inspect open sockets; isolate host from network."},
		ConfidenceHigh)

	m("Process_Deleted_Binary",
		"Process Running Deleted Binary",
		"A running process's executable has been unlinked from disk (deleted), which can indicate in-memory execution after staging.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1070.004", TechniqueName: "File Deletion"}},
		[]string{"Inspect /proc/<pid>/exe and /proc/<pid>/fd to recover the image.", "Terminate the process and investigate the launch chain."},
		ConfidenceMedium)

	m("Process_Deleted_Binary_Package_Upgrade",
		"Process Running Deleted Binary After Package Upgrade",
		"A system process is executing an unlinked binary from a package directory; the package was upgraded while the daemon stayed running.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1070.004", TechniqueName: "File Deletion"}},
		[]string{"Restart the service (systemctl restart <service>) to load the on-disk binary."},
		ConfidenceLow)

	m("Process_Deleted_Binary_Replaced",
		"Process Running Replaced Binary Image",
		"The on-disk executable was replaced with a newer inode; the running process still executes the old deleted inode.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1070.004", TechniqueName: "File Deletion"}},
		[]string{"Restart the process to load the new on-disk binary."},
		ConfidenceLow)

	m("Process_Deleted_Binary_Suspicious_Location",
		"Deleted Binary Running from Temporary/Suspicious Path",
		"A running process executable was deleted from a temporary or volatile directory, typical of dropper execution that unlinks its on-disk binary.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1070.004", TechniqueName: "File Deletion"}, {Tactic: "Defense Evasion", Technique: "T1620", TechniqueName: "Reflective Code Loading"}},
		[]string{"Inspect memory maps and open descriptors to recover the executable.", "Terminate the process and inspect persistence hooks."},
		ConfidenceHigh)

	m("Process_Deleted_Binary_Home",
		"Deleted Binary Running from Home Directory",
		"A user process is executing a deleted binary from a home directory, which is unusual for legitimate software.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1070.004", TechniqueName: "File Deletion"}},
		[]string{"Identify the binary's origin and whether deletion was intentional.", "Terminate the process if unauthorized."},
		ConfidenceMedium)

	m("Process_Deleted_Binary_App_Managed",
		"Deleted Binary in App-Managed Process (Benign)",
		"A deleted binary belongs to an app-managed runtime (browser, Electron, container), typically benign after updates.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1070.004", TechniqueName: "File Deletion"}},
		[]string{"Restart the app-managed process or acknowledge as known update window."},
		ConfidenceLow)

	m("Process_Fileless_Memory_ELF",
		"Fileless In-Memory ELF Execution",
		"A process has an anonymous executable memory mapping containing an ELF header, indicating fileless code execution.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1620", TechniqueName: "Reflective Code Loading"}},
		[]string{"Dump the anonymous mapping via /proc/<pid>/mem or a memory forensics capture.", "Investigate the process's parent and launch vector."},
		ConfidenceHigh)

	m("Process_Fileless_Memory_Mapping",
		"Fileless Anonymous Memory Mapping",
		"A process has a suspicious anonymous executable mapping, potentially indicating staged shellcode.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1620", TechniqueName: "Reflective Code Loading"}},
		[]string{"Inspect the mapping's permissions and content where accessible.", "Correlate with network and persistence findings."},
		ConfidenceMedium)

	m("Process_Kernel_Thread_Masquerade",
		"Process Masquerading as Kernel Thread",
		"A user-space process uses bracketed naming (e.g. [kworker/...]) but has user-space memory mappings, masquerading as a kernel thread.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1036.004", TechniqueName: "Masquerade Task or Service"}},
		[]string{"Inspect /proc/<pid>/maps and exe for the deceptive process.", "Terminate the rogue process and identify its parent."},
		ConfidenceHigh)

	m("Process_System_Daemon_Masquerade",
		"Process Masquerading as System Daemon",
		"A process name matches a standard system daemon but its executable lives outside standard system paths.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1036.005", TechniqueName: "Match Legitimate Name or Location"}},
		[]string{"Inspect the executable location and hash.", "Terminate the process and restore original system binaries if compromised."},
		ConfidenceHigh)

	m("Process_Root_NonRoot_Owned_Exe",
		"Root Process Running Non-Root Owned Executable",
		"A UID-0 process executes a binary owned by a non-root user, presenting privilege escalation risk.",
		[]MITREMapping{{Tactic: "Privilege Escalation", Technique: "T1548", TechniqueName: "Abuse Elevation Control Mechanism"}},
		[]string{"Correct file ownership to root:root and verify package provenance.", "Ensure root services only execute trusted system paths."},
		ConfidenceHigh)

	m("Process_Root_User_Writable_Exe",
		"Root Process Running User-Writable Executable",
		"A UID-0 process executes a binary in a user-writable directory, allowing local privilege escalation via binary replacement.",
		[]MITREMapping{{Tactic: "Privilege Escalation", Technique: "T1548", TechniqueName: "Abuse Elevation Control Mechanism"}},
		[]string{"Harden the executable's directory permissions and ownership.", "Ensure root services only execute binaries in trusted paths."},
		ConfidenceHigh)

	m("Process_Root_World_Writable_Parent_Dir",
		"Root Process Executable in World-Writable Directory",
		"The parent directory of a root-executed binary is world-writable, permitting binary planting.",
		[]MITREMapping{{Tactic: "Privilege Escalation", Technique: "T1548", TechniqueName: "Abuse Elevation Control Mechanism"}},
		[]string{"Fix parent directory permissions (root:root 0755).", "Audit for planted binaries."},
		ConfidenceHigh)

	m("Process_Exe_Or_Cwd_In_Temp",
		"Process Executing from Temporary Directory",
		"A process's executable or working directory is in /tmp, /var/tmp, or /dev/shm.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1070.004", TechniqueName: "File Deletion"}},
		[]string{"Inspect the running process and its executable path.", "Ensure legitimate services execute from standard system directories."},
		ConfidenceMedium)
}

func registerNetworkRules() {
	m := func(name, title, why string, mitre []MITREMapping, remediation []string, c Confidence) {
		mustRegister(name, title, why, mitre, remediation, c)
	}

	m("Network_Wildcard_Listener_Unrecognized_Process",
		"Unmapped Wildcard Network Listener",
		"A process outside the standard daemon allowlist is listening on all interfaces (0.0.0.0 or ::), exposing an accessible network service.",
		[]MITREMapping{{Tactic: "Command and Control", Technique: "T1571", TechniqueName: "Non-Standard Port"}, {Tactic: "Execution", Technique: "T1059", TechniqueName: "Command and Scripting Interpreter"}},
		[]string{"Verify whether the listening process is an authorized service.", "Bind the service to localhost if remote access is not required.", "Add known services to the listener allowlist."},
		ConfidenceMedium)

	m("Network_Suspicious_Raw_Packet_Socket",
		"Suspicious Raw/Packet Network Socket",
		"A non-allowlisted process opened a RAW or PACKET socket, which may indicate packet sniffing or injection.",
		[]MITREMapping{{Tactic: "Credential Access", Technique: "T1040", TechniqueName: "Network Sniffing"}},
		[]string{"Inspect the process binary and command line.", "Terminate unauthorized packet-capturing processes.", "Audit CAP_NET_RAW grants."},
		ConfidenceMedium)

	m("Network_Loopback_Listener",
		"Local Loopback Network Listener",
		"Local system services are listening on loopback (127.0.0.1 or ::1) for inter-process communication.",
		[]MITREMapping{{Tactic: "Discovery", Technique: "T1046", TechniqueName: "Network Service Discovery"}},
		[]string{"No remediation required for benign local services."},
		ConfidenceLow)

	m("Network_IOC_IP_Connection_Legacy",
		"Connection to Known Malicious IP (Legacy Alias)",
		"Legacy alias for Network_IOC_IP_Connection. See the canonical rule for remediation.",
		[]MITREMapping{{Tactic: "Command and Control", Technique: "T1071", TechniqueName: "Application Layer Protocol"}},
		[]string{"Identify and terminate the process holding the malicious connection.", "Block the destination IP."},
		ConfidenceHigh)
}

func registerKernelRules() {
	m := func(name, title, why string, mitre []MITREMapping, remediation []string, c Confidence) {
		mustRegister(name, title, why, mitre, remediation, c)
	}

	m("Kernel_Hidden_LKM_Module_Legacy",
		"Kernel Rootkit / Hidden LKM Module (Legacy Alias)",
		"Legacy alias for Kernel_Hidden_LKM_Module.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1014", TechniqueName: "Rootkit"}},
		[]string{"Inspect loaded kernel modules and audit /lib/modules."},
		ConfidenceHigh)

	m("Kernel_Modprobe_Install_Command_Legacy",
		"Modprobe Install Command (Legacy Alias)",
		"Legacy alias for Kernel_Modprobe_Install_Command.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547.006", TechniqueName: "Kernel Modules and Extensions"}},
		[]string{"Inspect modprobe configuration under /etc/modprobe.d and /lib/modprobe.d."},
		ConfidenceMedium)

	m("Kernel_Taint_Active_Legacy",
		"Kernel Taint Flags Active (Legacy Alias)",
		"Legacy alias for Kernel_Taint_Active.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1547.006", TechniqueName: "Kernel Modules and Extensions"}},
		[]string{"Identify which loaded modules caused the taint."},
		ConfidenceLow)
}

func registerUsersRules() {
	m := func(name, title, why string, mitre []MITREMapping, remediation []string, c Confidence) {
		mustRegister(name, title, why, mitre, remediation, c)
	}

	m("Users_Duplicate_UID",
		"Duplicate UID Across /etc/passwd Entries",
		"Two distinct usernames share the same UID, which can conceal privileged access under an alternate login name.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1136.001", TechniqueName: "Local Account"}},
		[]string{"Audit /etc/passwd for duplicate UID assignments.", "Remove or reassign the duplicate account."},
		ConfidenceMedium)

	m("Users_Shadow_Empty_Password",
		"Account with Empty Password in /etc/shadow",
		"An account has an empty password hash, allowing passwordless authentication.",
		[]MITREMapping{{Tactic: "Credential Access", Technique: "T1110", TechniqueName: "Brute Force"}},
		[]string{"Lock the account (passwd -l <user>) or set a strong password.", "Review auth logs for passwordless logins."},
		ConfidenceHigh)

	m("Users_Shadow_Legacy_Hash_Format",
		"Legacy / Obsolete Password Hash Format in /etc/shadow",
		"A password hash uses an obsolete format (DES or MD5 $1$), which is trivially crackable.",
		[]MITREMapping{{Tactic: "Credential Access", Technique: "T1003.008", TechniqueName: "OS Credential Dumping"}},
		[]string{"Re-hash passwords with yescrypt or sha512crypt.", "Force password rotation for affected accounts."},
		ConfidenceMedium)

	m("Users_Shadow_Insecure_Permissions",
		"Insecure Permissions on /etc/shadow",
		"/etc/shadow is readable or writable by non-root users, exposing password hashes.",
		[]MITREMapping{{Tactic: "Credential Access", Technique: "T1003.008", TechniqueName: "OS Credential Dumping"}},
		[]string{"Fix permissions: chown root:shadow /etc/shadow; chmod 0640 /etc/shadow."},
		ConfidenceHigh)

	m("Users_Shadow_World_Writable",
		"/etc/shadow Is World-Writable",
		"/etc/shadow is world-writable, permitting arbitrary credential modification.",
		[]MITREMapping{{Tactic: "Credential Access", Technique: "T1003.008", TechniqueName: "OS Credential Dumping"}, {Tactic: "Persistence", Technique: "T1136.001", TechniqueName: "Local Account"}},
		[]string{"Immediately fix permissions and audit /etc/shadow for tampering."},
		ConfidenceHigh)

	m("Users_Passwd_World_Writable",
		"/etc/passwd Is World-Writable",
		"/etc/passwd is world-writable, permitting arbitrary account creation.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1136.001", TechniqueName: "Local Account"}},
		[]string{"Fix permissions: chown root:root /etc/passwd; chmod 0644 /etc/passwd.", "Audit /etc/passwd for unauthorized entries."},
		ConfidenceHigh)

	m("Users_Passwd_Group_Writable",
		"/etc/passwd Is Group-Writable",
		"/etc/passwd is group-writable, allowing members of the owning group to modify accounts.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1136.001", TechniqueName: "Local Account"}},
		[]string{"Fix permissions: chmod 0644 /etc/passwd.", "Audit group membership for the owning group."},
		ConfidenceMedium)

	m("Users_System_Account_Interactive_Shell",
		"System Account Has Interactive Login Shell",
		"A system account (UID < 1000, excluding root) has an interactive shell, expanding the set of logon-capable accounts.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1136.001", TechniqueName: "Local Account"}},
		[]string{"Set the shell to /usr/sbin/nologin or /bin/false for system accounts that do not require login."},
		ConfidenceLow)

	m("Users_Privileged_Group_Membership",
		"Privileged Group Membership (sudo/wheel/docker)",
		"A user is a member of a privileged group granting elevated capabilities (sudo, wheel, docker, lxd).",
		[]MITREMapping{{Tactic: "Privilege Escalation", Technique: "T1548.003", TechniqueName: "Sudo and Sudo Caching"}},
		[]string{"Verify group membership is intended; remove unnecessary members.", "Audit sudoers for what the group is permitted."},
		ConfidenceLow)

	m("Users_Container_Group_Membership",
		"Container Runtime Group Membership (docker/lxd)",
		"Membership in docker/lxd groups grants effective root via container breakout primitives.",
		[]MITREMapping{{Tactic: "Privilege Escalation", Technique: "T1611", TechniqueName: "Escape to Host"}},
		[]string{"Remove unnecessary docker/lxd group members.", "Require root or policy-gated access for container runtimes."},
		ConfidenceMedium)
}

func registerScannerRules() {
	m := func(name, title, why string, mitre []MITREMapping, remediation []string, c Confidence) {
		mustRegister(name, title, why, mitre, remediation, c)
	}

	m("Heuristic_Suspicious_SUID_SGID_Legacy",
		"Elevated SUID/SGID Binary (Legacy Alias)",
		"Legacy alias for Heuristic_Suspicious_SUID_SGID.",
		[]MITREMapping{{Tactic: "Privilege Escalation", Technique: "T1548.001", TechniqueName: "Setuid and Setgid"}},
		[]string{"Confirm package ownership; remove the SUID bit if unnecessary."},
		ConfidenceMedium)

	m("Heuristic_Hidden_Executable_In_System_Dir",
		"Hidden Executable in System Directory",
		"A hidden (dotfile) executable was found in a system directory such as /bin, /sbin, or /usr/bin.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1564.001", TechniqueName: "Hidden Files and Directories"}},
		[]string{"Verify package ownership and remove unauthorized hidden executables.", "Check for companion persistence hooks."},
		ConfidenceMedium)

	m("Heuristic_World_Writable_In_Etc",
		"World-Writable File in /etc",
		"A file under /etc is world-writable, allowing any local user to modify system configuration.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"}},
		[]string{"Fix permissions (root:root 0644).", "Audit the file for tampering."},
		ConfidenceMedium)

	m("Heuristic_ELF_In_Temp",
		"ELF Binary in Temporary Directory",
		"An ELF executable was found in /tmp, /var/tmp, or /dev/shm outside the package database.",
		[]MITREMapping{{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"}},
		[]string{"Identify how the binary was staged in the temporary directory.", "Quarantine it and check for dropper persistence."},
		ConfidenceMedium)

	m("Heuristic_ELF_In_Dev",
		"ELF Binary in /dev (Suspicious Location)",
		"An ELF executable was found directly under /dev, which should not contain regular executable files.",
		[]MITREMapping{{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"}},
		[]string{"Quarantine the binary and check for persistence hooks.", "Verify /dev is mounted correctly and not used for staging."},
		ConfidenceHigh)

	m("Heuristic_ELF_In_Temp_Escalated",
		"ELF Binary in Temporary Directory (Escalated)",
		"An ELF binary in a temporary directory is corroborated by an additional signal (IOC match or suspicious packaging).",
		[]MITREMapping{{Tactic: "Execution", Technique: "T1204.002", TechniqueName: "Malicious File"}},
		[]string{"Treat as confirmed payload staging; quarantine and hunt for persistence."},
		ConfidenceHigh)

	m("Heuristic_ELF_In_Temp_NonExec",
		"ELF Binary in Temporary Directory (Non-Executable)",
		"An ELF file in a temporary directory lacks execute permission, consistent with staged-but-not-yet-executed payloads.",
		[]MITREMapping{{Tactic: "Execution", Technique: "T1204.002", TechniqueName: "Malicious File"}},
		[]string{"Determine whether the file is a staged payload awaiting execution.", "Remove it if unauthorized."},
		ConfidenceLow)

	m("Heuristic_ELF_In_Temp_BuildTree",
		"ELF Build Artifact in Temporary Directory",
		"An ELF file in a temporary directory appears to be a compiler/build artifact rather than a staged payload.",
		[]MITREMapping{{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"}},
		[]string{"Verify the build tree provenance; acknowledge if this is a legitimate build output."},
		ConfidenceLow)

	m("File_ELF_In_Temp_Or_Dev",
		"ELF Binary in Temp or /dev (Generic)",
		"Generic alias for ELF-in-temp/dev heuristics when the specific sub-variant is not distinguished.",
		[]MITREMapping{{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"}},
		[]string{"Identify how the ELF binary was staged.", "Check for companion persistence."},
		ConfidenceMedium)

	m("Benign_Suppressed_File",
		"Benign File Suppressed (Informational)",
		"A file matched a heuristic but was suppressed because its path is on the known-benign allowlist.",
		nil,
		[]string{"No action required. Use --verbose to list suppressed files."},
		ConfidenceLow)

	m("YARA_Rule_File",
		"YARA Rule File Detected (Informational)",
		"The file looks like a YARA rule file and was identified to avoid self-detection on rule signature strings.",
		nil,
		[]string{"No action required. YARA rule files are excluded from content matching."},
		ConfidenceLow)

	m("YARA_Skipped_Oversize",
		"YARA Scan Skipped: Oversize File (Informational)",
		"The file exceeds the YARA max file size and was not content-scanned.",
		nil,
		[]string{"Increase --yara-max-filesize if deep content inspection of large files is required."},
		ConfidenceLow)

	// Canonical YARA rule names shipped in embedded_rules.go
	m("Linux_Webshell_PHP_Generic_Backdoor",
		"PHP Web Shell — Generic Backdoor (YARA)",
		"YARA rule matched obfuscated PHP code execution backdoor patterns.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1505.003", TechniqueName: "Web Shell"}},
		[]string{"Quarantine the PHP file and review web server access logs around its mtime."},
		ConfidenceHigh)

	m("Linux_Webshell_PHP_Known_Families",
		"PHP Web Shell — Known Families (c99/r57/WSO/b374k) (YARA)",
		"YARA rule matched strings from known PHP webshell families.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1505.003", TechniqueName: "Web Shell"}},
		[]string{"Quarantine the PHP file and audit the web server for compromise."},
		ConfidenceHigh)

	m("Linux_Webshell_JSP_Runtime_Exec",
		"JSP Web Shell — Runtime Exec (YARA)",
		"YARA rule matched JSP runtime execution patterns typical of Java web shells.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1505.003", TechniqueName: "Web Shell"}},
		[]string{"Quarantine the JSP file and review application server logs."},
		ConfidenceHigh)

	m("Linux_Implant_RedTeam_Persistence_Framework",
		"Red-Team Persistence Framework Implant (YARA)",
		"YARA rule matched an automated red-team persistence framework (stealth procfs mounting and backdoor installers).",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1547.001", TechniqueName: "Boot or Logon Autostart Execution"}},
		[]string{"Isolate the host and inspect /proc mounts, systemd units, and cron for implants."},
		ConfidenceHigh)

	m("Linux_Rootkit_LDPRELOAD_Hook_Artifact",
		"Userland Rootkit LD_PRELOAD Hook Artifact (YARA)",
		"YARA rule matched userland rootkit artifacts hooking libc via dynamic linker interposition.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1014", TechniqueName: "Rootkit"}},
		[]string{"Inspect /etc/ld.so.preload and audit preloaded libraries.", "Reboot from trusted media for forensics."},
		ConfidenceHigh)

	m("Linux_Rootkit_Diamorphine_Reptile_Strings",
		"Kernel Rootkit Strings (Diamorphine/Reptile) (YARA)",
		"YARA rule matched known kernel rootkit control strings.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1014", TechniqueName: "Rootkit"}},
		[]string{"Audit loaded kernel modules and inspect /lib/modules for malicious .ko files.", "Reboot into trusted live media."},
		ConfidenceHigh)

	m("Linux_Malware_Cryptominer_Stratum_Pool",
		"Cryptominer Stratum Pool Configuration (YARA)",
		"YARA rule matched cryptocurrency mining pool endpoints or miner configuration.",
		[]MITREMapping{{Tactic: "Impact", Technique: "T1496", TechniqueName: "Resource Hijacking"}},
		[]string{"Terminate the miner process and remove its persistence.", "Block mining pool domains at the perimeter."},
		ConfidenceHigh)

	m("Linux_Dropper_Remote_Pipe_Shell_Execution",
		"Remote Pipe-to-Shell Dropper (YARA)",
		"YARA rule matched a dropper that fetches remote code and pipes it to a shell.",
		[]MITREMapping{{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"}, {Tactic: "Command and Control", Technique: "T1105", TechniqueName: "Ingress Tool Transfer"}},
		[]string{"Verify whether the remote URL is a trusted installer.", "Inspect the URL content offline before executing."},
		ConfidenceHigh)

	m("Linux_Ransomware_Python_Locker",
		"Python Ransomware Locker (YARA)",
		"YARA rule matched a Python ransomware locker encrypting files and generating ransom notes.",
		[]MITREMapping{{Tactic: "Impact", Technique: "T1486", TechniqueName: "Data Encrypted for Impact"}},
		[]string{"Quarantine the script and verify whether files were encrypted.", "Check for recovery keys in temporary locations."},
		ConfidenceHigh)

	m("Linux_Malware_Data_Exfiltration_Client",
		"Data Exfiltration Client (YARA)",
		"YARA rule matched a data exfiltration client crawling and exfiltrating files over the network.",
		[]MITREMapping{{Tactic: "Exfiltration", Technique: "T1041", TechniqueName: "Exfiltration Over C2 Channel"}},
		[]string{"Inspect firewall logs for the exfiltration destination and quarantine the client script."},
		ConfidenceHigh)

	m("Linux_Malware_Data_Exfiltration_Server",
		"Data Exfiltration Collection Server (YARA)",
		"YARA rule matched a C2 listener reconstructing exfiltrated directory trees.",
		[]MITREMapping{{Tactic: "Command and Control", Technique: "T1071.001", TechniqueName: "Web Protocols"}},
		[]string{"Terminate the listener and block its port; inspect dumped data for compromised clients."},
		ConfidenceHigh)

	m("Linux_Backdoor_Reverse_Shell_OneLiner",
		"Reverse Shell One-Liner Backdoor (YARA)",
		"YARA rule matched a reverse shell one-liner backdoor.",
		[]MITREMapping{{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"}},
		[]string{"Quarantine the script and inspect network connections for the C2 endpoint."},
		ConfidenceHigh)

	m("Linux_Backdoor_Encrypted_Reverse_Shell",
		"Encrypted Reverse Shell Backdoor (YARA)",
		"YARA rule matched an encrypted (TLS-wrapped) reverse shell backdoor.",
		[]MITREMapping{{Tactic: "Command and Control", Technique: "T1573.002", TechniqueName: "Asymmetric Cryptography"}},
		[]string{"Inspect TLS egress logs for the destination host and block the endpoint."},
		ConfidenceHigh)

	m("Linux_Script_PowerShell_Encoded_Execution",
		"Encoded PowerShell Command Execution (YARA)",
		"YARA rule matched PowerShell Core invocation with Base64 encoded payload flags (-EncodedCommand).",
		[]MITREMapping{{Tactic: "Execution", Technique: "T1059.001", TechniqueName: "PowerShell"}, {Tactic: "Defense Evasion", Technique: "T1027", TechniqueName: "Obfuscated Files or Information"}},
		[]string{"Decode the Base64 command payload using `echo <base64> | base64 -d | iconv -f utf-16le`.", "Identify child processes and network connections spawned by PowerShell.", "Quarantine the invoking script."},
		ConfidenceHigh)

	m("Linux_Script_Cloud_Exfiltration_Tool",
		"Automated Cloud Storage Exfiltration Tool (YARA)",
		"YARA rule matched automated cloud storage synchronization/upload commands targeting sensitive local directories or archives.",
		[]MITREMapping{{Tactic: "Exfiltration", Technique: "T1567.002", TechniqueName: "Exfiltration to Cloud Storage"}, {Tactic: "Collection", Technique: "T1005", TechniqueName: "Data from Local System"}},
		[]string{"Review the destination cloud storage credentials and remote endpoints in the script.", "Check egress firewall logs for high-volume uploads to cloud providers.", "Revoke compromised cloud access tokens."},
		ConfidenceMedium)

	m("Linux_Persistence_Linker_Audit_Hijack",
		"Dynamic Linker Hook Hijack (LD_PRELOAD / LD_AUDIT) (YARA)",
		"YARA rule matched a dynamic linker hook value referencing a volatile or non-standard library directory, a relative path, or ld.so preload/audit configuration.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"}, {Tactic: "Defense Evasion", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"}},
		[]string{"Inspect /etc/ld.so.preload, /etc/ld.so.audit, and environment configurations for rogue library paths.", "Verify integrity and package ownership of preloaded or audit libraries.", "Remove unauthorized LD_PRELOAD / LD_AUDIT entries."},
		ConfidenceHigh)

	m("Linux_Persistence_PAM_Exec_Suspicious",
		"Suspicious PAM Authentication Hook (pam_exec) (YARA)",
		"YARA rule matched PAM configuration directing authentication hooks to volatile or unprivileged paths.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1556.004", TechniqueName: "Pluggable Authentication Modules"}, {Tactic: "Credential Access", Technique: "T1556", TechniqueName: "Modify Authentication Process"}},
		[]string{"Inspect the referenced script in PAM configuration for unauthorized commands.", "Verify package ownership of the PAM directive.", "Quarantine rogue scripts and remove the pam_exec directive."},
		ConfidenceHigh)

	// Phase 5: Linux System Visibility Expansion
	m("Process_Environ_LDPreload",
		"Process Environment Injected with LD_PRELOAD Hook",
		"The process was launched with an LD_PRELOAD value adjudicated as anomalous (volatile directory, non-absolute path, missing library, or a library outside the standard linker directories) — the classic userland rootkit preload pattern used to intercept libc calls in every child process.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"}},
		[]string{"Inspect the preloaded library file path and verify package ownership.", "Terminate the injected process and investigate the parent process that spawned it.", "Audit /etc/ld.so.preload and shell startup files."},
		ConfidenceHigh)

	m("Process_Environ_AntiForensic",
		"Anti-Forensic History Tampering in Process Environment",
		"The process was launched with HISTFILE=/dev/null or HISTSIZE=0 to prevent shell activity from being recorded to disk.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1070.003", TechniqueName: "Clear Command History"}},
		[]string{"Review the active session and process tree.", "Inspect auditd and syslog logs for commands executed by the user.", "Verify user authentication history in /var/log/auth.log."},
		ConfidenceHigh)

	m("Process_Environ_C2_Artifact",
		"Command & Control Framework Token in Process Environment",
		"The process runtime environment contains indicators of known offensive C2 frameworks or anonymous proxy configurations.",
		[]MITREMapping{{Tactic: "Command and Control", Technique: "T1071.001", TechniqueName: "Web Protocols"}},
		[]string{"Identify the process binary and established network sockets.", "Isolate the host from the network and dump memory if required for forensics.", "Terminate the process and trace how it was executed."},
		ConfidenceHigh)

	m("Kernel_eBPF_Persistent_Probe",
		"Suspicious or Unmapped eBPF / Kernel Trace Hook",
		"A kernel tracing kprobe, uprobe, or pinned eBPF program is active that does not map to standard system observability tools.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1014", TechniqueName: "Rootkit"}, {Tactic: "Persistence", Technique: "T1547.001", TechniqueName: "Boot or Logon Autostart Execution"}},
		[]string{"Inspect /sys/kernel/debug/tracing/kprobe_events and /sys/fs/bpf.", "Audit bpftool or tracefs for rogue kernel hooks.", "Reboot the host from trusted media if stealth kernel rootkit behavior is suspected."},
		ConfidenceHigh)

	m("Persistence_Systemd_Unowned_Socket",
		"Unowned Systemd Socket Unit",
		"A systemd .socket unit is installed on the system that is not owned by any registered operating system package.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1543.002", TechniqueName: "Systemd Service"}},
		[]string{"Review the .socket definition and the target service it activates.", "Verify if the socket was created by local administrator or malicious software."},
		ConfidenceMedium)

	m("Persistence_Systemd_Socket_Activation",
		"Suspicious Systemd Socket-Activation Backdoor",
		"A systemd .socket unit listens on network ports or FIFOs and activates a shell, temporary directory binary, or unowned service.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1543.002", TechniqueName: "Systemd Service"}, {Tactic: "Command and Control", Technique: "T1095", TechniqueName: "Non-Application Layer Protocol"}},
		[]string{"Disable and stop the socket unit immediately (`systemctl disable --now <socket>`).", "Inspect the activated service and executables.", "Block unauthorized inbound traffic to the listening port."},
		ConfidenceHigh)

	m("Trojaned_Package_Binary_Modified",
		"Package Binary Integrity Compromised (Checksum Mismatch)",
		"A system executable in a standard system directory has a cryptographic checksum that does not match the package manager's signed/recorded database, indicating binary tampering or trojanization.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1036.005", TechniqueName: "Match Legitimate Name"}, {Tactic: "Persistence", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"}},
		[]string{"Immediately quarantine the compromised binary.", "Reinstall the package using trusted repositories (`apt-get install --reinstall <package>`).", "Initiate incident response to investigate how root-level filesystem modification occurred."},
		ConfidenceHigh)

	m("Persistence_ELF_RPATH_Hijack",
		"ELF Library Search Path Hijack (DT_RPATH / DT_RUNPATH)",
		"The inspected ELF binary embeds an RPATH or RUNPATH entry that references a volatile execution directory (/tmp, /var/tmp, /dev/shm, /run/user), a world-writable directory, or a relative search root. The dynamic linker resolves dependencies from these entries before any trust check runs, so a hostile binary or library planted there is executed inside every process the ELF starts.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"}, {Tactic: "Defense Evasion", Technique: "T1574.007", TechniqueName: "PATH Environment Variable Hijacking"}},
		[]string{"Relocate the binary, or rebuild it without embedding dangerous search paths (`patchelf --remove-rpath <binary>`, or `-Wl,--enable-new-dtags` hygiene at build time).", "Check for planted or attacker-updated shared objects inside every referenced directory, and remove-or-restore entries that are not package-owned.", "Compute the binary's SHA256, compare it against vendor or package signatures, and quarantine any binary whose search paths cannot be explained by a legitimate build or packaging tool."},
		ConfidenceHigh)

	m("Container_Socket_World_Writable",
		"Container Runtime Socket is World-Writable",
		"A container runtime control socket (Docker, Containerd, or Podman) has world-writable permissions (0666 or other-write), allowing unprivileged local users to control the container daemon and obtain root-equivalent host access.",
		[]MITREMapping{{Tactic: "Privilege Escalation", Technique: "T1611", TechniqueName: "Escape to Host"}, {Tactic: "Execution", Technique: "T1059", TechniqueName: "Command and Scripting Interpreter"}},
		[]string{"Restrict socket permissions immediately (`chmod 0660 <socket>`).", "Ensure socket is owned by root and the authorized container group (e.g. docker).", "Audit auditd logs for unauthorized commands sent to the daemon."},
		ConfidenceHigh)

	m("Container_Escape_Mounted_Docker_Socket",
		"Mounted Docker/Containerd Socket Inside Container (Escape Path)",
		"A container daemon socket (e.g., docker.sock or containerd.sock) is mounted inside a running container, providing containerized processes direct root-level execution privileges on the underlying host system.",
		[]MITREMapping{{Tactic: "Privilege Escalation", Technique: "T1611", TechniqueName: "Escape to Host"}, {Tactic: "Execution", Technique: "T1610", TechniqueName: "Deploy Container"}},
		[]string{"Remove Docker/Containerd socket mounts from container run configurations.", "Use Docker-in-Docker (dind) rootless mode or sysbox if container orchestration is required.", "Audit processes launched on the host during the container execution timeframe."},
		ConfidenceHigh)

	m("Process_Environ_LDAudit",
		"Process Environment Injected with LD_AUDIT Hook",
		"The process was launched with an active LD_AUDIT environment variable pointing to a dynamic library, used to hook dynamic linker symbol resolutions and execute code stealthily before main().",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"}},
		[]string{"Inspect the audited library file path.", "Terminate the infected process and investigate the parent process that spawned it.", "Audit dynamic linker configuration."},
		ConfidenceHigh)

	m("Process_Environ_Suspicious_LibPath",
		"Process Environment Injected with Suspicious LD_LIBRARY_PATH",
		"The process was launched with LD_LIBRARY_PATH pointing to temporary, shared memory, or non-standard writable locations, allowing malicious shared objects to shadow legitimate system libraries.",
		[]MITREMapping{{Tactic: "Defense Evasion", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"}},
		[]string{"Inspect the directories referenced in LD_LIBRARY_PATH.", "Verify whether malicious libraries exist in those directories.", "Review the parent process and service unit."},
		ConfidenceHigh)

	m("Persistence_Systemd_Generator_Unowned",
		"Unowned Systemd Early-Boot Generator Executable",
		"An executable or script exists in systemd-generators directories that is not owned by any registered operating system package. Systemd executes all generator binaries early during boot and daemon-reload before service startup.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1543.002", TechniqueName: "Systemd Service"}},
		[]string{"Inspect the generator script or binary.", "Verify whether the generator dynamically synthesizes malicious service units.", "Remove the unowned generator file and run systemctl daemon-reload."},
		ConfidenceMedium)

	m("Persistence_Systemd_Generator_Suspicious_Target",
		"Systemd Early-Boot Generator Symlink Points to Suspicious Location",
		"A systemd generator symlink points to a volatile, temporary, or user-controlled directory (/tmp, /dev/shm, /var/tmp), allowing unprivileged code to execute as root during boot.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1543.002", TechniqueName: "Systemd Service"}, {Tactic: "Defense Evasion", Technique: "T1574.006", TechniqueName: "Dynamic Linker Hijacking"}},
		[]string{"Quarantine and remove the generator symlink immediately.", "Inspect volatile directories for malicious payload binaries.", "Reboot or daemon-reload after cleaning."},
		ConfidenceHigh)

	m("Persistence_Binfmt_Unowned_Registration",
		"Unowned Binary Format (binfmt_misc) Registration",
		"A custom binary format registration in /etc/binfmt.d is not owned by any OS package, allowing custom binary interpreters to intercept execution.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1546", TechniqueName: "Event Triggered Execution"}},
		[]string{"Inspect the binfmt registration file and the interpreter it designates.", "Ensure the registration was created by a known software package (such as wine or qemu)."},
		ConfidenceMedium)

	m("Persistence_Binfmt_Suspicious_Interpreter",
		"Binary Format Handler Points to Suspicious or User Directory",
		"A binfmt_misc handler configuration designates an interpreter located in a volatile, temporary, or user-writable directory (/tmp, /dev/shm, /home), enabling arbitrary code execution on binary launch.",
		[]MITREMapping{{Tactic: "Persistence", Technique: "T1546", TechniqueName: "Event Triggered Execution"}, {Tactic: "Privilege Escalation", Technique: "T1548", TechniqueName: "Abuse Elevation Control Mechanism"}},
		[]string{"Remove the binfmt configuration immediately (`systemctl restart systemd-binfmt`).", "Quarantine the rogue interpreter executable."},
		ConfidenceHigh)
}
