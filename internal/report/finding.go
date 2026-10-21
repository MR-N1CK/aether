package report

import (
	"strings"
	"time"
)

// Severity represents the alert level of a threat hunting finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityAlert    Severity = "ALERT"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityWarning  Severity = "WARNING"
	SeverityLow      Severity = "LOW"
	SeverityNotice   Severity = "NOTICE"
	SeverityInfo     Severity = "INFO"
)

func (s Severity) String() string {
	return string(s)
}

// Confidence represents the detection confidence of a finding.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

func (c Confidence) String() string {
	return string(c)
}

// Verdict represents the final analytical classification of a finding.
type Verdict string

const (
	// VerdictMalicious indicates confirmed, evidence-backed threat with high confidence.
	VerdictMalicious Verdict = "MALICIOUS"
	// VerdictSuspicious indicates an anomaly or suspicious pattern requiring analyst review.
	VerdictSuspicious Verdict = "SUSPICIOUS"
	// VerdictSafe indicates an inspected artifact verified clean or context-suppressed.
	VerdictSafe Verdict = "SAFE"
	// VerdictUnknown indicates insufficient visibility or inspection truncated due to permissions (EACCES).
	VerdictUnknown Verdict = "UNKNOWN"
)

func (v Verdict) String() string {
	return string(v)
}

// EvidenceStrength categorizes the intrinsic evidential weight of an observation.
type EvidenceStrength string

const (
	// StrengthDirect represents an unambiguous signature or cryptographic IOC.
	StrengthDirect EvidenceStrength = "DIRECT"
	// StrengthCorroborated represents a suspicious pattern confirmed by an independent operational signal.
	StrengthCorroborated EvidenceStrength = "CORROBORATED"
	// StrengthContextual represents a weak or dual-use anomaly.
	StrengthContextual EvidenceStrength = "CONTEXTUAL"
	// StrengthIncomplete represents a blocked observation due to permissions.
	StrengthIncomplete EvidenceStrength = "INCOMPLETE"
)

func (s EvidenceStrength) String() string {
	return string(s)
}

// CorroboratingDomain represents the operational domain of a corroborating signal.
type CorroboratingDomain string

const (
	DomainFilesystem  CorroboratingDomain = "filesystem"
	DomainProcess     CorroboratingDomain = "process"
	DomainNetwork     CorroboratingDomain = "network"
	DomainPersistence CorroboratingDomain = "persistence"
	DomainIOC         CorroboratingDomain = "ioc"
)

// CorroboratingSignal represents an independent operational confirmation linked to a primary finding.
type CorroboratingSignal struct {
	Domain      CorroboratingDomain `json:"domain"`
	RuleName    string              `json:"rule_name"`
	Description string              `json:"description,omitempty"`
	TargetRef   string              `json:"target_ref"` // e.g. "PID: 1337", "Socket: 0.0.0.0:4444", "Cron: /etc/cron.d/bot"
	Confidence  string              `json:"confidence,omitempty"`
	Timestamp   time.Time           `json:"timestamp,omitempty"`
}

// EvidenceRecord encapsulates structured forensic evidence for transparent provenance.
type EvidenceRecord struct {
	DetectorType          string                `json:"detector_type"`                    // "heuristic" | "yara" | "ioc" | "module"
	RuleName              string                `json:"rule_name"`                        // Exact rule identifier
	EvidenceStrength      EvidenceStrength      `json:"evidence_strength,omitempty"`      // "DIRECT" | "CORROBORATED" | "CONTEXTUAL" | "INCOMPLETE"
	MatchedCondition      string                `json:"matched_condition,omitempty"`      // Human-readable summary of matched condition
	LineContent           string                `json:"line_content,omitempty"`           // Matched snippet (if text)
	LineNumber            int                   `json:"line_number,omitempty"`            // File line number (if applicable)
	TargetPath            string                `json:"target_path"`                      // Virtual path inspected
	PID                   int                   `json:"pid,omitempty"`                    // Process ID (if runtime)
	Comm                  string                `json:"comm,omitempty"`                   // Process comm
	Cmdline               string                `json:"cmdline,omitempty"`                // Process command line
	SocketInfo            string                `json:"socket_info,omitempty"`            // Network socket info (e.g. "0.0.0.0:4444")
	MountNamespace        string                `json:"mount_namespace,omitempty"`        // Mount namespace identifier
	SHA256                string                `json:"sha256,omitempty"`                 // Cryptographic SHA-256 hash
	FileMode              uint32                `json:"file_mode,omitempty"`              // POSIX file permissions
	OwnerUID              uint32                `json:"owner_uid,omitempty"`              // File owner UID
	PackageName           string                `json:"package_name,omitempty"`           // Owning OS package (if any)
	PackageStatus         string                `json:"package_status"`                   // "unowned" | "verified_package" | "modified_package" | "unknown"
	ContextProfile        string                `json:"context_profile"`                  // "standard" | "doc_metadata" | "package_test" | "build_tree" | "container_namespace"
	CorroboratingSignals  []string              `json:"corroborating_signals,omitempty"`  // Independent physical signals
	CorroborationDetails  []CorroboratingSignal `json:"corroboration_details,omitempty"`  // Structured corroboration signals
	ContributingDetectors []string              `json:"contributing_detectors,omitempty"` // Multiple rules flagging same target
	ConfidenceRationale   string                `json:"confidence_rationale"`             // Plain-English justification
}

// MITREMapping associates a finding with an enterprise MITRE ATT&CK technique.
type MITREMapping struct {
	Tactic        string `json:"tactic"`
	Technique     string `json:"technique"`
	TechniqueName string `json:"technique_name,omitempty"`
}

// RuleSummary provides an aggregated count and severity for a specific rule.
type RuleSummary struct {
	RuleName     string   `json:"rule_name"`
	Severity     Severity `json:"severity"`
	Count        int      `json:"count"`
	Acknowledged bool     `json:"acknowledged,omitempty"`
}

// Finding represents a single security observation or compromise indicator
// discovered during a hunt scan.
type Finding struct {
	ID                  string                 `json:"id,omitempty"`
	Timestamp           time.Time              `json:"timestamp"`
	Module              string                 `json:"module"`
	Severity            Severity               `json:"severity"`
	Confidence          Confidence             `json:"confidence,omitempty"`
	Verdict             Verdict                `json:"verdict,omitempty"`
	Title               string                 `json:"title,omitempty"`
	Path                string                 `json:"path,omitempty"`
	LineNumber          int                    `json:"line_number,omitempty"`
	Reason              string                 `json:"reason"`
	RuleName            string                 `json:"rule_name,omitempty"`
	Evidence            string                 `json:"evidence,omitempty"`
	Context             string                 `json:"context,omitempty"`
	Why                 string                 `json:"why,omitempty"`
	Remediation         []string               `json:"remediation,omitempty"`
	MITRE               []MITREMapping         `json:"mitre,omitempty"`
	Count               int                    `json:"count,omitempty"`
	Paths               []string               `json:"paths,omitempty"`
	Hashes              map[string]string      `json:"hashes,omitempty"`
	Metadata            map[string]interface{} `json:"metadata,omitempty"`
	EvidenceRecord      *EvidenceRecord        `json:"evidence_record,omitempty"`
	EvidenceStrength    EvidenceStrength       `json:"evidence_strength,omitempty"`
	ConfidenceRationale string                 `json:"confidence_rationale,omitempty"`
}

// NewFinding creates a populated Finding with the current local timestamp (with timezone offset).
func NewFinding(module string, severity Severity, path, reason, ruleName string) Finding {
	f := Finding{
		Timestamp:   time.Now(),
		Module:      module,
		Severity:    severity,
		Path:        path,
		Reason:      reason,
		RuleName:    ruleName,
		Count:       1,
		Paths:       []string{path},
		Hashes:      make(map[string]string),
		Metadata:    make(map[string]interface{}),
		Remediation: make([]string, 0),
		MITRE:       make([]MITREMapping, 0),
	}
	PopulateFindingDetails(&f)
	return f
}

// PopulateFindingDetails enriches a finding with Title, Confidence, MITRE ATT&CK,
// Why explanation, and Remediation recommendations based on RuleName and Module.
// First it consults the typed rule metadata registry (rule_registry.go +
// rule_metadata*.go). If the rule is unregistered it falls back to the
// legacy substring switch so that third-party / custom IOC names keep working.
func PopulateFindingDetails(f *Finding) {
	if f == nil {
		return
	}

	// Registry path — exact rule name lookup.
	if meta, ok := LookupRuleMeta(f.RuleName); ok {
		if f.Title == "" || strings.EqualFold(f.Title, strings.ReplaceAll(f.RuleName, "_", " ")) {
			f.Title = meta.Title
		}
		if meta.Confidence != "" {
			f.Confidence = meta.Confidence
		}
		if meta.EvidenceStrength != "" {
			f.EvidenceStrength = meta.EvidenceStrength
		}
		// Only override Why/MITRE/Remediation when the finding does not
		// already carry detector-supplied values that are more specific.
		if f.Why == "" {
			f.Why = meta.Why
		}
		if len(f.MITRE) == 0 && len(meta.MITRE) > 0 {
			f.MITRE = append([]MITREMapping(nil), meta.MITRE...)
		}
		if len(f.Remediation) == 0 && len(meta.Remediation) > 0 {
			f.Remediation = append([]string(nil), meta.Remediation...)
		}
	}

	// If registry already fully populated the finding (registered rule with
	// non-empty Why+Remediation), skip the legacy fallback — just fill
	// verdict/confidence rationale and evidence record below.
	if _, registered := LookupRuleMeta(f.RuleName); registered && f.Why != "" && len(f.Remediation) > 0 {
		applyFindingDefaults(f)
		return
	}

	// Legacy substring fallback for unregistered / custom names.
	if f.Title == "" {
		if f.RuleName != "" {
			f.Title = strings.ReplaceAll(f.RuleName, "_", " ")
		} else {
			f.Title = f.Reason
		}
	}

	rule := strings.ToLower(f.RuleName)

	switch {
	case strings.Contains(rule, "multi_vector") || strings.Contains(rule, "multi_persistence"):
		f.Confidence = ConfidenceHigh
		f.Title = "Multi-Vector Persistence Payload"
		f.Why = "The same executable or hidden directory payload is wired into multiple independent persistence hooks (e.g. systemd, cron, shell profiles, or SSH), indicating an intentional multi-stage persistence setup."
		f.MITRE = []MITREMapping{
			{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"},
			{Tactic: "Defense Evasion", Technique: "T1564.001", TechniqueName: "Hidden Files and Directories"},
		}
		f.Remediation = []string{
			"Inspect all linked persistence configurations identified in the finding.",
			"Quarantine the referenced payload binary and remove the autostart entries.",
			"Check process tree for active instances spawned by these persistence mechanisms.",
		}

	case strings.Contains(rule, "suspicious_private_key") || strings.Contains(rule, "private_key_location"):
		f.Confidence = ConfidenceHigh
		f.Title = "Private Key Material in Suspicious Location"
		f.Why = "Cryptographic private key headers (OpenSSH/PEM/RSA/EC) were identified in an unowned, temporary, or hidden directory outside standard SSH/SSL configuration paths."
		f.MITRE = []MITREMapping{
			{Tactic: "Credential Access", Technique: "T1552.004", TechniqueName: "Private Keys"},
		}
		f.Remediation = []string{
			"Verify if this key was intentionally generated or placed for automated tooling.",
			"Check whether the key matches any entry in ~/.ssh/authorized_keys or server configs.",
			"If unauthorized, revoke the key pair across all servers and remove the file.",
		}

	case strings.Contains(rule, "redteam") || strings.Contains(rule, "persistence_framework") || strings.Contains(rule, "ghostshell") || strings.Contains(rule, "kali_master"):
		f.Confidence = ConfidenceHigh
		f.Title = "Red-Team Stealth Implant & Persistence Framework"
		f.Why = "The script contains signatures of an automated red-team persistence framework (such as GhostShell/Kali-Master), including stealth procfs process hiding, fake systemd/cron hooks, and persistent reverse shell listeners."
		f.MITRE = []MITREMapping{
			{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"},
			{Tactic: "Defense Evasion", Technique: "T1564.001", TechniqueName: "Hidden Files and Directories"},
			{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"},
		}
		f.Remediation = []string{
			"Immediately isolate the affected endpoint and inspect /proc mounts for hidden processes.",
			"Quarantine the framework script and inspect systemd service directories and cron tabs for installed implants.",
			"Audit system authentication logs to determine initial intrusion vector.",
		}

	case strings.Contains(rule, "proc_hiding") || strings.Contains(rule, "process_hiding"):
		f.Confidence = ConfidenceHigh
		f.Title = "Stealth Process Hiding via Procfs Manipulation"
		f.Why = "The file mounts a tmpfs layer over /proc/<PID> entries to conceal malicious background processes and backdoors from tools like ps, top, and lsof."
		f.MITRE = []MITREMapping{
			{Tactic: "Defense Evasion", Technique: "T1564.001", TechniqueName: "Hidden Files and Directories"},
			{Tactic: "Defense Evasion", Technique: "T1014", TechniqueName: "Rootkit"},
		}
		f.Remediation = []string{
			"Unmount unauthorized tmpfs filesystems from /proc mountpoints (`umount -l /proc/<PID>`).",
			"Check running processes and kernel task list for rogue concealed PIDs.",
		}

	case strings.Contains(rule, "ransomware") || strings.Contains(rule, "ransom") || strings.Contains(rule, "locker"):
		f.Confidence = ConfidenceHigh
		f.Title = "Ransomware File Encryptor & Locker"
		f.Why = "The script performs automated recursive filesystem encryption (Fernet/AES), locks target files (.locked/.enc), destroys original copies, and generates ransom demand notes."
		f.MITRE = []MITREMapping{
			{Tactic: "Impact", Technique: "T1486", TechniqueName: "Data Encrypted for Impact"},
			{Tactic: "Defense Evasion", Technique: "T1070.004", TechniqueName: "File Deletion"},
		}
		f.Remediation = []string{
			"Immediately quarantine or remove the script payload.",
			"Verify if any files in target directories were encrypted or deleted.",
			"Check for locally backed-up session recovery keys in temporary locations.",
		}

	case strings.Contains(rule, "exfiltration") || strings.Contains(rule, "exfil") || strings.Contains(rule, "stealer"):
		f.Confidence = ConfidenceHigh
		f.Title = "Automated Data Exfiltration / File Stealer"
		f.Why = "The script recursively crawls directories, compresses and encodes document data, and exfiltrates files outbound over network sockets to a remote C2 server."
		f.MITRE = []MITREMapping{
			{Tactic: "Exfiltration", Technique: "T1041", TechniqueName: "Exfiltration Over C2 Channel"},
			{Tactic: "Collection", Technique: "T1005", TechniqueName: "Data from Local System"},
		}
		f.Remediation = []string{
			"Inspect network connections and firewall logs for traffic to the exfiltration destination IP/port.",
			"Audit file access timestamps to identify what confidential documents were staged or exfiltrated.",
			"Quarantine the exfiltration client script.",
		}

	case strings.Contains(rule, "exfil_server") || strings.Contains(rule, "c2_server"):
		f.Confidence = ConfidenceHigh
		f.Title = "C2 Data Exfiltration Collection Server"
		f.Why = "The script configures a listening network server to receive, decompress, and reconstruct exfiltrated directory trees and stolen credentials."
		f.MITRE = []MITREMapping{
			{Tactic: "Command and Control", Technique: "T1071.001", TechniqueName: "Web Protocols"},
			{Tactic: "Exfiltration", Technique: "T1041", TechniqueName: "Exfiltration Over C2 Channel"},
		}
		f.Remediation = []string{
			"Terminate the listening process and block the configured port.",
			"Inspect exfiltrated data dumps to identify compromised client endpoints.",
		}

	case strings.Contains(rule, "interactive_reverse_shell"):
		f.Confidence = ConfidenceHigh
		f.Title = "Interactive Reverse Shell Socket Redirection"
		f.Why = "Process standard input (stdin) or output (stdout) is redirected to an active network socket, establishing an interactive shell session with an external host."
		f.MITRE = []MITREMapping{
			{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"},
			{Tactic: "Command and Control", Technique: "T1071", TechniqueName: "Application Layer Protocol"},
		}
		f.Remediation = []string{
			"Immediately terminate the rogue process PID (`kill -9 <PID>`).",
			"Trace process parentage (PPID) and inspect open sockets (/proc/<PID>/net or /proc/net/tcp).",
			"Isolate the host from the network to sever C2 communications.",
		}

	case strings.Contains(rule, "container_dangerous_capability") || strings.Contains(rule, "capability_overprivilege"):
		f.Confidence = ConfidenceHigh
		f.Title = "Container Process with Dangerous Host Breakout Capabilities"
		f.Why = "A container process runs with elevated Linux capabilities (e.g. CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH), allowing potential container breakout and host compromise."
		f.MITRE = []MITREMapping{
			{Tactic: "Privilege Escalation", Technique: "T1611", TechniqueName: "Escape to Host"},
			{Tactic: "Privilege Escalation", Technique: "T1548", TechniqueName: "Abuse Elevation Control Mechanism"},
		}
		f.Remediation = []string{
			"Drop unnecessary Linux capabilities in container runtime configuration (use `cap_drop: [ALL]`).",
			"Avoid running containers with `--privileged` flag in Docker or Podman.",
			"Enable Seccomp and AppArmor profiles to restrict container system calls.",
		}

	case strings.Contains(rule, "reverse_shell") || strings.Contains(rule, "revshell") || strings.Contains(rule, "netcat") || strings.Contains(rule, "socat") || strings.Contains(rule, "openssl"):
		f.Confidence = ConfidenceHigh
		f.Title = "Interactive Reverse Shell Script / Backdoor"
		f.Why = "The file contains automated network socket redirection commands (/dev/tcp, openssl s_client, netcat -e, socat, or inline sockets) designed to connect outbound and grant an interactive remote command shell."
		f.MITRE = []MITREMapping{
			{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"},
			{Tactic: "Command and Control", Technique: "T1071.001", TechniqueName: "Web Protocols"},
			{Tactic: "Command and Control", Technique: "T1573.002", TechniqueName: "Asymmetric Cryptography"},
		}
		f.Remediation = []string{
			"Quarantine the script file and review authentication and bash history logs.",
			"Inspect network connections and firewall logs for active or outbound traffic to the target host/port.",
			"Check the process tree for any spawned interactive shells.",
		}

	case strings.Contains(rule, "download_and_execute") || strings.Contains(rule, "dropper"):
		f.Confidence = ConfidenceHigh
		f.Title = "Remote Download and Pipe Execution Dropper"
		f.Why = "The script downloads arbitrary code over HTTP/HTTPS and pipes it directly into an interpreter (e.g., curl | bash), which is a common staging pattern for malware droppers."
		f.MITRE = []MITREMapping{
			{Tactic: "Execution", Technique: "T1059.004", TechniqueName: "Unix Shell"},
			{Tactic: "Command and Control", Technique: "T1105", TechniqueName: "Ingress Tool Transfer"},
		}
		f.Remediation = []string{
			"Verify whether the remote URL is a trusted official software installer.",
			"Inspect the downloaded URL content in an isolated environment before executing.",
		}

	case strings.Contains(rule, "webshell") || strings.Contains(rule, "eval"):
		f.Confidence = ConfidenceHigh
		f.Title = "Possible Web Shell / Dynamic Code Execution"
		f.Why = "Matching YARA signatures or heuristics detected dynamic code execution patterns (eval, base64 payload decoding, system command wrappers) typical of backdoor web shells."
		f.MITRE = []MITREMapping{
			{Tactic: "Persistence", Technique: "T1505.003", TechniqueName: "Web Shell"},
			{Tactic: "Execution", Technique: "T1059", TechniqueName: "Command and Scripting Interpreter"},
		}
		f.Remediation = []string{
			"Review the web server document root access logs around the file's modification time.",
			"Quarantine the file and check for unauthorized administrative web sessions.",
		}

	case strings.Contains(rule, "suid") || strings.Contains(rule, "sgid"):
		f.Confidence = ConfidenceMedium
		f.Title = "Elevated SUID/SGID Binary in Non-Standard Path"
		f.Why = "A privileged binary with the SUID/SGID permission bit is located in a user-writable or non-standard directory, which presents privilege escalation risk."
		f.MITRE = []MITREMapping{
			{Tactic: "Privilege Escalation", Technique: "T1548.001", TechniqueName: "Setuid and Setgid"},
		}
		f.Remediation = []string{
			"Confirm package ownership using dpkg/rpm.",
			"Remove the SUID bit using `chmod u-s <path>` if elevated privilege is unnecessary.",
		}

	case strings.Contains(rule, "memfd") || strings.Contains(rule, "deleted_binary"):
		f.Confidence = ConfidenceHigh
		f.Title = "Memory Execution / Unlinked Binary"
		f.Why = "A running process executable has been unlinked from disk or executed entirely out of an anonymous in-memory file descriptor (memfd_create)."
		f.MITRE = []MITREMapping{
			{Tactic: "Defense Evasion", Technique: "T1620", TechniqueName: "Reflective Code Loading"},
			{Tactic: "Defense Evasion", Technique: "T1070.004", TechniqueName: "File Deletion"},
		}
		f.Remediation = []string{
			"Inspect /proc/<pid>/exe and /proc/<pid>/fd to extract the in-memory binary image.",
			"Terminate the process and investigate how it was launched.",
		}

	case strings.Contains(rule, "uid0") || strings.Contains(rule, "extra_uid0"):
		f.Confidence = ConfidenceHigh
		f.Title = "Rogue Non-Root UID 0 Account"
		f.Why = "A non-root user account in /etc/passwd has been assigned UID 0, giving it unconstrained root administrative privileges."
		f.MITRE = []MITREMapping{
			{Tactic: "Persistence", Technique: "T1136.001", TechniqueName: "Local Account"},
			{Tactic: "Privilege Escalation", Technique: "T1078.003", TechniqueName: "Local Accounts"},
		}
		f.Remediation = []string{
			"Audit /etc/passwd and /etc/shadow for unauthorized accounts.",
			"Remove or lock the rogue UID 0 account immediately.",
			"Review authentication logs to trace account creation.",
		}

	case strings.Contains(rule, "rootkit") || strings.Contains(rule, "diamorphine"):
		f.Confidence = ConfidenceHigh
		f.Title = "Kernel Rootkit / LKM Module Artifacts"
		f.Why = "Kernel module strings or symbol hooks associated with known Linux rootkits (e.g., Diamorphine/Reptile) were detected."
		f.MITRE = []MITREMapping{
			{Tactic: "Defense Evasion", Technique: "T1014", TechniqueName: "Rootkit"},
			{Tactic: "Persistence", Technique: "T1547.006", TechniqueName: "Kernel Modules and Extensions"},
		}
		f.Remediation = []string{
			"Inspect loaded kernel modules using `lsmod` and audit `/lib/modules/`.",
			"Reboot into a trusted live forensics environment to inspect rootkit hooks.",
			"Quarantine any malicious kernel object (.ko) files.",
		}

	case strings.Contains(rule, "ioc") || strings.Contains(strings.ToLower(f.Reason), "ioc match"):
		f.Confidence = ConfidenceHigh
		f.Title = "Cryptographic Threat Intelligence IOC Match"
		f.Why = "The file content or cryptographic SHA-256 hash matches a known high-confidence threat indicator of compromise (IOC)."
		f.MITRE = []MITREMapping{
			{Tactic: "Execution", Technique: "T1204.002", TechniqueName: "Malicious File"},
		}
		f.Remediation = []string{
			"Immediately isolate the affected system.",
			"Quarantine the matching IOC payload file.",
			"Correlate the IOC across enterprise endpoint telemetry.",
		}

	case strings.Contains(rule, "ssh") || strings.Contains(rule, "authorized_key"):
		f.Confidence = ConfidenceHigh
		f.Title = "Unauthorized SSH Key Injection / Backdoor"
		f.Why = "An unauthorized public key has been appended to an administrative or user authorized_keys file for persistent remote access."
		f.MITRE = []MITREMapping{
			{Tactic: "Persistence", Technique: "T1098.004", TechniqueName: "SSH Authorized Keys"},
		}
		f.Remediation = []string{
			"Remove unauthorized public keys from ~/.ssh/authorized_keys.",
			"Rotate host SSH keys and review SSH access logs.",
		}

	case strings.Contains(rule, "wildcard_listener") || strings.Contains(rule, "unmapped_listener"):
		f.Confidence = ConfidenceMedium
		f.Title = "Unmapped Wildcard Network Listener"
		f.Why = "A process outside the standard system daemon allowlist is listening on all network interfaces (0.0.0.0 or ::), exposing an accessible network service endpoint."
		f.MITRE = []MITREMapping{
			{Tactic: "Command and Control", Technique: "T1571", TechniqueName: "Non-Standard Port"},
			{Tactic: "Execution", Technique: "T1059", TechniqueName: "Command and Scripting Interpreter"},
		}
		f.Remediation = []string{
			"Verify if the listening process is an authorized custom service or developer server.",
			"Bind the service to localhost (127.0.0.1) if remote access is not required.",
			"Add known internal services to the listener allowlist in aether configuration.",
		}

	case strings.Contains(rule, "raw_packet_socket") || strings.Contains(rule, "raw_socket"):
		f.Confidence = ConfidenceMedium
		f.Title = "Suspicious Raw/Packet Network Socket"
		f.Why = "A non-kernel process opened a RAW or PACKET socket without being on the standard network diagnostic tools allowlist (e.g. tcpdump, wireshark), which may indicate network sniffing or packet injection."
		f.MITRE = []MITREMapping{
			{Tactic: "Credential Access", Technique: "T1040", TechniqueName: "Network Sniffing"},
		}
		f.Remediation = []string{
			"Inspect the process binary and command line.",
			"Terminate unauthorized packet capturing processes.",
			"Audit CAP_NET_RAW capabilities granted to binaries.",
		}

	case strings.Contains(rule, "loopback_listener"):
		f.Confidence = ConfidenceLow
		f.Title = "Local Loopback Network Listener"
		f.Why = "Local system services are listening on loopback (127.0.0.1 or ::1) interfaces for inter-process communication."
		f.MITRE = []MITREMapping{
			{Tactic: "Discovery", Technique: "T1046", TechniqueName: "Network Service Discovery"},
		}
		f.Remediation = []string{
			"No remediation required for benign local system services.",
		}

	case strings.Contains(rule, "kernel_thread_masquerade"):
		f.Confidence = ConfidenceHigh
		f.Title = "Process Masquerading as Kernel Thread"
		f.Why = "A user-space process with bracketed naming convention (e.g., [kworker/...]) is running with user-space memory mappings, masquerading as a Linux kernel thread to evade detection."
		f.MITRE = []MITREMapping{
			{Tactic: "Defense Evasion", Technique: "T1036.004", TechniqueName: "Masquerade Task or Service"},
		}
		f.Remediation = []string{
			"Inspect /proc/<pid>/maps and /proc/<pid>/exe for the deceptive process.",
			"Immediately terminate the rogue process and identify its parent process.",
		}

	case strings.Contains(rule, "system_daemon_masquerade"):
		f.Confidence = ConfidenceHigh
		f.Title = "Process Masquerading as System Daemon"
		f.Why = "A process name matches a standard system daemon (e.g. sshd, cron) but its executable is located in a non-standard path outside /usr, /bin, or /sbin."
		f.MITRE = []MITREMapping{
			{Tactic: "Defense Evasion", Technique: "T1036.005", TechniqueName: "Match Legitimate Name or Location"},
		}
		f.Remediation = []string{
			"Inspect the executable location and cryptographic hash.",
			"Terminate the process and restore original system binaries if compromised.",
		}

	case strings.Contains(rule, "deleted_binary_package_upgrade"):
		f.Confidence = ConfidenceLow
		f.Title = "Process Running Deleted Binary After Package Upgrade"
		f.Why = "A running system process is executing an unlinked binary from a package directory (/usr/bin, /usr/sbin, /lib), indicating the package was upgraded while the daemon remained running."
		f.MITRE = []MITREMapping{
			{Tactic: "Defense Evasion", Technique: "T1070.004", TechniqueName: "File Deletion"},
		}
		f.Remediation = []string{
			"Restart the service or system daemon (e.g., systemctl restart <service>) to load the upgraded binary from disk.",
		}

	case strings.Contains(rule, "deleted_binary_replaced"):
		f.Confidence = ConfidenceLow
		f.Title = "Process Running Replaced Binary Image"
		f.Why = "The executable file on disk has been replaced with a newer version (different inode/device), and the running process is still executing the old deleted inode."
		f.MITRE = []MITREMapping{
			{Tactic: "Defense Evasion", Technique: "T1070.004", TechniqueName: "File Deletion"},
		}
		f.Remediation = []string{
			"Restart the process to load the newly replaced on-disk binary.",
		}

	case strings.Contains(rule, "deleted_binary_suspicious_location"):
		f.Confidence = ConfidenceHigh
		f.Title = "Deleted Binary Running from Temporary/Suspicious Path"
		f.Why = "A running process executable was deleted from a temporary or volatile directory (/tmp, /var/tmp, /dev/shm), typical of dropper malware executing memory payloads then unlinking on-disk binaries."
		f.MITRE = []MITREMapping{
			{Tactic: "Defense Evasion", Technique: "T1070.004", TechniqueName: "File Deletion"},
			{Tactic: "Defense Evasion", Technique: "T1620", TechniqueName: "Reflective Code Loading"},
		}
		f.Remediation = []string{
			"Inspect memory maps and open descriptors (/proc/<pid>/fd) to recover the executable image.",
			"Terminate the process and inspect initial persistence hooks.",
		}

	case strings.Contains(rule, "root_user_writable_exe") || strings.Contains(rule, "root_world_writable") || strings.Contains(rule, "root_nonroot_owned"):
		f.Confidence = ConfidenceHigh
		f.Title = "Root Process Running Non-Root or Writable Executable"
		f.Why = "A process running as root (UID 0) is executing a binary owned by a non-root user or located in a user-writable directory, presenting high local privilege escalation risk."
		f.MITRE = []MITREMapping{
			{Tactic: "Privilege Escalation", Technique: "T1548", TechniqueName: "Abuse Elevation Control Mechanism"},
		}
		f.Remediation = []string{
			"Correct file permissions and ownership on the executable.",
			"Ensure root services only execute binaries owned by root:root in trusted system paths.",
		}

	case strings.Contains(rule, "exe_or_cwd_in_temp"):
		f.Confidence = ConfidenceMedium
		f.Title = "Process Executing from Temporary Directory"
		f.Why = "A process is running with its executable or working directory in a temporary or world-writable location (/tmp, /var/tmp, /dev/shm)."
		f.MITRE = []MITREMapping{
			{Tactic: "Defense Evasion", Technique: "T1070.004", TechniqueName: "File Deletion"},
		}
		f.Remediation = []string{
			"Inspect the running process and its executable path.",
			"Ensure legitimate services execute from standard system directories.",
		}

	case strings.Contains(rule, "permission_denied"):
		f.Confidence = ConfidenceLow
		f.Title = "Inspection Limited by Permissions"
		f.Why = "Inspection could not complete due to insufficient operating system privileges (requires root / CAP_DAC_OVERRIDE)."
		f.MITRE = []MITREMapping{}
		f.Remediation = []string{
			"Re-run Aether with elevated privileges (sudo / root) for complete forensic visibility.",
		}

	case strings.Contains(rule, "missing_target"):
		f.Confidence = ConfidenceLow
		f.Title = "Missing Persistence Executable Target"
		f.Why = "An autostart configuration or startup script references an executable path that does not exist on disk."
		f.MITRE = []MITREMapping{
			{Tactic: "Persistence", Technique: "T1547", TechniqueName: "Boot or Logon Autostart Execution"},
		}
		f.Remediation = []string{
			"Verify whether the referenced binary belongs to an uninstalled package.",
			"Remove dead startup entries to prevent potential binary path hijacking.",
		}

	default:
		if f.Confidence == "" {
			f.Confidence = ConfidenceMedium
		}
		if f.Why == "" {
			f.Why = f.Reason
		}
		if len(f.Remediation) == 0 {
			f.Remediation = []string{"Inspect the affected artifact and verify legitimacy against system baseline."}
		}
	}

	applyFindingDefaults(f)
}

// applyFindingDefaults fills verdict, confidence rationale, and the evidence
// record for any finding, regardless of which enrichment path populated it.
func applyFindingDefaults(f *Finding) {
	if f.Verdict == "" {
		switch f.Severity {
		case SeverityCritical, SeverityAlert:
			f.Verdict = VerdictMalicious
		case SeverityWarning, SeverityHigh, SeverityMedium:
			f.Verdict = VerdictSuspicious
		case SeverityNotice, SeverityInfo, SeverityLow:
			f.Verdict = VerdictSafe
		default:
			f.Verdict = VerdictSuspicious
		}
	}

	if f.ConfidenceRationale == "" {
		if f.EvidenceRecord != nil && f.EvidenceRecord.ConfidenceRationale != "" {
			f.ConfidenceRationale = f.EvidenceRecord.ConfidenceRationale
		} else if f.Confidence != "" {
			f.ConfidenceRationale = "Assigned " + string(f.Confidence) + " confidence based on detector rule and baseline context."
		}
	}

	if f.EvidenceStrength == "" {
		f.EvidenceStrength = EvaluateEvidenceStrength(f.RuleName, f.Reason, false, nil)
	}

	if f.EvidenceRecord == nil {
		detType := f.Module
		if detType == "" {
			detType = "heuristic"
		}
		f.EvidenceRecord = &EvidenceRecord{
			DetectorType:        detType,
			RuleName:            f.RuleName,
			EvidenceStrength:    f.EvidenceStrength,
			MatchedCondition:    f.Reason,
			TargetPath:          f.Path,
			LineNumber:          f.LineNumber,
			PackageStatus:       "unowned",
			ContextProfile:      "standard",
			ConfidenceRationale: f.ConfidenceRationale,
		}
	} else if f.EvidenceRecord.EvidenceStrength == "" {
		f.EvidenceRecord.EvidenceStrength = f.EvidenceStrength
	}
}
