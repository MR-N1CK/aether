# Feature Specification: Aether Runtime Threat Assessment & Static/Runtime Correlation

**Feature Branch**: `003-runtime-threat-assessment`
**Created**: 2026-10-03
**Status**: Draft
**Input**: User description: "AETHER — RUNTIME THREAT ASSESSMENT & STATIC/RUNTIME CORRELATION"

## Overview & Background

Aether provides deep static Linux security assessment and threat hunting, verified by the Feature 002 Benchmark to achieve 100% Threat Recall, 100% Precision, and 0% False-Positive Rate across static file and persistence indicators. However, the benchmark established that static analysis alone yields 33.33% Suspicious Triage Accuracy because live runtime phenomena—specifically unmapped wildcard network listeners (`SUSP-LISTEN-001`) and deleted running executables pending post-upgrade restart (`SUSP-UPGRADE-001`)—cannot be reliably evaluated solely from passive filesystem artifacts.

This feature introduces a safe, read-only Runtime Threat Assessment layer and a Multi-Vector Static/Runtime Correlation Engine. By correlating static indicators (heuristics, YARA matches, persistence entries, package verification, IOCs) with live runtime state (processes, executable mappings, fileless memory segments, socket owners, network endpoints, namespace contexts), Aether elevates detection trustworthiness without increasing uncorroborated alert volume.

```
+-------------------------------------------------------------------------------+
|                             AETHER CORRELATION ENGINE                         |
|                                                                               |
|  +---------------------------+             +-------------------------------+  |
|  |      STATIC EVIDENCE      |             |       RUNTIME EVIDENCE        |  |
|  | - Heuristic Script Rules  |             | - Live Process Tree (/proc)   |  |
|  | - Static YARA-X Rules     |             | - Memory Mappings (/maps)     |  |
|  | - Persistence Mechanisms  |             | - Socket Listeners (/net)     |  |
|  | - Package Integrity (DB) |             | - Socket-Process Links (/fd)  |  |
|  | - Cryptographic IOC Hits  |             | - Namespace Context (mnt/net) |  |
|  +-------------+-------------+             +---------------+---------------+  |
|                |                                           |                  |
|                +--------------------+----------------------+                  |
|                                     |                                         |
|                                     v                                         |
|                     +-------------------------------+                         |
|                     | MULTI-VECTOR CORROBORATION    |                         |
|                     | - Corroboration Multipliers   |                         |
|                     | - Contextual Suppressions     |                         |
|                     | - Namespace Adjustments       |                         |
|                     +---------------+---------------+                         |
|                                     |                                         |
|                                     v                                         |
|                     +-------------------------------+                         |
|                     | UNIFIED VERDICT ARCHITECTURE  |                         |
|                     | - Severity != Confidence      |                         |
|                     | - Severity != Verdict         |                         |
|                     | - 8-Question Explainability   |                         |
|                     | [ALERT | WARNING | NOTICE]    |                         |
|                     | [MALICIOUS | SUSPICIOUS| SAFE]|                         |
|                     +-------------------------------+                         |
+-------------------------------------------------------------------------------+
```

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Live Process & Execution State Assessment (Priority: P1)

As a security auditor or system administrator, I want Aether to inspect live Linux processes and memory mappings for anomalous execution patterns (unlinked/deleted binaries, temporary directory execution, anonymous memfd payloads, masquerading, and hidden PIDs) so that I can discover active in-memory threats without executing code or destabilizing the endpoint.

**Why this priority**: Active processes represent running threats. Detecting fileless execution, unlinked payloads, and masquerading is essential for runtime security visibility.

**Independent Test**: Execute Aether against running test fixtures representing: (1) a process running from an unlinked binary in `/tmp`, (2) a process with an executable `memfd:` ELF mapping, (3) a masqueraded kernel thread `[kworker/0:0]` executing userland code, and (4) legitimate daemons (e.g. `sshd`, `cron`). Verify that threats are flagged with appropriate severity while clean daemons produce zero false alerts.

**Acceptance Scenarios**:
1. **Given** a running process whose executable binary was unlinked from `/tmp` (`/proc/<pid>/exe -> /tmp/payload (deleted)`), **When** Aether runs process inspection, **Then** it generates a `WARNING` or `ALERT` finding (`Process_Deleted_Binary_Suspicious_Location`), reports the target path and PID, and assigns `VerdictMalicious` or `VerdictSuspicious` based on corroborating signals.
2. **Given** a process with an executable memory mapping containing ELF headers from `memfd:` or anonymous space, **When** Aether inspects memory maps, **Then** it flags `Process_Fileless_Memory_ELF` with direct evidence strength.
3. **Given** a legitimate system service whose binary was upgraded on disk (new package inode on disk, running process holds old inode), **When** Aether inspects the process, **Then** it identifies `Process_Deleted_Binary_Replaced` as a `NOTICE` / `VerdictSafe` requiring a service restart, preventing false alarms.
4. **Given** an unprivileged audit run encountering `/proc/<pid>` owned by another user with restricted permissions (`EACCES`), **When** Aether inspects the process, **Then** it records a coverage gap, marks the process status as `limited_visibility`, and abstains from issuing speculative `SAFE` or `MALICIOUS` verdicts.

---

### User Story 2 - Socket & Network Listener Threat Hunting (Priority: P1)

As a security analyst, I want Aether to audit active network sockets and listeners across TCP, UDP, RAW, and PACKET tables, linking each listening port to its owning process, command line, and package status, so that I can detect unauthorized listeners and suspicious C2 callbacks.

**Why this priority**: Command and control (C2) listeners, reverse shells, and packet sniffing sockets are primary vectors of active compromise.

**Independent Test**: Run Aether on a host with: (1) a legitimate package-managed SSH daemon listening on `0.0.0.0:22`, (2) a local development server listening on `127.0.0.1:8080`, (3) an unmapped standalone wildcard listener on `0.0.0.0:4444` (`SUSP-LISTEN-001`), and (4) a raw packet capture socket. Verify accurate socket-to-process mapping and defensible triage.

**Acceptance Scenarios**:
1. **Given** a process listening on wildcard `0.0.0.0:4444` where the executable is an unowned/standalone script, **When** Aether runs network inspection, **Then** it maps the socket inode to the owning PID, reports `Socket_Unmapped_Wildcard_Listener` with `WARNING` severity, `ConfidenceMedium`, and `VerdictSuspicious` (`SUSP-LISTEN-001` resolved).
2. **Given** a verified system daemon (`sshd` owned by `openssh-server`) listening on `0.0.0.0:22`, **When** Aether audits sockets, **Then** it recognizes the verified package ownership and classifies the listener as `VerdictSafe` with `INFO` severity.
3. **Given** a non-root process opening a RAW or PACKET capture socket, **When** Aether scans `/proc/net/raw` and `/proc/net/packet`, **Then** it generates `Socket_Raw_Packet_Sniffer` finding with `WARNING` severity.
4. **Given** a process listening strictly on loopback interface (`127.0.0.1` or `::1`), **When** Aether evaluates the listener, **Then** it suppresses high-severity alerts unless linked to known malicious signatures or external exfiltration.

---

### User Story 3 - Multi-Vector Static & Runtime Correlation (Priority: P1)

As a security responder, I want Aether to cross-correlate static filesystem findings with live process, persistence, and network socket observations, so that isolated suspicious indicators are elevated to high-confidence `MALICIOUS` alerts when corroborated, while uncorroborated single-vector anomalies remain appropriately bounded as `SUSPICIOUS` or `SAFE`.

**Why this priority**: Corroborating multiple independent operational signals (e.g. suspicious script + running process + open listener + persistence) is the foundation of trustworthy, defensible detection.

**Independent Test**: Provide test scenarios combining:
- Case 1: Suspicious script on disk alone -> `VerdictSuspicious` (WARNING).
- Case 2: Suspicious script on disk + running PID -> elevated confidence `VerdictSuspicious` (WARNING).
- Case 3: Suspicious script on disk + running PID + active listening socket + autostart persistence -> `VerdictMalicious` (ALERT, high confidence).
- Case 4: Package-owned script with dual-use commands but no active execution -> `VerdictSafe` (NOTICE).

**Acceptance Scenarios**:
1. **Given** a heuristic finding on `/tmp/dropper.sh` (dual-use script) AND an active process running `/tmp/dropper.sh` AND an active outbound or listening socket owned by that PID, **When** the correlation engine runs, **Then** it consolidates findings into a single primary threat record with `VerdictMalicious`, `SeverityAlert`, `ConfidenceHigh`, listing all three corroborating signals in `CorroboratingSignals`.
2. **Given** an uncorroborated dual-use script on disk (`/usr/local/bin/backup.sh`) with no running process, no socket, and no persistence, **When** correlation executes, **Then** it remains `VerdictSuspicious` with `ConfidenceLow`/`ConfidenceMedium` without generating an unjustified `ALERT`.
3. **Given** a static persistence entry (`/etc/cron.d/job`) pointing to an unlinked binary currently executing in memory, **When** correlation runs, **Then** the correlation engine links the cron persistence finding to the running process finding and surfaces a unified incident timeline.

---

### User Story 4 - Container & Namespace Awareness (Priority: P2)

As a platform engineer auditing a containerized Linux host, I want Aether to recognize when processes, filesystem paths, and network sockets operate inside distinct Linux namespaces (containers/chroots), so that container-internal operations are not misclassified as host filesystem compromises.

**Why this priority**: Containers share the host kernel but operate in isolated namespaces. Without namespace awareness, standard container rootfs operations trigger false positive host alerts.

**Independent Test**: Scan processes and paths residing in isolated mount namespaces (`/proc/<pid>/ns/mnt != self.mnt_ns`). Verify path-based heuristic scores apply container context reductions while direct cryptographic IOCs and fileless ELF injections maintain full `ALERT` severity.

**Acceptance Scenarios**:
1. **Given** a process running inside a Docker/Podman container with an unlinked binary or temporary path inside the container's private mount namespace, **When** Aether inspects the process, **Then** it records `container: true` and `mnt_ns` metadata, and applies configured container score adjustments.
2. **Given** a direct high-confidence threat (e.g. reverse shell script or known ransomware IOC) executing inside a container namespace, **When** Aether audits the container process, **Then** it preserves `VerdictMalicious` and `SeverityAlert` regardless of namespace isolation.

---

### User Story 5 - Privilege-Bounded Assessment & Transparent Abstention (Priority: P3)

As a security practitioner running Aether as an unprivileged user, I want Aether to clearly report what could and could not be inspected due to Linux DAC/capability boundaries, so that I receive an honest assessment of visible assets without misleading `SAFE` guarantees or speculative alerts.

**Why this priority**: Compliance with Principle II (Least Privilege) and Principle V (Detection Integrity). Unprivileged users cannot read `/proc/<other_user>/fd` or protected socket tables.

**Independent Test**: Run Aether under an unprivileged user (`UID != 0` without `CAP_SYS_PTRACE`/`CAP_NET_ADMIN`). Verify that unreadable processes and sockets are enumerated as coverage gaps and reported as `UNKNOWN` / `limited_visibility`.

**Acceptance Scenarios**:
1. **Given** Aether running as non-root user, **When** it encounters `/proc/<pid>/exe` owned by another user returning `EACCES`, **Then** it increments `SkippedPermission`, sets `NonRootLimited: true`, and includes an explainable scope limitation note in the report.
2. **Given** an unmapped socket in `/proc/net/tcp` that cannot be associated with a PID due to unreadable `/proc/*/fd` links, **When** running as non-root, **Then** Aether classifies the socket as `UnmappedSocketsNonRoot` and suppresses speculative `ALERT` classifications.

---

### User Story 6 - Synthetic Benchmark Validation & Gap Resolution (Priority: P2)

As a developer maintaining Aether, I want the Feature 002 Benchmark Suite to evaluate runtime threat assessment and static/runtime correlation using safe, hermetic synthetic fixtures, so that detection accuracy on runtime scenarios (`SUSP-LISTEN-001`, `SUSP-UPGRADE-001`) is measurably proven without executing malware samples.

**Why this priority**: Preserves Principle XI (Static Analysis Invariant & AI Safety) and Feature 002 measurement authority.

**Independent Test**: Run `go test ./test/benchmark/...` with mocked/synthetic process and socket tables. Verify `SUSP-LISTEN-001` and `SUSP-UPGRADE-001` pass contract verification and Suspicious Triage Accuracy meets or exceeds 90%.

**Acceptance Scenarios**:
1. **Given** benchmark case `SUSP-LISTEN-001` with accompanying synthetic runtime socket descriptor, **When** the benchmark runs, **Then** it evaluates to `VerdictSuspicious`, `SeverityWarning`, `ConfidenceMedium`, matching the contract.
2. **Given** benchmark case `SUSP-UPGRADE-001` with synthetic deleted binary process state, **When** the benchmark runs, **Then** it evaluates to `VerdictNotice` / `VerdictSuspicious` with package upgrade rationale, matching the contract.

---

## Edge Cases

- **Process Race Conditions (Vanishing Processes)**: Processes exiting between `/proc` directory enumeration and `/proc/<pid>/*` inspection must return `ErrProcessVanished` and be recorded under `SkippedVanished` without generating error crashes or bogus findings.
- **Zombie and Kernel Threads**: PIDs with state `Z` (Zombie) or kernel threads (`PF_KTHREAD` / `ppid == 2`) must be identified and skipped from userland heuristic inspection.
- **Short-Lived Ephemeral Sockets**: Sockets closed between `/proc/net/*` parsing and `/proc/<pid>/fd` mapping must handle unmapped state gracefully without flagging false C2 alarms.
- **Deep Symlink Loops & /proc Recursion**: Reading `/proc/<pid>/root` or `/proc/<pid>/cwd` must never traverse recursive symlinks or escape host confinement.
- **Large Memory Maps**: Processes with tens of thousands of memory mappings (e.g. JVM, databases) must be parsed within memory and time budgets (`scanner.MemoryBudgetTracker`).
- **High-Port Local Development Binds**: Developers frequently bind wildcard ports (e.g. `0.0.0.0:3000` for Node.js, `0.0.0.0:8000` for Python). When the process command line or working directory clearly indicates a local development framework and lacks malicious heuristics, it must be triaged as `VerdictSuspicious` (WARNING/NOTICE) rather than `MALICIOUS`.

---

## Requirements *(mandatory)*

### Functional Requirements

#### Live Process Inspection
- **FR-001**: System MUST enumerate userland processes via `/proc` in a strictly read-only manner using `safeopen` and native procfs parsers without invoking external binaries (`ps`, `lsof`, `netstat`).
- **FR-002**: System MUST extract and parse process metadata: PID, PPID, Comm, Cmdline, UID/EUID, GID/EGID, Exe path, Cwd, and Mount Namespace (`/proc/<pid>/ns/mnt`).
- **FR-003**: System MUST identify unlinked running executables (`/proc/<pid>/exe` ending in ` (deleted)`) and differentiate between:
  - Suspicious/Temporary locations (`/tmp`, `/var/tmp`, `/dev/shm`) -> `Process_Deleted_Binary_Suspicious_Location` (`ALERT`/`WARNING`, strong evidence).
  - Package-managed upgrade replacements (new binary on disk with different inode) -> `Process_Deleted_Binary_Replaced` (`NOTICE`, low confidence, restart needed).
  - Standard user/application directories (`/home`, `.local/share`) -> `Process_Deleted_Binary_Home` (`WARNING`/`NOTICE`).
- **FR-004**: System MUST inspect `/proc/<pid>/maps` for executable memory regions and detect anonymous/memfd executions (`memfd:`, `/memfd`, unlinked anonymous executable segments).
- **FR-005**: System MUST read the first 4 bytes of suspect executable mappings to verify ELF magic (`\x7fELF`) without attaching debuggers (`ptrace`) or writing to memory.
- **FR-006**: System MUST detect process masquerading:
  - Userland processes attempting to hide as kernel threads using bracketed names (e.g. `[kworker/0:0]`) while possessing valid `/proc/<pid>/exe`.
  - Processes named after system daemons (`sshd`, `systemd`, `cron`) executing from non-standard user paths (`/tmp`, `/home`, `/dev/shm`).
- **FR-007**: System MUST detect root processes (UID 0) executing binaries owned by non-root users or located in world-writable parent directories.
- **FR-008**: System MUST perform hidden PID detection by comparing `/proc` directory entries against direct `stat` access across PID ranges, detecting kernel rootkit hiding techniques (e.g. Diamorphine) while respecting `hidepid` mount options.

#### Network Socket & Listener Inspection
- **FR-009**: System MUST parse Linux network tables (`/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6`, `/proc/net/raw`, `/proc/net/raw6`, `/proc/net/packet`) in a single read-only pass.
- **FR-010**: System MUST build an inverted socket-to-process map by inspecting `/proc/<pid>/fd/*` symlink targets (`socket:[<inode>]`) to associate each socket with its owning process.
- **FR-011**: System MUST classify network listeners into:
  - Standard Verified Service: Process owned by verified system package listening on standard or configured ports -> `VerdictSafe` (`INFO`).
  - Localhost/Loopback Listener: Listening on `127.0.0.1` or `::1` -> `VerdictSafe` / `VerdictNotice` unless matched to suspicious content.
  - Unmapped Wildcard Listener: Non-package binary or script listening on `0.0.0.0` or `::` -> `VerdictSuspicious` (`WARNING`).
  - Active C2 Connection: Established TCP connection to IP/domain matching known threat IOCs -> `VerdictMalicious` (`ALERT`, direct evidence).
  - Promiscuous / Raw Packet Capture: Unauthorized non-system processes with open RAW or PACKET sockets -> `VerdictSuspicious` (`WARNING`).

#### Static & Runtime Correlation Engine
- **FR-012**: System MUST provide a correlation engine that connects static filesystem findings (files, YARA signatures, AST heuristics, persistence configs) with runtime state (running PIDs, active sockets, memory mappings).
- **FR-013**: The correlation engine MUST evaluate findings according to Tiered Evidence Strength:
  - `StrengthDirect`: Cryptographic IOC match, confirmed reverse shell pattern, in-memory ELF injection, unauthorized UID 0 account.
  - `StrengthCorroborated`: Suspicious static file + active running process + open socket / persistence hook.
  - `StrengthContextual`: Standalone dual-use script, unmapped listener, deleted binary in home directory.
  - `StrengthIncomplete`: Permission denied (`EACCES`), unreadable map, restricted namespace.
- **FR-014**: System MUST consolidate multiple signals targeting the same underlying asset/process into a single primary `Finding` containing aggregated scores, individual rule severities, and the list of corroborating signals.
- **FR-015**: Corroboration MUST NOT be satisfied by two weak signals from the same detector; corroboration requires independent cross-module evidence (e.g. filesystem scanner finding + process module signal + network module signal).
- **FR-016**: Findings resulting from static/runtime correlation MUST enter the existing unified reporting pipeline (`internal/report.DetermineVerdict`) and satisfy all 8 diagnostic explainability questions.

#### Forensic Safety, Least Privilege & Namespace Handling
- **FR-017**: All runtime inspection MUST be strictly passive and read-only: no process termination (`kill`), no process suspension (`SIGSTOP`), no code injection, no file mutation, and no network packet transmission.
- **FR-018**: When running as an unprivileged user, the system MUST gracefully log permission boundaries, record coverage gaps, and emit `VerdictUnknown` with clear confidence rationales for uninspected assets.
- **FR-019**: System MUST record mount namespace IDs (`/proc/<pid>/ns/mnt`) and adjust path-based heuristic scores when inspecting processes inside container namespaces.

---

### Key Entities *(include if feature involves data)*

- **ProcessInfo**: Represents live process state including PID, PPID, UID, GID, Comm, Cmdline, Exe, Cwd, Mount Namespace, Memory Maps, Open FDs, and read-status coverage flags.
- **SocketDescriptor**: Represents a network socket record including Protocol (TCP/UDP/RAW/PACKET), Local Address & Port, Remote Address & Port, State (LISTEN, ESTABLISHED), Socket Inode, and Owning Process Link (`ProcessSocketOwner`).
- **ProcessSignal**: An individual heuristic observation on a process (rule name, score, severity, path-based flag, strong-evidence flag, reason).
- **CorrelationContext**: Cross-module evidence store mapping filesystem paths, hashes, PIDs, socket inodes, and persistence entries to evaluate cross-domain corroboration.
- **EvidenceRecord**: Complete audit trail attached to each `Finding`, capturing DetectorType, RuleName, TargetPath, PID, SocketInfo, PackageStatus, ContextProfile, EvidenceStrength, and CorroboratingSignals.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: **Suspicious Triage Accuracy**: Suspicious triage accuracy on the Feature 002 benchmark increases from 33.33% to $\ge 90.0\%$ by correctly resolving `SUSP-LISTEN-001` and `SUSP-UPGRADE-001` without manual whitelist overrides.
- **SC-002**: **Threat Recall Preservation**: Threat recall on Category B malicious benchmark threats remains at $100.00\%$ ($12/12$) across both Pure-Go and YARA-X engines.
- **SC-003**: **False-Positive Invariant**: False-positive rate on Category A benign systems and standard daemons (`sshd`, `systemd`, `cron`, `NetworkManager`) remains at $0.00\%$.
- **SC-004**: **Corroboration Defensibility**: 100% of findings escalated from `WARNING` to `ALERT` via correlation possess at least two independent operational signals across separate modules (e.g. process + network or file + process).
- **SC-005**: **Explainability Compliance**: 100% of emitted runtime and correlated findings answer all 8 standard diagnostic questions (WHAT, WHERE, WHY, EVIDENCE, CONTEXT, CORROBORATION, CONFIDENCE, REMEDIATION).
- **SC-006**: **Determinism & Reproducibility**: 10 consecutive benchmark evaluation runs on simulated runtime state yield 100% byte-for-byte identical JSON reports.
- **SC-007**: **Execution Overhead**: Complete runtime process and socket evaluation on a standard Linux workstation (up to 500 processes and 1,000 sockets) completes in under 2.0 seconds with peak memory allocation under 25 MB.
- **SC-008**: **Forensic Safety**: 0 mutating system calls, 0 process terminations, 0 ptrace attachments, and 0 network transmissions executed during runtime inspection.

---

## Assumptions

- Target Linux kernel supports standard `/proc` filesystem interfaces (`/proc/<pid>/stat`, `/proc/<pid>/cmdline`, `/proc/<pid>/exe`, `/proc/<pid>/maps`, `/proc/<pid>/fd`, `/proc/net/*`).
- When running in container environments, container runtimes mount `/proc` inside the container namespace.
- Unprivileged users have access to `/proc` for their own processes, but may receive `EACCES` when querying `/proc/<pid>/fd` or `/proc/<pid>/maps` for processes owned by other UIDs.
- Synthetic benchmark testing will utilize injectable mock filesystem and procfs abstractions (`NewModuleWithRoots`) to evaluate runtime algorithms hermetically without spawning live malicious processes.
- Non-goals: Aether is not an EDR agent, does not install kernel hooks, does not monitor processes continuously in the background, and does not execute automated containment or kill actions.
