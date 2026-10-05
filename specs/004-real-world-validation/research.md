# Research & Technical Decisions: Real-World Linux Security Assessment & Reliability Validation

**Feature**: `004-real-world-validation`
**Date**: 2026-10-04
**Status**: Completed

---

## 1. Research Topic 1: Realistic Environment Representation Strategy

### Context & Problem
Aether must be validated against 8 distinct environment classes (`desktop-standard`, `workstation-dev`, `workstation-pentest`, `server-web`, `server-minimal`, `container-host`, `package-mixed`, `upgraded-pending`). However, requiring 8 separate physical hosts, virtual machines, or live Docker daemons in automated testing creates severe disadvantages:
- Running live virtual machines or external containers requires root/privileged virtualization, slow spin-up times, and internet-dependent base image pulls, violating Aether's offline-first and hermetic test requirements.
- Relying exclusively on whatever host the developer runs on means tests are non-reproducible across developer laptops, headless CI servers, and air-gapped forensic endpoints.
- Conversely, using only tiny 1-file fixtures (as in Feature 002) fails to test real-world scale, package databases with tens of thousands of installed files, deep directory structures, and complex `/proc` states.

### Decision
Implement a **hybrid hermetic snapshot & live host evaluation strategy**:
1. **Hermetic Environment Snapshots (`testdata/realworld_corpus/<profile>/`)**:
   - Each environment profile is captured as a self-contained, read-only filesystem, package database, and mock procfs/sysfs hierarchy.
   - Realistic package database files (e.g. realistic Debian `/var/lib/dpkg/status` with 1,500+ package definitions, Arch `/var/lib/pacman/local/`, RedHat `/var/lib/rpm/`) index tens of thousands of package-owned paths.
   - Synthetic mock `/proc` hierarchies capture realistic process tables (50–200 processes with kernel threads, system daemons, user apps, container processes, mount namespaces) and socket tables (`/proc/net/tcp`, `/proc/net/udp`).
2. **In-Situ Live Host Adapter (`internal/realworld/live_adapter.go`)**:
   - For live host evaluation, Aether audits the actual running machine in read-only mode, extracting live system profile characteristics (distro, init system, package count, running services) and comparing observed findings against declared safety invariants.
3. **Execution Mode**:
   - Offline CI and standard test suites execute against the hermetic environment snapshots without root privileges and with zero external dependencies.
   - Manual or staging validation can invoke the live adapter on real workstations and servers.

### Rationale
- Completely preserves the Forensic Safety & Read-Only Invariant: zero sample execution, zero container orchestration vulnerabilities.
- Enables 100% deterministic, hermetic automated regression testing in milliseconds without spinning up heavyweight VMs.
- Accurately tests package database resolution across diverse distributions (`dpkg`, `pacman`, `rpm`).

### Alternatives Considered
- **Full QEMU/KVM Virtual Machines**: Rejected due to high overhead (minutes to boot, gigabytes of storage), inability to run in standard unprivileged containerized CI runners, and high operational friction.
- **Docker/Podman Container Workloads**: Rejected because container runtimes require root or rootless namespace privileges, depend on network image pulls, and do not model full init/systemd/kernel states accurately.
- **Static File Dumps Only**: Rejected because they lack `/proc` process links, socket tables, and package manager databases.

---

## 2. Research Topic 2: Ground-Truth Independence & Triage Distinction

### Context & Problem
If Aether evaluates its own findings without an independent standard, any false positive or false negative could simply be normalized as "expected". The validation framework must establish external ground truth for every environment profile.

### Decision
Define a declarative, schema-validated **`EnvironmentManifest` (`profile_manifest.json`)** for each profile, authored independently of Aether's internal rule names:
- **`expected_status`**: Expected overall system posture (`SAFE`, `ATTENTION REQUIRED`, `HIGH RISK`, `LIMITED VISIBILITY`).
- **`acceptable_findings`**: Whitelist of legitimate operational findings that are expected and acceptable on this profile (e.g. `Heuristic_World_Writable_In_Etc` on `/etc/motd`, `Process_Deleted_Binary_Replaced` on upgraded services, authorized dual-use tools).
- **`forbidden_findings`**: Finding types that must NEVER appear on this profile (e.g. `ALERT` findings on `desktop-standard` or `server-minimal`).
- **`expected_coverage_limits`**: Known uninspected areas when run unprivileged (e.g. `/etc/shadow`, root processes).
- **`dual_use_software`**: Explicit catalog of dual-use tools present in the profile, with their expected triage classification (passive presence -> `SAFE`/`INFO`).

### Rationale
- Ground truth is expressed in business and security terms (system status, allowed anomalies, forbidden alerts) rather than internal detection IDs.
- Discrepancies between Aether's actual verdict and the manifest are flagged as explicit validation failures, preventing silent regression.

### Alternatives Considered
- **Recorded Baseline Snapshot (Golden File Testing)**: Rejected because simply diffing against previous output enshrines existing bugs and false positives as expected baseline behavior.

---

## 3. Research Topic 3: Dual-Use Security Software Discrimination

### Context & Problem
Dual-use tools (Metasploit, Nmap, Wireshark, GDB, ExploitDB, Python HTTP test servers, netcat, socat) contain code strings, shell redirection logic, and network socket code that closely resemble malware. Security researchers, developers, and pentesting workstations legitimate install these tools. Aether must distinguish passive installation from active weaponization.

### Decision
Codify a 4-dimensional **Dual-Use Discrimination Matrix**:
1. **Spatial / Package Context**:
   - Files residing in standard package locations (`/usr/share/metasploit-framework`, `/usr/share/exploitdb`, `/usr/share/nmap`) or verified by `pkgdb` are tagged with `pentest_tool_path = true`.
   - In `internal/report/verdict.go`, passive files in these paths are classified as `VerdictSafe` with `INFO` severity (`"Authorized penetration testing tool located in standard pentest package path"`).
2. **Execution State**:
   - A passive script on disk in `/usr/share/...` remains `INFO`/`VerdictSafe`.
   - If the script is actively executing as a running process, it transitions to `WARNING`/`VerdictSuspicious`.
3. **Operational Corroboration**:
   - If the executing dual-use tool is linked to an unmapped external wildcard listener, an outbound interactive reverse shell pipe (`/dev/tcp` or `/bin/sh`), or an autostart persistence mechanism (cron, systemd), the cross-domain correlation engine elevates it to `ALERT` (`VerdictMalicious`, `StrengthCorroborated`).
4. **Localhost / Development Servers**:
   - Ephemeral Python development servers (`python3 -m http.server`) listening strictly on `127.0.0.1` are classified as `VerdictSafe` (`INFO`, `Network_Loopback_Listener`).
   - If bound to wildcard `0.0.0.0` without package ownership, they are classified as `VerdictSuspicious` (`WARNING`) with `ConfidenceMedium`, prompting administrative awareness without raising a compromise alert.

### Rationale
- Completely eliminates false `ALERT` alarms on Kali Linux, pentest environments, and developer workstations.
- Accurately catches actual weaponization (e.g., an adversary using `nc` or `python` for a live reverse shell).

### Alternatives Considered
- **Blanket Allowlist for Tool Names**: Rejected because attackers frequently abuse installed `nc`, `nmap`, or `python` to execute living-off-the-land attacks (LotL). Blanket allowlisting creates massive blind spots.
- **Ignoring Tool Presence Entirely**: Rejected because administrators need visibility into unauthorized dual-use tools installed on sensitive production servers.

---

## 4. Research Topic 4: Runtime Race & Dynamic State Simulation

### Context & Problem
During a live system scan, processes terminate in milliseconds, sockets close, and temporary files vanish. When Aether encounters `ENOENT` while inspecting `/proc/<pid>/exe`, `/proc/<pid>/fd`, or `/proc/net/tcp`, it must not crash, panic, or log misleading errors. Furthermore, a vanished process must never be misclassified as an evasive "hidden process" or "deleted executable malware".

### Decision
1. **Atomic Procfs Traversal Pattern**:
   - In `internal/modules/process/procfs.go` and `internal/modules/network/network.go`, wrap all `/proc` symlink and stat operations in `os.IsNotExist(err)` and `safeopen.ErrVanished` checks.
   - Categorize vanished entries immediately under `coverage.SkippedVanished++`.
   - Never generate findings on targets where the initial stat succeeded but `/proc/<pid>/stat` or `/proc/<pid>/cmdline` disappeared before verification.
2. **Hermetic Dynamic Race Simulation Harness (`internal/realworld/race_harness.go`)**:
   - A dedicated concurrent test harness that spawns high-churn goroutines creating and deleting temporary files, opening and closing ephemeral local sockets, and launching short-lived worker commands while Aether's scanner runs concurrently.
   - Asserts:
     - 0 panics / crashes.
     - 0 false `ALERT` findings.
     - `SkippedVanished > 0` accurately reflecting handled churn.
     - Deterministic scan completion without hangs.

### Rationale
- Eliminates brittle assumptions about static OS state.
- Formally validates Aether's thread-safety and error-trapping resilience under heavy Linux multitasking loads.

### Alternatives Considered
- **Freezing Host Processes via SIGSTOP**: Rejected because freezing processes requires root privileges, destabilizes host services, and cannot be used in defensive audits.

---

## 5. Research Topic 5: Scale, Performance & Memory Profiling

### Context & Problem
Real-world systems contain 50,000 to 500,000+ files and thousands of processes. If Aether leaks memory during large directory walks or spends excessive time in regex compilation or YARA execution, it will be terminated by the Linux OOM killer or abandoned by users.

### Decision
1. **Standardized Benchmark Hardware Profile**:
   - Specify a reference baseline environment (e.g. 4-core x86_64 / ARM64, 4GB RAM, NVMe/SATA SSD) to ensure performance measurements are grounded and comparable across runs.
2. **Subsystem Duration Breakdown**:
   - Implement fine-grained duration instrumentation in `events.ScanFinished` and `events.ModuleFinished` recording:
     - `DurationFilesystemWalk`: directory traversal and stat overhead.
     - `DurationHashing`: SHA-256 / MD5 streaming calculation.
     - `DurationHeuristics`: pure-Go AST and regex matching.
     - `DurationYARA`: YARA-X compiled rule scanning.
     - `DurationProcess`: `/proc` enumeration and memory map inspection.
     - `DurationNetwork`: `/proc/net` parsing and inode resolution.
     - `DurationCorrelation`: cross-domain correlation pass.
     - `DurationReporting`: format rendering (plain, HTML, JSON).
3. **Memory Budget Verification**:
   - Track `runtime.MemStats.Alloc`, `TotalAlloc`, and `Sys` alongside peak resident set size (RSS) via `/proc/self/statm`.
   - Verify that peak RSS never exceeds `config.Config.Scan.MaxFileSize` bounds plus base memory budget (default $\le 250\text{MB}$).

### Rationale
- Gives engineers actionable profiling data to target specific bottlenecks (e.g. regex compilation vs hashing) without guessing.
- Guarantees host safety on memory-constrained Linux virtual machines.

---

## 6. Research Topic 6: False-Positive & False-Negative Taxonomy

### Context & Problem
Field discoveries must not be handled ad-hoc. Detection engineering requires structured root-cause classification and a permanent pipeline converting field anomalies into hermetic regression tests.

### Decision
Establish the standard **Aether Anomaly Taxonomy**:
- **False Positives (FP)**:
  - `FP_MISSING_CONTEXT`: Rule matched a benign script/binary lacking context (e.g. documentation, wheel metadata).
  - `FP_WEAK_HEURISTIC`: Regex or pattern too generic for Linux ecosystem diversity.
  - `FP_DUAL_USE_TOOL`: Legitimate pentest/admin/debugger utility misidentified as malware.
  - `FP_PACKAGE_MISMATCH`: File belongs to an unmanaged or local package not indexed by `pkgdb`.
  - `FP_RUNTIME_RACE`: Vanishing process or closed socket misinterpreted as evasive hiding.
  - `FP_NAMESPACE_ISOLATION`: Containerized path evaluated with host filesystem assumptions.
  - `FP_ENVIRONMENTAL`: Harmless distribution-specific idiosyncrasy in `/etc`.
- **False Negatives (FN)**:
  - `FN_COLLECTION_GAP`: Evidence existed but was skipped (e.g. size cutoff, path exclude).
  - `FN_DETECTOR_GAP`: Evidence collected but no heuristic or YARA rule matched.
  - `FN_CONTEXT_SUPPRESSION`: Over-aggressive package or doc context suppressed genuine threat.
  - `FN_CORRELATION_GAP`: Multi-vector signals failed to link due to path/inode normalization error.
  - `FN_PERMISSION_LIMITATION`: Target was unreadable due to DAC/EACCES (properly classified as UNKNOWN).

### Regression Capture Pipeline:
```
Field Anomaly Identified
       ↓
Taxonomy Categorization (FP_* or FN_*)
       ↓
Minimal Inert Fixture Created (in testdata/realworld_corpus/regressions/)
       ↓
Hermetic Unit / Benchmark Test Added
       ↓
Automated CI Verification (go test ./...)
```

### Rationale
- Ensures that every real-world bug or false alarm fixed in Aether is permanently immunized against regression.
- Isolates real-world regression fixtures from the immutable Feature 002/003 controlled benchmark suite.

