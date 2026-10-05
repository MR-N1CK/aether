# Research: Feature 003 — Runtime Threat Assessment & Static/Runtime Correlation

**Feature Branch**: `003-runtime-threat-assessment`
**Status**: Complete
**Ratification Date**: 2026-10-03

---

## 1. Current Runtime Capability Audit

| Module / Component | Existing Capability | Current Limitation / Gap | Reusability in Feature 003 |
| :--- | :--- | :--- | :--- |
| [`internal/modules/process`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/modules/process) | Enumerates `/proc`, parses stat/cmdline/maps/ns, detects unlinked binaries, temp exec, memfd ELF magic, masquerading, root user-writable exe, hidden PIDs. | Emits isolated process findings; no cross-link to static scanner findings or persistence configs. | **Directly Reusable**: Serves as core process collector. |
| [`internal/modules/network`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/modules/network) | Parses `/proc/net/*` (TCP, UDP, RAW, PACKET), maps socket inodes to PID via `/proc/<pid>/fd`, evaluates wildcard listeners and C2 matches. | Emits isolated network findings; does not share context with filesystem scanner. | **Directly Reusable**: Serves as core socket/listener collector. |
| [`internal/modules/persistence`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/modules/persistence) | Audits cron, systemd, shell profiles, SSH keys, PAM, loader configs. | Does not verify whether persisted binaries are currently active in memory. | **Directly Reusable**: Targets can be correlated with live process executables. |
| [`internal/scanner`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/scanner) | High-performance filesystem traversal, AST heuristics, YARA scanning, file hashing. | Passive filesystem only; cannot observe running state or listening ports. | **Directly Reusable**: Static findings provide baseline evidence for correlation. |
| [`internal/report/verdict.go`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/report/verdict.go) | `DetermineVerdict`, `EvaluateEvidenceStrength`, tiered confidence (`StrengthDirect`, `StrengthCorroborated`, `StrengthContextual`, `StrengthIncomplete`). | `corroboration []string` parameter exists but was previously populated manually rather than via an automated correlation engine. | **Directly Reusable & Central**: The unified verdict authority for both static and runtime findings. |
| [`internal/benchmark`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/benchmark) | Independent measurement harness evaluating contracts across 21 test cases. | Evaluated filesystem findings only; lacked mock runtime procfs injection for `SUSP-LISTEN-001` and `SUSP-UPGRADE-001`. | **Directly Reusable**: Extend loader to support mock procfs fixtures. |

---

## 2. Key Technical Decisions & Alternatives Considered

### Decision 1: Unified Static/Runtime Correlation Engine Location
- **Decision**: Implement the cross-module correlator in [`internal/report/correlate.go`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/report/correlate.go) as a post-accumulation reconciliation pass within the existing report pipeline.
- **Rationale**:
  - Aether's architecture routes all findings from `scanner` and `modules` into `report.FindingAccumulator` before rendering.
  - Placing correlation in `internal/report` prevents circular dependencies between `scanner`, `process`, `network`, and `persistence`.
  - All findings can be indexed into an in-memory `CorrelationIndex` (keyed by normalized path, SHA-256 hash, PID, and socket inode) in $O(N)$ time with minimal memory overhead (<100KB).
- **Alternatives Considered**:
  - *Inter-module event bus coordination during scanning*: Complex state management across concurrent goroutines, prone to race conditions and non-deterministic finding arrival order.
  - *Separate correlation daemon or background worker*: Violates Principle II (Least Privilege) and Principle IV (Preserve Existing Architecture).

---

### Decision 2: Multi-Vector Corroboration Standard
- **Decision**: Define strict cross-domain corroboration rules. A finding is elevated from `StrengthContextual` to `StrengthCorroborated` **only** when corroborated by an independent signal from a **different domain**:
  $$\text{Corroboration} \iff \text{Domain}_1 \cap \text{Domain}_2 \neq \emptyset \quad (\text{where Domains } \in \{\text{Filesystem/Script}, \text{Process/Memory}, \text{Network/Socket}, \text{Persistence}\})$$
- **Rationale**:
  - Multiple weak heuristic hits from the same file (e.g. two regex matches in a bash script) do **not** constitute operational corroboration.
  - True corroboration requires cross-layer confirmation: a suspicious script file on disk + a running process executing that file + an active listening socket or established C2 connection.
  - Prevents alert inflation while guaranteeing high-confidence `MALICIOUS` verdicts on multi-stage compromises.
- **Alternatives Considered**:
  - *Score addition without domain checks*: Risky; could allow two low-confidence AST regex matches on a benign admin script to reach the `ALERT` threshold.

---

### Decision 3: Preserving Tier 1 Direct Strong Evidence Without Mandatory Corroboration
- **Decision**: Reaffirm that `StrengthDirect` evidence (e.g. cryptographic IOC hash match, confirmed reverse shell, in-memory ELF injection `Process_Fileless_Memory_ELF`, unauthorized UID 0 backdoor account) independently supports `VerdictMalicious` (`ALERT`, `ConfidenceHigh`) without requiring runtime or network corroboration.
- **Rationale**:
  - Direct evidence is unambiguous proof of threat intent. Requiring a reverse shell script or ransomware locker to also be actively running at the exact millisecond Aether executes would create unacceptable false negatives against dormant or staging payloads.
- **Alternatives Considered**:
  - *Mandatory runtime execution for all ALERTs*: Disastrous for threat hunting; attackers could evade detection simply by pausing processes during scans.

---

### Decision 4: Hermetic Mock Runtime State for Benchmark Evaluation
- **Decision**: Extend `BenchmarkCorpusCase` in `internal/benchmark/types.go` with optional synthetic runtime descriptors (`MockProcesses`, `MockSockets`), and utilize `NewModuleWithRoots` to target simulated `/proc` directory fixtures during benchmark execution.
- **Rationale**:
  - In accordance with Principle XI (Static Analysis Invariant) and Forensic Safety, Aether must **never** execute real malware samples (e.g. spawning `nc -lvnp 4444` or unlinking running binaries) in the test environment.
  - Synthetic `/proc` and `/proc/net` directory structures are 100% deterministic, hermetic, cross-platform compatible, and reproduce the exact runtime states of `SUSP-LISTEN-001` and `SUSP-UPGRADE-001`.
- **Alternatives Considered**:
  - *Spawning dummy background test processes during `go test`*: Non-deterministic, requires host root privileges for some socket types, leaves dangling child processes, and introduces flaky port conflicts on CI servers.

---

### Decision 5: Non-Root Privilege Degradation & Transparent Abstention
- **Decision**: When `/proc/<pid>/exe`, `/proc/<pid>/maps`, or `/proc/<pid>/fd` return `EACCES` or `EPERM` during unprivileged execution, record atomic counters in `ProcessCoverage` / `NetworkCoverage`, attach `EvidenceRecord.EvidenceStrength = StrengthIncomplete`, assign `VerdictUnknown`, and explain the limitation in `ConfidenceRationale`.
- **Rationale**:
  - Prevents misleading security guarantees (`SAFE`) on processes that could not be audited.
  - Prevents speculative `MALICIOUS` accusations against inaccessible system processes.
  - Complies with Feature 001 and 002 abstention accuracy standards (`UNKNOWN != SAFE`).

---

### Decision 6: Container & Namespace Score Calibration
- **Decision**: Compare `/proc/<pid>/ns/mnt` against Aether's invoking mount namespace (`selfMntNs`). When inspecting processes in container namespaces:
  - Path-based heuristics (e.g. `Process_Exe_Or_Cwd_In_Temp`, `Process_Deleted_Binary_Home`) apply configurable container score reductions (`cfg.Scan.ContainerScoreReduction`, default 20 points).
  - Direct threat detections (`Process_Fileless_Memory_ELF`, IOC matches, rootkit hooks) remain at full severity without reduction.
  - `Metadata["container"] = true` and `Metadata["mnt_ns"] = info.MntNs` are recorded for explainability.
- **Rationale**:
  - Container images frequently use non-standard base paths (e.g. `/app`, `/tmp`) as standard operational directories.
  - Distinguishing container namespaces eliminates false positive noise while preserving detection of active container escapes and in-memory payloads.
