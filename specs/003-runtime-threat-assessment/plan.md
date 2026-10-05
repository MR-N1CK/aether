# Implementation Plan: Aether Runtime Threat Assessment & Static/Runtime Correlation

**Branch**: `003-runtime-threat-assessment` | **Date**: 2026-10-03 | **Spec**: [spec.md](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/specs/003-runtime-threat-assessment/spec.md)

---

## 1. Summary

This plan defines the architectural design and execution strategy for **Feature 003: Runtime Threat Assessment & Static/Runtime Correlation**.

Building upon Feature 001 (*Trustworthy Detection & False-Positive Control*) and Feature 002 (*Detection Accuracy & Validation Benchmark*), this feature extends Aether from a static-only analyzer into a unified **Static + Runtime Security Assessment Engine**. It introduces an automated cross-module Correlation Engine that binds static filesystem and persistence findings with live process, memory, and network socket observations. It directly resolves the measured Suspicious Triage Accuracy gap on `SUSP-LISTEN-001` (unmapped wildcard listeners) and `SUSP-UPGRADE-001` (post-upgrade running deleted binaries) through hermetic, non-executing synthetic runtime fixtures while preserving all forensic safety and read-only invariants.

$$\text{STATIC EVIDENCE} + \text{RUNTIME EVIDENCE} + \text{CONTEXT} + \text{INDEPENDENT CORROBORATION} = \text{TRUSTWORTHY ASSESSMENT}$$

---

## 2. Technical Context

- **Language/Version**: Go 1.22+ (Strictly adhering to Pure-Go standard build `CGO_ENABLED=0` and optional YARA-X CGO `-tags yara`).
- **Primary Dependencies**: Existing standard library (`os`, `syscall`, `path/filepath`, `strings`, `sync/atomic`, `time`, `encoding/json`), `internal/safeopen`, `internal/pkgdb`, `internal/ioc`, `internal/report`, `internal/events`.
- **Target Platform**: Linux 3.10+ (x86_64, ARM64) with standard `/proc` and `/proc/net` filesystem interfaces.
- **Constraints**:
  - **Forensic Safety**: 100% passive and read-only; 0 process terminations (`kill`), 0 `ptrace` attachments, 0 memory injections, 0 payload executions, 0 socket transmissions.
  - **Least Privilege**: Clean degradation under non-root users (`EACCES`/`EPERM` -> `UNKNOWN` / `limited_visibility` without false `SAFE` or speculative `MALICIOUS`).
  - **Performance**: Full runtime evaluation (< 500 processes, < 1,000 sockets) completes in < 2.0s with memory allocation bounded < 25 MB.
  - **Determinism**: 100% byte-for-byte reproducible JSON serialization on static and simulated runtime snapshots.

---

## 3. Constitution & Quality Gates Check

| Principle / Invariant | Status | Architectural Compliance Rationale |
| :--- | :---: | :--- |
| **I. Forensic Safety & Read-Only Invariant** | ✅ PASS | All `/proc` inspection uses read-only calls and `safeopen`. Zero syscall mutation, zero process signaling, zero file mtime modification. |
| **II. Least Privilege & Security-First** | ✅ PASS | Unprivileged execution records coverage gaps without panics; non-root constraints map to `VerdictUnknown`. |
| **III. Offline-First & Zero Telemetry** | ✅ PASS | Zero outbound network calls; offline local socket table parsing only. |
| **IV. Preserve Existing Architecture** | ✅ PASS | Reuses `internal/modules/process`, `internal/modules/network`, and `internal/report/verdict.go`. No second verdict engine. |
| **V. Detection Integrity & Scoring** | ✅ PASS | Adheres to strict scoring (`ALERT` $\ge 85$, `WARNING` 50–84, `NOTICE` 20–49, `INFO` 0–19). Tier 1 direct strong evidence preserved. |
| **VI. Mandatory MITRE & Remediation** | ✅ PASS | All runtime and correlated rules registered in `internal/report/finding.go` with WHAT, WHERE, WHY, MITRE, and REMEDIATION. |
| **VII. Test Integrity & Verification** | ✅ PASS | 100% test pass rate required; hermetic synthetic runtime fixtures used in benchmark. |
| **VIII. Executive Studio UI Contract** | ✅ PASS | Output formatted with theme tokens into MALICIOUS, SUSPICIOUS, and SAFE categories across plain, TUI, JSON, and HTML. |
| **XI. AI Safety Protocol & Static Analysis Invariant** | ✅ PASS | Zero sample execution during development and testing; mocked procfs structures used instead of live malware processes. |

---

## 4. Current Runtime Capability Assessment & Reuse Map

### Codebase Audit Summary
1. **Process Inspection** ([`internal/modules/process`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/modules/process)):
   - *Existing*: `/proc` scanning, stat parsing, unlinked binary detection (`CheckDeletedExe`), temp execution (`CheckExeOrCwdInTemp`), fileless memfd inspection with ELF magic checks (`CheckFilelessExecution`), masquerading (`CheckMasquerading`), root user-writable exe (`CheckRootWritableExe`), hidden PIDs (`CheckHiddenPIDsWithTimings`), container mount namespace adjustment (`ApplyContainerScoreAdjustment`).
   - *Reuse*: 100% reused as the core process assessment module.
2. **Network Inspection** ([`internal/modules/network`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/modules/network)):
   - *Existing*: `/proc/net/*` parsing (`ParseAllSockets`), socket inode to process mapping (`BuildSocketProcessMap`), wildcard listener detection, C2 hash checking.
   - *Reuse*: 100% reused as the core socket assessment module.
3. **Persistence Auditing** ([`internal/modules/persistence`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/modules/persistence)):
   - *Existing*: Cron, systemd units, shell profiles, SSH authorized keys, PAM hooks.
   - *Reuse*: Target paths emitted by persistence checks feed the correlation index.
4. **Unified Verdict Engine** ([`internal/report/verdict.go`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/report/verdict.go)):
   - *Existing*: `DetermineVerdict`, `EvaluateEvidenceStrength`, `EvidenceRecord` structure.
   - *Extension*: Automated population of `EvidenceRecord.CorroboratingSignals` and `EvidenceRecord.EvidenceStrength` via cross-module correlation.

---

## 5. Architectural Designs

### 5.1 Runtime Evidence Architecture
All runtime observations (processes, memory mappings, network sockets) are translated into standard `report.Finding` records enriched with `EvidenceRecord` structures:

```go
type EvidenceRecord struct {
    DetectorType         string                `json:"detector_type"`
    RuleName             string                `json:"rule_name"`
    TargetPath           string                `json:"target_path"`
    PID                  int                   `json:"pid,omitempty"`
    Comm                 string                `json:"comm,omitempty"`
    Cmdline              string                `json:"cmdline,omitempty"`
    SocketInfo           string                `json:"socket_info,omitempty"`
    MountNamespace       string                `json:"mount_namespace,omitempty"`
    PackageName          string                `json:"package_name,omitempty"`
    PackageStatus        string                `json:"package_status"`
    ContextProfile       string                `json:"context_profile"`
    EvidenceStrength     EvidenceStrength      `json:"evidence_strength"`
    ConfidenceRationale  string                `json:"confidence_rationale"`
    CorroboratingSignals []string              `json:"corroborating_signals,omitempty"`
    CorroborationDetails []CorroboratingSignal `json:"corroboration_details,omitempty"`
}
```

---

### 5.2 Cross-Module Static & Runtime Correlation Engine
The Correlation Engine ([`internal/report/correlate.go`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/report/correlate.go)) operates on the complete set of accumulated findings in a single $O(N)$ pass prior to final report generation:

```
+-----------------------------------------------------------------------------------+
|                        CORRELATION RECONCILIATION PASS                            |
|                                                                                   |
| 1. Build Index:                                                                   |
|    - PathIndex:   normalized_path -> []*Finding                                   |
|    - HashIndex:   sha256_hash     -> []*Finding                                   |
|    - PIDIndex:    pid             -> []*Finding                                   |
|    - SocketIndex: socket_inode    -> []*Finding                                   |
|                                                                                   |
| 2. Detect Cross-Domain Links:                                                     |
|    - If Finding(Filesystem) matches Finding(Process) by ExePath or SHA256:       |
|      -> Attach Process corroboration to Filesystem Finding                        |
|    - If Finding(Process) matches Finding(Network) by PID or SocketInode:          |
|      -> Attach Network listener corroboration to Process Finding                  |
|    - If Finding(Persistence) matches Finding(Process) by ExecutableTarget:        |
|      -> Attach Persistence corroboration to Process Finding                       |
|                                                                                   |
| 3. Evaluate Domain Multipliers:                                                   |
|    - If len(UniqueDomains) >= 2 AND BaseSeverity >= WARNING:                     |
|      -> EvidenceStrength = StrengthCorroborated                                   |
|      -> DetermineVerdict promotes to VerdictMalicious (ALERT, HIGH confidence)    |
|                                                                                   |
| 4. Deduplicate Findings:                                                          |
|    - Consolidate auxiliary findings into Primary Threat Finding to prevent        |
|      duplicate alert inflation.                                                   |
+-----------------------------------------------------------------------------------+
```

---

### 5.3 Namespace & Container Context Handling
- Compare `/proc/<pid>/ns/mnt` against the scanner process's mount namespace (`selfMntNs`).
- If `info.MntNs != selfMntNs`, mark `ContextProfile = "container_namespace"`.
- Path-based heuristics apply container score reduction (`cfg.Scan.ContainerScoreReduction`, default 20) to prevent false alerts on container-internal temporary paths.
- Direct threat rules (`Process_Fileless_Memory_ELF`, confirmed reverse shells, cryptographic IOCs) remain unaffected by namespace reductions.

---

### 5.4 Privilege Boundaries & Transparent Abstention
- Non-root audit constraints (`EACCES`/`EPERM` on `/proc/<pid>/exe`, `/proc/<pid>/maps`, `/proc/<pid>/fd`) are trapped and incremented in `ProcessCoverage` / `NetworkCoverage`.
- Findings generated on partially readable processes receive `EvidenceStrength = StrengthIncomplete`, `Verdict = VerdictUnknown`, `Severity = SeverityInfo`, and `Confidence = ConfidenceLow`.
- Confidence rationales explicitly state: *"Insufficient visibility due to permission constraints (requires elevated root / CAP_DAC_OVERRIDE)."*

---

### 5.5 Feature 002 Benchmark Integration & Hermetic Fixtures
To evaluate `SUSP-LISTEN-001` and `SUSP-UPGRADE-001` without executing live binaries:
1. Extend `BenchmarkCorpusCase` in [`internal/benchmark/types.go`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/benchmark/types.go) with `MockProcRoot` pointing to synthetic `/proc` test trees in `testdata/benchmark_corpus/`.
2. For `SUSP-LISTEN-001`: Provide synthetic `/proc` tree containing PID 1337 (`dev_server.py`), `/proc/1337/fd/3 -> socket:[99999]`, and `/proc/net/tcp` entry for `0.0.0.0:4444`.
3. For `SUSP-UPGRADE-001`: Provide synthetic `/proc` tree containing PID 1042 (`/usr/sbin/deleted_daemon (deleted)`), with new binary present on disk with different inode.
4. Benchmark runner instantiates `process.NewModuleWithRoots` and `network.NewModuleWithRoots` targeting mock proc roots, asserting exact contract compliance.

---

## 6. Project Structure & File Changes

```text
specs/003-runtime-threat-assessment/
├── spec.md                                     # Ratified feature specification
├── plan.md                                     # This implementation plan
├── research.md                                 # Phase 0 technical decisions
├── data-model.md                               # Phase 1 entity definitions & state machine
├── quickstart.md                               # Phase 1 validation walkthrough
├── contracts/
│   ├── runtime-finding-schema.json             # JSON schema for runtime findings
│   ├── correlation-context-schema.json         # JSON schema for correlation records
│   └── benchmark-runtime-schema.json           # JSON schema for synthetic benchmark fixtures
└── checklists/
    └── requirements.md                         # Quality validation checklist
```

### Source Code Modifications

| Action | File Path | Component | Description |
| :--- | :--- | :--- | :--- |
| **[NEW]** | [`internal/report/correlate.go`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/report/correlate.go) | `report` | Core Static/Runtime Correlation Engine and finding reconciler. |
| **[NEW]** | [`internal/report/correlate_test.go`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/report/correlate_test.go) | `report` | Unit tests for cross-module correlation, deduplication, and corroboration scoring. |
| **[MODIFY]** | [`internal/report/finding.go`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/report/finding.go) | `report` | Add MITRE ATT&CK registrations for runtime findings; add runtime explainability fields. |
| **[MODIFY]** | [`internal/report/verdict.go`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/report/verdict.go) | `report` | Integrate automated corroboration records and container context profile. |
| **[MODIFY]** | [`internal/benchmark/types.go`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/benchmark/types.go) | `benchmark` | Add `MockProcRoot` and runtime fixtures support to `BenchmarkCorpusCase`. |
| **[MODIFY]** | [`internal/benchmark/loader.go`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/benchmark/loader.go) | `benchmark` | Support loading and normalizing companion synthetic procfs trees. |
| **[MODIFY]** | [`test/benchmark/benchmark_test.go`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/test/benchmark/benchmark_test.go) | `benchmark` | Update `TestCategoryC_Suspicious` to execute process & network modules against synthetic proc roots for `SUSP-LISTEN-001` and `SUSP-UPGRADE-001`. |
| **[NEW]** | `testdata/benchmark_corpus/suspicious/03_unmapped_listeners/mock_proc/...` | `fixtures` | Hermetic synthetic `/proc` and `/proc/net/tcp` fixture for `SUSP-LISTEN-001`. |
| **[NEW]** | `testdata/benchmark_corpus/suspicious/02_deleted_binaries_upgraded/mock_proc/...` | `fixtures` | Hermetic synthetic `/proc` fixture for `SUSP-UPGRADE-001`. |

---

## 7. Implementation Phases & Validation Strategy

### Phase 1: Correlation Engine Implementation
1. Create [`internal/report/correlate.go`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/report/correlate.go) with `CorrelateFindings(findings []*Finding, pkgDB pkgdb.PackageDB) []*Finding`.
2. Build indexing logic: path, hash, PID, socket inode.
3. Apply cross-domain corroboration rules and update `EvidenceStrength` / `CorroboratingSignals`.
4. Validate with unit tests in [`internal/report/correlate_test.go`](file:///home/nick/Documents/doc/tools/WORKING_TOOLS/Aether/internal/report/correlate_test.go).

### Phase 2: Runtime Explainability & MITRE Enrichment
1. Register all runtime and socket rule names in `internal/report/finding.go` (`PopulateFindingDetails`).
2. Ensure 100% compliance with 8-question explainability (WHAT, WHERE, WHY, EVIDENCE, CONTEXT, CORROBORATION, CONFIDENCE, REMEDIATION).

### Phase 3: Benchmark Extension & Synthetic Fixture Integration
1. Construct hermetic synthetic procfs directories for `SUSP-LISTEN-001` and `SUSP-UPGRADE-001`.
2. Wire `BenchmarkCorpusCase.MockProcRoot` into `loader.go` and `benchmark_test.go`.
3. Verify `SUSP-LISTEN-001` -> `VerdictSuspicious` (`WARNING`) and `SUSP-UPGRADE-001` -> `VerdictSafe`/`VerdictNotice` (`NOTICE`).

### Phase 4: Full Verification & Acceptance Gate Validation
1. Run `go test ./...` across all packages.
2. Run `go test -tags yara ./...`.
3. Run `make benchmark` and verify:
   - Threat Recall $= 100.00\%$
   - Precision $= 100.00\%$
   - Category A FPR $= 0.00\%$
   - Suspicious Triage Accuracy $\ge 90.00\%$
   - Abstention Accuracy $= 100.00\%$
   - Explainability $= 100.00\%$
   - Determinism $= 100.00\%$

---

## 8. Validation Commands

```bash
# 1. Run unit test suite
go test -v ./internal/report/... ./internal/modules/process/... ./internal/modules/network/...

# 2. Run benchmark suite (Pure-Go)
go test -v -count=1 ./test/benchmark/...

# 3. Run benchmark suite (YARA-X)
go test -v -tags yara -count=1 ./test/benchmark/...

# 4. Verify 10-run determinism
go test -v -run TestDeterminism_10ConcurrentRuns ./test/benchmark/...

# 5. Full repository verification
go test ./...
```

---

## 9. Risks and Mitigations

| Risk | Impact | Mitigation Strategy |
| :--- | :---: | :--- |
| **Process Vanishing Race Conditions** | Medium | Gracefully catch `ErrProcessVanished` / `os.ErrNotExist` during procfs reads; increment `SkippedVanished` counter without error crashing. |
| **Alert Inflation from Dual Signals** | High | Consolidate cross-module findings into a single primary `Finding` record with attached `CorroboratingSignals` rather than emitting duplicate findings for the same PID. |
| **Flaky Network Tests in CI** | High | Strictly avoid binding real network ports or querying host network state during automated unit tests; use injectable rootFS/procRoot abstractions (`NewModuleWithRoots`). |
| **Large `/proc/net` Tables** | Low | Parse socket tables in single streaming passes with bounded memory allocations. |

---

## 10. Explicit Non-Goals

- **No EDR Background Daemon**: Aether does not run as a resident background service.
- **No Active Process Termination**: Aether will never terminate (`kill`), suspend (`SIGSTOP`), or modify processes.
- **No Automated Remediation**: Remediation guidance is provided for human analysts; no files or configs will be deleted or edited.
- **No Live Payload Detonation**: Zero live malware binaries will be executed in testing or production.
