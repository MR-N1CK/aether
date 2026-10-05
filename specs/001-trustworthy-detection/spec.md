# Feature Specification: Trustworthy Detection & False-Positive Control

**Feature Branch**: `001-trustworthy-detection`  
**Created**: 2026-10-03  
**Status**: Revised  
**Input**: User description: "Aether must prioritize trustworthy detection over the number of detections. The goal is NOT to maximize the number of findings. The goal is to make every high-severity finding defensible, evidence-backed, explainable, reproducible, and resistant to false positives."

---

## Existing System Audit & Architectural Assessment

An in-depth static audit of the existing Aether engine was conducted across `internal/scanner`, `internal/report`, `internal/pkgdb`, `internal/triage`, `internal/ioc`, `internal/yara`, `internal/modules/*`, and `internal/config`.

### 1. Existing Capabilities vs. Critical Gaps

| Component | Current Implementation | Correct Aspects | Gaps & False-Positive Risks |
| :--- | :--- | :--- | :--- |
| **Finding Model** (`internal/report/finding.go`) | Struct with `Severity` (`ALERT`, `WARNING`, `NOTICE`, `INFO`) and `Confidence` (`HIGH`, `MEDIUM`, `LOW`). `PopulateFindingDetails()` enriches MITRE ATT&CK, Title, and Remediation. | MITRE enrichment is structured, human-readable, and well-typed. | **Score equals Verdict**: `Confidence` defaults directly from `Severity` (`ALERT` $\to$ `HIGH`, `WARNING` $\to$ `MEDIUM`). An isolated regex or YARA hit automatically displays as a top-level red alert without checking corroboration or environmental context. |
| **Heuristics Engine** (`internal/scanner/heuristics.go`) | Single-pass regex/AST checks for ELF-in-temp, SUID, private keys, reverse shells, webshells, ransomware, exfiltration, and droppers. | Pure-Go build independence; build-tree downgrades (`CheckBuildTree`) work effectively for known build markers. | Pure-Go checks check `pkgDB` at entry point, but lack multi-signal corroboration. Weak single regexes (e.g. `curl \| sh`) fire on harmless setup scripts. |
| **YARA Engine** (`internal/yara/embedded_rules.go`) | 13 embedded YARA-X rules for Linux backdoors, webshells, droppers, and rootkits. | Fast single-pass evaluation, compiled YARA-X integration, isolated test fixtures. | **Zero package awareness**: The YARA engine does not query `pkgdb.PackageDB`. Scans against `/usr/lib/python3` produce false positives on standard library test fixtures (e.g. `cheroot`, `joblib`, `twisted`) and metadata files (`elasticsearch.dist-info/METADATA`). |
| **Package DB** (`internal/pkgdb/pkgdb.go`) | Pure-Go parser for Debian (`dpkg`) and Arch (`pacman`) databases with merged `/usr` path normalization. | Fast in-memory map lookup, path normalization. | Treated as a binary toggle (`return nil` in heuristics), which risks hiding genuine trojanized files if modified, while being completely bypassed by YARA. |
| **Triage & Ack** (`internal/triage/triage.go`) | SHA-256 pinning of files, lines, and symlink targets (`aether ack`). | Cryptographically robust; auto-voids if files change; forbids acking ALERT/IOCs. | Suppression only happens post-scan if an operator manually acks; does not prevent initial false-positive alarms. |
| **IOC Engine** (`internal/ioc/ioc.go`) | O(1) hash matching, regex path matching, CIDR IP matching, and `known_benign.yaml` pattern suppression. | Fast lookups, owner UID verification (`OwnerMatchesNameUID`). | Path-based benign patterns are static and don't evaluate execution contexts (e.g. whether a file is an inert `.txt`/`.md` documentation file vs. an executable binary). |
| **Persistence & Modules** (`internal/modules/*`) | Specialized audits for `kernel`, `network`, `persistence`, `process`, `users`. | Deep inspections (`memfd:`, unlinked executables, socket mapping, hidden PIDs, UID 0 accounts). | Multi-vector persistence correlation (`correlateMultiVectorPersistence`) exists only in the persistence module; scanner lacks a unified engine-wide evidence corroboration layer. |

---

## Core Detection Principles

1. **Trustworthy Detection Over Raw Volume**: Aether measures efficacy by the precision, defensibility, and reproducibility of its findings—never by raw finding counts.
2. **Strict Conceptual Separation**: The engine MUST NOT collapse analytical stages into an opaque score:
   - **Observation**: An empirical fact discovered during scan (e.g. file `/tmp/stage.sh` exists with mode `0755` containing byte sequence `curl -s ... | bash`).
   - **Evidence**: Concrete provenance attributes (path, cryptographic SHA-256, UID/GID, mode, line numbers, package ownership, matching rule).
   - **Detection**: A signature or heuristic rule flagging the evidence as matching a known threat pattern.
   - **Context**: Environmental metadata (package ownership, installation directory, file extension, whether the file is documentation/test fixture or executable script).
   - **Corroboration**: Independent verifying signals supporting the same threat hypothesis (e.g. an executable script with an active open network socket or a systemd persistence hook).
   - **Confidence**: The mathematical/logical certainty that the observed behavior represents genuine malice, calculated independently from severity.
   - **Severity**: The potential operational impact on the endpoint if the finding is malicious.
   - **Verdict**: The final actionable classification presented to the analyst (`MALICIOUS`, `SUSPICIOUS`, `SAFE`/`CLEAN`, `UNKNOWN`/`INSUFFICIENT_EVIDENCE`).
3. **Score $\neq$ Verdict**: A high severity score (e.g. 90) indicates high potential impact, but CANNOT produce a `MALICIOUS` verdict without high confidence and appropriate evidence validation.
4. **No Double-Counting**: Correlated signals derived from the same underlying artifact (e.g. YARA rule hit + Regex heuristic hit on the exact same line of a single file) MUST NOT be counted as independent corroborating proofs.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Defensible High-Confidence Triage (Priority: P1)

As a security analyst or incident responder during an active incident triage,  
I want every `MALICIOUS` alert reported by Aether to be backed by unambiguous, high-confidence evidence and corroboration,  
So that I can immediately take containment actions (isolating endpoints, terminating PIDs, quarantining payloads) without wasting critical hours chasing false alarms.

**Why this priority**: Eliminating false alarms on high-severity alerts is the fundamental value proposition of a trustworthy defensive tool. Alert fatigue destroys operational effectiveness.

**Independent Test**: Can be tested by running Aether against standard system trees containing developer tools, Python virtual environments, and doc packages; verifies that zero `MALICIOUS` alerts are raised on benign packages, while known malware fixtures reliably trigger `MALICIOUS` with full evidence chains.

**Acceptance Scenarios**:
1. **Given** a system with Python packages containing test fixtures or documentation files containing example reverse shell strings (e.g. `twisted` or `elasticsearch.dist-info`), **When** Aether scans `/usr/lib/python3`, **Then** the engine classifies the artifacts as `SAFE` or `NOTICE` (context-suppressed documentation/package test fixture), producing 0 `MALICIOUS` alerts.
2. **Given** an unowned executable script in `/tmp/.x11-unix/backdoor.sh` containing an interactive reverse shell one-liner and executable bit `0755`, **When** Aether scans the directory, **Then** Aether outputs a `MALICIOUS` verdict with confidence `HIGH`, detailing the exact rule, matched line, file hash, and execution capabilities.

---

### User Story 2 - Transparent Evidence & Provenance Inspection (Priority: P2)

As a forensic investigator,  
I want to press `[Enter]` on any finding in the TUI (or view the HTML/JSON report) and immediately see the full evidence provenance—including detector source, matched strings, package verification status, file hashes, and corroborating signals,  
So that I can answer *"Why did Aether report this?"* and justify containment actions to leadership without reading source code.

**Why this priority**: High-assurance forensics requires transparent explainability. Black-box scores without provenance are inadmissible in forensic audits.

**Independent Test**: Can be tested by running `--json-out` and `--plain` on synthetic test fixtures and asserting that every output contains `detector_source`, `matched_condition`, `evidence_provenance`, `mitre`, and `remediation`.

**Acceptance Scenarios**:
1. **Given** a finding raised by a heuristic or YARA rule, **When** the analyst inspects the finding in JSON or the TUI dossier modal, **Then** the finding contains structured evidence fields (`rule_source`, `evidence_summary`, `corroborating_signals`, `package_status`, `sha256`).
2. **Given** a finding whose severity was downgraded due to package database context or build tree recognition, **When** viewing the finding details, **Then** the finding explicitly documents the downgrade reason (e.g. `Context Suppressor: Owned by verified Debian package 'cheroot'`).

---

### User Story 3 - Explicit Abstention on Incomplete Visibility (Priority: P3)

As a security auditor running Aether as an unprivileged user,  
I want Aether to explicitly report `UNKNOWN / INSUFFICIENT_EVIDENCE` for high-risk targets that could not be inspected due to permission constraints (`EACCES`),  
So that I am aware of potential blind spots without the engine falsely reporting the system as clean or fabricating an alert.

**Why this priority**: High-assurance tools must never convert uncertainty into false certainty. Silence must not be confused with security.

**Independent Test**: Can be tested by scanning `/etc/shadow` or root-only directories as a standard user; verifies that the engine emits an explicit `UNKNOWN` visibility notice rather than a false positive or clean pass.

**Acceptance Scenarios**:
1. **Given** Aether is executed as non-root without `CAP_DAC_OVERRIDE`, **When** the scanner encounters `/etc/shadow` or `/var/spool/cron/crontabs/root` returning `EACCES`, **Then** the engine outputs an `UNKNOWN` coverage observation with reason `Permission Denied (requires root/CAP_DAC_OVERRIDE)` and does not alter the threat count.

---

### User Story 4 - Multi-Signal Corroboration Engine (Priority: P4)

As an incident responder,  
I want weak or ambiguous heuristic signals (such as a generic `curl | sh` dropper pattern or a non-standard SUID binary) to require corroborating evidence (such as autostart persistence, network listener, or unowned temp path) before escalating to a high-severity verdict,  
So that administrative installation scripts and legitimate tooling are not mistakenly flagged as active compromises.

**Why this priority**: Distinguishes between dual-use administrator scripts and active attacker tooling based on behavioral context.

**Independent Test**: Can be tested against legitimate setup scripts (e.g. `rustup-init.sh`) vs. weaponized droppers with persistence hooks.

**Acceptance Scenarios**:
1. **Given** a standalone `.sh` file in `/usr/local/bin` containing `curl -s ... | bash`, **When** the file is not executable and has no persistence hook or network socket, **Then** Aether classifies it as `NOTICE` / `SUSPICIOUS (Low Confidence)`.
2. **Given** the same script placed in `/etc/cron.hourly` with execution permissions, **When** scanned, **Then** Aether corroborates the persistence trigger with the dropper payload and escalates the verdict to `MALICIOUS (High Confidence)`.

---

## Edge Cases

- **Trojanized Package Files**: A file is listed in `/var/lib/dpkg/info/*.list`, but its contents have been altered by an attacker. The engine MUST NOT blindly suppress the finding based on package name alone if direct high-confidence signatures (e.g. reverse shell redirection, ransomware encryptors) or explicit cryptographic IOC matches are present.
- **Documentation & Test Fixtures**: Benign packages (e.g. security tools like `nmap`, Python packages like `twisted`, documentation packages) containing raw malware string literals. The engine evaluates file path attributes (e.g. `*.dist-info/METADATA`, `*/test/*`, `*/docs/*`) and package ownership to suppress false positives.
- **Sparse Files & Enormous Artifacts**: Files exceeding `MaxFileSize` (50MB) must have metadata evaluated without attempting full memory loading, gracefully noting `Scanned Metadata Only (Exceeds Max Size)`.
- **Cyclic Symlinks & Traversal Traps**: Traversal encounters deep recursive symlink directories. Symlinks are rejected via `O_NOFOLLOW` and ignored per Principle I.
- **Concurrent Rule Hits**: A file matches 3 different rules simultaneously (e.g., Heuristic Reverse Shell, YARA Reverse Shell, and IOC IP). The engine recognizes these as correlated manifestations of the same artifact, emitting a single enriched finding with contributing detectors rather than 3 duplicate alerts.

---

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: **Explicit Verdict Architecture**: The system MUST support four mutually exclusive final verdict classifications:
  - `MALICIOUS`: High-confidence, corroborated threat with concrete forensic evidence.
  - `SUSPICIOUS`: Anomaly or suspicious pattern detected, but lacking full corroboration or having potential dual-use explanations.
  - `SAFE` / `CLEAN`: Inspected artifact verified clean or confirmed as an authorized package/build-tree component.
  - `UNKNOWN` / `INSUFFICIENT_EVIDENCE`: High-interest target where inspection was truncated or blocked due to environmental limits (permissions, size bounds).
- **FR-002**: **Score-to-Verdict Independence**: The numeric severity score (0–100) MUST represent potential operational impact, while the verdict MUST be determined by evidence quality, corroboration, and contextual confidence. High score ALONE shall never produce a `MALICIOUS` verdict.
- **FR-003**: **Dual-Engine Package Awareness**: The YARA evaluation pipeline MUST query `pkgdb.PackageDB` alongside pure-Go heuristics before assigning final finding confidence.
- **FR-004**: **Contextual Suppression Matrix**: The engine MUST apply contextual suppressors before finalizing verdicts:
  - *Package Context*: Verified distribution package ownership downgrades uncorroborated heuristic/YARA alerts to `NOTICE` or `SAFE`.
  - *Documentation/Metadata Context*: Inert file formats (`.dist-info/METADATA`, `.md`, `.rst`, `.txt`, `.json`, `.yaml`) in package trees without executable permissions MUST NOT trigger `MALICIOUS` verdicts on script dropper or exfiltration rules.
  - *Build-Tree Context*: Preserved from `internal/scanner/heuristics.go` (`CheckBuildTree`).
  - *Test-Fixture Context*: Files located in recognized test directories (`/test/`, `/tests/`, `/testing/`, `*_test.py`) inside verified packages MUST be downgraded from `ALERT` to `NOTICE`.
- **FR-005**: **Tiered Evidence Standards for MALICIOUS**: A `MALICIOUS` verdict MUST require:
  1. *Direct Strong Evidence*: Unambiguous high-confidence signatures (e.g. verified reverse shell socket redirection, ransomware encryptor loop with key destruction, kernel rootkit hook) on unowned/unverified files, OR cryptographic IOC hash matches.
  2. *Strong + Independent Corroboration*: Suspicious payload heuristics corroborated by an independent execution signal (e.g. autostart persistence hook, memory-only execution descriptor, unauthorized active listening socket).
  3. *Weak/Contextual Signals*: Active socket alone, deleted executable binary after package upgrade, generic `curl | sh` without persistence, or unmapped listener alone shall produce `SUSPICIOUS` or `SAFE`, never `MALICIOUS` without corroboration.
- **FR-006**: **Corroboration & Deduplication Engine**: When multiple detectors flag the same target file or process, the engine MUST aggregate the evidence into a single canonical finding with a list of contributing rules (`ContributingDetectors`), rather than inflating confidence through duplicate alerts.
- **FR-007**: **Evidence Provenance Contract**: Every generated `Finding` MUST contain structured evidence attributes:
  - `Detector`: Source module and specific rule name.
  - `Condition`: Human-readable summary of the exact condition matched.
  - `Target`: Exact path, inode, or process ID inspected.
  - `FileMetadata`: File mode, UID, GID, SHA-256 hash.
  - `PackageContext`: Package name (or `unowned`), verified status.
  - `CorroboratingSignals`: List of independent corroborating observations (if any).
  - `ConfidenceRationale`: Plain-English explanation of why the confidence was assigned.
- **FR-008**: **Abstention on Permission Denied**: When a critical target cannot be inspected due to `EACCES` / `EPERM`, the engine MUST record an `UNKNOWN` finding with the required capability (e.g. `Requires root / CAP_DAC_OVERRIDE`), without penalizing system cleanliness score.
- **FR-009**: **Deterministic Output Invariant**: For identical filesystem state, configuration, and rule sets, Aether MUST produce byte-for-byte deterministic JSON and identical finding ordering across multi-threaded runs by sorting final finding lists by `(Path, LineNumber, RuleName)`.
- **FR-010**: **Regression Test Guarantee**: Every false positive identified during benign corpus evaluation MUST be codified as a permanent automated test case in `heuristics_test.go` or `yarax_integration_test.go`.

---

### Key Entities

- **`Observation`**: The raw empirical forensic observation collected from an endpoint subsystem (e.g. regular file, socket entry, process table entry, systemd unit).
- **`EvidenceRecord`**: Structured evidence container encapsulating hashes, file modes, UID/GID, matched string byte offsets, and package ownership.
- **`DetectionSignal`**: A single rule or heuristic match stating that an observation conforms to a threat pattern.
- **`ContextProfile`**: Environmental attributes associated with the target (package owner, test directory marker, documentation marker, build tree root).
- **`FindingVerdict`**: The final defensible verdict tuple: `{Verdict: MALICIOUS|SUSPICIOUS|SAFE|UNKNOWN, Severity: ALERT|WARNING|NOTICE|INFO, Confidence: HIGH|MEDIUM|LOW, Evidence: EvidenceRecord}`.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: **Zero False Positives on Standard Benign Corpus**: Scanning standard distribution directories (`/etc`, `/usr/bin`, `/usr/lib/python3*`) on a clean system produces exactly **0 `MALICIOUS` alerts** (100% false-positive elimination on benign packages).
- **SC-002**: **100% Threat Recall on Malicious Fixtures**: All 13 embedded YARA rules and 12 native heuristic rules maintain **100% detection rate** against authorized test fixtures.
- **SC-003**: **100% Evidence Transparency**: 100% of reported findings across JSON, TUI, and HTML reports include full provenance fields (`rule_source`, `matched_condition`, `sha256`, `package_status`, `confidence_rationale`).
- **SC-004**: **Deterministic Scan Output**: 10 consecutive scans on an identical static fixture tree produce **100% identical JSON outputs** with zero order divergence.
- **SC-005**: **Full Test Passing Standard**: 100% of unit and integration tests pass in both pure-Go (`go test ./...`) and YARA-X (`go test -tags yara ./...`) builds.
- **SC-006**: **Execution Speed Preservation**: The enhanced contextual evaluation pipeline adds less than 5% overhead to total scan duration.

---

## Assumptions

1. **Host Environment**: Linux x86_64 / arm64 endpoints with standard filesystem hierarchies and optional package management (`dpkg`, `pacman`).
2. **Forensic Integrity**: The read-only invariant defined in Aether Constitution v1.0.0 is strictly maintained.
3. **Engine Runtime**: Operates completely offline without external internet connectivity or dynamic sandbox emulation.

---

## Unresolved Questions & Clarifications

*All architectural ambiguities have been resolved through code inspection and grounded in existing engine conventions. No open blockers remain.*
