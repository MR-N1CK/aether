<!--
Sync Impact Report
==================
Version Change: 0.0.0 (Unratified Scaffold) -> 1.0.0
Ratification Date: 2026-10-03
Modified Principles: None (Initial adoption)
Added Principles:
  - I. Forensic Safety & Read-Only Invariant
  - II. Security-First Engineering & Least Privilege
  - III. Offline-First Architecture & Zero Telemetry
  - IV. Preserve Existing Architecture & Abstractions
  - V. Detection Integrity & Severity Standards
  - VI. Mandatory MITRE ATT&CK & Actionable Remediation
  - VII. Test Integrity & Verification Standard
  - VIII. Executive Studio UI & Output Contract
  - IX. Backward Compatibility & CLI Stability
  - X. Minimal-Change Principle & Targeted Scope
  - XI. AI Safety Protocol & Static Analysis Invariant
Added Sections:
  - Technical Constraints & Forensic Security Standards
  - Development Workflow & Quality Gates
Removed Sections: None
Follow-up TODOs: None
-->

# Aether Constitution

## Core Principles

### I. Forensic Safety & Read-Only Invariant (NON-NEGOTIABLE)
All inspections, file audits, and threat hunting routines MUST remain strictly read-only:
- **Zero Execution**: Never execute, compile-run, or dynamically trigger target binaries, scripts, payload samples, or suspicious files.
- **Zero State Mutation**: Never modify inspected files, directory contents, ownership, permissions, or metadata timestamps (`mtime` / `ctime`).
- **Forensic File Access**: All file reads MUST use `safeopen.OpenRegularReadOnly` with flags `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOATIME` (falling back gracefully if `CAP_FOWNER` is absent).
- **Symlink Boundary Isolation**: Symlinks MUST NOT be followed during filesystem traversal to prevent race-condition exploits, path traversal escapes, and malicious FIFO blocking.

*Rationale*: High-assurance digital forensics demands uncontaminated host evidence and absolute engine immunity against anti-analysis traps.

### II. Security-First Engineering & Least Privilege
Every subsystem and routine MUST be secure by default:
- **Least Privilege Operation**: Core scanning and inspection logic must function safely as an unprivileged user where possible, gracefully reporting non-root permission constraints without crashing.
- **Root Operation Hardening**: Root-only operations (such as system setup and binary installation) MUST enforce strict path boundaries (e.g., restricting root setup to `/etc/aether`), reject symlinked path components, and refuse to install binaries from non-root or group/world-writable directories without verified cryptographic SHA-256 confirmation.
- **Attack Surface Minimization**: Avoid introducing external daemons, unverified parsers, or privileged background workers.

*Rationale*: A forensic and defensive tool must never become a vector for privilege escalation or endpoint exploitation.

### III. Offline-First Architecture & Zero Telemetry
Aether is an air-gapped forensic engine designed for isolated environments:
- **Zero Remote Dependencies**: The engine MUST operate 100% offline without requiring internet access, remote telemetry endpoints, cloud verification, or external DNS resolutions.
- **Self-Contained Reporting**: All generated reports (including HTML dashboards produced by `internal/report/html`) MUST remain 100% self-contained with inline CSS, SVG icons, and scripts, enforcing a strict Content Security Policy (`CSP`) with cryptographically secure random nonces (`crypto/rand`) and zero external CDN fetches.
- **Pure-Go Autonomy**: The engine MUST support compiling and operating as a pure-Go standalone binary (`CGO_ENABLED=0`) with native AST and regex heuristics when YARA-X CGO libraries are not present.

*Rationale*: Threat hunting often takes place on compromised hosts or sensitive enclaves where network egress is restricted or could alert an adversary.

### IV. Preserve Existing Architecture & Abstractions
Engineering contributions MUST build upon and respect Aether's established architecture:
- **Reuse Existing Packages**: Leverage existing modules (`internal/safeopen`, `internal/scanner`, `internal/yara`, `internal/report`, `internal/modules/*`, `internal/ui/*`, `internal/pkgdb`, `internal/hasher`, `internal/triage`) rather than creating redundant abstractions.
- **No Unwarranted Rewrites**: Existing functional modules must not be rewritten without an explicit architectural requirement.
- **Unified Pipeline**: New inspection capabilities must integrate into the existing event broker (`internal/events`) and findings reporting pipeline (`internal/report`).

*Rationale*: Preserves engine stability, prevents architectural fragmentation, and maintains long-term codebase maintainability.

### V. Detection Integrity & Severity Standards
Detections MUST prioritize signal quality and adhere to defined severity scoring:
- **High Signal-to-Noise Ratio**: Avoid low-confidence heuristic rules that produce excessive false positives on standard Linux distributions or legitimate developer toolchains.
- **Dual-Engine Consistency**: Where applicable, native pure-Go regex/AST heuristics (`internal/scanner/heuristics.go`) and embedded YARA-X rules (`internal/yara/embedded_rules.go`) MUST maintain consistent detection coverage and naming.
- **Strict Severity Classification**:
  - `ALERT` (Score 85–100): Confirmed reverse shells, ransomware lockers, data stealers, kernel rootkit hooks, UID 0 accounts, or memory injection artifacts.
  - `WARNING` (Score 50–84): World-writable `/etc` configs, unmapped listening sockets, dropper download pipes, suspicious SUID binaries, or C2 listener servers.
  - `NOTICE` (Score 20–49): Non-executable ELF binaries in `/tmp` owned by the invoking user, benign build trees, or unrun modules.
  - `INFO` (Score 0–19): Baseline system observations and acknowledged triage entries.

*Rationale*: Accurate severity scoring prevents alert fatigue and ensures security teams can immediately triage critical threats.

### VI. Mandatory MITRE ATT&CK & Actionable Remediation
Every threat finding MUST provide enriched context for human responders:
- **Mandatory Registration**: Every detection rule MUST be registered in `internal/report/finding.go` (`PopulateFindingDetails`).
- **Structured Fields**: Each finding definition MUST include:
  - `Title`: A descriptive, human-readable name.
  - `Why`: Plain-English explanation of why the detected pattern is dangerous.
  - `MITRE`: Array of `{Tactic, Technique, TechniqueName}` mapping to the MITRE ATT&CK framework.
  - `Remediation`: Actionable, step-by-step containment instructions.

*Rationale*: Detections without context or actionable remediation delay incident response and increase dwell time during active attacks.

### VII. Test Integrity & Verification Standard
Verification is continuous and non-negotiable:
- **100% Test Passing Standard**: All packages MUST pass `go test ./...` and `go test -tags yara ./...` prior to committing any change.
- **Per-Rule Subtests**: Every added heuristic pattern or YARA signature MUST be accompanied by dedicated unit tests with isolated, harmless synthetic fixtures.
- **Memory & Resource Budgeting**: Inspection routines MUST respect `config.Config.Scan.MaxFileSize` (default 50MB) and `scanner.MemoryBudgetTracker` bounds to prevent out-of-memory panics on large or sparse files.

*Rationale*: Rigorous automated testing ensures detection precision and engine resilience across varied Linux endpoint environments.

### VIII. Executive Studio UI & Output Contract
User interfaces and data outputs MUST maintain consistent visual and structured contracts:
- **Theme & Styling Tokens**: Terminal and TUI outputs MUST use the design tokens defined in `internal/ui/theme/theme.go`.
- **Triage Categorization**: Output MUST clearly delineate:
  - 🚨 **MALICIOUS THREATS (Alerts)**
  - ⚠️ **SUSPICIOUS ANOMALIES (Warnings)**
  - 🛡️ **SAFE ASSETS (Inspected Clean Objects)**
- **Multi-Modal Output Integrity**: Plain terminal (`--plain`), JSON stream (`--json-out`), interactive TUI (`--tui`), and offline HTML (`--html-out`) must present identical finding details and severity metrics.

*Rationale*: Consistent visual hierarchy and multi-format reporting accelerate triage and enable seamless ingestion into SIEM platforms.

### IX. Backward Compatibility & CLI Stability
The external interface of Aether MUST remain stable:
- **CLI Invariants**: Core subcommands (`scan`, `quick`, `full`, `setup`, `ack`, `rules`), flags, and exit codes MUST NOT be broken or removed without an explicit specification requiring the change.
- **Configuration Compatibility**: Triage acknowledgments (`aether ack`) and configuration files must maintain backward compatibility across minor versions.

*Rationale*: Security engineers depend on predictable CLI syntax for incident response runbooks, automated pipelines, and cron auditing.

### X. Minimal-Change Principle & Targeted Scope
Engineering efforts MUST be focused and surgical:
- **Smallest Viable Diff**: Modifications MUST target only the smallest necessary set of components required to deliver the feature or fix.
- **No Unrelated Refactoring**: Do not reformat, rewrite, or refactor unrelated files or modules.

*Rationale*: Minimizes regression risk, keeps pull requests auditable, and ensures clear forensic traceability of changes.

### XI. AI Safety Protocol & Static Analysis Invariant
Autonomous agents and developers MUST observe strict safety boundaries when analyzing threats:
- **Strictly Static Analysis**: AI agents and automated tools MUST NEVER execute, interpret, or dynamically invoke malware samples or test payloads.
- **Safe Fixture Handling**: Test fixtures representing malicious code MUST remain inert text strings or synthetic test data and must never be placed in executable system paths.

*Rationale*: Prevents accidental execution or payload detonation within developer and agent runtime environments.

## Technical Constraints & Forensic Security Standards

- **Filesystem Traversal**: Traversal logic MUST enforce root containment, prevent cyclic symlink loops, and skip special filesystems (`/proc`, `/sys`, `/dev`) unless specifically targeted by a dedicated forensic module.
- **Package Database Verification**: When auditing suspicious binaries or modifications, the engine SHOULD query `internal/pkgdb` to verify package ownership against the local package database (e.g. `dpkg`) to eliminate false positives on legitimate distribution files.
- **Cryptographic False-Positive Pinning**: Triage suppressions (`aether ack`) MUST record SHA-256 hashes of matched targets and lines; modifications to an acknowledged file automatically void the suppression. `ALERT` findings and known IOCs MUST remain non-ackable.
- **DOM Safety in HTML Reporting**: The HTML report generator MUST NOT use `innerHTML` or raw string concatenation for dynamic data; all DOM elements must be constructed safely to prevent cross-site scripting (XSS) when viewing report files.

## Development Workflow & Quality Gates

1. **Specification & Planning**: Complex changes require prior design review against the Core Principles.
2. **Implementation**: Code must adhere to standard Go formatting (`gofmt`), utilize existing packages, and enforce the minimal-change principle.
3. **Automated Verification**:
   - Run `go test ./...` (pure-Go build validation).
   - Run `go test -tags yara ./...` (YARA-X integration validation).
   - Run `go test -race ./...` (concurrency race verification).
4. **Benign Corpus Validation**: When adding or updating signatures, verify that false positives are not introduced against standard system paths (`/etc`, `/usr/bin`, `/usr/lib/python3*`).

## Governance

This Constitution is the authoritative governing document for the Aether project. All autonomous AI agents, language models, and human developers contributing to this codebase MUST comply with the principles and quality gates established herein.

- **Supremacy**: This Constitution supersedes all other informal practices or conventions.
- **Amendment Procedure**: Amendments require explicit justification, a documented sync impact report, and a semantic version update.
- **Versioning Policy**:
  - `MAJOR`: Incompatible principle removals or foundational architectural redefinitions.
  - `MINOR`: Addition of new principles, expanded sections, or refined detection standards.
  - `PATCH`: Wording clarifications, typo fixes, and non-semantic refinements.
  - **Compliance Review**: All proposed changes, pull requests, and automated tasks MUST be verified against these principles before merging.

**Version**: 1.0.0 | **Ratified**: 2026-10-03 | **Last Amended**: 2026-10-03
