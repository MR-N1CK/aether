# Implementation Plan: Trustworthy Detection & False-Positive Control

**Branch**: `001-trustworthy-detection` | **Date**: 2026-10-03 | **Spec**: [`specs/001-trustworthy-detection/spec.md`](spec.md)

---

## 1. Current Architecture Assessment

Aether's current detection architecture operates as follows:
- **Heuristics Engine** (`internal/scanner/heuristics.go`): Single-pass regex/AST checks emitting `HeuristicMatch` structs with fixed numeric scores (e.g. 90 $\to$ ALERT). Pure-Go checks consult `pkgdb.PackageDB` via `pkgDB.Owner(cleaned)` and return `nil` if owned.
- **YARA-X Engine** (`internal/yara/yarax_engine.go` & `embedded_rules.go`): Evaluates 13 embedded YARA rules against raw file bytes. It does **not** evaluate package ownership or path context, causing false positives on Python library test fixtures (e.g. `twisted`, `joblib`, `cheroot`) and documentation wheel metadata (`.dist-info/METADATA`).
- **Finding & Reporting** (`internal/report/finding.go`): Struct containing `Severity` (`ALERT`, `WARNING`, `NOTICE`, `INFO`) and `Confidence` (`HIGH`, `MEDIUM`, `LOW`). In `PopulateFindingDetails(f *Finding)`, `Confidence` is automatically defaulted from `Severity` (`ALERT` $\to$ `HIGH`), collapsing the distinction between impact and certainty.
- **Package DB** (`internal/pkgdb/pkgdb.go`): Provides Debian (`dpkg`) and Arch (`pacman`) database lookups with normalized `/usr` paths.
- **Triage** (`internal/triage/triage.go`): SHA-256 pinning of files/lines (`aether ack`), auto-voiding on modification.

**Identified Shortcomings**:
1. Score directly determines verdict; an isolated regex or YARA hit is immediately presented as a red Malicious Alert.
2. YARA engine is blind to package context and document file types.
3. No structured distinction between Observations, Evidence, Detections, Context, Corroboration, Confidence, Severity, and Verdict.
4. Concurrent scan results lack deterministic sorting prior to JSON/plain report generation.

---

## 2. Requirement $\to$ Code Mapping

| Requirement | Description | Target Code Location | Minimal Architectural Mechanism |
| :--- | :--- | :--- | :--- |
| **FR-001** | Explicit Verdict States (`MALICIOUS`, `SUSPICIOUS`, `SAFE`, `UNKNOWN`) | `internal/report/finding.go`, `internal/report/verdict.go` | Introduce `Verdict` and `EvidenceStrength` enums and determination engine in `internal/report`. |
| **FR-002** | Score $\neq$ Verdict Decoupling | `internal/report/verdict.go` | Separate potential impact (`Severity`) from evidence certainty (`Verdict`). |
| **FR-003** | Dual-Engine Package Awareness | `internal/scanner/scanner.go`, `internal/yara/yarax_engine.go` | Pass `PackageDB` and file path context into YARA match processing. |
| **FR-004** | Contextual Suppression Matrix | `internal/report/verdict.go`, `internal/scanner/heuristics.go` | Suppress alerts for package test suites, documentation wheel metadata (`.dist-info`), and build trees. |
| **FR-005** | Tiered Evidence Standards for MALICIOUS | `internal/report/verdict.go` | Direct strong evidence or corroborated signals required for `MALICIOUS`; weak signals produce `SUSPICIOUS`. |
| **FR-006** | Corroboration & Deduplication | `internal/report/dedup.go`, `internal/scanner/scanner.go` | Group multi-detector hits on same file/line into `ContributingDetectors` without multiplying confidence. |
| **FR-007** | Evidence Provenance Contract | `internal/report/finding.go` | Add `EvidenceRecord` struct capturing detector, matched condition, hashes, UID, and rationale. |
| **FR-008** | Abstention on Permission Denied | `internal/scanner/scanner.go`, `internal/modules/*` | Emit `VerdictUnknown` visibility observations on `EACCES` without penalizing cleanliness. |
| **FR-009** | Deterministic Scan Output | `internal/report/reporter.go` | Sort final finding slices by `(Path, LineNumber, RuleName)` before serialization. |
| **FR-010** | Benign Regression Protection | `internal/scanner/heuristics_test.go`, `internal/yara/benign_corpus_test.go` | Add permanent unit tests for benign package fixtures (`cheroot`, `elasticsearch`, `twisted`, `joblib`). |

---

## 3. Proposed Data & Model Changes

### A. Extended `Finding` Struct (`internal/report/finding.go`)
Extend `Finding` without removing existing fields to preserve complete backward compatibility:

```go
type Verdict string

const (
    VerdictMalicious  Verdict = "MALICIOUS"
    VerdictSuspicious Verdict = "SUSPICIOUS"
    VerdictSafe       Verdict = "SAFE"
    VerdictUnknown    Verdict = "UNKNOWN"
)

type EvidenceStrength string

const (
    StrengthDirect       EvidenceStrength = "DIRECT"
    StrengthCorroborated EvidenceStrength = "CORROBORATED"
    StrengthContextual   EvidenceStrength = "CONTEXTUAL"
    StrengthIncomplete   EvidenceStrength = "INCOMPLETE"
)

type EvidenceRecord struct {
    DetectorType          string           `json:"detector_type"`
    RuleName              string           `json:"rule_name"`
    EvidenceStrength      EvidenceStrength `json:"evidence_strength"`
    MatchedCondition      string           `json:"matched_condition"`
    LineContent           string           `json:"line_content,omitempty"`
    LineNumber            int              `json:"line_number,omitempty"`
    TargetPath            string           `json:"target_path"`
    SHA256                string           `json:"sha256,omitempty"`
    FileMode              uint32           `json:"file_mode,omitempty"`
    OwnerUID              uint32           `json:"owner_uid,omitempty"`
    PackageName           string           `json:"package_name,omitempty"`
    PackageStatus         string           `json:"package_status"` // "unowned" | "verified_package" | "modified_package"
    ContextProfile        string           `json:"context_profile"` // "standard" | "doc_metadata" | "package_test" | "build_tree"
    CorroboratingSignals  []string         `json:"corroborating_signals,omitempty"`
    ContributingDetectors []string         `json:"contributing_detectors,omitempty"`
    ConfidenceRationale   string           `json:"confidence_rationale"`
}
```

### B. New Verdict Determination Engine (`internal/report/verdict.go`)
Provides a clean, testable evaluation function:
`func DetermineVerdict(f *Finding, pkgDB pkgdb.PackageDB, isExec bool, isDoc bool, isTestFixture bool, corroboration []string) Verdict`

---

## 4. Detection Pipeline Changes

```
1. Scanner / Module reads target via safeopen.OpenRegularReadOnly
2. Detections evaluated:
   - Native Heuristics (heuristics.go)
   - Static YARA-X Engine (yarax_engine.go)
   - IOC Engine (ioc.go)
3. Raw matches passed to Context & Verdict Evaluator:
   - Check PackageDB ownership
   - Check file attributes (isExec, isDoc, isTestFixture)
   - Evaluate Evidence Strength (Direct vs Corroborated vs Contextual)
   - Evaluate corroborating signals (open socket, persistence unit, memfd)
4. Populate Finding:
   - Sets Verdict, Severity, Confidence, EvidenceRecord, MITRE, Remediation
5. Accumulator / Reporter deduplicates and stores findings
6. Final Output: Deterministic Sort -> Render JSON / TUI / Plain / HTML
```

---

## 5. Correlation & Deduplication Design

1. **Intra-File Duplicate Consolidation**:
   - If both YARA (`Linux_Backdoor_Reverse_Shell_OneLiner`) and pure-Go regex (`Script_Reverse_Shell_Interactive`) match the same line or file:
   - The engine selects the primary rule with the most specific MITRE mapping and records the second rule in `EvidenceRecord.ContributingDetectors`.
   - Confidence is calculated based on the evidence strength of the primary detector—**not** inflated by the presence of a duplicate signature.
2. **Cross-Module Corroboration**:
   - Independent observations (e.g. an unowned script in `/tmp` that ALSO has an active listening socket in `internal/modules/network` and an autostart hook in `internal/modules/persistence`) are merged into `CorroboratingSignals`, elevating the finding from `SUSPICIOUS` to `MALICIOUS (High Confidence)`.
   - An active socket or deleted binary ALONE without independent malicious signatures produces `SUSPICIOUS` or `SAFE` (normal daemon/upgrade context).

---

## 6. Context & Package-Awareness Changes

1. **YARA Context Integration**:
   - Update `internal/yara/yarax_engine.go` and the scanner calling loop to evaluate `pkgdb.PackageDB` when processing YARA rule hits.
2. **Context Profiles**:
   - **`doc_metadata`**: Matches `.dist-info/METADATA`, `.egg-info/*`, `README*`, `*.md`, `*.rst`, `*.txt` in package directories without executable bits $\to$ Downgrades droppers/exfiltration matches to `SAFE` / `NOTICE`.
   - **`package_test`**: Matches `/test/`, `/tests/`, `*_test.py` inside verified packages $\to$ Downgrades socket listener / mock server matches to `SAFE` / `NOTICE`.
   - **`build_tree`**: Maintained via `CheckBuildTree` $\to$ Downgrades unlinked build binaries to `NOTICE`.
3. **No Blind Whitelisting**:
   - Package-owned files with direct malicious signatures (e.g. reverse shell redirection or ransomware encryptor) or modified file hashes are NOT suppressed.

---

## 7. Confidence & Verdict Changes

- `PopulateFindingDetails(f *Finding)` will no longer blindly set `Confidence = HIGH` based solely on `Severity = ALERT`.
- `Verdict` is assigned according to the Tiered Evidence & Verdict Determination Matrix:
  - `MALICIOUS`: Direct unowned malware signatures (reverse shells, ransomware loops, rootkit hooks, IOC hits) or corroborated droppers/implants.
  - `SUSPICIOUS`: Uncorroborated generic droppers, non-standard SUIDs, unmapped listeners, deleted binaries without malicious payloads.
  - `SAFE`: Package test fixtures, wheel doc metadata, build trees, acknowledged clean triage entries, standard service listeners.
  - `UNKNOWN`: Permission denied (`EACCES`), uninspected special descriptors.

---

## 8. Testing & Fixture Architecture

1. **Benign Regression Suite**:
   - `testdata/fixtures/benign/cheroot_server.py`
   - `testdata/fixtures/benign/elasticsearch_metadata.txt`
   - `testdata/fixtures/benign/twisted_test_fdset.py`
   - Unit tests in `internal/scanner/heuristics_test.go` and `internal/yara/yarax_integration_test.go` asserting `Verdict == VerdictSafe` (or `SeverityNotice`).
2. **Malicious Verification Suite**:
   - Synthetic reverse shells, Python ransomware loops, OpenSSL shells in `testdata/fixtures/malicious/` asserting `Verdict == VerdictMalicious` and `Confidence == ConfidenceHigh`.
3. **Corroboration & Non-Inflation Suite**:
   - Tests asserting that dual heuristic + YARA matches produce 1 canonical finding with `len(ContributingDetectors) > 0` and non-inflated confidence.

---

## 9. Determinism Strategy

1. **Deterministic Finding Sort**:
   - In `internal/report/reporter.go` and `internal/scanner/scanner.go`:
   ```go
   sort.Slice(findings, func(i, j int) bool {
       if findings[i].Path != findings[j].Path {
           return findings[i].Path < findings[j].Path
       }
       if findings[i].LineNumber != findings[j].LineNumber {
           return findings[i].LineNumber < findings[j].LineNumber
       }
       return findings[i].RuleName < findings[j].RuleName
   })
   ```
2. **Separation of Stable Findings vs. Run Metadata**:
   - Finding contents, IDs, and ordering are 100% deterministic. Dynamic execution metadata (`scan_start_time`, `elapsed_duration`) is isolated to the top-level scan envelope.

---

## 10. Permission & UNKNOWN Handling

- When `safeopen.OpenRegularReadOnly` returns `os.ErrPermission` / `EACCES`:
  - Emit a finding with `Verdict = VerdictUnknown`, `Severity = SeverityInfo`, `Confidence = ConfidenceLow`.
  - Reason: `Incomplete Visibility: Permission Denied (Requires root / CAP_DAC_OVERRIDE)`.
  - Displayed in TUI and Plain output under a dedicated **Coverage / Incomplete Visibility** notice without incrementing threat counters.

---

## 11. Report, JSON, and UI Impact

- **JSON Output**: Adds `verdict`, `evidence_record`, and `confidence_rationale` fields matching [`finding-schema.json`](contracts/finding-schema.json). Existing consumers reading `severity` and `mitre` remain 100% compatible.
- **Plain & TUI Output**:
  - 🚨 **MALICIOUS THREATS**: Displays only `VerdictMalicious` findings.
  - ⚠️ **SUSPICIOUS ANOMALIES**: Displays `VerdictSuspicious` findings.
  - 🛡️ **SAFE ASSETS & NOTICES**: Displays `VerdictSafe` and acknowledged findings.
  - ℹ️ **COVERAGE LIMITS**: Displays `VerdictUnknown` visibility notices.
- **HTML Dashboard**: Updated in `internal/report/html/html.go` to render the verdict badge and context profile in the finding detail drawer.

---

## 12. Backward Compatibility Considerations

- All existing CLI commands (`scan`, `quick`, `full`, `setup`, `ack`, `rules`) and flags remain unchanged.
- Pure-Go compilation (`make build`) and YARA-X compilation (`make build-yara-static`) remain 100% supported.
- Existing triage acknowledgment files (`/etc/aether/acknowledged.yaml`) remain valid.

---

## 13. Files That Will Change

1. `internal/report/finding.go` (Add `Verdict`, `EvidenceStrength`, `EvidenceRecord` types, update finding fields)
2. `internal/report/verdict.go` (**[NEW]** Implement verdict determination & contextual suppression logic)
3. `internal/report/verdict_test.go` (**[NEW]** Unit tests for verdict evaluation matrix)
4. `internal/scanner/scanner.go` (Pass package DB to YARA, integrate verdict evaluation, deterministic sort)
5. `internal/scanner/heuristics.go` (Integrate context profile awareness)
6. `internal/scanner/heuristics_test.go` (Add benign regression test fixtures)
7. `internal/scanner/corroboration_test.go` (**[NEW]** Add multi-signal non-inflation tests)
8. `internal/yara/yarax_integration_test.go` (Add package context suppression tests)
9. `internal/ui/plain/card.go` (Render Verdict badge and Evidence rationale)
10. `internal/ui/tui/view.go` (Display Verdict and Evidence in threat dossier modal)
11. `internal/report/html/html.go` (Display Verdict badge in offline HTML dashboard)

---

## 14. Files That Must NOT Change

- `internal/safeopen/*` (Core forensic safeopen invariants and flags must remain untouched)
- `internal/modules/kernel/*` (Functioning kernel taint and sysfs module audits remain untouched)
- `internal/modules/process/*` (Functioning hidden PID and memfd audits remain untouched)
- `internal/modules/users/*` (Functioning passwd/shadow audits remain untouched)
- `internal/ioc/ioc.go` (O(1) hash matching and allowlist remain untouched)
- `internal/setup/*` (Hardened setup path validation remains untouched)
- `install.sh` (Hardened installer remains untouched)

---

## 15. Implementation Phases

```
Phase 1: Model & Verdict Foundation
  ├── Extend Finding struct with Verdict, EvidenceStrength, EvidenceRecord in internal/report/finding.go
  ├── Implement internal/report/verdict.go (contextual suppression & tiered verdict determination)
  └── Implement internal/report/verdict_test.go (100% test coverage of verdict matrix)

Phase 2: Pipeline & Context Integration
  ├── Update internal/scanner/scanner.go to pass pkgdb context to YARA & evaluate verdicts
  ├── Update internal/scanner/heuristics.go to classify doc/metadata & test contexts
  └── Add deterministic finding sort in internal/report/reporter.go

Phase 3: UI & Reporter Surface Integration
  ├── Update internal/ui/plain to render Verdict badges and Evidence rationale
  ├── Update internal/ui/tui to render EvidenceRecord in threat dossier modal
  └── Update internal/report/html/html.go to render Verdict badges in offline HTML reports

Phase 4: Verification & Regression Testing
  ├── Add benign corpus regression tests in heuristics_test.go & benign_corpus_test.go
  ├── Run go test ./... (pure-Go verification)
  └── Run go test -tags yara ./... (YARA-X and benign corpus scan verification)
```

---

## 16. Validation Commands

```bash
# 1. Run all unit tests in pure-Go mode
go test -v ./...

# 2. Run all unit tests with YARA-X enabled
go test -v -tags yara ./...

# 3. Verify benign corpus scan (Must yield 0 false-positive MALICIOUS alerts)
go test -v -tags yara -run TestBenignCorpus ./internal/yara/...

# 4. Verify race conditions
go test -race -count=1 ./...
```

---

## 17. Risks & Mitigations

| Risk | Mitigation |
| :--- | :--- |
| **Over-suppression of trojanized package files** | Contextual suppression is bypassed if direct malicious signatures (e.g. reverse shell redirection, ransomware encryptors) or explicit cryptographic IOC matches are present. |
| **Performance overhead from package lookups** | `pkgdb.PackageDB` uses in-memory map lookup with $O(1)$ complexity; total scan duration overhead must remain $<5\%$ per `SC-006`. |
| **Output format breaking external SIEM parsers** | All existing JSON fields (`severity`, `confidence`, `mitre`, `path`, `reason`) remain intact; `verdict` and `evidence_record` are added as additive extensions. |

---

## 18. Explicit Non-Goals

1. **No Rule Rewriting**: We do not delete or rewrite the 13 embedded YARA rules; we contextualize their evaluation.
2. **No Dynamic Emulation / Sandboxing**: Aether remains strictly static and forensic; no dynamic script interpretation or execution is introduced.
3. **No Outbound Network Lookups**: Package verification and benign evaluation remain 100% offline using local `/var/lib/dpkg` or `/var/lib/pacman`.
4. **No Arbitrary Heuristic Scoring Inflation**: Adding more heuristic rules will not arbitrarily increase confidence without concrete corroborating evidence.
