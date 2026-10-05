# Data Model: Trustworthy Detection & False-Positive Control

**Feature**: Trustworthy Detection & False-Positive Control  
**Date**: 2026-10-03  
**Status**: Revised  

---

## 1. Type Definitions & Enums

### `Verdict`
Defines the final analytical verdict classification presented to the security analyst:

```go
type Verdict string

const (
    // VerdictMalicious indicates confirmed, evidence-backed threat with high confidence.
    VerdictMalicious  Verdict = "MALICIOUS"
    // VerdictSuspicious indicates an anomaly or suspicious pattern requiring analyst review.
    VerdictSuspicious Verdict = "SUSPICIOUS"
    // VerdictSafe indicates an inspected artifact verified clean or context-suppressed (package/build tree).
    VerdictSafe       Verdict = "SAFE"
    // VerdictUnknown indicates insufficient visibility or inspection truncated due to permissions (EACCES).
    VerdictUnknown    Verdict = "UNKNOWN"
)
```

### `EvidenceStrength`
Categorizes the intrinsic evidential weight of an observation:

```go
type EvidenceStrength string

const (
    // StrengthDirect: Unambiguous signature or cryptographic IOC (e.g. reverse shell redirection, IOC hash, rootkit hook).
    StrengthDirect    EvidenceStrength = "DIRECT"
    // StrengthCorroborated: Suspicious pattern confirmed by an independent operational signal (e.g. payload + persistence).
    StrengthCorroborated EvidenceStrength = "CORROBORATED"
    // StrengthContextual: Weak or dual-use anomaly (e.g. open listener, deleted binary, uncorroborated curl|sh).
    StrengthContextual EvidenceStrength = "CONTEXTUAL"
    // StrengthIncomplete: Blocked observation due to permissions (EACCES).
    StrengthIncomplete EvidenceStrength = "INCOMPLETE"
)
```

### `EvidenceRecord`
Encapsulates structured forensic evidence for transparent provenance:

```go
type EvidenceRecord struct {
    DetectorType          string           `json:"detector_type"`           // "heuristic" | "yara" | "ioc" | "module"
    RuleName              string           `json:"rule_name"`               // Exact rule identifier
    EvidenceStrength      EvidenceStrength `json:"evidence_strength"`       // "DIRECT" | "CORROBORATED" | "CONTEXTUAL" | "INCOMPLETE"
    MatchedCondition      string           `json:"matched_condition"`       // Human-readable summary of matched condition
    LineContent           string           `json:"line_content,omitempty"`  // Matched snippet (if text)
    LineNumber            int              `json:"line_number,omitempty"`   // File line number (if applicable)
    TargetPath            string           `json:"target_path"`             // Virtual path inspected
    SHA256                string           `json:"sha256,omitempty"`        // Cryptographic SHA-256 hash
    FileMode              uint32           `json:"file_mode,omitempty"`     // POSIX file permissions
    OwnerUID              uint32           `json:"owner_uid,omitempty"`     // File owner UID
    PackageName           string           `json:"package_name,omitempty"`  // Owning OS package (if any)
    PackageStatus         string           `json:"package_status"`          // "unowned" | "verified_package" | "modified_package"
    ContextProfile        string           `json:"context_profile"`         // "standard" | "doc_metadata" | "package_test" | "build_tree"
    CorroboratingSignals  []string         `json:"corroborating_signals,omitempty"`   // Independent physical signals
    ContributingDetectors []string         `json:"contributing_detectors,omitempty"`  // Multiple rules flagging same target
    ConfidenceRationale   string           `json:"confidence_rationale"`    // Plain-English justification
}
```

### Extended `Finding` Model (in `internal/report/finding.go`)
Extends the existing `Finding` struct without breaking backward compatibility:

```go
type Finding struct {
    ID                  string                 `json:"id,omitempty"`
    Timestamp           time.Time              `json:"timestamp"`
    Module              string                 `json:"module"`
    Severity            Severity               `json:"severity"`            // Operational impact (ALERT/WARN/NOTICE/INFO)
    Confidence          Confidence             `json:"confidence,omitempty"` // Evidence certainty (HIGH/MEDIUM/LOW)
    Verdict             Verdict                `json:"verdict,omitempty"`    // Analytical state (MALICIOUS/SUSPICIOUS/SAFE/UNKNOWN)
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
    ConfidenceRationale string                 `json:"confidence_rationale,omitempty"`
}
```

---

## 2. Tiered Evidence & Verdict Determination Matrix

The verdict is determined deterministically according to **Evidence Strength**, **Context Profile**, and **Corroborating Signals**:

| Evidence Category | Evidence Strength | Context Profile | Corroborating Signals | Resulting Verdict | Resulting Severity | Resulting Confidence |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Direct Malware Signature** (Reverse shell socket redirection, ransomware encryptor loop, kernel rootkit hook, IOC hash) | `DIRECT` | Unowned / Custom Path | Not required (Direct proof) | `MALICIOUS` | `ALERT` | `HIGH` |
| **Direct Malware Signature** (Reverse shell or socket listener mock) | `DIRECT` | Verified Package Test Fixture (`/test/`, `test_*.py`) | None | `SAFE` | `NOTICE` | `LOW` |
| **Suspicious Payload Script** (`curl \| sh` dropper) | `CONTEXTUAL` | Unowned Executable in `/etc/cron.*` | Autostart persistence hook | `MALICIOUS` | `ALERT` | `HIGH` |
| **Suspicious Payload Script** (`curl \| sh`) | `CONTEXTUAL` | Verified Package Wheel Metadata (`.dist-info/METADATA`) | None (Inert doc) | `SAFE` | `NOTICE` | `LOW` |
| **Suspicious Payload Script** (`curl \| sh`) | `CONTEXTUAL` | Unowned Standalone Script in `/usr/local/bin` | None (Uncorroborated) | `SUSPICIOUS` | `WARNING` | `MEDIUM` |
| **Deleted Process Binary** (Process running from `(deleted)` path) | `CONTEXTUAL` | Package-managed binary (e.g. post `apt upgrade`) | None | `SUSPICIOUS` | `NOTICE` | `LOW` |
| **Deleted Process Binary** (Process running from `(deleted)` path) | `CORROBORATED` | Unowned temp binary (`/tmp/.*`) | Active unmapped network socket | `MALICIOUS` | `ALERT` | `HIGH` |
| **Memory-Only Execution** (`/memfd:`) | `CORROBORATED` | Anonymous descriptor with ELF header | Spawned interactive command shell | `MALICIOUS` | `ALERT` | `HIGH` |
| **Active Network Listener** | `CONTEXTUAL` | Standard daemon in `/etc/services` | None | `SAFE` | `INFO` | `LOW` |
| **Active Network Listener** | `CONTEXTUAL` | Unmapped non-root listening port | None (Uncorroborated) | `SUSPICIOUS` | `WARNING` | `MEDIUM` |
| **Non-Exec ELF in `/tmp`** | `CONTEXTUAL` | Non-root owned Build Tree (`Cargo.toml`, `go.mod`) | None | `SAFE` | `NOTICE` | `LOW` |
| **Any Target** | `INCOMPLETE` | Permission Denied (`EACCES` / `EPERM`) | N/A | `UNKNOWN` | `INFO` | `LOW` |

---

## 3. Relationships & Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Observation (Scanner / SafeOpen / Modules)               │
│    Path, Inode, Mode, UID, Bytes, Socket, Process           │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Detections (Heuristics, YARA-X, IOC Matchers)            │
│    Emits RuleMatch: Name, Severity, Score, Condition        │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Context & Evidence Evaluator (internal/report/verdict)   │
│    - Evaluates EvidenceStrength (DIRECT / CORROBORATED ...) │
│    - Queries pkgdb.PackageDB (PackageName, PackageStatus)   │
│    - Evaluates ContextProfile (doc_metadata, package_test)  │
│    - Evaluates CorroboratingSignals (socket, cron, memfd)   │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Finding Construction & Deduplication                     │
│    - Populates Finding, Verdict, EvidenceRecord, MITRE      │
│    - Merges duplicate hits into ContributingDetectors       │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. Deterministic Sort & Multi-Modal Output                  │
│    - Sorts by (Path, LineNumber, RuleName)                  │
│    - Renders JSON, TUI, Plain ANSI, Self-Contained HTML     │
└─────────────────────────────────────────────────────────────┘
```
