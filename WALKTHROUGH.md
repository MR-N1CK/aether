# Aether: High-Assurance Linux Threat Hunting & Incident Response Cockpit
## Architectural Hardening & Forensic Verification Walkthrough

---

### Executive Overview

This walkthrough documents the comprehensive hardening, anti-evasion engineering, forensic purity guarantees, and Executive Studio UI/UX enhancements implemented in **Aether**. The updates resolve all critique gaps, elevating Aether to a high-assurance, principal-level Linux compromise assessment and threat hunting Cockpit.

---

### 1. Multi-Signal Detection Across Obfuscated & Decoded Streams

**Problem**: Previously, `DecodeAndRescanWithYARA` terminated traversal upon encountering the first heuristic or YARA rule match within a decoded candidate. If a threat actor packed multiple payloads (e.g., an interactive reverse shell, a dropper curl pipe, and an encrypted ransomware locker) into a single base64/gzip-obfuscated script, secondary threats were left unrecorded.

**Implementation**:
- `internal/scanner/decode.go`:
  - `DecodeAndRescanWithYARA` now evaluates all de-obfuscation candidates across depths 1–3 (capped at 50 candidates, 20 matches max).
  - Accumulates all distinct heuristic script detections, private key matches, and YARA rule matches into `([]*HeuristicMatch, []string, []yara.RuleMatch)`.
  - Dedupes findings by `Name:Reason` signature to prevent duplicate signal inflation.
- `internal/scanner/inspect.go`:
  - Receives `hDecodes []*HeuristicMatch` slice and iterates across all matching payloads, combining severity levels, additive threat scores, and metadata flags.
- **Verification**:
  - `TestDecodeAndRescan_MultiSignalAggregated` verifies that a single base64-encoded stream containing both an interactive reverse shell and a download-and-execute dropper triggers dual-signal detection with proper decode layer attribution.

---

### 2. Evasion-Resistant Filesystem Traversal

**Problem**: In `internal/scanner/scanner.go`, the default `--full` scan mode contained hardcoded exclusions for directories named `testdata`, paths containing `/Downloads/Aether`, and directories containing a `go.mod` file. Threat actors could effortlessly blind the scanner by naming malware staging directories `/tmp/testdata/`, `/var/www/html/testdata/`, or planting an empty `go.mod` file.

**Implementation**:
- `internal/scanner/scanner.go`:
  - Completely removed directory pruning based on `testdata`, `/Downloads/Aether`, and content-based `go.mod` presence from the filesystem walker.
  - Legitimate developer build trees are handled post-inspection via `CheckBuildTree(path, mode, uid, ...)` rather than blinding the walker.
- **Verification**:
  - `TestScanner_FullScan_AntiEvasion_NoContentPruning` confirms that full scans traverse and inspect files inside `testdata/`, `Downloads/Aether/`, and `dev_project/` (containing `go.mod`) without pruning.

---

### 3. Dual-Window Script Scanning (Eliminating Tail-Evasion Blind Spots)

**Problem**: Script heuristic inspection previously truncated inputs to the first 2MB (`data[:2*1024*1024]`). Adversaries could bypass inspection by prepending 2.1MB of benign comment padding and appending active reverse shells or webshells at the tail.

**Implementation**:
- `internal/scanner/heuristics.go`:
  - When script content exceeds 2MB, `CheckAllSuspiciousScriptContent` constructs a dual-window buffer consisting of the first 1MB (head window) and the final 1MB (tail window) separated by a newline boundary (`head[1MB] + \n + tail[1MB]`).
  - Sets `Truncated = true` on all generated `HeuristicMatch` structs.
- `internal/scanner/inspect.go`:
  - Flags finding metadata with `f.Metadata["script_scan_truncated"] = true` when any match originates from a truncated dual-window buffer.
- **Verification**:
  - `TestCheckSuspiciousScriptContent_DualWindowTailEvasion` validates that a 2.5MB script containing 2.1MB of benign comments followed by a tail-appended reverse shell is detected with `Truncated: true`.

---

### 4. Remote Archive Hardening in 1-Click Setup

**Problem**: Automated ruleset downloading in `setup.go` had a download size check on the raw HTTP body, but lacked decompression bomb protection, ZipSlip path traversal guards, and restrictive file permissions.

**Implementation**:
- `internal/setup/setup.go`:
  - Extracted modular `ExtractRulesFromZip(zipReader *zip.Reader, destDir string) (int, error)`.
  - Added strict ZipSlip traversal protection: validates `filepath.Clean` and rejects directory traversal sequences (`..`, `/`, `\`).
  - Added decompression bomb guardrails:
    - `MaxEntryUncompressedSize` (20MB) enforced via `io.LimitReader`.
    - `MaxTotalUncompressedSize` (100MB) cumulative cap across all extracted rules.
  - Enforced restrictive `0600` file modes on all written YARA rule files.
- **Verification**:
  - `TestExtractRulesFromZip_ArchiveSecurity` validates:
    1. Valid extraction with `0600` file permissions.
    2. Immediate rejection and containment of ZipSlip path traversal archives (`../../etc/evil.yar`).
    3. Immediate abort and cleanup on decompression bombs (>20MB uncompressed per entry).

---

### 5. Safeopen Host-File Audit & Pseudofs Boundary Contract

**Problem**: Multiple subsystems (`pkgdb.go`, `ioc.go`, `triage.go`, `yarax_engine.go`, `modules/kernel/modules.go`) were performing raw `os.Open` / `os.ReadFile` calls on host filesystem targets, risking symlink hijacking, blocking on FIFOs, or contaminating file access timestamps (`atime`).

**Implementation**:
- Replaced raw file opens with `safeopen.OpenReadOnly` and `safeopen.ReadFileReadOnly` (enforcing `O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | O_NOATIME`):
  - `internal/pkgdb/pkgdb.go`: dpkg info lists, md5sums, diversions, and pacman local files.
  - `internal/ioc/ioc.go`: known_benign.yaml, IP lists, pattern YAML, and hash files.
  - `internal/triage/triage.go`: acknowledgment files and pinned file lines.
  - `internal/yara/yarax_engine.go`: external YARA rule files and verification checks.
  - `internal/modules/kernel/modules.go`: `modules.dep` dependency maps.
- **Architecture & Invariant Documentation**:
  - Created `internal/safeopen/doc.go` documenting the forensic contract and the explicit boundary between persistent block-device files (must use `safeopen`) and synthetic in-memory pseudofilesystems (`/proc/*`, `/sys/*`).
  - Enriched `AGENTS.md` Section 1 with the synthetic kernel pseudofs boundary specification.

---

### 6. Truthful Evidence Bands in Risk Assessment

**Problem**: The TUI risk gauge previously calculated a synthetic percentage using `80 + (alerts-1)*4`, projecting mathematical certainty and Bayesian posterior probability where only empirical forensic indicators exist.

**Implementation**:
- `internal/ui/tui/view.go`:
  - Replaced arbitrary percentages with explicit, industry-standard DFIR evidence bands:
    - `[DIRECT COMPROMISE]`: Active reverse shells, confirmed lockers, High confidence alerts, or direct forensic evidence records.
    - `[CORROBORATED ANOMALY]`: Multiple corroborated warnings across disparate subsystems or uncorroborated single alerts.
    - `[CONTEXTUAL SUSPICION]`: Isolated warnings (e.g. deleted binary in memory or wildcard socket listener).
    - `[AUDIT NOTICE]`: Low-priority configuration observations and unowned units.
    - `[CLEAN & SECURE]`: Zero findings across inspected assets.
- **Verification**:
  - `internal/ui/tui/view_test.go`: All gauge tests assert truthful evidence-band labels.

---

### 7. Interactive Forensic Command Palette & Mouse Navigation

**Implementation**:
- `internal/ui/tui/run.go`: Enabled `tea.WithMouseCellMotion()` in the Bubble Tea program configuration.
- `internal/ui/tui/model.go`:
  - Implemented `handleMouse(msg tea.MouseMsg)` supporting:
    - Mouse wheel scrolling up and down in the findings list.
    - Mouse wheel scrolling inside the deep Forensic Dossier modal.
    - Right-click dismiss to return to the dashboard.
  - Re-architected Command Palette into a searchable, interactive modal (`showPalette`):
    - Real-time search query filtering (`paletteQuery`).
    - Up/down selection navigation with keyboard or mouse wheel.
    - `Enter` executes the selected command directly (Inspect, Jump to Alert, Toggle Sort, Copy Runbook, Copy Path, Copy Hash, Open HTML Report, Switch Tabs, Quit).
- `internal/ui/tui/view.go`:
  - Rendered search input box with live cursor, highlighted selection row (`▶`), and action descriptions.
- **Verification**:
  - `TestCommandPalette_SearchFilterAndExecute` validates the entire palette search, navigation, execution, mouse wheel interaction, and dismissal cycle.

---

### 8. Verification Summary

```bash
# 100% test pass rate across all packages with zero cache:
CGO_ENABLED=0 go test -count=1 ./...
```
All packages pass with pure-Go static compilation contracts.
