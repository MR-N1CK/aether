# Quickstart Validation Guide: Trustworthy Detection & False-Positive Control

**Feature**: Trustworthy Detection & False-Positive Control  
**Date**: 2026-10-03  
**Status**: Draft  

This guide describes the end-to-end test scenarios used to validate that Aether's detection engine prioritizes trustworthy detection, evidence transparency, and false-positive suppression without regressions.

---

## 1. Automated Test Suite Execution

Run the complete test suite across pure-Go and YARA-X compiled builds:

```bash
# 1. Pure-Go test suite (Validates heuristics, pkgdb, triage, and verdict logic)
go test -v ./...

# 2. YARA-X embedded engine integration tests
go test -v -tags yara -run TestYaraX_EmbeddedCoreLinuxRules ./internal/yara/...

# 3. Benign corpus validation test (Must produce 0 MALICIOUS alerts)
go test -v -tags yara -run TestBenignCorpus ./internal/yara/...
```

---

## 2. Validation Scenario Walkthroughs

### Scenario A: Benign Package Context Suppression (Zero False Positives)
- **Goal**: Verify that Python documentation metadata and unit test socket mocks do not trigger `MALICIOUS` alerts.
- **Command**:
  ```bash
  ./bin/aether-yara-static scan --plain /usr/lib/python3/dist-packages/cheroot/server.py
  ./bin/aether-yara-static scan --plain /usr/lib/python3/dist-packages/theharvester-4.11.1.dist-info/METADATA
  ```
- **Expected Outcome**:
  - `Verdict: SAFE` (or `NOTICE`).
  - No `ALERT` or `MALICIOUS` cards emitted.
  - Reason includes `Context: Verified package ownership / documentation format`.

### Scenario B: Genuine Malicious Payload Detection
- **Goal**: Verify that confirmed reverse shells, ransomware lockers, and stealth implants trigger `MALICIOUS` with full evidence chains.
- **Command**:
  ```bash
  ./bin/aether-yara-static scan --plain testdata/fixtures/reverse_shell.sh
  ```
- **Expected Outcome**:
  - `Verdict: MALICIOUS` (Severity: `ALERT`, Confidence: `HIGH`).
  - Output displays matched condition, rule name, SHA-256 hash, and remediation steps.

### Scenario C: Deterministic Multi-Threaded Scan Output
- **Goal**: Verify that multi-threaded concurrent scans produce deterministic finding ordering.
- **Command**:
  ```bash
  ./bin/aether-yara-static scan --json-out /tmp/scan1.json testdata/fixtures/
  ./bin/aether-yara-static scan --json-out /tmp/scan2.json testdata/fixtures/
  diff -u <(jq '.findings' /tmp/scan1.json) <(jq '.findings' /tmp/scan2.json)
  ```
- **Expected Outcome**:
  - Zero diff between the `.findings` arrays across runs.

### Scenario D: Permission-Denied Partial Visibility
- **Goal**: Verify that unreadable files produce an explicit `UNKNOWN` finding rather than being reported as clean.
- **Command**:
  ```bash
  # Run as unprivileged non-root user against a 0600 root file
  aether scan --plain /etc/shadow
  ```
- **Expected Outcome**:
  - Output records `UNKNOWN / INSUFFICIENT_EVIDENCE` for `/etc/shadow`.
  - Reason: `Permission Denied (requires root / CAP_DAC_OVERRIDE)`.
  - Threat score remains 0 (no false positive).
