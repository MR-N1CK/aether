# Quickstart Validation Guide: Detection Accuracy & Validation Benchmark

**Feature**: Detection Accuracy & Validation Benchmark  
**Date**: 2026-10-03  
**Status**: Draft  

This guide describes how to run the automated detection validation benchmark, verify accuracy metrics, evaluate evasion mutations, and review the explainability scorecard.

---

## 1. Running the Automated Benchmark Suite

Execute the benchmark suite using Go testing tools:

```bash
# 1. Run full detection benchmark suite with YARA-X support
go test -v -tags yara ./test/benchmark/...

# 2. Run benchmark with JSON report output
go test -v -tags yara -run TestRunDetectionBenchmark ./test/benchmark/... -args -json-report /tmp/aether-benchmark.json

# 3. Run evasion mutation robustness test
go test -v -tags yara -run TestStaticEvasionResilience ./test/benchmark/...

# 4. Run explainability verification scorecard
go test -v ./test/benchmark/... -run TestExplainabilityCompliance
```

---

## 2. Validation Scenarios

### Scenario 1: Zero False-Positive Gate on Benign Corpus
- **Command**:
  ```bash
  go test -v -tags yara ./test/benchmark/... -run TestCategoryA_Benign
  ```
- **Expected Outcome**:
  - 100% of cases pass.
  - Exactly 0 `MALICIOUS` verdicts produced.
  - False Positive Rate ($\text{FPR}$) is $0.0\%$.

---

### Scenario 2: Threat Recall on Baseline Malicious Corpus
- **Command**:
  ```bash
  go test -v -tags yara ./test/benchmark/... -run TestCategoryB_Malicious
  ```
- **Expected Outcome**:
  - $\ge 95\%$ of malicious fixtures produce `VerdictMalicious` with Severity `ALERT` and Confidence `HIGH`.
  - Zero uncorroborated downgrades on direct reverse shells, webshells, or rootkits.

---

### Scenario 3: Ambiguous / Suspicious Triage Separation
- **Command**:
  ```bash
  go test -v -tags yara ./test/benchmark/... -run TestCategoryC_Suspicious
  ```
- **Expected Outcome**:
  - Dual-use scripts and unmapped listeners classify as `VerdictSuspicious` (`WARNING`/`NOTICE`).
  - None are over-escalated to `MALICIOUS` without independent autostart persistence or active socket corroboration.

---

### Scenario 4: Permission-Denied Abstention Contract
- **Command**:
  ```bash
  go test -v ./test/benchmark/... -run TestCategoryE_PartialVisibility
  ```
- **Expected Outcome**:
  - Inaccessible root files scanned as non-root produce `VerdictUnknown` with reason `Permission Denied`.
  - System cleanliness score remains 0; no false alarm or false clean pass emitted.

---

### Scenario 5: Deterministic Reproducibility
- **Command**:
  ```bash
  go test -v -tags yara ./test/benchmark/... -run TestBenchmarkDeterminism
  ```
- **Expected Outcome**:
  - 10 consecutive multi-threaded runs produce byte-for-byte identical JSON reports.
