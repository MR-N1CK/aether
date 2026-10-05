# Quickstart Guide: Real-World Linux Security Assessment & Reliability Validation

**Feature**: `004-real-world-validation`
**Date**: 2026-10-04
**Status**: Draft

This quickstart guide demonstrates how to run, validate, and verify Aether's real-world Linux security assessment capabilities across hermetic snapshots, dual-use tool environments, runtime race stress simulations, and live host audits.

---

## 1. Prerequisites

- Go 1.22+ installed
- Linux operating system (or Linux container/WSL2)
- Zero external network dependencies (100% offline verification)

---

## 2. Validation Scenarios

### Scenario 1: Hermetic Environment Matrix Validation

Verify that Aether accurately evaluates the 8 distinct Linux environment profiles against their independent manifests:

```bash
# Run real-world environment profile validation suite
go test -v ./test/realworld/... -run TestRealWorldEnvironmentProfiles
```

**Expected Outcome**:
- All 8 profiles (`desktop-standard`, `workstation-dev`, `workstation-pentest`, `server-web`, `server-minimal`, `container-host`, `package-mixed`, `upgraded-pending`) pass their independent manifest contracts.
- Benign profiles produce overall status `SAFE` or `ATTENTION_REQUIRED` (e.g. for pending daemon restarts post-upgrade).
- Zero false `ALERT` findings on standard benign installations.

---

### Scenario 2: Dual-Use Software Discrimination

Verify that passive penetration-testing tools (Metasploit, Nmap, Wireshark, GDB, ExploitDB) and local development servers are not misclassified as malicious:

```bash
# Run dual-use tool classification test
go test -v ./test/realworld/... -run TestDualUseToolDiscrimination
```

**Expected Outcome**:
- Passive tools in standard paths produce `VerdictSafe` with `INFO` severity (`pentest_tool_path`).
- Localhost development servers (`127.0.0.1:8000`) produce `VerdictSafe` (`Network_Loopback_Listener`).
- Actively weaponized dual-use tools (e.g. `socat`/`nc` piped to reverse shell) are elevated to `ALERT` (`VerdictMalicious`, `StrengthCorroborated`).
- Triage accuracy $\ge 95.0\%$.

---

### Scenario 3: Runtime Race & Vanishing Process Churn

Stress-test Aether's procfs and socket traversal against rapidly terminating processes and ephemeral sockets:

```bash
# Run 50 iterations of high-churn process stress testing
go test -v ./test/realworld/... -run TestRuntimeRaceStress
```

**Expected Outcome**:
- Zero crashes, zero panics, zero unhandled errors (`os.ErrNotExist` / `safeopen.ErrVanished`).
- `SkippedVanished > 0` accurately recorded in coverage metrics.
- Zero false malware findings generated due to vanishing processes.

---

### Scenario 4: Scale, Memory Budget & Duration Profiling

Audit a large directory hierarchy (10k, 50k, 100k+ files) and measure throughput and resident set size (RSS):

```bash
# Run performance and memory scale benchmark
go test -v ./test/realworld/... -run TestRealWorldScaleAndMemory
```

**Expected Outcome**:
- Peak memory consumption remains strictly $\le 250\text{MB}$ RSS.
- Sustained file inspection throughput $\ge 2,500$ files/second on SSD storage.
- Subsystem duration breakdown logged (filesystem walk, hashing, heuristics, YARA, process, network, correlation).

---

### Scenario 5: Full Deep Scan & Executive Posture Assessment

Execute an end-to-end full audit on the host machine in read-only mode and inspect the multi-format report:

```bash
# Run full scan producing plain terminal output and offline HTML report
./aether scan --full --plain --html-out /tmp/aether-assessment.html
```

**Expected Outcome**:
- Executive summary clearly displays:
  - **SYSTEM STATUS**: `SAFE` | `ATTENTION REQUIRED` | `HIGH RISK` | `LIMITED VISIBILITY`
  - Total inspected files, running processes, sockets, persistence entries
  - Critical/high findings requiring immediate attention
  - Prioritized actionable remediation recommendations
- 100% 8-question explainability compliance on all reported findings.
- HTML report is 100% self-contained with zero external CDN fetches.

---

### Scenario 6: False-Positive Taxonomy & Regression Ingestion

Ingest an unexpected finding into the anomaly taxonomy and verify companion regression generation:

```bash
# Verify regression capture pipeline
go test -v ./test/realworld/... -run TestFalsePositiveTaxonomyRegression
```

**Expected Outcome**:
- Root cause categorized under `FP_*` or `FN_*`.
- Companion synthetic fixture added to `testdata/realworld_corpus/regressions/`.
- Regression test permanently verified in automated test suite.

