# Quickstart: Feature 003 — Runtime Threat Assessment & Static/Runtime Correlation

This guide demonstrates how to validate the runtime threat hunting capabilities, static/runtime correlation engine, and benchmark integration introduced in Feature 003.

---

## 1. Prerequisites & Compilation

```bash
# Verify standard pure-Go build
go build -o /tmp/aether ./cmd/aether

# Verify YARA-X enabled build (optional)
go build -tags yara -o /tmp/aether-yara ./cmd/aether
```

---

## 2. Validation Scenarios

### Scenario A: Full System Threat Assessment with Live Process & Network Inspection
Run a quick hunt evaluating processes, network sockets, persistence, and critical filesystem locations:

```bash
/tmp/aether quick --plain
```

**Expected Outcome**:
- Emits clean inspection metrics for active processes (`Inspected`, `SkippedPermission`, `Limited`).
- Maps listening ports (`0.0.0.0:*`, `127.0.0.1:*`) to owning processes and package status.
- Classifies verified system services (`sshd`, `systemd`) as `VerdictSafe` (`INFO`).

---

### Scenario B: Multi-Vector Static & Runtime Correlation Verification
Simulate an incident where a suspicious dropper script exists on disk and is actively running with an open socket:

```bash
# Run unit tests validating cross-module correlation logic
go test -v ./internal/report/... -run TestCorrelation
```

**Expected Outcome**:
- Individual contextual signals from filesystem, process, and network modules are correlated into a single `Finding`.
- Evidence strength elevates to `StrengthCorroborated`.
- Final verdict computes to `VerdictMalicious` (`ALERT`, `ConfidenceHigh`).

---

### Scenario C: Feature 002 Benchmark Evaluation with Hermetic Runtime Fixtures
Run the detection accuracy benchmark including `SUSP-LISTEN-001` and `SUSP-UPGRADE-001`:

```bash
# Run the benchmark suite
go test -v -count=1 ./test/benchmark/... -run TestRunDetectionBenchmark
```

**Expected Benchmark Scorecard**:
- **Threat Recall**: $100.00\%$ ($12/12$) $\ge 95.0\%$
- **Precision**: $100.00\%$ ($12/12$) $\ge 90.0\%$
- **False-Positive Rate**: $0.00\%$ ($0/9$) $= 0.0\%$
- **Suspicious Triage Accuracy**: $\ge 90.00\%$ (resolving `SUSP-LISTEN-001` and `SUSP-UPGRADE-001`)
- **Abstention Accuracy**: $100.00\%$ ($1/1$)
- **8-Question Explainability**: $100.00\%$ compliant
- **10-Run Determinism**: $100.00\%$ byte-for-byte identical JSON
