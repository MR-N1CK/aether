# Research & Architectural Decisions: Trustworthy Detection & False-Positive Control

**Feature**: Trustworthy Detection & False-Positive Control  
**Date**: 2026-10-03  
**Status**: Completed  

---

## 1. Analysis of Benign Corpus Matches (Ground Truth Investigation)

During system-wide benign corpus verification on Kali Linux (`/etc`, `/usr/bin`, `/usr/lib/python3*`), 5 matches were reported across 94,310 files:

### Match 1 & 2: `Linux_Dropper_Remote_Pipe_Shell_Execution`
- **Paths**:
  - `/usr/lib/python3/dist-packages/elasticsearch-9.5.0.dist-info/METADATA`
  - `/usr/lib/python3/dist-packages/theharvester-4.11.1.dist-info/METADATA`
- **Root Cause**: Python wheel metadata files (`.dist-info/METADATA`) include the upstream package's `README.rst` / `README.md` text. The documentation contains example setup commands such as `curl -s https://... | bash`.
- **Finding**: These are inert text/documentation files (`mode 0644`, owned by Debian package `python3-elasticsearch` / `theharvester`), not executable scripts or droppers.
- **Architectural Decision**: Non-executable documentation, metadata files, and package wheel metadata (`*.dist-info/*`, `*.egg-info/*`, `*.md`, `*.rst`, `*.txt`) in verified package directories MUST NOT be treated as active droppers. The engine will evaluate file attributes (`isExec`, path pattern, package ownership) before elevating to `ALERT`.

### Match 3, 4, 5: `Linux_Malware_Data_Exfiltration_Server`
- **Paths**:
  - `/usr/lib/python3/dist-packages/cheroot/server.py`
  - `/usr/lib/python3/dist-packages/joblib/test/test_numpy_pickle.py`
  - `/usr/lib/python3/dist-packages/twisted/internet/test/test_fdset.py`
- **Root Cause**:
  - `cheroot/server.py` is a legitimate HTTP server implementation that binds, listens, and accepts sockets, and happens to include debugging strings.
  - `joblib` and `twisted` are unit test files (`/test/`, `test_*.py`) that implement mock socket listeners to test network transport handling.
- **Architectural Decision**:
  - Package Ownership: All three files are owned by verified Debian packages (`python3-cheroot`, `python3-joblib`, `python3-twisted`).
  - Test Directory Context: Files located in test subtrees (`/test/`, `/tests/`, `*_test.py`) inside verified packages represent unit test mock code, not active C2 listeners.
  - The engine will contextualize matches using package DB validation and test path semantics to downgrade them to `NOTICE` / `SAFE`.

---

## 2. Decision: Decoupling Severity Score from Final Verdict

### Decision
`Severity` (`ALERT`, `WARNING`, `NOTICE`, `INFO`) and `Score` (0–100) are retained as measures of **potential operational impact**, while an explicit `Verdict` (`MALICIOUS`, `SUSPICIOUS`, `SAFE`, `UNKNOWN`) is introduced as the **analytical classification**.

```
┌───────────────────────────┐      ┌───────────────────────────┐
│     Severity / Score      │      │          Verdict          │
├───────────────────────────┤      ├───────────────────────────┤
│ • ALERT (85–100)          │      │ • MALICIOUS (Confirmed)   │
│ • WARNING (50–84)         │      │ • SUSPICIOUS (Anomaly)    │
│ • NOTICE (20–49)          │      │ • SAFE (Clean/Suppressed) │
│ • INFO (0–19)             │      │ • UNKNOWN (Visibility Lim)│
└───────────────────────────┘      └───────────────────────────┘
```

### Rationale
- Existing CLI flags, UI themes, and reporting formats depend on the severity bands.
- However, currently, any finding created with `SeverityAlert` is automatically rendered as a top-level Malicious Threat in UI summaries.
- By computing `Verdict` independently from `(Evidence, Context, Confidence, Corroboration)`, a rule with score 90 that matches a package-owned test file will be classified as `Verdict: SAFE` (or `NOTICE`) with reason `Context: Verified package test fixture`, preventing false-positive alarm triggers.

### Alternatives Considered
- *Alternative A: Mutating the YARA rule scores directly to 0.* Rejected because the rule is genuinely dangerous if found in `/tmp` or an unauthorized path; changing the static score breaks rule reuse.
- *Alternative B: Rewriting the entire Finding model.* Rejected because it violates the Minimal-Change Principle and breaks backward compatibility with existing reporters.

---

## 3. Decision: Package DB & Context Evaluation Pipeline

### Decision
Extend the scanning flow so that **both** pure-Go heuristics and embedded YARA-X scanning pass through a unified `ContextEvaluator` before finalizing findings.

```
[ Raw Rule Match (Heuristic / YARA / IOC) ]
                     │
                     ▼
       [ ContextEvaluator (pkgdb + fs) ]
                     │
      ┌──────────────┴──────────────┐
      ▼                             ▼
[ Verified Package / Doc ]    [ Unowned / Active Threat ]
      │                             │
      ▼                             ▼
Verdict: SAFE/NOTICE          Verdict: MALICIOUS/SUSPICIOUS
(Context Suppressed)          (High Confidence Alert)
```

### Context Evaluation Rules:
1. **Unmodified Package Owned**: If `pkgdb.Owner(path)` is true and file is an inert format (`.dist-info`, `.md`, `.rst`, `.txt`) or in a test path (`/test/`, `test_*.py`), downgrade from `MALICIOUS` to `SAFE`/`NOTICE`.
2. **Trojanized / Active Execution Exception**: If a package-owned file has an active open listening socket mapped in `/proc/net/tcp` or a live memory execution descriptor (`memfd:` / deleted binary), the finding is NOT suppressed.
3. **Build-Tree Artifacts**: Preserved via `CheckBuildTree`.

---

## 4. Decision: Multi-Detector Deduplication & Corroboration

### Decision
When multiple detectors flag the same target (e.g. Heuristic Reverse Shell + YARA Reverse Shell on `/tmp/backdoor.sh`), the engine groups them by `(Path, TargetAsset)`:
- Primary finding retains the highest severity and most specific MITRE mapping.
- Additional matching rule names are aggregated into `ContributingDetectors []string`.
- Corroborating signals from different inspection vectors (e.g. static file content + persistence unit + active network socket) elevate confidence to `HIGH`.

---

## 5. Decision: Deterministic Aggregation & Output

### Decision
Multi-threaded worker pool results collected by `Reporter` MUST be sorted deterministically before output serialization:
- Primary Sort Key: `Path` (alphabetical).
- Secondary Sort Key: `LineNumber` (ascending).
- Tertiary Sort Key: `RuleName` (alphabetical).

Presentation metadata that legitimately varies per run (such as `ScanStartTime` and `ElapsedTime`) will be kept in run headers without affecting the deterministic ordering of findings.
