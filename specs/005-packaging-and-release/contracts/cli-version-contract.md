# Contract: CLI Version Output Contract

**Feature Branch**: `005-packaging-and-release`  
**Created**: 2026-10-04  
**Status**: Active

---

## 1. Overview

The `aether version` command provides standardized, human-readable, and script-parseable metadata describing the exact build version, git commit, build date, Go compiler, OS/architecture, and active threat detection engine.

To uphold **Principle III (Zero False Equivalence)**, the command MUST explicitly distinguish between the **Pure-Go Build** and the **YARA-X Enabled Build**.

---

## 2. Command Invocation

```bash
aether version
```

- Exit code: `0` on success.
- Standard output: UTF-8 formatted text block.
- Standard error: Empty.

---

## 3. Pure-Go Binary Contract (`CGO_ENABLED=0`)

When invoked on a pure-Go compiled binary:

```text
Aether Threat Hunter v1.0.0
  Commit:     <7-to-40-char-git-commit>
  Build Date: <ISO-8601-UTC-timestamp>
  Go Version: go1.26.8
  OS/Arch:    linux/amd64
  YARA:       disabled (native heuristics only)
```

### Constraints:
- Line 1 MUST match: `^Aether Threat Hunter v[0-9]+\.[0-9]+\.[0-9]+.*$`
- Line 2 MUST match: `^\s*Commit:\s+[a-f0-9]+$`
- Line 3 MUST match: `^\s*Build Date:\s+[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`
- Line 4 MUST match: `^\s*Go Version:\s+go[0-9.]+$`
- Line 5 MUST match: `^\s*OS/Arch:\s+linux/(amd64|arm64)$`
- Line 6 MUST EXACTLY EQUAL: `  YARA:       disabled (native heuristics only)`

---

## 4. Static YARA-X Binary Contract (`CGO_ENABLED=1`, `-tags yara`)

When invoked on a YARA-X static compiled binary:

```text
Aether Threat Hunter v1.0.0
  Commit:     <7-to-40-char-git-commit>
  Build Date: <ISO-8601-UTC-timestamp>
  Go Version: go1.26.8
  OS/Arch:    linux/amd64
  YARA:       YARA-X v1.21.0 (static)
```

### Constraints:
- Line 6 MUST EXACTLY EQUAL: `  YARA:       YARA-X v1.21.0 (static)`
- Neither variant may output confusing or ambiguous phrasing such as `YARA: not compiled in` or `YARA: active`.
