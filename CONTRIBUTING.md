# Contributing

Aether is a read-only forensic scanner. Changes should keep that promise obvious to the next reader.

## Before you change detection logic

Read [AGENTS.md](AGENTS.md). New heuristics belong in `internal/scanner/heuristics.go` and, when they are signatures, in `internal/yara/embedded_rules.go`. Every new rule name needs a title, a plain-language explanation, MITRE ATT&CK mapping, and remediation in `internal/report/finding.go` (via the rule metadata registers). Add a unit test beside the change.

## Checks

```bash
make test
gofmt -l .
```

A YARA-linked build is optional. `make build` stays pure Go.

## Review shape

- Keep pulls focused. A detection, its report copy, and its test belong together.
- Do not execute samples, including anything under test fixtures that is meant to be scanned statically.
- Do not open inspected files with a write flag, and do not update `mtime` or `ctime`.
- Do not add telemetry, hardcoded credentials, or a default outbound connection.
- Match the Aurora Command Deck tokens in [DESIGN.md](DESIGN.md) when you touch the TUI, plain output, or HTML report.

Questions about behavior belong in an issue. Suspected vulnerabilities belong in a private advisory. See [SECURITY.md](SECURITY.md).
