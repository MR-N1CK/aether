# YARA Rules Guide for Aether

Aether includes native support for compiling and evaluating YARA rules via YARA-X when compiled with `-tags yara`.

---

## 1. Rule Discovery & Directory Trust

Aether discovers rule files (`*.yar`, `*.yara`) recursively from standard and configured locations:

1. `~/.config/aether/rules/`
2. `/etc/aether/rules/`
3. Custom directory passed via `--rules-dir <path>` or `rules_dir` config setting.

### Strict Trust Enforcement
- **Root execution (euid 0)**: Aether strictly ignores user-controlled directories (e.g. under `/home/`) and loads only `/etc/aether/rules/` or explicit `--rules-dir`.
- **Non-root execution**: User directories are rejected with a warning if they are not owned by the invoking user (or root) or if they have group/world-writable permissions (`chmod g+w` or `chmod o+w`).

---

## 2. External Variables

To ensure compatibility with major public and private rule sets, Aether pre-defines and sets the following external string variables at scan time per file:

| Variable | Description | Example |
| :--- | :--- | :--- |
| `filename` | Base name of the target file | `malware.sh` |
| `filepath` | Full absolute path of the target file | `/tmp/malware.sh` |
| `extension` | File extension including leading dot | `.sh`, `.exe` |
| `filetype` | Detected file type | `ELF`, `PE`, `ASCII` |
| `owner` | File owner UID / username | `1000`, `root` |

Example condition using external variables:
```yara
rule Detect_Suspicious_Script {
    strings:
        $cmd = "/bin/bash -i >& /dev/tcp/"
    condition:
        $cmd and extension == ".sh"
}
```

---

## 3. Metadata & Scoring Conventions

Aether inspects rule metadata to calculate threat severity and determine verdict impact:

```yara
rule Example_Threat {
    meta:
        description = "Detects webshell payload"
        author = "Security Team"
        score = 85               // Numeric score (0 - 100)
        severity = "HIGH"        // CRITICAL, HIGH, MEDIUM, LOW, INFO
        confidence = "high"      // "high" allows single-match COMPROMISED
    strings:
        $eval = "eval(base64_decode("
    condition:
        $eval
}
```

### Score-to-Severity Mapping Table

All scores are clamped to `[0, 100]` before severity mapping:

| Score Range | Severity Classification | Signal Type | Default Impact |
| :--- | :--- | :--- | :--- |
| `< 40` | `NOTICE` | Informational / Anomaly | Clean (noted in summary) |
| `40 - 74` | `WARNING` | Weak Indicator | Triggers `SUSPICIOUS` |
| `75 - 89` | `WARNING` | Strong Indicator (`IsStrong = true`) | Corroborating indicator for compromise |
| `$\ge 90$` | `ALERT` | High-Confidence Threat | Triggers `COMPROMISED` if `confidence: high` |

*Thresholds are configurable in `config.yaml` via `yara_warning_score` (default 40), `yara_strong_score` (default 75), and `yara_alert_score` (default 90).*

---

## 4. Rule File Qualification & Self-Detection Prevention

To prevent YARA rule files from triggering false-positive detections on their own signature strings during filesystem scans, Aether applies the following rules:

- Target files located in scanned directories that match a YARA rule are checked for rule qualification:
  1. Have `.yar` or `.yara` extension.
  2. Size $\le 2\text{MB}$.
  3. Contain no NUL bytes, no ELF header (`\x7fELF`), and no shebang (`#!`).
  4. Contain valid YARA rule structure (`rule ... { ... }`).
  5. **No other threat signals** (IOC or filesystem heuristics) triggered on the file.
- When qualified, the match is downgraded to `INFO` `"looks like a YARA rule file"` and counted as `"Rule Files Seen: N"` in the scan coverage summary.
- Binary files (e.g. ELFs renamed to `.yar`) or malicious scripts prefixed with dummy rule headers **never qualify** and are not downgraded.

---

## 5. Third-Party Rule Licensing Notice

> [!IMPORTANT]
> **Check Licenses Before Deploying Rule Sets**:
> - Aether does not bundle third-party rule sets by default. Only harmless synthetic demo rules (e.g. EICAR test string and marker signatures) are embedded and enabled via `--demo-rules`.
> - When importing external rule collections (such as Neo23x0/signature-base, YARA-Forge, ReversingLabs, or community repositories), you must verify their respective software licenses:
>   - **signature-base**: Detection Rule License (DRL).
>   - **YARA-Forge**: Mixed licenses (Apache 2.0, GPL, CC-BY, etc. depending on rule package).
> - Ensure your usage and organizational deployment comply with the specific license terms of each included rule repository.
