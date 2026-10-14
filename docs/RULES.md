# YARA Rules Guide for Aether

Aether includes native support for compiling and evaluating YARA rules via YARA-X when compiled with `-tags yara` (or using `make build-yara-static`).

---

## 1. Rule Discovery & Directory Structure

Aether discovers rule files (`*.yar`, `*.yara`) recursively from standard and configured locations:

1. `~/.config/aether/rules/`
2. `/etc/aether/rules/`
3. Custom directory passed via `--rules-dir <path>` or `rules_dir` config setting.

### Organizing Multiple Rule Sources
Place different signature sources in their own subdirectories under `~/.config/aether/rules/<source-name>/`:

```text
~/.config/aether/rules/
├── signature-base/     # Cloned from Neo23x0/signature-base
│   └── yara/
├── yara-forge-core/    # YARA-Forge core rule set
│   └── yara-forge-core.yar
└── custom/             # Internal / proprietary threat rules
    └── incident_response.yar
```

This structure allows multiple rule feeds to coexist cleanly. Aether derives distinct namespaces for each rule file so rules with identical names across different feeds do not collide.

### Strict Trust Enforcement
- **Root execution (`euid 0`)**: Aether strictly ignores user-controlled directories (e.g. under `/home/`) and loads only `/etc/aether/rules/` or explicit `--rules-dir`.
- **Non-root execution**: User directories are rejected with a warning if they are not owned by the invoking user (or root) or if they have group/world-writable permissions (`chmod g+w` or `chmod o+w`).

---

## 2. Acquiring Threat Intelligence Rule Sets

Aether does not bundle third-party threat signatures by default (only harmless demo rules via `--demo-rules`). You can populate `~/.config/aether/rules/` with public or commercial rule sets.

### Source A: Neo23x0 / signature-base
[signature-base](https://github.com/Neo23x0/signature-base) is a widely used collection of high-quality detection rules maintained by Florian Roth (Nextron Systems).

#### Download Instructions
```bash
mkdir -p ~/.config/aether/rules
git clone https://github.com/Neo23x0/signature-base.git ~/.config/aether/rules/signature-base
```

#### Licensing Terms
> [!IMPORTANT]
> **CC BY-NC 4.0 License Notice**:
> `signature-base` is licensed under the **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)** license.
> - **Permitted**: Free for personal, internal defense, and academic/research usage.
> - **Restriction**: Must **NOT** be redistributed inside a packaged, commercial, or distributed version of Aether without a separate commercial agreement from Nextron Systems.

---

### Source B: YARA-Forge
[YARA-Forge](https://yaraforge.github.io/) is an automated aggregator that collects, standardizes, tests, and deduplicates open-source YARA rules from dozens of trusted security repositories.

#### Recommendation: Use "Core" Package
YARA-Forge provides multiple package tiers. We recommend starting with the **"Core"** package:
- **Core Package (Recommended)**: Curated rule set with lower false-positive rates, high-fidelity signatures, and optimized scanning performance.
- **Full / Extended Packages**: Contain experimental or noisy signatures that may produce false positives on standard Linux systems.

#### Download Instructions
```bash
mkdir -p ~/.config/aether/rules/yara-forge-core
cd ~/.config/aether/rules/yara-forge-core

# Download the latest core rule set release
wget https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip
unzip yara-forge-rules-core.zip
rm yara-forge-rules-core.zip
```

#### Licensing Terms
YARA-Forge preserves individual upstream rule source licenses (e.g., Apache 2.0, BSD, MIT, GPL, CC-BY) with clear per-rule attribution in metadata.

---

## 3. Validating Rules (`aether rules validate`)

Before running a scan, you can verify that your downloaded rules compile cleanly using the `rules validate` subcommand. This parses all `*.yar` and `*.yara` files with the exact same YARA-X loader and global variables used during hunting, without inspecting target files.

### Syntax
```bash
./bin/aether-yara-static rules validate <directory>
```

### Example 1: Successful Validation
```bash
$ ./bin/aether-yara-static rules validate ~/.config/aether/rules/
[AETHER] YARA Rule Validation Report:
  Directory:                 /home/user/.config/aether/rules
  Rule Files Found:          142
  Files Compiled:            142
  Files Failed:              0
  Total Rules Loaded:        3850

[AETHER] Validation status: SUCCESS (all 142 file(s) valid)
```

### Example 2: Detecting Broken Rules
If a rule contains syntax errors or unsupported modules, `rules validate` details the failing file and exact error, exiting with a non-zero status:

```bash
$ ./bin/aether-yara-static rules validate /tmp/broken_rules/
[AETHER] YARA Rule Validation Report:
  Directory:                 /tmp/broken_rules
  Rule Files Found:          2
  Files Compiled:            1
  Files Failed:              1
  Total Rules Loaded:        1

[AETHER] Compilation Errors:
  [FAIL] /tmp/broken_rules/bad_syntax.yar
         Error: syntax error, unexpected identifier, expecting end of file

Error: YARA validation failed: 1 file(s) had syntax or compilation errors
```

---

## 4. External Variables

To ensure compatibility with public and private rule sets, Aether pre-defines and populates the following external string variables at scan time per file:

| Variable | Description | Example |
| :--- | :--- | :--- |
| `filename` | Base name of the target file | `malware.sh` |
| `filepath` | Full absolute path of the target file | `/tmp/malware.sh` |
| `extension` | File extension including leading dot | `.sh`, `.exe` |
| `filetype` | Detected file type | `ELF`, `PE`, `ASCII` |
| `owner` | File owner UID / username | `1000`, `root` |

Example rule utilizing external variables:
```yara
rule Suspicious_Temp_Script {
    strings:
        $rev = "/bin/bash -i >& /dev/tcp/"
    condition:
        $rev and (filepath matches /^\/tmp\// or filepath matches /^\/dev\/shm\//)
}
```

---

## 5. Metadata & Scoring Conventions

Aether parses rule metadata to calculate threat severity and determine verdict impact:

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

### Score-to-Severity Mapping

| Score Range | Severity Classification | Signal Type | Default Impact |
| :--- | :--- | :--- | :--- |
| `< 40` | `NOTICE` | Informational / Anomaly | Clean (noted in summary) |
| `40 - 74` | `WARNING` | Weak Indicator | Triggers `SUSPICIOUS` |
| `75 - 89` | `WARNING` | Strong Indicator (`IsStrong = true`) | Corroborating indicator for compromise |
| `$\ge 90$` | `ALERT` | High-Confidence Threat | Triggers `COMPROMISED` if `confidence: high` |

---

## 6. Self-Detection Prevention & Rules Directory Exclusions

To prevent YARA rule files from triggering false-positive detections on their own signature strings during filesystem scans, Aether applies multi-layered protection:
- **Walker-Level Exclusion**: All configured rules directories (`~/.config/aether/rules/`, `/etc/aether/rules/`, and `--rules-dir`) are excluded at the walker level (`filepath.SkipDir`). The scanner will never scan files inside its own rule directories regardless of target arguments.
- **Rule File Qualification**: Any `.yar`/`.yara` files outside configured rule directories ($\le 2\text{MB}$) that contain valid rule structure and no other threat signals are classified as `YARA_Rule_File` (`INFO`).

---

## 7. Known-Tool Suppression & Pentest Workstations

When scanning Linux systems with extensive security tooling installed (e.g. Kali Linux, Parrot OS, or security analyst workstations), standard YARA rules often match legitimate penetration testing utilities. Aether handles this via two mechanisms:

### 1. Package-Ownership Downgrade
When a file matching a YARA rule is owned by an installed distribution package (e.g. verified via `dpkg`/`pacman` database), Aether downgrades the match severity by one level (`ALERT` $\rightarrow$ `WARNING` $\rightarrow$ `NOTICE`) and tags the finding with `known_package_owned: true` and `package_name`.
- **Active Exploit Exception**: If a rule explicitly defines `severity = "alert"` or `severity = "critical"` in its metadata, the downgrade is bypassed (ransomware and active exploitation artifacts retain full severity regardless of package ownership).

### 2. Pentest Tool Path Trust (`--trust-installed-pentest-tools`)
Aether includes the `--trust-installed-pentest-tools` flag (disabled by default: `false` for maximum incident response assurance). When explicitly enabled on pentest audit machines, matches inside well-known pentest tool locations:
- `/usr/share/metasploit-framework`
- `/usr/share/windows-resources`
- `/usr/share/powershell-empire`
- `/usr/share/exploitdb`
- `/usr/share/peass`
- `/usr/lib/python3/dist-packages/pypykatz*`
- `/usr/lib/python3/dist-packages/nxc*`

are downgraded to `INFO` with the original severity recorded in metadata (`original_severity`), preventing legitimate tool suites from skewing the final scan verdict.

> [!IMPORTANT]
> `--trust-installed-pentest-tools` is strictly opt-in and designed for authorized workstations and VMs where penetration testing tools are legitimately installed. When scanning an authorized pentest machine, enable this flag:
> ```bash
> sudo aether scan --full --trust-installed-pentest-tools=true
> ```

