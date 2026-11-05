# Aether: High-Assurance Linux Threat Hunting & Forensics Engine

**Aether** is a fast, read-only Linux threat hunting and incident response tool written in **Go** with embedded **YARA-X** signature evaluation. It is designed to inspect Linux endpoints for active compromises, web shells, reverse shells, ransomware encryptors, data exfiltration stealers, rogue persistence mechanisms, unauthorized accounts, and kernel rootkits.

---

## Verified Capabilities & Codebase References

Every capability listed below is implemented in this repository and validated by automated unit and integration tests.

### 1. Detection Modules & Forensic Auditing

| Module | Implemented Capabilities | Implementation & Test Evidence |
| :--- | :--- | :--- |
| **`process`** | • Memory-only execution (`/memfd:`, anonymous memory descriptors)<br>• Execution of unlinked binaries (`(deleted)` target marker)<br>• Hidden process detection via two-pass `os.ReadDir` vs parallel `unix.Fstatat` probes with `/proc` `hidepid` detection<br>• Process `comm` vs `cmdline` vs `exe` name masquerading<br>• Process tree anomaly detection and allowlist matching | Implemented: [`internal/modules/process/process.go`](internal/modules/process/process.go), [`hidden_pid.go`](internal/modules/process/hidden_pid.go)<br>Tested: [`internal/modules/process/process_test.go`](internal/modules/process/process_test.go) |
| **`persistence`** | • Systemd system and user units, unowned unit files, and autostart services<br>• Masked unit analysis (`/dev/null` symlink targets)<br>• System cron (`/etc/cron*`, `/etc/crontab`) and per-user spool crontabs (`/var/spool/cron/crontabs`)<br>• At-jobs and timer services<br>• Sudoers configurations (`/etc/sudoers`, `/etc/sudoers.d/*`)<br>• Shell login profiles (`.bashrc`, `.zshrc`, `/etc/profile.d/`)<br>• SSH authorized keys auditing (`~/.ssh/authorized_keys*`) and private keys in non-standard paths<br>• Multi-vector persistence correlation | Implemented: [`internal/modules/persistence/persistence.go`](internal/modules/persistence/persistence.go), [`systemd.go`](internal/modules/persistence/systemd.go), [`cron.go`](internal/modules/persistence/cron.go), [`ssh.go`](internal/modules/persistence/ssh.go)<br>Tested: [`internal/modules/persistence/persistence_test.go`](internal/modules/persistence/persistence_test.go) |
| **`users`** | • Non-root accounts with UID 0<br>• Duplicate UIDs across `/etc/passwd`<br>• `/etc/shadow` password checks (empty passwords, obsolete DES/MD5 `$1$` hashes, locked account filtering)<br>• System accounts configured with interactive login shells<br>• Privileged group memberships (`sudo`, `wheel`, `docker`, `lxd`) | Implemented: [`internal/modules/users/users.go`](internal/modules/users/users.go)<br>Tested: [`internal/modules/users/users_test.go`](internal/modules/users/users_test.go) |
| **`network`** | • Inode-to-process socket mapping across TCP, UDP, and Raw sockets<br>• Wildcard listener detection (`0.0.0.0`, `::`) with daemon allowlists<br>• Loopback listener reporting (`Network_Loopback_Listener`)<br>• Promiscuous packet sniffers and raw socket consumers via `/proc/net/raw` | Implemented: [`internal/modules/network/network.go`](internal/modules/network/network.go)<br>Tested: [`internal/modules/network/network_test.go`](internal/modules/network/network_test.go) |
| **`kernel`** | • Loaded kernel module audit via `/proc/modules` vs `/sys/module`<br>• Hidden kernel module detection (two-pass state comparison with `coming`/`going` filter)<br>• Kernel taint flag decoding per Linux kernel documentation<br>• World-writable or non-standard modprobe configuration rules | Implemented: [`internal/modules/kernel/kernel.go`](internal/modules/kernel/kernel.go)<br>Tested: [`internal/modules/kernel/kernel_test.go`](internal/modules/kernel/kernel_test.go) |
| **`filesystem` & `scanner`** | • SUID/SGID binary anomalies outside standard binary paths<br>• Hidden executables in system directories (`/bin`, `/sbin`, `/usr/bin`, `/etc`)<br>• Non-packaged ELF binaries in `/tmp`, `/var/tmp`, `/dev/shm`, and regular files in `/dev`<br>• Build tree artifact recognition to avoid false positives on legitimate compiler output<br>• World-writable configuration files in `/etc`<br>• Concurrent worker pool with dynamic memory budget enforcement | Implemented: [`internal/scanner/scanner.go`](internal/scanner/scanner.go), [`heuristics.go`](internal/scanner/heuristics.go), [`memory_budget.go`](internal/scanner/memory_budget.go)<br>Tested: [`internal/scanner/heuristics_test.go`](internal/scanner/heuristics_test.go), [`fixtures_test.go`](internal/scanner/fixtures_test.go) |

---

### 2. Verified Heuristic & YARA-X Signature Rules

> **Build Notice**: The embedded threat signatures below are active in **every build**. Default binaries (`make build`, `CGO_ENABLED=0`) evaluate them with the **pure-Go fallback signature engine** ([`internal/yara/fallback_engine.go`](internal/yara/fallback_engine.go)), a dependency-free interpreter for the embedded rule subset; YARA builds (`make build-yara` / `make build-yara-static` with `-tags yara`, linking `libyara_x_capi`) evaluate the same rule source with **YARA-X** ([`internal/yara/yarax_engine.go`](internal/yara/yarax_engine.go)). Both engines compile the identical embedded source ([`internal/yara/embedded_rules.go`](internal/yara/embedded_rules.go)), and a cross-engine parity test ([`internal/yara/fallback_parity_test.go`](internal/yara/fallback_parity_test.go)) guarantees identical verdicts. In addition to signatures, the default build always evaluates native pure-Go regex heuristics ([`internal/scanner/heuristics.go`](internal/scanner/heuristics.go)).
>
> **Signature Note**: Rootkit and known-family detection rules (such as `Linux_Rootkit_Diamorphine_Reptile_Strings`, `Linux_Webshell_PHP_Known_Families`, and `Linux_Implant_RedTeam_Persistence_Framework`) are string matches for known samples and repository artifacts only; they are not generic behavioral kernel hooks.

| Category | Native Heuristics (Default Pure-Go Build) | Embedded YARA-X Rules (YARA Builds Only) | Source & Test Verification |
| :--- | :--- | :--- | :--- |
| **Reverse Shells** | • `Script_Reverse_Shell_Interactive`<br>• `Script_OpenSSL_Reverse_Shell`<br>• `Script_Netcat_Reverse_Shell`<br>• `Script_Socat_Reverse_Shell`<br>• `Script_Reverse_Shell_Inline` | • `Linux_Backdoor_Reverse_Shell_OneLiner`<br>• `Linux_Backdoor_Encrypted_Reverse_Shell` | Heuristics: [`internal/scanner/heuristics.go`](internal/scanner/heuristics.go), tested in [`heuristics_test.go`](internal/scanner/heuristics_test.go)<br>YARA: [`internal/yara/embedded_rules.go`](internal/yara/embedded_rules.go), tested in [`yarax_integration_test.go`](internal/yara/yarax_integration_test.go) |
| **Ransomware & Stealers** | • `Script_Python_Ransomware_Encryptor`<br>• `Script_Data_Exfiltration_Stealer`<br>• `Script_C2_Exfiltration_Server` | • `Linux_Ransomware_Python_Locker`<br>• `Linux_Malware_Data_Exfiltration_Client`<br>• `Linux_Malware_Data_Exfiltration_Server` | Heuristics: [`internal/scanner/heuristics.go`](internal/scanner/heuristics.go), tested in [`heuristics_test.go`](internal/scanner/heuristics_test.go)<br>YARA: [`internal/yara/embedded_rules.go`](internal/yara/embedded_rules.go), tested in [`yarax_integration_test.go`](internal/yara/yarax_integration_test.go) |
| **Web Shells & Backdoors** | • `Webshell_PHP_Generic_Backdoor` | • `Linux_Webshell_PHP_Generic_Backdoor`<br>• `Linux_Webshell_PHP_Known_Families`<br>• `Linux_Webshell_JSP_Runtime_Exec` | Heuristics: [`internal/scanner/heuristics.go`](internal/scanner/heuristics.go), tested in [`heuristics_test.go`](internal/scanner/heuristics_test.go)<br>YARA: [`internal/yara/embedded_rules.go`](internal/yara/embedded_rules.go), tested in [`yarax_integration_test.go`](internal/yara/yarax_integration_test.go) |
| **Implants & Rootkits** | • `Script_RedTeam_Persistence_Framework`<br>• `Script_Process_Hiding_Procfs`<br>• `Script_Download_And_Execute` | • `Linux_Implant_RedTeam_Persistence_Framework`<br>• `Linux_Rootkit_LDPRELOAD_Hook_Artifact`<br>• `Linux_Rootkit_Diamorphine_Reptile_Strings`<br>• `Linux_Malware_Cryptominer_Stratum_Pool`<br>• `Linux_Dropper_Remote_Pipe_Shell_Execution` | Heuristics: [`internal/scanner/heuristics.go`](internal/scanner/heuristics.go), tested in [`heuristics_test.go`](internal/scanner/heuristics_test.go)<br>YARA: [`internal/yara/embedded_rules.go`](internal/yara/embedded_rules.go), tested in [`yarax_integration_test.go`](internal/yara/yarax_integration_test.go) |

---

### 3. MITRE ATT&CK & Enrichment Pipeline

Findings are enriched with MITRE ATT&CK tactical classifications, explanations, and remediation guidance in [`internal/report/finding.go`](internal/report/finding.go):

- **Mapped Techniques**: `T1547` (Boot or Logon Autostart), `T1564.001` (Hidden Files/Directories), `T1552.004` (Private Keys), `T1059.004` (Unix Shell), `T1014` (Rootkit), `T1486` (Data Encrypted for Impact), `T1070.004` (File Deletion), `T1041` (Exfiltration Over C2 Channel), `T1005` (Data from Local System), `T1071.001` (Web Protocols), `T1573.002` (Asymmetric Cryptography), `T1105` (Ingress Tool Transfer), `T1505.003` (Web Shell), `T1548.001` (Setuid/Setgid), `T1620` (Reflective Code Loading).
- **Test Evidence**: Verified in [`internal/report/reporter_test.go`](internal/report/reporter_test.go) and [`internal/scanner/heuristics_test.go`](internal/scanner/heuristics_test.go).

---

### 4. User Interfaces & Reporting

1. **Interactive Terminal UI (TUI) & Command Center**:
   - Built with Bubbletea and Lipgloss.
   - Interactive launcher menu when run without arguments (`aether`).
   - Live scanning telemetry, module progress indicators, and interactive finding navigation.
   - **Forensic Threat Dossier Modal**: Pressing `[Enter]` on a finding displays threat assessment, cryptographic hashes, MITRE ATT&CK techniques, and containment steps.
   - Evidence: Implemented in [`internal/ui/tui/launcher.go`](internal/ui/tui/launcher.go), [`model.go`](internal/ui/tui/model.go), [`view.go`](internal/ui/tui/view.go).
2. **Plain Terminal Output (`--plain`)**:
   - High-contrast ANSI formatted card output for standard terminal environments and CI/CD pipelines.
   - Evidence: Implemented in [`internal/ui/plain/plain.go`](internal/ui/plain/plain.go), tested in [`ui_test.go`](internal/ui/plain/ui_test.go).
3. **Structured JSON Output (`--json-out <file>`)**:
   - Streamed event format for SIEM ingestion (Splunk, Elastic, Sentinel).
   - Evidence: Implemented in [`internal/report/reporter.go`](internal/report/reporter.go), tested in [`reporter_test.go`](internal/report/reporter_test.go).
4. **Self-Contained Offline HTML Report (`--html-out <file.html>`)**:
   - Single-file report with zero external CDN dependencies, inline styles, inline SVG, and a strict Content-Security-Policy with cryptographic nonce (`crypto/rand`).
   - Dynamic DOM-safe rendering (no `innerHTML`).
   - Host/user redaction support (`--redact-hosts`).
   - Evidence: Implemented in [`internal/report/html/html.go`](internal/report/html/html.go), tested in [`html_test.go`](internal/report/html/html_test.go).
5. **Cryptographic Hash Display**:
   - Streaming SHA-256, MD5, and SHA-1 hashing up to the maximum file size.
   - Evidence: Implemented in [`internal/hasher/hasher.go`](internal/hasher/hasher.go), surfaced in HTML and TUI modal views.

---

## Installation & Setup

### Hardened Installation Workflow (`install.sh`)
The repository includes a security-hardened installation script ([`install.sh`](install.sh)) with separation of privileges:

1. **Build Phase (Unprivileged user)**:
   ```bash
   ./install.sh build
   ```
   - Refuses execution if run as root.
   - If `pkg-config` detects `yara_x_capi`, compiles `bin/aether-yara-static` (statically linking `libyara_x_capi.a`).
   - Otherwise, compiles pure Go `bin/aether` and prints that YARA is not included.

2. **Install Phase (Root user with SHA-256 pin)**:
   ```bash
   # 1. Check binary hash and path
   sha256sum bin/aether-yara-static
   
   # 2. Install with explicit SHA-256 confirmation
   sudo ./install.sh install --sha256 <computed-sha256>
   ```
   - Verifies `bin/` directory and source binary are owned by `$SUDO_USER` and strictly non-group/world-writable.
   - Requires `--sha256 <hash>` parameter matching the computed file hash.
   - Installs to `/usr/local/bin/aether` (`root:root`, mode `0755`).
   - Invokes `/usr/local/bin/aether setup --download-rules=false`.

### What `aether setup` Creates
[`internal/setup/setup.go`](internal/setup/setup.go) creates only directory structures (never chmods pre-existing directories):

| Context | Created Path | Mode | Owner | Condition |
| :--- | :--- | :--- | :--- | :--- |
| **Root** (`sudo aether setup`) | `/etc/aether/rules` | `0755` (`rwxr-xr-x`) | `root:root` | Created only if does not exist; path restricted to `/etc/aether` |
| **Non-Root** (`aether setup`) | `~/.config/aether/rules` | `0700` (`rwx------`) | Invoking user | Created only if does not exist |

*(Note: If `--download-rules` is passed, YARA rules `.yar` are written to that directory).*

### Manual Compilation
```bash
# 1. Pure Go build (CGO_ENABLED=0, pure Go heuristics and fallback engine)
make build

# 2. Native YARA-X build (Dynamic linking against libyara_x_capi)
make build-yara

# 3. Static YARA-X build (Statically links libyara_x_capi.a for portability)
make build-yara-static
```

---

## CLI Usage Guide

```bash
# 1. Open Interactive Command Center (when run with no arguments in a TTY)
aether

# 2. Fast triage scan of high-risk locations and persistence hooks
aether scan --quick --plain

# 3. Full deep system scan with self-contained HTML report
aether scan --full --html-out /tmp/aether-report.html

# 4. Target a specific directory or script
aether scan --plain /path/to/target

# 5. Interactive Bubbletea TUI scan
aether scan --quick --tui

# 6. Acknowledge a known benign finding (pins file/line hash to suppress alerts)
aether ack /path/to/file --reason "Approved internal administration script"

# 7. Refresh YARA ruleset and (optionally) a remote intel feed
sudo aether update                                # re-download YARA-Forge Core ruleset
sudo aether update --intel-url https://example.com/feeds/hashlist.txt   # HTTPS feeds only
aether intel import /path/to/local-feed.txt       # offline import path
```

---

## Forensic Integrity & File Access Semantics

- **Read-Only Invariant**: Aether never writes to, modifies, deletes, or executes inspected files. File modification time (`mtime`) and metadata change time (`ctime`) are **never** altered.
- **Access Time (`atime`) Behavior**:
  - File reads are initiated using [`safeopen.OpenRegularReadOnly`](internal/safeopen/safeopen.go) with flags `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOATIME`.
  - On Linux, the `O_NOATIME` flag requires file ownership or the `CAP_FOWNER` capability (typically root). If `O_NOATIME` returns `EPERM`, `safeopen` falls back to `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`.
  - Consequently, running scans as an unprivileged user against files owned by other accounts on filesystems mounted with `atime` or `relatime` may result in the kernel updating `atime`, unless the filesystem is mounted with `noatime`.
- **Symlink Boundary Isolation**: Evaluates paths using `O_NOFOLLOW` and verifies root containment to protect against TOCTOU race conditions and symlink escape attacks. Tested in [`internal/safeopen/safeopen_test.go`](internal/safeopen/safeopen_test.go).

---

## Trust Model

1. **Air-Gapped Operation**: Aether performs zero outbound network requests and requires no cloud connectivity or telemetry ingestion.
2. **YARA Rule Security & Qualification**: Custom rule directories supplied via `--rules-dir` are subjected to strict root-safety qualification ([`internal/yara/lib_trust.go`](internal/yara/lib_trust.go)). Rules located in non-root-owned or world-writable paths are rejected unless `--trust-rules-dir` is explicitly passed. Rule files are also checked to prevent self-detection on rule signature strings. Tested in [`internal/yara/lib_trust_test.go`](internal/yara/lib_trust_test.go).
3. **Cryptographic False-Positive Pinning**: The `aether ack` triage mechanism ([`internal/triage/triage.go`](internal/triage/triage.go)) records cryptographic SHA-256 hashes of matched lines and targets. If an acknowledged file is modified, the acknowledgment is automatically voided. `ALERT` and explicit IOC matches are non-ackable. Tested in [`internal/triage/triage_test.go`](internal/triage/triage_test.go).
4. **Package DB Validation**: Integrates with local dpkg status databases ([`internal/pkgdb/pkgdb.go`](internal/pkgdb/pkgdb.go)) to verify package file ownership and avoid false positives on legitimate vendor binaries.

---

## Limitations

1. **Non-Root Coverage Constraints**: When executed as an unprivileged user, Aether cannot read `/etc/shadow`, root-only cron spool files, or other users' private `/proc/<PID>` entries (especially when `hidepid` is active). Coverage limits are reported explicitly in the output summary.
2. **Static Inspection Scope**: Aether performs static and structural analysis. It does not perform dynamic binary emulation, sandboxing, or unpack runtime-packed executables in memory unless the binary or memory dump is accessible on disk or via `/proc/<PID>/mem`.
3. **Advanced Kernel Rootkits**: Kernel module inspection verifies `/proc/modules` against `/sys/module` sysfs structures. Rootkits utilizing direct kernel object manipulation (DKOM) that unlink module objects from both lists without sysfs residue require live memory dump analysis or hypervisor-level introspection.
4. **File Size Bounds**: Files exceeding `max-filesize` (default 50MB, configurable via `--max-filesize`) are not hashed or scanned with YARA to avoid memory exhaustion, though their metadata and presence are recorded.

---

## Tested On

- **Verified Environment**:
  - Kali Linux, kernel `7.1.5+kali`, `amd64` (x86_64)

- **Not Yet Tested**:
  - Ubuntu, Debian, Arch Linux, `arm64` (aarch64), Linux kernels 5.x / 6.x

---

## Development & AI Guidelines

Instructions for autonomous AI agents, language models, and developers maintaining or extending this codebase are located in [**`AGENTS.md`**](AGENTS.md).

---

## Test Suite Execution

Run all automated test suites across the repository:

```bash
# Run unit tests across all packages
make test

# Run tests with the Go race detector
go test -race -count=1 ./...

# Run tests with YARA-X enabled
make test-yara
```

---

## License

License: Apache-2.0 (see [LICENSE](LICENSE)).
