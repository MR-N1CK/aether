<p align="center">
  <img src="docs/assets/hero-banner.svg" alt="Aether — Read-only Linux threat hunting: zero sample execution, zero timestamp mutation, zero outbound telemetry" width="880">
</p>

<p align="center">
  <a href="https://mr-n1ck.github.io/aether/"><strong>Web Overview</strong></a>
  &nbsp;•&nbsp;
  <a href="#quickstart">Quickstart</a>
  &nbsp;•&nbsp;
  <a href="#why-aether">Why Aether?</a>
  &nbsp;•&nbsp;
  <a href="#comparison-matrix">Comparison</a>
  &nbsp;•&nbsp;
  <a href="#surface-inspection">What it Inspects</a>
  &nbsp;•&nbsp;
  <a href="#deep-dives">Deep Dives</a>
  &nbsp;•&nbsp;
  <a href="#technical-reference">Reference</a>
</p>

<p align="center">
  <a href="https://github.com/MR-N1CK/aether/releases/latest"><img src="https://img.shields.io/github/v/release/MR-N1CK/aether?style=flat-square&label=Release&color=22d3ee" alt="Latest Release"></a>
  <a href="https://goreportcard.com/report/github.com/MR-N1CK/aether"><img src="https://goreportcard.com/badge/github.com/MR-N1CK/aether?style=flat-square" alt="Go Report Card"></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white&style=flat-square" alt="Requires Go 1.26+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square" alt="Apache License 2.0"></a>
  <a href="https://github.com/MR-N1CK/aether/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/CI-100%25_Passing-34d399?style=flat-square&logo=githubactions&logoColor=white" alt="CI 100% Passing"></a>
  <a href="https://attack.mitre.org/"><img src="https://img.shields.io/badge/MITRE_ATT%26CK-Enriched-f43f5e?style=flat-square" alt="MITRE ATT&CK Mapped"></a>
  <a href="#forensic-safety"><img src="https://img.shields.io/badge/Telemetry-Zero_Outbound-success?style=flat-square" alt="Zero Outbound Telemetry"></a>
  <a href="#multi-distribution-grounding"><img src="https://img.shields.io/badge/Distros-Alpine_|_Debian_|_Arch_|_RPM-38bdf8?style=flat-square" alt="Multi-Distro Support"></a>
  <a href="#verification--test-suite"><img src="docs/assets/accuracy-badge.svg" alt="Benchmark accuracy: precision 100%, recall 100%, 0 false positives across 32 scenarios"></a>
</p>

---

## Why Aether?

Aether is purpose-built for incident responders, detection engineers, and security auditors who need a definitive answer to **“Is this Linux host compromised?”** without altering evidentiary state.

<p align="center">
  <img src="docs/assets/command-center.gif" alt="Aether Command Center: live threat hunt — card deck navigation, streaming findings, dossier" width="880">
</p>

<p align="center"><sub><i>Live capture: Command Center → simulated hunt with streaming findings → forensic dossier. Record yourself: <code>sudo aether</code>.</i></sub></p>

<table>
<tr>
<td width="50" valign="middle"><b>◆</b></td>
<td valign="top"><b>Forensic Safety & Read-Only Invariant</b><br>
All host inspection uses <code>safeopen.OpenRegularReadOnly</code> with <code>O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOATIME</code> — symlink-traversal proof, FIFO-proof, and never touches <code>mtime</code>/<code>ctime</code>. Targets are statically inspected; <b>untrusted code is never executed</b>.</td>
</tr>
<tr>
<td width="50" valign="middle"><b>▲</b></td>
<td valign="top"><b>Dual-Engine Architecture (Zero-Dependency Pure-Go + YARA-X)</b><br>
One static pure-Go binary (<code>CGO_ENABLED=0</code>), zero libc. Native multi-signal heuristics plus embedded YARA-X rules via pure-Go fallback interpretation — and when built with CGO (<code>make build-yara</code>), native Rust-compiled <code>libyara_x_capi</code> with 100% verdict parity.</td>
</tr>
<tr>
<td width="50" valign="middle"><b>◇</b></td>
<td valign="top"><b>Static ELF Behavioral & Anti-Evasion Analysis</b><br>
Weaponized syscall combinations (<code>socket + connect + dup2 + execve</code>), W⊕X segment violations, UPX packer headers, corrupted section offsets, <code>.text</code> Shannon entropy. Recursive de-obfuscation: base64, hex, rot13, shell de-quoting (<code>ba''sh</code>), inline Python execution.</td>
</tr>
<tr>
<td width="50" valign="middle"><b>▣</b></td>
<td valign="top"><b>Multi-Distribution Package Grounding</b><br>
Zero-dependency pure-Go readers for <b>Alpine APK</b>, <b>Debian/Ubuntu dpkg</b>, <b>Arch Pacman</b>, and <b>RPM</b> — correlating hashes to suppress false positives on legitimate system binaries (<code>/usr/bin/curl</code>, <code>/usr/bin/ssh</code>).</td>
</tr>
</table>

---

## Comparison Matrix

| Feature / Standard | **Aether** | **Lynis** | **Osquery** | **Falco** |
| :--- | :---: | :---: | :---: | :---: |
| **Analysis Paradigm** | **100% Static** | Shell Scripts (Runs tests) | SQL Query Daemon | eBPF Kernel Driver |
| **Forensic Contamination** | **Zero (`O_NOATIME`)** | Mutates `mtime`/`ctime` | Standard OS opens | Runtime hooks |
| **Static ELF Behavioral & $W \oplus X$** | **Yes (Syscall Combos)** | No | No | Runtime only |
| **Dual YARA-X Engine** | **Native Embedded** | External plugin | Extension required | Rule syntax only |
| **Multi-Distro Grounding (apk, deb, rpm, pacman)** | **Pure-Go Built-in** | Shell calls | SQLite virtual table | None |
| **Self-Contained Offline HTML Report** | **Yes (Strict CSP)** | Plain text | External SIEM | gRPC / Syslog |
| **Outbound Telemetry** | **Zero by Default** | Update checks | SIEM logging | Cloud stream |

---

## Quickstart

### 1. Build and Run in 10 Seconds

```bash
# Clone repository
git clone https://github.com/MR-N1CK/aether.git
cd aether

# Build static pure-Go binary
make build

# Run engine health check
./bin/aether doctor

# Launch the Flight Deck interactive terminal UI
sudo ./bin/aether
```

### 2. Export Standalone Reports for Responders

```bash
# Quick audit of live system and export self-contained air-gapped HTML dossier
sudo ./bin/aether scan --quick --plain --html-out /tmp/aether-report.html

# Stream NDJSON findings directly to SIEM or log pipelines
sudo ./bin/aether scan --quick --plain --json-out /var/log/aether_findings.json
```

---

## Surface Inspection

```mermaid
flowchart TD
  Target["Linux Endpoint"] --> safeopen["Safeopen: O_RDONLY · O_NOFOLLOW · O_NOATIME"]

  subgraph Triage ["Live Triage Modules"]
    safeopen --> M1["Process Hunter: /memfd, hidden PIDs, masquerading"]
    safeopen --> M2["Persistence: systemd, cron, at, sudoers, PAM, SSH"]
    safeopen --> M3["Privilege: UID 0 clones, duplicate UIDs, shadow hashes"]
    safeopen --> M4["Network: Inode-to-PID correlation, raw sockets, sniffers"]
    safeopen --> M5["Kernel: /proc/modules vs sysfs, rootkits, taint flags"]
  end

  subgraph Engine ["Dual Threat Inspection"]
    Triage --> Heuristics["Native Go Heuristics: anti-evasion & shell dequoting"]
    Triage --> YARAX["Static YARA-X Engine: embedded rules & family signatures"]
    Triage --> ELF["Static ELF Behavioral: imports, W⊕X, entropy, UPX"]
    PkgDB[("Package Grounding: apk, deb, rpm, pacman")] -.-> Engine
  end

  subgraph Presentation ["Executive Output"]
    Engine --> TUI["Flight Deck TUI: 60 FPS Bubbletea HUD"]
    Engine --> HTML["Self-Contained HTML: air-gapped SVG dossier"]
    Engine --> JSON["Streaming NDJSON: SIEM ingestion"]
  end
```

---

## Deep Dives

| Document | Contents |
| :--- | :--- |
| [WALKTHROUGH.md](WALKTHROUGH.md) | Guided tour: first scan, reading findings, the dossier, triage |
| [docs/BUILDING.md](docs/BUILDING.md) | Build modes, reproducible releases, cross-compilation |
| [docs/ENGINES.md](docs/ENGINES.md) | Dual signature engine: YARA-X vs pure-Go fallback, parity guarantees |
| [docs/RULES.md](docs/RULES.md) | Detection rules: families, MITRE mappings, authoring guidance |
| [docs/TESTING.md](docs/TESTING.md) | Test strategy: accuracy benchmark, cross-distro matrix, race harness |
| [DESIGN.md](DESIGN.md) | The Aurora Command Deck design system: tokens, motion, states |

## Technical Reference

<details>
<summary><strong>1. Live Triage Modules & Forensic Mechanics</strong></summary>

### Process Forensics
- **In-Memory Executables**: Detects execution from anonymous shared memory (`/memfd:`) or unlinked binary inodes (`(deleted)`).
- **Hidden Process Discovery**: Two-pass sweep comparing `os.ReadDir("/proc")` against iterative `unix.Fstatat` to detect processes hidden via rootkit hooks or procfs bind mounts.
- **Masquerading Detection**: Compares executable path (`/proc/[pid]/exe`), command line (`/proc/[pid]/cmdline`), and task comm name (`/proc/[pid]/comm`).

### Persistence Audit
- **systemd Services**: Inspects unit definitions across `/lib/systemd/system`, `/etc/systemd/system`, and user scopes for suspicious binaries in volatile drop directories.
- **Scheduled Tasks**: Comprehensive parser for `/etc/crontab`, `/etc/cron.*`, per-user spools (`/var/spool/cron/crontabs`), and `at` job queues.
- **Privilege Escalation Paths**: Sudoers configuration (`/etc/sudoers` and `/etc/sudoers.d/`), PAM execution hooks (`pam_exec`, `pam_script`), dynamic linker hooks (`/etc/ld.so.preload`), and SSH `authorized_keys`.

### Network & Kernel
- **Socket Inode Mapping**: Resolves TCP/UDP/Raw sockets from `/proc/net/*` directly to owning PID descriptors.
- **Kernel Module Discrepancies**: Compares loaded drivers reported in `/proc/modules` with active sysfs trees (`/sys/module/*`) to detect rootkits employing list unlink hooks.
- **Kernel Taint Verification**: Decodes all 18 standard Linux kernel taint flags (`sys/kernel/tainted`).

</details>

<details>
<summary><strong>2. Static ELF Behavioral & Capabilities Engine</strong></summary>

Aether statically inspects compiled Linux binaries without executing them:
- **Capability Import Combinations**:
  - *Reverse Shell*: `socket + connect + dup2 + execve` $\to$ **ALERT (Score 90)**
  - *C2 Listener*: `socket + bind + listen + execve` $\to$ **ALERT (Score 85)**
  - *Process Injection*: `ptrace + mprotect + /proc/*/mem` $\to$ **ALERT (Score 90)**
  - *Fileless Execution*: `memfd_create + execveat` $\to$ **ALERT (Score 85)**
- **$W \oplus X$ Segment Violations**: Detects memory load segments (`PT_LOAD`) marked simultaneously Writable (`PF_W`) and Executable (`PF_X`).
- **Packer Signatures**: Flags UPX and custom packer headers in unprivileged/volatile directories.
- **High Shannon Entropy**: Scans `.text` code sections for high entropy ($> 7.20$ bits/byte) indicating encrypted payloads.
- **Section Table Header Corruption**: Flags intentionally corrupted `e_shoff` offsets designed to crash static disassemblers.

</details>

<details>
<summary><strong>3. CLI Command Suite & Options</strong></summary>

| Command | Action |
| :--- | :--- |
| `aether` | Opens the interactive Flight Deck TUI (when run in a TTY). |
| `aether doctor` | Performs environment diagnostics: root privileges, kernel capabilities, package DB status, and signature tests. |
| `aether scan --quick` | Rapid scan targeting live processes, persistence mechanisms, and volatile drop locations. |
| `aether scan --full` | Exhaustive scan covering the entire filesystem and all modules. |
| `aether scan /path` | Direct inspection of a specific directory or target mount. |
| `aether scan --modules process,persistence` | Restricts triage to the specified modules. |
| `aether ack /path --reason "..."` | Creates a cryptographic hash acknowledgement to suppress acknowledged benign fixtures. |

</details>

---

## Verification & Test Suite

Aether maintains a **100% test passing rate** across 29 packages with extensive regression and real-world scale benchmarks:

```bash
# Run complete test suite
make test

# Run race detector verification
go test -race -count=1 ./...

# Verify 100k-file real-world scale benchmark (21,000+ files/sec)
go test -v -run TestRealWorldScaleAndMemory ./test/realworld
```

---

## License

Aether is released under the **[Apache License 2.0](LICENSE)**. Created by **[MR-N1CK](https://github.com/MR-N1CK)**.

---

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=wave&color=0:0E7490,55:22D3EE,100:0B1220&height=110&section=footer&text=AETHER&fontColor=E6EDF7&fontSize=42&desc=mission-control%20threat%20hunting&descAlignY=72&descSize=16" alt="" width="100%">
</p>
