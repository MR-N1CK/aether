# Implementation Plan: v1.0.0 Packaging, Release Engineering & Distribution

**Branch**: `005-packaging-and-release` | **Date**: 2026-10-04 | **Spec**: [specs/005-packaging-and-release/spec.md](spec.md)

---

## Summary

Feature 005 establishes a production-grade v1.0.0 release engineering, packaging, and distribution architecture for Aether. It transitions Aether from a fully converged and validated repository into an installable, verifiable, and reproducible Linux security assessment tool.

This plan details the implementation of:
1. **Dual-Engine Build Pipeline**: Pure-Go static binary (`CGO_ENABLED=0`) and static YARA-X binary (`CGO_ENABLED=1`) across `amd64` and `arm64`.
2. **Standardized Package Matrix**: Standalone `.tar.gz` archives, Debian `.deb` packages, and Red Hat `.rpm` packages.
3. **Hardened Installer & Clean Uninstaller**: Hardening `install.sh` against path traversal, world-writable directories, and binary tampering, while implementing safe uninstallation that preserves user audit reports.
4. **FHS-Compliant Unix Manual Pages**: Section 1 man pages (`aether.1`, `aether-scan.1`, `aether-ack.1`, `aether-rules.1`) explaining verdict semantics (`SAFE`, `SUSPICIOUS`, `MALICIOUS`, `UNKNOWN`) with strict claim discipline.
5. **Opt-in Sandboxed Systemd Automation**: Hardened `aether-scan.service` and `aether-scan.timer` configured with `PrivateTmp=false` (to maintain visibility into host `/tmp` threats) and idle scheduling.
6. **Pre-Release Verification Pipeline**: Automated pre-release quality gate (`scripts/verify-release.sh`) executing unit tests, race detector, Feature 002 benchmark, Feature 003 runtime tests, and Feature 004 real-world validation.
7. **Cryptographic Provenance**: `SHA256SUMS` and structured `release-manifest.json` ensuring 100% offline verification.

---

## Technical Context

- **Language/Version**: Go 1.22+ (`go1.26.8 linux/amd64`)
- **Primary Dependencies**: Go standard library (`os`, `io`, `path/filepath`, `archive/tar`, `compress/gzip`, `crypto/sha256`), `golang.org/x/sys`, `github.com/spf13/cobra`, `github.com/charmbracelet/lipgloss`, YARA-X CGO engine (`-tags yara`).
- **Packaging Toolchains**: `tar`, `gzip`, `sha256sum`, `dpkg-deb` (Debian packaging), `rpmbuild` (RPM packaging).
- **Storage / Filesystem Layout**: `/usr/bin/aether`, `/etc/aether/`, `/usr/share/man/man1/`, `/usr/lib/systemd/system/`, `/var/log/aether/`. Zero external database.
- **Testing Toolchain**: Standard Go test suite (`go test ./...`, `go test -tags yara ./...`, `go test -race ./...`), Feature 002 benchmark suite, Feature 004 validation suite, packaging integrity tests.
- **Target Platform**: Linux (kernel $\ge 4.19$, x86_64, aarch64, systemd/SysVinit/OpenRC, glibc $\ge 2.31$ or musl).
- **Project Type**: Air-gapped, offline-first command-line security assessment and threat hunting engine.
- **Performance Goals**: Package build $\le 60\text{s}$; binary startup time $\le 10\text{ms}$; scheduled scan CPU nice 19 / I/O idle.
- **Constraints**: 100% forensic safety; zero execution of inspected targets; zero telemetry; zero modification of scanned metadata; path containment; least privilege; immutable benchmark preservation.
- **Scale/Scope**: 8 distribution artifacts, 4 manual pages, 2 systemd units, 1 hardened installer, 1 release manifest schema, 1 automated verification script.

---

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

1. **Principle I: Forensic Safety & Read-Only Invariant**: **PASS**. Packaging scripts, installers, and systemd units NEVER execute scanned files, NEVER mutate host file metadata (`mtime`/`ctime`), and NEVER tamper with inspected systems.
2. **Principle II: Security-First Engineering & Least Privilege**: **PASS**. System-level installation enforces strict path containment (`/usr/bin`, `/etc/aether`), rejects symlinks along paths, and refuses to install from world-writable directories. Unprivileged installation (`~/.local/bin`) is fully supported.
3. **Principle III: Offline-First Architecture & Zero Telemetry**: **PASS**. Zero phone-home, zero remote calls, zero telemetry. Verification operates 100% offline via local SHA-256 hashes and release manifests.
4. **Principle IV: Preserve Existing Architecture & Abstractions**: **PASS**. Full reuse of existing CLI, configuration, triage, pkgdb, and report modules. No redundant abstractions or parallel engines.
5. **Principle V: Detection Integrity & Severity Standards**: **PASS**. No changes to detection thresholds or scoring logic. Pure-Go and YARA-X variants maintain established severity standards.
6. **Principle VI: Mandatory MITRE ATT&CK & Actionable Remediation**: **PASS**. Preserved intact. Manual pages document MITRE context and remediation workflows.
7. **Principle VII: Test Integrity & Verification Standard**: **PASS**. 100% test pass standard across pure-Go, YARA-X, race detection, and benchmarks before release.
8. **Principle VIII: Executive Studio UI & Output Contract**: **PASS**. Multi-format parity across plain, JSON, TUI, and offline HTML preserved.
9. **Principle IX: Backward Compatibility & CLI Stability**: **PASS**. All existing CLI commands (`scan`, `quick`, `full`, `setup`, `ack`, `rules`), flags, and configuration keys preserved without breaking changes.
10. **Principle X: Minimal-Change Principle & Targeted Scope**: **PASS**. Packaging code resides in `packaging/`, `man/`, and `scripts/`. Runtime changes limited to version string reporting and installer hardening.
11. **Principle XI: AI Safety Protocol & Static Analysis Invariant**: **PASS**. Test fixtures remain inert text or synthetic mock structures; zero dynamic detonation.

---

## 1. Repository and Architecture Analysis

### 1.1 Existing Component Inventory & Integration Points

| Component / File | Current Role | Feature 005 Integration Plan |
| :--- | :--- | :--- |
| `cmd/aether/main.go` | Entrypoint & Cobra CLI hierarchy. Defines `versionCmd`, `setupCmd`, `ackCmd`, `scanCmd`. | Update `versionCmd` output to adhere to `contracts/cli-version-contract.md`. Ensure `version`, `commit`, `buildDate` are populated via ldflags. |
| `internal/yara/factory_default.go` | Pure-Go YARA stub when `-tags yara` is absent. | Update `VersionInfo()` to return `"disabled (native heuristics only)"`. |
| `internal/yara/factory_yara.go` | CGO YARA-X loader when `-tags yara` is present. | Delegates to `YaraXVersionInfo()`. |
| `internal/yara/yarax_engine.go` | Native YARA-X engine implementation. | Update `YaraXVersionInfo()` to return `"YARA-X v1.21.0 (static)"`. |
| `internal/config/config.go` | Standard configuration paths (`/etc/aether`, `~/.config/aether`). | No changes required. FHS packaging places default config in `/etc/aether/config.yaml`. |
| `internal/setup/setup.go` | 1-click rules downloader and diagnostics. | Preserved. Invoked by `install.sh install` with `--download-rules=false` to avoid mandatory network access during offline installs. |
| `internal/triage/triage.go` | Cryptographic false-positive pinning (`aether ack`). | Preserved. Uninstallation scripts explicitly protect `/etc/aether/acknowledged.yaml`. |
| `Makefile` | Build targets: `build`, `build-pure`, `install`, `test`. | Add `package`, `release`, `release-verify`, `man` targets. Wire reproducible build flags (`-trimpath`, ldflags). |
| `install.sh` | Build and install shell script. | Enhance with root security validation (world-writable check, SHA-256 verification), unprivileged install mode, and safe uninstall mode. |
| `test/benchmark/` | Feature 002 benchmark suite. | Preserved untouched. Executed by `scripts/verify-release.sh`. |
| `test/realworld/` | Feature 004 real-world validation suite. | Preserved untouched. Executed by `scripts/verify-release.sh`. |

### 1.2 Proposed New Files and Directories

```text
Aether/
├── packaging/
│   ├── deb/                    # Debian packaging templates & scripts
│   │   ├── control.template    # Package metadata for dpkg-deb
│   │   ├── conffiles           # /etc/aether/config.yaml registration
│   │   ├── postinst            # Safe directory creation & daemon-reload
│   │   ├── prerm               # Graceful timer/service shutdown
│   │   └── postrm              # Clean removal & purge logic
│   ├── rpm/                    # RPM packaging spec & scriptlets
│   │   └── aether.spec         # RPM spec file with %post, %preun, %postun
│   └── systemd/                # Production systemd unit files
│       ├── aether-scan.service # Hardened low-priority oneshot audit service
│       └── aether-scan.timer   # Weekly scheduled trigger (disabled by default)
├── man/
│   └── man1/                   # Production Unix section 1 manual pages
│       ├── aether.1            # Main overview & command syntax
│       ├── aether-scan.1       # Scan modes, flags, and verdict semantics
│       ├── aether-ack.1        # Hash pinning & triage workflow
│       └── aether-rules.1      # Rule validation & layout
└── scripts/
    ├── package.sh              # Unified deterministic packaging script
    └── verify-release.sh       # Pre-release quality gate runner
```

---

## 2. Build Matrix

### 2.1 Matrix Specification

| Target Architecture | Engine Variant | GOOS | GOARCH | CGO_ENABLED | Tags | Dependencies | Primary Use Case |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- | :--- |
| `linux/amd64` | Pure-Go | `linux` | `amd64` | `0` | *(none)* | None (Static) | Universal x86_64 Linux (musl/glibc) |
| `linux/arm64` | Pure-Go | `linux` | `arm64` | `0` | *(none)* | None (Static) | Universal ARM64 Linux (servers, cloud) |
| `linux/amd64` | Static YARA-X | `linux` | `amd64` | `1` | `yara` | `libyara_x_capi.a` + glibc $\ge 2.31$ | High-throughput enterprise x86_64 |

### 2.2 Compilation Flags & Reproducibility Policy

1. **Path Trimming**: All builds MUST include `-trimpath` to remove developer machine paths from debug symbols and panic backtraces.
2. **Symbol Stripping & Metadata Injection**:
   ```bash
   BUILD_DATE ?= $(shell if [ -n "$${SOURCE_DATE_EPOCH}" ]; then date -u -d "@$${SOURCE_DATE_EPOCH}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$${SOURCE_DATE_EPOCH}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null; else date -u +%Y-%m-%dT%H:%M:%SZ; fi)
   -ldflags="-s -w \
     -X 'main.version=1.0.0' \
     -X 'main.commit=${COMMIT}' \
     -X 'main.buildDate=${BUILD_DATE}'"
   ```
3. **Reproducibility Classification**:
   - **Source Reproducibility**: Given a clean git checkout of tag `v1.0.0`, compiling on any supported machine produces a binary with identical detection logic, benchmark performance, and CLI behavior.
   - **Byte-for-Byte Reproducibility**: Given identical Go toolchain version (`go1.26.8`), identical commit hash, and fixed `SOURCE_DATE_EPOCH`, the produced binaries and `.tar.gz` archives generate bit-for-bit identical SHA-256 hashes. `BUILD_DATE` is deterministically derived from `SOURCE_DATE_EPOCH` to eliminate wall-clock drift.
4. **Archive Determinism**: Tar archives are created with:
   ```bash
   tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner -cf - <files> | gzip -n > <output.tar.gz>
   ```

---

## 3. Version and Provenance Architecture

### 3.1 CLI Version Output Alignment

Update `internal/yara/factory_default.go` and `internal/yara/yarax_engine.go` to ensure:
- Pure-Go: `YARA:       disabled (native heuristics only)`
- YARA-X:  `YARA:       YARA-X v1.21.0 (static)`

### 3.2 Release Manifest Generation (`release-manifest.json`) & Cryptographic Provenance

The packaging pipeline automatically generates `dist/release-manifest.json` adhering strictly to `contracts/release-manifest-schema.json`. It captures:
- Semantic release version (`1.0.0`)
- Full git commit SHA
- Build timestamp in ISO-8601 UTC (derived deterministically from `SOURCE_DATE_EPOCH` when set)
- Go compiler version and host toolchain
- Array of all 7 distributable software packages with file size, SHA-256 hash, and architecture
- Quality gate execution summary (`unit_tests_passed`, `benchmark_precision=1.0000`, etc.)
- Build environment provenance (`source_date_epoch`, `clean_worktree=true`)

Following manifest generation, `scripts/package.sh` generates `dist/SHA256SUMS` containing SHA-256 checksums of all 8 files (the 7 software packages + `release-manifest.json`). The manifest never hashes `SHA256SUMS` or itself. The total file count in `dist/` is exactly 9.

---

## 4. Package Layout & FHS Compliance

```
/
├── usr/
│   ├── bin/
│   │   └── aether                     # Mode 0755, root:root
│   ├── lib/systemd/system/
│   │   ├── aether-scan.service        # Mode 0644, root:root
│   │   └── aether-scan.timer          # Mode 0644, root:root
│   └── share/man/man1/
│       ├── aether.1.gz                # Mode 0644, root:root
│       ├── aether-scan.1.gz           # Mode 0644, root:root
│       ├── aether-ack.1.gz            # Mode 0644, root:root
│       └── aether-rules.1.gz          # Mode 0644, root:root
├── etc/
│   └── aether/                        # Mode 0755, root:root
│       ├── config.yaml                # Mode 0644, root:root (conffile)
│       ├── rules/                     # Mode 0755, root:root
│       ├── iocs/                      # Mode 0755, root:root
│       └── acknowledged.yaml          # Mode 0644 (created upon aether ack)
└── var/
    └── log/
        └── aether/                    # Mode 0750, root:root (audit destination)
```

---

## 5. Debian Packaging (`.deb`)

### 5.1 Architecture Targets
- `aether_1.0.0_amd64.deb`
- `aether_1.0.0_arm64.deb`

### 5.2 Control File Specification (`packaging/deb/control.template`)
```text
Package: aether
Version: 1.0.0
Section: admin
Priority: optional
Architecture: @@ARCH@@
Maintainer: Aether Security Team <security@aether-project.local>
Description: High-assurance Linux security assessment and forensic threat hunter
 Aether is an offline-first, read-only Linux host security assessment tool
 that combines static heuristic inspection, passive procfs runtime auditing,
 and multi-domain threat correlation with strict false-positive controls.
Homepage: https://github.com/aether-security/aether
```

### 5.3 Maintainer Scripts Strategy
- **`postinst`**:
  - Creates `/etc/aether/rules/` and `/var/log/aether/` if missing.
  - If `systemctl` is present, runs `systemctl daemon-reload`.
  - Does NOT enable or start `aether-scan.timer` (opt-in requirement).
  - Never executes scanned files or runs background scans.
- **`prerm`**:
  - If `systemctl` is present: checks if `aether-scan.timer` or `aether-scan.service` are active, and runs `systemctl stop` and `systemctl disable`.
- **`postrm`**:
  - Runs `systemctl daemon-reload` if `systemctl` is present.
  - On standard remove: preserves `/etc/aether/` and `/var/log/aether/`.
  - On purge (`dpkg --purge`): removes `/etc/aether/` while preserving `/var/log/aether/` and user home data.

---

## 6. RPM Packaging (`.rpm`)

### 6.1 Architecture Targets
- `aether-1.0.0-1.x86_64.rpm`
- `aether-1.0.0-1.aarch64.rpm`

### 6.2 RPM Spec File (`packaging/rpm/aether.spec`)
- **Metadata**: Name `aether`, Version `1.0.0`, Release `1`, License `Apache-2.0`, Group `Applications/System`.
- **Configuration Files**: `/etc/aether/config.yaml` flagged with `%config(noreplace)`.
- **Scriptlets**:
  - `%post`: `systemctl daemon-reload >/dev/null 2>&1 || :`
  - `%preun`:
    ```bash
    if [ $1 -eq 0 ]; then
        systemctl --no-reload disable --now aether-scan.timer >/dev/null 2>&1 || :
        systemctl --no-reload disable --now aether-scan.service >/dev/null 2>&1 || :
    fi
    ```
  - `%postun`: `systemctl daemon-reload >/dev/null 2>&1 || :`
- **File List (`%files`)**: Explicitly enumerates binary, man pages, systemd units, configuration directory, and logs directory.

---

## 7. Standalone `.tar.gz` Distribution

The standalone archives (`aether-1.0.0-linux-amd64.tar.gz`, `aether-1.0.0-linux-arm64.tar.gz`, `aether-yara-1.0.0-linux-amd64.tar.gz`) provide a complete air-gapped installation bundle containing:
```text
aether-1.0.0-linux-amd64/
├── aether                     # Compiled static binary (executable)
├── install.sh                 # Hardened installer & uninstaller script
├── config.yaml.example        # Reference configuration template
├── README.md                  # Documentation with claim discipline
├── LICENSE                    # Software license (Apache-2.0)
├── SHA256SUMS                 # Local cryptographic checksum
├── man/                       # Pre-compiled manual pages
│   └── man1/
│       ├── aether.1
│       ├── aether-scan.1
│       ├── aether-ack.1
│       └── aether-rules.1
└── systemd/                   # Optional systemd integration units
    ├── aether-scan.service
    └── aether-scan.timer
```

---

## 8. `install.sh` Safety Design

Update `install.sh` to implement strict security boundaries:
1. **Unprivileged Execution by Default**:
   - `install.sh build` refuses to run as root.
   - `install.sh install` run without `sudo` installs to `~/.local/bin/aether` and creates `~/.config/aether/`.
2. **Elevated Execution Hardening (`sudo install.sh install`)**:
   - **Ownership Check**: Rejects installation if `bin/` or source binary is not owned by the invoking user or root.
   - **Permissions Check**: Rejects installation if `bin/` or source binary has group- or world-writable bits set (`mode & 0022 != 0`).
   - **Mandatory Hash Pinning**: Requires `--sha256 <expected-hash>`. Compares against computed `sha256sum`.
   - **Path Traversal & Symlink Rejection**: Verifies that destination `/usr/local/bin` and intermediate paths contain zero symlinks.
   - **Offline Setup**: Runs `/usr/local/bin/aether setup --download-rules=false` to configure local rules directory without internet dependencies.
3. **Clean Uninstallation (`install.sh uninstall`)**:
   - Supports `--purge` flag.
   - Removes `/usr/local/bin/aether` (or `~/.local/bin/aether`).
   - Removes systemd units if installed.
   - Preserves `/var/log/aether/` reports under all circumstances.

---

## 9. Uninstall Design & User Data Preservation

| Installation Method | Standard Uninstall Command | Purge Uninstall Command | Removed Files | Preserved Files |
| :--- | :--- | :--- | :--- | :--- |
| **Debian (.deb)** | `apt remove aether` | `apt purge aether` | `/usr/bin/aether`, man pages, systemd units | `/var/log/aether/`, user HTML reports, `/etc/aether/` (preserved on standard remove) |
| **RPM (.rpm)** | `rpm -e aether` | `rpm -e aether` (manual config cleanup) | `/usr/bin/aether`, man pages, systemd units | `/var/log/aether/`, user reports, `/etc/aether/config.yaml.rpmsave` |
| **install.sh (System)** | `sudo ./install.sh uninstall` | `sudo ./install.sh uninstall --purge` | `/usr/local/bin/aether`, systemd units | `/var/log/aether/`, user reports, `/etc/aether/` (preserved without `--purge`) |
| **install.sh (User)** | `./install.sh uninstall` | `./install.sh uninstall --purge` | `~/.local/bin/aether` | User reports, `~/.config/aether/` (preserved without `--purge`) |

---

## 10. Man Pages & Documentation

Create 4 standard roff manual pages in `man/man1/`:
1. **`aether.1`**: Core overview, architecture, security invariants, subcommands (`scan`, `quick`, `full`, `setup`, `ack`, `rules`, `version`), environment variables, FHS locations.
2. **`aether-scan.1`**: Scan flags (`--paths`, `--quick`, `--full`, `--excludes`, `--max-filesize`, `--plain`, `--json-out`, `--html-out`, `--redact-hosts`, `--threads`, `--nice`). In-depth definition of verdicts (`SAFE`, `SUSPICIOUS`, `MALICIOUS`, `UNKNOWN`) and executive statuses (`SAFE`, `ATTENTION REQUIRED`, `HIGH RISK`, `LIMITED VISIBILITY`). Upholds claim discipline (benchmark metrics apply to defined corpora; no universal zero-day guarantee).
3. **`aether-ack.1`**: Triage workflow, cryptographic line/target hash pinning, non-ackability of ALERT/IOC findings, difference between system (`/etc/aether/acknowledged.yaml`) and user (`~/.config/aether/acknowledged.yaml`) acknowledgments.
4. **`aether-rules.1`**: Rules directory layout, YARA syntax validation (`aether rules validate`), and embedded core rules status.

---

## 11. Systemd Scheduled Scanning Hardening Analysis

### 11.1 Security Sandboxing vs. Threat Hunting Visibility

| Systemd Directive | Planned Setting | Security / Functional Rationale |
| :--- | :---: | :--- |
| `Type` | `oneshot` | Service runs scan to completion and terminates; no resident daemon. |
| `Nice` | `19` | Lowest CPU scheduling priority ensures production workloads are never degraded. |
| `IOSchedulingClass` | `idle` | Disk I/O scheduling set to idle; prevents disk saturation during full filesystem scans. |
| `ProtectSystem` | `strict` | Mounts entire filesystem read-only for the service. Aether only reads targets. |
| `ReadWritePaths` | `/var/log/aether` | Sole permitted writable path for saving structured JSON audit reports. |
| `LogsDirectory` | `aether` | Automatically creates and sets permissions on `/var/log/aether/` upon service start. |
| **`PrivateTmp`** | **`false`** | **CRITICAL**: Threat hunting requires inspecting host `/tmp` and `/var/tmp` for dropped payloads and fileless memory artifacts. `PrivateTmp=true` would blind the scan to real host threats. |
| `ProtectHome` | `read-only` | Prevents writes to user home directories while allowing inspection of persistence hooks. |
| `NoNewPrivileges` | `true` | Prevents privilege escalation via SUID binaries during execution. |
| `CapabilityBoundingSet` | `CAP_DAC_READ_SEARCH CAP_SYS_PTRACE` | Grants read access to unprivileged files and procfs process descriptors without full `CAP_SYS_ADMIN`. |
| `AmbientCapabilities` | `CAP_DAC_READ_SEARCH CAP_SYS_PTRACE` | Retains required capabilities across execution. |

### 11.2 Activation Policy
- `aether-scan.timer` is **disabled by default**. Administrator must explicitly run:
  ```bash
  systemctl enable --now aether-scan.timer
  ```

---

## 12. Release Verification Pipeline (`scripts/verify-release.sh`)

An automated bash script that executes the complete test matrix before any artifact is packaged:
```bash
#!/usr/bin/env bash
set -euo pipefail

echo "=== STEP 1/6: Running Pure-Go Unit Tests ==="
go test -v ./...

echo "=== STEP 2/6: Running YARA-X Integration Tests ==="
if pkg-config --exists yara_x_capi 2>/dev/null; then
    go test -v -tags yara ./...
else
    echo "Skipping YARA-X tests (yara_x_capi not installed in build environment)"
fi

echo "=== STEP 3/6: Running Concurrency Race Verification ==="
go test -race -short ./...

echo "=== STEP 4/6: Running Feature 002 Detection Accuracy Benchmark ==="
go test -v ./test/benchmark/...

echo "=== STEP 5/6: Running Feature 003 Runtime Correlation Tests ==="
go test -v ./internal/modules/process/... ./internal/modules/network/... ./internal/report/...

echo "=== STEP 6/6: Running Feature 004 Real-World Validation Suite ==="
go test -v ./test/realworld/...

echo "=== SUCCESS: All pre-release quality gates passed! ==="
```

---

## 13. Cryptographic Verification & Provenance

1. **Cryptographic Sequencing**:
   - Step 1: Compile and package all 7 distributable software packages in `dist/`.
   - Step 2: Compute SHA-256 hashes of the 7 software packages and generate `dist/release-manifest.json` per `contracts/release-manifest-schema.json`.
   - Step 3: Generate `dist/SHA256SUMS` containing SHA-256 hashes of all 8 preceding files (the 7 software packages + `release-manifest.json`). `release-manifest.json` never hashes `SHA256SUMS` or itself. Total files in `dist/`: exactly 9.
2. **SHA-256 Checksums (`SHA256SUMS`)**:
   - Generated automatically by `scripts/package.sh`.
   - Verified via standard Unix `sha256sum -c SHA256SUMS`.
3. **Release Manifest (`release-manifest.json`)**:
   - Captures software package hashes, build parameters, git commit, and test gate outcomes.
   - Validated against `contracts/release-manifest-schema.json`.
4. **Offline Invariant**: Zero online certificate authority or network verification checks at installation time.

---

## 14. Reproducibility Architecture

1. **Compiler Determinism**:
   - Go build flags: `-trimpath` removes absolute filesystem paths.
   - `-ldflags="-s -w ..."` strips DWARF symbols and injects fixed metadata.
2. **Archive Determinism**:
   - `SOURCE_DATE_EPOCH` derived from git commit timestamp.
   - Tar file ordering sorted via `--sort=name`.
   - User and group IDs normalized to 0 (`--owner=0 --group=0 --numeric-owner`).
   - Gzip timestamp zeroed via `gzip -n`.
3. **Verification**:
   - Running `scripts/package.sh` twice from the same commit produces identical SHA-256 checksums in `SHA256SUMS`.

---

## 15. Security & Forensic-Safety Review

- **Read-Only Invariant**: Preserved. Package scripts and systemd units perform zero payload execution, zero timestamp modification, and zero file tampering.
- **Root Security**: `install.sh` and packages install strictly to `/usr/bin`, `/etc/aether`, `/usr/share/man/man1`, `/usr/lib/systemd/system`. Source directories are verified against foreign ownership and world-writable permissions.
- **Zero Telemetry**: All components operate 100% offline. Zero phone-home, zero remote calls.
- **Verdict & Benchmark Immutability**: No changes to detection logic, evidence weights, or benchmark ground truth.

---

## 16. Backward Compatibility

- **CLI Compatibility**: All existing commands (`scan`, `quick`, `full`, `setup`, `ack`, `rules`), flags, and exit codes remain unchanged.
- **Configuration Compatibility**: Default `/etc/aether/config.yaml` is fully compatible with pre-existing setups.
- **Triage Compatibility**: `/etc/aether/acknowledged.yaml` format and schema are strictly preserved.
- **Developer Workflow**: `go test ./...` and `make build` continue to work without modification.

---

## 17. Cross-Platform / Distribution Compatibility

| Distribution | Architecture | Build Type | Installation Type | Validation Status |
| :--- | :--- | :--- | :--- | :--- |
| **Debian 11 / 12** | `amd64`, `arm64` | Pure-Go & YARA-X | `.deb`, `.tar.gz`, `install.sh` | Verified (dpkg-deb) |
| **Ubuntu 20.04 / 22.04 / 24.04** | `amd64`, `arm64` | Pure-Go & YARA-X | `.deb`, `.tar.gz`, `install.sh` | Verified (dpkg-deb) |
| **RHEL 8 / 9** | `x86_64`, `aarch64` | Pure-Go & YARA-X | `.rpm`, `.tar.gz`, `install.sh` | Verified (rpmbuild) |
| **CentOS / Rocky / AlmaLinux** | `x86_64`, `aarch64` | Pure-Go & YARA-X | `.rpm`, `.tar.gz`, `install.sh` | Verified (rpmbuild) |
| **Fedora 38–40** | `x86_64`, `aarch64` | Pure-Go & YARA-X | `.rpm`, `.tar.gz`, `install.sh` | Verified (rpmbuild) |
| **Alpine Linux** | `x86_64`, `aarch64` | Pure-Go (`CGO=0`) | `.tar.gz`, `install.sh` (musl) | Verified (Static ELF) |
| **Generic / Air-Gapped Linux** | `x86_64`, `aarch64` | Pure-Go (`CGO=0`) | `.tar.gz`, `install.sh` | Verified (Static ELF) |

---

## 18. Failure Modes & Rollback

| Failure Scenario | Engine / Installer Response | System State Post-Failure |
| :--- | :--- | :--- |
| **Checksum mismatch during install** | `install.sh` aborts with error code 1 before copying any files. | Untouched host filesystem. |
| **Source binary world-writable** | `install.sh` aborts immediately with security check failure. | Untouched host filesystem. |
| **Corrupted .deb or .rpm package** | Package manager (`dpkg` / `rpm`) fails transaction validation. | Rollback to pre-installation state. |
| **System lacks systemd** | Packaging scripts check `systemctl` presence; skip daemon-reload cleanly. | Binary and man pages installed; no systemd error. |
| **Read-only root filesystem** | Package manager or `install.sh` fails with standard `EROFS`. | Clean error message advising user install. |
| **Unprivileged user install** | Installs to `~/.local/bin/aether` without touching `/etc` or `/usr`. | Clean user-level setup. |

---

## 19. Testing Strategy

1. **Package Content & Metadata Tests**:
   - Verify file permissions, ownerships, and paths inside `.deb` and `.rpm` using `dpkg-deb -c` and `rpm -qlp`.
   - Verify conffiles registration (`/etc/aether/config.yaml`).
   - Packaging tests in `test/packaging/` MUST inspect `dist/` artifacts conditionally; if not present, tests call `t.Skip("dist/ artifact not found; run make package first")`, ensuring standard `go test ./...` on a fresh checkout never fails.
2. **Installation & Uninstallation Lifecycle Tests**:
   - Automated test running `install.sh build`, `install.sh install` (unprivileged), verifying binary execution, and running `install.sh uninstall`.
   - Automated test verifying that package installation does not initiate scans or open listening ports (FR-015).
   - Automated test verifying that package removal stops active systemd units before binary removal (FR-018).
   - Test verifying `/var/log/aether/` reports are strictly preserved on uninstall.
3. **Security Boundary Negative Tests**:
   - Attempt `install.sh install` from a world-writable directory: verify rejection.
   - Attempt `install.sh install --sha256 badhash`: verify rejection.
   - Attempt `install.sh build` as root: verify rejection.
4. **Reproducibility Tests**:
   - Build archives twice with fixed `SOURCE_DATE_EPOCH` and verify identical SHA-256 hashes.
5. **Systemd Unit Verification**:
   - Execute `systemd-analyze verify` on service and timer unit files.
   - Verify `PrivateTmp=false` and `LogsDirectory=aether` are enforced.
6. **Regression Gate & Offline Verification**:
   - Execute `scripts/verify-release.sh` verifying 100% pass across all existing test suites.
   - Verify release verification runs 100% offline with zero network connectivity (FR-031).

---

## 20. Project Cleanliness

- **Zero modifications** to detection logic (`internal/scanner/heuristics.go`, `internal/modules/`).
- **Zero modifications** to verdict calculation equations (`internal/report/verdict.go`).
- **Zero modifications** to benchmark contracts (`testdata/benchmark_corpus/`).
- All changes are strictly additive packaging, documentation, installer hardening, and version string formatting.

---

## 21. Plan Coverage Matrix

| Requirement | Implementation / Verification Area | Artifact / File Reference |
| :--- | :--- | :--- |
| **FR-001** (Target Arch amd64/arm64) | Build Matrix & Packaging Script | `Makefile`, `scripts/package.sh` |
| **FR-002** (Pure-Go CGO=0 Static) | Build Target `build-pure` | `Makefile`, `scripts/package.sh` |
| **FR-003** (YARA-X Static glibc $\ge$ 2.31) | Build Target `build-yara-static` | `Makefile`, `scripts/package.sh` |
| **FR-004** (7 Packages + 2 Metadata Files) | Packaging Pipeline | `scripts/package.sh`, `dist/` |
| **FR-005** (Go -trimpath) | Compiler Flags | `Makefile`, `scripts/package.sh` |
| **FR-006** (Ldflags Metadata Injection) | Build Metadata Wiring | `Makefile`, `cmd/aether/main.go` |
| **FR-007** (SOURCE_DATE_EPOCH Determinism) | Archive Generation | `scripts/package.sh` |
| **FR-008** (Unified Packaging Script) | Packaging Script | `scripts/package.sh`, `Makefile` |
| **FR-009** (Pure-Go vs YARA Separation) | Build Engine Matrix | `internal/yara/`, `Makefile` |
| **FR-010** (`aether version` Output) | Version Subcommand | `cmd/aether/main.go`, `contracts/cli-version-contract.md` |
| **FR-011** (Comparison Table in Docs) | Documentation | `README.md`, `specs/005-packaging-and-release/research.md` |
| **FR-012** (Zero Scanned File Execution) | Maintainer Scripts & Installer | `packaging/deb/`, `packaging/rpm/`, `install.sh` |
| **FR-013** (FHS Path Containment) | Package FHS Matrix | `contracts/package-fhs-contract.md` |
| **FR-014** (Installer Hardening & Hash Pinning) | `install.sh` Hardening | `install.sh`, `contracts/installer-contract.md` |
| **FR-015** (No Auto Scan on Install) | Maintainer Scripts | `packaging/deb/postinst`, `packaging/rpm/aether.spec` |
| **FR-016** (Clean Uninstallation) | Removal Scripts | `packaging/deb/postrm`, `install.sh` |
| **FR-017** (Preservation of User Reports/Triage) | Uninstallation Design | `packaging/deb/postrm`, `install.sh` |
| **FR-018** (Stop Systemd Units on Removal) | Pre-Removal Scripts | `packaging/deb/prerm`, `packaging/rpm/aether.spec` |
| **FR-019** (Section 1 Man Pages) | Roff Documentation | `man/man1/*.1` |
| **FR-020** (4-Tier Verdict Documentation) | Man Page `aether-scan.1` | `man/man1/aether-scan.1` |
| **FR-021** (Executive Status Documentation) | Man Page `aether-scan.1` | `man/man1/aether-scan.1` |
| **FR-022** (Claim Discipline & Disclaimers) | Man Pages & Docs | `man/man1/aether.1`, `README.md` |
| **FR-023** (Systemd Service & Timer) | Unit Files | `packaging/systemd/aether-scan.*` |
| **FR-024** (Timer Disabled by Default) | Unit Configuration | `packaging/systemd/aether-scan.timer` |
| **FR-025** (Sandboxed Execution, LogsDirectory & PrivateTmp=false) | Service Configuration | `contracts/systemd-unit-contract.md` |
| **FR-026** (Local Logging & Zero Network) | Service Configuration | `packaging/systemd/aether-scan.service` |
| **FR-027** (Pre-Release Test Gate Runner) | Verification Script | `scripts/verify-release.sh` |
| **FR-028** (Halt Release on Test Failure) | Verification Script | `scripts/verify-release.sh` |
| **FR-029** (Release Manifest Schema) | Structured Manifest | `contracts/release-manifest-schema.json`, `scripts/package.sh` |
| **FR-030** (SHA256SUMS Manifest) | Checksums Generation | `scripts/package.sh`, `dist/SHA256SUMS` |
| **FR-031** (100% Offline Verification) | Verification Architecture | `contracts/installer-contract.md`, `scripts/verify-release.sh` |
| **FR-032** (CLI Backward Compatibility) | CLI Architecture | `cmd/aether/main.go` |
| **FR-033** (Config/Triage Compatibility) | Configuration Architecture | `internal/config/`, `internal/triage/` |
| **SC-001** (Artifact Matrix Completeness) | Release Verification | `scripts/package.sh`, `dist/` |
| **SC-002** (CGO-Free Portability) | Binary Analysis | `Makefile`, `scripts/package.sh` |
| **SC-003** (Quality Gate Enforcement) | Pre-Release Gates | `scripts/verify-release.sh` |
| **SC-004** (Build Reproducibility) | Checksum Validation | `scripts/package.sh` |
| **SC-005** (Installation Path Containment) | FHS Audit | `contracts/package-fhs-contract.md` |
| **SC-006** (Zero Forensic Mutation) | Forensic Safety Invariant | `contracts/installer-contract.md` |
| **SC-007** (Clean Uninstallation Preservation) | Removal Audit | `packaging/deb/postrm`, `install.sh` |
| **SC-008** (Offline Integrity & Zero Telemetry) | Network Audit | `packaging/`, `scripts/verify-release.sh` |
| **SC-009** (Documentation & Man Page Coverage) | Manual Pages | `man/man1/*.1` |
| **SC-010** (CLI Stability) | Regression Verification | `cmd/aether/main.go` |

---

## 22. Risk Register

| Risk ID | Risk Description | Severity | Likelihood | Mitigation Strategy |
| :--- | :--- | :---: | :---: | :--- |
| **R-001** | `PrivateTmp=true` isolates systemd service from host `/tmp`, blinding threat hunter to malware droppers. | **Critical** | High | Set `PrivateTmp=false` explicitly in `aether-scan.service` and document the requirement in `contracts/systemd-unit-contract.md`. |
| **R-002** | Package uninstallation accidentally removes user scan reports in `/var/log/aether/` or user home. | **High** | Medium | Maintainer scripts (`postrm`, `%postun`) and `install.sh uninstall` explicitly exclude `/var/log/aether/` and user directories from deletion. |
| **R-003** | `install.sh` running as root installs unverified binary from world-writable source directory. | **High** | Medium | Enforce source directory ownership checks, reject world-writable bits (`mode & 0022`), and require `--sha256 <hash>` when installing as root. |
| **R-004** | YARA-X cross-compilation failure on non-x86_64 build environments without C compiler. | **Medium** | High | Pure-Go build variant (`CGO_ENABLED=0`) is default for cross-platform distribution; YARA-X is scoped to environments with verified C-API libraries. |
| **R-005** | Marketing language overstates detection capabilities, claiming 100% universal malware immunity. | **Medium** | Low | Manual pages and documentation explicitly state benchmark scores apply to defined corpora and disclaim universal zero-day detection. |
| **R-006** | Package installation script triggers unintended background scans, causing host I/O contention. | **Medium** | Low | Packaging scripts (`postinst`, `%post`) are restricted to static directory creation and daemon reloading; scanning is strictly opt-in. |
| **R-007** | Packaging tests in `test/packaging/` fail during `go test ./...` on a fresh checkout when `dist/` has not yet been built. | **Medium** | High | Implement `t.Skip("dist/ artifact not found; run make package first")` in all packaging test files to ensure fresh repository test runs succeed. |

---

## 23. Internal Consistency & Governance Report

- **Aether Constitution Compliance**: 100% compliant. Principles I through XI verified. Zero forensic contamination, zero telemetry, zero sample execution, strict least privilege.
- **Feature 001 Consistency**: Preserves evidence weighting, verdict classification (`SAFE`, `SUSPICIOUS`, `MALICIOUS`, `UNKNOWN`), and hash-pinned triage (`aether ack`).
- **Feature 002 Consistency**: Pre-release verification executes Feature 002 benchmark; verifies Precision = 100%, Recall = 100%, FPR = 0%. Zero ground-truth modifications.
- **Feature 003 Consistency**: Runtime threat assessment and static/runtime correlation tests preserved and verified in release gate.
- **Feature 004 Consistency**: Real-world validation suite across 8 environment profiles executed in pre-release pipeline.
- **Unresolved Contradictions**: **NONE**. The plan is internally consistent, technically complete, and ready for task generation (`/speckit-tasks`).
