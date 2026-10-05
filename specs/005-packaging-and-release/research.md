# Technical Research: v1.0.0 Packaging, Release Engineering & Distribution

**Feature Branch**: `005-packaging-and-release`  
**Created**: 2026-10-04  
**Status**: Completed  
**Spec**: [specs/005-packaging-and-release/spec.md](spec.md)

---

## 1. Executive Summary & Research Scope

Aether Feature 005 establishes a production-grade v1.0.0 release engineering, packaging, and distribution architecture. This research investigates the technical requirements, constraints, and trade-offs for:
1. **Dual-Engine Build Matrix**: Statically-linked Pure-Go (`CGO_ENABLED=0`) vs. Static YARA-X (`CGO_ENABLED=1`) across `amd64` and `arm64`.
2. **Build Reproducibility & Provenance**: Determining the boundaries between deterministic source reproducibility and bit-for-bit byte-level archive reproducibility using Go `-trimpath`, ldflags, and `SOURCE_DATE_EPOCH`.
3. **Packaging Toolchains & Maintainer Scripts**: Debian (`.deb`) and Red Hat (`.rpm`) package structures, FHS layout, conffile handling, and scriptlet safety.
4. **Installer Hardening & Uninstallation Integrity**: Auditing `install.sh` for root privilege validation, path traversal prevention, symlink trap rejection, SHA-256 pinning, and clean uninstallation without user report loss.
5. **Systemd Security Sandbox vs. Threat Hunting Visibility**: In-depth audit of systemd isolation flags, identifying why `PrivateTmp=false` is essential for host `/tmp` malware detection while validating `ProtectSystem=strict`, `ProtectHome=read-only`, and capability bounding sets.
6. **Unix Manual Pages & Verdict Explainability**: Formatting standard roff section 1 man pages adhering to strict claim discipline and the 4-tier verdict model (`SAFE`, `SUSPICIOUS`, `MALICIOUS`, `UNKNOWN`).
7. **Release Verification Quality Gates**: Defining the pre-release automated validation pipeline across all package unit tests, race detector, Feature 002 benchmark, Feature 003 runtime tests, and Feature 004 real-world validation.

---

## 2. Research Decision Matrix

### Decision 1: Dual-Engine Build Matrix & Naming Strategy

- **Context**: Aether provides two detection engines: (1) native pure-Go AST, regex heuristics, and procfs/network/persistence hunting; and (2) compiled static YARA-X scanning using Rust `libyara_x_capi.a`.
- **Decision**: Produce two distinct release artifact tiers:
  - **Tier 1 (Default / Pure-Go)**: Zero-dependency static binary (`CGO_ENABLED=0`). Runs on any Linux kernel $\ge 4.19$ (glibc or musl, Alpine, Debian, RHEL). Packaged as `aether-1.0.0-linux-amd64.tar.gz`, `aether-1.0.0-linux-arm64.tar.gz`, and standard `.deb` / `.rpm` packages.
  - **Tier 2 (Advanced / YARA-X Static)**: High-throughput pattern matching statically linked against `libyara_x_capi.a` on glibc $\ge 2.31$. Packaged as `aether-yara-1.0.0-linux-amd64.tar.gz`.
- **Rationale**: The Pure-Go binary has zero external dependencies, consumes $\le 25\text{MB}$ RAM, and runs seamlessly on minimal containers, musl-based routers/appliances, and embedded systems. The YARA-X binary adds heavy compiled rule matching ($\le 60\text{MB}$ RAM) for enterprise servers and workstations with glibc.
- **Alternatives Considered**:
  - *Dynamic linking with libyara_x_capi.so*: Rejected because dynamic library path mismatches (`LD_LIBRARY_PATH`, glibc versions) cause brittle runtime failures on user endpoints.
  - *Unified single binary bundling YARA-X for all targets*: Rejected because ARM64 and musl environments lack standardized prebuilt YARA-X C-API static archives, which would break cross-compilation and universal portability.

---

### Decision 2: Build Reproducibility & Provenance Tracking

- **Context**: High-assurance forensic and security tools require that binaries and packages be traceable to exact source revisions, preventing unverified or tampered binaries from being deployed.
- **Decision**:
  1. **Go Compiler Flags**: Use `-trimpath` to strip host build paths from binary symbol tables.
  2. **Metadata Injection via LDFLAGS**:
     ```bash
     -s -w \
     -X 'main.version=1.0.0' \
     -X 'main.commit=$(COMMIT)' \
     -X 'main.buildDate=$(BUILD_DATE)'
     ```
  3. **Deterministic Tarball Creation**: Use `SOURCE_DATE_EPOCH` (derived from git commit timestamp `git log -1 --format=%ct`), set `--mtime="@${SOURCE_DATE_EPOCH}"`, `--owner=0 --group=0 --numeric-owner`, `--sort=name`, and `gzip -n` (which omits the variable timestamp from the gzip header).
  4. **Delineation of Reproducibility**:
     - *Source Reproducibility*: Any clean checkout of git tag `v1.0.0` compiles working software with identical functionality, test passes, and CLI behaviors.
     - *Byte-for-Byte Reproducibility*: Compiling on identical Go toolchain versions with `-trimpath` and identical `SOURCE_DATE_EPOCH` produces bit-for-bit identical binary and tarball SHA-256 hashes.
- **Rationale**: Deterministic archive timestamps eliminate artificial diffs caused by local build times while preserving immutable commit provenance.

---

### Decision 3: Package Layout & Filesystem Hierarchy Standard (FHS)

- **Context**: System-wide installation via `.deb`, `.rpm`, and `install.sh` must conform to standard Linux FHS conventions and maintain strict boundaries to prevent filesystem contamination.
- **Decision**:
  - Binary executable: `/usr/bin/aether` (mode `0755`, owner `root:root`)
  - System configuration: `/etc/aether/config.yaml` (mode `0644`, owner `root:root`, marked as `conffile`)
  - Rule directories:
    - `/etc/aether/rules/` (mode `0755`, owner `root:root`)
    - `/etc/aether/iocs/` (mode `0755`, owner `root:root`)
  - Triage acknowledgments: `/etc/aether/acknowledged.yaml` (mode `0644`, created upon `aether ack --system`)
  - Scheduled audit logs: `/var/log/aether/` (mode `0750`, owner `root:root`)
  - Manual pages:
    - `/usr/share/man/man1/aether.1.gz`
    - `/usr/share/man/man1/aether-scan.1.gz`
    - `/usr/share/man/man1/aether-ack.1.gz`
    - `/usr/share/man/man1/aether-rules.1.gz`
  - Systemd unit files:
    - `/usr/lib/systemd/system/aether-scan.service` (mode `0644`)
    - `/usr/lib/systemd/system/aether-scan.timer` (mode `0644`)
- **Rationale**: Strict FHS compliance ensures compatibility with package managers, SELinux policies, and security auditing tools.

---

### Decision 4: Packaging Implementations (`.deb` and `.rpm`)

- **Context**: Users expect native packages installable via `dpkg -i` / `apt` and `rpm -i` / `dnf`.
- **Decision**:
  - Implement Debian packaging using standard directory structures and `dpkg-deb -b`.
  - Implement RPM packaging using standard `.spec` files and `rpmbuild -bb`.
  - Maintainer scripts:
    - `postinst` / `%post`: Creates `/etc/aether/rules` and `/var/log/aether`, sets permissions, runs `systemctl daemon-reload` if systemd is active. Does NOT start or enable the timer automatically.
    - `prerm` / `%preun`: If upgrading or uninstalling, stops `aether-scan.timer` and `aether-scan.service` if active.
    - `postrm` / `%postun`: On package removal, removes systemd units and man pages. Only on purge (`dpkg --purge` / `$1 == 0`) removes `/etc/aether`. Strictly preserves `/var/log/aether` reports and user-created files.
- **Safety Invariant**: Maintainer scripts MUST NEVER invoke `aether scan`, never execute any binaries in `/tmp` or scanned directories, and never phone home.

---

### Decision 5: `install.sh` Hardening & Safe Uninstallation

- **Context**: Shell script installers are common attack vectors if they execute untrusted inputs, lack path sanitization, or fail to verify binary integrity.
- **Decision**:
  1. **Root Installation Safety Checks**:
     - Verify `bin/` directory and source binary are owned by the invoking user (or root when run directly).
     - Check permissions: reject installation if `bin/` or the source binary is group- or world-writable (`mode & 0022 != 0`).
     - Mandatory SHA-256 verification: require `--sha256 <hash>` when installing to `/usr/local/bin` as root.
     - Validate destination paths against symlink traversal using clean paths and `lstat`.
  2. **Unprivileged Mode**:
     - When run as a normal user without `sudo`, install binary to `~/.local/bin/aether` (mode `0755`), create `~/.config/aether/rules/` (mode `0700`), and print instructions to add `~/.local/bin` to `PATH`.
  3. **Uninstallation Support**:
     - Implement `install.sh uninstall` supporting both privileged (`/usr/local/bin/aether`, `/etc/aether`) and unprivileged (`~/.local/bin/aether`, `~/.config/aether`) targets.
     - Add `--purge` flag: without `--purge`, preserves configuration and triage files (`acknowledged.yaml`); with `--purge`, removes configuration while preserving `/var/log/aether/` reports.
- **Rationale**: Eliminates race conditions and privilege escalation vectors, ensuring Aether's installation toolchain adheres to the same forensic safety standards as the scanning engine.

---

### Decision 6: Systemd Hardening vs Threat Hunting Visibility

- **Context**: Hardening systemd units with restrictive sandboxing flags can inadvertently blind threat-hunting tools that must inspect host state.
- **Technical Analysis**:
  - `ProtectSystem=strict`: Mounts `/usr`, `/boot`, `/etc` read-only.
    - *Impact on Aether*: Aether only reads these paths during scans. **Allowed**.
    - *Requirement*: Writing reports to `/var/log/aether` requires `ReadWritePaths=/var/log/aether` and `LogsDirectory=aether` (so systemd automatically creates the directory and manages permissions).
  - `ProtectHome=read-only`: Mounts `/home`, `/root`, `/run/user` read-only.
    - *Impact on Aether*: Aether only reads user paths to hunt for persistence hooks, shell profiles, and hidden executables. **Allowed**. Prevents any accidental writes to user directories.
  - `PrivateTmp=true`: Creates an isolated, private file namespace for `/tmp` and `/var/tmp`.
    - *Impact on Aether*: **CRITICAL CONFLICT**. Aether's primary detection capabilities include `ELF_In_Temp_Directory`, `Proc_Exe_In_Temp`, and hunting for dropped malware samples in `/tmp` and `/var/tmp`. If `PrivateTmp=true` is set, Aether will only inspect an empty private temporary directory, blinding the scan to actual threats running on the host!
    - *Decision*: **`PrivateTmp=false` (or omit)** is strictly required.
  - `NoNewPrivileges=true`: Prevents execution of SUID binaries from gaining new privileges.
    - *Impact on Aether*: Aether never executes target binaries (Principle I: Zero Execution). **Allowed**.
  - `CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE`:
    - *Impact on Aether*: `CAP_DAC_READ_SEARCH` allows bypassing DAC file read permissions; `CAP_SYS_PTRACE` allows reading `/proc/<pid>/exe`, `/proc/<pid>/maps`, and socket links across users without modifying processes. **Allowed and recommended**.
  - `Nice=19` and `IOSchedulingClass=idle`:
    - *Impact on Aether*: Scans run strictly in idle CPU and disk I/O scheduling, ensuring zero impact on host production workloads. **Allowed**.
  - `Activation Policy`:
    - `aether-scan.timer` must be **disabled by default**. Administrator must explicitly run `systemctl enable --now aether-scan.timer`.

---

### Decision 7: Claim Discipline & Documentation Integrity

- **Context**: Security tools often suffer from exaggerated marketing claims ("100% protection", "zero false positives").
- **Decision**:
  - All manual pages (`aether.1`, `aether-scan.1`, `aether-ack.1`, `aether-rules.1`) and README documentation must maintain strict claim discipline.
  - Clearly state that benchmark accuracy metrics (100% precision/recall on synthetic testbeds) apply strictly to defined benchmark corpora.
  - Explicitly disclaim universal detection of unknown, zero-day, or unobserved attack techniques.
  - Clearly define that Aether is a static/runtime forensic assessment and threat-hunting tool, not an active kernel blocking EDR.
  - Explain the 4-tier verdict system (`SAFE`, `SUSPICIOUS`, `MALICIOUS`, `UNKNOWN`) and executive posture status (`SAFE`, `ATTENTION REQUIRED`, `HIGH RISK`, `LIMITED VISIBILITY`). Emphasize that `UNKNOWN != SAFE`.

---

### Decision 8: Release Verification Pipeline (`scripts/verify-release.sh`)

- **Context**: Release engineering must enforce that no artifact is published if any test or benchmark fails.
- **Decision**: Build an automated pre-release verification script `scripts/verify-release.sh` that sequentially runs:
  1. `go test -v ./...` (pure-Go unit tests)
  2. `go test -v -tags yara ./...` (YARA-X integration tests)
  3. `go test -race -short ./...` (concurrency race verification)
  4. Feature 002 Detection Accuracy Benchmark (`go test -v ./test/benchmark/...`) verifying Precision = 100%, Recall = 100%, FPR = 0%
  5. Feature 003 Runtime Correlation Tests (`go test -v ./internal/modules/process/... ./internal/modules/network/... ./internal/report/...`)
  6. Feature 004 Real-World Validation Suite (`go test -v ./test/realworld/...`)
  7. Package build validation (testing artifact compilation, tarball integrity, and checksum manifest generation)
- **Gate Enforcement**: Any non-zero exit code halts the pipeline immediately and prints diagnostic output.

---

## 3. Technology & Architecture Choices Summary

| Domain | Selected Technology | Primary Rationale |
| :--- | :--- | :--- |
| **Pure-Go Build** | `CGO_ENABLED=0 go build -trimpath` | Zero-dependency static binary; runs on any Linux kernel $\ge 4.19$ (glibc/musl). |
| **YARA-X Build** | `CGO_ENABLED=1 go build -tags yara -trimpath` | Statically links `libyara_x_capi.a` for high-throughput compiled pattern matching. |
| **Debian Packaging** | Native directory tree + `dpkg-deb -b` | Standards-compliant `.deb` without heavy external tooling dependencies. |
| **RPM Packaging** | Standard `.spec` file + `rpmbuild -bb` | Standards-compliant `.rpm` for RHEL/CentOS/Fedora/Rocky distributions. |
| **Archive Packaging** | `tar --sort=name --mtime=... | gzip -n` | Deterministic byte-reproducible standalone tarballs using `SOURCE_DATE_EPOCH`. |
| **Integrity Manifest** | `SHA256SUMS` + `release-manifest.json` | Offline cryptographic verification with structured build provenance metadata. |
| **Systemd Hardening** | `ProtectSystem=strict`, `LogsDirectory=aether`, `PrivateTmp=false`, `CAP_DAC_READ_SEARCH` | Enforces least privilege and idle scheduling while preserving host `/tmp` threat visibility. |
| **Documentation** | Standard roff (`man/man1/*.1`) | Universally accessible Unix manual pages with zero external dependencies. |
