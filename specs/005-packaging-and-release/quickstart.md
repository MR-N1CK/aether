# Quickstart & Verification Guide: v1.0.0 Packaging, Release Engineering & Distribution

**Feature Branch**: `005-packaging-and-release`  
**Created**: 2026-10-04  
**Status**: Completed  
**Spec**: [specs/005-packaging-and-release/spec.md](spec.md)

---

## 1. Overview

This document provides step-by-step verification procedures to validate that Aether v1.0.0 release artifacts, packaging scripts, systemd units, man pages, and installers meet all functional requirements and security invariants.

---

## 2. Prerequisites

- Linux host running kernel $\ge 4.19$ (x86_64 or aarch64)
- Go $\ge 1.22$ toolchain
- Packaging tools: `tar`, `gzip`, `sha256sum`, and optionally `dpkg-deb` and `rpmbuild`
- Root or `sudo` access (only for testing privileged package installations)

---

## 3. Validation Scenarios

### Scenario 1: Dual-Engine Compilation & Version Verification

```bash
# 1. Compile Pure-Go static binary
make build-pure
./bin/aether version

# Expected output:
# Aether Threat Hunter v1.0.0
#   Commit:     <git-commit>
#   Build Date: <timestamp>
#   Go Version: go1.26.8
#   OS/Arch:    linux/amd64
#   YARA:       disabled (native heuristics only)

# 2. Compile YARA-X static binary (if yara_x_capi is available)
make build-yara-static
./bin/aether-yara-static version

# Expected output:
# Aether Threat Hunter v1.0.0
#   Commit:     <git-commit>
#   Build Date: <timestamp>
#   Go Version: go1.26.8
#   OS/Arch:    linux/amd64
#   YARA:       YARA-X v1.21.0 (static)
```

---

### Scenario 2: Automated Release Packaging & Artifact Verification

```bash
# Run release packaging pipeline
make package

# Verify generated artifacts in dist/
ls -la dist/

# Expected contents (7 distributable software packages + 2 metadata files = 9 total files):
# Software Packages (7):
# - aether-1.0.0-linux-amd64.tar.gz
# - aether-1.0.0-linux-arm64.tar.gz
# - aether-yara-1.0.0-linux-amd64.tar.gz
# - aether_1.0.0_amd64.deb
# - aether_1.0.0_arm64.deb
# - aether-1.0.0-1.x86_64.rpm
# - aether-1.0.0-1.aarch64.rpm
# Provenance & Verification Metadata (2):
# - release-manifest.json
# - SHA256SUMS

# Verify cryptographic checksums (SHA256SUMS verifies all 8 preceding files)
cd dist && sha256sum -c SHA256SUMS
```

---

### Scenario 3: Installer Security & Uninstallation Validation

```bash
# Test 1: Non-root build & unprivileged installation
./install.sh build
./install.sh install
~/.local/bin/aether version

# Test 2: Unprivileged uninstallation
./install.sh uninstall
[ ! -f ~/.local/bin/aether ] && echo "Cleanly uninstalled"

# Test 3: Root installation with mandatory SHA-256 verification
ACTUAL_SHA=$(sha256sum bin/aether | awk '{print $1}')
sudo ./install.sh install --sha256 "${ACTUAL_SHA}"
/usr/local/bin/aether version

# Test 4: Root uninstallation preserving user reports
sudo ./install.sh uninstall
[ ! -f /usr/local/bin/aether ] && echo "Cleanly uninstalled system binary"
```

---

### Scenario 4: Manual Page Formatting & FHS Verification

```bash
# Validate man page rendering
man -l man/man1/aether.1
man -l man/man1/aether-scan.1
man -l man/man1/aether-ack.1
man -l man/man1/aether-rules.1

# Verify verdict section presence in aether-scan.1
man -l man/man1/aether-scan.1 | grep -E "SAFE|SUSPICIOUS|MALICIOUS|UNKNOWN"
```

---

### Scenario 5: Systemd Unit Verification & Sandboxing Audit

```bash
# Validate systemd unit syntax
systemd-analyze verify packaging/systemd/aether-scan.service
systemd-analyze verify packaging/systemd/aether-scan.timer

# Verify PrivateTmp is false (threat hunting requirement) and LogsDirectory is configured
grep "PrivateTmp=false" packaging/systemd/aether-scan.service
grep "LogsDirectory=aether" packaging/systemd/aether-scan.service
```

---

### Scenario 6: Pre-Release Quality Gate Execution

```bash
# Run the complete automated release verification gate
./scripts/verify-release.sh

# Verifies:
# 1. Pure-Go unit tests: PASS
# 2. YARA-X tests: PASS
# 3. Concurrency race detection: PASS
# 4. Feature 002 Benchmark: Precision=100%, Recall=100%, FPR=0%
# 5. Feature 003 Runtime Correlation: PASS
# 6. Feature 004 Real-World Validation: PASS
# 7. Package build & checksum validation: PASS
```
