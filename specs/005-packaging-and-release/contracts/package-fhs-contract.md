# Contract: Package Filesystem Hierarchy (FHS) Contract

**Feature Branch**: `005-packaging-and-release`  
**Created**: 2026-10-04  
**Status**: Active

---

## 1. Overview

This contract defines the strict filesystem locations, file permissions, ownerships, and conffile flags for all Debian (`.deb`) and Red Hat (`.rpm`) packages produced for Aether v1.0.0.

---

## 2. Installed Filesystem Matrix

| Path | Type | Owner | Group | Mode | Conffile? | Purpose |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| `/usr/bin/aether` | File | `root` | `root` | `0755` | No | Main executable binary |
| `/etc/aether/` | Directory | `root` | `root` | `0755` | No | System configuration root |
| `/etc/aether/config.yaml` | File | `root` | `root` | `0644` | **Yes** | Default engine configuration |
| `/etc/aether/rules/` | Directory | `root` | `root` | `0755` | No | System YARA/heuristic rules root |
| `/etc/aether/iocs/` | Directory | `root` | `root` | `0755` | No | System IOC pattern files root |
| `/var/log/aether/` | Directory | `root` | `root` | `0750` | No | Local scheduled audit log destination |
| `/usr/share/man/man1/aether.1.gz` | File | `root` | `root` | `0644` | No | Core tool manual page |
| `/usr/share/man/man1/aether-scan.1.gz` | File | `root` | `root` | `0644` | No | Scan subcommand manual page |
| `/usr/share/man/man1/aether-ack.1.gz` | File | `root` | `root` | `0644` | No | Triage acknowledgment manual page |
| `/usr/share/man/man1/aether-rules.1.gz` | File | `root` | `root` | `0644` | No | Rules compiler manual page |
| `/usr/lib/systemd/system/aether-scan.service` | File | `root` | `root` | `0644` | No | Scheduled scanning oneshot service |
| `/usr/lib/systemd/system/aether-scan.timer` | File | `root` | `root` | `0644` | No | Scheduled weekly scanning timer |

---

## 3. Package Lifecycle Contracts

### 3.1 Post-Installation (`postinst` / `%post`)
- Ensure `/etc/aether/rules/` and `/var/log/aether/` exist with specified permissions.
- If `systemctl` is available, execute `systemctl daemon-reload`.
- **Prohibited Actions**:
  - MUST NOT execute `systemctl enable aether-scan.timer` automatically.
  - MUST NOT execute `systemctl start aether-scan.service`.
  - MUST NOT execute `aether scan` or execute any scanned user binaries.
  - MUST NOT perform remote network requests.

### 3.2 Pre-Removal (`prerm` / `%preun`)
- If `systemctl` is available:
  - Check if `aether-scan.timer` is active; if active, run `systemctl stop aether-scan.timer`.
  - Check if `aether-scan.service` is active; if active, run `systemctl stop aether-scan.service`.
  - Run `systemctl disable aether-scan.timer` if enabled.

### 3.3 Post-Removal (`postrm` / `%postun`)
- If `systemctl` is available, execute `systemctl daemon-reload`.
- Standard removal (`apt remove aether` / `rpm -e aether`):
  - Preserves `/etc/aether/config.yaml`.
  - Preserves `/etc/aether/acknowledged.yaml`.
  - Preserves `/var/log/aether/` and all contained audit reports.
- Complete purge (`apt purge aether`):
  - Removes `/etc/aether/`.
  - Strictly preserves user reports in `/var/log/aether/` or user home directories.
