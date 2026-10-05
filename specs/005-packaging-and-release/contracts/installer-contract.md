# Contract: Installer Script (`install.sh`) Security Contract

**Feature Branch**: `005-packaging-and-release`  
**Created**: 2026-10-04  
**Status**: Active

---

## 1. Overview

The `install.sh` script provides a portable, self-contained shell interface for building, verifying, installing, and cleanly uninstalling Aether across Linux endpoints without package managers.

Because `install.sh` may be executed with elevated (`root`) privileges, its operation constitutes an integral component of Aether's forensic security perimeter.

---

## 2. Command Synopsis

```bash
install.sh build
install.sh install [--sha256 <expected-hash>]
install.sh uninstall [--purge]
```

---

## 3. Subcommand Contracts

### 3.1 `install.sh build`
- **Execution Context**: MUST be executed as a normal unprivileged user (`id -u != 0`). If invoked as root, it MUST immediately exit with code 1:
  `[ERROR] Refusing to build as root. Run './install.sh build' as a normal user.`
- **Action**:
  - Creates `bin/` directory.
  - If `yara_x_capi` is found via `pkg-config`, compiles static YARA-X binary: `bin/aether-yara-static` via:
    `CGO_ENABLED=1 go build -tags yara -trimpath -ldflags="-s -w" -o bin/aether-yara-static ./cmd/aether`
  - Otherwise, compiles pure-Go binary: `bin/aether` via:
    `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/aether ./cmd/aether`

### 3.2 `install.sh install`
- **Privileged Installation (when run as root / sudo)**:
  1. **Binary Location**: Prioritizes `bin/aether-yara-static`, then `bin/aether`.
  2. **Security Checks**:
     - Checks ownership: `bin/` directory and source binary MUST be owned by the invoking user (e.g. `SUDO_USER` or `root`). If foreign-owned, abort with error code 1.
     - Checks permissions: Rejects installation if `bin/` or source binary is group- or world-writable (`mode & 0022 != 0`).
     - **Mandatory SHA-256 Pinning**: Requires `--sha256 <expected-hash>`. Computes SHA-256 of source binary; if mismatched or omitted, aborts with error code 1.
  3. **Installation Target**: Installs binary to `/usr/local/bin/aether` with permissions `0755` and owner `root:root`.
  4. **Setup**: Invokes `/usr/local/bin/aether setup --download-rules=false`.

- **Unprivileged Installation (when run as non-root user without sudo)**:
  1. Detects `id -u != 0`.
  2. Creates `~/.local/bin` (mode `0755`) and `~/.config/aether/rules` (mode `0700`).
  3. Installs binary to `~/.local/bin/aether` (mode `0755`).
  4. Emits user notification reminding user to ensure `~/.local/bin` is in `$PATH`.

### 3.3 `install.sh uninstall`
- **Privileged Uninstallation (root / sudo)**:
  1. Removes `/usr/local/bin/aether`.
  2. If systemd service/timer are installed, disables and removes `/usr/lib/systemd/system/aether-scan.*`.
  3. Without `--purge`: Preserves `/etc/aether/config.yaml`, `/etc/aether/acknowledged.yaml`, and all reports in `/var/log/aether/`.
  4. With `--purge`: Removes `/etc/aether/`. Strictly preserves `/var/log/aether/` reports.
- **Unprivileged Uninstallation (normal user)**:
  1. Removes `~/.local/bin/aether`.
  2. Without `--purge`: Preserves `~/.config/aether/`.
  3. With `--purge`: Removes `~/.config/aether/`.

---

## 4. Exit Code Contract

| Exit Code | Meaning |
| :---: | :--- |
| `0` | Operation completed successfully. |
| `1` | Security check failure, permission error, checksum mismatch, or missing argument. |
