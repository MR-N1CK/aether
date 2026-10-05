#!/usr/bin/env bash
# ==============================================================================
# Aether Installer & Uninstaller Script
# ==============================================================================
# Implements hardened privileged and unprivileged installation and uninstallation
# adhering to contracts/installer-contract.md and Principle II (Least Privilege).

set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 {build|install|uninstall} [OPTIONS]

Commands:
  build                       Build Aether binary as non-root user
  install [--sha256 <HASH>]   Install Aether:
                                - As root: installs to /usr/local/bin (requires --sha256)
                                - As non-root: installs to ~/.local/bin
  uninstall [--purge]         Uninstall Aether binary:
                                - Preserves /var/log/aether and configuration by default
                                - --purge removes /etc/aether (logs always preserved)
EOF
    exit 1
}

if [ "$#" -lt 1 ]; then
    usage
fi

MODE="$1"
shift

locate_source_binary() {
    if [ -f "bin/aether-yara-static" ] && [ -f "bin/aether" ]; then
        echo "[WARNING] Both bin/aether-yara-static and bin/aether exist. Choosing bin/aether-yara-static." >&2
        SRC_BIN="bin/aether-yara-static"
    elif [ -f "bin/aether-yara-static" ]; then
        SRC_BIN="bin/aether-yara-static"
    elif [ -f "bin/aether" ]; then
        SRC_BIN="bin/aether"
    else
        echo "[ERROR] No compiled binary found in bin/. Run '$0 build' first as a normal user." >&2
        exit 1
    fi
    echo "$SRC_BIN"
}

case "$MODE" in
    build)
        if [ "$(id -u)" -eq 0 ]; then
            echo "[ERROR] Refusing to build as root. Run '$0 build' as a normal user." >&2
            exit 1
        fi

        echo "[STEP 1/2] Checking build prerequisites..."
        mkdir -p bin

        if pkg-config --exists yara_x_capi 2>/dev/null || [ -f /usr/local/lib/libyara_x_capi.a ]; then
            echo "[STEP 2/2] Building static YARA-X binary: bin/aether-yara-static..."
            CGO_ENABLED=1 CGO_LDFLAGS="-Wl,-Bstatic -lyara_x_capi -lstdc++ -Wl,-Bdynamic -lpthread -ldl -lm" \
                go build -tags yara -trimpath -ldflags="-s -w -X 'main.version=${VERSION:-1.0.0}'" -o bin/aether-yara-static ./cmd/aether
            echo "[SUCCESS] Built bin/aether-yara-static"
        else
            echo "[STEP 2/2] Building pure-Go static binary: bin/aether..."
            CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X 'main.version=${VERSION:-1.0.0}'" -o bin/aether ./cmd/aether
            echo "[SUCCESS] Built bin/aether"
        fi
        ;;

    install)
        SRC_BIN="$(locate_source_binary)"
        ACTUAL_SHA="$(sha256sum "$SRC_BIN" | awk '{print $1}')"

        if [ "$(id -u)" -ne 0 ]; then
            # Unprivileged installation
            echo "[INFO] Running unprivileged installation for user $(id -un)..."
            INSTALL_DIR="${HOME}/.local/bin"
            CONFIG_DIR="${HOME}/.config/aether"
            RULES_DIR="${CONFIG_DIR}/rules"

            mkdir -p "${INSTALL_DIR}" "${RULES_DIR}"
            chmod 0755 "${INSTALL_DIR}"
            chmod 0700 "${CONFIG_DIR}" "${RULES_DIR}"

            install -m 0755 "$SRC_BIN" "${INSTALL_DIR}/aether"
            echo "[SUCCESS] Aether installed to ${INSTALL_DIR}/aether"
            if [ -f config.yaml ] && [ ! -f "${CONFIG_DIR}/config.yaml" ]; then
                cp config.yaml "${CONFIG_DIR}/config.yaml"
                chmod 0600 "${CONFIG_DIR}/config.yaml"
            fi

            echo "[NOTE] Ensure ${INSTALL_DIR} is in your PATH (e.g. export PATH=\"\$HOME/.local/bin:\$PATH\")"
            exit 0
        fi

        # Privileged (root) installation
        echo "[STEP 1/3] Verifying source binary security and ownership..."

        if [ -n "${SUDO_USER:-}" ]; then
            TARGET_USER="$SUDO_USER"
            TARGET_UID="$(id -u "$SUDO_USER")"
        else
            TARGET_USER="$(id -un)"
            TARGET_UID="$(id -u)"
        fi

        BIN_DIR_UID="$(stat -c '%u' bin)"
        SRC_BIN_UID="$(stat -c '%u' "$SRC_BIN")"

        if [ "$BIN_DIR_UID" -ne "$TARGET_UID" ]; then
            echo "[ERROR] Security check failed: 'bin/' is owned by UID $BIN_DIR_UID, expected $TARGET_USER (UID $TARGET_UID)." >&2
            exit 1
        fi

        if [ "$SRC_BIN_UID" -ne "$TARGET_UID" ]; then
            echo "[ERROR] Security check failed: '$SRC_BIN' is owned by UID $SRC_BIN_UID, expected $TARGET_USER (UID $TARGET_UID)." >&2
            exit 1
        fi

        # Check group/world writable permissions
        BIN_DIR_PERM="$(stat -c '%a' bin)"
        SRC_BIN_PERM="$(stat -c '%a' "$SRC_BIN")"

        if [ "$(( 8#$BIN_DIR_PERM & 8#0022 ))" -ne 0 ]; then
            echo "[ERROR] Security check failed: 'bin/' is group- or world-writable (mode: $BIN_DIR_PERM). Refusing to install." >&2
            exit 1
        fi

        if [ "$(( 8#$SRC_BIN_PERM & 8#0022 ))" -ne 0 ]; then
            echo "[ERROR] Security check failed: '$SRC_BIN' is group- or world-writable (mode: $SRC_BIN_PERM). Refusing to install." >&2
            exit 1
        fi

        # Parse --sha256 argument
        EXPECTED_SHA=""
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --sha256)
                    EXPECTED_SHA="${2:-}"
                    shift 2 || true
                    ;;
                --sha256=*)
                    EXPECTED_SHA="${1#*=}"
                    shift
                    ;;
                *)
                    shift
                    ;;
            esac
        done

        if [ -z "$EXPECTED_SHA" ]; then
            echo "[ERROR] Security check failed: '--sha256 <hash>' is required for root installation." >&2
            echo "[HINT] Re-run with the verified binary hash:" >&2
            echo "       sudo $0 install --sha256 $ACTUAL_SHA" >&2
            exit 1
        fi

        if [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
            echo "[ERROR] SHA-256 checksum mismatch!" >&2
            echo "  Expected: $EXPECTED_SHA" >&2
            echo "  Actual:   $ACTUAL_SHA" >&2
            exit 1
        fi

        echo "[STEP 2/3] Installing $SRC_BIN to /usr/local/bin/aether..."
        mkdir -p /usr/local/bin /etc/aether/rules /var/log/aether
        install -o root -g root -m 0755 "$SRC_BIN" /usr/local/bin/aether

        if [ -f config.yaml ] && [ ! -f /etc/aether/config.yaml ]; then
            install -o root -g root -m 0644 config.yaml /etc/aether/config.yaml
        fi

        # Install systemd units if present
        if [ -d packaging/systemd ]; then
            mkdir -p /etc/systemd/system
            if [ -f packaging/systemd/aether-scan.service ]; then
                install -o root -g root -m 0644 packaging/systemd/aether-scan.service /etc/systemd/system/
            fi
            if [ -f packaging/systemd/aether-scan.timer ]; then
                install -o root -g root -m 0644 packaging/systemd/aether-scan.timer /etc/systemd/system/
            fi
            if [ -d /run/systemd/system ]; then
                systemctl daemon-reload >/dev/null 2>&1 || true
            fi
        fi

        # Install manual pages if present
        if [ -d man/man1 ]; then
            mkdir -p /usr/local/share/man/man1
            install -o root -g root -m 0644 man/man1/aether*.1 /usr/local/share/man/man1/ 2>/dev/null || true
            if command -v mandb >/dev/null 2>&1; then
                mandb -q >/dev/null 2>&1 || true
            fi
        fi

        echo "[STEP 3/3] Running setup verification..."
        /usr/local/bin/aether setup --download-rules=false

        echo "[SUCCESS] Installation and system setup complete."
        ;;

    uninstall)
        PURGE=false
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --purge)
                    PURGE=true
                    shift
                    ;;
                *)
                    shift
                    ;;
            esac
        done

        if [ "$(id -u)" -ne 0 ]; then
            echo "[INFO] Removing unprivileged user installation..."
            rm -f "${HOME}/.local/bin/aether"
            if [ "$PURGE" = true ]; then
                rm -rf "${HOME}/.config/aether"
            fi
            echo "[SUCCESS] Unprivileged Aether uninstalled."
            exit 0
        fi

        echo "[INFO] Removing system-wide Aether installation..."
        if [ -d /run/systemd/system ]; then
            systemctl stop aether-scan.timer aether-scan.service >/dev/null 2>&1 || true
            systemctl disable aether-scan.timer >/dev/null 2>&1 || true
        fi

        rm -f /usr/local/bin/aether
        rm -f /etc/systemd/system/aether-scan.service /etc/systemd/system/aether-scan.timer
        rm -f /usr/local/share/man/man1/aether*.1

        if [ -d /run/systemd/system ]; then
            systemctl daemon-reload >/dev/null 2>&1 || true
        fi

        if [ "$PURGE" = true ]; then
            rm -rf /etc/aether
            echo "[INFO] Removed /etc/aether configuration."
        else
            echo "[INFO] Preserved /etc/aether/ configuration (use --purge to remove)."
        fi

        # ALWAYS preserve /var/log/aether/
        echo "[INFO] Preserved /var/log/aether/ reports and audit logs."
        echo "[SUCCESS] Aether uninstallation complete."
        ;;

    *)
        usage
        ;;
esac
