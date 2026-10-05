#!/usr/bin/env bash
#
# scripts/baseline.sh - Export clean Kali Linux rootfs and verify with Aether scan
#
set -euo pipefail

# Safety refusal: Never run in a laboratory environment with AETHER_LAB marker
if [[ -n "${AETHER_LAB:-}" ]] || [[ -f "/etc/aether_lab" ]] || [[ -f "${HOME}/.aether_lab" ]]; then
    echo "[!] Refusing to run baseline generation: AETHER_LAB environment detected." >&2
    exit 1
fi

DEFAULT_OUTPUT_DIR="${HOME}/baseline/kali-clean"
OUTPUT_DIR="${DEFAULT_OUTPUT_DIR}"
WITH_TOOLS=false
RECREATE=false
DOCKER_IMAGE="kalilinux/kali-rolling"

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --with-tools        Install common tools (curl, python3, wget, etc.) before exporting"
    echo "  --output-dir DIR    Target directory for rootfs export (default: ~/baseline/kali-clean)"
    echo "  --recreate          Remove and recreate baseline directory if it exists"
    echo "  --image IMAGE       Docker image to use (default: kalilinux/kali-rolling)"
    echo "  -h, --help          Show this help message"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --with-tools)
            WITH_TOOLS=true
            shift
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --recreate)
            RECREATE=true
            shift
            ;;
        --image)
            DOCKER_IMAGE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_PATH="${REPO_ROOT}/bin/aether"

# Check docker availability
if ! command -v docker >/dev/null 2>&1; then
    echo "[-] Error: docker is not installed or not in PATH." >&2
    exit 1
fi

if [[ -d "${OUTPUT_DIR}" ]]; then
    if [[ "${RECREATE}" == true ]]; then
        echo "[*] Removing existing baseline directory: ${OUTPUT_DIR}"
        rm -rf "${OUTPUT_DIR}"
    else
        echo "[*] Baseline directory already exists: ${OUTPUT_DIR}"
    fi
fi

if [[ ! -d "${OUTPUT_DIR}" ]]; then
    echo "[*] Exporting clean ${DOCKER_IMAGE} container filesystem to: ${OUTPUT_DIR}"
    mkdir -p "${OUTPUT_DIR}"

    echo "[*] Pulling ${DOCKER_IMAGE}..."
    docker pull "${DOCKER_IMAGE}"

    CONTAINER_ID=""
    if [[ "${WITH_TOOLS}" == true ]]; then
        echo "[*] Creating container and installing tools..."
        CONTAINER_ID=$(docker create "${DOCKER_IMAGE}" /bin/bash -c "apt-get update && apt-get install -y curl wget python3 python3-pip net-tools procps")
        docker start -a "${CONTAINER_ID}" || true
    else
        echo "[*] Creating container..."
        CONTAINER_ID=$(docker create "${DOCKER_IMAGE}")
    fi

    echo "[*] Exporting filesystem..."
    docker export "${CONTAINER_ID}" | tar -x -C "${OUTPUT_DIR}"
    docker rm -f "${CONTAINER_ID}" >/dev/null 2>&1 || true
    echo "[+] Export completed successfully."
fi

# Build Aether if needed
if [[ ! -f "${BIN_PATH}" ]]; then
    echo "[*] Building Aether binary..."
    make -C "${REPO_ROOT}" build
fi

echo ""
echo "================================================================="
echo "[*] Running Aether scan on baseline rootfs: ${OUTPUT_DIR}"
echo "================================================================="
echo ""

"${BIN_PATH}" scan --root "${OUTPUT_DIR}" --plain --verbose || true

echo ""
echo "[+] Baseline scan verification complete."
