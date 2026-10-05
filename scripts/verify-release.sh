#!/usr/bin/env bash
# ==============================================================================
# Aether Automated Pre-Release Quality Gate Pipeline
# ==============================================================================
# Executes all test suites, race detectors, benchmark suites, and real-world
# validation profiles strictly offline. Halts release if any test fails.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/build-env.sh"

echo "======================================================================"
echo " Aether v${VERSION} Pre-Release Verification Gates"
echo " Commit:     ${COMMIT}"
echo " Mode:       100% Offline Integrity Verification"
echo "======================================================================"

run_gate() {
    local GATE_NUM="$1"
    local GATE_NAME="$2"
    shift 2
    echo ""
    echo "----------------------------------------------------------------------"
    echo "[GATE ${GATE_NUM}/7] ${GATE_NAME}"
    echo "Command: $*"
    echo "----------------------------------------------------------------------"
    if "$@"; then
        echo "[PASSED] Gate ${GATE_NUM}: ${GATE_NAME}"
    else
        echo "[FAILED] Gate ${GATE_NUM}: ${GATE_NAME} - HALTING RELEASE" >&2
        exit 1
    fi
}

# Gate 1: Core Unit Tests
run_gate 1 "Core Unit Tests" go test ./...

# Gate 2: YARA-X Engine Integration Tests
run_gate 2 "YARA-X Engine Integration Tests" go test -tags yara ./...

# Gate 3: Concurrency Race Detector
run_gate 3 "Concurrency Data Race Detector" go test -race -short ./...

# Gate 4: Feature 002 Detection Accuracy Benchmark
run_gate 4 "Feature 002 Detection Accuracy Benchmark" go test -v ./test/benchmark/...

# Gate 5: Feature 003 Runtime Threat Assessment Suite
run_gate 5 "Feature 003 Runtime Threat Assessment" go test -v ./internal/modules/process/... ./internal/modules/network/... ./internal/report/...

# Gate 6: Feature 004 Real-World System Validation
run_gate 6 "Feature 004 Real-World System Validation" go test -v ./test/realworld/...

# Gate 7: Packaging & Release Artifact Contracts
run_gate 7 "Packaging & Release Artifact Contracts" go test -v ./test/packaging/...

echo ""
echo "======================================================================"
echo "[SUCCESS] All 7 Pre-Release Quality Gates Passed 100% Offline!"
echo "======================================================================"
