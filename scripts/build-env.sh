#!/usr/bin/env bash
# ==============================================================================
# Aether Build & Packaging Environment Configuration
# ==============================================================================
# Sets deterministic timestamps, versions, commit metadata, and compiler flags.
# Complies with Principle III (Zero False Equivalence) & Principle VII (Test Integrity).

set -euo pipefail

# Release Version — derived from the latest git tag so release artifacts
# always carry their tag's version (v1.1.0 -> 1.1.0). Override with
# VERSION=... to pin; falls back to 1.0.0 when no tag exists.
if [ -z "${VERSION:-}" ]; then
    if git describe --tags --abbrev=0 >/dev/null 2>&1; then
        export VERSION="$(git describe --tags --abbrev=0 | sed 's/^v//')"
    else
        export VERSION="1.0.0"
    fi
fi

# Git Commit Metadata
if [ -z "${COMMIT:-}" ]; then
    if git rev-parse --short HEAD >/dev/null 2>&1; then
        GIT_COMMIT="$(git rev-parse --short HEAD)"
        if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
            GIT_COMMIT="${GIT_COMMIT}-dirty"
        fi
        export COMMIT="${GIT_COMMIT}"
    else
        export COMMIT="release"
    fi
fi

# SOURCE_DATE_EPOCH for Deterministic / Reproducible Builds
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    if git rev-parse HEAD >/dev/null 2>&1; then
        export SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct 2>/dev/null || echo 1760000000)"
    else
        export SOURCE_DATE_EPOCH="1760000000"
    fi
fi

# Derive BUILD_DATE in ISO-8601 UTC format from SOURCE_DATE_EPOCH
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
    export BUILD_DATE="$(date -u -d "@${SOURCE_DATE_EPOCH}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
                         date -u -r "${SOURCE_DATE_EPOCH}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
                         date -u +%Y-%m-%dT%H:%M:%SZ)"
else
    export BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fi

# Go linker flags with trimpath and symbol stripping
export GO_LDFLAGS="-s -w -X 'main.version=${VERSION}' -X 'main.commit=${COMMIT}' -X 'main.buildDate=${BUILD_DATE}'"

# Output directories
export PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export BIN_DIR="${PROJECT_ROOT}/bin"
export DIST_DIR="${PROJECT_ROOT}/dist"

mkdir -p "${BIN_DIR}" "${DIST_DIR}"
