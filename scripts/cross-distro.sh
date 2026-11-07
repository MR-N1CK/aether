#!/usr/bin/env bash
# Cross-distro test matrix for Aether.
#
# Runs the full Go suite (build, vet, tests) inside real distro containers so
# package-database backends (dpkg/pacman/apk/rpm) and live-system tests are
# exercised on the userspace they target. Docker layer caching makes repeat
# runs cheap; first run pulls base images and downloads Go modules.
#
# Usage:
#   scripts/cross-distro.sh                 # all five distros
#   scripts/cross-distro.sh --distro fedora # a single distro
#   scripts/cross-distro.sh --list          # list distros and exit
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKERFILE="$REPO_ROOT/scripts/docker/Dockerfile.aether-test"

ALL_DISTROS=(debian ubuntu fedora arch alpine)

base_for() {
	case "$1" in
	debian) echo "debian:12-slim" ;;
	ubuntu) echo "ubuntu:24.04" ;;
	fedora) echo "fedora:41" ;;
	arch) echo "archlinux:base-devel" ;;
	alpine) echo "golang:1.26-alpine" ;;
	*) return 1 ;;
	esac
}

# Alpine runs the musl toolchain from golang:1.26-alpine so CGO is musl-linked.
goimage_for() {
	case "$1" in
	alpine) echo "golang:1.26-alpine" ;;
	*) echo "golang:1.26" ;;
	esac
}

pre_for() {
	case "$1" in
	debian | ubuntu) echo "apt-get install -y" ;;
	fedora) echo "dnf install -y" ;;
	arch) echo "pacman -S --noconfirm" ;;
	alpine) echo "apk add --no-cache" ;;
	esac
}

update_for() {
	case "$1" in
	debian | ubuntu) echo "apt-get update" ;;
	*) echo "" ;;
	esac
}

pkgs_for() {
	case "$1" in
	debian | ubuntu | fedora) echo "ca-certificates git gcc" ;;
	arch) echo "ca-certificates git" ;; # base-devel already ships gcc
	alpine) echo "ca-certificates gcc musl-dev git bash" ;;
	esac
}

SELECTED=("${ALL_DISTROS[@]}")
while [[ $# -gt 0 ]]; do
	case "$1" in
	--distro)
		shift
		[[ " ${ALL_DISTROS[*]} " == *" $1 "* ]] || { echo "unknown distro: $1 (choose from ${ALL_DISTROS[*]})"; exit 2; }
		SELECTED=("$1")
		shift
		;;
	--list) echo "distros: ${ALL_DISTROS[*]}"; exit 0 ;;
	*) echo "usage: $0 [--distro debian|ubuntu|fedora|arch|alpine] [--list]"; exit 2 ;;
	esac
done

command -v docker >/dev/null 2>&1 || { echo "docker is required"; exit 2; }
docker info >/dev/null 2>&1 || { echo "docker daemon is not running"; exit 2; }

# Pre-create cache bind-mount hosts: Docker creates missing host dirs as
# root, which the non-root container user cannot write.
mkdir -p "$HOME/.cache/aether-gomod" "$HOME/.cache/aether-gobuild"

declare -a RESULTS=()
FAILED=0

for distro in "${SELECTED[@]}"; do
	image="aether-test:${distro}"
	echo ""
	echo "=================================================================="
	echo "[$distro] building test image (base: $(base_for "$distro"))"
	echo "=================================================================="
	if ! docker build \
		--build-arg "GOIMAGE=$(goimage_for "$distro")" \
		--build-arg "BASE=$(base_for "$distro")" \
		--build-arg "UPDATE=$(update_for "$distro")" \
		--build-arg "PRE=$(pre_for "$distro")" \
		--build-arg "PKGS=$(pkgs_for "$distro")" \
		-f "$DOCKERFILE" -t "$image" "$REPO_ROOT"; then
		RESULTS+=("$distro: BUILD-FAILED")
		FAILED=1
		continue
	fi

	echo ""
	echo "[$distro] running suite (build + vet + test, 20m timeout)"
	echo "=================================================================="
	# Run as the host user (never root): root containers rewrite bind-mounted
	# fixture files as root-owned, corrupting the checked-in testdata (observed
	# 2026-11-06: privilege-restricted etc/shadow became root:root 0644), and
	# DAC privilege-boundary tests are meaningless as root. HOME/GOCACHE/
	# GOPATH move to /tmp so the caches live in host-owned bind mounts.
	if docker run --rm \
		--user "$(id -u):$(id -g)" \
		-e HOME=/tmp \
		-e GOCACHE=/tmp/.go-build \
		-e GOPATH=/tmp/.go \
		-v "$REPO_ROOT":/app \
		-v "$HOME/.cache/aether-gomod":/tmp/.go/pkg/mod \
		-v "$HOME/.cache/aether-gobuild":/tmp/.go-build \
		-w /app \
		"$image" \
		sh -c 'go build ./... && go vet ./... && go test ./... -timeout 30m'; then
		RESULTS+=("$distro: PASS")
	else
		RESULTS+=("$distro: TEST-FAILED")
		FAILED=1
	fi
done

echo ""
echo "=================================================================="
echo "CROSS-DISTRO MATRIX SUMMARY"
echo "=================================================================="
for r in "${RESULTS[@]}"; do echo "  $r"; done
exit "$FAILED"
