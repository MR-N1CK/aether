#!/bin/bash
# Nightly home-directory backup to the attached storage disk.
set -euo pipefail
DEST="/mnt/backup-storage/$(date +%F)"
mkdir -p "$DEST"
tar -czf "$DEST/home.tar.gz" -C /home nick --exclude='.cache' --exclude='node_modules'
sha256sum "$DEST/home.tar.gz" > "$DEST/home.tar.gz.sha256"
