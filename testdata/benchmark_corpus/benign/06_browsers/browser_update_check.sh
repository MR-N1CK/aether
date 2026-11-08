#!/bin/bash
# Vendor update agent: fetch manifest, verify signature, apply update.
MANIFEST_URL="https://updates.vendor.example.com/stable/manifest.json"
TMP=$(mktemp)
curl -sSL --max-time 30 "$MANIFEST_URL" -o "$TMP" || exit 1
openssl dgst -sha256 -verify /usr/share/vendor/keys/release.pem -signature "$TMP.sig" "$TMP" >/dev/null 2>&1 || { rm -f "$TMP"; exit 2; }
apply-update --quiet --manifest "$TMP"
rm -f "$TMP"
