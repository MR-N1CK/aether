package ioc

import (
	"embed"
)

//go:embed intel/*.txt
var embeddedIntelFS embed.FS

const builtinDemoHashes = `# Aether Builtin Benign Demo Hash Indicators
# Format: <hash> # <description>
# Harmless test hash for verifying IOC pipeline
b6d7732601e6575123995043f0f223b1855c42528f6652431fa6977483e65f42 # Aether_Benign_Test_SHA256_Indicator
`

const builtinDemoPatterns = `
# Aether Builtin Benign Demo Path Indicators
- pattern: '.*\.aether-test-malware.*'
  score: 85
  reason: 'Matches test indicator file for Aether validation'
  os_hint: 'linux'

- pattern: '.*/(malicious_script|fake_payload)\.sh$'
  score: 65
  reason: 'Suspicious script name matching threat pattern'
  os_hint: 'linux'
`

const builtinKnownBenignPatterns = `
# Built-in Known Benign Path Patterns for Common Tool Caches
- path_regex: '^/tmp/\.bun-([0-9]+)-.*'
  reason: 'Bun runtime cache/temporary directory'
  owner_matches_name_uid: true
- path_regex: '^/var/tmp/\.bun-([0-9]+)-.*'
  reason: 'Bun runtime cache/temporary directory'
  owner_matches_name_uid: true
- path_regex: '^/tmp/go-build.*'
  reason: 'Go build cache temporary directory'
- path_regex: '^/var/tmp/go-build.*'
  reason: 'Go build cache temporary directory'
- path_regex: '^/tmp/npm-.*'
  reason: 'npm cache temporary directory'
- path_regex: '^/var/tmp/npm-.*'
  reason: 'npm cache temporary directory'
- path_regex: '^/tmp/pip-.*'
  reason: 'pip cache temporary directory'
- path_regex: '^/var/tmp/pip-.*'
  reason: 'pip cache temporary directory'
- path_regex: '^/tmp/cargo-install.*'
  reason: 'Cargo install temporary directory'
- path_regex: '^/var/tmp/cargo-install.*'
  reason: 'Cargo install temporary directory'
- path_regex: '^/tmp/\.mount_.*'
  reason: 'AppImage FUSE mount directory'
- path_regex: '^/var/tmp/\.mount_.*'
  reason: 'AppImage FUSE mount directory'
`
