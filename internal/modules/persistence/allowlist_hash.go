package persistence

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"aether/internal/safeopen"
)

// maxAllowlistHashBytes caps artifact hashing for allowlist suppression.
// Persistence artifacts (units, cron spools, profiles, keys) are small; a
// bound keeps a hostile oversized entry from stalling the module.
const maxAllowlistHashBytes = 4 << 20 // 4 MiB

// allowlistSHA256 computes the SHA-256 hex digest of a regular file for
// allowlist evaluation. The IOC allowlist stores 64-hex digests, never paths,
// so suppression requires hashing the artifact. Reads are forensic-safe
// (O_NOFOLLOW|O_CLOEXEC|O_NOATIME via safeopen); unreadable, vanished,
// symlinked, or oversized targets simply return "" (no suppression).
func allowlistSHA256(rootFS, virtPath string) string {
	if virtPath == "" || strings.HasPrefix(virtPath, "[") {
		return ""
	}

	hostPath := virtPath
	if rootFS != "" {
		hostPath = filepath.Join(rootFS, strings.TrimPrefix(virtPath, "/"))
	}

	fi, err := os.Lstat(hostPath)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxAllowlistHashBytes {
		return ""
	}

	data, err := safeopen.ReadFileReadOnly(hostPath, maxAllowlistHashBytes)
	if err != nil {
		return ""
	}

	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
