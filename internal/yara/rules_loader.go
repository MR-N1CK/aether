package yara

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// Embedded Demo Rules (Harmless test patterns)
const (
	DemoRuleEICAR = `rule Aether_Demo_EICAR {
    meta:
        description = "Matches harmless EICAR synthetic test signature"
        score = 85
        author = "Aether Team"
        confidence = "high"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}`

	DemoRuleMarker = `rule Aether_Demo_Marker {
    meta:
        description = "Harmless test marker for scanner verification"
        score = 30
        author = "Aether Team"
    strings:
        $marker = "AETHER_DEMO_TEST_MARKER_STRING"
    condition:
        $marker
}`
)

// ValidateRulesDirTrust enforces strict multi-user directory ownership and permission constraints:
// - If trustRulesDir is true: explicitly bypasses all trust checks (e.g. for development/testing).
// - As root (euid 0), verifies directory and all parent directories up to / are root-owned (UID 0)
//   and not group- or world-writable (perm & 0022 == 0).
// - As non-root, user rules dirs must be owned by the user (or root) and NOT group/world-writable.
func ValidateRulesDirTrust(dir string, isRoot bool, currentUID uint32, trustRulesDir bool) (bool, string) {
	if trustRulesDir {
		return true, ""
	}

	cleanDir := filepath.Clean(dir)
	fi, err := os.Stat(cleanDir)
	if err != nil {
		return false, fmt.Sprintf("cannot access directory: %v", err)
	}

	if !fi.IsDir() {
		return false, fmt.Sprintf("path is not a directory: %s", cleanDir)
	}

	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, "failed to retrieve POSIX file stats"
	}

	if isRoot {
		// Root: rules directory and all parent directories up to / must be root-owned (UID 0)
		// and not group- or world-writable (perm & 0022 == 0).
		if trusted, reason := VerifyRootOwnedPath(cleanDir, nil, nil); !trusted {
			return false, fmt.Sprintf("rules directory %s is not in a secure root-owned path: %s", cleanDir, reason)
		}
		return true, ""
	}

	// Non-root: verify owner is invoking user or root
	if stat.Uid != currentUID && stat.Uid != 0 {
		return false, fmt.Sprintf("directory owned by uid %d, expected %d: %s", stat.Uid, currentUID, cleanDir)
	}

	// Non-root: verify not group- or world-writable
	perm := fi.Mode().Perm()
	if perm&0022 != 0 {
		return false, fmt.Sprintf("directory has insecure permissions (%04o, group/world-writable): %s", perm, cleanDir)
	}

	return true, ""
}

// DiscoverRuleFiles searches configured rule directories for *.yar and *.yara files.
// Untrusted directories are rejected with a single warning unless trustRulesDir is enabled.
func DiscoverRuleFiles(dirs []string, isRoot bool, currentUID uint32, trustRulesDir bool, logger *slog.Logger) ([]string, []string) {
	var ruleFiles []string
	var warnings []string
	seen := make(map[string]bool)

	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		cleanDir := filepath.Clean(dir)
		if seen[cleanDir] {
			continue
		}
		seen[cleanDir] = true

		if _, err := os.Stat(cleanDir); os.IsNotExist(err) {
			continue
		}

		trusted, reason := ValidateRulesDirTrust(cleanDir, isRoot, currentUID, trustRulesDir)
		if !trusted {
			msg := fmt.Sprintf("skipping untrusted rules directory %s: %s", cleanDir, reason)
			warnings = append(warnings, msg)
			if logger != nil {
				logger.Warn(msg)
			}
			continue
		}

		err := filepath.WalkDir(cleanDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				// Don't follow symlinked directories
				if d.Type()&os.ModeSymlink != 0 {
					return filepath.SkipDir
				}
				return nil
			}

			// Do NOT follow symlinks for rule files
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}

			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".yar" || ext == ".yara" {
				ruleFiles = append(ruleFiles, path)
			}
			return nil
		})

		if err != nil && logger != nil {
			logger.Warn("error walking rules directory", slog.String("dir", cleanDir), slog.Any("error", err))
		}
	}

	sort.Strings(ruleFiles)
	return ruleFiles, warnings
}

// GetRuleNamespace derives an isolated namespace for a rule file based on its filename or path.
func GetRuleNamespace(path string) string {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	// Sanitize identifier
	var sb strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('_')
		}
	}
	res := sb.String()
	if res == "" || (res[0] >= '0' && res[0] <= '9') {
		res = "ns_" + res
	}
	return res
}
