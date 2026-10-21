package triage

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"aether/internal/report"
	"aether/internal/safeopen"
)

var (
	ErrAlertNotAckable  = errors.New("ALERT and IOC findings cannot be acknowledged")
	ErrUnsafePermission = errors.New("user acknowledgment file has insecure permissions (group or world writable)")
	ErrForeignOwner     = errors.New("user acknowledgment file is not owned by the invoking user")
	ErrOutsideHome      = errors.New("user acknowledgment file cannot acknowledge paths outside user home directory")
)

// AckEntry represents a single pinned finding acknowledgment.
type AckEntry struct {
	Path                string            `yaml:"path"`
	Rule                string            `yaml:"rule,omitempty"`
	FileSHA256          string            `yaml:"sha256,omitempty"`
	LegacyFileSHA256    string            `yaml:"file_sha256,omitempty"`
	LineSHA256          string            `yaml:"line_sha256,omitempty"` // For profiles/cron: sha256 of normalized line
	LineContent         string            `yaml:"line_content,omitempty"`
	ExecTargetHashes    map[string]string `yaml:"exec_target_hashes,omitempty"` // targetPath -> sha256
	SymlinkTarget       string            `yaml:"symlink_target,omitempty"`
	SymlinkTargetSHA256 string            `yaml:"symlink_target_sha256,omitempty"`
	Reason              string            `yaml:"reason"`
	AddedBy             string            `yaml:"added_by"`
	Date                string            `yaml:"date"`
}

// AckFile models the on-disk YAML format.
type AckFile struct {
	Entries       []AckEntry `yaml:"entries"`
	LegacyEntries []AckEntry `yaml:"acknowledgments,omitempty"`
}

// CountAckEntries reads an acknowledgment file and returns the count of valid entries.
func CountAckEntries(path string) (int, error) {
	data, err := safeopen.ReadFileReadOnly(path, 10*1024*1024)
	if err != nil {
		return 0, err
	}
	var af AckFile
	if err := yaml.Unmarshal(data, &af); err != nil {
		return 0, err
	}
	count := len(af.Entries)
	if count == 0 {
		count = len(af.LegacyEntries)
	}
	return count, nil
}

// Engine manages finding triage and verification against stored pin hashes.
type Engine struct {
	entries     []AckEntry
	loadedPaths []string
}

// HashFile hashes a regular file using safeopen.OpenRegularReadOnly.
func HashFile(hostPath string, maxBytes int64) (string, error) {
	if maxBytes <= 0 {
		maxBytes = 50 * 1024 * 1024
	}
	f, err := safeopen.OpenRegularReadOnly(hostPath, maxBytes)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// NormalizeLine returns a line with uniform single-space whitespace.
func NormalizeLine(line string) string {
	return strings.Join(strings.Fields(line), " ")
}

// HashLine returns the SHA256 hex string of a normalized line.
func HashLine(line string) string {
	normalized := NormalizeLine(line)
	h := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(h[:])
}

// LoadEngine initializes the triage engine from system and user config paths.
// - If euid == 0: loads ONLY /etc/aether/acknowledged.yaml (ignores user files).
// - If non-root: loads /etc/aether/acknowledged.yaml + user's ~/.config/aether/acknowledged.yaml.
// User file is validated: must be owned by user, mode <= 0600 (not group/world writable),
// and only acknowledges paths inside user's home.
func LoadEngine(customPath, rootFS string) (*Engine, error) {
	eng := &Engine{}

	if customPath != "" {
		isSys := strings.HasPrefix(customPath, "/etc/") || strings.Contains(customPath, "etc/aether")
		if err := eng.loadFile(customPath, rootFS, isSys); err != nil {
			return nil, err
		}
		return eng, nil
	}

	isRoot := os.Geteuid() == 0

	// 1. System file: /etc/aether/acknowledged.yaml
	sysPath := "/etc/aether/acknowledged.yaml"
	if rootFS != "" {
		sysPath = filepath.Join(rootFS, "etc/aether/acknowledged.yaml")
	}
	if _, err := os.Stat(sysPath); err == nil {
		if err := eng.loadFile(sysPath, rootFS, true); err != nil {
			slog.Warn("failed to load system acknowledged file", "path", sysPath, "error", err)
		}
	}

	// 2. If running as euid 0, root ignores user ack files completely.
	if isRoot {
		return eng, nil
	}

	// 3. User file: ~/.config/aether/acknowledged.yaml
	homeDir, err := os.UserHomeDir()
	if err == nil && homeDir != "" {
		userPath := filepath.Join(homeDir, ".config/aether/acknowledged.yaml")
		if rootFS != "" {
			userPath = filepath.Join(rootFS, strings.TrimPrefix(userPath, "/"))
		}
		if _, err := os.Stat(userPath); err == nil {
			if err := eng.loadFile(userPath, rootFS, false); err != nil {
				slog.Warn("rejected user acknowledged file", "path", userPath, "error", err)
			}
		}
	}

	return eng, nil
}

func (eng *Engine) loadFile(path, rootFS string, isSystem bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}

	// If user file, enforce ownership and permission security
	if !isSystem {
		if statSys, ok := fi.Sys().(*syscall.Stat_t); ok {
			invokingUID := uint32(os.Geteuid())
			if statSys.Uid != invokingUID && rootFS == "" {
				return fmt.Errorf("%w: file owner %d != current user %d", ErrForeignOwner, statSys.Uid, invokingUID)
			}
		}
		perm := fi.Mode().Perm()
		if (perm & 0022) != 0 {
			return fmt.Errorf("%w: permissions %04o allow group/world write", ErrUnsafePermission, perm)
		}
	}

	data, err := safeopen.ReadFileReadOnly(path, 10*1024*1024)
	if err != nil {
		return err
	}

	var af AckFile
	if err := yaml.Unmarshal(data, &af); err != nil {
		return fmt.Errorf("invalid YAML in %s: %w", path, err)
	}

	if len(af.Entries) == 0 && len(af.LegacyEntries) > 0 {
		af.Entries = af.LegacyEntries
	}
	for i := range af.Entries {
		if af.Entries[i].FileSHA256 == "" && af.Entries[i].LegacyFileSHA256 != "" {
			af.Entries[i].FileSHA256 = af.Entries[i].LegacyFileSHA256
		}
	}

	userHome := ""
	if !isSystem {
		userHome, _ = os.UserHomeDir()
	}

	for _, entry := range af.Entries {
		if entry.Path == "" {
			continue
		}
		// User file entries must strictly reside within user's home directory
		if !isSystem && userHome != "" {
			cleanTarget := filepath.Clean(entry.Path)
			cleanHome := filepath.Clean(userHome)
			if !strings.HasPrefix(cleanTarget, cleanHome+"/") && cleanTarget != cleanHome {
				slog.Warn("skipping acknowledgment for path outside user home", "path", entry.Path, "user_home", userHome)
				continue
			}
		}
		eng.entries = append(eng.entries, entry)
	}

	eng.loadedPaths = append(eng.loadedPaths, path)
	return nil
}

// Entries returns loaded ack entries.
func (eng *Engine) Entries() []AckEntry {
	return eng.entries
}

// Evaluate checks a finding against acknowledged entries.
//   - ALERT, IOC hits, and high-confidence primitives are NEVER acknowledged.
//   - If matched entry pin hashes match current file/target hashes:
//     downgrades to report.SeverityInfo, marks f.Metadata["acknowledged"] = true.
//   - If pin hashes differ: voids acknowledgment with reason "acknowledged file was modified".
func (eng *Engine) Evaluate(f *report.Finding, rootFS string) bool {
	if f == nil {
		return false
	}

	if isAck, ok := f.Metadata["acknowledged"].(bool); ok && isAck {
		return true
	}

	// 1. ALERT and high-confidence primitives cannot be acknowledged
	if f.Severity == report.SeverityAlert {
		return false
	}
	if isIOC, ok := f.Metadata["is_ioc_match"].(bool); ok && isIOC {
		return false
	}
	if isHC, ok := f.Metadata["high_confidence"].(bool); ok && isHC {
		return false
	}
	if strings.Contains(f.RuleName, "IOC") || strings.Contains(f.RuleName, "Reverse_Shell_Primitive") {
		return false
	}

	// 2. Find matching entry by path and optional rule
	var matched *AckEntry
	for i := range eng.entries {
		e := &eng.entries[i]
		if e.Path == f.Path {
			if e.Rule == "" || e.Rule == f.RuleName || strings.Contains(f.RuleName, e.Rule) {
				matched = e
				break
			}
		}
	}

	if matched == nil {
		return false
	}

	hostPath := f.Path
	if rootFS != "" {
		hostPath = filepath.Join(rootFS, strings.TrimPrefix(f.Path, "/"))
	}

	// 3. Verify pins
	lstat, err := os.Lstat(hostPath)
	if err != nil {
		// File vanished or cannot be stat'd -> void
		f.Reason += " | acknowledged file was modified (inaccessible)"
		f.Metadata["ack_void"] = true
		return false
	}

	// Symlink check
	if (lstat.Mode() & os.ModeSymlink) != 0 {
		target, err := os.Readlink(hostPath)
		if err != nil {
			f.Reason += " | acknowledged file was modified (symlink unreadable)"
			f.Metadata["ack_void"] = true
			return false
		}
		if matched.SymlinkTarget != "" && matched.SymlinkTarget != target {
			f.Reason += " | acknowledged file was modified (symlink target changed)"
			f.Metadata["ack_void"] = true
			return false
		}
		if matched.SymlinkTargetSHA256 != "" {
			targetHost := target
			if filepath.IsAbs(target) && rootFS != "" {
				targetHost = filepath.Join(rootFS, strings.TrimPrefix(target, "/"))
			} else if !filepath.IsAbs(target) {
				targetHost = filepath.Join(filepath.Dir(hostPath), target)
			}
			tHash, err := HashFile(targetHost, 50*1024*1024)
			if err != nil || tHash != matched.SymlinkTargetSHA256 {
				f.Reason += " | acknowledged file was modified (target content changed)"
				f.Metadata["ack_void"] = true
				return false
			}
		}
	} else {
		// Regular file whole-hash check (if pinned)
		if matched.FileSHA256 != "" {
			currHash, err := HashFile(hostPath, 50*1024*1024)
			if err != nil || currHash != matched.FileSHA256 {
				f.Reason += " | acknowledged file was modified (hash mismatch)"
				f.Metadata["ack_void"] = true
				return false
			}
		}
	}

	// Line hash check (for profile / cron matched lines)
	if matched.LineSHA256 != "" {
		lineMatched := false
		if matchedLine, ok := f.Metadata["line_content"].(string); ok && matchedLine != "" {
			if HashLine(matchedLine) == matched.LineSHA256 {
				lineMatched = true
			}
		}
		if !lineMatched {
			// Check file lines for the hash
			fLines, rErr := safeopen.ReadFileReadOnly(hostPath, 50*1024*1024)
			if rErr == nil {
				sc := bufio.NewScanner(bytes.NewReader(fLines))
				for sc.Scan() {
					if HashLine(sc.Text()) == matched.LineSHA256 {
						lineMatched = true
						break
					}
				}
			}
		}
		if !lineMatched {
			f.Reason += " | acknowledged file was modified (pinned line changed)"
			f.Metadata["ack_void"] = true
			return false
		}
	}

	// Exec target hashes check (referenced scripts in user home)
	if len(matched.ExecTargetHashes) > 0 {
		for targetVirt, expectedHash := range matched.ExecTargetHashes {
			targetHost := targetVirt
			if rootFS != "" {
				targetHost = filepath.Join(rootFS, strings.TrimPrefix(targetVirt, "/"))
			}
			tHash, err := HashFile(targetHost, 50*1024*1024)
			if err != nil || tHash != expectedHash {
				f.Reason += fmt.Sprintf(" | acknowledged file was modified (referenced target %s modified)", targetVirt)
				f.Metadata["ack_void"] = true
				return false
			}
		}
	}

	// All pins verified -> Downgrade finding to INFO
	f.Metadata["original_severity"] = string(f.Severity)
	f.Metadata["acknowledged"] = true
	f.Metadata["ack_reason"] = matched.Reason
	f.Metadata["ack_added_by"] = matched.AddedBy
	f.Metadata["ack_date"] = matched.Date

	f.Severity = report.SeverityInfo
	return true
}

// WriteAckEntry atomically writes an AckEntry to destPath (mode 0600, parent dir 0700).
func WriteAckEntry(destPath string, entry AckEntry) error {
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Load existing entries if any
	var af AckFile
	if data, err := safeopen.ReadFileReadOnly(destPath, 10*1024*1024); err == nil {
		_ = yaml.Unmarshal(data, &af)
	}

	// Set date if missing
	if entry.Date == "" {
		entry.Date = time.Now().UTC().Format(time.RFC3339)
	}

	// Update or append entry
	updated := false
	for i := range af.Entries {
		if af.Entries[i].Path == entry.Path && (entry.Rule == "" || af.Entries[i].Rule == entry.Rule) {
			af.Entries[i] = entry
			updated = true
			break
		}
	}
	if !updated {
		af.Entries = append(af.Entries, entry)
	}

	outBytes, err := yaml.Marshal(&af)
	if err != nil {
		return fmt.Errorf("failed to marshal acknowledged entries: %w", err)
	}

	// Write atomically: temp file in same dir + rename
	tmpFile, err := os.CreateTemp(dir, "ack-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to chmod temp file: %w", err)
	}

	if _, err := tmpFile.Write(outBytes); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write to temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Rename(tmpName, destPath); err != nil {
		return fmt.Errorf("failed to replace %s: %w", destPath, err)
	}

	return nil
}
