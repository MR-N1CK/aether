package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"aether/internal/report"
)

// Baseline snapshots record the security-relevant state of a host at a point
// in time so later scans can classify every finding as UNCHANGED (same rule
// on the same file with the same content hash — known state), NEW (not in
// the baseline — the delta an analyst must triage), or, in aggregate,
// RESOLVED (baseline entries that no longer fire). This is the classic
// hunting workflow: fingerprint the clean host, then hunt what changed.

// BaselineEntry is one recorded finding fingerprint.
type BaselineEntry struct {
	Path      string `json:"path"`
	Rule      string `json:"rule"`
	SHA256    string `json:"sha256,omitempty"`
	Severity  string `json:"severity"`
	FirstSeen string `json:"first_seen"`
}

// BaselineFile is the serialized snapshot.
type BaselineFile struct {
	Version   int             `json:"version"`
	CreatedAt time.Time       `json:"created_at"`
	Hostname  string          `json:"hostname"`
	Mode      string          `json:"mode"`
	Paths     []string        `json:"paths"`
	Entries   []BaselineEntry `json:"entries"`

	index map[baselineKey]int `json:"-"`
}

// Baseline states attached to findings via metadata["baseline_state"].
const (
	BaselineStateUnchanged = "unchanged"
	BaselineStateNew       = "new"
)

// baselineKey is the composite lookup key for a finding fingerprint.
type baselineKey struct {
	path string
	rule string
}

// SaveBaseline serializes a findings snapshot to path via temp-file + rename
// with 0600 permissions (baseline files list host state and are sensitive).
func SaveBaseline(path string, findings []report.Finding, hostname, mode string, paths []string) error {
	clean := filepath.Clean(path)
	if fi, err := os.Lstat(clean); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write baseline to symlink: %s", clean)
	}

	bf := BaselineFile{
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Hostname:  hostname,
		Mode:      mode,
		Paths:     paths,
		Entries:   make([]BaselineEntry, 0, len(findings)),
	}
	for _, f := range findings {
		sha := f.Hashes["SHA256"]
		if sha == "" && f.EvidenceRecord != nil {
			sha = f.EvidenceRecord.SHA256
		}
		bf.Entries = append(bf.Entries, BaselineEntry{
			Path:      f.Path,
			Rule:      f.RuleName,
			SHA256:    sha,
			Severity:  string(f.Severity),
			FirstSeen: f.Timestamp.Format(time.RFC3339),
		})
	}
	sort.Slice(bf.Entries, func(i, j int) bool {
		if bf.Entries[i].Path != bf.Entries[j].Path {
			return bf.Entries[i].Path < bf.Entries[j].Path
		}
		return bf.Entries[i].Rule < bf.Entries[j].Rule
	})

	raw, err := json.MarshalIndent(bf, "", "  ")
	if err != nil {
		return fmt.Errorf("baseline marshal: %w", err)
	}

	dir := filepath.Dir(clean)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("baseline dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".aether-baseline-*.tmp")
	if err != nil {
		return fmt.Errorf("baseline temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("baseline permissions: %w", err)
	}
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("baseline write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("baseline sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("baseline close: %w", err)
	}
	if err := os.Rename(tmpName, clean); err != nil {
		return fmt.Errorf("baseline rename: %w", err)
	}
	return nil
}

// LoadBaseline reads and validates a baseline snapshot.
func LoadBaseline(path string) (*BaselineFile, error) {
	raw, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // operator-provided file path
	if err != nil {
		return nil, fmt.Errorf("baseline read: %w", err)
	}
	var bf BaselineFile
	if err := json.Unmarshal(raw, &bf); err != nil {
		return nil, fmt.Errorf("baseline parse: %w", err)
	}
	if bf.Version != 1 {
		return nil, fmt.Errorf("unsupported baseline version %d", bf.Version)
	}
	if len(bf.Entries) == 0 {
		return nil, fmt.Errorf("baseline contains no entries")
	}
	// Build lookup index.
	bf.index = make(map[baselineKey]int, len(bf.Entries))
	for i, e := range bf.Entries {
		bf.index[baselineKey{e.Path, e.Rule}] = i
	}
	return &bf, nil
}

// Classify reports the baseline state of a finding. A matching entry with a
// pinned hash that still matches (or no hash on either side) is UNCHANGED;
// a hash mismatch means the artifact itself changed since the baseline and
// is reported as NEW — content drift is exactly what a hunter wants surfaced.
func (b *BaselineFile) Classify(f *report.Finding) string {
	if b == nil || b.index == nil {
		return BaselineStateNew
	}
	i, ok := b.index[baselineKey{f.Path, f.RuleName}]
	if !ok {
		return BaselineStateNew
	}
	entry := b.Entries[i]
	sha := f.Hashes["SHA256"]
	if sha == "" && f.EvidenceRecord != nil {
		sha = f.EvidenceRecord.SHA256
	}
	if entry.SHA256 != "" && sha != "" && entry.SHA256 != sha {
		return BaselineStateNew // content changed since baseline
	}
	return BaselineStateUnchanged
}

// ResolvedDiff returns baseline entries whose (path, rule) fingerprint no
// longer fires in the current findings — state that healed between snapshots.
func (b *BaselineFile) ResolvedDiff(current []report.Finding) []BaselineEntry {
	if b == nil {
		return nil
	}
	fired := make(map[baselineKey]struct{}, len(current))
	for _, f := range current {
		fired[baselineKey{f.Path, f.RuleName}] = struct{}{}
	}
	var resolved []BaselineEntry
	for _, e := range b.Entries {
		if _, ok := fired[baselineKey{e.Path, e.Rule}]; !ok {
			resolved = append(resolved, e)
		}
	}
	return resolved
}
