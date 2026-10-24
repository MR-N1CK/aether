//go:build linux

package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"aether/internal/pkgdb"
	"aether/internal/report"
)

// TestSystemBinaryCorpus_ZeroMaliciousVerdicts sweeps a bounded slice of the
// live /usr/bin tree — real distribution binaries, the closest thing to an
// external benign corpus available offline — and asserts the ELF behavioral
// engine never adjudicates a package-owned system binary MALICIOUS. This is
// the crying-wolf gate: one false COMPROMISED on /usr/bin/ssh destroys more
// analyst trust than a hundred correct detections build.
func TestSystemBinaryCorpus_ZeroMaliciousVerdicts(t *testing.T) {
	db := pkgdb.New("")
	if !db.IsAvailable() {
		t.Skip("no package database available (requires dpkg/rpm database)")
	}

	entries, err := os.ReadDir("/usr/bin")
	if err != nil {
		t.Skip("/usr/bin not readable")
	}

	var targets []string
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		targets = append(targets, filepath.Join("/usr/bin", e.Name()))
	}
	sort.Strings(targets)

	const maxTargets = 400
	const minSize = int64(2048)
	const maxSize = int64(8 << 20)

	scanned := 0
	checked := 0
	for _, path := range targets {
		if scanned >= maxTargets {
			break
		}
		if _, owned := db.Owner(path); !owned {
			continue
		}
		fi, err := os.Stat(path)
		if err != nil || fi.Size() < minSize || fi.Size() > maxSize {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil || len(data) < 4 || !IsELF(data) {
			continue
		}
		scanned++

		matches := AnalyzeELFExecutable(path, data, uint32(fi.Mode().Perm()), db, nil)
		for _, m := range matches {
			checked++
			f := report.NewFinding("filesystem", m.Severity, path, m.Reason, m.Name)
			verdict := report.DetermineVerdict(&f, db, true, false, false, m.Corroboration)
			if verdict == report.VerdictMalicious {
				t.Errorf("FALSE POSITIVE: package-owned system binary %s adjudicated MALICIOUS via %s (corroboration: %v)", path, m.Name, m.Corroboration)
			}
		}
	}

	if scanned < 50 {
		t.Skipf("only %d package-owned ELF binaries found; environment too sparse for a meaningful corpus", scanned)
	}
	t.Logf("system corpus: %d package-owned ELF binaries, %d rule matches, 0 MALICIOUS tolerated", scanned, checked)
}
