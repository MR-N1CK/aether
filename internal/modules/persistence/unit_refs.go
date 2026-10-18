package persistence

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"aether/internal/report"
	"aether/internal/safeopen"
)

// unitRefMaxUnitBytes bounds a single unit file read; units larger than this
// are treated as unreadable rather than parsed.
const unitRefMaxUnitBytes = int64(1 << 20)

// unitRefMaxRefs caps the total number of distinct exec-target references
// returned by CollectEnabledUnitRefs so a pathological host cannot explode
// the correlation map.
const unitRefMaxRefs = 512

// localSystemdUnitDirs are the systemd search paths scanned for units that
// define what runs on this host, in systemd's own precedence order: admin
// trees first, then runtime generator output, then packaged units.
var localSystemdUnitDirs = []string{
	"/etc/systemd/system",
	"/run/systemd/generator",
	"/run/systemd/generator.early",
	"/usr/lib/systemd/system",
	"/usr/local/lib/systemd/system",
}

// isExecDirective reports whether a systemd key name is one of the Exec*
// directives that launch processes.
func isExecDirective(key string) bool {
	switch key {
	case "ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop",
		"ExecStopPost", "ExecReload", "ExecCond", "ExecOnFailure",
		"ExecOnSuccess":
		return true
	default:
		return false
	}
}

// hasUnitSuffix reports whether name looks like a systemd unit filename.
func hasUnitSuffix(name string) bool {
	for _, sfx := range []string{".service", ".timer", ".path", ".socket", ".mount", ".automount", ".target"} {
		if strings.HasSuffix(name, sfx) {
			return true
		}
	}
	return false
}

// joinVirt concatenates a virtual directory and unit filename.
func joinVirt(dir, name string) string {
	return filepath.Clean(dir + "/" + name)
}

// CollectEnabledUnitRefs crawls the local systemd unit directories and builds
// a map from absolute executable paths to the sorted basenames of ENABLED
// units referencing them. A unit counts as enabled when it is
//
//   - defined directly under /etc/systemd/system (admin-authored),
//   - produced by a generator under /run/systemd/generator*,
//   - a drop-in placed inside a *.wants / *.requires directory, or
//   - a packaged unit (/usr/lib, /usr/local/lib) with an enablement symlink
//     inside any local *.wants / *.requires directory.
//
// The crawl is best-effort and strictly read-only: unreadable or vanished
// files are skipped silently, and no inspected file is mutated. It is
// intended for post-scan correlation, annotating findings whose paths are
// actively launched by a boot-enabled unit.
//
// maxRefs caps the number of distinct references; pass 0 for the default cap.
func CollectEnabledUnitRefs(rootFS string, maxRefs int) map[string][]string {
	if maxRefs <= 0 {
		maxRefs = unitRefMaxRefs
	}
	refs := make(map[string][]string)
	seenTargets := make(map[string]bool)
	seenUnits := make(map[string]bool)

	parseUnit := func(virtUnit string) []string {
		data, _, err := SafeReadRegularFile(rootFS, virtUnit, unitRefMaxUnitBytes)
		if err != nil || len(data) == 0 {
			return nil
		}
		scan := bufio.NewScanner(bytes.NewReader(data))
		scan.Buffer(make([]byte, 0, 64*1024), int(unitRefMaxUnitBytes))
		execSet := make(map[string]bool)
		for scan.Scan() {
			line := strings.TrimSpace(scan.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			if !strings.HasPrefix(line, "Exec") {
				continue
			}
			eq := strings.Index(line, "=")
			if eq <= 0 || !isExecDirective(line[:eq]) {
				continue
			}
			cmd := strings.TrimSpace(line[eq+1:])
			cmd = strings.TrimPrefix(cmd, "-")
			cmd = strings.TrimPrefix(cmd, "@")
			if cmd == "" || cmd == "!" {
				continue
			}
			targets, _ := ExtractExecTargets(cmd)
			for _, t := range targets {
				execSet[t] = true
			}
		}
		return keysSorted(execSet)
	}

	addRef := func(target, unit string) {
		if seenTargets[target] {
			for _, u := range refs[target] {
				if u == unit {
					return
				}
			}
			refs[target] = append(refs[target], unit)
			return
		}
		seenTargets[target] = true
		refs[target] = []string{unit}
	}

	record := func(virtUnit string) {
		if seenUnits[virtUnit] {
			return
		}
		seenUnits[virtUnit] = true
		unit := filepath.Base(virtUnit)
		for _, t := range parseUnit(virtUnit) {
			if !filepath.IsAbs(t) {
				continue // bare names resolve at runtime; unmatchable
			}
			addRef(t, unit)
			if len(refs) >= maxRefs {
				return
			}
		}
	}

	// Enablement symlink names across the local trees.
	wanted := make(map[string]bool)
	for _, dir := range localSystemdUnitDirs {
		hostDir, _, _, err := safeopen.ResolveUnderRoot(rootFS, dir)
		if err != nil {
			continue
		}
		entries, err := os.ReadDir(hostDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if !strings.HasSuffix(e.Name(), ".wants") && !strings.HasSuffix(e.Name(), ".requires") {
				continue
			}
			wEntries, err := os.ReadDir(filepath.Join(hostDir, e.Name()))
			if err != nil {
				continue
			}
			for _, we := range wEntries {
				wanted[we.Name()] = true
			}
		}
	}

	hostJoinRoot := func(absVirt string) string {
		if rootFS == "" {
			return absVirt
		}
		return filepath.Join(rootFS, absVirt)
	}
	hostToVirt := func(host string) string {
		if rootFS == "" {
			return host
		}
		if host == rootFS {
			return "/"
		}
		if strings.HasPrefix(host, rootFS+"/") {
			return strings.TrimPrefix(host, rootFS)
		}
		return "" // escapes the scanned root; unmatchable
	}

	// scanWantsDir records every unit inside a *.wants / *.requires
	// directory: membership alone makes the unit boot-relevant. Symlinks are
	// resolved manually because SafeReadRegularFile refuses to follow them.
	scanWantsDir := func(virtWants, hostWants string) {
		wEntries, err := os.ReadDir(hostWants)
		if err != nil {
			return
		}
		for _, we := range wEntries {
			name := we.Name()
			if !hasUnitSuffix(name) {
				continue
			}
			hostEntry := filepath.Join(hostWants, name)
			if we.Type()&os.ModeSymlink != 0 {
				tgt, rErr := os.Readlink(hostEntry)
				if rErr != nil {
					continue
				}
				var hostTgt string
				if filepath.IsAbs(tgt) {
					hostTgt = hostJoinRoot(tgt)
				} else {
					hostTgt = filepath.Clean(filepath.Join(hostWants, tgt))
				}
				if virtTgt := hostToVirt(hostTgt); virtTgt != "" {
					record(virtTgt)
				}
			} else {
				record(joinVirt(virtWants, name)) // admin drop-in, enabled
			}
			if len(refs) >= maxRefs {
				return
			}
		}
	}

	for _, dir := range localSystemdUnitDirs {
		hostDir, _, _, err := safeopen.ResolveUnderRoot(rootFS, dir)
		if err != nil {
			continue
		}
		entries, err := os.ReadDir(hostDir)
		if err != nil {
			continue
		}
		isLocalTree := strings.HasPrefix(dir, "/etc/systemd/system") ||
			strings.HasPrefix(dir, "/run/systemd/generator") ||
			strings.HasPrefix(dir, "/usr/local/lib")
		for _, e := range entries {
			name := e.Name()
			// Wants/requires subdirectories: every unit inside is
			// boot-relevant by membership.
			if e.IsDir() && (strings.HasSuffix(name, ".wants") || strings.HasSuffix(name, ".requires")) {
				scanWantsDir(joinVirt(dir, name), filepath.Join(hostDir, name))
				if len(refs) >= maxRefs {
					return refs
				}
				continue
			}
			if !hasUnitSuffix(name) || !e.Type().IsRegular() {
				continue // only plain unit files at top level
			}
			if !isLocalTree && !wanted[name] {
				continue // packaged unit without enablement: not boot-relevant
			}
			record(joinVirt(dir, name))
			if len(refs) >= maxRefs {
				return refs
			}
		}
	}

	return refs
}

// keysSorted returns the sorted keys of a string set.
func keysSorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// AnnotateEnabledUnitRefs decorates findings whose target path is executed by
// a boot-enabled systemd unit with forensic metadata:
//
//	enabled_units  — comma-separated unit basenames launching the path
//	enabled_unit   — the first such unit (stable: sorted)
//
// The function is annotation-only: severity, verdict, and reason text are
// never modified, so it cannot introduce false positives on its own. Paths
// are matched using the same normalization the cross-domain correlator uses.
// Returns the number of annotated findings. The refs crawl is skipped when
// there are neither findings nor refs to match.
func AnnotateEnabledUnitRefs(rootFS string, findings []report.Finding) int {
	if len(findings) == 0 {
		return 0
	}
	rawRefs := CollectEnabledUnitRefs(rootFS, unitRefMaxRefs)
	if len(rawRefs) == 0 {
		return 0
	}

	normedRefs := make(map[string][]string, len(rawRefs))
	for target, units := range rawRefs {
		n := report.NormalizeFindingPath(target)
		if n == "" && !filepath.IsAbs(target) {
			continue
		}
		sort.Strings(units)
		normedRefs[n] = units
	}
	if len(normedRefs) == 0 {
		return 0
	}

	annotated := 0
	for i := range findings {
		f := &findings[i]
		candidates := []string{f.Path}
		if f.EvidenceRecord != nil && f.EvidenceRecord.TargetPath != "" {
			candidates = append(candidates, f.EvidenceRecord.TargetPath)
		}
		for _, c := range candidates {
			n := report.NormalizeFindingPath(c)
			units, ok := normedRefs[n]
			if !ok {
				continue
			}
			if _, dup := f.Metadata["enabled_units"]; !dup {
				if f.Metadata == nil {
					f.Metadata = make(map[string]interface{}, 2)
				}
				f.Metadata["enabled_units"] = strings.Join(units, ", ")
				f.Metadata["enabled_unit"] = units[0]
				annotated++
			}
			break
		}
	}
	return annotated
}
