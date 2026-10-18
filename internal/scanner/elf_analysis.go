package scanner

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aether/internal/config"
	"aether/internal/report"
)

// ELF magic bytes; scanning many files makes a cheap pre-check worthwhile.
var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// standardSystemDirs are the ELF library/binary trees a package manager owns.
// Binaries found there are attack surface for every process on the host, so a
// hostile RPATH entry inside them ranks ALERT. Outside them it still signals
// staging behaviour, but ranks WARNING.
var standardSystemDirs = []string{
	"/bin", "/sbin",
	"/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec",
	"/lib", "/lib64", "/lib32",
}

// volatileLibDirs are temporary execution/staging roots; an RPATH pointing
// into them is the classic directory-hijack bootstrap (loader resolves
// dependencies before any trust check runs).
func volatileLibDir(p string) bool {
	return p == "/tmp" || strings.HasPrefix(p, "/tmp/") ||
		p == "/var/tmp" || strings.HasPrefix(p, "/var/tmp/") ||
		p == "/dev/shm" || strings.HasPrefix(p, "/dev/shm/") ||
		strings.HasPrefix(p, "/run/user/")
}

// worldWritableDir stats a directory and reports whether it is group/world
// writable. Lookup failures return false silently: the detector fires on
// values it can verify as hostile, not on unreadable state.
func worldWritableDir(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || !fi.IsDir() {
		return false
	}
	return fi.Mode().Perm()&0002 != 0
}

// CheckSuspiciousELFRPath inspects an ELF binary's DT_RPATH / DT_RUNPATH
// entries for hijack-prone search roots: volatile execution directories,
// world-writable directories, or relative entries ($ORIGIN-relative forms
// are ignored as they are the legitimate relocatable pattern).
//
// The check is deliberately narrow to stay false-positive free: it fires
// only on values that are verifiably dangerous. File reads are read-only
// (forensic-safe); the returned rule name must be registered in
// internal/report rule metadata.
func CheckSuspiciousELFRPath(path string, data []byte, mode uint32, cfg *config.Config) *HeuristicMatch {
	if len(data) < 4 || !bytes.Equal(data[:4], elfMagic) {
		return nil
	}

	// Gate on executability semantics: executables (any exec bit) or shared
	// objects get library-search treatment. Plain data files matching the ELF
	// magic are skipped.
	cleaned := filepath.Clean(path)
	isSharedObject := strings.Contains(filepath.Base(cleaned), ".so")
	if (mode&0111) == 0 && !isSharedObject {
		return nil
	}

	ef, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil
	}

	inSystemDir := false
	for _, d := range standardSystemDirs {
		if cleaned == d || strings.HasPrefix(cleaned, d+"/") {
			inSystemDir = true
			break
		}
	}

	type offending struct {
		entry string
		why   string
	}
	var offenders []offending

	inspect := func(values []string) {
		for _, raw := range values {
			for _, entry := range filepath.SplitList(raw) {
				entry = strings.TrimSpace(entry)
				if entry == "" {
					continue
				}
				if strings.HasPrefix(entry, "$ORIGIN") || strings.HasPrefix(entry, "${ORIGIN}") {
					continue
				}
				if !filepath.IsAbs(entry) {
					offenders = append(offenders, offending{entry: entry, why: "relative search path"})
					continue
				}
				if volatileLibDir(entry) {
					offenders = append(offenders, offending{entry: entry, why: "volatile execution directory"})
					continue
				}
				if worldWritableDir(entry) {
					offenders = append(offenders, offending{entry: entry, why: "world-writable directory"})
				}
			}
		}
	}

	if rpaths, err := ef.DynString(elf.DT_RPATH); err == nil {
		inspect(rpaths)
	}
	if runpaths, err := ef.DynString(elf.DT_RUNPATH); err == nil {
		inspect(runpaths)
	}

	if len(offenders) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(offenders))
	summary := make([]string, 0, len(offenders))
	for _, o := range offenders {
		key := o.entry + "|" + o.why
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		summary = append(summary, fmt.Sprintf("%s (%s)", o.entry, o.why))
	}

	reason := fmt.Sprintf("ELF DT_RPATH/DT_RUNPATH entries reference attacker-controllable library search roots: %s",
		strings.Join(summary, "; "))

	score := config.DefaultScoreELFRPATHUser
	severity := report.SeverityWarning
	if inSystemDir {
		score = config.DefaultScoreELFRPATHSystem
		severity = report.SeverityAlert
	}
	if cfg != nil {
		if cfg.Scan.ScoreELFRPATHSystem > 0 && inSystemDir {
			score = cfg.Scan.ScoreELFRPATHSystem
		}
		if cfg.Scan.ScoreELFRPATHUser > 0 && !inSystemDir {
			score = cfg.Scan.ScoreELFRPATHUser
		}
	}

	return &HeuristicMatch{
		Name:     "Persistence_ELF_RPATH_Hijack",
		Reason:   reason,
		Score:    score,
		Severity: severity,
	}
}
