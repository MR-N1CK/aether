package kernel

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"aether/internal/report"
)

// kallsymsReadLimit bounds /proc/kallsyms reads (typically 2-4 MB on
// module-heavy hosts; 16 MB covers pathological symbol tables).
const kallsymsReadLimit = 16 * 1024 * 1024

// readKallsymsModuleNames parses /proc/kallsyms and returns the set of
// loadable-module names that own symbols. Symbol lines look like:
//
//	ffffffffc0123456 T sym_name  [module_name]
//
// Built-in symbols carry no bracket segment. Names are dash-normalized to
// match /proc/modules and /sys/module conventions.
func readKallsymsModuleNames(procRoot string) (map[string]bool, int, error) {
	path := "/proc/kallsyms"
	if procRoot != "" {
		path = filepath.Join(procRoot, "kallsyms")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	modules := make(map[string]bool)
	symbolCount := 0
	scanner := bufio.NewScanner(io.LimitReader(f, kallsymsReadLimit))
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.LastIndex(line, " [")
		if idx == -1 {
			continue
		}
		name := strings.TrimSuffix(strings.TrimSpace(line[idx+2:]), "]")
		if name == "" || name == "builtin" {
			continue
		}
		symbolCount++
		modules[strings.ReplaceAll(name, "-", "_")] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, symbolCount, err
	}
	return modules, symbolCount, nil
}

// CheckKallsymsHiddenModules performs a three-way reconciliation that closes
// the gap the two-pass /proc/modules vs /sys/module check cannot cover:
// rootkits that unlink their module from BOTH lists (DKOM) still leak their
// symbol owners through /proc/kallsyms — the symbol table is populated by the
// module loader independently of the module lists. A module owning kallsyms
// symbols while absent from both /proc/modules and /sys/module is a hidden
// loaded module: the DKOM unlink signature (T1014).
//
// The check requires a root-readable kallsyms table; under kptr_restrict or
// as an unprivileged user the table is empty or address-zeroed, in which case
// the check degrades to a coverage note instead of raising noise.
func CheckKallsymsHiddenModules(procRoot, sysRoot string, cov *KernelCoverage, logger *slog.Logger) []report.Finding {
	kallsymsModules, symbolCount, err := readKallsymsModuleNames(procRoot)
	if err != nil {
		if !os.IsNotExist(err) {
			cov.GapsNote += " | kallsyms hidden-module check skipped: " + err.Error()
			logger.Debug("kallsyms unreadable", slog.String("error", err.Error()))
		}
		return nil
	}
	if len(kallsymsModules) == 0 || symbolCount == 0 {
		// Empty table: kptr_restrict hides symbols from this reader — no signal.
		cov.GapsNote += " | kallsyms hidden-module check degraded: empty symbol table (unprivileged reader or kptr_restrict)"
		return nil
	}

	procModules, err := readProcModules(procRoot)
	if err != nil {
		procModules = make(map[string]bool)
	}
	sysfsModules, err := readSysfsLiveModules(sysRoot)
	if err != nil {
		sysfsModules = make(map[string]string)
	}

	var findings []report.Finding
	for name := range kallsymsModules {
		if procModules[name] {
			continue
		}
		if _, live := sysfsModules[name]; live {
			continue
		}
		// The module owns loaded-code symbols yet is invisible to both module
		// lists — the direct kernel object manipulation signature.
		findings = append(findings, report.Finding{
			Module:     "kernel",
			Severity:   report.SeverityAlert,
			Confidence: report.ConfidenceHigh,
			Path:       fmt.Sprintf("/proc/kallsyms [%s]", name),
			RuleName:   "Kernel_Module_Hidden_Kallsyms",
			Reason: fmt.Sprintf(
				"Loaded code symbols owned by module %q are present in /proc/kallsyms but the module is absent from both /proc/modules and /sys/module — kernel object hiding (DKOM) signature",
				name),
		})
	}
	return findings
}

// kallsymsReadAll parses a kallsyms-like buffer and returns the module owner
// set (test helper).
func kallsymsReadAll(data []byte) map[string]bool {
	modules := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.LastIndex(line, " [")
		if idx == -1 {
			continue
		}
		name := strings.TrimSuffix(strings.TrimSpace(line[idx+2:]), "]")
		if name == "" || name == "builtin" {
			continue
		}
		modules[strings.ReplaceAll(name, "-", "_")] = true
	}
	return modules
}
