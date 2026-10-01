package kernel

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aether/internal/pkgdb"
	"aether/internal/report"
)

// readProcModules parses /proc/modules and returns a set of active module names.
func readProcModules(procRoot string) (map[string]bool, error) {
	procModulesPath := "/proc/modules"
	if procRoot != "" {
		procModulesPath = filepath.Join(procRoot, "modules")
	}

	data, err := os.ReadFile(procModulesPath)
	if err != nil {
		return nil, err
	}

	modules := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			name := strings.ReplaceAll(fields[0], "-", "_")
			modules[name] = true
		}
	}

	return modules, scanner.Err()
}

// readSysfsLiveModules scans /sys/module for loadable modules with initstate == "live".
// Ignores "coming" or "going" modules to prevent transient load/unload race conditions.
func readSysfsLiveModules(sysRoot string) (map[string]string, error) {
	baseSys := "/sys/module"
	if sysRoot != "" {
		baseSys = sysRoot
	}

	entries, err := os.ReadDir(baseSys)
	if err != nil {
		return nil, err
	}

	liveModules := make(map[string]string)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		rawName := entry.Name()
		normName := strings.ReplaceAll(rawName, "-", "_")

		initStatePath := filepath.Join(baseSys, rawName, "initstate")
		data, err := os.ReadFile(initStatePath)
		if err != nil {
			// Built-in module (no initstate file in sysfs)
			continue
		}

		state := strings.TrimSpace(string(data))
		// Ignore "coming" or "going" modules
		if state == "live" {
			liveModules[normName] = rawName
		}
	}

	return liveModules, nil
}

// collectDiscrepancies returns the set of modules in sysfs with initstate=live but missing from /proc/modules.
func collectDiscrepancies(procRoot, sysRoot string) (map[string]string, int64, int64, error) {
	procMods, pErr := readProcModules(procRoot)
	if pErr != nil {
		return nil, 0, 0, pErr
	}

	sysLiveMods, sErr := readSysfsLiveModules(sysRoot)
	if sErr != nil {
		return nil, 0, 0, sErr
	}

	discrepancies := make(map[string]string)
	for normName, rawName := range sysLiveMods {
		if !procMods[normName] {
			discrepancies[normName] = rawName
		}
	}

	return discrepancies, int64(len(procMods)), int64(len(sysLiveMods)), nil
}

// loadModulesDep reads modules.dep if present under /lib/modules or /usr/lib/modules.
func loadModulesDep(rootFS string) map[string]bool {
	depMap := make(map[string]bool)

	var depPaths []string
	if rootFS != "" {
		matches, _ := filepath.Glob(filepath.Join(rootFS, "lib/modules/*/modules.dep"))
		depPaths = append(depPaths, matches...)
		matches2, _ := filepath.Glob(filepath.Join(rootFS, "usr/lib/modules/*/modules.dep"))
		depPaths = append(depPaths, matches2...)
	} else {
		matches, _ := filepath.Glob("/lib/modules/*/modules.dep")
		depPaths = append(depPaths, matches...)
		matches2, _ := filepath.Glob("/usr/lib/modules/*/modules.dep")
		depPaths = append(depPaths, matches2...)
	}

	for _, dp := range depPaths {
		data, err := os.ReadFile(dp)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			modFile := filepath.Base(strings.TrimSpace(parts[0]))
			modName := strings.TrimSuffix(modFile, ".ko")
			modName = strings.TrimSuffix(modName, ".ko.xz")
			modName = strings.TrimSuffix(modName, ".ko.zst")
			modName = strings.TrimSuffix(modName, ".ko.gz")
			depMap[strings.ReplaceAll(modName, "-", "_")] = true
		}
	}

	return depMap
}

// CheckHiddenModules performs a two-pass comparison between /proc/modules and /sys/module/*/initstate.
// Only modules discrepant across BOTH passes are flagged as hidden LKM rootkits.
func CheckHiddenModules(
	ctx context.Context,
	procRoot, sysRoot, rootFS string,
	testDelay time.Duration,
	pkgDB pkgdb.PackageDB,
	cov *KernelCoverage,
	logger *slog.Logger,
) []report.Finding {
	var findings []report.Finding

	// Pass 1
	pass1Discrepancies, procCount, sysCount, err := collectDiscrepancies(procRoot, sysRoot)
	if err != nil {
		return findings
	}

	cov.LoadedModulesInspected = procCount
	cov.SysfsLoadableEntries = sysCount

	if len(pass1Discrepancies) == 0 {
		return findings
	}

	// Sleep for ~200ms (or testDelay) before Pass 2
	select {
	case <-ctx.Done():
		return findings
	case <-time.After(testDelay):
	}

	// Pass 2
	pass2Discrepancies, _, _, err := collectDiscrepancies(procRoot, sysRoot)
	if err != nil {
		return findings
	}

	// Only flag modules present in BOTH passes
	for normName, rawName := range pass1Discrepancies {
		if _, presentInPass2 := pass2Discrepancies[normName]; presentInPass2 {
			sysPath := fmt.Sprintf("/sys/module/%s", rawName)
			reason := fmt.Sprintf("Kernel module %q is active in sysfs (%s/initstate=live) but hidden from /proc/modules (LKM rootkit indicator)", rawName, sysPath)

			findings = append(findings, report.Finding{
				Timestamp: time.Now(),
				Module:    "kernel",
				Severity:  report.SeverityWarning,
				Path:      sysPath,
				Reason:    reason,
				RuleName:  "Kernel_Hidden_LKM_Module",
				Count:     1,
				Paths:     []string{sysPath},
				Metadata: map[string]interface{}{
					"module_name": rawName,
					"sysfs_path":  sysPath,
					"is_strong":   true,
					"score":       85,
				},
			})
		}
	}

	return findings
}
