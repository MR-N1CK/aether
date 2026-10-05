package persistence

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aether/internal/config"
	"aether/internal/ioc"
	"aether/internal/pkgdb"
	"aether/internal/report"
	"aether/internal/safeopen"
)

// CheckLoader inspects dynamic linker preload and configuration hooks.
func CheckLoader(ctx context.Context, rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, iocEng ioc.Engine, cov *CheckCoverage) ([]report.Finding, error) {
	cov.Name = "loader"
	var findings []report.Finding

	// 1. Inspect /etc/ld.so.preload
	inspectLDPreload(rootFS, cfg, pkgDB, cov, &findings)

	// 2. Inspect /etc/ld.so.conf and /etc/ld.so.conf.d/*
	inspectLDSoConf(rootFS, cfg, cov, &findings)

	// 3. Inspect LD_PRELOAD in /etc/environment
	inspectEnvironmentPreload(rootFS, cfg, cov, &findings)

	return findings, nil
}

func inspectLDPreload(rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, cov *CheckCoverage, findings *[]report.Finding) {
	virtPath := "/etc/ld.so.preload"
	cov.Inspected++

	data, isSymlink, err := SafeReadRegularFile(rootFS, virtPath, 64*1024)
	if err != nil {
		if os.IsNotExist(err) {
			cov.Missing++
		} else {
			cov.RecordUnreadable(virtPath, err)
		}
		return
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		return
	}

	var signals []*PersistenceSignal

	if isSymlink {
		signals = append(signals, &PersistenceSignal{
			Class:      ClassSymlinkHijack,
			RuleName:   "Persistence_Loader_Symlink_Preload",
			Reason:     "/etc/ld.so.preload is a symlink",
			Score:      55,
			Severity:   report.SeverityWarning,
			LineNumber: 0,
		})
	}

	// Any non-empty /etc/ld.so.preload is at least WARNING
	signals = append(signals, &PersistenceSignal{
		Class:      ClassObfuscation,
		RuleName:   "Persistence_Loader_Preload_Active",
		Reason:     "/etc/ld.so.preload specifies dynamic linker preloads for all executing binaries",
		Score:      cfg.Scan.ScorePersistLoaderPreload,
		Severity:   report.SeverityWarning,
		LineNumber: 0,
		Snippet:    RedactSnippet(content),
	})

	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split on spaces or tabs (ld.so.preload supports space-separated libraries)
		libs := strings.Fields(line)
		for _, lib := range libs {
			cleanLib := filepath.Clean(lib)
			hostLib, _, _, err := safeopen.ResolveUnderRoot(rootFS, cleanLib)

			// Check temp or hidden path -> ALERT
			if strings.HasPrefix(cleanLib, "/tmp/") || strings.HasPrefix(cleanLib, "/var/tmp/") || strings.HasPrefix(cleanLib, "/dev/shm/") || strings.Contains(cleanLib, "/.") {
				signals = append(signals, &PersistenceSignal{
					Class:      ClassExecFromTemp,
					RuleName:   "Persistence_Loader_Preload_Temp_Library",
					Reason:     fmt.Sprintf("Preloaded library is located in volatile or hidden directory: %s", cleanLib),
					Score:      cfg.Scan.ScorePersistLoaderPreloadSusp,
					Severity:   report.SeverityAlert,
					LineNumber: lineNum,
					Snippet:    cleanLib,
				})
			}

			// Check if library file exists (missing library = WARNING, not ALERT alone)
			if err != nil || hostLib == "" {
				signals = append(signals, &PersistenceSignal{
					Class:      ClassMissingTarget,
					RuleName:   "Persistence_Loader_Preload_Missing_Library",
					Reason:     fmt.Sprintf("Preloaded library does not exist on disk: %s", cleanLib),
					Score:      55,
					Severity:   report.SeverityWarning,
					LineNumber: lineNum,
					Snippet:    cleanLib,
				})
			} else if _, sErr := os.Stat(hostLib); os.IsNotExist(sErr) {
				signals = append(signals, &PersistenceSignal{
					Class:      ClassMissingTarget,
					RuleName:   "Persistence_Loader_Preload_Missing_Library",
					Reason:     fmt.Sprintf("Preloaded library does not exist on disk: %s", cleanLib),
					Score:      55,
					Severity:   report.SeverityWarning,
					LineNumber: lineNum,
					Snippet:    cleanLib,
				})
			}

			// Check if package owned (unowned library = WARNING, not ALERT alone)
			if pkgDB != nil && pkgDB.IsAvailable() {
				if _, ok := pkgDB.Owner(cleanLib); !ok {
					signals = append(signals, &PersistenceSignal{
						Class:      ClassUnowned,
						RuleName:   "Persistence_Loader_Preload_Unowned_Library",
						Reason:     fmt.Sprintf("Preloaded library is not owned by any OS package: %s", cleanLib),
						Score:      40,
						Severity:   report.SeverityWarning,
						LineNumber: lineNum,
						Snippet:    cleanLib,
					})
				}
			}
		}
	}

	if len(signals) > 0 {
		meta := map[string]any{
			"artifact": "ld.so.preload",
			"file":     virtPath,
		}
		if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
			*findings = append(*findings, *f)
		}
	}
}

func inspectLDSoConf(rootFS string, cfg *config.Config, cov *CheckCoverage, findings *[]report.Finding) {
	files := []string{"/etc/ld.so.conf"}

	dDir := "/etc/ld.so.conf.d"
	if hostDDir, _, _, err := safeopen.ResolveUnderRoot(rootFS, dDir); err == nil {
		if entries, err := os.ReadDir(hostDDir); err == nil {
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".conf") && !e.IsDir() {
					files = append(files, filepath.Join(dDir, e.Name()))
				}
			}
		}
	}

	for _, virtFile := range files {
		cov.Inspected++
		data, _, err := SafeReadRegularFile(rootFS, virtFile, 256*1024)
		if err != nil {
			if os.IsNotExist(err) {
				cov.Missing++
			} else {
				cov.RecordUnreadable(virtFile, err)
			}
			continue
		}

		var signals []*PersistenceSignal
		scanner := bufio.NewScanner(bytes.NewReader(data))
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "include ") {
				continue
			}

			// Check directory path
			dirPath := filepath.Clean(line)
			hostPath := dirPath
			if rootFS != "" {
				hostPath = filepath.Join(rootFS, strings.TrimPrefix(dirPath, "/"))
			}

			if strings.HasPrefix(dirPath, "/tmp") || strings.HasPrefix(dirPath, "/var/tmp") || strings.HasPrefix(dirPath, "/dev/shm") || strings.HasPrefix(dirPath, "/home") {
				signals = append(signals, &PersistenceSignal{
					Class:      ClassPrivilegeAbuse,
					RuleName:   "Persistence_Loader_Insecure_Library_Directory",
					Reason:     fmt.Sprintf("Dynamic linker configuration includes user-accessible library directory: %s", dirPath),
					Score:      65,
					Severity:   report.SeverityWarning,
					LineNumber: lineNum,
					Snippet:    dirPath,
				})
			} else if st, sErr := os.Stat(hostPath); sErr == nil {
				if st.Mode()&0002 != 0 { // world-writable
					signals = append(signals, &PersistenceSignal{
						Class:      ClassPrivilegeAbuse,
						RuleName:   "Persistence_Loader_World_Writable_Directory",
						Reason:     fmt.Sprintf("Dynamic linker includes world-writable search directory: %s", dirPath),
						Score:      75,
						Severity:   report.SeverityWarning,
						LineNumber: lineNum,
						Snippet:    dirPath,
					})
				}
			}
		}

		if len(signals) > 0 {
			meta := map[string]any{
				"artifact": "ld.so.conf",
				"file":     virtFile,
			}
			if f := ConsolidateSignals(signals, virtFile, meta); f != nil {
				*findings = append(*findings, *f)
			}
		}
	}
}

func inspectEnvironmentPreload(rootFS string, cfg *config.Config, cov *CheckCoverage, findings *[]report.Finding) {
	virtPath := "/etc/environment"
	data, _, err := SafeReadRegularFile(rootFS, virtPath, 64*1024)
	if err != nil {
		return
	}

	cov.Inspected++
	var signals []*PersistenceSignal

	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "LD_PRELOAD=") {
			val := strings.TrimPrefix(line, "LD_PRELOAD=")
			val = strings.Trim(val, `"'`)
			isTemp := strings.Contains(val, "/tmp") || strings.Contains(val, "/var/tmp") || strings.Contains(val, "/dev/shm")

			if isTemp {
				signals = append(signals, &PersistenceSignal{
					Class:      ClassExecFromTemp,
					RuleName:   "Persistence_Loader_Environment_Preload_Temp",
					Reason:     fmt.Sprintf("/etc/environment sets LD_PRELOAD in volatile location: %s", val),
					Score:      85,
					Severity:   report.SeverityAlert,
					LineNumber: lineNum,
					Snippet:    RedactSnippet(line),
				})
			} else {
				signals = append(signals, &PersistenceSignal{
					Class:      ClassObfuscation,
					RuleName:   "Persistence_Loader_Environment_Preload",
					Reason:     fmt.Sprintf("/etc/environment configures global LD_PRELOAD: %s", val),
					Score:      cfg.Scan.ScorePersistLoaderPreload,
					Severity:   report.SeverityWarning,
					LineNumber: lineNum,
					Snippet:    RedactSnippet(line),
				})
			}
		}
	}

	if len(signals) > 0 {
		meta := map[string]any{
			"artifact": "environment",
			"file":     virtPath,
		}
		if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
			*findings = append(*findings, *f)
		}
	}
}
