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

// CheckPAM inspects /etc/pam.d configuration and security module directories.
func CheckPAM(ctx context.Context, rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, iocEng ioc.Engine, cov *CheckCoverage) ([]report.Finding, error) {
	cov.Name = "pam"
	var findings []report.Finding

	pamD := "/etc/pam.d"
	hostPamD, _, _, err := safeopen.ResolveUnderRoot(rootFS, pamD)
	if err != nil {
		if os.IsNotExist(err) {
			cov.Missing++
		} else {
			cov.RecordUnreadable(pamD, err)
		}
	} else {
		entries, rErr := os.ReadDir(hostPamD)
		if rErr != nil {
			if os.IsNotExist(rErr) {
				cov.Missing++
			} else {
				cov.RecordUnreadable(pamD, rErr)
			}
		} else {
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				virtFile := filepath.Join(pamD, e.Name())
				inspectPAMConfigFile(virtFile, rootFS, cfg, pkgDB, cov, &findings)
			}
		}
	}

	// Check PAM module directories for unowned modules
	inspectPAMModuleDirs(rootFS, pkgDB, cov, &findings)

	return findings, nil
}

func inspectPAMConfigFile(virtPath, rootFS string, cfg *config.Config, pkgDB pkgdb.PackageDB, cov *CheckCoverage, findings *[]report.Finding) {
	cov.Inspected++
	data, isSymlink, err := SafeReadRegularFile(rootFS, virtPath, 256*1024)
	if err != nil {
		if os.IsNotExist(err) {
			cov.Missing++
		} else {
			cov.RecordUnreadable(virtPath, err)
		}
		return
	}

	var signals []*PersistenceSignal
	if isSymlink {
		if symSig := AssessSymlink(rootFS, virtPath, pkgDB, false, "", 0); symSig != nil {
			signals = append(signals, symSig)
		}
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@include") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		// PAM format: type control module-path [args...]
		modulePath := fields[2]
		args := fields[3:]

		// 1. pam_exec check
		if strings.Contains(modulePath, "pam_exec") {
			for _, arg := range args {
				cleanArg := filepath.Clean(arg)
				if strings.HasPrefix(cleanArg, "/") {
					// Check if script is outside standard system dirs
					isSys := strings.HasPrefix(cleanArg, "/bin/") ||
						strings.HasPrefix(cleanArg, "/sbin/") ||
						strings.HasPrefix(cleanArg, "/usr/bin/") ||
						strings.HasPrefix(cleanArg, "/usr/sbin/") ||
						strings.HasPrefix(cleanArg, "/lib/") ||
						strings.HasPrefix(cleanArg, "/usr/lib/")

					isTemp := strings.HasPrefix(cleanArg, "/tmp/") ||
						strings.HasPrefix(cleanArg, "/var/tmp/") ||
						strings.HasPrefix(cleanArg, "/dev/shm/") ||
						strings.Contains(cleanArg, "/.")

					if isTemp {
						signals = append(signals, &PersistenceSignal{
							Class:      ClassExecFromTemp,
							RuleName:   "Persistence_PAM_Exec_Temp_Script",
							Reason:     fmt.Sprintf("pam_exec executes script from volatile or hidden path: %s", cleanArg),
							Score:      85,
							Severity:   report.SeverityAlert,
							LineNumber: lineNum,
							Snippet:    RedactSnippet(line),
						})
					} else if !isSys {
						signals = append(signals, &PersistenceSignal{
							Class:      ClassPrivilegeAbuse,
							RuleName:   "Persistence_PAM_Exec_Non_System_Script",
							Reason:     fmt.Sprintf("pam_exec executes script outside standard system directories: %s", cleanArg),
							Score:      cfg.Scan.ScorePersistPAMExec,
							Severity:   report.SeverityWarning,
							LineNumber: lineNum,
							Snippet:    RedactSnippet(line),
						})
					}
				}
			}
		}

		// 2. Absolute .so outside standard security paths
		if strings.HasPrefix(modulePath, "/") && strings.HasSuffix(modulePath, ".so") {
			cleanMod := filepath.Clean(modulePath)
			isStdSecurity := strings.HasPrefix(cleanMod, "/lib/security") ||
				strings.HasPrefix(cleanMod, "/usr/lib/security") ||
				strings.Contains(cleanMod, "/security/")

			if !isStdSecurity {
				isOwned := false
				if pkgDB != nil && pkgDB.IsAvailable() {
					_, isOwned = pkgDB.Owner(cleanMod)
				}
				if !isOwned {
					signals = append(signals, &PersistenceSignal{
						Class:      ClassUnowned,
						RuleName:   "Persistence_PAM_Nonstandard_Module",
						Reason:     fmt.Sprintf("PAM references unowned module outside standard security directories: %s", cleanMod),
						Score:      cfg.Scan.ScorePersistPAMUnownedSO,
						Severity:   report.SeverityNotice,
						LineNumber: lineNum,
						Snippet:    cleanMod,
					})
				}
			}
		}
	}

	if len(signals) > 0 {
		meta := map[string]any{
			"artifact": "pam",
			"file":     virtPath,
		}
		if f := ConsolidateSignals(signals, virtPath, meta); f != nil {
			*findings = append(*findings, *f)
		}
	}
}

func inspectPAMModuleDirs(rootFS string, pkgDB pkgdb.PackageDB, cov *CheckCoverage, findings *[]report.Finding) {
	if pkgDB == nil || !pkgDB.IsAvailable() {
		return
	}

	dirs := []string{
		"/lib/security",
		"/lib/x86_64-linux-gnu/security",
		"/lib/aarch64-linux-gnu/security",
		"/usr/lib/security",
		"/usr/lib/x86_64-linux-gnu/security",
		"/usr/lib/aarch64-linux-gnu/security",
	}

	for _, d := range dirs {
		hostDir, _, _, err := safeopen.ResolveUnderRoot(rootFS, d)
		if err != nil {
			continue
		}

		entries, err := os.ReadDir(hostDir)
		if err != nil {
			continue
		}

		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".so") {
				continue
			}

			virtFile := filepath.Join(d, e.Name())
			cov.Inspected++

			if _, ok := pkgDB.Owner(virtFile); !ok {
				var signals []*PersistenceSignal
				signals = append(signals, &PersistenceSignal{
					Class:      ClassUnowned,
					RuleName:   "Persistence_PAM_Unowned_Module_Binary",
					Reason:     fmt.Sprintf("PAM module %s is not owned by any installed OS package", virtFile),
					Score:      25,
					Severity:   report.SeverityNotice,
					LineNumber: 0,
					Snippet:    virtFile,
				})

				meta := map[string]any{
					"artifact": "pam_module",
					"file":     virtFile,
				}
				if f := ConsolidateSignals(signals, virtFile, meta); f != nil {
					*findings = append(*findings, *f)
				}
			}
		}
	}
}
