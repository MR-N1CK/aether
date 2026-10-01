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

	"aether/internal/config"
	"aether/internal/modules/persistence"
	"aether/internal/report"
	"aether/internal/safeopen"
)

// CheckModprobe inspects modprobe and module loading configurations for suspicious install hooks.
func CheckModprobe(ctx context.Context, rootFS string, cfg *config.Config, cov *KernelCoverage, logger *slog.Logger) []report.Finding {
	var findings []report.Finding

	var targetFiles []string

	// 1. /etc/modules
	etcModules := "/etc/modules"
	if rootFS != "" {
		etcModules = filepath.Join(rootFS, "etc/modules")
	}
	if fi, err := os.Stat(etcModules); err == nil && fi.Mode().IsRegular() {
		targetFiles = append(targetFiles, "/etc/modules")
	}

	// 2. /etc/modules-load.d/*.conf
	modulesLoadDir := "/etc/modules-load.d"
	if rootFS != "" {
		modulesLoadDir = filepath.Join(rootFS, "etc/modules-load.d")
	}
	if entries, err := os.ReadDir(modulesLoadDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				targetFiles = append(targetFiles, filepath.Join("/etc/modules-load.d", e.Name()))
			}
		}
	}

	// 3. /etc/modprobe.d/*.conf
	modprobeDir := "/etc/modprobe.d"
	if rootFS != "" {
		modprobeDir = filepath.Join(rootFS, "etc/modprobe.d")
	}
	if entries, err := os.ReadDir(modprobeDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				targetFiles = append(targetFiles, filepath.Join("/etc/modprobe.d", e.Name()))
			}
		}
	}

	cov.ModprobeFilesInspected = int64(len(targetFiles))

	for _, virtPath := range targetFiles {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		hostPath := virtPath
		if rootFS != "" {
			hostPath = filepath.Join(rootFS, strings.TrimPrefix(virtPath, "/"))
		}

		data, err := safeopen.ReadFileReadOnly(hostPath, 1024*1024)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(bytes.NewReader(data))
		lineNum := 0

		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Look for "install <module> <command>" or "softdep <module> ...: <command>"
			if strings.HasPrefix(line, "install ") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					moduleName := parts[1]
					cmd := strings.Join(parts[2:], " ")

					// Standard benign modprobe directives:
					// e.g. "install x /bin/true", "install x /bin/false", "install sound-slot-0 /sbin/modprobe snd-card-0"
					if cmd == "/bin/true" || cmd == "/bin/false" || cmd == "/usr/bin/true" || cmd == "/usr/bin/false" || cmd == ":" {
						continue
					}

					// Evaluate command using persistence heuristics
					signals := persistence.CheckSuspiciousCommand(cmd, lineNum, cfg, rootFS, true, nil)
					for _, sig := range signals {
						if sig.Severity == report.SeverityAlert || sig.Severity == report.SeverityWarning {
							findings = append(findings, report.Finding{
								Timestamp: time.Now(),
								Module:    "kernel",
								Severity:  sig.Severity,
								Path:      virtPath,
								Reason:    fmt.Sprintf("Modprobe install hook for module %q runs suspicious command (line %d: %s): %s", moduleName, lineNum, persistence.RedactSnippet(cmd), sig.Reason),
								RuleName:  "Kernel_Modprobe_Install_Command",
								Count:     1,
								Paths:     []string{virtPath},
								Metadata: map[string]interface{}{
									"module":      moduleName,
									"command":     persistence.RedactSnippet(cmd),
									"line_number": lineNum,
									"is_strong":   true,
									"score":       75,
								},
							})
						}
					}
				}
			}
		}
	}

	return findings
}
