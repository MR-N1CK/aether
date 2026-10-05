package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/modules/persistence"
	"aether/internal/realworld"
	"aether/internal/report"
	htmlreport "aether/internal/report/html"
	"aether/internal/scanner"
	"aether/internal/setup"
	"aether/internal/triage"
	"aether/internal/ui/plain"
	"aether/internal/ui/theme"
	"aether/internal/ui/tui"
	appversion "aether/internal/version"
	"aether/internal/yara"
)

var (
	version   = "1.0.0"
	commit    = "none"
	buildDate = "unknown"
	devRpath  = "0"
)

type globalFlags struct {
	configPath string
	verbose    bool
	debug      bool
	quiet      bool
	plain      bool
	noAnim     bool
}

type scanCmdFlags struct {
	paths             []string
	root              string
	excludes          []string
	quick             bool
	full              bool
	maxFileSize     int64
	jsonOut           string
	htmlOut           string
	noReport          bool
	redactHosts       bool
	maxReportFindings int
	threads           int
	nice            int
	iocDir          string
	allowlist       string
	oneFileSystem   bool
	rulesDir                   string
	trustRulesDir              bool
	trustInstalledPentestTools bool
	yaraMaxFileSize            int64
	demoRules                  bool
	modules         []string
	fileTimeout     time.Duration
	hashOversizeMax int64
}

func isTerminal() bool {
	return isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
}

func attachScanFlags(cmd *cobra.Command, sFlags *scanCmdFlags) {
	cmd.Flags().StringSliceVarP(&sFlags.paths, "path", "p", nil, "Target path(s) to scan (repeatable)")
	cmd.Flags().StringVar(&sFlags.root, "root", "/", "Root directory to scan (resolves paths relative to this root for offline forensic scan)")
	cmd.Flags().BoolVar(&sFlags.quick, "quick", false, "Perform quick triage scan of high-risk locations")
	cmd.Flags().BoolVar(&sFlags.full, "full", false, "Perform full deep filesystem scan")
	cmd.Flags().StringSliceVarP(&sFlags.excludes, "exclude", "e", nil, "Target path(s) to exclude from scan (repeatable)")
	cmd.Flags().Int64Var(&sFlags.maxFileSize, "max-filesize", config.DefaultMaxFileSize, "Maximum file size in bytes to inspect/hash (default: 50MB); files larger than this are skipped completely")
	cmd.Flags().StringVar(&sFlags.jsonOut, "json-out", "", "Output report destination path for JSON format")
	cmd.Flags().StringVar(&sFlags.htmlOut, "html-out", "", "Output report destination path for self-contained HTML format")
	cmd.Flags().BoolVar(&sFlags.noReport, "no-report", false, "Disable automatic HTML report generation")
	cmd.Flags().BoolVar(&sFlags.redactHosts, "redact-hosts", false, "Redact hostnames, IPs, usernames, and user home paths in output")
	cmd.Flags().IntVar(&sFlags.maxReportFindings, "max-report-findings", config.DefaultMaxReportFindings, "Maximum number of findings to display in HTML report table (default: 5000)")
	cmd.Flags().IntVarP(&sFlags.threads, "threads", "t", runtime.NumCPU(), "Worker pool concurrency")
	cmd.Flags().IntVar(&sFlags.nice, "nice", config.DefaultNice, "CPU scheduling priority (-20 to 19, higher = lower priority)")
	cmd.Flags().StringVar(&sFlags.iocDir, "ioc-dir", "", "Custom directory containing IOC signature files (.txt, .yaml)")
	cmd.Flags().StringVar(&sFlags.allowlist, "allowlist", "", "Path to trusted SHA256 allowlist file")
	cmd.Flags().BoolVar(&sFlags.oneFileSystem, "one-file-system", false, "Do not cross filesystem mount boundaries (default on for --full)")
	cmd.Flags().StringVar(&sFlags.rulesDir, "rules-dir", "", "Custom directory containing YARA rules (*.yar, *.yara)")
	cmd.Flags().BoolVar(&sFlags.trustRulesDir, "trust-rules-dir", false, "Explicitly trust rules directory without ownership/permission checks (development/testing only)")
	cmd.Flags().BoolVar(&sFlags.trustInstalledPentestTools, "trust-installed-pentest-tools", true, "Downgrade YARA findings in well-known pentest tool directories to INFO (for pentest workstations/VMs; disable on suspect end-user systems)")
	cmd.Flags().Int64Var(&sFlags.yaraMaxFileSize, "yara-max-filesize", config.DefaultYaraMaxFileSize, "Maximum file size in bytes for in-memory YARA scanning (default: 20MB); files above this are stream-hashed but skip YARA")
	cmd.Flags().BoolVar(&sFlags.demoRules, "demo-rules", false, "Load synthetic demonstration YARA rules (harmless EICAR/marker patterns)")
	cmd.Flags().StringSliceVar(&sFlags.modules, "modules", nil, "Comma-separated list of modules to run (filesystem, process, persistence, users, network, kernel)")
	cmd.Flags().DurationVar(&sFlags.fileTimeout, "file-timeout", config.DefaultFileTimeout, "Timeout for inspecting/hashing a single file before abandoning worker (default: 30s)")
	cmd.Flags().Int64Var(&sFlags.hashOversizeMax, "hash-oversize-max", config.DefaultHashOversizeMax, "Maximum file size in bytes to hash without signature scanning (default: 2GB)")
}

func executeScan(cmd *cobra.Command, args []string, gFlags *globalFlags, sFlags *scanCmdFlags, defaultMode string) error {
	// 1. Determine execution mode (TUI vs Plain)
	usePlain := gFlags.plain || !isTerminal()

	// 2. Setup logging: unless --debug is explicitly set, suppress raw slog output
	var logger *slog.Logger
	if gFlags.debug {
		logger = report.SetupLogger("debug", false)
	} else {
		logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
		slog.SetDefault(logger)
	}

	// 3. Load configuration hierarchy
	cfg, loadedPath, err := config.LoadConfig(gFlags.configPath)
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}
	if loadedPath != "" {
		logger.Debug("loaded configuration file", slog.String("path", loadedPath))
	}

	// 4. Positional arguments support: args -> paths
	if len(args) > 0 {
		for _, arg := range args {
			cleanArg := filepath.Clean(arg)
			sFlags.paths = append(sFlags.paths, cleanArg)
		}
		cfg.Scan.Paths = sFlags.paths
		cfg.Scan.ExplicitPaths = true
	} else if cmd.Flags().Changed("path") {
		cfg.Scan.Paths = sFlags.paths
		cfg.Scan.ExplicitPaths = true
	}

	if cmd.Flags().Changed("root") {
		cfg.Scan.Root = filepath.Clean(sFlags.root)
	}
	if cmd.Flags().Changed("exclude") {
		cfg.Scan.Excludes = sFlags.excludes
	}

	// Apply mode overrides
	if defaultMode == "quick" || sFlags.quick {
		cfg.Scan.Quick = true
		cfg.Scan.Full = false
	} else if defaultMode == "full" || sFlags.full {
		cfg.Scan.Full = true
		cfg.Scan.Quick = false
	}

	if cmd.Flags().Changed("max-filesize") {
		cfg.Scan.MaxFileSize = sFlags.maxFileSize
	}
	if cmd.Flags().Changed("threads") {
		cfg.Scan.Threads = sFlags.threads
	}
	if cmd.Flags().Changed("nice") {
		cfg.Scan.Nice = sFlags.nice
	}
	if cmd.Flags().Changed("json-out") {
		cfg.Scan.JSONOut = sFlags.jsonOut
	}

	// Auto-HTML report: default to ./aether-report.html if not disabled
	if cmd.Flags().Changed("html-out") {
		cfg.Scan.HTMLOut = sFlags.htmlOut
	} else if !sFlags.noReport && cfg.Scan.HTMLOut == "" {
		cfg.Scan.HTMLOut = "aether-report.html"
	}

	if cmd.Flags().Changed("redact-hosts") {
		cfg.Scan.RedactHosts = sFlags.redactHosts
	}
	if cmd.Flags().Changed("max-report-findings") {
		cfg.Scan.MaxReportFindings = sFlags.maxReportFindings
	}
	if cmd.Flags().Changed("ioc-dir") {
		cfg.Scan.IOCDir = sFlags.iocDir
	}
	if cmd.Flags().Changed("allowlist") {
		cfg.Scan.AllowlistPath = sFlags.allowlist
	}
	if cmd.Flags().Changed("one-file-system") {
		cfg.Scan.OneFileSystem = sFlags.oneFileSystem
	}
	if cmd.Flags().Changed("rules-dir") {
		cfg.Scan.RulesDir = sFlags.rulesDir
	}
	if cmd.Flags().Changed("trust-rules-dir") {
		cfg.Scan.TrustRulesDir = sFlags.trustRulesDir
	}
	if cmd.Flags().Changed("trust-installed-pentest-tools") {
		cfg.Scan.TrustInstalledPentestTools = sFlags.trustInstalledPentestTools
	}
	if cmd.Flags().Changed("yara-max-filesize") {
		cfg.Scan.YaraMaxFileSize = sFlags.yaraMaxFileSize
	}
	if cmd.Flags().Changed("demo-rules") {
		cfg.Scan.DemoRules = sFlags.demoRules
	}
	if cmd.Flags().Changed("modules") {
		if err := config.ValidateModules(sFlags.modules); err != nil {
			return err
		}
		cfg.Scan.Modules = sFlags.modules
	}
	if cmd.Flags().Changed("file-timeout") {
		cfg.Scan.FileTimeout = sFlags.fileTimeout
	}
	if cmd.Flags().Changed("hash-oversize-max") {
		cfg.Scan.HashOversizeMax = sFlags.hashOversizeMax
	}

	// 5. Apply niceness early at startup before worker pool starts
	if cfg.Scan.Nice != 0 {
		if err := scanner.ApplyNice(cfg.Scan.Nice); err != nil {
			logger.Warn("could not apply nice priority", slog.Any("error", err))
		}
	}

	// 6. Initialize event bus and reporter subscriber
	bus := events.NewEventBus()
	defer bus.Close()

	reporter, err := report.NewConcurrentReporter(cfg.Scan.JSONOut)
	if err != nil {
		return fmt.Errorf("failed to initialize reporter: %w", err)
	}
	defer reporter.Close()

	// 7. Setup graceful cancellation context
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	exe, _ := os.Executable()
	binName := filepath.Base(exe)
	s := scanner.NewScanner(cfg, bus, reporter, logger,
		scanner.WithDevRpath(devRpath == "1"),
		scanner.WithBuildInfo(version, commit, buildDate, binName),
		scanner.WithExecutiveAssessment(func(findings []report.Finding, sf events.ScanFinished) (string, string, []htmlreport.RemediationAction, map[string]string) {
			synth := realworld.NewAssessmentSynthesizer()
			ass := synth.SynthesizeFromScan(findings, sf)
			var plan []htmlreport.RemediationAction
			for _, act := range ass.NextActions {
				plan = append(plan, htmlreport.RemediationAction{
					Priority:    act.Priority,
					Title:       act.Title,
					Description: act.Description,
					Command:     act.Command,
				})
			}
			bd := realworld.FromScanFinished(sf, 0)
			timing := map[string]string{
				"filesystem_walk": bd.FilesystemWalk.Round(time.Millisecond).String(),
				"hashing":         bd.Hashing.Round(time.Millisecond).String(),
				"heuristics":      bd.Heuristics.Round(time.Millisecond).String(),
				"yara":            bd.YARA.Round(time.Millisecond).String(),
				"process":         bd.Process.Round(time.Millisecond).String(),
				"network":         bd.Network.Round(time.Millisecond).String(),
				"correlation":     bd.Correlation.Round(time.Millisecond).String(),
				"total_duration":  bd.Total.Round(time.Millisecond).String(),
			}
			return string(ass.Posture), ass.SummaryRationale, plan, timing
		}),
	)

	mode := "custom"
	if cfg.Scan.Quick {
		mode = "quick"
	} else if cfg.Scan.Full {
		mode = "full"
	}

	th := theme.NewTheme(theme.DetectNoColor())

	if usePlain {
		var outWriter io.Writer = os.Stdout
		if sFlags.jsonOut == "-" {
			outWriter = os.Stderr
		}
		consumer := plain.NewConsumer(outWriter, th, gFlags.verbose)
		plainSub := bus.Subscribe()
		defer plainSub.Close()

		scanErrChan := make(chan error, 1)
		go func() {
			scanErrChan <- s.Run(ctx)
		}()

		_ = consumer.Consume(ctx, plainSub)
		scanErr := <-scanErrChan
		if cfg.Scan.HTMLOut != "" {
			greenStyle := lipgloss.NewStyle().Foreground(theme.ColorNotice).Bold(true)
			boldStyle := lipgloss.NewStyle().Bold(true)
			if th.NoColor {
				greenStyle = lipgloss.NewStyle().Bold(true)
				boldStyle = lipgloss.NewStyle().Bold(true)
			}
			fmt.Fprintf(outWriter, "\n  %s %s: %s\n\n", greenStyle.Render("✓"), boldStyle.Render("Executive HTML Report"), cfg.Scan.HTMLOut)
		}
		return scanErr
	}

	// Interactive TUI execution
	uiSub := bus.Subscribe()
	defer uiSub.Close()

	scanCtx, scanCancel := context.WithCancel(ctx)
	defer scanCancel()

	go func() {
		_ = s.Run(scanCtx)
	}()

	tuiErr := tui.Run(ctx, scanCancel, uiSub, th, gFlags.noAnim, mode, cfg.Scan.Threads, cfg.Scan.Paths)
	if cfg.Scan.HTMLOut != "" {
		greenStyle := lipgloss.NewStyle().Foreground(theme.ColorNotice).Bold(true)
		boldStyle := lipgloss.NewStyle().Bold(true)
		if th.NoColor {
			greenStyle = lipgloss.NewStyle().Bold(true)
			boldStyle = lipgloss.NewStyle().Bold(true)
		}
		fmt.Printf("\n  %s %s: %s\n\n", greenStyle.Render("✓"), boldStyle.Render("Executive HTML Report"), cfg.Scan.HTMLOut)
	}
	return tuiErr
}

func runInteractiveLauncher(cmd *cobra.Command, gFlags *globalFlags, sFlags *scanCmdFlags) error {
	th := theme.NewTheme(theme.DetectNoColor())

	res, err := tui.RunInteractiveLauncher(th)
	if err != nil {
		return err
	}

	switch res.Action {
	case tui.ActionQuick:
		sFlags.quick = true
		return executeScan(cmd, nil, gFlags, sFlags, "quick")
	case tui.ActionFull:
		sFlags.full = true
		return executeScan(cmd, nil, gFlags, sFlags, "full")
	case tui.ActionCustom:
		path := strings.TrimSpace(res.Path)
		if path == "" {
			path = "."
		}
		if path == "~" {
			if home, err := os.UserHomeDir(); err == nil {
				path = home
			}
		} else if strings.HasPrefix(path, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				path = filepath.Join(home, path[2:])
			}
		}
		return executeScan(cmd, []string{path}, gFlags, sFlags, "custom")
	case tui.ActionSetup:
		_, sErr := setup.RunSetup(setup.SetupOptions{
			DownloadRules: true,
			InstallBinary: true,
		}, th)
		return sErr
	case tui.ActionOpenReport:
		reportPath := "aether-report.html"
		if _, statErr := os.Stat(reportPath); statErr == nil {
			absPath, _ := filepath.Abs(reportPath)
			fmt.Printf("\n  %s %s: %s\n",
				lipgloss.NewStyle().Foreground(theme.ColorNotice).Bold(true).Render("✓"),
				lipgloss.NewStyle().Bold(true).Render("Executive HTML Report Available"),
				absPath)
			_ = exec.Command("xdg-open", absPath).Start()
		} else {
			fmt.Println("\n  No previous HTML report found in current directory. Run a scan first to generate a report.")
		}
		return nil
	case tui.ActionDemo:
		demoCmd := cmd.Root()
		for _, c := range demoCmd.Commands() {
			if c.Name() == "demo" {
				return c.RunE(c, nil)
			}
		}
		return nil
	case tui.ActionStatus:
		return printEngineDiagnostics(th)
	case tui.ActionExit:
		return nil
	default:
		return nil
	}
}

func printEngineDiagnostics(th *theme.Theme) error {
	titleStyle := lipgloss.NewStyle().Foreground(theme.ColorTextPrim).Bold(true)
	azureStyle := lipgloss.NewStyle().Foreground(theme.ColorAccent).Bold(true)
	subStyle := lipgloss.NewStyle().Foreground(theme.ColorTextMute)

	if th.NoColor {
		titleStyle = lipgloss.NewStyle().Bold(true)
		azureStyle = lipgloss.NewStyle().Bold(true)
		subStyle = lipgloss.NewStyle()
	}

	fmt.Printf("\n%s\n", azureStyle.Render("╭─────────────────────────────────────────────────────────────╮"))
	fmt.Printf("%s\n", azureStyle.Render("│  A E T H E R  ::  Engine Status & Security Diagnostics      │"))
	fmt.Printf("%s\n\n", azureStyle.Render("╰─────────────────────────────────────────────────────────────╯"))

	fmt.Printf("  %s %s\n", titleStyle.Render("Aether Version:"), version)
	fmt.Printf("  %s %s\n", subStyle.Render("Build Commit:  "), commit)
	fmt.Printf("  %s %s\n", subStyle.Render("Build Date:    "), buildDate)
	fmt.Printf("  %s %s/%s (%d CPU cores)\n", subStyle.Render("Runtime Host:  "), runtime.GOOS, runtime.GOARCH, runtime.NumCPU())

	if os.Geteuid() == 0 {
		fmt.Printf("  %s %s\n", titleStyle.Render("Privileges:    "), lipgloss.NewStyle().Foreground(theme.ColorNotice).Bold(true).Render("ROOT (Full live kernel/memory inspection enabled)"))
	} else {
		fmt.Printf("  %s %s\n", titleStyle.Render("Privileges:    "), lipgloss.NewStyle().Foreground(theme.ColorWarning).Render("NON-ROOT (Unprivileged mode - some kernel metrics restricted)"))
	}

	yInfo := yara.VersionInfo()
	if yInfo != "not compiled in" {
		fmt.Printf("  %s %s\n", titleStyle.Render("YARA Engine:   "), lipgloss.NewStyle().Foreground(theme.ColorNotice).Bold(true).Render(yInfo+" (Active with Embedded Core Rules)"))
	} else {
		fmt.Printf("  %s %s\n", titleStyle.Render("YARA Engine:   "), lipgloss.NewStyle().Foreground(theme.ColorWarning).Render("Pure-Go Heuristics (YARA not compiled in)"))
	}

	fmt.Printf("\n  %s\n", titleStyle.Render("Active Security Modules:"))
	modules := []string{
		"filesystem  (single-pass header inspection, IOC hashes, script heuristics)",
		"persistence (systemd services, cron jobs, shell profiles, ld.so.preload, ssh)",
		"process     (procfs inspections, hidden PIDs, deleted binary memory execution)",
		"kernel      (loaded module verification, kernel taint flags)",
		"network     (suspicious raw socket listeners, proc_net telemetry)",
		"users       (rogue UID 0 accounts, shadow integrity, PAM backdoors)",
		"yara        (multi-pattern signature matching against malware families)",
	}
	for _, m := range modules {
		fmt.Printf("    • %s\n", subStyle.Render(m))
	}
	fmt.Println()
	return nil
}

func main() {
	var gFlags globalFlags
	var sFlags scanCmdFlags

	rootCmd := &cobra.Command{
		Use:   "aether [command|path]",
		Short: "Aether - Defensive Linux threat-hunting scanner",
		Long: `Aether is a Linux-native defensive compromise detection and threat-hunting
scanner inspired by THOR Lite. It executes read-only inspections utilizing IOC
matching and YARA signature engines without altering scanned systems.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				// If a path was passed directly like: aether /var/www
				return executeScan(cmd, args, &gFlags, &sFlags, "custom")
			}
			if !isTerminal() || gFlags.plain {
				return cmd.Help()
			}
			return runInteractiveLauncher(cmd, &gFlags, &sFlags)
		},
	}

	rootCmd.PersistentFlags().StringVarP(&gFlags.configPath, "config", "c", "", "Path to YAML configuration file")
	rootCmd.PersistentFlags().BoolVarP(&gFlags.verbose, "verbose", "v", false, "Enable verbose info logging")
	rootCmd.PersistentFlags().BoolVar(&gFlags.debug, "debug", false, "Enable debug structured logging")
	rootCmd.PersistentFlags().BoolVarP(&gFlags.quiet, "quiet", "q", false, "Quiet mode (errors only)")
	rootCmd.PersistentFlags().BoolVar(&gFlags.plain, "plain", false, "Force plain text line-based output (no TUI)")
	rootCmd.PersistentFlags().BoolVar(&gFlags.noAnim, "no-anim", false, "Disable animations and splash screen")

	// Scan command
	scanCmd := &cobra.Command{
		Use:   "scan [paths...]",
		Short: "Perform compromise detection and threat hunting scan",
		Long: `Scan target filesystems, processes, and persistence hooks for indicators
of compromise (IOCs) and YARA signature matches in strict read-only mode.`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if sFlags.quick && sFlags.full {
				return errors.New("--quick and --full flags are mutually exclusive")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeScan(cmd, args, &gFlags, &sFlags, "custom")
		},
	}
	attachScanFlags(scanCmd, &sFlags)
	scanCmd.MarkFlagsMutuallyExclusive("quick", "full")

	// Quick command shortcut
	var qFlags scanCmdFlags
	quickCmd := &cobra.Command{
		Use:   "quick [paths...]",
		Short: "Perform fast triage scan of high-risk locations and persistence hooks",
		RunE: func(cmd *cobra.Command, args []string) error {
			qFlags.quick = true
			return executeScan(cmd, args, &gFlags, &qFlags, "quick")
		},
	}
	attachScanFlags(quickCmd, &qFlags)

	// Full command shortcut
	var fFlags scanCmdFlags
	fullCmd := &cobra.Command{
		Use:   "full [paths...]",
		Short: "Perform deep, comprehensive filesystem threat hunting scan",
		RunE: func(cmd *cobra.Command, args []string) error {
			fFlags.full = true
			return executeScan(cmd, args, &gFlags, &fFlags, "full")
		},
	}
	attachScanFlags(fullCmd, &fFlags)

	// Setup command
	var setupDownload bool
	var setupCustomDir string
	var setupForce bool

	setupCmd := &cobra.Command{
		Use:   "setup",
		Short: "Automated 1-click system configuration, permissions, and YARA-Forge rules setup",
		Long: `Configures secure rules directories (/etc/aether/rules or ~/.config/aether/rules),
verifies directory permissions, optionally installs binary to /usr/local/bin, and downloads
the latest verified YARA-Forge Core ruleset.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			th := theme.NewTheme(theme.DetectNoColor())
			opts := setup.SetupOptions{
				DownloadRules: setupDownload,
				CustomDir:     setupCustomDir,
				Force:         setupForce,
				InstallBinary: true,
			}
			_, err := setup.RunSetup(opts, th)
			return err
		},
	}
	setupCmd.Flags().BoolVar(&setupDownload, "download-rules", true, "Download latest YARA-Forge Core ruleset")
	setupCmd.Flags().StringVar(&setupCustomDir, "rules-dir", "", "Custom target directory for rules")
	setupCmd.Flags().BoolVar(&setupForce, "force", false, "Force overwrite existing rules")

	// Update command
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Update threat indicators, IOC signatures, and YARA rules",
		Long:  `Downloads latest threat definitions and rules from configured remote feeds.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := report.SetupLogger("info", false)
			logger.Info("checking for threat intelligence updates...")
			logger.Info("no remote signature feeds configured (update stub)")
			return nil
		},
	}

	// Version command
	var versionJSON bool
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version, commit, and build information",
		RunE: func(cmd *cobra.Command, args []string) error {
			info := appversion.New(version, commit, buildDate, yara.VersionInfo())
			if versionJSON {
				jsonStr, err := info.JSON()
				if err != nil {
					return err
				}
				fmt.Println(jsonStr)
				return nil
			}
			fmt.Println(info.String())
			return nil
		},
	}
	versionCmd.Flags().BoolVar(&versionJSON, "json", false, "Output version information in JSON format")

	// Hidden Demo command for UI testing and verification
	var demoJSONOut string
	demoCmd := &cobra.Command{
		Use:    "demo",
		Short:  "Run simulated hunting scan with synthetic events (UI test)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			usePlain := gFlags.plain || !isTerminal()
			bus := events.NewEventBus()
			defer bus.Close()

			th := theme.NewTheme(theme.DetectNoColor())

			var reporter *report.ConcurrentReporter
			if demoJSONOut != "" {
				var err error
				reporter, err = report.NewConcurrentReporter(demoJSONOut)
				if err != nil {
					return fmt.Errorf("failed to open demo json output: %w", err)
				}
				defer reporter.Close()
				bus.AttachReporter(reporter)
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			demoDone := make(chan struct{})

			// Simulated event generator
			go func() {
				defer close(demoDone)
				runDemoGenerator(ctx, bus)
			}()

			if usePlain {
				consumer := plain.NewConsumer(os.Stdout, th, gFlags.verbose)
				sub := bus.Subscribe()
				defer sub.Close()

				_ = consumer.Consume(ctx, sub)
				<-demoDone
				return nil
			}

			uiSub := bus.Subscribe()
			defer uiSub.Close()

			return tui.Run(ctx, cancel, uiSub, th, gFlags.noAnim, "QUICK", 8, []string{"/bin", "/etc", "/tmp", "/dev/shm"})
		},
	}
	demoCmd.Flags().StringVar(&demoJSONOut, "json-out", "", "Output report destination path for demo JSON format")

	// Ack command
	type ackCmdFlags struct {
		reason string
		rule   string
		system bool
		yes    bool
	}
	var aFlags ackCmdFlags

	ackCmd := &cobra.Command{
		Use:   "ack <path>",
		Short: "Acknowledge and triage known findings for a path",
		Long: `Acknowledge a finding to downgrade it to INFO and prevent it from altering the scan verdict.
Pins findings by file hash, unit exec target hashes, or matched line hash.
ALERT and IOC findings are never ackable.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetPath := filepath.Clean(args[0])
			if aFlags.reason == "" {
				return errors.New("--reason flag is required")
			}

			var destPath string
			var userHome string
			isSudoUser := false
			sudoUser := os.Getenv("SUDO_USER")

			if aFlags.system {
				if os.Geteuid() != 0 {
					return errors.New("root privileges required to write system acknowledgment file (/etc/aether/acknowledged.yaml)")
				}
				destPath = "/etc/aether/acknowledged.yaml"
			} else {
				if os.Geteuid() == 0 && sudoUser != "" {
					fmt.Printf("[AETHER] [WARNING] Running under sudo without --system: targeting user config for SUDO_USER=%s\n", sudoUser)
					if u, uErr := user.Lookup(sudoUser); uErr == nil && u.HomeDir != "" {
						userHome = u.HomeDir
						isSudoUser = true
					}
				}
				if userHome == "" {
					userHome, _ = os.UserHomeDir()
				}
				if userHome == "" {
					return errors.New("cannot determine user home directory")
				}
				cleanHome := filepath.Clean(userHome)
				if !strings.HasPrefix(targetPath, cleanHome+"/") && targetPath != cleanHome {
					return fmt.Errorf("user acknowledgment file cannot acknowledge paths outside user home directory (%s is not in %s; use --system as root)", targetPath, cleanHome)
				}
				destPath = filepath.Join(cleanHome, ".config/aether/acknowledged.yaml")
			}

			lst, err := os.Lstat(targetPath)
			if err != nil {
				return fmt.Errorf("target path inaccessible: %w", err)
			}

			addedBy := os.Getenv("USER")
			if addedBy == "" {
				if isSudoUser {
					addedBy = sudoUser
				} else {
					addedBy = "user"
				}
			}

			entry := triage.AckEntry{
				Path:    targetPath,
				Rule:    aFlags.rule,
				Reason:  aFlags.reason,
				AddedBy: addedBy,
			}

			if (lst.Mode() & os.ModeSymlink) != 0 {
				target, err := os.Readlink(targetPath)
				if err != nil {
					return fmt.Errorf("failed to read symlink %s: %w", targetPath, err)
				}
				entry.SymlinkTarget = target
				targetHost := target
				if !filepath.IsAbs(target) {
					targetHost = filepath.Join(filepath.Dir(targetPath), target)
				}
				targetHash, err := triage.HashFile(targetHost, 50*1024*1024)
				if err == nil {
					entry.SymlinkTargetSHA256 = targetHash
				}
			} else {
				isUnit := strings.HasSuffix(targetPath, ".service") || strings.HasSuffix(targetPath, ".timer") || strings.HasSuffix(targetPath, ".socket")
				if isUnit {
					h, err := triage.HashFile(targetPath, 50*1024*1024)
					if err != nil {
						return fmt.Errorf("failed to hash unit file %s: %w", targetPath, err)
					}
					entry.FileSHA256 = h
					if data, err := os.ReadFile(targetPath); err == nil {
						sc := bufio.NewScanner(bytes.NewReader(data))
						entry.ExecTargetHashes = make(map[string]string)
						for sc.Scan() {
							line := strings.TrimSpace(sc.Text())
							if strings.HasPrefix(line, "Exec") && strings.Contains(line, "=") {
								cmd := strings.TrimSpace(line[strings.Index(line, "=")+1:])
								targets, _ := persistence.ExtractExecTargets(cmd)
								for _, t := range targets {
									if strings.HasPrefix(t, "/home/") || strings.HasPrefix(t, "~/") || strings.HasPrefix(t, "/root/") {
										th, thErr := triage.HashFile(t, 50*1024*1024)
										if thErr == nil {
											entry.ExecTargetHashes[t] = th
										}
									}
								}
							}
						}
						if len(entry.ExecTargetHashes) == 0 {
							entry.ExecTargetHashes = nil
						}
					}
				} else {
					if data, err := os.ReadFile(targetPath); err == nil {
						sc := bufio.NewScanner(bytes.NewReader(data))
						var foundLine string
						cfg := config.NewDefaultConfig()
						for sc.Scan() {
							line := strings.TrimSpace(sc.Text())
							sigs := persistence.CheckSuspiciousCommand(line, 0, cfg, "", false, nil)
							for _, s := range sigs {
								if aFlags.rule == "" || s.RuleName == aFlags.rule || strings.Contains(s.RuleName, aFlags.rule) {
									if s.Severity == report.SeverityAlert || s.IsReverseShellPrimitive || s.IsIOCMatch {
										return errors.New("ALERT and IOC findings cannot be acknowledged")
									}
									foundLine = line
									break
								}
							}
							if foundLine != "" {
								break
							}
						}
						if foundLine != "" {
							entry.LineSHA256 = triage.HashLine(foundLine)
							entry.LineContent = foundLine
							targets, _ := persistence.ExtractExecTargets(foundLine)
							entry.ExecTargetHashes = make(map[string]string)
							for _, t := range targets {
								th, thErr := triage.HashFile(t, 50*1024*1024)
								if thErr == nil {
									entry.ExecTargetHashes[t] = th
								}
							}
							if len(entry.ExecTargetHashes) == 0 {
								entry.ExecTargetHashes = nil
							}
						} else {
							h, err := triage.HashFile(targetPath, 50*1024*1024)
							if err != nil {
								return fmt.Errorf("failed to hash file: %w", err)
							}
							entry.FileSHA256 = h
						}
					}
				}
			}

			// Show preview
			fmt.Println("[AETHER] Finding Acknowledgment Preview:")
			fmt.Printf("  Target Path:        %s\n", targetPath)
			if entry.Rule != "" {
				fmt.Printf("  Rule:               %s\n", entry.Rule)
			} else {
				fmt.Printf("  Rule:               (all rules on this path)\n")
			}
			fmt.Printf("  Reason:             %s\n", entry.Reason)
			fmt.Printf("  Destination Config: %s\n", destPath)
			if entry.FileSHA256 != "" {
				fmt.Printf("  File SHA256:        %s\n", entry.FileSHA256)
			}
			if entry.LineSHA256 != "" {
				fmt.Printf("  Line SHA256:        %s\n", entry.LineSHA256)
				fmt.Printf("  Line Content:       %s\n", entry.LineContent)
			}
			if len(entry.ExecTargetHashes) > 0 {
				fmt.Printf("  Exec Target Hashes:\n")
				for tp, th := range entry.ExecTargetHashes {
					fmt.Printf("    - %s: %s\n", tp, th)
				}
			}
			if entry.SymlinkTarget != "" {
				fmt.Printf("  Symlink Target:     %s (%s)\n", entry.SymlinkTarget, entry.SymlinkTargetSHA256)
			}

			if !aFlags.yes {
				fmt.Print("\nApply acknowledgment? [y/N]: ")
				var answer string
				_, _ = fmt.Scanln(&answer)
				answer = strings.ToLower(strings.TrimSpace(answer))
				if answer != "y" && answer != "yes" {
					fmt.Println("[AETHER] Operation aborted.")
					return nil
				}
			}

			if err := triage.WriteAckEntry(destPath, entry); err != nil {
				return fmt.Errorf("failed to write acknowledgment: %w", err)
			}

			if isSudoUser {
				if u, uErr := user.Lookup(sudoUser); uErr == nil {
					var uid, gid int
					fmt.Sscanf(u.Uid, "%d", &uid)
					fmt.Sscanf(u.Gid, "%d", &gid)
					_ = os.Chown(destPath, uid, gid)
					_ = os.Chown(filepath.Dir(destPath), uid, gid)
				}
			}

			fmt.Printf("[AETHER] Successfully acknowledged %s in %s\n", targetPath, destPath)
			return nil
		},
	}
	ackCmd.Flags().StringVar(&aFlags.reason, "reason", "", "Reason for acknowledging the finding (required)")
	ackCmd.Flags().StringVar(&aFlags.rule, "rule", "", "Specific rule name to acknowledge (optional)")
	ackCmd.Flags().BoolVar(&aFlags.system, "system", false, "Write to system acknowledgment file (/etc/aether/acknowledged.yaml)")
	ackCmd.Flags().BoolVarP(&aFlags.yes, "yes", "y", false, "Non-interactive confirmation")

	// Rules command
	rulesCmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage and validate YARA rules",
	}

	validateCmd := &cobra.Command{
		Use:   "validate <dir>",
		Short: "Validate and compile YARA rule files in a directory",
		Long: `Recursively discovers and compiles all *.yar and *.yara rule files in a given directory
using the YARA-X engine, checking syntax, namespaces, and variables without running a scan.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := filepath.Clean(args[0])
			res, err := yara.ValidateRulesDir(dir)
			if err != nil {
				return err
			}

			fmt.Println("[AETHER] YARA Rule Validation Report:")
			fmt.Printf("  Directory:                 %s\n", dir)
			fmt.Printf("  Rule Files Found:          %d\n", res.TotalFilesFound)
			fmt.Printf("  Files Compiled:            %d\n", res.FilesCompiled)
			fmt.Printf("  Files Failed:              %d\n", res.FilesFailed)
			fmt.Printf("  Total Rules Loaded:        %d\n", res.TotalRulesLoaded)
			fmt.Printf("  With Explicit Score:       %d\n", res.RulesWithExplicitScore)
			fmt.Printf("  With Explicit Severity:    %d\n", res.RulesWithExplicitSev)
			fmt.Printf("  With Alert/Critical/Score>=90: %d\n", res.RulesWithAlertOrCritical)
			fmt.Printf("  With Defaulted Metadata:   %d\n", res.RulesWithDefaultMetadata)

			if len(res.Failures) > 0 {
				fmt.Println("\n[AETHER] Compilation Errors:")
				for _, f := range res.Failures {
					fmt.Printf("  [FAIL] %s\n         Error: %s\n", f.Path, f.Error)
				}
				return fmt.Errorf("YARA validation failed: %d file(s) had syntax or compilation errors", len(res.Failures))
			}

			fmt.Printf("\n[AETHER] Validation status: SUCCESS (all %d file(s) valid)\n", res.TotalFilesFound)
			return nil
		},
	}
	rulesCmd.AddCommand(validateCmd)

	rootCmd.AddCommand(scanCmd, quickCmd, fullCmd, setupCmd, ackCmd, updateCmd, versionCmd, demoCmd, rulesCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runDemoGenerator(ctx context.Context, bus *events.EventBus) {
	startTime := time.Now()
	bus.Publish(events.ScanStarted{
		Time:        startTime,
		Paths:       []string{"/bin", "/sbin", "/etc", "/tmp", "/dev/shm"},
		Excludes:    []string{"/proc", "/sys", "/dev/pts", "/run/user"},
		Mode:        "quick",
		Threads:     8,
		MaxFileSize: 52428800,
	})

	time.Sleep(300 * time.Millisecond)

	sampleFiles := []string{
		"/bin/systemd", "/bin/bash", "/usr/bin/sudo", "/etc/shadow",
		"/etc/pam.d/common-auth", "/etc/systemd/system/threat.service",
		"/tmp/.X11-unix/X0", "/dev/shm/.stealth_miner", "/var/tmp/.cache_bak",
		"/proc/1420/exe", "/usr/sbin/cron", "/etc/crontab",
	}

	modulesList := []struct {
		name string
		desc string
	}{
		{"process", "Inspects running processes, memory mappings, and deleted binaries"},
		{"persistence", "Scans systemd services, cron jobs, and shell profiles"},
		{"filesystem", "Inspects permissions, hidden directories, and suspicious executables"},
	}

	for _, m := range modulesList {
		select {
		case <-ctx.Done():
			return
		default:
			bus.Publish(events.ModuleStarted{
				Time:        time.Now(),
				ModuleName:  m.name,
				Description: m.desc,
			})
			time.Sleep(250 * time.Millisecond)
		}
	}

	var filesCount int64
	for i := 0; i < 40; i++ {
		select {
		case <-ctx.Done():
			return
		default:
			filePath := sampleFiles[rand.Intn(len(sampleFiles))]
			filesCount += 35
			bus.Publish(events.FileScanned{
				Time: time.Now(),
				Path: filePath,
				Size: 1024 + int64(rand.Intn(50000)),
			})

			bus.Publish(events.Progress{
				Time:         time.Now(),
				CurrentFiles: filesCount,
				FilesPerSec:  float64(300 + rand.Intn(200)),
				Elapsed:      time.Since(startTime),
			})

			// Emit synthetic findings with [DEMO] prefix and {"synthetic": true}
			if i == 5 {
				f := report.NewFinding(
					"persistence",
					report.SeverityInfo,
					"/etc/cron.d/anacron",
					"[DEMO] Routine cron job discovered in standard location",
					"Routine_Cron_Task",
				)
				f.Metadata["synthetic"] = true
				bus.Publish(events.FindingRaised{Time: time.Now(), Finding: f})
			} else if i == 12 {
				f := report.NewFinding(
					"filesystem",
					report.SeverityNotice,
					"/var/tmp/.cache_bak",
					"[DEMO] Hidden dot-directory discovered in world-writable temp location",
					"Suspicious_Hidden_Directory",
				)
				f.Metadata["synthetic"] = true
				bus.Publish(events.FindingRaised{Time: time.Now(), Finding: f})
			} else if i == 20 {
				f := report.NewFinding(
					"process",
					report.SeverityWarning,
					"/proc/1842/exe",
					"[DEMO] Process running with unlinked/deleted binary from filesystem",
					"Unlinked_Process_Binary",
				)
				f.Metadata["synthetic"] = true
				f.Hashes["SHA256"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
				bus.Publish(events.FindingRaised{Time: time.Now(), Finding: f})
			} else if i == 28 {
				f := report.NewFinding(
					"process",
					report.SeverityAlert,
					"/dev/shm/.stealth_miner",
					"[DEMO] Memory-only stealth execution detected via memfd_create descriptor",
					"Linux_Trojan_BPFDoor",
				)
				f.Metadata["synthetic"] = true
				f.Hashes["MD5"] = "5d41402abc4b2a76b9719d911017c592"
				f.Hashes["SHA256"] = "a8f5f167f44f4964e6c998dee827110c"
				bus.Publish(events.FindingRaised{Time: time.Now(), Finding: f})
			}

			time.Sleep(60 * time.Millisecond)
		}
	}

	for _, m := range modulesList {
		bus.Publish(events.ModuleFinished{
			Time:          time.Now(),
			ModuleName:    m.name,
			Duration:      time.Duration(400+rand.Intn(300)) * time.Millisecond,
			FindingsCount: 1,
		})
	}

	time.Sleep(100 * time.Millisecond)

	// Final scan event
	verdict, _ := events.ComputeVerdict(nil, 1, 1, 1, 0)
	bus.Publish(events.ScanFinished{
		Time:          time.Now(),
		TotalDuration: time.Since(startTime),
		FilesScanned:  filesCount,
		Coverage: events.CoverageStats{
			FilesScanned:      filesCount,
			SkippedOversize:   2,
			SkippedPermission: 1,
			SkippedVanished:   0,
			SkippedNotRegular: 4,
			SkippedExcluded:   3,
		},
		TotalFindings: 4,
		Alerts:        1,
		Warnings:      1,
		Notices:       1,
		Infos:         1,
		Verdict:       verdict,
		Partial:       true,
	})
}
