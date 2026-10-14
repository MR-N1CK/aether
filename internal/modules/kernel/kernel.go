package kernel

import (
	"context"
	"log/slog"
	"os"
	"time"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/ioc"
	"aether/internal/pkgdb"
	"aether/internal/report"
)

// KernelCoverage captures inspection statistics from kernel threat hunting.
type KernelCoverage struct {
	LoadedModulesInspected int64
	SysfsLoadableEntries   int64
	TaintValue             uint64
	TaintFlags             []string
	TaintSeverity          string
	ModprobeFilesInspected int64
	GapsNote               string
	NonRootLimited         bool
}

// Module implements threat hunting inspection for Linux kernel modules, sysfs discrepancies, taint, and modprobe hooks.
type Module struct {
	rootFS    string
	procRoot  string
	sysRoot   string
	iocEngine ioc.Engine
	bus       *events.EventBus
	logger    *slog.Logger
	pkgDB     pkgdb.PackageDB
	coverage  KernelCoverage
	// testDelay allows overriding the 200ms delay in unit tests
	testDelay time.Duration
}

// NewModule creates an initialized kernel module targeting the host system.
func NewModule(iocEng ioc.Engine, bus *events.EventBus, logger *slog.Logger) *Module {
	return NewModuleWithRoots("", "", "", iocEng, bus, logger)
}

// NewModuleWithRoots creates an initialized kernel module with injectable roots for testing.
func NewModuleWithRoots(rootFS, procRoot, sysRoot string, iocEng ioc.Engine, bus *events.EventBus, logger *slog.Logger) *Module {
	if logger == nil {
		logger = slog.Default()
	}
	return &Module{
		rootFS:    rootFS,
		procRoot:  procRoot,
		sysRoot:   sysRoot,
		iocEngine: iocEng,
		bus:       bus,
		logger:    logger,
		pkgDB:     pkgdb.New(rootFS),
		testDelay: 200 * time.Millisecond,
	}
}

// SetTestDelay overrides the inter-pass sleep duration for fast unit testing.
func (m *Module) SetTestDelay(d time.Duration) {
	m.testDelay = d
}

func (m *Module) Name() string { return "kernel" }

func (m *Module) Description() string {
	return "Inspects kernel module integrity (/proc/modules vs /sys/module), kernel taint bitmask, and modprobe install hooks"
}

// Coverage returns the statistics from the last kernel module execution.
func (m *Module) Coverage() KernelCoverage {
	return m.coverage
}

// Run executes the complete kernel inspection sweep.
func (m *Module) Run(ctx context.Context, cfg *config.Config, rep report.Reporter) error {
	m.logger.Debug("starting kernel threat hunting module",
		slog.String("proc_root", m.procRoot),
		slog.String("sys_root", m.sysRoot),
		slog.String("root_fs", m.rootFS),
	)

	isNonRoot := os.Geteuid() != 0 && m.procRoot == "" && m.rootFS == ""

	cov := KernelCoverage{
		GapsNote:       "Live kernel memory and firmware integrity are not inspected",
		NonRootLimited: isNonRoot,
	}

	var allFindings []report.Finding

	// 1. Two-pass hidden module inspection (/proc/modules vs /sys/module/*/initstate)
	// Skip live kernel inspection when scanning an offline root without explicit procRoot
	if m.procRoot != "" || m.rootFS == "" {
		moduleFindings := CheckHiddenModules(ctx, m.procRoot, m.sysRoot, m.rootFS, m.testDelay, m.pkgDB, &cov, m.logger)
		allFindings = append(allFindings, moduleFindings...)

		// 2. Taint bitmask decoding (/proc/sys/kernel/tainted)
		taintFindings := CheckTainted(m.procRoot, &cov, m.logger)
		allFindings = append(allFindings, taintFindings...)
	}

	// 3. Modprobe install & softdep configuration hooks
	modprobeFindings := CheckModprobe(ctx, m.rootFS, cfg, &cov, m.logger)
	allFindings = append(allFindings, modprobeFindings...)

	// 4. eBPF & Kernel Trace Hook Inspection
	ebpfFindings := CheckEBPFProbes(ctx, m.rootFS, m.sysRoot, &cov, m.logger)
	allFindings = append(allFindings, ebpfFindings...)

	// Report findings
	for _, f := range allFindings {
		if rep != nil {
			rep.Report(f)
		}
	}

	m.coverage = cov
	return nil
}
