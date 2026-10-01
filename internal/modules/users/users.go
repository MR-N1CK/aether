package users

import (
	"context"
	"log/slog"
	"os"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/ioc"
	"aether/internal/pkgdb"
	"aether/internal/report"
)

// UsersCoverage captures inspection statistics for the users module.
type UsersCoverage struct {
	AccountsInspected      int64
	SystemAccounts         int64
	ShadowReadable         bool
	ShadowGapNonRoot       bool
	DuplicateUIDs          int64
	PrivilegedGroupMembers []string
	DockerLXDMembers       []string
	NonRootLimited         bool
	UnreadablePaths        []events.UnreadablePersistencePath
}

// Module implements threat hunting inspection for Linux user accounts, shadow hashes, and groups.
type Module struct {
	rootFS    string
	iocEngine ioc.Engine
	bus       *events.EventBus
	logger    *slog.Logger
	pkgDB     pkgdb.PackageDB
	coverage  UsersCoverage
}

// NewModule creates an initialized users module targeting the host system.
func NewModule(iocEng ioc.Engine, bus *events.EventBus, logger *slog.Logger) *Module {
	return NewModuleWithRoot("", iocEng, bus, logger)
}

// NewModuleWithRoot creates an initialized users module with injectable root filesystem for hermetic testing.
func NewModuleWithRoot(rootFS string, iocEng ioc.Engine, bus *events.EventBus, logger *slog.Logger) *Module {
	if logger == nil {
		logger = slog.Default()
	}
	return &Module{
		rootFS:    rootFS,
		iocEngine: iocEng,
		bus:       bus,
		logger:    logger,
		pkgDB:     pkgdb.New(rootFS),
	}
}

func (m *Module) Name() string { return "users" }

func (m *Module) Description() string {
	return "Inspects user accounts (/etc/passwd), password hashes (/etc/shadow), group memberships, and account permissions"
}

// Coverage returns the statistics from the last users module execution.
func (m *Module) Coverage() UsersCoverage {
	return m.coverage
}

// Run executes user account, shadow, and permission checks.
func (m *Module) Run(ctx context.Context, cfg *config.Config, rep report.Reporter) error {
	m.logger.Debug("starting users threat hunting module", slog.String("root_fs", m.rootFS))

	isNonRoot := os.Geteuid() != 0 && m.rootFS == ""
	cov := UsersCoverage{
		NonRootLimited: isNonRoot,
	}

	var allFindings []report.Finding

	// 1. Check file permissions for /etc/passwd and /etc/shadow
	permFindings := CheckPermissions(m.rootFS, cfg, &cov)
	allFindings = append(allFindings, permFindings...)

	// 2. Parse /etc/shadow (root or fake rootFS only)
	shadowEntries, shadowFindings := CheckShadow(m.rootFS, cfg, isNonRoot, &cov)
	allFindings = append(allFindings, shadowFindings...)

	// 3. Parse /etc/passwd
	passwdFindings := CheckPasswd(ctx, m.rootFS, cfg, m.pkgDB, shadowEntries, &cov)
	allFindings = append(allFindings, passwdFindings...)

	// 4. Parse /etc/group
	groupFindings := CheckGroups(m.rootFS, cfg, &cov)
	allFindings = append(allFindings, groupFindings...)

	// Report findings
	for _, f := range allFindings {
		if rep != nil {
			rep.Report(f)
		}
	}

	m.coverage = cov
	return nil
}
