package persistence

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/ioc"
	"aether/internal/pkgdb"
	"aether/internal/report"
)

// CheckCoverage tracks inspection counts for a single persistence area.
type CheckCoverage struct {
	Name            string                             `json:"name"`
	Inspected       int64                              `json:"inspected"`
	Unreadable      int64                              `json:"unreadable"`
	NotPresent      int64                              `json:"not_present"`
	Missing         int64                              `json:"missing,omitempty"`
	Masked          int64                              `json:"masked,omitempty"`
	MaskedPaths     []string                           `json:"masked_paths,omitempty"`
	UnreadablePaths []events.UnreadablePersistencePath `json:"unreadable_paths,omitempty"`
}

// RecordUnreadable records an unreadable file and classifies the error reason.
func (c *CheckCoverage) RecordUnreadable(path string, err error) {
	if c == nil {
		return
	}
	clean := filepath.Clean(path)
	for _, up := range c.UnreadablePaths {
		if up.Path == clean {
			return
		}
	}
	c.Unreadable++
	c.UnreadablePaths = append(c.UnreadablePaths, events.UnreadablePersistencePath{
		Path:   clean,
		Reason: ClassifyUnreadableReason(err),
	})
}

// RecordMasked records a masked unit path and deduplicates so the same path is not counted twice.
func (c *CheckCoverage) RecordMasked(path string) {
	if c == nil {
		return
	}
	clean := filepath.Clean(path)
	for _, p := range c.MaskedPaths {
		if p == clean {
			return
		}
	}
	c.Masked++
	c.MaskedPaths = append(c.MaskedPaths, clean)
}

// PersistenceCoverage aggregates coverage metrics across all persistence hooks.
type PersistenceCoverage struct {
	TotalInspected  int64                              `json:"total_inspected"`
	TotalUnreadable int64                              `json:"total_unreadable"`
	NotPresent      int64                              `json:"not_present"`
	TotalMissing    int64                              `json:"total_missing,omitempty"`
	TotalMasked     int64                              `json:"total_masked,omitempty"`
	MaskedPaths     []string                           `json:"masked_paths,omitempty"`
	NonRootLimited  bool                               `json:"non_root_limited"`
	PkgDBAvailable  bool                               `json:"pkgdb_available"`
	PkgDBNote       string                             `json:"pkgdb_note"`
	Checks          map[string]CheckCoverage           `json:"checks"`
	UnreadablePaths []events.UnreadablePersistencePath `json:"unreadable_paths,omitempty"`
}

// Module implements the specialized Linux persistence hunting module.
type Module struct {
	rootFS    string
	iocEngine ioc.Engine
	bus       *events.EventBus
	logger    *slog.Logger
	pkgDB     pkgdb.PackageDB
	coverage  PersistenceCoverage
}

// NewModule creates an initialized persistence module targeting the host system.
func NewModule(iocEng ioc.Engine, bus *events.EventBus, logger *slog.Logger) *Module {
	return NewModuleWithRoot("", iocEng, bus, logger)
}

// NewModuleWithRoot creates an initialized persistence module with an injectable rootFS
// for unit testing against isolated directory trees without requiring root privileges.
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
		coverage: PersistenceCoverage{
			Checks: make(map[string]CheckCoverage),
		},
	}
}

func (m *Module) Name() string { return "persistence" }

func (m *Module) Description() string {
	return "Scans common Linux persistence hooks such as cron, systemd services, shell profiles, and loader hijacks"
}

// Coverage returns the statistics from the last persistence run.
func (m *Module) Coverage() PersistenceCoverage {
	return m.coverage
}

// Run executes the complete persistence sweep across all 7 hook categories.
func (m *Module) Run(ctx context.Context, cfg *config.Config, rep report.Reporter) error {
	m.logger.Debug("starting persistence threat hunting module", slog.String("root_fs", m.rootFS))

	isNonRoot := os.Geteuid() != 0 && m.rootFS == ""
	covMap := make(map[string]CheckCoverage)

	type checkFn func(context.Context, string, *config.Config, pkgdb.PackageDB, ioc.Engine, *CheckCoverage) ([]report.Finding, error)

	checks := []struct {
		name string
		fn   checkFn
	}{
		{"cron", CheckCron},
		{"systemd", CheckSystemd},
		{"ssh", CheckSSH},
		{"profiles", CheckProfiles},
		{"loader", CheckLoader},
		{"pam", CheckPAM},
		{"hooks", CheckOtherHooks},
	}

	startTime := time.Now()
	var allFindings []report.Finding

	for _, check := range checks {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		cov := CheckCoverage{Name: check.name}
		findings, err := check.fn(ctx, m.rootFS, cfg, m.pkgDB, m.iocEngine, &cov)
		if err != nil {
			m.logger.Warn("persistence check encountered error", slog.String("check", check.name), slog.Any("error", err))
		}
		covMap[check.name] = cov
		allFindings = append(allFindings, findings...)

		if m.bus != nil {
			m.bus.Publish(events.Progress{
				Time:          time.Now(),
				CurrentFiles:  cov.Inspected,
				FilesPerSec:   0,
				Elapsed:       time.Since(startTime),
				ActiveModules: []string{"persistence"},
			})
		}
	}

	// Filter and report findings
	for _, f := range allFindings {
		// Allowlist check: if allowlisted, suppress heuristic finding
		if m.iocEngine != nil {
			if isAllowlisted, _ := m.iocEngine.IsAllowlisted(f.Path); isAllowlisted {
				continue
			}
		}

		if rep != nil {
			rep.Report(f)
		}
	}

	// Calculate totals
	var totalInspected, totalNotPresent, totalMissing int64
	var allUnreadablePaths []events.UnreadablePersistencePath
	seenUnreadable := make(map[string]bool)
	var allMaskedPaths []string
	seenMasked := make(map[string]bool)

	for _, c := range covMap {
		totalInspected += c.Inspected
		totalNotPresent += c.NotPresent
		totalMissing += c.Missing
		for _, up := range c.UnreadablePaths {
			if !seenUnreadable[up.Path] {
				seenUnreadable[up.Path] = true
				allUnreadablePaths = append(allUnreadablePaths, up)
			}
		}
		for _, mp := range c.MaskedPaths {
			resolved := ResolveVirtualPath(m.rootFS, mp)
			if !seenMasked[resolved] {
				seenMasked[resolved] = true
				allMaskedPaths = append(allMaskedPaths, resolved)
			}
		}
	}
	if totalNotPresent == 0 && totalMissing > 0 {
		totalNotPresent = totalMissing
	}

	m.coverage = PersistenceCoverage{
		TotalInspected:  totalInspected,
		TotalUnreadable: int64(len(allUnreadablePaths)),
		NotPresent:      totalNotPresent,
		TotalMissing:    totalMissing,
		TotalMasked:     int64(len(allMaskedPaths)),
		MaskedPaths:     allMaskedPaths,
		NonRootLimited:  isNonRoot,
		PkgDBAvailable:  m.pkgDB != nil && m.pkgDB.IsAvailable(),
		PkgDBNote:       "",
		Checks:          covMap,
		UnreadablePaths: allUnreadablePaths,
	}
	if m.pkgDB != nil {
		m.coverage.PkgDBNote = m.pkgDB.StatusNote()
	}

	m.logger.Debug("persistence inspection finished",
		slog.Int64("inspected", totalInspected),
		slog.Int64("unreadable", m.coverage.TotalUnreadable),
		slog.Int64("missing", totalMissing),
		slog.Int("findings", len(allFindings)),
	)

	return nil
}
