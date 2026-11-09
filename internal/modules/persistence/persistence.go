package persistence

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aether/internal/config"
	"aether/internal/events"
	"aether/internal/ioc"
	"aether/internal/pkgdb"
	"aether/internal/report"
	"aether/internal/safeopen"
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
	if c == nil || err == nil {
		return
	}
	if os.IsNotExist(err) || errors.Is(err, safeopen.ErrVanished) || errors.Is(err, os.ErrNotExist) {
		c.NotPresent++
		c.Missing++
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

	// Correlate multi-vector persistence
	correlFindings := correlateMultiVectorPersistence(allFindings, m.rootFS, m.pkgDB)
	allFindings = append(allFindings, correlFindings...)

	// Filter and report findings
	for _, f := range allFindings {
		// Allowlist check: the IOC allowlist stores SHA-256 digests, so the
		// artifact must be hashed before lookup. A bare path never matches a
		// digest entry; unreadable or non-file targets simply skip suppression.
		if m.iocEngine != nil {
			if digest := allowlistSHA256(m.rootFS, f.Path); digest != "" {
				if isAllowlisted, _ := m.iocEngine.IsAllowlisted(digest); isAllowlisted {
					continue
				}
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

// multiVectorStrength classifies the evidential weight of a multi-vector
// correlation hit for one payload path.
//
// Calibration (2026-11 review): "unowned" alone is common for legitimate user
// tooling (cargo/rustup/nvm launchers in hidden home paths referenced by a
// user systemd unit + an XDG autostart entry + a profile), and unprivileged
// scans cannot stat other users' files, which masquerades as unreadable rather
// than missing. So a payload wired ONLY from user-session reference files,
// present on disk, and inside a user home tree is downgraded to a
// WARNING-level SUSPICIOUS observation instead of a MALICIOUS alert.
//
// Escalation back to a full-strength ALERT happens when ANY of:
//   - at least one reference file is admin-managed (anything under /etc,
//     /var, /usr, /lib, or /root — root is an administrator account);
//   - the payload is genuinely missing from disk (stat says ENOENT);
//   - the payload lives outside user home trees (hidden system dirs like
//     /usr/lib/.system-cache are never user-session territory).
type multiVectorStrength struct {
	strong    bool
	downgrade bool
}

// classifyMultiVectorPayload decides ALERT vs downgraded-WARNING for one
// correlated payload. artMap maps artifact class -> referencing source files.
// isMissing is the os.Stat IsNotExist result for the payload on the inspected
// (possibly offline-root) filesystem.
func classifyMultiVectorPayload(p string, artMap map[string]map[string]bool, isMissing bool) multiVectorStrength {
	// Hidden system path (outside user home trees): always strong.
	inUserHome := strings.HasPrefix(p, "/home/") || strings.HasPrefix(p, "/root/") ||
		strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "$HOME/") || strings.HasPrefix(p, "${HOME}/")
	if !inUserHome {
		return multiVectorStrength{strong: true}
	}

	// Payload genuinely absent from disk: the hooks reference something that
	// was dropped or removed — treat as strong regardless of mechanism mix.
	if isMissing {
		return multiVectorStrength{strong: true}
	}

	// Strong unless EVERY mechanism is wired exclusively from user-session
	// reference files (under /home/<user>/ or a home-relative path). The
	// referencing file's location, not the artifact class, decides: a systemd
	// unit under /etc/systemd/system is admin-managed, while the same-named
	// unit under /home/<u>/.config/systemd/user is the user's own session
	// unit. The artifact class tag alone cannot tell them apart.
	for _, files := range artMap {
		allUserWired := len(files) > 0
		for file := range files {
			if !isUserSessionRefFile(file) {
				allUserWired = false
				break
			}
		}
		if !allUserWired {
			return multiVectorStrength{strong: true}
		}
	}

	// User-home payload, present on disk, referenced only from user-session
	// files: downgrade.
	return multiVectorStrength{strong: false, downgrade: true}
}

// isUserSessionRefFile reports whether a persistence reference file lives in a
// user's home tree (their own session configuration, not admin-managed).
// /root is deliberately excluded: root is an administrator account, so anything
// wired from /root keeps full strength.
func isUserSessionRefFile(file string) bool {
	clean := filepath.Clean(file)
	return strings.HasPrefix(clean, "/home/") ||
		strings.HasPrefix(clean, "~/") ||
		strings.HasPrefix(clean, "$HOME/") ||
		strings.HasPrefix(clean, "${HOME}/")
}

func correlateMultiVectorPersistence(allFindings []report.Finding, rootFS string, pkgDB pkgdb.PackageDB) []report.Finding {
	// target -> map[artifact]map[file]bool
	targetRefs := make(map[string]map[string]map[string]bool)
	// targetMissing records whether os.Stat reported genuine ENOENT for a
	// payload path (EACCES is NOT missing — it is a visibility gap).
	targetMissing := make(map[string]bool)

	for _, f := range allFindings {
		// Determine artifact type
		artifact := ""
		if artVal, ok := f.Metadata["artifact"].(string); ok && artVal != "" {
			artifact = artVal
		} else {
			if strings.Contains(f.RuleName, "Cron") {
				artifact = "cron"
			} else if strings.Contains(f.RuleName, "Systemd") {
				artifact = "systemd"
			} else if strings.Contains(f.RuleName, "SSH") {
				artifact = "ssh"
			} else if strings.Contains(f.RuleName, "Profile") {
				artifact = "profile"
			} else if strings.Contains(f.RuleName, "Loader") {
				artifact = "loader"
			} else if strings.Contains(f.RuleName, "PAM") {
				artifact = "pam"
			} else if strings.Contains(f.RuleName, "InitD") {
				artifact = "init.d"
			} else if strings.Contains(f.RuleName, "RCD") {
				artifact = "rc.d"
			} else if strings.Contains(f.RuleName, "MOTD") {
				artifact = "update-motd"
			} else if strings.Contains(f.RuleName, "Udev") {
				artifact = "udev"
			} else if strings.Contains(f.RuleName, "Sudoers") {
				artifact = "sudoers"
			} else if strings.Contains(f.RuleName, "APT") {
				artifact = "apt_hook"
			} else {
				artifact = "persistence"
			}
		}

		sourceFile := f.Path
		if fileVal, ok := f.Metadata["file"].(string); ok && fileVal != "" {
			sourceFile = fileVal
		}

		var candidates []string
		if execTargets, ok := f.Metadata["exec_targets"].([]string); ok {
			candidates = append(candidates, execTargets...)
		}
		if tgt, ok := f.Metadata["target"].(string); ok && tgt != "" {
			candidates = append(candidates, tgt)
		}

		for _, cand := range candidates {
			cand = strings.TrimSpace(cand)
			if cand == "" || cand == "/" || cand == "." || cand == "/bin" || cand == "/usr/bin" {
				continue
			}
			p := filepath.Clean(cand)
			base := filepath.Base(p)

			// 1. Ignore interpreters and shells as payloads
			if isInterpreterOrShell(base) {
				continue
			}

			// 2. Only correlate payloads that are hidden, missing on disk, or unowned by any package
			isHidden := strings.Contains(p, "/.") || strings.HasPrefix(base, ".")

			hostP := p
			if rootFS != "" && strings.HasPrefix(p, "/") {
				hostP = filepath.Join(rootFS, strings.TrimPrefix(p, "/"))
			}
			_, statErr := os.Stat(hostP)
			isMissing := errors.Is(statErr, os.ErrNotExist) || os.IsNotExist(statErr)

			isUnowned := false
			if pkgDB != nil && pkgDB.IsAvailable() {
				if _, ok := pkgDB.Owner(p); !ok {
					isUnowned = true
				}
			}

			if !isHidden && !isMissing && !isUnowned {
				// Benign package-owned binary on disk: do not correlate
				continue
			}

			if isMissing {
				targetMissing[p] = true
			}
			if targetRefs[p] == nil {
				targetRefs[p] = make(map[string]map[string]bool)
			}
			if targetRefs[p][artifact] == nil {
				targetRefs[p][artifact] = make(map[string]bool)
			}
			targetRefs[p][artifact][sourceFile] = true

			// If payload is located inside a hidden system directory, also index the hidden directory
			if hDir := extractHiddenDirPrefix(p); hDir != "" && hDir != p && hDir != "/" {
				if targetRefs[hDir] == nil {
					targetRefs[hDir] = make(map[string]map[string]bool)
				}
				if targetRefs[hDir][artifact] == nil {
					targetRefs[hDir][artifact] = make(map[string]bool)
				}
				targetRefs[hDir][artifact][sourceFile] = true
			}
		}
	}

	var results []report.Finding
	var sortedTargets []string
	for p := range targetRefs {
		sortedTargets = append(sortedTargets, p)
	}
	sort.Strings(sortedTargets)

	for _, p := range sortedTargets {
		artMap := targetRefs[p]
		if len(artMap) >= 3 {
			var artList []string
			var fileList []string
			for art, files := range artMap {
				artList = append(artList, art)
				for file := range files {
					fileList = append(fileList, file)
				}
			}
			sort.Strings(artList)
			sort.Strings(fileList)

			strength := classifyMultiVectorPayload(p, artMap, targetMissing[p])

			sev := report.SeverityAlert
			score := 95
			highConf := true
			distinctStrong := len(artList)
			payloadNote := ""
			if strength.downgrade {
				// User-home payload, present on disk, referenced only by
				// user-session mechanisms (profile/xdg_autostart): keep the
				// observation visible but stop short of MALICIOUS/CRITICAL.
				sev = report.SeverityWarning
				score = 65
				highConf = false
				distinctStrong = 0
				payloadNote = " [downgraded: user-home payload present on disk, referenced only by user-session mechanisms; re-run as root to confirm full visibility]"
			}

			reason := fmt.Sprintf("Multi-vector persistence: payload %s referenced across %d distinct persistence mechanisms: %s (files: %s)%s",
				p, len(artList), strings.Join(artList, ", "), strings.Join(fileList, ", "), payloadNote)

			f := report.NewFinding("persistence", sev, p, reason, "Persistence_Multi_Vector_Persistence")
			f.Metadata["score"] = score
			f.Metadata["high_confidence"] = highConf
			f.Metadata["payload"] = p
			f.Metadata["mechanisms"] = artList
			f.Metadata["referencing_files"] = fileList
			f.Metadata["classes_count"] = len(artList)
			f.Metadata["distinct_strong_classes"] = distinctStrong
			if strength.downgrade {
				f.Metadata["user_session_only"] = true
			}

			results = append(results, f)
		}
	}

	return results
}

func extractHiddenDirPrefix(p string) string {
	clean := filepath.Clean(p)
	parts := strings.Split(clean, "/")
	var res []string
	foundHidden := false
	for _, part := range parts {
		if part == "" {
			continue
		}
		res = append(res, part)
		if strings.HasPrefix(part, ".") && part != "." && part != ".." {
			foundHidden = true
			break
		}
	}
	if foundHidden && len(res) > 0 {
		return "/" + strings.Join(res, "/")
	}
	return ""
}
