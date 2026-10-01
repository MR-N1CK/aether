package plain

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aether/internal/events"
	"aether/internal/report"
	"aether/internal/ui/theme"
)

type errorGroup struct {
	dir   string
	count int
}

// Consumer prints scan events as deterministic, clean text lines without
// animations or raw terminal control sequences.
type Consumer struct {
	writer              io.Writer
	theme               *theme.Theme
	verbose             bool
	permErrors          map[string]int
	vanishedErrors      map[string]int
	totalPermErrors     int
	totalVanishedErrors int
}

// NewConsumer initializes a plain output renderer.
func NewConsumer(w io.Writer, th *theme.Theme, verbose bool) *Consumer {
	if w == nil {
		w = os.Stdout
	}
	if th == nil {
		th = theme.NewTheme(theme.DetectNoColor())
	}
	return &Consumer{
		writer:         w,
		theme:          th,
		verbose:        verbose,
		permErrors:     make(map[string]int),
		vanishedErrors: make(map[string]int),
	}
}

// Consume processes events from a subscription until the channel is closed,
// a ScanFinished event is rendered, or context cancelled.
func (c *Consumer) Consume(ctx context.Context, sub *events.Subscription) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e, ok := <-sub.Events():
			if !ok {
				return nil
			}
			if c.renderEvent(e) {
				return nil
			}
		}
	}
}

func (c *Consumer) renderEvent(e events.Event) bool {
	switch ev := e.(type) {
	case events.ScanStarted:
		if os.Geteuid() != 0 {
			fmt.Fprintf(c.writer, "[AETHER] [NOTICE] Running as non-root (euid=%d): coverage is limited (privileged files cannot be accessed); run with sudo for complete coverage.\n", os.Geteuid())
		}
		for _, n := range ev.Notices {
			fmt.Fprintf(c.writer, "[AETHER] [NOTICE] %s\n", n)
		}
		verStr := ""
		if ev.Version != "" {
			bName := ev.BinaryName
			if bName == "" {
				bName = "aether"
			}
			bDate := ev.BuildDate
			if bDate == "" {
				bDate = "unknown"
			}
			verStr = fmt.Sprintf("aether %s build %s (%s) - ", ev.Version, bDate, bName)
		}
		fmt.Fprintf(c.writer, "[AETHER] [%s] %sScan started. Mode: %s, Threads: %d, Target Paths: %v\n",
			ev.Time.Format(time.RFC3339), verStr, ev.Mode, ev.Threads, ev.Paths)

	case events.ModuleStarted:
		fmt.Fprintf(c.writer, "[AETHER] [%s] Module started: %s (%s)\n",
			ev.Time.Format(time.RFC3339), ev.ModuleName, ev.Description)

	case events.ModuleFinished:
		status := ev.Status
		if status == "" {
			if ev.Err != nil {
				status = "FAILED"
			} else {
				status = "OK"
			}
		}
		fmt.Fprintf(c.writer, "[AETHER] [%s] Module finished: %s (Duration: %v, Findings: %d, Inspected: %d, Status: %s)\n",
			ev.Time.Format(time.RFC3339), ev.ModuleName, ev.Duration.Round(time.Millisecond), ev.FindingsCount, ev.InspectedCount, status)
		if status == "FAILED" && ev.Err != nil {
			fmt.Fprintf(c.writer, "[AETHER] [NOTICE] Module %s failed: %v\n", ev.ModuleName, ev.Err)
		}

	case events.FindingRaised:
		if ev.Finding.Severity == report.SeverityInfo && !c.verbose {
			return false
		}
		badge := c.theme.SeverityBadge(ev.Finding.Severity)
		fmt.Fprintf(c.writer, "%s [%s] [%s] %s - %s (Rule: %s)\n",
			badge,
			ev.Finding.Timestamp.Format("15:04:05-07:00"),
			ev.Finding.Module,
			ev.Finding.Path,
			ev.Finding.Reason,
			ev.Finding.RuleName,
		)

	case events.Error:
		if ev.IsFatal {
			module := ev.Module
			if module == "" {
				module = "filesystem"
			}
			fmt.Fprintf(c.writer, "[ERROR] [%s] [%s] %v (Path: %s)\n",
				ev.Time.Format(time.RFC3339), module, ev.Err, ev.Path)
			return true
		}
		// Non-fatal errors are grouped by parent directory and reported at scan finish with -v
		parentDir := filepath.Dir(ev.Path)
		if os.IsPermission(ev.Err) || strings.Contains(strings.ToLower(ev.Err.Error()), "permission denied") {
			c.totalPermErrors++
			c.permErrors[parentDir]++
		} else if os.IsNotExist(ev.Err) || strings.Contains(strings.ToLower(ev.Err.Error()), "no such file") {
			c.totalVanishedErrors++
			c.vanishedErrors[parentDir]++
		} else if c.verbose {
			module := ev.Module
			if module == "" {
				module = "filesystem"
			}
			fmt.Fprintf(c.writer, "[ERROR] [%s] [%s] %v (Path: %s)\n",
				ev.Time.Format(time.RFC3339), module, ev.Err, ev.Path)
		}

	case events.ScanFinished:
		fmt.Fprintf(c.writer, "\n[AETHER] ========================================================\n")
		fmt.Fprintf(c.writer, "[AETHER] Threat hunt scan completed in %v\n", ev.TotalDuration.Round(time.Millisecond))
		if ev.AffectedFiles > 0 && ev.AffectedFiles != ev.TotalFindings {
			fmt.Fprintf(c.writer, "[AETHER] Files Inspected: %d | Total Findings: %d (Affected Files: %d)\n", ev.FilesScanned, ev.TotalFindings, ev.AffectedFiles)
		} else {
			fmt.Fprintf(c.writer, "[AETHER] Files Inspected: %d | Total Findings: %d\n", ev.FilesScanned, ev.TotalFindings)
		}
		if ev.Coverage.TotalSkipped() > 0 {
			fmt.Fprintf(c.writer, "[AETHER] Files Skipped: %d (Oversize: %d, Perm Denied: %d, Vanished: %d, Non-Regular: %d, Excluded: %d)\n",
				ev.Coverage.TotalSkipped(),
				ev.Coverage.SkippedOversize,
				ev.Coverage.SkippedPermission,
				ev.Coverage.SkippedVanished,
				ev.Coverage.SkippedNotRegular,
				ev.Coverage.SkippedExcluded,
			)
		}
		if len(ev.Coverage.OversizeFiles) > 0 {
			limit := 20
			if len(ev.Coverage.OversizeFiles) < limit {
				limit = len(ev.Coverage.OversizeFiles)
			}
			for i := 0; i < limit; i++ {
				of := ev.Coverage.OversizeFiles[i]
				fmt.Fprintf(c.writer, "[AETHER] not inspected (oversize, not hashed): %s, %d bytes\n", of.Path, of.Size)
			}
			if len(ev.Coverage.OversizeFiles) > limit {
				fmt.Fprintf(c.writer, "[AETHER]   ... and %d more oversize files (full list in JSON report)\n", len(ev.Coverage.OversizeFiles)-limit)
			}
		}
		if ev.Coverage.Suppressed > 0 {
			fmt.Fprintf(c.writer, "[AETHER] Suppressed: %d\n", ev.Coverage.Suppressed)
		}
		if ev.Coverage.Acknowledged > 0 {
			fmt.Fprintf(c.writer, "[AETHER] Acknowledged: %d\n", ev.Coverage.Acknowledged)
		}
		if c.verbose && len(ev.Coverage.TopInspectedDirs) > 0 {
			fmt.Fprintf(c.writer, "[AETHER] Top Inspected Directories:\n")
			for _, dc := range ev.Coverage.TopInspectedDirs {
				fmt.Fprintf(c.writer, "[AETHER]   - %s: %d files\n", dc.Dir, dc.Count)
			}
		}
		if c.verbose && c.totalPermErrors > 0 {
			var groups []errorGroup
			for d, count := range c.permErrors {
				groups = append(groups, errorGroup{dir: d, count: count})
			}
			sort.Slice(groups, func(i, j int) bool {
				if groups[i].count != groups[j].count {
					return groups[i].count > groups[j].count
				}
				return groups[i].dir < groups[j].dir
			})
			limit := 15
			if len(groups) < limit {
				limit = len(groups)
			}
			fmt.Fprintf(c.writer, "[AETHER] Permission denied (%d):\n", c.totalPermErrors)
			for i := 0; i < limit; i++ {
				fmt.Fprintf(c.writer, "[AETHER]   - %s: %d\n", groups[i].dir, groups[i].count)
			}
			if len(groups) > limit {
				rem := 0
				for i := limit; i < len(groups); i++ {
					rem += groups[i].count
				}
				fmt.Fprintf(c.writer, "[AETHER]   - and %d more in %d directories\n", rem, len(groups)-limit)
			}
		}
		if c.verbose && c.totalVanishedErrors > 0 {
			var groups []errorGroup
			for d, count := range c.vanishedErrors {
				groups = append(groups, errorGroup{dir: d, count: count})
			}
			sort.Slice(groups, func(i, j int) bool {
				if groups[i].count != groups[j].count {
					return groups[i].count > groups[j].count
				}
				return groups[i].dir < groups[j].dir
			})
			limit := 15
			if len(groups) < limit {
				limit = len(groups)
			}
			fmt.Fprintf(c.writer, "[AETHER] Vanished (%d):\n", c.totalVanishedErrors)
			for i := 0; i < limit; i++ {
				fmt.Fprintf(c.writer, "[AETHER]   - %s: %d\n", groups[i].dir, groups[i].count)
			}
			if len(groups) > limit {
				rem := 0
				for i := limit; i < len(groups); i++ {
					rem += groups[i].count
				}
				fmt.Fprintf(c.writer, "[AETHER]   - and %d more in %d directories\n", rem, len(groups)-limit)
			}
		}
		if ev.ProcessCoverage != nil {
			fmt.Fprintf(c.writer, "[AETHER] Process Coverage: Inspected: %d, Limited: %d, Perm Denied: %d, Vanished: %d, Kernel Threads: %d, Zombies: %d, Non-Root: %v, Hidden-PID Range: %s, Not Hashed: %d\n",
				ev.ProcessCoverage.Inspected,
				ev.ProcessCoverage.Limited,
				ev.ProcessCoverage.SkippedPermission,
				ev.ProcessCoverage.SkippedVanished,
				ev.ProcessCoverage.KernelThreads,
				ev.ProcessCoverage.Zombies,
				ev.ProcessCoverage.NonRootLimited,
				ev.ProcessCoverage.HiddenPIDRange,
				ev.ProcessCoverage.NotHashed,
			)
			if c.verbose && ev.ProcessCoverage.DurationBreakdown != nil {
				bd := ev.ProcessCoverage.DurationBreakdown
				fmt.Fprintf(c.writer, "[AETHER] Process Timings: procfs: %v, hashing: %v, hidden-pid pass 1: %v, hidden-pid pass 2: %v, total: %v\n",
					bd.Procfs.Round(time.Millisecond),
					bd.Hashing.Round(time.Millisecond),
					bd.HiddenPass1.Round(time.Millisecond),
					bd.HiddenPass2.Round(time.Millisecond),
					bd.Total.Round(time.Millisecond),
				)
			}
		}
		if ev.PersistenceCoverage != nil {
			pkgStatus := "available"
			if !ev.PersistenceCoverage.PkgDBAvailable {
				pkgStatus = "unavailable"
				if ev.PersistenceCoverage.PkgDBNote != "" {
					pkgStatus = ev.PersistenceCoverage.PkgDBNote
				}
			}
			fmt.Fprintf(c.writer, "[AETHER] Persistence Coverage: Inspected: %d, Unreadable: %d, Masked: %d, Not Present: %d, Package DB: %s\n",
				ev.PersistenceCoverage.TotalInspected,
				ev.PersistenceCoverage.TotalUnreadable,
				ev.PersistenceCoverage.TotalMasked,
				ev.PersistenceCoverage.NotPresent,
				pkgStatus,
			)
			if c.verbose && len(ev.PersistenceCoverage.MaskedPaths) > 0 {
				fmt.Fprintf(c.writer, "[AETHER] Persistence Masked Units:\n")
				for _, mp := range ev.PersistenceCoverage.MaskedPaths {
					fmt.Fprintf(c.writer, "[AETHER]   - %s\n", mp)
				}
			}
			if c.verbose && len(ev.PersistenceCoverage.UnreadablePaths) > 0 {
				fmt.Fprintf(c.writer, "[AETHER] Persistence Unreadable Paths:\n")
				for _, up := range ev.PersistenceCoverage.UnreadablePaths {
					fmt.Fprintf(c.writer, "[AETHER]   - %s: %s\n", up.Path, up.Reason)
				}
			}
		}
		if ev.YARACoverage != nil {
			if !ev.YARACoverage.CompiledIn {
				fmt.Fprintf(c.writer, "[AETHER] YARA not run: %s\n", ev.YARACoverage.NotRunReason)
			} else if ev.YARACoverage.NotRunReason != "" {
				fmt.Fprintf(c.writer, "[AETHER] YARA not run: %s\n", ev.YARACoverage.NotRunReason)
			} else if ev.YARACoverage.DemoRulesOnly {
				fmt.Fprintf(c.writer, "[AETHER] YARA: demo rules only, no real rule set loaded (Rules Loaded: %d, Scanned: %d)\n",
					ev.YARACoverage.RulesLoaded, ev.YARACoverage.FilesScanned)
			} else {
				ruleFilesSeenStr := ""
				if ev.YARACoverage.RuleFilesSeen > 0 {
					ruleFilesSeenStr = fmt.Sprintf(", Rule Files Seen: %d", ev.YARACoverage.RuleFilesSeen)
				}
				fmt.Fprintf(c.writer, "[AETHER] YARA Coverage: Rules Loaded: %d (Failed: %d), Scanned: %d%s, Oversize: %d, Timeout: %d, Error: %d\n",
					ev.YARACoverage.RulesLoaded,
					ev.YARACoverage.RulesFailed,
					ev.YARACoverage.FilesScanned,
					ruleFilesSeenStr,
					ev.YARACoverage.SkippedOversize,
					ev.YARACoverage.SkippedTimeout,
					ev.YARACoverage.SkippedError,
				)
			}
		}
		if os.Geteuid() != 0 {
			fmt.Fprintf(c.writer, "[AETHER] [NOTICE] Running as non-root: other users' processes were not inspected (partial coverage).\n")
		}
		if len(ev.ModulesNotRun) > 0 {
			fmt.Fprintf(c.writer, "[AETHER] Modules Not Run: %s\n", strings.Join(ev.ModulesNotRun, ", "))
		}
		if len(ev.TopRules) > 0 {
			fmt.Fprintf(c.writer, "[AETHER] Top Rules:\n")
			limit := 5
			if len(ev.TopRules) < limit {
				limit = len(ev.TopRules)
			}
			for i := 0; i < limit; i++ {
				tr := ev.TopRules[i]
				ackTag := ""
				if tr.Acknowledged {
					ackTag = " (acknowledged)"
				}
				fmt.Fprintf(c.writer, "[AETHER]   - [%s] %s%s: %d\n", tr.Severity, tr.RuleName, ackTag, tr.Count)
			}
		}
		if len(ev.AcknowledgedWarnings) > 0 {
			fmt.Fprintf(c.writer, "[AETHER] Acknowledged Warnings:\n")
			for _, aw := range ev.AcknowledgedWarnings {
				fmt.Fprintf(c.writer, "[AETHER]   - %s (%s)\n", aw.Path, aw.RuleName)
			}
		}
		fmt.Fprintf(c.writer, "[AETHER] Breakdown -> Alerts: %d, Warnings: %d, Notices: %d, Infos: %d\n",
			ev.Alerts, ev.Warnings, ev.Notices, ev.Infos)
		verdictLine := string(ev.Verdict)
		if ev.VerdictReason != "" {
			verdictLine = ev.VerdictReason
		}
		var notes []string
		if ev.Partial {
			notes = append(notes, "partial coverage")
		}
		if len(ev.ModulesNotRun) > 0 {
			notes = append(notes, fmt.Sprintf("modules not run: %s", strings.Join(ev.ModulesNotRun, ", ")))
		}
		if len(notes) > 0 {
			verdictLine += fmt.Sprintf(" (%s)", strings.Join(notes, ", "))
		}
		fmt.Fprintf(c.writer, "[AETHER] Final Verdict: %s\n", verdictLine)
		fmt.Fprintf(c.writer, "[AETHER] ========================================================\n\n")
		return true
	}
	return false
}
