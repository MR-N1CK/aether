package plain

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aether/internal/events"
	"aether/internal/report"
	"aether/internal/ui/theme"
)

// Consumer prints scan events as a professional, executive terminal experience.
type Consumer struct {
	writer              io.Writer
	theme               *theme.Theme
	verbose             bool
	dashboard           *LiveDashboard
	permErrors          map[string]int
	vanishedErrors      map[string]int
	totalPermErrors     int
	totalVanishedErrors int
	alertsCount         int
	warningsCount       int
	noticesCount        int
	infosCount          int
}

// NewConsumer initializes an executive terminal output renderer.
func NewConsumer(w io.Writer, th *theme.Theme, verbose bool) *Consumer {
	if w == nil {
		w = os.Stdout
	}
	if th == nil {
		th = theme.NewTheme(theme.DetectNoColor())
	}
	isTTY := IsTerminalWriter(w)
	return &Consumer{
		writer:         w,
		theme:          th,
		verbose:        verbose,
		dashboard:      NewLiveDashboard(w, th, isTTY),
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
		RenderScanHeader(c.writer, ev, c.theme)

	case events.ModuleStarted:
		c.dashboard.activeMod = ev.ModuleName

	case events.ModuleFinished:
		status := ev.Status
		if status == "" {
			if ev.Err != nil {
				status = "FAILED"
			} else {
				status = "OK"
			}
		}
		if status == "FAILED" || ev.Err != nil {
			c.dashboard.ClearLine()
			fmt.Fprintf(c.writer, "Module finished: %s (Status: %s)\n", ev.ModuleName, status)
			if ev.Err != nil {
				fmt.Fprintf(c.writer, "[AETHER] [NOTICE] Module %s failed: %v\n", ev.ModuleName, ev.Err)
			}
		} else if c.verbose {
			c.dashboard.ClearLine()
			fmt.Fprintf(c.writer, "  ✓  [%-14s] %-8s (%d objects inspected, %v)\n",
				ev.ModuleName, status, ev.InspectedCount, ev.Duration.Round(time.Millisecond))
		}

	case events.FindingRaised:
		switch ev.Finding.Severity {
		case report.SeverityCritical, report.SeverityAlert:
			c.alertsCount++
		case report.SeverityHigh, report.SeverityWarning:
			c.warningsCount++
		case report.SeverityMedium, report.SeverityNotice:
			c.noticesCount++
		default:
			c.infosCount++
		}
		c.dashboard.UpdateCounters(c.alertsCount, c.warningsCount, c.noticesCount, c.infosCount)

		if ev.Finding.Severity == report.SeverityInfo && !c.verbose {
			return false
		}

		c.dashboard.ClearLine()
		RenderFindingCard(c.writer, ev.Finding, c.theme)

	case events.Progress:
		active := "filesystem"
		if len(ev.ActiveModules) > 0 {
			active = ev.ActiveModules[0]
		}
		c.dashboard.RenderProgress(ev.CurrentFiles, ev.FilesPerSec, ev.Elapsed, active)

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
		c.dashboard.ClearLine()
		if len(ev.ModulesNotRun) > 0 {
			fmt.Fprintf(c.writer, "Modules Not Run: %s\n", strings.Join(ev.ModulesNotRun, ", "))
		}
		RenderExecutiveVerdict(c.writer, ev, c.theme)
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
		fmt.Fprintf(c.writer, "Final Verdict: %s\n", verdictLine)
		if c.verbose {
			if ev.Coverage.TotalSkipped() > 0 {
				fmt.Fprintf(c.writer, "  Coverage Telemetry: Inspected: %d, Skipped: %d (Perm: %d, Vanished: %d, Non-regular: %d)\n",
					ev.Coverage.FilesScanned, ev.Coverage.TotalSkipped(), ev.Coverage.SkippedPermission, ev.Coverage.SkippedVanished, ev.Coverage.SkippedNotRegular)
			}
		}
		return true
	}
	return false
}
