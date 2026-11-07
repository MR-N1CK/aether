package plain

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"

	"aether/internal/ui/theme"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// LiveDashboard manages real-time scan progress rendering without flooding stdout.
type LiveDashboard struct {
	writer       io.Writer
	th           *theme.Theme
	isTTY        bool
	frameIdx     int
	lastRender   time.Time
	alerts       int
	warnings     int
	notices      int
	infos        int
	activeMod    string
	filesSec     float64
	totalScanned int64
}

// NewLiveDashboard initializes a live dashboard instance.
func NewLiveDashboard(w io.Writer, th *theme.Theme, isTTY bool) *LiveDashboard {
	return &LiveDashboard{
		writer: w,
		th:     th,
		isTTY:  isTTY,
	}
}

// UpdateCounters updates current finding counts.
func (d *LiveDashboard) UpdateCounters(alerts, warnings, notices, infos int) {
	d.alerts = alerts
	d.warnings = warnings
	d.notices = notices
	d.infos = infos
}

// RenderProgress renders the live progress bar and counters.
func (d *LiveDashboard) RenderProgress(filesScanned int64, filesPerSec float64, elapsed time.Duration, activeModule string) {
	d.totalScanned = filesScanned
	d.filesSec = filesPerSec
	d.activeMod = activeModule
	d.frameIdx = (d.frameIdx + 1) % len(spinnerFrames)

	if !d.isTTY {
		// Non-interactive / CI milestone logging every 5 seconds
		if time.Since(d.lastRender) >= 5*time.Second {
			d.lastRender = time.Now()
			fmt.Fprintf(d.writer, "[-] Scan in progress: %d files scanned (%.0f files/sec, %s elapsed, active: %s) [Alerts: %d, Warnings: %d, Notices: %d]\n",
				filesScanned, filesPerSec, elapsed.Round(time.Second), activeModule, d.alerts, d.warnings, d.notices)
		}
		return
	}

	// Interactive TTY rendering
	spinner := spinnerFrames[d.frameIdx]
	if d.th.NoColor {
		fmt.Fprintf(d.writer, "\r[%s] Scanning (%s) - %d files (%.0f/s) | Alerts: %d, Warnings: %d, Notices: %d, Infos: %d",
			spinner, activeModule, filesScanned, filesPerSec, d.alerts, d.warnings, d.notices, d.infos)
		return
	}

	spinStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#22D3EE")).Bold(true).Render(spinner)
	modStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#A78BFA")).Bold(true).Render(activeModule)
	statsStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#E6EDF7")).Render(fmt.Sprintf("%d files (%.0f/s, %s)", filesScanned, filesPerSec, elapsed.Round(time.Second)))

	badgeAlert := lipgloss.NewStyle().Background(lipgloss.Color("#F43F5E")).Foreground(lipgloss.Color("#FFFFFF")).Bold(true).Padding(0, 1).Render(fmt.Sprintf("%d Alerts", d.alerts))
	badgeWarn := lipgloss.NewStyle().Background(lipgloss.Color("#FBBF24")).Foreground(lipgloss.Color("#000000")).Bold(true).Padding(0, 1).Render(fmt.Sprintf("%d Warnings", d.warnings))
	badgeNotice := lipgloss.NewStyle().Background(lipgloss.Color("#34D399")).Foreground(lipgloss.Color("#000000")).Bold(true).Padding(0, 1).Render(fmt.Sprintf("%d Notices", d.notices))
	badgeInfo := lipgloss.NewStyle().Background(lipgloss.Color("#24334F")).Foreground(lipgloss.Color("#E6EDF7")).Padding(0, 1).Render(fmt.Sprintf("%d Infos", d.infos))

	line := fmt.Sprintf("\r %s  [%s] %s  │  %s %s %s %s   ",
		spinStyle, modStyle, statsStyle,
		badgeAlert, badgeWarn, badgeNotice, badgeInfo,
	)

	fmt.Fprint(d.writer, line)
}

// ClearLine clears the active progress line before printing findings or final verdicts.
func (d *LiveDashboard) ClearLine() {
	if d.isTTY {
		fmt.Fprint(d.writer, "\r\033[K")
	}
}

// Helper to determine TTY status on writer
func IsTerminalWriter(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		return isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
	}
	return false
}
