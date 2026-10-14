package plain

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"aether/internal/events"
	"aether/internal/ui/theme"
)

// RenderScanHeader prints a modern, structured system and scan profile box.
func RenderScanHeader(w io.Writer, ev events.ScanStarted, th *theme.Theme) {
	if th == nil {
		th = theme.NewTheme(theme.DetectNoColor())
	}

	host, _ := os.Hostname()
	if host == "" {
		host = "unknown-host"
	}

	privStr := fmt.Sprintf("non-root (uid=%d)", os.Geteuid())
	if os.Geteuid() == 0 {
		privStr = "root (uid=0) - FULL PRIVILEGES"
	}

	targetStr := strings.Join(ev.Paths, ", ")
	if len(targetStr) > 40 {
		targetStr = targetStr[:37] + "..."
	}

	bName := ev.BinaryName
	if bName == "" {
		bName = "aether"
	}
	verStr := ev.Version
	if verStr == "" {
		verStr = "0.1.0-dev"
	}

	if th.NoColor {
		fmt.Fprintf(w, "+-------------------------------------------------------------------------+\n")
		fmt.Fprintf(w, "| AETHER - Linux Threat Hunt & Defensive Security Scanner                 |\n")
		fmt.Fprintf(w, "| Version: %-15s Mode: %-10s Target: %-25s |\n", verStr, ev.Mode, targetStr)
		fmt.Fprintf(w, "| Host:    %-15s OS: %s/%s CPU Cores: %-20d |\n", host, runtime.GOOS, runtime.GOARCH, ev.Threads)
		fmt.Fprintf(w, "| Privs:   %-40s Threads: %-12d |\n", privStr, ev.Threads)
		fmt.Fprintf(w, "+-------------------------------------------------------------------------+\n\n")
		return
	}

	// Rich Lipgloss Box Header
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#38BDF8"))

	subStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#8B949E"))

	keyStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#38BDF8")).
		Bold(true)

	valStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F0F6FC"))

	modeLabel := strings.ToUpper(ev.Mode) + " HUNT"
	if ev.Mode == "full" {
		modeLabel = "FULL REAL-WORLD AUDIT"
	}
	badgeMode := lipgloss.NewStyle().
		Background(lipgloss.Color("#0284C7")).
		Foreground(lipgloss.Color("#FFFFFF")).
		Padding(0, 1).
		Bold(true).
		Render(modeLabel)

	headerBanner := fmt.Sprintf("%s  %s  %s",
		titleStyle.Render("A E T H E R"),
		subStyle.Render("::  Linux Threat Hunter  ::  v"+verStr),
		badgeMode,
	)

	row1 := fmt.Sprintf("%s %-20s  %s %-20s  %s %d cores",
		keyStyle.Render("Host:"), valStyle.Render(host),
		keyStyle.Render("Kernel:"), valStyle.Render(runtime.GOARCH),
		keyStyle.Render("CPU:"), ev.Threads,
	)

	row2 := fmt.Sprintf("%s %-20s  %s %-20s  %s %s",
		keyStyle.Render("Target:"), valStyle.Render(targetStr),
		keyStyle.Render("Threads:"), valStyle.Render(fmt.Sprintf("%d workers", ev.Threads)),
		keyStyle.Render("Privs:"), valStyle.Render(privStr),
	)

	boxContent := fmt.Sprintf("%s\n\n%s\n%s", headerBanner, row1, row2)

	card := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#38BDF8")).
		Padding(0, 2).
		MarginBottom(1).
		Render(boxContent)

	fmt.Fprintln(w, card)
}
