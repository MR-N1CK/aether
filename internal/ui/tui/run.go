package tui

import (
	"context"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"aether/internal/events"
	"aether/internal/ui/theme"
)

// Run launches the Bubble Tea interactive TUI with robust terminal restoration
// guarantees across normal exit, scan cancellation, Ctrl+C, and unexpected panic.
func Run(ctx context.Context, cancel context.CancelFunc, sub *events.Subscription, th *theme.Theme, noAnim bool, mode string, threads int, paths []string, reportPath ...string) error {
	// Recover hook to ensure cursor and alternate screen restoration on panic
	defer func() {
		if r := recover(); r != nil {
			// ANSI restore sequences: disable alternate screen buffer, restore cursor visibility
			fmt.Fprint(os.Stderr, "\033[?1049l\033[?25h")
			panic(r)
		}
	}()

	m := NewModel(ctx, cancel, sub, th, noAnim, mode, threads, paths, reportPath...)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())

	// Handle parent context cancellation (e.g. SIGTERM)
	go func() {
		<-ctx.Done()
		p.Quit()
	}()

	_, err := p.Run()

	// Explicit terminal sanity check upon return
	fmt.Fprint(os.Stderr, "\033[?1049l\033[?25h")

	return err
}
