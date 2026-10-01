package tui

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"aether/internal/events"
	"aether/internal/report"
	"aether/internal/ui/theme"
)

type tuiState int

const (
	stateSplash tuiState = iota
	stateDashboard
	stateDetail
	stateFinished
)

type frameTickMsg time.Time
type splashTickMsg int

// ModuleStatus tracks per-module execution state in the UI.
type ModuleStatus struct {
	Name        string
	Description string
	Running     bool
	Finished    bool
	Duration    time.Duration
	Findings    int
	Err         error
	Status      string
}

// Model is the Bubble Tea model managing the interactive scanner interface.
type Model struct {
	ctx           context.Context
	cancelScan    context.CancelFunc
	sub           *events.Subscription
	theme         *theme.Theme
	noAnim        bool
	state         tuiState

	// Terminal dimensions
	width  int
	height int

	// Splash animation state
	splashFrame int
	maxSplash   int

	// Scan metrics
	startTime     time.Time
	elapsed       time.Duration
	mode          string
	threads       int
	hostname      string
	paths         []string
	filesScanned  int64
	filesPerSec   float64
	activeModules map[string]*ModuleStatus
	moduleOrder   []string

	// Findings
	findings       []report.Finding
	filtered       []report.Finding
	selectedIndex  int
	isFiltering    bool
	filterQuery    string

	// Completion metrics
	scanFinished   bool
	finishEvent    *events.ScanFinished

	// UI components
	spinner spinner.Model
}

// NewModel constructs a new interactive TUI model.
func NewModel(ctx context.Context, cancel context.CancelFunc, sub *events.Subscription, th *theme.Theme, noAnim bool, mode string, threads int, paths []string) Model {
	if th == nil {
		th = theme.NewTheme(theme.DetectNoColor())
	}

	host, _ := os.Hostname()
	if host == "" {
		host = "linux-endpoint"
	}

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = th.BadgeNotice

	initialState := stateSplash
	if noAnim {
		initialState = stateDashboard
	}

	return Model{
		ctx:           ctx,
		cancelScan:    cancel,
		sub:           sub,
		theme:         th,
		noAnim:        noAnim,
		state:         initialState,
		splashFrame:   0,
		maxSplash:     20, // ~1s at 50ms per step
		startTime:     time.Now(),
		mode:          strings.ToUpper(mode),
		threads:       threads,
		hostname:      host,
		paths:         paths,
		activeModules: make(map[string]*ModuleStatus),
		findings:      make([]report.Finding, 0),
		filtered:      make([]report.Finding, 0),
		spinner:       sp,
	}
}

// Init kicks off the initial ticks and listeners.
func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{
		m.spinner.Tick,
		m.listenEvents(),
		m.tick30FPS(),
	}

	if m.state == stateSplash {
		cmds = append(cmds, m.tickSplash(0))
	}

	return tea.Batch(cmds...)
}

func (m Model) listenEvents() tea.Cmd {
	return func() tea.Msg {
		e, ok := <-m.sub.Events()
		if !ok {
			return nil
		}
		return e
	}
}

func (m Model) tick30FPS() tea.Cmd {
	return tea.Tick(33*time.Millisecond, func(t time.Time) tea.Msg {
		return frameTickMsg(t)
	})
}

func (m Model) tickSplash(frame int) tea.Cmd {
	return tea.Tick(50*time.Millisecond, func(t time.Time) tea.Msg {
		return splashTickMsg(frame + 1)
	})
}

// Update handles incoming events, keyboard input, and render ticks.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case splashTickMsg:
		if m.state == stateSplash {
			m.splashFrame = int(msg)
			if m.splashFrame >= m.maxSplash {
				m.state = stateDashboard
			} else {
				cmds = append(cmds, m.tickSplash(m.splashFrame))
			}
		}

	case frameTickMsg:
		if !m.scanFinished {
			m.elapsed = time.Since(m.startTime)
		}
		var spCmd tea.Cmd
		m.spinner, spCmd = m.spinner.Update(msg)
		cmds = append(cmds, spCmd, m.tick30FPS())

	case events.Event:
		m.handleScanEvent(msg)
		cmds = append(cmds, m.listenEvents())

	case tea.KeyMsg:
		cmd := m.handleKey(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

func (m *Model) handleScanEvent(e events.Event) {
	switch ev := e.(type) {
	case events.ScanStarted:
		m.mode = strings.ToUpper(ev.Mode)
		m.threads = ev.Threads
		m.paths = ev.Paths

	case events.ModuleStarted:
		if _, exists := m.activeModules[ev.ModuleName]; !exists {
			m.moduleOrder = append(m.moduleOrder, ev.ModuleName)
		}
		m.activeModules[ev.ModuleName] = &ModuleStatus{
			Name:        ev.ModuleName,
			Description: ev.Description,
			Running:     true,
		}

	case events.ModuleFinished:
		if mod, exists := m.activeModules[ev.ModuleName]; exists {
			mod.Running = false
			mod.Finished = true
			mod.Duration = ev.Duration
			mod.Findings = ev.FindingsCount
			mod.Err = ev.Err
			mod.Status = ev.Status
		}

	case events.FileScanned:
		m.filesScanned++

	case events.FindingRaised:
		m.findings = append(m.findings, ev.Finding)
		m.applyFilter()
		if mod, exists := m.activeModules[ev.Finding.Module]; exists {
			mod.Findings++
		}

	case events.Progress:
		m.filesScanned = ev.CurrentFiles
		m.filesPerSec = ev.FilesPerSec

	case events.ScanFinished:
		m.scanFinished = true
		m.finishEvent = &ev
		m.filesScanned = ev.FilesScanned
		m.elapsed = ev.TotalDuration
		if m.state != stateDetail {
			m.state = stateFinished
		}
	}
}

func (m *Model) handleKey(msg tea.KeyMsg) tea.Cmd {
	// Any key during splash skips to dashboard
	if m.state == stateSplash {
		m.state = stateDashboard
		return nil
	}

	// Filter input mode
	if m.isFiltering {
		switch msg.Type {
		case tea.KeyEnter:
			m.isFiltering = false
			return nil
		case tea.KeyEsc:
			m.isFiltering = false
			m.filterQuery = ""
			m.applyFilter()
			return nil
		case tea.KeyBackspace:
			if len(m.filterQuery) > 0 {
				m.filterQuery = m.filterQuery[:len(m.filterQuery)-1]
				m.applyFilter()
			}
			return nil
		case tea.KeyRunes:
			m.filterQuery += string(msg.Runes)
			m.applyFilter()
			return nil
		}
		return nil
	}

	// Detail modal mode
	if m.state == stateDetail {
		switch msg.String() {
		case "esc", "enter", "q":
			if m.scanFinished {
				m.state = stateFinished
			} else {
				m.state = stateDashboard
			}
		}
		return nil
	}

	// Normal navigation & dashboard controls
	switch msg.String() {
	case "ctrl+c", "q":
		if m.cancelScan != nil {
			m.cancelScan()
		}
		return tea.Quit

	case "up", "k":
		if m.selectedIndex > 0 {
			m.selectedIndex--
		}

	case "down", "j":
		if m.selectedIndex < len(m.currentList())-1 {
			m.selectedIndex++
		}

	case "pgup":
		m.selectedIndex -= 5
		if m.selectedIndex < 0 {
			m.selectedIndex = 0
		}

	case "pgdown":
		m.selectedIndex += 5
		list := m.currentList()
		if m.selectedIndex >= len(list) {
			m.selectedIndex = len(list) - 1
		}
		if m.selectedIndex < 0 {
			m.selectedIndex = 0
		}

	case "enter":
		list := m.currentList()
		if len(list) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(list) {
			m.state = stateDetail
		}

	case "/":
		m.isFiltering = true
	}

	return nil
}

func (m *Model) currentList() []report.Finding {
	if m.filterQuery != "" {
		return m.filtered
	}
	return m.findings
}

func (m *Model) applyFilter() {
	if m.filterQuery == "" {
		m.filtered = m.findings
		return
	}

	q := strings.ToLower(m.filterQuery)
	filtered := make([]report.Finding, 0)
	for _, f := range m.findings {
		if strings.Contains(strings.ToLower(f.Path), q) ||
			strings.Contains(strings.ToLower(f.Reason), q) ||
			strings.Contains(strings.ToLower(f.Module), q) ||
			strings.Contains(strings.ToLower(string(f.Severity)), q) ||
			strings.Contains(strings.ToLower(f.RuleName), q) {
			filtered = append(filtered, f)
		}
	}
	m.filtered = filtered
	if m.selectedIndex >= len(filtered) {
		m.selectedIndex = 0
	}
}

// SelectedFinding returns the currently highlighted finding if any.
func (m *Model) SelectedFinding() *report.Finding {
	list := m.currentList()
	if len(list) == 0 || m.selectedIndex < 0 || m.selectedIndex >= len(list) {
		return nil
	}
	return &list[m.selectedIndex]
}
