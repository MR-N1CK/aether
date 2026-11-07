package tui

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"

	"aether/internal/ui/theme"
	"aether/internal/yara"
)

// LauncherAction represents a user choice in the interactive Command Center.
type LauncherAction string

const (
	ActionQuick      LauncherAction = "quick"
	ActionFull       LauncherAction = "full"
	ActionCustom     LauncherAction = "custom"
	ActionSetup      LauncherAction = "setup"
	ActionOpenReport LauncherAction = "open_report"
	ActionDemo       LauncherAction = "demo"
	ActionStatus     LauncherAction = "status"
	ActionExit       LauncherAction = "exit"
)

// LauncherResult contains the selected action and any associated parameters.
type LauncherResult struct {
	Action LauncherAction
	Path   string
}

type menuItem struct {
	id          LauncherAction
	keyNumber   string
	icon        string
	title       string
	description string
	tag         string
}

type launcherState int

const (
	launcherStateMenu launcherState = iota
	launcherStateInputPath
)

// LauncherModel is the Bubble Tea model for the unified interactive Command Center.
type LauncherModel struct {
	theme       *theme.Theme
	state       launcherState
	cursor      int
	items       []menuItem
	textInput   textinput.Model
	width       int
	height      int
	result      LauncherResult
	yaraEnabled bool
	isRoot      bool
	hostname    string
	cpuCores    int
	osArch      string
	version     string
	// animFrame drives the Command Center's staggered card reveal and the
	// selected-card pulse. It advances on launcherTickMsg only when the
	// theme renders color; monochrome/ASCII themes render fully revealed.
	animFrame int
}

// launcherTickMsg advances the Command Center animation state.
type launcherTickMsg time.Time

func tickLauncher() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(t time.Time) tea.Msg {
		return launcherTickMsg(t)
	})
}

// NewLauncherModel creates an initialized LauncherModel with optional version string.
func NewLauncherModel(th *theme.Theme, ver ...string) LauncherModel {
	if th == nil {
		th = theme.NewTheme(theme.DetectNoColor())
	}

	v := "1.0.0"
	if len(ver) > 0 && ver[0] != "" {
		v = ver[0]
	}

	ti := textinput.New()
	ti.Placeholder = "Enter path (e.g. ~/Music or /var/www)"
	ti.Focus()
	ti.CharLimit = 256
	ti.Width = 50

	host, _ := os.Hostname()
	if host == "" {
		host = "linux-endpoint"
	}

	items := []menuItem{
		{
			id:          ActionQuick,
			keyNumber:   "1",
			icon:        "◆",
			title:       "Quick Triage Scan",
			description: "Fast 15-second threat hunt of persistence hooks, active processes, and memory",
			tag:         "RECOMMENDED",
		},
		{
			id:          ActionFull,
			keyNumber:   "2",
			icon:        "▣",
			title:       "Full System Deep Hunt",
			description: "Exhaustive scan across the entire root filesystem and all 7 security modules",
			tag:         "DEEP HUNT",
		},
		{
			id:          ActionCustom,
			keyNumber:   "3",
			icon:        "▤",
			title:       "Target Directory / File Scan",
			description: "Scan any specific folder, download directory, or suspicious file payload",
			tag:         "CUSTOM PATH",
		},
		{
			id:          ActionSetup,
			keyNumber:   "4",
			icon:        "▦",
			title:       "1-Click Rules Setup & Sync",
			description: "Download verified YARA-Forge Core ruleset and harden directory permissions",
			tag:         "SETUP",
		},
		{
			id:          ActionOpenReport,
			keyNumber:   "5",
			icon:        "◈",
			title:       "Open Executive HTML Report",
			description: "View the standalone dark-mode executive threat report with charts & timeline",
			tag:         "REPORT",
		},
		{
			id:          ActionDemo,
			keyNumber:   "6",
			icon:        "◇",
			title:       "Interactive Threat Simulator",
			description: "Run a live simulated threat hunt demonstrating detection capabilities",
			tag:         "SIMULATOR",
		},
		{
			id:          ActionStatus,
			keyNumber:   "7",
			icon:        "≡",
			title:       "Engine Status & Diagnostics",
			description: "Inspect loaded signature counts, memory budgets, and security parameters",
			tag:         "DIAGNOSTICS",
		},
		{
			id:          ActionExit,
			keyNumber:   "q",
			icon:        "✕",
			title:       "Exit",
			description: "Close Aether Command Center",
			tag:         "",
		},
	}

	yaraActive := yara.VersionInfo() != "not compiled in"

	return LauncherModel{
		theme:       th,
		state:       launcherStateMenu,
		cursor:      0,
		items:       items,
		textInput:   ti,
		width:       80,
		height:      24,
		yaraEnabled: yaraActive,
		isRoot:      os.Geteuid() == 0,
		hostname:    host,
		cpuCores:    runtime.NumCPU(),
		osArch:      fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		version:     v,
	}
}

// Init initializes the Bubble Tea launcher.
func (m LauncherModel) Init() tea.Cmd {
	if m.theme.NoColor {
		return textinput.Blink
	}
	return tea.Batch(textinput.Blink, tickLauncher())
}

// Update handles UI events in the launcher.
func (m LauncherModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case launcherTickMsg:
		m.animFrame++
		return m, tickLauncher()

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		if m.state == launcherStateInputPath {
			switch msg.String() {
			case "enter":
				val := strings.TrimSpace(m.textInput.Value())
				if val == "" {
					val = "."
				}
				m.result = LauncherResult{
					Action: ActionCustom,
					Path:   val,
				}
				return m, tea.Quit
			case "esc":
				m.state = launcherStateMenu
				return m, nil
			case "ctrl+c":
				m.result = LauncherResult{Action: ActionExit}
				return m, tea.Quit
			default:
				var cmd tea.Cmd
				m.textInput, cmd = m.textInput.Update(msg)
				return m, cmd
			}
		}

		// Menu state keys
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			m.result = LauncherResult{Action: ActionExit}
			return m, tea.Quit

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			} else {
				m.cursor = len(m.items) - 1
			}

		case "down", "j":
			if m.cursor < len(m.items)-1 {
				m.cursor++
			} else {
				m.cursor = 0
			}

		case "1", "2", "3", "4", "5", "6", "7":
			idx := int(msg.Runes[0] - '1')
			if idx >= 0 && idx < len(m.items) {
				m.cursor = idx
				return m.selectCurrent()
			}

		case "enter", "space":
			return m.selectCurrent()
		}
	}

	return m, nil
}

func (m LauncherModel) selectCurrent() (tea.Model, tea.Cmd) {
	selected := m.items[m.cursor]
	if selected.id == ActionCustom {
		m.state = launcherStateInputPath
		m.textInput.SetValue("")
		m.textInput.Focus()
		return m, textinput.Blink
	}

	m.result = LauncherResult{
		Action: selected.id,
	}
	return m, tea.Quit
}

// Result returns the user's chosen action and parameters.
func (m LauncherModel) Result() LauncherResult {
	return m.result
}

// View renders the Command Center interface with the Premium Executive Studio aesthetic.
func (m LauncherModel) View() string {
	var b strings.Builder

	// Color definitions
	titleStyle := lipgloss.NewStyle().Foreground(theme.ColorTextPrim).Bold(true)
	azureStyle := lipgloss.NewStyle().Foreground(theme.ColorAccent).Bold(true)
	indigoStyle := lipgloss.NewStyle().Foreground(theme.ColorIndigo).Bold(true)
	subStyle := lipgloss.NewStyle().Foreground(theme.ColorTextMute)

	if m.theme.NoColor {
		titleStyle = lipgloss.NewStyle().Bold(true)
		azureStyle = lipgloss.NewStyle().Bold(true)
		indigoStyle = lipgloss.NewStyle().Bold(true)
		subStyle = lipgloss.NewStyle()
	}

	// 1. Executive Header Box (Compact 2-line header that always stays visible)
	var yaraBadge string
	if m.yaraEnabled {
		yaraBadge = lipgloss.NewStyle().Background(theme.ColorNotice).Foreground(lipgloss.Color("#000000")).Bold(true).Padding(0, 1).Render("● YARA-X ACTIVE")
	} else {
		yaraBadge = lipgloss.NewStyle().Background(theme.ColorWarning).Foreground(lipgloss.Color("#000000")).Bold(true).Padding(0, 1).Render("○ PURE-GO")
	}

	var privBadge string
	if m.isRoot {
		privBadge = lipgloss.NewStyle().Background(theme.ColorNotice).Foreground(lipgloss.Color("#000000")).Bold(true).Padding(0, 1).Render("● FULL ACCESS")
	} else {
		privBadge = lipgloss.NewStyle().Background(theme.ColorWarning).Foreground(lipgloss.Color("#000000")).Bold(true).Padding(0, 1).Render("▲ LIMITED")
	}

	wBox := m.width - 2
	if wBox > 76 {
		wBox = 76
	}
	if wBox < 68 {
		wBox = 68
	}

	vStr := "v" + strings.TrimPrefix(m.version, "v")
	headerTop := fmt.Sprintf("%s %s %s",
		m.theme.RenderGradientText("AETHER", theme.AuroraRamp...),
		indigoStyle.Render("COMMAND CENTER"),
		subStyle.Render(vStr),
	)
	headerBadges := fmt.Sprintf("%s  %s", privBadge, yaraBadge)

	// Right align badges relative to title
	spacerLen := wBox - lipgloss.Width(headerTop) - lipgloss.Width(headerBadges) - 4
	if spacerLen < 2 {
		spacerLen = 2
	}
	headerLine1 := headerTop + strings.Repeat(" ", spacerLen) + headerBadges

	headerInfo := "Defensive Linux Threat Hunter"
	if !m.isRoot {
		headerInfo += "  │  ▲ run with sudo for full coverage"
	}
	headerLine2 := subStyle.Render(fmt.Sprintf("Host: %s (%s)  │  CPU: %d cores  │  %s", m.hostname, m.osArch, m.cpuCores, headerInfo))

	headerBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(theme.ColorBorder).
		Padding(0, 1).
		Width(wBox).
		Render(headerLine1 + "\n" + headerLine2)

	b.WriteString(headerBox)
	b.WriteString("\n")

	// 2. Body / Mode Content
	if m.state == launcherStateInputPath {
		// Custom Path Input Modal
		inputBoxContent := fmt.Sprintf(
			" %s\n\n %s\n %s\n\n %s\n %s",
			titleStyle.Render("▤ TARGET DIRECTORY SCAN"),
			subStyle.Render("Enter a specific folder or file path to hunt for threats:"),
			m.textInput.View(),
			subStyle.Render("Scans folder files only — live system checks stay off."),
			subStyle.Render("Press Enter to launch scan  •  Esc to go back"),
		)

		inputModal := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(theme.ColorBorderLit).
			Background(theme.ColorSurface).
			Padding(1, 2).
			Width(wBox).
			Render(inputBoxContent)

		b.WriteString(inputModal)
		b.WriteString("\n")
		return m.theme.AppContainer.Render(b.String())
	}

	// Menu Action Items — every action renders as a rounded card in the deck;
	// the selected card carries the lit rail, gradient title, and pulse.
	animated := !m.theme.NoColor
	revealedOf := func(i int) bool {
		if !animated {
			return true
		}
		return m.animFrame >= i*2
	}

	for i, item := range m.items {
		if !revealedOf(i) {
			b.WriteString("\n")
			continue
		}
		isSelected := i == m.cursor

		if isSelected {
			// Luminous rail + gradient title; border pulses between two cyans.
			borderColor := theme.ColorBorderLit
			if animated && (m.animFrame/6)%2 == 1 {
				borderColor = "#7DD3FC"
			}
			selector := lipgloss.NewStyle().Foreground(theme.ColorBorderLit).Bold(true).Render("▌") + azureStyle.Render("▶ ")
			keyBadge := lipgloss.NewStyle().Background(theme.ColorAccent).Foreground(lipgloss.Color("#FFFFFF")).Bold(true).Padding(0, 1).Render(item.keyNumber)
			itemTitle := m.theme.RenderGradientText(item.title, theme.AuroraRamp...)
			var tagBadge string
			if item.tag != "" {
				tagBadge = " " + lipgloss.NewStyle().Background(theme.ColorIndigo).Foreground(lipgloss.Color("#FFFFFF")).Bold(true).Padding(0, 1).Render(item.tag)
			}

			line1 := fmt.Sprintf("%s%s  %s %s%s", selector, keyBadge, item.icon, itemTitle, tagBadge)
			line2 := "    " + subStyle.Render(item.description)

			cardText := lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(borderColor).
				Background(theme.ColorRaised).
				Padding(0, 1).
				Width(wBox).
				Render(line1 + "\n" + line2)

			b.WriteString(cardText + "\n")
		} else {
			keyBadge := subStyle.Render("[" + item.keyNumber + "]")
			itemTitle := titleStyle.Render(item.title)

			// Quiet single-line row with a dim rail — the findings-feed visual
			// language. Keeps the whole deck inside small terminals (the
			// selected card above is the only bordered element). Truncation is
			// applied to the raw description text BEFORE styling so multi-byte
			// runes and ANSI sequences are never split mid-sequence.
			descText := item.description
			prefixW := lipgloss.Width(keyBadge) + 1 + lipgloss.Width(item.icon) + 1 + lipgloss.Width(item.title) + 2
			descBudget := wBox - prefixW - 2 // dim rail prefix
			if descBudget < 1 {
				descBudget = 1
			}
			if lipgloss.Width(descText) > descBudget {
				descText = runewidth.Truncate(descText, descBudget-1, "…")
			}
			rail := subStyle.Render("│")
			row := fmt.Sprintf("%s  %s %s %-32s %s", rail, keyBadge, item.icon, itemTitle, subStyle.Render(descText))
			if lipgloss.Width(row) > wBox {
				row = runewidth.Truncate(row, wBox-1, "…")
			}
			b.WriteString(row + "\n")
		}
	}

	// 3. Footer shortcuts — same visual language as the scan screens.
	footer := m.theme.KeyHint.Render("[↑/↓ or j/k] Navigate   ") +
		m.theme.KeyHint.Render("[1-7] Quick Select   ") +
		m.theme.KeyHint.Render("[Enter] Launch   ") +
		m.theme.KeyHint.Render("[q] Exit")
	b.WriteString("\n" + footer + "\n")

	return m.theme.AppContainer.Render(b.String())
}

// RunInteractiveLauncher executes the Bubble Tea interactive Command Center.
func RunInteractiveLauncher(th *theme.Theme, ver ...string) (LauncherResult, error) {
	m := NewLauncherModel(th, ver...)
	p := tea.NewProgram(m, tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		return LauncherResult{Action: ActionExit}, err
	}

	if lm, ok := finalModel.(LauncherModel); ok {
		return lm.Result(), nil
	}
	return LauncherResult{Action: ActionExit}, nil
}
