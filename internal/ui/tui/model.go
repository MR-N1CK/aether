package tui

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/atotto/clipboard"
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

// sortMode selects the ordering of the findings feed.
type sortMode int

const (
	sortBySeverity sortMode = iota // worst first, score tiebreak
	sortByArrival                  // chronological detection order
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
	ctx        context.Context
	cancelScan context.CancelFunc
	sub        *events.Subscription
	theme      *theme.Theme
	noAnim     bool
	state      tuiState

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
	findings      []report.Finding
	visible       []report.Finding // display list: filtered (fuzzy) + sorted
	selectedIndex int
	isFiltering   bool
	filterQuery   string
	sortBy        sortMode

	// Completion metrics
	scanFinished bool
	finishEvent  *events.ScanFinished

	// Enhanced UX & Animation state
	smoothFilesScanned float64
	velocitySamples    []float64
	activeTab          int
	modalScrollY       int
	showPalette        bool
	confirmQuit        bool
	toastMessage       string
	toastUntil         time.Time
	findingsDirty      bool
	htmlReportPath     string

	// UI components
	spinner spinner.Model
}

// NewModel constructs a new interactive TUI model.
func NewModel(ctx context.Context, cancel context.CancelFunc, sub *events.Subscription, th *theme.Theme, noAnim bool, mode string, threads int, paths []string, reportPath ...string) Model {
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

	var repPath string
	if len(reportPath) > 0 {
		repPath = reportPath[0]
	}

	return Model{
		ctx:             ctx,
		cancelScan:      cancel,
		sub:             sub,
		theme:           th,
		noAnim:          noAnim,
		state:           initialState,
		splashFrame:     0,
		maxSplash:       18, // 3-phase smooth gradient splash ~720ms
		startTime:       time.Now(),
		mode:            strings.ToUpper(mode),
		threads:         threads,
		hostname:        host,
		paths:           paths,
		htmlReportPath:  repPath,
		activeModules:   make(map[string]*ModuleStatus),
		findings:        make([]report.Finding, 0),
		visible:         make([]report.Finding, 0),
		velocitySamples: make([]float64, 0, 10),
		activeTab:       0,
		sortBy:          sortBySeverity,
		spinner:         sp,
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
	return tea.Tick(40*time.Millisecond, func(t time.Time) tea.Msg {
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
				if m.scanFinished {
					m.state = stateFinished
				} else {
					m.state = stateDashboard
				}
			} else {
				cmds = append(cmds, m.tickSplash(m.splashFrame))
			}
		}

	case frameTickMsg:
		if m.findingsDirty {
			m.recomputeVisible()
			m.findingsDirty = false
		}
		if !m.scanFinished {
			m.elapsed = time.Since(m.startTime)
		}
		// Smooth counter interpolation
		diff := float64(m.filesScanned) - m.smoothFilesScanned
		if diff > 0.05 || diff < -0.05 {
			m.smoothFilesScanned += diff * 0.25
		} else {
			m.smoothFilesScanned = float64(m.filesScanned)
		}

		var spCmd tea.Cmd
		m.spinner, spCmd = m.spinner.Update(msg)
		if m.scanFinished && (diff <= 0.05 && diff >= -0.05) && time.Now().After(m.toastUntil) {
			// Scan is finished and display settled: reduce from 30 FPS to 1s idle heartbeat
			cmds = append(cmds, spCmd, tea.Tick(1*time.Second, func(t time.Time) tea.Msg {
				return frameTickMsg(t)
			}))
		} else {
			cmds = append(cmds, spCmd, m.tick30FPS())
		}

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
		m.findingsDirty = true
		if mod, exists := m.activeModules[ev.Finding.Module]; exists {
			mod.Findings++
		}

	case events.Progress:
		m.filesScanned = ev.CurrentFiles
		m.filesPerSec = ev.FilesPerSec
		m.velocitySamples = append(m.velocitySamples, ev.FilesPerSec)
		if len(m.velocitySamples) > 10 {
			m.velocitySamples = m.velocitySamples[len(m.velocitySamples)-10:]
		}

	case events.ScanFinished:
		m.scanFinished = true
		m.finishEvent = &ev
		m.filesScanned = ev.FilesScanned
		m.smoothFilesScanned = float64(ev.FilesScanned)
		m.elapsed = ev.TotalDuration
		if m.findingsDirty {
			m.recomputeVisible()
			m.findingsDirty = false
		}
		if m.state != stateDetail && m.state != stateSplash {
			m.state = stateFinished
		}
	}
}

func (m *Model) handleKey(msg tea.KeyMsg) tea.Cmd {
	// Command palette toggle or dismiss
	if m.showPalette {
		switch msg.String() {
		case "?", "esc", "q", "enter", " ":
			m.showPalette = false
			return nil
		}
		return nil
	}

	// Quit confirmation modal: swallow every key except the verdict keys so a
	// stray j/k or / cannot interact with the dashboard underneath.
	if m.confirmQuit {
		switch msg.String() {
		case "y", "Y":
			if m.cancelScan != nil {
				m.cancelScan()
			}
			return tea.Quit
		case "n", "N", "esc":
			m.confirmQuit = false
			m.showToast("Scan continues — press [q] to abort")
		}
		return nil
	}

	// Any key during splash skips to dashboard or finished view
	if m.state == stateSplash {
		if m.scanFinished {
			m.state = stateFinished
		} else {
			m.state = stateDashboard
		}
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
			m.recomputeVisible()
			return nil
		case tea.KeyBackspace:
			if len(m.filterQuery) > 0 {
				m.filterQuery = m.filterQuery[:len(m.filterQuery)-1]
				m.recomputeVisible()
			}
			return nil
		case tea.KeyRunes:
			m.filterQuery += string(msg.Runes)
			m.recomputeVisible()
			return nil
		}
		return nil
	}

	// Detail modal mode
	if m.state == stateDetail {
		switch msg.String() {
		case "?":
			m.showPalette = true
			return nil
		case "esc", "q":
			m.modalScrollY = 0
			if m.scanFinished {
				m.state = stateFinished
			} else {
				m.state = stateDashboard
			}
			return nil
		case "tab", "right", "]":
			m.activeTab = (m.activeTab + 1) % 4
			m.modalScrollY = 0
			return nil
		case "shift+tab", "left", "[":
			m.activeTab = (m.activeTab + 3) % 4
			m.modalScrollY = 0
			return nil
		case "1":
			m.activeTab = 0
			m.modalScrollY = 0
			return nil
		case "2":
			m.activeTab = 1
			m.modalScrollY = 0
			return nil
		case "3":
			m.activeTab = 2
			m.modalScrollY = 0
			return nil
		case "4":
			m.activeTab = 3
			m.modalScrollY = 0
			return nil
		case "up", "k":
			if m.modalScrollY > 0 {
				m.modalScrollY--
			}
			return nil
		case "down", "j":
			m.modalScrollY++
			return nil
		case "pgup":
			m.modalScrollY -= 5
			if m.modalScrollY < 0 {
				m.modalScrollY = 0
			}
			return nil
		case "pgdown":
			m.modalScrollY += 5
			return nil
		case "g", "home":
			m.modalScrollY = 0
			return nil
		case "G", "end":
			m.modalScrollY = 9999
			return nil
		case "y":
			m.copySelectedPath()
			return nil
		case "h", "hash", "#":
			m.copySelectedHash()
			return nil
		case "c", "r":
			m.copySelectedCommand()
			return nil
		case "enter":
			m.modalScrollY = 0
			if m.scanFinished {
				m.state = stateFinished
			} else {
				m.state = stateDashboard
			}
			return nil
		}
		return nil
	}

	// Normal navigation & dashboard controls
	switch msg.String() {
	case "ctrl+c":
		if m.cancelScan != nil {
			m.cancelScan()
		}
		return tea.Quit

	case "q":
		// Guarded quit: an in-flight scan is aborted by accident far more
		// easily than on purpose, so require confirmation while it runs.
		if !m.scanFinished {
			m.confirmQuit = true
			return nil
		}
		if m.cancelScan != nil {
			m.cancelScan()
		}
		return tea.Quit

	case "s":
		if m.sortBy == sortBySeverity {
			m.sortBy = sortByArrival
			m.showToast("Feed sorted by arrival time")
		} else {
			m.sortBy = sortBySeverity
			m.showToast("Feed sorted by severity (worst first)")
		}
		m.recomputeVisible()
		return nil

	case "?":
		m.showPalette = true
		return nil

	case "n":
		m.jumpToNextAlert()

	case "N":
		m.jumpToPrevAlert()

	case "o":
		m.openHTMLReport()

	case "up", "k":
		if m.selectedIndex > 0 {
			m.selectedIndex--
		}

	case "down", "j":
		if m.selectedIndex < len(m.currentList())-1 {
			m.selectedIndex++
		}

	case "g", "home":
		m.selectedIndex = 0

	case "G", "end":
		list := m.currentList()
		if len(list) > 0 {
			m.selectedIndex = len(list) - 1
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

	case "y":
		m.copySelectedPath()

	case "h":
		m.copySelectedHash()

	case "c", "r":
		m.copySelectedCommand()

	case "esc":
		if m.filterQuery != "" {
			m.filterQuery = ""
			m.recomputeVisible()
			m.showToast("Search filter cleared")
		}

	case "enter":
		list := m.currentList()
		if len(list) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(list) {
			m.state = stateDetail
			m.activeTab = 0
			m.modalScrollY = 0
		}

	case "/":
		m.isFiltering = true
	}

	return nil
}

func (m *Model) showToast(msg string) {
	m.toastMessage = msg
	m.toastUntil = time.Now().Add(2500 * time.Millisecond)
}

func (m *Model) copyToClipboard(text, label string) {
	if text == "" {
		m.showToast(fmt.Sprintf("No %s to copy", label))
		return
	}
	err := clipboard.WriteAll(text)
	if err != nil {
		m.showToast("Clipboard unavailable in headless session")
	} else {
		m.showToast(fmt.Sprintf("Copied %s to clipboard!", label))
	}
}

func (m *Model) copySelectedPath() {
	if sel := m.SelectedFinding(); sel != nil {
		m.copyToClipboard(sel.Path, "Path")
	}
}

func (m *Model) copySelectedHash() {
	if sel := m.SelectedFinding(); sel != nil {
		hash := sel.Hashes["SHA256"]
		if hash == "" {
			hash = sel.Hashes["MD5"]
		}
		m.copyToClipboard(hash, "SHA256")
	}
}

func (m *Model) copySelectedCommand() {
	if sel := m.SelectedFinding(); sel != nil {
		report.PopulateFindingDetails(sel)
		cmd := ""
		for _, step := range sel.Remediation {
			if strings.Contains(step, "`") {
				start := strings.Index(step, "`")
				end := strings.LastIndex(step, "`")
				if end > start {
					cmd = step[start+1 : end]
					break
				}
			}
		}
		if cmd == "" && len(sel.Remediation) > 0 {
			cmd = sel.Remediation[0]
		}
		m.copyToClipboard(cmd, "Remediation Command")
	}
}

func (m *Model) currentList() []report.Finding {
	return m.visible
}

// findingKey builds a stable identity key for selection anchoring across
// recomputes (path, rule, and nanosecond timestamp make duplicates unlikely).
func findingKey(f report.Finding) string {
	return f.Path + "\x1f" + f.RuleName + "\x1f" + strconv.FormatInt(f.Timestamp.UnixNano(), 10)
}

// recomputeVisible rebuilds the display list from the raw findings:
// fuzzy filter (when a query is active), then ordering per the active sort
// mode. The cursor is anchored to the same finding across recomputes so new
// high-severity detections arriving mid-scan do not move it unexpectedly.
func (m *Model) recomputeVisible() {
	anchorKey := ""
	if m.selectedIndex >= 0 && m.selectedIndex < len(m.visible) {
		anchorKey = findingKey(m.visible[m.selectedIndex])
	}

	visible := make([]report.Finding, 0, len(m.findings))
	if m.filterQuery == "" {
		visible = append(visible, m.findings...)
	} else {
		qf := ParseQueryFilter(m.filterQuery)
		for _, f := range m.findings {
			if qf.Matches(f.Path, f.Reason, f.Module, string(f.Severity), f.RuleName) {
				visible = append(visible, f)
			}
		}
	}
	m.sortFindings(visible)
	m.visible = visible

	reanchored := false
	if anchorKey != "" {
		for i := range m.visible {
			if findingKey(m.visible[i]) == anchorKey {
				m.selectedIndex = i
				reanchored = true
				break
			}
		}
	}
	if !reanchored {
		if m.selectedIndex >= len(m.visible) {
			m.selectedIndex = maxInt(0, len(m.visible)-1)
		}
		if m.selectedIndex < 0 {
			m.selectedIndex = 0
		}
	}
}

// sortFindings orders the display list in place per the active sort mode.
// Arrival mode keeps the underlying detection order.
func (m *Model) sortFindings(list []report.Finding) {
	if m.sortBy != sortBySeverity {
		return
	}
	sort.SliceStable(list, func(i, j int) bool {
		ri, rj := severityRank(list[i].Severity), severityRank(list[j].Severity)
		if ri != rj {
			return ri > rj
		}
		si, sj := findingScore(list[i]), findingScore(list[j])
		if si != sj {
			return si > sj
		}
		return list[i].Timestamp.Before(list[j].Timestamp)
	})
}

// severityRank orders the full report severity vocabulary; unknown values rank last.
func severityRank(s report.Severity) int {
	switch s {
	case report.SeverityCritical:
		return 8
	case report.SeverityAlert:
		return 7
	case report.SeverityHigh:
		return 6
	case report.SeverityWarning:
		return 5
	case report.SeverityMedium:
		return 4
	case report.SeverityNotice:
		return 3
	case report.SeverityLow:
		return 2
	case report.SeverityInfo:
		return 1
	default:
		return 0
	}
}

// findingScore extracts the additive detection score from finding metadata
// (0 when absent or of an unexpected type).
func findingScore(f report.Finding) int {
	switch v := f.Metadata["score"].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// SelectedFinding returns the currently highlighted finding if any.
func (m *Model) SelectedFinding() *report.Finding {
	list := m.currentList()
	if len(list) == 0 || m.selectedIndex < 0 || m.selectedIndex >= len(list) {
		return nil
	}
	return &list[m.selectedIndex]
}

func (m *Model) jumpToNextAlert() {
	list := m.currentList()
	if len(list) == 0 {
		return
	}
	for i := m.selectedIndex + 1; i < len(list); i++ {
		if list[i].Severity == report.SeverityAlert || list[i].Severity == report.SeverityCritical {
			m.selectedIndex = i
			m.showToast(fmt.Sprintf("Jumped to alert #%d", i+1))
			return
		}
	}
	for i := 0; i <= m.selectedIndex; i++ {
		if list[i].Severity == report.SeverityAlert || list[i].Severity == report.SeverityCritical {
			m.selectedIndex = i
			m.showToast(fmt.Sprintf("Wrapped to alert #%d", i+1))
			return
		}
	}
	m.showToast("No alert findings in current view")
}

func (m *Model) jumpToPrevAlert() {
	list := m.currentList()
	if len(list) == 0 {
		return
	}
	for i := m.selectedIndex - 1; i >= 0; i-- {
		if list[i].Severity == report.SeverityAlert || list[i].Severity == report.SeverityCritical {
			m.selectedIndex = i
			m.showToast(fmt.Sprintf("Jumped to alert #%d", i+1))
			return
		}
	}
	for i := len(list) - 1; i >= m.selectedIndex; i-- {
		if list[i].Severity == report.SeverityAlert || list[i].Severity == report.SeverityCritical {
			m.selectedIndex = i
			m.showToast(fmt.Sprintf("Wrapped to alert #%d", i+1))
			return
		}
	}
	m.showToast("No alert findings in current view")
}

func (m *Model) openHTMLReport() {
	var candidates []string
	if m.htmlReportPath != "" {
		candidates = append(candidates, m.htmlReportPath)
	}
	candidates = append(candidates, "aether-report.html", "report.html", "/tmp/aether-report.html")
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			cmd := exec.Command("xdg-open", p)
			if err := cmd.Start(); err == nil {
				m.showToast(fmt.Sprintf("Opened %s in browser", p))
				return
			}
		}
	}
	m.showToast("No HTML report found to open")
}

