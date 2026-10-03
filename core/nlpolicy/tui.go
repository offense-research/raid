// Raid natural-language policy TUI (Bubble Tea v2 + Lipgloss).
//
// A Charm-stack form for drafting a policy from a plain-language statement:
// set the OpenRouter key, describe permissions, draft, review the YAML, then
// save it or activate it against a running daemon. Every draft still passes
// the deterministic load + compile gate before it is shown as valid or
// activated; the model is an authoring aid, never an authority.
//
// All network I/O runs inside tea.Cmd functions; Update never blocks.
package nlpolicy

import (
	"fmt"
	"os"
	"strings"

	tea "charm.land/bubbletea/v2"
	lipgloss "charm.land/lipgloss/v2"

	"github.com/offense-research/raid/core/policy"
	"github.com/offense-research/raid/pkg/raidclient"
)

// Model is the TUI state.
type Model struct {
	key       string
	model     string
	statement string
	draft     string
	status    string
	focus     int // 0 key, 1 model, 2 statement
	editing   bool
	showDraft bool
	busy      bool
	width     int
	height    int
}

// --- messages ---

type DraftMsg struct {
	YAML string
	Err  string
}

type SaveMsg struct {
	OK   bool
	Path string
	Body string
}

type ActivateMsg struct {
	OK   bool
	Body string
}

// --- commands: blocking I/O inside Cmd functions ---

func draftCmd(opts TranslateOptions, statement string) tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		yaml, terr := Translate(nil, opts, statement)
		if terr != nil {
			return DraftMsg{Err: terr.Error()}
		}
		return DraftMsg{YAML: yaml}
	})
}

func saveCmd(path, yaml string) tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
			return SaveMsg{OK: false, Path: path, Body: err.Error()}
		}
		return SaveMsg{OK: true, Path: path}
	})
}

func activateCmd(yaml string) tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		client := raidclient.NewClient(os.Getenv("RAID_SOCKET"))
		resp, err := client.Post("/v1/policies/activate", yaml, os.Getenv("RAID_APPROVER"), nil)
		if err != nil {
			return ActivateMsg{OK: false, Body: err.Error()}
		}
		return ActivateMsg{OK: resp.Status == 200, Body: resp.BodyString()}
	})
}

// --- init / update ---

func (m Model) Init() tea.Cmd {
	m.key = os.Getenv(KeyEnv)
	m.model = DefaultModel
	m.statement = `allow GitHub issue reads on staging;
require approval before modifying production issues;
deny repository deletion`
	m.showDraft = true
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		key := msg.String()
		var cmd tea.Cmd
		if m.editing {
			m, cmd = editKey(m, key)
		} else {
			m, cmd = commandKey(m, key)
		}
		return m, cmd
	case DraftMsg:
		m.busy = false
		if msg.Err != "" {
			m.status = paint("✗ draft failed: "+msg.Err, colorErr, false)
			return m, nil
		}
		m.draft = msg.YAML
		m.status = gateDraftStatus(m)
		if strings.Trim(m.status, "\t\r\n ") != "" {
			m.showDraft = true
		}
		return m, nil
	case SaveMsg:
		if msg.OK {
			m.status = paint("✔ saved "+msg.Path, colorOK, false)
		} else {
			m.status = paint("✗ save failed: "+msg.Body, colorErr, false)
		}
		return m, nil
	case ActivateMsg:
		if msg.OK {
			m.status = paint(msg.Body, colorOK, true)
		} else {
			m.status = paint("✗ activation rejected: "+msg.Body, colorErr, false)
		}
		return m, nil
	}
	return m, nil
}

// commandKey handles keys in command (non-editing) mode.
func commandKey(m Model, key string) (Model, tea.Cmd) {
	switch key {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "tab", "j", "down":
		m.focus = (m.focus + 1) % 3
		return m, nil
	case "k", "up":
		m.focus = (m.focus + 2) % 3
		return m, nil
	case "i", "enter":
		m.editing = true
		return m, nil
	case "d":
		if m.busy {
			return m, nil
		}
		if strings.Trim(m.statement, "\t\r\n ") == "" {
			m.status = paint("✗ describe your permissions first", colorErr, false)
			return m, nil
		}
		m.busy = true
		m.status = paint("drafting…", colorWarn, false)
		return m, draftCmd(TranslateOptions{ApiKey: m.key, Model: m.model}, m.statement)
	case "s":
		if m.draft == "" {
			m.status = paint("✗ nothing to save yet — press d to draft", colorErr, false)
			return m, nil
		}
		return m, saveCmd("raid-policy-generated.yaml", m.draft)
	case "a":
		if m.draft == "" {
			m.status = paint("✗ nothing to activate yet — press d to draft", colorErr, false)
			return m, nil
		}
		return m, activateCmd(m.draft)
	case "v":
		m.showDraft = !m.showDraft
		return m, nil
	case "/":
		m.status = ""
		return m, nil
	}
	return m, nil
}

// editKey handles keys while editing the focused field.
func editKey(m Model, key string) (Model, tea.Cmd) {
	switch key {
	case "esc", "escape":
		m.editing = false
		return m, nil
	case "backspace":
		return backspace(m)
	case "tab":
		m.focus = (m.focus + 1) % 3
		return m, nil
	case "enter":
		if m.focus == 2 {
			return appendChar(m, "\n")
		}
		m.editing = false
		return m, nil
	}
	if len(key) == 1 {
		return appendChar(m, key)
	}
	return m, nil
}

func backspace(m Model) (Model, tea.Cmd) {
	switch m.focus {
	case 0:
		m.key = dropLastRune(m.key)
	case 1:
		m.model = dropLastRune(m.model)
	default:
		m.statement = dropLastRune(m.statement)
	}
	return m, nil
}

func appendChar(m Model, ch string) (Model, tea.Cmd) {
	switch m.focus {
	case 0:
		m.key = m.key + ch
	case 1:
		m.model = m.model + ch
	default:
		m.statement = m.statement + ch
	}
	return m, nil
}

// gateDraftStatus runs the deterministic load + compile gate over a draft and
// returns a colored status string ("" when the draft is being kept).
func gateDraftStatus(m Model) string {
	sch, lerr := policy.LoadBundle([]byte(m.draft), "language")
	if lerr != nil {
		return paint("✗ draft rejected by deterministic gate: "+lerr.Error(), colorErr, false)
	}
	compiled, cerr := policy.CompileBundle(sch, policy.CompileOptions{})
	if cerr != nil {
		return paint("✗ draft rejected at compile: "+cerr.Error(), colorErr, false)
	}
	return paint(fmt.Sprintf("✔ valid PolicyBundle — %d rule(s); deterministic gate passed", len(compiled.Rules())), colorOK, true)
}

// --- rendering ---

func (m Model) View() tea.View {
	return tea.NewView(compose(m, viewWidth(m), true))
}

// ViewText returns an un-styled render for tests.
func (m Model) ViewText() string {
	return compose(m, 80, false)
}

func viewWidth(m Model) int {
	if m.width > 0 {
		return m.width
	}
	return 80
}

func compose(m Model, width int, decorate bool) string {
	lines := []string{}
	lines = append(lines, titleBar(m, width, decorate))
	lines = append(lines, formBox(m, width, decorate))
	if m.showDraft {
		lines = append(lines, draftBox(m, width, decorate))
	}
	lines = append(lines, statusLine(m, width, decorate))
	lines = append(lines, footerLine(m, width, decorate))
	if m.height > 0 && len(lines) > m.height {
		lines = lines[:m.height]
	}
	return strings.Join(lines, "\n") + "\n"
}

func titleBar(m Model, width int, decorate bool) string {
	base := " RAID · natural-language policy "
	if decorate {
		base = paint(base, colorAccent, true)
	}
	return "┌" + centered(base, width) + "┐"
}

func centered(s string, width int) string {
	n := runeLen(s)
	if n >= width-2 {
		return truncateTo(s, width-2)
	}
	pad := width - 2 - n
	left := pad / 2
	right := pad - left
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
}

func formBox(m Model, width int, decorate bool) string {
	body := []string{}
	body = append(body, fieldRow(m, 0, "OpenRouter key", hideKey(m), decorate, width))
	body = append(body, fieldRow(m, 1, "Model", m.model, decorate, width))
	body = append(body, fieldRow(m, 2, "Permissions", m.statement, decorate, width))
	return box("Authoring", body, width)
}

func hideKey(m Model) string {
	if m.key == "" {
		return ""
	}
	if m.focus == 0 && m.editing {
		return m.key
	}
	return "••••••••"
}

func fieldRow(m Model, idx int, label, value string, decorate bool, width int) string {
	active := m.focus == idx
	marker := "  "
	if active {
		marker = "▸ "
	}
	lab := label
	if decorate && active {
		marker = paint("▸ ", colorAccent, true)
		lab = paint(label, colorAccent, true)
	}
	val := value
	if idx == 2 {
		// multiline statement: squeeze to a single padded line
		val = strings.ReplaceAll(val, "\n", " ⏎ ")
	}
	row := "│ " + marker + pad(lab+"   "+val, widthBroth(width))
	if active && m.editing {
		row = row + "▏"
	}
	return truncateTo(row, width) + "│"
}

func draftBox(m Model, width int, decorate bool) string {
	if m.draft == "" {
		body := []string{"│ " + pad("(no draft yet — press d to draft from your permissions)", width-3) + "│"}
		return box("Review", body, width)
	}
	raw := []string{}
	for _, line := range strings.Split(m.draft, "\n") {
		raw = append(raw, "│ "+pad(truncateTo(line, width-4), width-4)+"│")
	}
	// cap the box height at 14 lines
	if len(raw) > 14 {
		more := len(raw) - 14
		raw = raw[:14]
		raw[13] = "│ " + pad(truncateTo(fmt.Sprintf("… %d more line(s)", more), width-4), width-4) + "│"
	}
	return box("Review", raw, width)
}

func statusLine(m Model, width int, decorate bool) string {
	s := m.status
	if s == "" {
		s = paint("draft → review → save/activate", colorDim, false)
	}
	return "┌" + strings.Repeat("─", maxRune(0, width-2)) + "┐\n" +
		"│ " + pad(s, width-3) + "│"
}

func footerLine(m Model, width int, decorate bool) string {
	hint := "tab: fields   i: edit   d: draft   s: save   a: activate   v: toggle review   q: quit"
	if decorate {
		hint = paint(hint, colorDim, false)
	}
	return pad(hint, width)
}

func box(title string, body []string, width int) string {
	head := "┌ " + title + " "
	var sb strings.Builder
	inner := width - runeLen(head) - 1
	sb.WriteString(head + strings.Repeat("─", maxRune(0, inner)) + "┐")
	for _, l := range body {
		sb.WriteString("\n" + l)
	}
	sb.WriteString("\n└" + strings.Repeat("─", maxRune(0, width-2)) + "┘")
	return sb.String()
}

// --- styling (Lipgloss) ---

const (
	colorAccent = "6" // cyan
	colorOK     = "2" // green
	colorErr    = "1" // red
	colorWarn   = "3" // yellow
	colorDim    = "8" // bright black
)

// paint wraps text in ANSI styling; renders the same text when decorate is
// off via callers that skip it.
func paint(s, c string, bold bool) string {
	st := lipgloss.NewStyle().Foreground(lipgloss.Color(c)).Bold(bold)
	return st.Render(s)
}

// --- terminal helpers ---

var checkedTTY bool
var ttyResult bool

// isTTY reports whether a controlling terminal exists.
func isTTY() bool {
	if checkedTTY {
		return ttyResult
	}
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		ttyResult = false
	} else {
		f.Close()
		ttyResult = true
	}
	checkedTTY = true
	return ttyResult
}

// NewModel builds a Model for tests and embedding.
func NewModel(key, model, statement string) Model {
	return Model{key: key, model: model, statement: statement, showDraft: true}
}

// NewDraftModel builds a Model with a planted draft (for test rendering).
func NewDraftModel(draft string) Model {
	return Model{draft: draft, showDraft: true}
}

// runTTY launches the TUI; fails loudly without a controlling terminal.
func Run() int {
	if !isTTY() {
		fmt.Println("raid: `policy from-language --interactive` requires a TTY (use a plain `--statement` otherwise)")
		return 1
	}
	p := tea.NewProgram(Model{})
	if _, err := p.Run(); err != nil {
		fmt.Println("raid: tui error: " + err.Error())
		return 1
	}
	return 0
}

// --- small string helpers ---

func dropLastRune(s string) string {
	if len(s) == 0 {
		return s
	}
	last := 0
	for i, _ := range s {
		last = i
	}
	return s[:last]
}

func runeLen(s string) int {
	n := 0
	for _, r := range s {
		n++
		_ = r
	}
	return n
}

func maxRune(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func pad(s string, width int) string {
	if runeLen(s) >= width {
		return truncateTo(s, width)
	}
	return s + strings.Repeat(" ", width-runeLen(s))
}

func truncateTo(s string, width int) string {
	if runeLen(s) <= width {
		return s
	}
	return runeSlice(s, width) + "…"
}

func runeSlice(s string, n int) string {
	out := s
	count := 0
	for i, _ := range s {
		if count >= n {
			return s[:i]
		}
		count++
	}
	return out
}

func widthBroth(width int) int {
	return width - 4
}
