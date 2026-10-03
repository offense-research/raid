// Raid approval TUI (spec section 9): Bubble Tea v2 model, update, view.
//
// All network I/O runs inside tea.Cmd functions; Update never blocks. API
// responses arrive as typed messages on the event loop.
package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"offense.dev/raid/pkg/raidclient"
)

// Model is the TUI state (spec 9.7).
type Model struct {
	approvals []ApprovalView
	grants    []GrantView
	mode      string // "" / "approvals" or "grants"
	cursor    int
	selected  map[string]bool
	filter    string
	filtering bool
	width     int
	height    int
	connected bool
	lastSeq   uint64
	err       string
	detail    bool
	confirm   string // non-empty while a confirm prompt is open
}

// ApprovalView is a safe, rendered-shape approval.
type ApprovalView struct {
	ID          string
	AgentID     string
	Operation   string
	ResourceEnv string
	ResourceID  string
	SubjectID   string
	SessionID   string
	Reason      string
	Summary     string
	State       string
	Version     uint64
	ExpiresAt   time.Time
}

// GrantView is a safe, rendered-shape grant.
type GrantView struct {
	ID          string
	ApprovalID  string
	Operation   string
	Environment string
	Scope       string
	ExpiresAt   time.Time
}

// --- messages (all implement the empty uv.Event marker) ---

type FetchListMsg struct {
	JSON       string
	GrantsJSON string
	Err        string
}

type ApproveDoneMsg struct {
	ApprovalID string
	OK         bool
	Body       string
}

type RevokeDoneMsg struct {
	GrantID string
	OK      bool
	Body    string
}

type FilterMsg struct{}

// --- commands: blocking I/O inside Cmd functions ---

func refreshCmd(client *raidclient.Client) tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		resp, err := client.Get("/v1/approvals", "")
		if err != nil {
			return FetchListMsg{Err: err.Error()}
		}
		msg := FetchListMsg{JSON: resp.BodyString()}
		if gresp, gerr := client.Get("/v1/grants", ""); gerr == nil {
			msg.GrantsJSON = gresp.BodyString()
		}
		return msg
	})
}

func revokeCmd(client *raidclient.Client, id string) tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		resp, err := client.Delete("/v1/grants/"+id, os.Getenv("RAID_APPROVER"))
		if err != nil {
			return RevokeDoneMsg{GrantID: id, OK: false, Body: err.Error()}
		}
		return RevokeDoneMsg{GrantID: id, OK: resp.Status == 200, Body: resp.BodyString()}
	})
}

func approveCmd(client *raidclient.Client, id string, version uint64) tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		body := fmt.Sprintf(`{"expected_version":%d}`, version)
		resp, err := client.Post("/v1/approvals/"+id+"/approve", body, os.Getenv("RAID_APPROVER"), nil)
		if err != nil {
			return ApproveDoneMsg{ApprovalID: id, OK: false, Body: err.Error()}
		}
		return ApproveDoneMsg{ApprovalID: id, OK: resp.Status == 200, Body: resp.BodyString()}
	})
}

func denyCmd(client *raidclient.Client, id string, version uint64) tea.Cmd {
	return tea.Cmd(func() tea.Msg {
		body := fmt.Sprintf(`{"expected_version":%d}`, version)
		resp, err := client.Post("/v1/approvals/"+id+"/deny", body, os.Getenv("RAID_APPROVER"), nil)
		if err != nil {
			return ApproveDoneMsg{ApprovalID: id, OK: false, Body: err.Error()}
		}
		return ApproveDoneMsg{ApprovalID: id, OK: resp.Status == 200, Body: resp.BodyString()}
	})
}

// --- init/update/view ---

func (m Model) Init() tea.Cmd {
	return refreshCmd(newClient())
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		key := msg.String()
		switch key {
		case "ctrl+c":
			return m, tea.Quit
		case "q":
			if m.confirm != "" {
				// escape confirm without quitting
			} else {
				return m, tea.Quit
			}
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.approvals) - 1 {
				m.cursor++
			}
		case "g", "home":
			m.cursor = 0
		case "G", "end":
			m.cursor = len(m.approvals) - 1
		case "d", "enter":
			m.detail = !m.detail
		case "r":
			return m, refreshCmd(newClient())
		case "y":
			if len(m.approvals) > 0 {
				a := m.approvals[max(0, m.cursor)]
				return m, approveCmd(newClient(), a.ID, a.Version)
			}
		case "n":
			if len(m.approvals) > 0 {
				a := m.approvals[max(0, m.cursor)]
				return m, denyCmd(newClient(), a.ID, a.Version)
			}
		case "t", "tab":
			if m.mode == "grants" {
				m.mode = "approvals"
			} else {
				m.mode = "grants"
			}
			m.cursor = 0
		case "x":
			if m.mode == "grants" && len(m.grants) > 0 {
				g := m.grants[max(0, m.cursor)]
				return m, revokeCmd(newClient(), g.ID)
			}
		case "/":
			m.filtering = true
		case "escape", "esc":
			if m.filtering {
				m.filtering = false
				m.filter = ""
			}
		default:
			if m.filtering && len(key) == 1 {
				m.filter = m.filter + key
			}
		}
		return m, nil
	case FetchListMsg:
		if msg.Err != "" {
			m.err = msg.Err
			m.connected = false
			return m, nil
		}
		m.approvals = parseApprovals(msg.JSON)
		m.grants = parseGrants(msg.GrantsJSON)
		m.connected = true
		m.err = ""
		return m, nil
	case ApproveDoneMsg:
		if msg.OK {
			m.err = "approved " + msg.ApprovalID
		} else {
			m.err = "approve failed: " + msg.Body
		}
		return m, refreshCmd(newClient())
	case RevokeDoneMsg:
		if msg.OK {
			m.err = "revoked " + msg.GrantID
		} else {
			m.err = "revoke failed: " + msg.Body
		}
		return m, refreshCmd(newClient())
	case FilterMsg:
		return m, nil
	}
	return m, nil
}

func (m Model) View() tea.View {
	width := 80
	height := 24
	if v := m.width; v > 0 {
		width = v
	}
	if v := m.height; v > 0 {
		height = v
	}
	lines := []string{}
	lines = append(lines, headerLine(m, width))
	if m.mode == "grants" {
		lines = append(lines, grantsList(m, width))
	} else {
		lines = append(lines, pendingList(m, width))
	}
	lines = append(lines, requestDetail(m, width))
	lines = append(lines, footerLine(m, width))
	// honor height by trimming
	if len(lines) > height {
		lines = lines[:height]
	}
	return tea.NewView(strings.Join(lines, "\n") + "\n")
}

// NewApprovalView builds a safe view for tests and rendering.
func NewApprovalView(v ApprovalView) ApprovalView { return v }

// ZeroTime returns the zero Time (for test views).
func ZeroTime() time.Time { return time.Time{} }

// AddView appends an approval view (used by tests to plant fixtures).
func (m *Model) AddView(v ApprovalView) () {
	m.approvals = append(m.approvals, v)
}

// AddGrantView appends a grant view (used by tests to plant fixtures).
func (m *Model) AddGrantView(v GrantView) {
	m.grants = append(m.grants, v)
}

// Run launches the TUI. It fails loudly when there is no TTY (spec 9.9).
func Run() int {
	if !isTTY() {
		fmt.Println("raid: approve requires a TTY (use `raid approval list` or `raid approval approve <id> --expected-version N`)")
		return 1
	}
	p := tea.NewProgram(Model{})
	if _, err := p.Run(); err != nil {
		fmt.Println("raid: tui error: " + err.Error())
		return 1
	}
	return 0
}

// newClient builds the socket client from the environment.
func newClient() *raidclient.Client {
	return raidclient.NewClient(os.Getenv("RAID_SOCKET"))
}

// TestModel builds a benchmark model with n synthetic approvals.
func TestModel(n int) Model {
	var m Model
	m.height = 40
	for i := 0; i < n; i++ {
		m.approvals = append(m.approvals, ApprovalView{
			ID: "apr_" + fmt.Sprintf("%d", i), AgentID: "agent-" + fmt.Sprintf("%d", i % 10),
			Operation: "github.issues.add_labels", ResourceEnv: "production",
			ResourceID: "repo:1:issue:" + fmt.Sprintf("%d", i),
			SubjectID: "usr", SessionID: "ses", Reason: "rule", State: "pending",
			Version: 0, Summary: "labels = [needs-triage]",
		})
	}
	return m
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
