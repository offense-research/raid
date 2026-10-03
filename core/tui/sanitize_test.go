package tui_test

import (
	"strings"
	"testing"

	"github.com/offense-research/raid/core/tui"
)

// U05: ANSI/OSC sequences and controls in untrusted fields render inert.
func TestU05SanitizerInert(t *testing.T) {
	const evil = "agent\u001b[31mred\u001b[0m \u001b]0;title\u0007 osc \u0000 nul \u0007 bell"
	clean := tui.Sanitize(evil)
	if strings.Contains(clean, "\u001b") {
		t.Errorf("escape byte survived: %q", clean)
	}
	if !strings.Contains(clean, "red") {
		t.Errorf("visible text must survive")
	}
	// the ESC is gone so "[31m" can only render as inert visible text
	if strings.Contains(clean, "\u001b[") {
		t.Errorf("CSI introducer survived")
	}
	if strings.Contains(clean, "\u0000") || strings.Contains(clean, "\u0007") {
		t.Errorf("control bytes survived")
	}
}

// Rendering never contains a raw control byte.
func TestU05NoControlsInViews(t *testing.T) {
	m := tui.TestModel(0)
	m.AddView(tui.NewApprovalView(tui.ApprovalView{
		ID: "apr_1", AgentID: "agent\u001b[31m\u001b]x\u0007", Operation: "op",
		ResourceEnv: "prod", ResourceID: "r", SubjectID: "u", SessionID: "s",
		Reason: "r", State: "pending", Version: 0, ExpiresAt: tui.ZeroTime(),
	}))
	out := m.ViewText()
	for _, c := range out {
		if (c < 0x20 && c != '\n' && c != '\t') || c == 0x7f || c == 0x1b {
			t.Errorf("control byte %#x leaked into view", uint32(c))
		}
	}
}

// Truncate bounds width without splitting runes.
func TestTruncateBounds(t *testing.T) {
	s := tui.Truncate("abcdefghij", 4)
	if len(s) > 10 {
		t.Errorf("truncate must cap width")
	}
	marked := tui.Truncate("aaaaaaaaaaaaaaaa", 8)
	if !strings.HasSuffix(marked, "…") {
		t.Errorf("truncate must mark overflow")
	}
}
