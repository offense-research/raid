package tui

import (
	"strings"
	"testing"
	"time"
)

func TestGrantsViewRenders(t *testing.T) {
	var m Model
	m.mode = "grants"
	m.AddGrantView(GrantView{
		ID: "gnt_1", ApprovalID: "apr_1", Operation: "shell.execute",
		Environment: "development", Scope: "operation",
		ExpiresAt: time.Now().Add(time.Minute),
	})
	out := m.ViewText()
	for _, want := range []string{"grants", "gnt_1", "shell.execute", "operation", "x revoke"} {
		if !strings.Contains(out, want) {
			t.Errorf("grants view missing %q:\n%s", want, out)
		}
	}
}

func TestParseGrants(t *testing.T) {
	doc := `[{"id":"gnt_9","approval_id":"apr_1","operation":"shell.delete","environment":"development","scope":"operation","expires_at":"2026-01-01T00:00:00Z"}]`
	gs := parseGrants(doc)
	if len(gs) != 1 {
		t.Fatalf("got %d grants, want 1", len(gs))
	}
	if gs[0].ID != "gnt_9" || gs[0].Scope != "operation" || gs[0].Operation != "shell.delete" {
		t.Errorf("parse: %+v", gs[0])
	}
	if gs[0].ExpiresAt.IsZero() {
		t.Errorf("expires_at not parsed")
	}
	if got := parseGrants(""); len(got) != 0 {
		t.Errorf("empty input should be empty, got %d", len(got))
	}
}
