// TUI rendering and JSON parsing (spec 9.3).
package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"offense.dev/raid/core/canonical"
)

// parseApprovals converts /v1/approvals JSON into bounded views.
func parseApprovals(jsonDoc string) []ApprovalView {
	out := []ApprovalView{}
	v, perr := canonical.Decode([]byte(jsonDoc), canonical.DecodeOptions{MaxBytes: 8 * 1024 * 1024})
	if perr != nil {
		return out
	}
	if v.Kind() != canonical.VList {
		return out
	}
	for _, item := range v.AsList() {
		if item.Kind() != canonical.VObject {
			continue
		}
		m := item.AsMap()
		var av ApprovalView
		av.ID = strField(m, "id")
		av.AgentID = strField(m, "agent_id")
		av.Operation = strField(m, "operation")
		av.ResourceEnv = strField(m, "environment")
		av.ResourceID = strField(m, "resource_id")
		av.SubjectID = strField(m, "principal_id")
		av.SessionID = strField(m, "session_id")
		av.State = strField(m, "state")
		av.Reason = "rule-based"
		av.Version = uintField(m, "version")
		av.Summary = summaryField(m)
		if ts, ok := m["expires_at"]; ok && ts.Kind() == canonical.VString {
			av.ExpiresAt, _ = time.Parse(time.RFC3339, ts.AsString())
		}
		out = append(out, av)
	}
	return out
}

func strField(m map[string]canonical.Value, key string) string {
	if v, ok := m[key]; ok && v.Kind() == canonical.VString {
		return Sanitize(v.AsString())
	}
	return ""
}

func uintField(m map[string]canonical.Value, key string) uint64 {
	if v, ok := m[key]; ok {
		switch v.Kind() {
		case canonical.VInt64:
			if v.AsInt() >= 0 {
				return uint64(v.AsInt())
			}
		case canonical.VUint64:
			return v.AsUint()
		}
	}
	return 0
}

// summaryField renders argument summaries as "+ name = value".
func summaryField(m map[string]canonical.Value) string {
	if v, ok := m["arguments_summary"]; ok && v.Kind() == canonical.VList {
		parts := []string{}
		for _, item := range v.AsList() {
			if item.Kind() != canonical.VObject {
				continue
			}
			im := item.AsMap()
			n := ""
			val := ""
			if x, ok := im["name"]; ok && x.Kind() == canonical.VString {
				n = x.AsString()
			}
			if x, ok := im["value"]; ok && x.Kind() == canonical.VString {
				val = x.AsString()
			}
			parts = append(parts, n + " = " + Truncate(Sanitize(val), 60))
		}
		return strings.Join(parts, ", ")
	}
	return ""
}

func headerLine(m Model, width int) string {
	count := 0
	for _, a := range m.approvals {
		if a.State == "pending" {
			count++
		}
	}
	s := fmt.Sprintf(" RAID  approvals   %d pending", count)
	if !m.connected {
		s = s + "   [disconnected]"
	}
	return pad(s, width)
}

func pendingList(m Model, width int) string {
	rows := []string{}
	rows = append(rows, " ┌ Pending " + strings.Repeat("─", maxRune(0, width-11)) + "┐")
	// virtualized window: only render around the cursor (spec U01/U02)
	window := 24
	start := maxRune(0, m.cursor - window/2)
	for i, a := range m.approvals {
		if i < start || i > m.cursor + window/2 {
			continue
		}
		if m.filter != "" && !strings.Contains(a.AgentID + a.Operation + a.ResourceEnv, m.filter) {
			continue
		}
		mark := "  "
		if _, ok := m.selected[a.ID]; ok {
			mark = "● "
		}
		cursor := " "
		if i == m.cursor {
			cursor = "●"
			if _, ok := m.selected[a.ID]; ok {
				cursor = ">"
			}
		}
		ttl := ""
		if a.ExpiresAt.UnixNano() != 0 {
			remain := a.ExpiresAt.UnixNano() - time.Now().UTC().UnixNano()
			if remain < 0 {
				ttl = "expired"
			} else {
				ttl = fmtNanos(remain)
			}
		}
		row := " │ " + cursor + " " + mark
		row = row + pad(Truncate(a.AgentID, 12), 12)
		row = row + " " + pad(Truncate(a.Operation, 32), 32)
		row = row + " " + pad(Truncate(a.ResourceEnv, 12), 12)
		row = row + " " + pad(ttl, 8)
		rows = append(rows, truncateTo(row, width-3))
	}
	rows = append(rows, " └" + strings.Repeat("─", maxRune(0, width-2)) + "┘")
	return strings.Join(rows, "\n")
}

func requestDetail(m Model, width int) string {
	var sb strings.Builder
	sb.WriteString(" ┌ Request " + strings.Repeat("─", maxRune(0, width-11)) + "┐")
	if len(m.approvals) == 0 {
		sb.WriteString("\n │ (no pending approvals)"+ strings.Repeat(" ", maxRune(0, width-24)) + "│")
	} else {
		a := m.approvals[maxRune(0, m.cursor)]
		detail := []string{
			"Agent       " + a.AgentID + " / " + a.SessionID,
			"Action      " + a.Operation,
			"Resource    " + a.ResourceID,
			"Environment " + a.ResourceEnv,
		}
		if a.Summary != "" {
			detail = append(detail, "Arguments   " + a.Summary)
		}
		if m.detail {
			detail = append(detail, "Requester   " + a.SubjectID)
			detail = append(detail, "Reason      " + a.Reason)
			detail = append(detail, "Expires     " + a.ExpiresAt.Format(time.RFC3339))
		}
		for _, line := range detail {
			sb.WriteString("\n │ " + truncateTo(Sanitize(line), width-3))
		}
	}
	sb.WriteString("\n └" + strings.Repeat("─", maxRune(0, width-2)) + "┘")
	return sb.String()
}

func footerLine(m Model, width int) string {
	hint := " y approve once   n deny   d details   r refresh   / filter   ? help   q quit"
	if m.err != "" {
		hint = m.err
	}
	if m.filtering {
		hint = " filter: " + m.filter + "_"
	}
	return pad(hint, width)
}

// View returns the rendered view; Text extracts the raw string for tests.
func (m Model) ViewText() string {
	lines := []string{}
	lines = append(lines, headerLine(m, 80))
	lines = append(lines, pendingList(m, 80))
	lines = append(lines, requestDetail(m, 80))
	lines = append(lines, footerLine(m, 80))
	return strings.Join(lines, "\n") + "\n"
}

// isTTY reports whether a controlling terminal exists (spec 9.9).
func isTTY() bool {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func maxRune(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func pad(s string, width int) string {
	used := 0
	for _, r := range s {
		used = used + runeWidth(r)
	}
	if used >= width {
		return truncateTo(s, width)
	}
	return s + strings.Repeat(" ", width - used)
}

func truncateTo(s string, width int) string {
	return Truncate(s, width)
}

func fmtNanos(ns int64) string {
	secs := int(ns / int64(time.Second))
	m := secs / 60
	s := secs % 60
	return fmt.Sprintf("%02dm %02ds", m, s)
}