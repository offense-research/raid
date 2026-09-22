// Safe terminal-string sanitizer (spec 9.8, U05).
//
// Untrusted fields (agent ids, resource ids, task summaries) pass through
// here before rendering: ANSI escapes, OSC sequences, and C0 controls are
// rendered inert.
package tui

import "strings"

// Sanitize strips terminal control sequences from untrusted text.
func Sanitize(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if !safeRune(r) {
			sb.WriteRune('\uFFFD')
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func safeRune(r rune) bool {
	if r == '\n' || r == '\t' {
		return true
	}
	// C0 controls and DEL stay out; everything printable passes.
	if r < 0x20 || r == 0x7f {
		return false
	}
	// ESC is the start of any ANSI/OSC sequence.
	if r == 0x1b {
		return false
	}
	return true
}

// Truncate caps a line's display width safely.
func Truncate(s string, maxRunes int) string {
	total := 0
	var sb strings.Builder
	for _, r := range s {
		if !safeRune(r) {
			continue
		}
		width := runeWidth(r)
		if total + width > maxRunes {
			sb.WriteString("…")
			return sb.String()
		}
		total = total + width
		if r != '\t' {
			sb.WriteRune(r)
		} else {
			sb.WriteString("    ")
		}
	}
	return sb.String()
}

// runeWidth approximates display width (1 or 2 columns).
func runeWidth(r rune) int {
	if r >= 0x1100 &&
		(r <= 0x115f ||
		 r == 0x2329 || r == 0x232a ||
		 (r >= 0x2e80 && r <= 0xa4cf && r != 0x303f) ||
		 (r >= 0xac00 && r <= 0xd7a3) ||
		 (r >= 0xf900 && r <= 0xfaff) ||
		 (r >= 0xfe10 && r <= 0xfe19) ||
		 (r >= 0xfe30 && r <= 0xfe6f) ||
		 (r >= 0xff00 && r <= 0xff60) ||
		 (r >= 0xffe0 && r <= 0xffe6) ||
		 (r >= 0x20000 && r <= 0x2fffd) ||
		 (r >= 0x30000 && r <= 0x3fffd)) {
		return 2
	}
	return 1
}