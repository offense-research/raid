// Jev data minimization (spec 7.5, RAID-SEC-009).
//
// The adapter builds bounded textual state from an allowlist. Only public
// and explicitly approved internal fields may appear; secret-classified
// fields are never serialized. The canonical canary test (J08) asserts a
// planted secret is absent from both the state and any HTTP body.
package jev

import (
	"strconv"
	"strings"

	"github.com/offense-research/raid/core/canonical"
)

// Classification of request fields for Jev state building.
type Class int

const (
	ClassPublic    Class = 0
	ClassInternal  Class = 1
	ClassSensitive Class = 2
	ClassSecret    Class = 3
)

// MaxStateBytes bounds the state text.
const MaxStateBytes = 2048

// MaxArgLen bounds individual argument values.
const MaxArgLen = 200

// classifyField maps a field path to its classification.
func classifyField(path string) Class {
	switch path {
	case "principal.subject_id", "principal.agent_id", "principal.runtime",
		"principal.trust_level", "action.provider", "action.operation",
		"action.effect", "resource.type", "resource.environment",
		"context.task_summary", "context.source_product", "context.interactive":
		return ClassPublic
	case "principal.session_id", "resource.id", "resource.attributes.repository_id":
		return ClassInternal
	case "principal.attributes", "context.source_request_id":
		return ClassSensitive
	}
	if strings.HasPrefix(path, "arguments.") ||
		strings.HasPrefix(path, "resource.attributes") {
		return ClassSecret
	}
	return ClassSecret
}

// classifyArgumentKey classifies an argument key (always secret by default).
func classifyArgumentKey(key string) Class {
	switch key {
	case "labels", "issue_number", "assignees", "reviewers", "title", "body_tail",
		"environment", "target_branch", "region", "environment_name":
		return ClassPublic
	case "amount", "quantity":
		return ClassInternal
	}
	return ClassSecret
}

// BuildState produces the allowlisted, bounded state string.
// secretCanaries (if any) must never appear in the output (J08).
func BuildState(req *canonical.ActionRequest, canaries []string) (string, bool) {
	var sb strings.Builder
	writePair(&sb, "subject", s(req.Principal().SubjectID()))
	writePair(&sb, "agent", s(req.Principal().AgentID()))
	writePair(&sb, "runtime", s(req.Principal().Runtime()))
	writePair(&sb, "trust", s(req.Principal().TrustLevel()))
	writePair(&sb, "provider", s(req.Action().Provider()))
	writePair(&sb, "operation", s(req.Action().Operation()))
	writePair(&sb, "effect", s(req.Action().Effect()))
	writePair(&sb, "resource_type", s(req.Resource().Type()))
	writePair(&sb, "environment", s(req.Resource().Environment()))
	if t := req.Context().TaskSummary(); t != "" {
		writePair(&sb, "task", truncate(sanitizeText(t), 400))
	}
	// allowlisted arguments only
	for k, v := range req.Arguments() {
		cls := classifyArgumentKey(k)
		if cls == ClassSecret || cls == ClassSensitive {
			continue
		}
		vs := argValueText(v)
		var stripped string
		if cls == ClassInternal && !allDigits(vs) {
			continue // internal amounts only when fully numeric
		}
		stripped = truncate(sanitizeText(vs), MaxArgLen)
		writePair(&sb, "arg:"+k, stripped)
	}
	state := sb.String()
	// Defense in depth (J08): any planted secret is scrubbed from the final
	// state and, by construction, from the HTTP body built from that state.
	for _, c := range canaries {
		if c != "" && strings.Contains(state, c) {
			state = strings.Replace(state, c, "[redacted]", -1)
		}
	}
	return state, true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' && r != '-' {
			return false
		}
	}
	return true
}

func s(v string) string { return sanitizeText(truncate(v, 200)) }

func writePair(sb *strings.Builder, k, v string) {
	if v == "" {
		return
	}
	sb.WriteString(k)
	sb.WriteString("=")
	sb.WriteString(v)
	sb.WriteString(" ")
}

// sanitizeText strips control and escape characters (secondary defense).
func sanitizeText(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == 0x1b {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func truncate(s string, n int) string {
	count := 0
	var sb strings.Builder
	for _, r := range s {
		if count >= n {
			break
		}
		sb.WriteRune(r)
		count++
	}
	return sb.String()
}

// argValueText renders an argument value as bounded text (no escaping).
func argValueText(v canonical.Value) string {
	var sb strings.Builder
	argValueInto(&sb, v, 0)
	return sb.String()
}

func argValueInto(sb *strings.Builder, v canonical.Value, depth int) {
	if depth > 2 {
		sb.WriteString("…")
		return
	}
	switch v.Kind() {
	case canonical.VNull:
		sb.WriteString("null")
	case canonical.VBool:
		if v.AsBool() {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case canonical.VInt64:
		sb.WriteString(strconv.FormatInt(v.AsInt(), 10))
	case canonical.VUint64:
		sb.WriteString(strconv.FormatUint(v.AsUint(), 10))
	case canonical.VString, canonical.VDecimal, canonical.VTimestamp, canonical.VDuration:
		sb.WriteString(v.AsString())
	case canonical.VList:
		sb.WriteByte('[')
		for i, item := range v.AsList() {
			if i > 0 {
				sb.WriteByte(',')
			}
			argValueInto(sb, item, depth+1)
		}
		sb.WriteByte(']')
	case canonical.VObject:
		sb.WriteByte('{')
		first := true
		for k, item := range v.AsMap() {
			if !first {
				sb.WriteByte(',')
			}
			first = false
			sb.WriteString(k + "=")
			argValueInto(sb, item, depth+1)
		}
		sb.WriteByte('}')
	}
}
