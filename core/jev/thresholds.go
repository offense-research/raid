// Threshold application and monotonic combination (spec 7.1-7.2, 7.6).
package jev

import (
	"slices"
	"strconv"
	"strings"

	"offense.dev/raid/core/canonical"
)



// Answer is one typed judgment response.
type Answer struct {
	Choice string
	Score  float64   // 0..1 normalized
	Valid  bool
}

// SemanticResult is the outcome of a Jev evaluation.
type SemanticResult struct {
	Escalation string // "" | require_approval | deny
	Model      string
	QuestionSet string
	LatencyMs  int64
	Answers    string // compact JSON evidence (sanitized)
}

func (r *SemanticResult) EscalationEffect() string { return r.Escalation }
func (r *SemanticResult) ModelVersion() string     { return r.Model }
func (r *SemanticResult) Latency() int64           { return r.LatencyMs }

// EscalationNone / constants.
var EscalationNone = ""

// Thresholds maps question id -> scalar threshold.
type Thresholds struct {
	m map[string]float64
}

// FromConfig builds thresholds from a policy guard config.
func FromConfig(m map[string]float64) Thresholds {
	out := map[string]float64{}
	// defaults from the spec (section 7.3)
	out["credential_exposure"] = 0.20
	out["prompt_injection"] = 0.35
	out["intent_mismatch"] = 0.45
	out["impact"] = 0.60
	out["ambiguity"] = 2.0
	for k, v := range m {
		out[k] = v
	}
	return Thresholds{m: out}
}

// ThresholdsHash returns a stable fingerprint for cache keys.
func (t Thresholds) Hash() []byte {
	keys := []string{}
	for k := range t.m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k + "=" + strconv.FormatFloat(t.m[k], byte('g'), 6, 64) + ";")
	}
	return canonical.HashBytes([]byte(sb.String()))
}

// ApplyQuestion merges one answer into the running judgment.
type Accum struct {
	crossed map[string]string // question -> evidence
}

// crossedThreshold reports whether an answer breaches its threshold.
func (t Thresholds) Crossed(question string, score float64) bool {
	th, ok := t.m[question]
	if !ok {
		return false
	}
	return score >= th
}

// decideEscalation returns the escalation effect when any threshold crossed.
func (t Thresholds) DecideEscalation(answers map[string]Answer, escalationCeiling string) string {
	crossed := []string{}
	for id, a := range answers {
		if !a.Valid {
			continue
		}
		if t.Crossed(id, a.Score) {
			crossed = append(crossed, id)
		}
	}
	if len(crossed) > 0 {
		if escalationCeiling == "deny" {
			return "deny"
		}
		return "require_approval"
	}
	return EscalationNone
}

// combine applies the monotonic ordering: final = max(base, semantic).
// A semantic escalation can never reduce restriction (RAID-SEC-002).
func combine(base, semantic string) string {
	if rank(semantic) > rank(base) {
		return semantic
	}
	return base
}

func rank(e string) int {
	switch e {
	case "allow":
		return 0
	case "require_approval":
		return 1
	case "deny":
		return 2
	}
	return -1
}

// EvidenceJSON renders sanitized answer evidence.
func EvidenceJSON(answers map[string]Answer) string {
	keys := []string{}
	for k := range answers {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var sb strings.Builder
	sb.WriteByte('[')
	first := true
	for _, k := range keys {
		a := answers[k]
		if !first {
			sb.WriteByte(',')
		}
		first = false
		sb.WriteString(`{"q":`)
		esJ(&sb, k)
		sb.WriteString(`,"choice":`)
		esJ(&sb, a.Choice)
		sb.WriteString(`,"p":`)
		sb.WriteString(strconv.FormatFloat(a.Score, byte('g'), 4, 64))
		sb.WriteByte('}')
	}
	sb.WriteByte(']')
	return sb.String()
}

func esJ(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for _, r := range s {
		if r == '"' {
			sb.WriteString(`\"`)
		} else if r == '\\' {
			sb.WriteString(`\\`)
		} else if r >= 0x20 && r != 0x7f {
			sb.WriteRune(r)
		}
	}
	sb.WriteByte('"')
}

