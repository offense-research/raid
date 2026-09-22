// Deterministic evaluation of a compiled bundle against a normalized request.
package policy

import (
	"strconv"
	"time"

	"offense.dev/raid/core/canonical"
)

// BaseDecision is the deterministic outcome before any semantic guard.
type BaseDecision struct {
	effect         string // allow | deny | require_approval | error
	reasonCode     string
	matchedRuleIDs []string
	approvalRule   *CompiledRule // set when effect == require_approval
	errorMsg       string
}

func (b *BaseDecision) Effect() string          { return b.effect }
func (b *BaseDecision) ReasonCode() string      { return b.reasonCode }
func (b *BaseDecision) MatchedRuleIDs() []string { return b.matchedRuleIDs }
func (b *BaseDecision) ApprovalRule() *CompiledRule { return b.approvalRule }
func (b *BaseDecision) IsError() bool           { return b.effect == "error" }

// Rank orders effects: allow < require_approval < deny; none < allow.
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

// BuildActivation converts a normalized request into the CEL environment
// input. Timestamps become time.Time, durations become time.Duration,
// decimals become float64 (CEL-Go has no decimal type; exactness is retained
// in the typed Value layer and the request hash), and unsigned integers are
// passed through natively.
func BuildActivation(req *canonical.ActionRequest) map[string]any {
	return map[string]any{
		"principal": map[string]any{
			"subject_id":  req.Principal().SubjectID(),
			"agent_id":    req.Principal().AgentID(),
			"session_id":  req.Principal().SessionID(),
			"runtime":     req.Principal().Runtime(),
			"groups":      strList(req.Principal().Groups()),
			"trust_level": req.Principal().TrustLevel(),
			"revision":    int64(req.Principal().Revision()),
		},
		"action": map[string]any{
			"provider":  req.Action().Provider(),
			"operation": req.Action().Operation(),
			"effect":    req.Action().Effect(),
		},
		"resource": map[string]any{
			"type":        req.Resource().Type(),
			"id":          req.Resource().ID(),
			"environment": req.Resource().Environment(),
			"attributes":  strMap(req.Resource().Attributes()),
		},
		"arguments": argsMap(req.Arguments()),
		"context":   contextMap(req),
	}
}

func strList(in []string) []any {
	out := []any{}
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

func strMap(in map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

// argsMap converts the typed Value union to native CEL values.
func argsMap(in map[string]canonical.Value) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = valueToAny(v)
	}
	return out
}

func valueToAny(v canonical.Value) any {
	switch v.Kind() {
	case canonical.VNull:
		return nil
	case canonical.VBool:
		return v.AsBool()
	case canonical.VInt64:
		return v.AsInt()
	case canonical.VUint64:
		return v.AsUint()
	case canonical.VString:
		return v.AsString()
	case canonical.VDecimal:
		f, _ := strconv.ParseFloat(v.AsString(), 64)
		return f
	case canonical.VTimestamp:
		t, _ := time.Parse(time.RFC3339, v.AsTimestampText())
		return t
	case canonical.VDuration:
		d, _ := time.ParseDuration(v.AsDurationText())
		return d
	case canonical.VList:
		out := []any{}
		for _, item := range v.AsList() {
			out = append(out, valueToAny(item))
		}
		return out
	case canonical.VObject:
		out := map[string]any{}
		for k, item := range v.AsMap() {
			out[k] = valueToAny(item)
		}
		return out
	}
	return nil
}

func contextMap(req *canonical.ActionRequest) map[string]any {
	ts, has := req.Context().Timestamp()
	m := map[string]any{
		"source_product":    req.Context().SourceProduct(),
		"source_version":    req.Context().SourceVersion(),
		"source_request_id": req.Context().SourceRequestID(),
		"interactive":       req.Context().Interactive(),
	}
	if req.Context().TaskSummary() != "" {
		m["task_summary"] = req.Context().TaskSummary()
	}
	if has {
		m["timestamp"] = ts
	}
	return m
}

// ErrorResult builds a fail-closed base decision.
func ErrorResult(code string) *BaseDecision {
	return &BaseDecision{effect: "error", reasonCode: code}
}

// EvaluateBundle evaluates all candidate rules and combines matching effects
// monotonically (deny > require_approval > allow > default). CEL errors are
// not false: they produce an error result that the engine maps to deny.
func EvaluateBundle(b *CompiledBundle, req *canonical.ActionRequest) *BaseDecision {
	ix := b.Index()
	action := req.Action()
	rsrc := req.Resource()
	candidates := ix.Candidates(action.Operation(), action.Provider(), action.Effect(), rsrc.Environment())
	activation := BuildActivation(req)
	effect := ""
	matched := []string{}
	var approvalRule *CompiledRule = nil
	for _, idx := range candidates {
		r := ix.rules[int(idx)]
		if !r.MatchStatic(action.Operation(), action.Provider(), action.Effect(), rsrc.Environment()) {
			continue
		}
		match, err := r.EvaluateWhen(activation)
		if err != nil {
			return ErrorResult("POLICY_EVALUATION_ERROR")
		}
		if !match {
			continue
		}
		matched = append(matched, r.ID())
		if rank(r.Effect()) > rank(effect) {
			effect = r.Effect()
		}
		if r.Effect() == "require_approval" && approvalRule == nil && r.Approval() != nil {
			approvalRule = r
		}
	}
	if effect == "" {
		// no rule matched: the bundle default applies (deny by default)
		effect = b.DefaultEffect()
	}
	if effect == "error" {
		return ErrorResult("POLICY_EVALUATION_ERROR")
	}
	code := "POLICY_ALLOW"
	if effect == "deny" {
		code = "POLICY_DENY"
	} else if effect == "require_approval" {
		code = "POLICY_REQUIRES_APPROVAL"
	}
	return &BaseDecision{
		effect:         effect,
		reasonCode:     code,
		matchedRuleIDs: matched,
		approvalRule:   approvalRule,
	}
}