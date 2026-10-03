// Semantic escalation orchestration (spec 7.6): deterministic first, Jev
// only when required, monotonic combination, fail-closed on errors.
package decision

import (
	"time"

	"github.com/offense-research/raid/core/canonical"
	"github.com/offense-research/raid/core/jev"
	"github.com/offense-research/raid/core/policy"
)

// ApplySemantic runs the evaluator and combines monotonically.
// Returns (finalDecision, skipped); skipped=true when Jev was not required.
func ApplySemantic(base *Decision, guard *policy.CompiledGuard, evaluator jev.SemanticEvaluator,
	req *canonical.ActionRequest) (*Decision, bool, error) {
	if guard == nil || evaluator == nil || guard.Mode() == "off" {
		return base, true, nil
	}
	// Rule 3: a deterministic deny returns without Jev.
	if base.Effect() == "deny" {
		return base, true, nil
	}
	// Rule 5: if base is require_approval and Jev cannot escalate to a
	// configured deny, skip Jev.
	if base.Effect() == "require_approval" && guard.Escalation() != "deny" {
		return base, true, nil
	}
	// build allowlisted state
	state, clean := jev.BuildState(req, nil)
	if !clean {
		return injectSemantic(base, guard.FailureEffect(), "sanitize-guard-error"), false, nil
	}
	in := &jev.SemanticInput{State: state, Ceiling: guard.Escalation()}
	start := time.Now()
	result, err := evaluator.Evaluate(*in)
	latency := time.Since(start).Milliseconds()
	_ = latency
	if err != nil {
		// Jev failure never falls back to allow (spec 7.7).
		fx := guard.FailureEffect()
		if rankFx(fx) < 1 {
			fx = "require_approval"
		}
		return injectSemantic(base, fx, "evaluation-failure"), false, nil
	}
	// thresholds applied by the evaluator result; combine monotonically
	escalation := result.EscalationEffect()
	if guard.Mode() == "shadow" {
		// shadow mode records evidence without changing the outcome
		return attachEvidence(base, result), false, nil
	}
	if escalation != "" && rankFx(escalation) > rankFx(base.Effect()) {
		final := base
		if escalation == "deny" {
			final = setSemantic(base, "deny", "POLICY_DENY", result)
		} else {
			final = setSemantic(base, "require_approval", "POLICY_REQUIRES_APPROVAL", result)
		}
		return final, false, nil
	}
	return attachEvidence(base, result), false, nil
}

func injectSemantic(d *Decision, effect, reason string) *Decision {
	var nf Decision
	nf = *d
	nf.effect = effect
	nf.semantic = &SemanticSummary{escalation: effect, model: "jev", questions: "agent-action-risk-v1", latencyMs: 0}
	if effect == "require_approval" {
		nf.reasonCode = "POLICY_REQUIRES_APPROVAL"
	} else {
		nf.reasonCode = "POLICY_EVALUATION_ERROR"
	}
	c := nf.CopySemantic()
	return c
}

func attachEvidence(d *Decision, r *jev.SemanticResult) *Decision {
	var nf Decision
	nf = *d
	nf.semantic = &SemanticSummary{
		escalation: r.EscalationEffect(), model: r.ModelVersion(),
		questions: r.QuestionSet, latencyMs: r.Latency(),
	}
	return nf.CopySemantic()
}

func setSemantic(d *Decision, effect, reason string, r *jev.SemanticResult) *Decision {
	var nf Decision
	nf = *d
	nf.effect = effect
	nf.reasonCode = reason
	nf.semantic = &SemanticSummary{
		escalation: r.EscalationEffect(), model: r.ModelVersion(),
		questions: r.QuestionSet, latencyMs: r.Latency(),
	}
	return nf.CopySemantic()
}

func rankFx(e string) int {
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
