// The deterministic decision engine: hard rules, atomic bundle snapshot,
// policy evaluation, and decision construction.
package decision

import (
	"sync/atomic"
	"time"

	"offense.dev/raid/core/canonical"
	"offense.dev/raid/core/policy"
	"offense.dev/raid/core/util"
)

// Reason codes (fail-closed surface).
const (
	ReasonInputInvalid     = "POLICY_INPUT_INVALID"
	ReasonNoBundle         = "POLICY_BUNDLE_UNAVAILABLE"
	ReasonEvalError        = "POLICY_EVALUATION_ERROR"
	ReasonAllow            = "POLICY_ALLOW"
	ReasonDeny             = "POLICY_DENY"
	ReasonRequiresApproval = "POLICY_REQUIRES_APPROVAL"
	ReasonGrantCovered     = "POLICY_GRANT_COVERED"
)

// DecisionTTL bounds how long any decision (allow or deny) may be cached by
// consumers before re-evaluation.
const DecisionTTL = 30 * time.Second

// Engine evaluates normalized requests against one immutable policy snapshot.
// Exactly one bundle version is used from the start to the end of a request.
type Engine struct {
	active atomic.Pointer[policy.CompiledBundle]
}

// NewEngine returns an engine with no active bundle (fails closed).
func NewEngine() *Engine {
	return &Engine{}
}

// Activate atomically swaps the active bundle. Compilation and validation
// must already have happened off the hot path.
func (e *Engine) Activate(b *policy.CompiledBundle) {
	e.active.Store(b)
}

// Active returns the active bundle (nil when none).
func (e *Engine) Active() *policy.CompiledBundle {
	return e.active.Load()
}

// Base runs the hard rules and deterministic policy against one bundle
// snapshot. The returned decision is never an allow without authority.
func (e *Engine) Evaluate(req *canonical.ActionRequest) *Decision {
	start := time.Now()
	now := start.UTC()
	expires := now.Add(DecisionTTL)
	bundle := e.active.Load()
	if bundle == nil {
		return NewDecision(util.NewID("dec"), "deny", ReasonNoBundle,
			canonical.HashRequest(req), "", nil, nil, now, expires,
			time.Since(start).Microseconds())
	}
	hash := canonical.HashRequest(req)
	res := policy.EvaluateBundle(bundle, req)
	if res.IsError() {
		return NewDecision(util.NewID("dec"), "deny", res.ReasonCode(),
			hash, bundle.ID(), bundle.Hash(), nil, now, expires,
			time.Since(start).Microseconds())
	}
	d := NewDecision(util.NewID("dec"), res.Effect(), res.ReasonCode(),
		hash, bundle.ID(), bundle.Hash(), res.MatchedRuleIDs(), now, expires,
		time.Since(start).Microseconds())
	if res.Effect() == "require_approval" && res.ApprovalRule() != nil {
		d = d.WithApprovalConfig(res.ApprovalRule().Approval())
	}
	return d
}