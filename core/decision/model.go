// Decision output model and effect ranking.
package decision

import (
	"fmt"
	"strings"
	"time"

	"offense.dev/raid/core/canonical"
	"offense.dev/raid/core/policy"
)

// Effect rank: ALLOW < REQUIRE_APPROVAL < DENY (spec section 2.3).
func Rank(e string) int {
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

// CombineEffects returns max(a, b) under the monotonic ordering.
func CombineEffects(a, b string) string {
	if Rank(b) > Rank(a) {
		return b
	}
	return a
}

// ApprovalReference is the safe subset of an approval returned with a
// decision. It intentionally carries no argument or approver detail.
type ApprovalReference struct {
	id        string
	state     string
	expiresAt time.Time
}

// NewApprovalReference builds the safe reference to a durable approval.
func NewApprovalReference(id, state string, expiresAt time.Time) *ApprovalReference {
	return &ApprovalReference{id: id, state: state, expiresAt: expiresAt}
}

func (a *ApprovalReference) ID() string          { return a.id }
func (a *ApprovalReference) State() string       { return a.state }
func (a *ApprovalReference) ExpiresAt() time.Time { return a.expiresAt }

// SemanticSummary records semantic-evaluation evidence (no raw state).
type SemanticSummary struct {
	escalation string
	model      string
	questions  string
	latencyMs  int64
}

func (s *SemanticSummary) Escalation() string { return s.escalation }
func (s *SemanticSummary) Model() string      { return s.model }
func (s *SemanticSummary) Questions() string  { return s.questions }
func (s *SemanticSummary) LatencyMs() int64   { return s.latencyMs }

// Decision is the complete, immutable evaluation result.
type Decision struct {
	id               string
	effect           string
	reasonCode       string
	requestHash      []byte
	policyBundleID   string
	policyBundleHash []byte
	matchedRuleIDs   []string
	approval         *ApprovalReference
	approvalConfig   *policy.ApprovalConfig
	grantID          string
	semantic         *SemanticSummary
	evaluatedAt      time.Time
	expiresAt        time.Time
	evaluationMicros int64
}

func (d *Decision) ID() string                 { return d.id }
func (d *Decision) Effect() string             { return d.effect }
func (d *Decision) ReasonCode() string         { return d.reasonCode }
func (d *Decision) RequestHash() []byte        { return d.requestHash }
func (d *Decision) PolicyBundleID() string     { return d.policyBundleID }
func (d *Decision) PolicyBundleHash() []byte   { return d.policyBundleHash }
func (d *Decision) MatchedRuleIDs() []string   { return d.matchedRuleIDs }
func (d *Decision) Approval() *ApprovalReference { return d.approval }
func (d *Decision) ApprovalConfig() *policy.ApprovalConfig { return d.approvalConfig }
func (d *Decision) GrantID() string             { return d.grantID }
func (d *Decision) Semantic() *SemanticSummary { return d.semantic }
func (d *Decision) EvaluatedAt() time.Time     { return d.evaluatedAt }
func (d *Decision) ExpiresAt() time.Time       { return d.expiresAt }
func (d *Decision) EvaluationMicros() int64    { return d.evaluationMicros }

// CopySemantic derives an editable copy (same package field access).
func (d *Decision) CopySemantic() *Decision {
	c := *d
	return &c
}

// NewDecision constructs a decision; only the engine may do this.
func NewDecision(id, effect, reasonCode string, requestHash []byte,
	policyBundleID string, policyBundleHash []byte, ruleIDs []string,
	evaluatedAt, expiresAt time.Time, micros int64) *Decision {
	return &Decision{
		id: id, effect: effect, reasonCode: reasonCode,
		requestHash: requestHash, policyBundleID: policyBundleID,
		policyBundleHash: policyBundleHash, matchedRuleIDs: ruleIDs,
		evaluatedAt: evaluatedAt, expiresAt: expiresAt,
		evaluationMicros: micros,
	}
}

// AttachApproval is defined below; see WithApproval.

func (d *Decision) WithSemantic(s *SemanticSummary) *Decision {
	return &Decision{
		id: d.id, effect: d.effect, reasonCode: d.reasonCode,
		requestHash: d.requestHash, policyBundleID: d.policyBundleID,
		policyBundleHash: d.policyBundleHash, matchedRuleIDs: d.matchedRuleIDs,
		approval: d.approval, approvalConfig: d.approvalConfig, grantID: d.grantID,
		semantic: s,
		evaluatedAt: d.evaluatedAt, expiresAt: d.expiresAt,
		evaluationMicros: d.evaluationMicros,
	}
}

// WithApprovalConfig attaches the approval configuration the engine found,
// so the service layer can create the durable approval.
func (d *Decision) WithApprovalConfig(c *policy.ApprovalConfig) *Decision {
	return &Decision{
		id: d.id, effect: d.effect, reasonCode: d.reasonCode,
		requestHash: d.requestHash, policyBundleID: d.policyBundleID,
		policyBundleHash: d.policyBundleHash, matchedRuleIDs: d.matchedRuleIDs,
		approval: d.approval, approvalConfig: c, grantID: d.grantID,
		semantic: d.semantic,
		evaluatedAt: d.evaluatedAt, expiresAt: d.expiresAt,
		evaluationMicros: d.evaluationMicros,
	}
}

// WithApproval attaches the durable approval reference.
func (d *Decision) WithApproval(a *ApprovalReference) *Decision {
	return &Decision{
		id: d.id, effect: d.effect, reasonCode: d.reasonCode,
		requestHash: d.requestHash, policyBundleID: d.policyBundleID,
		policyBundleHash: d.policyBundleHash, matchedRuleIDs: d.matchedRuleIDs,
		approval: a, approvalConfig: d.approvalConfig, grantID: d.grantID,
		semantic: d.semantic,
		evaluatedAt: d.evaluatedAt, expiresAt: d.expiresAt,
		evaluationMicros: d.evaluationMicros,
	}
}

// WithGrantCoverage rewrites a require_approval decision into an allow when a
// previously approved scoped grant covers the request. It records the grant id
// so the audit trail shows the authorization came from a grant, not the
// deterministic rules.
func (d *Decision) WithGrantCoverage(grantID string) *Decision {
	return &Decision{
		id: d.id, effect: "allow", reasonCode: ReasonGrantCovered,
		requestHash: d.requestHash, policyBundleID: d.policyBundleID,
		policyBundleHash: d.policyBundleHash, matchedRuleIDs: d.matchedRuleIDs,
		approval: nil, approvalConfig: d.approvalConfig, grantID: grantID,
		semantic: d.semantic,
		evaluatedAt: d.evaluatedAt, expiresAt: d.expiresAt,
		evaluationMicros: d.evaluationMicros,
	}
}

// WriteJSON appends the wire representation of the decision.
func (d *Decision) WriteJSON(sb *strings.Builder) () {
	sb.WriteString(`{"id":`)
	canonical.WriteEscaped(sb, d.id)
	sb.WriteString(`,"effect":"` + d.effect + `","reason_code":`)
	canonical.WriteEscaped(sb, d.reasonCode)
	sb.WriteString(`,"request_hash":`)
	canonical.WriteEscaped(sb, canonical.RequestHashString(d.requestHash))
	sb.WriteString(`,"policy_bundle_id":`)
	canonical.WriteEscaped(sb, d.policyBundleID)
	sb.WriteString(`,"policy_bundle_hash":`)
	canonical.WriteEscaped(sb, canonical.RequestHashString(d.policyBundleHash))
	sb.WriteString(`,"matched_rule_ids":[`)
	for i, r := range d.matchedRuleIDs {
		if i > 0 {
			sb.WriteByte(',')
		}
		canonical.WriteEscaped(sb, r)
	}
	sb.WriteByte(']')
	if d.approval != nil {
		sb.WriteString(`,"approval":`)
		sb.WriteString(`{"id":`)
		canonical.WriteEscaped(sb, d.approval.id)
		sb.WriteString(`,"state":`)
		canonical.WriteEscaped(sb, d.approval.state)
		sb.WriteString(`,"expires_at":`)
		canonical.WriteEscaped(sb, d.approval.expiresAt.Format(time.RFC3339))
		sb.WriteString(`}`)
	}
	if d.grantID != "" {
		sb.WriteString(`,"grant_id":`)
		canonical.WriteEscaped(sb, d.grantID)
	}
	if d.semantic != nil {
		sb.WriteString(`,"semantic":`)
		sb.WriteString(`{"escalation":`)
		canonical.WriteEscaped(sb, d.semantic.escalation)
		sb.WriteString(`,"model":`)
		canonical.WriteEscaped(sb, d.semantic.model)
		sb.WriteString(`,"questions":`)
		canonical.WriteEscaped(sb, d.semantic.questions)
		sb.WriteString(`,"latency_ms":`)
		sb.WriteString(fmt.Sprintf("%d", d.semantic.latencyMs))
		sb.WriteString(`}`)
	}
	sb.WriteString(`,"evaluated_at":`)
	canonical.WriteEscaped(sb, d.evaluatedAt.Format(time.RFC3339))
	sb.WriteString(`,"expires_at":`)
	canonical.WriteEscaped(sb, d.expiresAt.Format(time.RFC3339))
	sb.WriteString(`,"evaluation_micros":`)
	sb.WriteString(fmt.Sprintf("%d", d.evaluationMicros))
	sb.WriteString(`}`)
}

// WriteJSONString renders the decision as a JSON document.
func (d *Decision) WriteJSONString() string {
	var sb strings.Builder
	d.WriteJSON(&sb)
	return sb.String()
}