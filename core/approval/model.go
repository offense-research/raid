// Approval domain model (spec section 8).
package approval

import (
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"offense.dev/raid/core/canonical"
	"offense.dev/raid/core/signing"
)

// State is an approval lifecycle state.
type State string

const (
	StatePending    State = "pending"
	StateApproved   State = "approved"
	StateDenied     State = "denied"
	StateExpired    State = "expired"
	StateCancelled  State = "cancelled"
	StateConsumed   State = "consumed"
	StateSuperseded State = "superseded"
)

// IsTerminal reports whether the state cannot transition further.
func IsTerminal(s State) bool {
	switch s {
	case StateDenied, StateExpired, StateCancelled, StateConsumed, StateSuperseded:
		return true
	}
	return false
}

// SafeField is a server-generated, size-limited argument summary.
type SafeField struct {
	name  string
	value string
}

func (f SafeField) Name() string  { return f.name }
func (f SafeField) Value() string { return f.value }

// Approval is the durable, request-bound approval.
type Approval struct {
	id               string
	decisionID       string
	requestHash      []byte
	principalID      string
	agentID          string
	sessionID        string
	operation        string
	resourceType     string
	resourceID       string
	environment      string
	argumentsSummary []SafeField
	policyBundleHash []byte
	matchedRuleIDs   []string
	requiredGroups   []string
	quorum           uint32
	allowScope       string
	votes            int64
	state            State
	version          uint64
	createdAt        time.Time
	expiresAt        time.Time
	resolvedAt       *time.Time
}

func (a *Approval) ID() string               { return a.id }
func (a *Approval) DecisionID() string       { return a.decisionID }
func (a *Approval) RequestHash() []byte      { return a.requestHash }
func (a *Approval) PrincipalID() string      { return a.principalID }
func (a *Approval) AgentID() string          { return a.agentID }
func (a *Approval) SessionID() string        { return a.sessionID }
func (a *Approval) Operation() string        { return a.operation }
func (a *Approval) ResourceType() string     { return a.resourceType }
func (a *Approval) ResourceID() string       { return a.resourceID }
func (a *Approval) Environment() string      { return a.environment }
func (a *Approval) ArgumentsSummary() []SafeField { return a.argumentsSummary }
func (a *Approval) PolicyBundleHash() []byte { return a.policyBundleHash }
func (a *Approval) MatchedRuleIDs() []string { return a.matchedRuleIDs }
func (a *Approval) RequiredGroups() []string { return a.requiredGroups }
func (a *Approval) Quorum() uint32           { return a.quorum }
func (a *Approval) AllowScope() string       { return a.allowScope }
func (a *Approval) Votes() int64             { return a.votes }
func (a *Approval) State() State             { return a.state }
func (a *Approval) Version() uint64          { return a.version }
func (a *Approval) CreatedAt() time.Time     { return a.createdAt }
func (a *Approval) ExpiresAt() time.Time     { return a.expiresAt }
func (a *Approval) ResolvedAt() *time.Time   { return a.resolvedAt }

// WriteJSON renders the safe approver-facing representation.
func (a *Approval) WriteJSON(sb *strings.Builder) () {
	sb.WriteString(`{"id":`)
	canonical.WriteEscaped(sb, a.id)
	sb.WriteString(`,"decision_id":`)
	canonical.WriteEscaped(sb, a.decisionID)
	sb.WriteString(`,"request_hash":`)
	canonical.WriteEscaped(sb, canonical.RequestHashString(a.requestHash))
	sb.WriteString(`,"principal_id":`)
	canonical.WriteEscaped(sb, a.principalID)
	sb.WriteString(`,"agent_id":`)
	canonical.WriteEscaped(sb, a.agentID)
	sb.WriteString(`,"session_id":`)
	canonical.WriteEscaped(sb, a.sessionID)
	sb.WriteString(`,"operation":`)
	canonical.WriteEscaped(sb, a.operation)
	sb.WriteString(`,"resource_type":`)
	canonical.WriteEscaped(sb, a.resourceType)
	sb.WriteString(`,"resource_id":`)
	canonical.WriteEscaped(sb, a.resourceID)
	sb.WriteString(`,"environment":`)
	canonical.WriteEscaped(sb, a.environment)
	sb.WriteString(`,"arguments_summary":[`)
	for i, f := range a.argumentsSummary {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`{"name":`)
		canonical.WriteEscaped(sb, f.name)
		sb.WriteString(`,"value":`)
		canonical.WriteEscaped(sb, f.value)
		sb.WriteByte('}')
	}
	sb.WriteByte(']')
	sb.WriteString(`,"matched_rule_ids":[`)
	for i, r := range a.matchedRuleIDs {
		if i > 0 {
			sb.WriteByte(',')
		}
		canonical.WriteEscaped(sb, r)
	}
	sb.WriteByte(']')
	sb.WriteString(`,"required_groups":[`)
	for i, g := range a.requiredGroups {
		if i > 0 {
			sb.WriteByte(',')
		}
		canonical.WriteEscaped(sb, g)
	}
	sb.WriteByte(']')
	sb.WriteString(`,"quorum":`)
	sb.WriteString(strconv.FormatUint(uint64(a.quorum), 10))
	sb.WriteString(`,"allow_scope":`)
	canonical.WriteEscaped(sb, a.allowScope)
	sb.WriteString(`,"votes":`)
	sb.WriteString(strconv.FormatInt(a.votes, 10))
	sb.WriteString(`,"state":`)
	canonical.WriteEscaped(sb, string(a.state))
	sb.WriteString(`,"version":`)
	sb.WriteString(strconv.FormatUint(a.version, 10))
	sb.WriteString(`,"created_at":`)
	canonical.WriteEscaped(sb, a.createdAt.Format(time.RFC3339))
	sb.WriteString(`,"expires_at":`)
	canonical.WriteEscaped(sb, a.expiresAt.Format(time.RFC3339))
	if a.resolvedAt != nil {
		sb.WriteString(`,"resolved_at":`)
		canonical.WriteEscaped(sb, a.resolvedAt.Format(time.RFC3339))
	}
	sb.WriteByte('}')
}

// ClaimsFromApproveJSON parses the receipt claims from an approve response
// body so consumers can verify exact binding.
func ClaimsFromApproveJSON(body string) *signing.Claims {
	v, perr := canonical.Decode([]byte(body), canonical.DecodeOptions{MaxBytes: 1 * 1024 * 1024})
	if perr != nil || v.Kind() != canonical.VObject {
		return nil
	}
	rec, ok := v.AsMap()["receipt"]
	if !ok || rec.Kind() != canonical.VObject {
		return nil
	}
	c, ok := rec.AsMap()["claims"]
	if !ok || c.Kind() != canonical.VObject {
		return nil
	}
	m := c.AsMap()
	var cl signing.Claims
	cl.Version = 1
	if x, ok := m["receipt_id"]; ok && x.Kind() == canonical.VString {
		cl.ReceiptID = x.AsString()
	}
	if x, ok := m["approval_id"]; ok && x.Kind() == canonical.VString {
		cl.ApprovalID = x.AsString()
	}
	if x, ok := m["decision_id"]; ok && x.Kind() == canonical.VString {
		cl.DecisionID = x.AsString()
	}
	if x, ok := m["request_hash"]; ok && x.Kind() == canonical.VString {
		cl.RequestHash, _ = hex.DecodeString(hexBody(x.AsString()))
	}
	if x, ok := m["policy_bundle_hash"]; ok && x.Kind() == canonical.VString {
		cl.PolicyBundleHash, _ = hex.DecodeString(hexBody(x.AsString()))
	}
	if x, ok := m["effect"]; ok && x.Kind() == canonical.VString {
		cl.Effect = x.AsString()
	}
	if x, ok := m["issued_at"]; ok {
		cl.IssuedAt = jsonInt(x)
	}
	if x, ok := m["expires_at"]; ok {
		cl.ExpiresAt = jsonInt(x)
	}
	if x, ok := m["nonce"]; ok && x.Kind() == canonical.VString {
		cl.Nonce, _ = hex.DecodeString(x.AsString())
	}
	return &cl
}

// hexBody strips a "sha256:" prefix before hex decoding.
func hexBody(h string) string {
	if strings.HasPrefix(h, "sha256:") {
		return h[len("sha256:"):]
	}
	return h
}

func jsonInt(v canonical.Value) int64 {
	switch v.Kind() {
	case canonical.VInt64:
		return v.AsInt()
	case canonical.VUint64:
		return int64(v.AsUint())
	}
	return 0
}

// Copy derives a new Approval pointing at the same immutable record.
func (a *Approval) Copy() *Approval {
	c := *a
	return &c
}

// WithState returns a copy with the state replaced (used on transitions).
func (a *Approval) WithState(s State, now time.Time) *Approval {
	c := a.Copy()
	c.state = s
	if IsTerminal(s) || s == StateApproved {
		res := now
		c.resolvedAt = &res
		c.version++
	}
	return c
}

// WithVotes returns a copy with the recorded approve-vote count replaced.
func (a *Approval) WithVotes(n int64) *Approval {
	c := a.Copy()
	c.votes = n
	return c
}