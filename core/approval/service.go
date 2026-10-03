// Approval service: durable creation, resolution, and receipt consumption.
//
// Durability contract (RAID-SEC-010): an approval is fsynced to SQLite
// (synchronous durability) before it is returned or visible. Resolution uses
// an optimistic-concurrency predicate; the first valid resolution wins.
package approval

import (
	"database/sql"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/offense-research/raid/core/canonical"
	"github.com/offense-research/raid/core/decision"
	"github.com/offense-research/raid/core/policy"
	"github.com/offense-research/raid/core/signing"
	"github.com/offense-research/raid/core/store"
	"github.com/offense-research/raid/core/stream"
	"github.com/offense-research/raid/core/util"
)

// Errors surfaced to the API layer.
var (
	ErrNotFound        = errors.New("raid: approval not found")
	ErrNotPending      = errors.New("raid: approval is not pending")
	ErrVersionConflict = errors.New("raid: optimistic concurrency conflict")
	ErrExpired         = errors.New("raid: approval expired")
	ErrUnauthorized    = errors.New("raid: approver not authorized")
	ErrSelfApproval    = errors.New("raid: self-approval forbidden")
	ErrTerminal        = errors.New("raid: approval already resolved")
	ErrAlreadyConsumed = errors.New("raid: receipt already consumed")
	ErrReceiptIssue    = errors.New("raid: receipt issuance failed")
	ErrGrantNotFound   = errors.New("raid: grant not found")
)

// Approver is the authenticated acting human.
type Approver struct {
	SubjectID string
	Groups    []string
	Active    bool
}

// Service coordinates approvals, receipts, and events.
type Service struct {
	store *store.Store
	key   *signing.KeyPair
	hub   *stream.Hub
	// ForbidSelfApproval rejects an approver who submitted the request.
	ForbidSelfApproval bool
}

// NewService wires the service. The signing key is the daemon's receipt key.
func NewService(st *store.Store, key *signing.KeyPair, hub *stream.Hub, forbidSelf bool) *Service {
	return &Service{store: st, key: key, hub: hub, ForbidSelfApproval: forbidSelf}
}

// Create durably commits the decision, the pending approval, and its audit
// event in one synchronous transaction, then publishes approval.created.
func (s *Service) Create(d *decision.Decision, req *canonical.ActionRequest, cfg *policy.ApprovalConfig) (*Approval, error) {
	if cfg == nil {
		cfg = &policy.ApprovalConfig{}
	}
	now := time.Now().UTC()
	ttlNs := cfg.TTLNs()
	if ttlNs == 0 {
		ttlNs = policy.DefaultApprovalTTLNs
	}
	expires := now.Add(time.Duration(ttlNs))
	appr := &Approval{
		id: util.NewID("apr"), decisionID: d.ID(),
		requestHash:      d.RequestHash(),
		principalID:      req.Principal().SubjectID(),
		agentID:          req.Principal().AgentID(),
		sessionID:        req.Principal().SessionID(),
		operation:        req.Action().Operation(),
		resourceType:     req.Resource().Type(),
		resourceID:       req.Resource().ID(),
		environment:      req.Resource().Environment(),
		argumentsSummary: SafeSummary(d.RequestHash(), req),
		policyBundleHash: d.PolicyBundleHash(),
		matchedRuleIDs:   d.MatchedRuleIDs(),
		requiredGroups:   cfg.ApproverGroups(),
		quorum:           cfg.Quorum(),
		allowScope:       scopeOrDefault(cfg.AllowScope()),
		state:            StatePending,
		version:          0,
		createdAt:        now,
		expiresAt:        expires,
	}
	tx, err := s.store.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := insertDecisionTx(tx, d, appr.id, now); err != nil {
		return nil, err
	}
	if err := insertApprovalTx(tx, appr); err != nil {
		return nil, err
	}
	if err := auditTx(tx, "approval.created", appr.id, appr.operation, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.hub.Publish(stream.Event{Kind: "approval.created", ApprovalID: appr.id, At: now})
	return appr, nil
}

// Resolve applies an approver's decision. Returns the updated approval and,
// when approved, the signed receipt.
func (s *Service) Resolve(approvalID string, approve bool, approver Approver, expectedVersion uint64) (*Approval, *signing.SignedReceipt, *signing.Claims, error) {
	if !approver.Active {
		return nil, nil, nil, ErrUnauthorized
	}
	now := time.Now().UTC()
	appr, err := s.Get(approvalID)
	if err != nil {
		return nil, nil, nil, err
	}
	if appr.State() != StatePending {
		return nil, nil, nil, ErrNotPending
	}
	if !now.Before(appr.ExpiresAt()) {
		return nil, nil, nil, ErrExpired
	}
	if appr.Version() != expectedVersion {
		return nil, nil, nil, ErrVersionConflict
	}
	if len(appr.RequiredGroups()) > 0 && !intersects(approver.Groups, appr.RequiredGroups()) {
		return nil, nil, nil, ErrUnauthorized
	}
	if s.ForbidSelfApproval && approver.SubjectID == appr.PrincipalID() {
		return nil, nil, nil, ErrSelfApproval
	}

	if !approve {
		return s.resolveTerminal(appr, StateDenied, expectedVersion, now)
	}
	return s.resolveApprove(appr, approver, expectedVersion, now)
}

// resolveTerminal flips a pending approval to a terminal state (deny).
func (s *Service) resolveTerminal(appr *Approval, nextState State, expectedVersion uint64, now time.Time) (*Approval, *signing.SignedReceipt, *signing.Claims, error) {
	tx, err := s.store.Begin()
	if err != nil {
		return nil, nil, nil, err
	}
	defer tx.Rollback()
	// optimistic concurrency + expiry predicate (spec 15.2)
	res, err := tx.Exec(`UPDATE approvals
		SET state = ?, version = version + 1, resolved_at_ns = ?
		WHERE id = ? AND state = 'pending' AND version = ? AND expires_at_ns > ?`,
		nextState, now.UnixNano(), appr.ID(), expectedVersion, now.UnixNano())
	if err != nil {
		return nil, nil, nil, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, nil, nil, ErrVersionConflict
	}
	if err := auditTx(tx, "approval."+string(nextState), appr.ID(), "", now); err != nil {
		return nil, nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, nil, err
	}
	out := appr.WithState(nextState, now)
	s.hub.Publish(stream.Event{Kind: "approval." + string(nextState), ApprovalID: out.ID(), At: now})
	return out, nil, nil, nil
}

// resolveApprove records the approver's vote and, once quorum is reached,
// transitions the approval to approved and issues the signed receipt. Until
// quorum is reached the approval stays pending and no receipt is issued.
func (s *Service) resolveApprove(appr *Approval, approver Approver, expectedVersion uint64, now time.Time) (*Approval, *signing.SignedReceipt, *signing.Claims, error) {
	tx, err := s.store.Begin()
	if err != nil {
		return nil, nil, nil, err
	}
	defer tx.Rollback()
	// One vote per approver (idempotent): re-approving is a no-op.
	if _, err := tx.Exec(`INSERT INTO approval_votes (id, approval_id, approver_id, decision, created_at_ns)
		VALUES (?, ?, ?, 'approve', ?)
		ON CONFLICT(approval_id, approver_id) DO NOTHING`,
		util.NewID("vote"), appr.ID(), approver.SubjectID, now.UnixNano()); err != nil {
		return nil, nil, nil, err
	}
	var votes int64
	if err := tx.QueryRow(`SELECT COUNT(*) FROM approval_votes
		WHERE approval_id = ? AND decision = 'approve'`, appr.ID()).Scan(&votes); err != nil {
		return nil, nil, nil, err
	}
	quorum := int64(appr.Quorum())
	if quorum < 1 {
		quorum = 1
	}
	if votes < quorum {
		if err := auditTx(tx, "approval.vote", appr.ID(), approver.SubjectID, now); err != nil {
			return nil, nil, nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, nil, nil, err
		}
		s.hub.Publish(stream.Event{Kind: "approval.voted", ApprovalID: appr.ID(), At: now})
		return appr.WithVotes(votes), nil, nil, nil
	}

	// Quorum reached: transition to approved and issue the receipt in the
	// same transaction.
	res, err := tx.Exec(`UPDATE approvals
		SET state = 'approved', version = version + 1, resolved_at_ns = ?
		WHERE id = ? AND state = 'pending' AND version = ? AND expires_at_ns > ?`,
		now.UnixNano(), appr.ID(), expectedVersion, now.UnixNano())
	if err != nil {
		return nil, nil, nil, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, nil, nil, ErrVersionConflict
	}
	if err := auditTx(tx, "approval.approved", appr.ID(), "", now); err != nil {
		return nil, nil, nil, err
	}
	claims := &signing.Claims{
		Version:          1,
		ReceiptID:        util.NewID("rcp"),
		ApprovalID:       appr.ID(),
		DecisionID:       appr.DecisionID(),
		RequestHash:      appr.RequestHash(),
		PolicyBundleHash: appr.PolicyBundleHash(),
		Effect:           "allow",
		IssuedAt:         now.Unix(),
		ExpiresAt:        now.Add(signing.ReceiptTTL).Unix(),
		Nonce:            signing.NewNonce(),
	}
	receipt := signing.Sign(claims, s.key)
	if err := insertReceiptTx(tx, claims, receipt, now); err != nil {
		return nil, nil, nil, err
	}
	// A scoped approval also mints a durable grant covering similar,
	// lower-risk requests until the approval expires.
	if scopeOrDefault(appr.AllowScope()) != "exact_request" {
		if err := insertGrantTx(tx, newGrant(appr, now)); err != nil {
			return nil, nil, nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, nil, err
	}
	out := appr.WithState(StateApproved, now).WithVotes(votes)
	s.hub.Publish(stream.Event{Kind: "approval.approved", ApprovalID: out.ID(), At: now})
	return out, receipt, claims, nil
}

// Consume atomically marks a receipt consumed. At-most-once semantics.
func (s *Service) Consume(receiptID, consumer string) error {
	now := time.Now().UTC()
	tx, err := s.store.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE receipts SET consumed_at_ns = ?
		WHERE id = ? AND consumed_at_ns IS NULL`, now.UnixNano(), receiptID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrAlreadyConsumed
	}
	if _, err := tx.Exec(`INSERT INTO receipt_consumptions (id, receipt_id, consumed_by, consumed_at_ns)
		VALUES (?, ?, ?, ?)`, util.NewID("cons"), receiptID, consumer, now.UnixNano()); err != nil {
		return err
	}
	var approvalID string
	if err := tx.QueryRow(`SELECT approval_id FROM receipts WHERE id = ?`, receiptID).Scan(&approvalID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE approvals SET state = 'consumed', version = version + 1 WHERE id = ? AND state = 'approved'`, approvalID); err != nil {
		return err
	}
	if err := auditTx(tx, "receipt.consumed", receiptID, consumer, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.hub.Publish(stream.Event{Kind: "approval.consumed", ApprovalID: approvalID, At: now})
	return nil
}

// Cancel lets the requesting session cancel a pending approval.
func (s *Service) Cancel(approvalID, sessionID string) error {
	appr, err := s.Get(approvalID)
	if err != nil {
		return err
	}
	if appr.State() != StatePending {
		return ErrNotPending
	}
	if appr.SessionID() != sessionID {
		return ErrUnauthorized
	}
	now := time.Now().UTC()
	tx, err := s.store.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE approvals SET state = 'cancelled', version = version + 1, resolved_at_ns = ?
		WHERE id = ? AND state = 'pending'`, now.UnixNano(), approvalID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotPending
	}
	if err := auditTx(tx, "approval.cancelled", approvalID, sessionID, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.hub.Publish(stream.Event{Kind: "approval.cancelled", ApprovalID: approvalID, At: now})
	return nil
}

// Get loads one approval (ErrNotFound when absent).
func (s *Service) Get(id string) (*Approval, error) {
	var row sqlApprovalRow
	var resolved sql.NullInt64
	err := s.store.QueryRow(`SELECT `+columnList()+` FROM approvals WHERE id = ?`, id).
		Scan(&row.id, &row.decisionID, &row.requestHash, &row.principalID, &row.agentID, &row.sessionID,
			&row.operation, &row.resourceType, &row.resourceID, &row.environment,
			&row.argumentsSummary, &row.policyBundleHash, &row.matchedRuleIDs,
			&row.requiredGroups, &row.quorum, &row.allowScope, &row.state, &row.version,
			&row.createdAtNs, &row.expiresAtNs, &resolved, &row.voteCount)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	row.resolvedAtNs = resolved.Int64
	row.hasResolved = resolved.Valid
	return row.toApproval(), nil
}

// ListPending returns pending, not-yet-expired approvals (approver view).
func (s *Service) ListPending() ([]*Approval, error) {
	now := time.Now().UTC().UnixNano()
	rows, err := s.store.Query(`
		SELECT `+columnList()+` FROM approvals
		WHERE state = 'pending' AND expires_at_ns > ? ORDER BY created_at_ns`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Approval{}
	for rows.Next() {
		var row sqlApprovalRow
		var resolved sql.NullInt64
		if err := rows.Scan(&row.id, &row.decisionID, &row.requestHash, &row.principalID, &row.agentID, &row.sessionID,
			&row.operation, &row.resourceType, &row.resourceID, &row.environment,
			&row.argumentsSummary, &row.policyBundleHash, &row.matchedRuleIDs,
			&row.requiredGroups, &row.quorum, &row.allowScope, &row.state, &row.version,
			&row.createdAtNs, &row.expiresAtNs, &resolved, &row.voteCount); err != nil {
			return nil, err
		}
		row.resolvedAtNs = resolved.Int64
		row.hasResolved = resolved.Valid
		out = append(out, row.toApproval())
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ByDecision loads the approval attached to a decision (nil when none).
func (s *Service) ByDecision(decisionID string) (*Approval, error) {
	var id string
	err := s.store.QueryRow(`SELECT id FROM approvals WHERE decision_id = ? ORDER BY created_at_ns DESC LIMIT 1`, decisionID).Scan(&id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.Get(id)
}

// SweepExpired marks expired approvals as expired (idempotent) and reaps
// expired scoped grants.
func (s *Service) SweepExpired() (int64, error) {
	now := time.Now().UTC()
	res, err := s.store.Exec(`UPDATE approvals SET state = 'expired', version = version + 1, resolved_at_ns = ?
		WHERE state = 'pending' AND expires_at_ns <= ?`, now.UnixNano(), now.UnixNano())
	if err != nil {
		return 0, err
	}
	_ = s.sweepExpiredGrants(now)
	return res.RowsAffected()
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// SafeSummary reduces an argument map to bounded, safe name/value pairs for
// the TUI and approvals (spec 9.8: safe summaries generated server-side).
func SafeSummary(hash []byte, req *canonical.ActionRequest) []SafeField {
	out := []SafeField{}
	const maxLen = 120
	const maxFields = 12
	names := sortedKeys(req.Arguments())
	for i, name := range names {
		if i >= maxFields {
			break
		}
		v := valueSummary(req.Arguments()[name], maxLen)
		out = append(out, SafeField{name: name, value: v})
	}
	return out
}

func sortedKeys(m map[string]canonical.Value) []string {
	keys := []string{}
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func valueSummary(v canonical.Value, maxLen int) string {
	var sb strings.Builder
	valueSummaryInto(&sb, v, 0, maxLen)
	s := sb.String()
	if len(s) > maxLen {
		s = s[:maxLen] + "..."
	}
	return sanitizeSummary(s)
}

func valueSummaryInto(sb *strings.Builder, v canonical.Value, depth, maxLen int) {
	if sb.Len() >= maxLen {
		return
	}
	if depth > 3 {
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
	case canonical.VString:
		sb.WriteString(v.AsString())
	case canonical.VDecimal, canonical.VTimestamp, canonical.VDuration:
		sb.WriteString(v.AsString())
	case canonical.VList:
		sb.WriteByte('[')
		for i, item := range v.AsList() {
			if i > 0 {
				sb.WriteString(", ")
			}
			valueSummaryInto(sb, item, depth+1, maxLen)
		}
		sb.WriteByte(']')
	case canonical.VObject:
		sb.WriteByte('{')
		first := true
		for k, item := range v.AsMap() {
			if !first {
				sb.WriteString(", ")
			}
			first = false
			sb.WriteString(k)
			sb.WriteByte('=')
			valueSummaryInto(sb, item, depth+1, maxLen)
		}
		sb.WriteByte('}')
	}
}

// sanitizeSummary strips terminal control bytes from server summaries.
func sanitizeSummary(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r < 0x20 && r != '\t' {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
