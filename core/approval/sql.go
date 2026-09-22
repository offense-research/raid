// SQL persistence for approvals, decisions, receipts, and audit events.
// All writes are synchronous; approvals are fsynced before acknowledgement.
package approval

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"offense.dev/raid/core/canonical"
	"offense.dev/raid/core/decision"
	"offense.dev/raid/core/signing"
	"offense.dev/raid/core/util"
)

func insertDecisionTx(tx *sql.Tx, d *decision.Decision, approvalID string, now time.Time) error {
	_, err := tx.Exec(`INSERT INTO decisions
		(id, effect, reason_code, request_hash, policy_bundle_id, policy_bundle_hash,
		 matched_rule_ids, approval_id, created_at_ns, expires_at_ns, evaluation_micros)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID(), d.Effect(), d.ReasonCode(), d.RequestHash(), d.PolicyBundleID(),
		d.PolicyBundleHash(), strings.Join(d.MatchedRuleIDs(), ","), approvalID,
		now.UnixNano(), d.ExpiresAt().UnixNano(), d.EvaluationMicros())
	return err
}

func insertApprovalTx(tx *sql.Tx, a *Approval) error {
	_, err := tx.Exec(`INSERT INTO approvals
		(id, decision_id, request_hash, principal_id, agent_id, session_id,
		 operation, resource_type, resource_id, environment, arguments_summary,
		 policy_bundle_hash, matched_rule_ids, required_groups, quorum, state,
		 version, created_at_ns, expires_at_ns)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.id, a.decisionID, a.requestHash, a.principalID, a.agentID, a.sessionID,
		a.operation, a.resourceType, a.resourceID, a.environment,
		summaryJSON(a.argumentsSummary), a.policyBundleHash,
		strings.Join(a.matchedRuleIDs, ","), strings.Join(a.requiredGroups, ","),
		a.quorum, StatePending, a.version, a.createdAt.UnixNano(), a.expiresAt.UnixNano())
	return err
}

func insertReceiptTx(tx *sql.Tx, claims *signing.Claims, r *signing.SignedReceipt, now time.Time) error {
	_, err := tx.Exec(`INSERT INTO receipts
		(id, approval_id, decision_id, request_hash, policy_bundle_hash, key_id,
		 claims, signature, issued_at_ns, expires_at_ns)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		claims.ReceiptID, claims.ApprovalID, claims.DecisionID, claims.RequestHash,
		claims.PolicyBundleHash, r.KeyID, r.ClaimsBytes, r.Signature,
		claims.IssuedAt * 1e9, claims.ExpiresAt * 1e9)
	return err
}

func auditTx(tx *sql.Tx, kind, subject, detail string, now time.Time) error {
	var seq int64
	err := tx.QueryRow(`SELECT COALESCE(MAX(seq), 0) + 1 FROM audit_events`).Scan(&seq)
	if err != nil {
		return err
	}
	payload := `{"subject":` + escapeJSON(subject) + `,"detail":` + escapeJSON(detail) + `}`
	_, err = tx.Exec(`INSERT INTO audit_events (id, seq, kind, payload, created_at_ns)
		VALUES (?, ?, ?, ?, ?)`, util.NewID("evt"), seq, kind, payload, now.UnixNano())
	return err
}

func escapeJSON(s string) string {
	return canonical.Escape(s)
}

func summaryJSON(fields []SafeField) string {
	var sb strings.Builder
	sb.WriteByte('[')
	for i, f := range fields {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`{"name":`)
		canonical.WriteEscaped(&sb, f.name)
		sb.WriteString(`,"value":`)
		canonical.WriteEscaped(&sb, f.value)
		sb.WriteByte('}')
	}
	sb.WriteByte(']')
	return sb.String()
}

func parseSummary(raw string) []SafeField {
	var fields []SafeField
	_ = json.Unmarshal([]byte(raw), &fields)
	return fields
}

// sqlApprovalRow mirrors one approval row for scanning.
type sqlApprovalRow struct {
	id                 string
	decisionID         string
	requestHash        []byte
	principalID        string
	agentID            string
	sessionID          string
	operation          string
	resourceType       string
	resourceID         string
	environment        string
	argumentsSummary   string
	policyBundleHash   []byte
	matchedRuleIDs     string
	requiredGroups     string
	quorum             uint32
	state              string
	version            uint64
	createdAtNs        int64
	expiresAtNs        int64
	resolvedAtNs       int64
	hasResolved        bool
}

func columnList() string {
	return `id, decision_id, request_hash, principal_id, agent_id, session_id,
	       operation, resource_type, resource_id, environment,
	       arguments_summary, policy_bundle_hash, matched_rule_ids,
	       required_groups, quorum, state, version, created_at_ns, expires_at_ns, resolved_at_ns`
}

func (row *sqlApprovalRow) toApproval() *Approval {
	var resolved *time.Time
	if row.hasResolved {
		t := time.Unix(0, row.resolvedAtNs).UTC()
		resolved = &t
	}
	return &Approval{
		id: row.id, decisionID: row.decisionID, requestHash: row.requestHash,
		principalID: row.principalID, agentID: row.agentID, sessionID: row.sessionID,
		operation: row.operation, resourceType: row.resourceType,
		resourceID: row.resourceID, environment: row.environment,
		argumentsSummary: parseSummary(row.argumentsSummary),
		policyBundleHash: row.policyBundleHash,
		matchedRuleIDs:   splitComma(row.matchedRuleIDs),
		requiredGroups:   splitComma(row.requiredGroups),
		quorum:           row.quorum,
		state:            State(row.state),
		version:          row.version,
		createdAt:        time.Unix(0, row.createdAtNs).UTC(),
		expiresAt:        time.Unix(0, row.expiresAtNs).UTC(),
		resolvedAt:       resolved,
	}
}

func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}