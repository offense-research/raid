// Decision audit events (spec 12.4).
//
// strict: the decision row is committed with synchronous durability before
// the response (SQLite synchronous=FULL fsyncs at commit).
// balanced: the row is committed with synchronous=NORMAL (acknowledged
// after OS write, group-committed); approvals and receipt consumption are
// always synchronous. The final event tail may be lost on catastrophic host
// failure; that is the documented tradeoff.
package audit

import (
	"strings"
	"time"

	"offense.dev/raid/core/canonical"
	"offense.dev/raid/core/decision"
	"offense.dev/raid/core/store"
	"offense.dev/raid/core/util"
)

// WriteDecision durably records a decision event according to the audit
// mode configured on the store.
func WriteDecision(st *store.Store, d *decision.Decision, now time.Time) error {
	_, err := st.Exec(`INSERT INTO decisions
		(id, effect, reason_code, request_hash, policy_bundle_id, policy_bundle_hash,
		 matched_rule_ids, approval_id, created_at_ns, expires_at_ns, evaluation_micros)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID(), d.Effect(), d.ReasonCode(), d.RequestHash(), d.PolicyBundleID(),
		d.PolicyBundleHash(), strings.Join(d.MatchedRuleIDs(), ","), "",
		now.UnixNano(), d.ExpiresAt().UnixNano(), d.EvaluationMicros())
	return err
}

// WriteAuditEvent appends a generic audit event with a monotonic sequence.
func WriteAuditEvent(st *store.Store, kind, subject, detail string, now time.Time) error {
	var seq int64
	if err := st.QueryRow(`SELECT COALESCE(MAX(seq), 0) + 1 FROM audit_events`).Scan(&seq); err != nil {
		return err
	}
	payload := `{"subject":` + canonical.Escape(subject) + `,"detail":` + canonical.Escape(detail) + `}`
	_, err := st.Exec(`INSERT INTO audit_events (id, seq, kind, payload, created_at_ns)
		VALUES (?, ?, ?, ?, ?)`, util.NewID("evt"), seq, kind, payload, now.UnixNano())
	return err
}