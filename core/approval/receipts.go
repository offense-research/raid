// Durable receipt state, for independent verification and status reporting.
package approval

import (
	"database/sql"
	"time"
)

// Receipt is the persisted state of an issued receipt: the signed claims
// bytes, the signature, the issuer key id, and whether it has been consumed.
type Receipt struct {
	id          string
	approvalID  string
	decisionID  string
	keyID       string
	claims      []byte
	signature   []byte
	requestHash []byte
	issuedAt    time.Time
	expiresAt   time.Time
	consumedAt  *time.Time
}

func (r *Receipt) ID() string             { return r.id }
func (r *Receipt) ApprovalID() string     { return r.approvalID }
func (r *Receipt) DecisionID() string     { return r.decisionID }
func (r *Receipt) KeyID() string          { return r.keyID }
func (r *Receipt) ClaimsBytes() []byte    { return r.claims }
func (r *Receipt) Signature() []byte      { return r.signature }
func (r *Receipt) RequestHash() []byte    { return r.requestHash }
func (r *Receipt) IssuedAt() time.Time    { return r.issuedAt }
func (r *Receipt) ExpiresAt() time.Time   { return r.expiresAt }
func (r *Receipt) ConsumedAt() *time.Time { return r.consumedAt }
func (r *Receipt) Consumed() bool         { return r.consumedAt != nil }

// Expired reports whether the receipt was not consumed before its expiry.
func (r *Receipt) Expired(now time.Time) bool { return !now.Before(r.expiresAt) }

// GetReceipt loads a receipt by id (ErrNotFound when absent).
func (s *Service) GetReceipt(id string) (*Receipt, error) {
	var r Receipt
	var issuedNs, expiresNs int64
	var consumed sql.NullInt64
	err := s.store.QueryRow(`SELECT id, approval_id, decision_id, key_id, claims, signature,
			request_hash, issued_at_ns, expires_at_ns, consumed_at_ns
		FROM receipts WHERE id = ?`, id).
		Scan(&r.id, &r.approvalID, &r.decisionID, &r.keyID, &r.claims, &r.signature,
			&r.requestHash, &issuedNs, &expiresNs, &consumed)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.issuedAt = time.Unix(0, issuedNs).UTC()
	r.expiresAt = time.Unix(0, expiresNs).UTC()
	if consumed.Valid {
		t := time.Unix(0, consumed.Int64).UTC()
		r.consumedAt = &t
	}
	return &r, nil
}
