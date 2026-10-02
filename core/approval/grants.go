// Scoped approval grants.
//
// An approval with allow_scope other than exact_request mints a durable,
// time-boxed grant when it is resolved: subsequent requests that fall inside
// the grant's operation/session window are authorized without a new approval.
// Grants exist to reduce re-approval friction for a single engineer driving an
// agent (see `raidd --solo`); the exact-request tier is unaffected.
package approval

import (
	"database/sql"
	"time"

	"offense.dev/raid/core/util"
)

// GrantScopeOperation covers the same operation+environment for the principal.
const GrantScopeOperation = "operation"

// GrantScopeSession covers any operation for the principal within the session.
const GrantScopeSession = "session"

// Grant is a durable, time-boxed authorization minted from an approval.
type Grant struct {
	id               string
	approvalID       string
	principalID      string
	agentID          string
	sessionID        string
	operation        string
	environment      string
	scope            string
	policyBundleHash []byte
	createdAt        time.Time
	expiresAt        time.Time
}

func (g *Grant) ID() string               { return g.id }
func (g *Grant) ApprovalID() string       { return g.approvalID }
func (g *Grant) PrincipalID() string      { return g.principalID }
func (g *Grant) AgentID() string          { return g.agentID }
func (g *Grant) SessionID() string        { return g.sessionID }
func (g *Grant) Operation() string        { return g.operation }
func (g *Grant) Environment() string      { return g.environment }
func (g *Grant) Scope() string            { return g.scope }
func (g *Grant) PolicyBundleHash() []byte { return g.policyBundleHash }
func (g *Grant) CreatedAt() time.Time     { return g.createdAt }
func (g *Grant) ExpiresAt() time.Time     { return g.expiresAt }

// newGrant builds the grant a resolved scoped approval mints.
func newGrant(appr *Approval, now time.Time) *Grant {
	return &Grant{
		id:               util.NewID("gnt"),
		approvalID:       appr.ID(),
		principalID:      appr.PrincipalID(),
		agentID:          appr.AgentID(),
		sessionID:        appr.SessionID(),
		operation:        appr.Operation(),
		environment:      appr.Environment(),
		scope:            appr.AllowScope(),
		policyBundleHash: appr.PolicyBundleHash(),
		createdAt:        now,
		expiresAt:        appr.ExpiresAt(),
	}
}

// FindGrant returns the most recent unexpired grant covering the request under
// the given policy bundle, or nil when none exists. A grant minted under a
// different bundle (i.e. the policy changed) never covers a request. An
// operation-scoped grant covers the same principal+agent+operation+
// environment; a session-scoped grant covers the same principal+agent+session.
func (s *Service) FindGrant(principalID, agentID, sessionID, operation, environment string, bundleHash []byte) (*Grant, error) {
	now := time.Now().UTC().UnixNano()
	row := s.store.QueryRow(`SELECT id, approval_id, principal_id, agent_id, session_id,
			operation, environment, scope, policy_bundle_hash, created_at_ns, expires_at_ns
		FROM grants
		WHERE expires_at_ns > ?
		  AND policy_bundle_hash = ?
		  AND principal_id = ? AND agent_id = ?
		  AND (
		    (scope = 'operation' AND operation = ? AND environment = ?)
		    OR (scope = 'session' AND session_id = ?)
		  )
		ORDER BY created_at_ns DESC LIMIT 1`,
		now, bundleHash, principalID, agentID, operation, environment, sessionID)
	return scanGrant(row)
}

// GetGrant loads a grant by id (nil, nil when absent).
func (s *Service) GetGrant(id string) (*Grant, error) {
	row := s.store.QueryRow(`SELECT id, approval_id, principal_id, agent_id, session_id,
			operation, environment, scope, policy_bundle_hash, created_at_ns, expires_at_ns
		FROM grants WHERE id = ?`, id)
	return scanGrant(row)
}

// ListGrants returns unexpired grants, newest first.
func (s *Service) ListGrants() ([]*Grant, error) {
	now := time.Now().UTC().UnixNano()
	rows, err := s.store.Query(`SELECT id, approval_id, principal_id, agent_id, session_id,
			operation, environment, scope, policy_bundle_hash, created_at_ns, expires_at_ns
		FROM grants WHERE expires_at_ns > ? ORDER BY created_at_ns DESC`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Grant{}
	for rows.Next() {
		g, gerr := scanGrant(rows)
		if gerr != nil {
			return nil, gerr
		}
		if g != nil {
			out = append(out, g)
		}
	}
	return out, rows.Err()
}

// grantScanner is the shared Scan source for *sql.Row and *sql.Rows.
type grantScanner interface {
	Scan(dest ...any) error
}

func scanGrant(scan grantScanner) (*Grant, error) {
	var g Grant
	var createdNs, expiresNs int64
	err := scan.Scan(&g.id, &g.approvalID, &g.principalID, &g.agentID, &g.sessionID,
		&g.operation, &g.environment, &g.scope, &g.policyBundleHash, &createdNs, &expiresNs)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	g.createdAt = time.Unix(0, createdNs).UTC()
	g.expiresAt = time.Unix(0, expiresNs).UTC()
	return &g, nil
}

// sweepExpiredGrants deletes grants past their expiry (idempotent).
func (s *Service) sweepExpiredGrants(now time.Time) error {
	_, err := s.store.Exec(`DELETE FROM grants WHERE expires_at_ns <= ?`, now.UnixNano())
	return err
}
