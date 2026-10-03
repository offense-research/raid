// Approver identity resolution (spec 8.5, 14.1).
//
// The MVP trusts the local approver surface (TUI/CLI on the same host or
// authenticated via the daemon config); group membership is authoritative
// from the approvers table, never from client claims.
package authn

import (
	"database/sql"
	"strings"

	"github.com/offense-research/raid/core/store"
)

// Approver is the resolved, authenticated acting human.
type Approver struct {
	SubjectID string
	Groups    []string
	Active    bool
}

// ApproverStore resolves approver identities from the approvers table.
type ApproverStore struct {
	st *store.Store
}

// NewApproverStore wires the store.
func NewApproverStore(st *store.Store) *ApproverStore {
	return &ApproverStore{st: st}
}

// Get resolves an approver by subject id. Unknown subjects are inactive.
func (a *ApproverStore) Get(subjectID string) Approver {
	rows, err := a.st.Query(`SELECT group_name, enabled FROM approvers WHERE subject_id = ?`, subjectID)
	if err != nil {
		return Approver{SubjectID: subjectID}
	}
	defer rows.Close()
	var groups []string
	active := false
	for rows.Next() {
		var group string
		var enabled int64
		if err := rows.Scan(&group, &enabled); err != nil {
			return Approver{SubjectID: subjectID}
		}
		groups = append(groups, group)
		if enabled != 0 {
			active = true
		}
	}
	if len(groups) == 0 {
		return Approver{SubjectID: subjectID}
	}
	return Approver{SubjectID: subjectID, Groups: groups, Active: active}
}

// Upsert registers (or updates) an approver's group membership.
func (a *ApproverStore) Upsert(subjectID, group string, enabled bool) error {
	e := int64(0)
	if enabled {
		e = 1
	}
	_, err := a.st.Exec(`INSERT INTO approvers (id, subject_id, group_name, enabled)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(subject_id, group_name) DO UPDATE SET enabled = excluded.enabled`,
		subjectID+"|"+group, subjectID, group, e)
	return err
}

// GroupMembers lists member subject ids of a group.
func (a *ApproverStore) GroupMembers(group string) ([]string, error) {
	rows, err := a.st.Query(`SELECT subject_id FROM approvers WHERE group_name = ? AND enabled = 1`, group)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// HasGroup reports membership.
func (a *Approver) HasGroup(group string) bool {
	for _, g := range a.Groups {
		if g == group {
			return true
		}
	}
	return false
}

// ParseGroups splits a comma-separated group claim (used only to seed the
// approver table from config).
func ParseGroups(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

var _ = sql.ErrNoRows
