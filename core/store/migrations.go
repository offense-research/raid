// Schema migrations. Version 1 is the MVP approval schema (spec 12.2).
package store

import (
	"fmt"
)

var migrations = []string{
	// v1: core MVP tables
	`CREATE TABLE IF NOT EXISTS policy_bundles (
		id               TEXT PRIMARY KEY,
		name             TEXT NOT NULL,
		revision         INTEGER NOT NULL,
		bundle_hash      BLOB NOT NULL,
		active           INTEGER NOT NULL DEFAULT 0,
		activated_at_ns  INTEGER NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS policy_activations (
		id               TEXT PRIMARY KEY,
		bundle_id        TEXT NOT NULL,
		actor            TEXT NOT NULL,
		activated_at_ns  INTEGER NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS decisions (
		id                TEXT PRIMARY KEY,
		effect            TEXT NOT NULL,
		reason_code       TEXT NOT NULL,
		request_hash      BLOB NOT NULL,
		policy_bundle_id  TEXT NOT NULL,
		policy_bundle_hash BLOB NOT NULL,
		matched_rule_ids  TEXT NOT NULL,
		approval_id       TEXT NOT NULL DEFAULT '',
		created_at_ns     INTEGER NOT NULL,
		expires_at_ns     INTEGER NOT NULL,
		evaluation_micros INTEGER NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS approvals (
		id                 TEXT PRIMARY KEY,
		decision_id        TEXT NOT NULL,
		request_hash       BLOB NOT NULL,
		principal_id       TEXT NOT NULL,
		agent_id           TEXT NOT NULL,
		session_id         TEXT NOT NULL,
		operation          TEXT NOT NULL,
		resource_type      TEXT NOT NULL,
		resource_id        TEXT NOT NULL,
		environment        TEXT NOT NULL,
		arguments_summary  TEXT NOT NULL,
		policy_bundle_hash BLOB NOT NULL,
		matched_rule_ids   TEXT NOT NULL,
		required_groups    TEXT NOT NULL,
		quorum             INTEGER NOT NULL,
		state              TEXT NOT NULL,
		version            INTEGER NOT NULL,
		created_at_ns      INTEGER NOT NULL,
		expires_at_ns      INTEGER NOT NULL,
		resolved_at_ns     INTEGER
	);`,
	`CREATE TABLE IF NOT EXISTS approval_votes (
		id             TEXT PRIMARY KEY,
		approval_id    TEXT NOT NULL,
		approver_id    TEXT NOT NULL,
		decision       TEXT NOT NULL,
		created_at_ns  INTEGER NOT NULL,
		UNIQUE(approval_id, approver_id)
	);`,
	`CREATE TABLE IF NOT EXISTS receipts (
		id              TEXT PRIMARY KEY,
		approval_id     TEXT NOT NULL,
		decision_id     TEXT NOT NULL,
		request_hash    BLOB NOT NULL,
		policy_bundle_hash BLOB NOT NULL,
		key_id          TEXT NOT NULL,
		claims          BLOB NOT NULL,
		signature       BLOB NOT NULL,
		issued_at_ns    INTEGER NOT NULL,
		expires_at_ns   INTEGER NOT NULL,
		consumed_at_ns  INTEGER
	);`,
	`CREATE TABLE IF NOT EXISTS receipt_consumptions (
		id               TEXT PRIMARY KEY,
		receipt_id       TEXT NOT NULL,
		consumed_by      TEXT NOT NULL,
		consumed_at_ns   INTEGER NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS approvers (
		id          TEXT PRIMARY KEY,
		subject_id  TEXT NOT NULL,
		group_name  TEXT NOT NULL,
		enabled     INTEGER NOT NULL DEFAULT 1,
		UNIQUE(subject_id, group_name)
	);`,
	`CREATE TABLE IF NOT EXISTS approver_groups (
		name     TEXT PRIMARY KEY,
		members  TEXT NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS audit_events (
		id             TEXT PRIMARY KEY,
		seq            INTEGER UNIQUE NOT NULL,
		kind           TEXT NOT NULL,
		payload        TEXT NOT NULL,
		created_at_ns  INTEGER NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS source_clients (
		id            TEXT PRIMARY KEY,
		client_id     TEXT NOT NULL,
		product       TEXT NOT NULL,
		enabled       INTEGER NOT NULL DEFAULT 1,
		revision      INTEGER NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS semantic_evaluations (
		id               TEXT PRIMARY KEY,
		decision_id      TEXT NOT NULL,
		question_set     TEXT NOT NULL,
		model            TEXT NOT NULL,
		thresholds_hash  BLOB NOT NULL,
		state_hash       BLOB NOT NULL,
		answers          TEXT NOT NULL,
		latency_ms       INTEGER NOT NULL,
		escalation       TEXT NOT NULL,
		created_at_ns    INTEGER NOT NULL
	);`,
}

// migrate applies pending migrations inside transactions.
func (s *Store) migrate() error {
	// bootstrap the version table (the first real migration inserts into it)
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version   INTEGER PRIMARY KEY,
		applied_at_ns INTEGER NOT NULL
	)`); err != nil {
		return err
	}
	for i, ddl := range migrations {
		version := i + 1
		var exists int64
		err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version).Scan(&exists)
		if err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		tx, terr := s.db.Begin()
		if terr != nil {
			return terr
		}
		if _, e := tx.Exec(ddl); e != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %v", version, e)
		}
		if _, e := tx.Exec(`INSERT INTO schema_migrations (version, applied_at_ns) VALUES (?, ?)`, version, nowNs()); e != nil {
			tx.Rollback()
			return e
		}
		if e := tx.Commit(); e != nil {
			return e
		}
	}
	return nil
}