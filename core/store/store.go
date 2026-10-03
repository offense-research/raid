// SQLite persistence layer (WAL mode).
//
// The deterministic decision engine never touches this store on the hot
// path; it exists for durable decisions, approvals, receipts, and audit
// events. Approvals and receipt consumption always use synchronous
// durability; routine decisions follow the configured audit mode.
package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// AuditMode selects decision durability.
type AuditMode int

const (
	// StrictAudit fsyncs every decision event before acknowledging.
	StrictAudit AuditMode = 2
	// BalancedAudit acknowledges after OS write with group commit
	// (synchronous=NORMAL); approvals and consumption stay synchronous.
	BalancedAudit AuditMode = 1
)

// Options configures the store.
type Options struct {
	Path      string
	AuditMode AuditMode
}

// Store is a SQLite-backed repository.
type Store struct {
	db   *sql.DB
	mode AuditMode
}

// Open opens (or creates) the database, applies WAL pragmas, and runs
// migrations. The daemon owns exactly one Store.
func Open(opts Options) (*Store, error) {
	priv := opts.AuditMode
	if priv == 0 {
		priv = StrictAudit
	}
	sync := "NORMAL"
	if priv == StrictAudit {
		sync = "FULL"
	}
	sep := "?"
	if strings.IndexRune(opts.Path, '?') >= 0 {
		sep = "&"
	}
	dsn := fmt.Sprintf("file:%s%s_journal_mode=WAL&_busy_timeout=5000&_synchronous=%s&_foreign_keys=on", opts.Path, sep, sync)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db, mode: priv}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// Mode reports the configured audit mode.
func (s *Store) Mode() AuditMode { return s.mode }

// InMemory opens a private in-memory database for tests.
func InMemory() (*Store, error) {
	return Open(Options{Path: "raid-mem?mode=memory&cache=shared", AuditMode: StrictAudit})
}

// nowNs returns unix nanoseconds (UTC).
func nowNs() int64 { return time.Now().UTC().UnixNano() }

// Begin starts a write transaction (synchronous durability).
func (s *Store) Begin() (*sql.Tx, error) { return s.db.Begin() }

// Exec runs a statement without rows.
func (s *Store) Exec(q string, args ...any) (sql.Result, error) { return s.db.Exec(q, args...) }

// Query runs a read statement.
func (s *Store) Query(q string, args ...any) (*sql.Rows, error) { return s.db.Query(q, args...) }

// QueryRow runs a read statement expecting one row.
func (s *Store) QueryRow(q string, args ...any) *sql.Row { return s.db.QueryRow(q, args...) }
