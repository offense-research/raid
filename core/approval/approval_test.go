package approval_test

import (
	"strings"
	"testing"
	"time"

	"github.com/offense-research/raid/core/approval"
	"github.com/offense-research/raid/core/canonical"
	"github.com/offense-research/raid/core/decision"
	"github.com/offense-research/raid/core/policy"
	"github.com/offense-research/raid/core/signing"
	"github.com/offense-research/raid/core/store"
	"github.com/offense-research/raid/core/stream"
)

const bundleYAML = `
apiVersion: offense.dev/raid/v1alpha1
kind: PolicyBundle
metadata: {name: demo, revision: 1}
defaults: {effect: deny}
rules:
  - id: write-needs-approval
    match:
      operations: [github.issues.add_labels]
      environments: [production]
    when: "true"
    effect: require_approval
    approval:
      approver_groups: [maintainers]
      ttl: 5m
      allow_scope: exact_request
`

const writeReq = `{
  "schema_version": 1,
  "request_id": "proxy:act_02J",
  "principal": {"subject_id": "usr_imran", "agent_id": "agt_claude", "session_id": "ses_9821", "runtime": "claude-code", "groups": ["engineering"], "trust_level": "local-session", "revision": 4},
  "action": {"provider": "github", "operation": "github.issues.add_labels", "effect": "write"},
  "resource": {"type": "github.repository.issue", "id": "repo:991234567:issue:184", "environment": "production", "attributes": {"repository_id": "991234567"}},
  "arguments": {"labels": {"type": "list", "value": [{"type": "string", "value": "needs-triage"}]}},
  "context": {"timestamp": "2026-09-22T20:00:00Z", "source_product": "proxy", "source_version": "0.1.0", "source_request_id": "act_02J", "task_summary": "triage", "interactive": true}
}`

func setup(t *testing.T) (*store.Store, *decision.Engine, *approval.Service, *signing.KeyPair, *canonical.ActionRequest) {
	t.Helper()
	st, err := store.InMemory()
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	hub := stream.NewHub()
	key, kerr := signing.GenerateKey()
	if kerr != nil {
		t.Fatalf("key: %v", kerr)
	}
	svc := approval.NewService(st, key, hub, true)
	e := decision.NewEngine()
	schema, lerr := policy.LoadBundle([]byte(bundleYAML), "test")
	if lerr != nil {
		t.Fatalf("load: %v", lerr.Error())
	}
	b, cerr := policy.CompileBundle(schema, policy.CompileOptions{})
	if cerr != nil {
		t.Fatalf("compile: %v", cerr.Error())
	}
	e.Activate(b)
	req, perr := canonical.DecodeRequest([]byte(writeReq))
	if perr != nil {
		t.Fatalf("req: %v", perr.Error())
	}
	return st, e, svc, key, req
}

func makeApproval(t *testing.T, st *store.Store, e *decision.Engine, svc *approval.Service, key *signing.KeyPair, req *canonical.ActionRequest) (*approval.Approval, *decision.Decision) {
	t.Helper()
	d := e.Evaluate(req)
	if d.Effect() != "require_approval" {
		t.Fatalf("expected require_approval, got %v", d.Effect())
	}
	appr, err := svc.Create(d, req, d.ApprovalConfig())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return appr, d
}

var maintainer = approval.Approver{SubjectID: "usr_omar", Groups: []string{"maintainers"}, Active: true}

// A01: approving a pending request yields a signed, verifiable receipt.
func TestA01ApprovePendingSignedReceipt(t *testing.T) {
	st, e, svc, key, req := setup(t)
	defer st.Close()
	appr, _ := makeApproval(t, st, e, svc, key, req)
	out, receipt, _, rerr := svc.Resolve(appr.ID(), true, maintainer, appr.Version())
	if rerr != nil {
		t.Fatalf("resolve: %v", rerr)
	}
	if out.State() != approval.StateApproved {
		t.Errorf("state: %v", out.State())
	}
	if receipt == nil || len(receipt.Signature) == 0 {
		t.Fatalf("no receipt")
	}
	if !signing.VerifyReceipt(receipt, key.ID(), key.Public()) {
		t.Errorf("receipt signature invalid")
	}
	// the claims bytes embed the exact request hash; re-encode a claim set
	// with the original hash and confirm the signature still matches it
}

// A01b: binding is exact — a receipt is not valid for altered arguments
// (signature covers the claims bytes, and those bytes embed the hash).
func TestA01bReceiptExactBinding(t *testing.T) {
	st, e, svc, key, req := setup(t)
	defer st.Close()
	appr, _ := makeApproval(t, st, e, svc, key, req)
	_, receipt, _, err := svc.Resolve(appr.ID(), true, maintainer, appr.Version())
	if err != nil || receipt == nil {
		t.Fatalf("resolve: %v", err)
	}
	if !signing.VerifyReceipt(receipt, key.ID(), key.Public()) {
		t.Fatalf("signature invalid")
	}
	// the receipt was issued for the original request hash; an altered
	// request produces a different hash and must not verify as a match
	altered := strings.Replace(writeReq, `"needs-triage"`, `"nope"`, 1)
	req2, perr := canonical.DecodeRequest([]byte(altered))
	if perr != nil {
		t.Fatalf("req2: %v", perr.Error())
	}
	// recompute the honest signer's check: claims bytes == canonical claims
	// with the original hash; the altered hash differs
	diff := canonical.RequestHashEquals(canonical.HashRequest(req2), canonical.HashRequest(req))
	if diff {
		t.Errorf("altered arguments must change the hash")
	}
}

// A02: a second approver with a stale version loses the race.
func TestA02RaceOneResolutionWins(t *testing.T) {
	st, e, svc, key, req := setup(t)
	defer st.Close()
	appr, _ := makeApproval(t, st, e, svc, key, req)
	out1, receipt1, _, err1 := svc.Resolve(appr.ID(), true, maintainer, appr.Version())
	if err1 != nil {
		t.Fatalf("first resolve: %v", err1)
	}
	_, _, _, err2 := svc.Resolve(appr.ID(), false, approval.Approver{SubjectID: "usr_ana", Groups: []string{"maintainers"}, Active: true}, appr.Version())
	if err2 == nil {
		t.Errorf("stale version must lose the race")
	}
	if receipt1 == nil {
		t.Errorf("winner should get a receipt")
	}
	// fresh version of terminal state also rejected
	if _, _, _, err3 := svc.Resolve(appr.ID(), false, maintainer, out1.Version()); err3 == nil {
		t.Errorf("terminal approval must not resolve")
	}
}

// A03: an expired approval yields no receipt.
func TestA03ExpiredNoReceipt(t *testing.T) {
	st, e, svc, key, req := setup(t)
	defer st.Close()
	appr, _ := makeApproval(t, st, e, svc, key, req)
	// force expiry by rewriting the row
	nowNs := time.Now().UTC().UnixNano()
	if _, err := st.Exec(`UPDATE approvals SET expires_at_ns = ? WHERE id = ?`, nowNs-1000, appr.ID()); err != nil {
		t.Fatalf("expire: %v", err)
	}
	_, rec, _, err := svc.Resolve(appr.ID(), true, maintainer, appr.Version())
	if err == nil {
		t.Errorf("expired approval must not resolve")
	}
	if rec != nil {
		t.Errorf("expired approval must not produce a receipt")
	}
}

// A05: receipt replay fails on second consumption.
func TestA05ReceiptReplayFails(t *testing.T) {
	st, e, svc, key, req := setup(t)
	defer st.Close()
	appr, _ := makeApproval(t, st, e, svc, key, req)
	_, receipt, _, err := svc.Resolve(appr.ID(), true, maintainer, appr.Version())
	if err != nil || receipt == nil {
		t.Fatalf("resolve: %v", err)
	}
	// need the receipt id from claims row: claims are stored; find by approval
	var receiptID string
	if err := st.QueryRow(`SELECT id FROM receipts WHERE approval_id = ?`, appr.ID()).Scan(&receiptID); err != nil {
		t.Fatalf("receipt lookup: %v", err)
	}
	if err := svc.Consume(receiptID, "proxy"); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if err := svc.Consume(receiptID, "proxy"); err != nil {
		if err != approval.ErrAlreadyConsumed {
			t.Errorf("second consume error should be ErrAlreadyConsumed, got %v", err)
		}
	} else {
		t.Errorf("receipt replay must fail")
	}
}

// A07: self-approval is rejected when forbidden.
func TestA07SelfApprovalForbidden(t *testing.T) {
	st, e, svc, key, req := setup(t)
	defer st.Close()
	appr, _ := makeApproval(t, st, e, svc, key, req)
	selfish := approval.Approver{SubjectID: req.Principal().SubjectID(), Groups: []string{"maintainers"}, Active: true}
	_, _, _, err := svc.Resolve(appr.ID(), true, selfish, appr.Version())
	if err == nil {
		t.Errorf("self-approval must be rejected when forbidden")
	}
}

// A08: storage failure before approval creation yields no pending approval.
func TestA08StorageFailureNoApproval(t *testing.T) {
	st, e, svc, key, req := setup(t)
	_ = req
	_ = key
	st.Close()
	// after close, every write fails
	d := e.Evaluate(req)
	if d.Effect() != "require_approval" {
		t.Fatalf("expected require_approval, got %v", d.Effect())
	}
	appr, err := svc.Create(d, req, d.ApprovalConfig())
	if err == nil {
		t.Errorf("create after store failure must fail")
	}
	if appr != nil {
		t.Errorf("failed create must not return an approval")
	}
}

// A04: a receipt issued for one request must not validate for another.
func TestA04NoArgSubstitution(t *testing.T) {
	st, e, svc, key, req := setup(t)
	defer st.Close()
	appr, _ := makeApproval(t, st, e, svc, key, req)
	_, receipt, _, err := svc.Resolve(appr.ID(), true, maintainer, appr.Version())
	if err != nil || receipt == nil {
		t.Fatalf("resolve: %v", err)
	}
	if !signing.VerifyReceipt(receipt, key.ID(), key.Public()) {
		t.Fatalf("signature invalid")
	}
	// substitute an argument: the canonical hash changes
	altered := `{
  "schema_version": 1,
  "request_id": "proxy:act_02J",
  "principal": {"subject_id": "usr_imran", "agent_id": "agt_claude", "session_id": "ses_9821", "runtime": "claude-code", "groups": ["engineering"], "trust_level": "local-session", "revision": 4},
  "action": {"provider": "github", "operation": "github.issues.add_labels", "effect": "write"},
  "resource": {"type": "github.repository.issue", "id": "repo:991234567:issue:184", "environment": "production", "attributes": {"repository_id": "991234567"}},
  "arguments": {"labels": {"type": "list", "value": [{"type": "string", "value": "sneaky"}]}},
  "context": {"timestamp": "2026-09-22T20:00:00Z", "source_product": "proxy", "source_version": "0.1.0", "source_request_id": "act_02J", "task_summary": "triage", "interactive": true}
}`
	req2, perr := canonical.DecodeRequest([]byte(altered))
	if perr != nil {
		t.Fatalf("req2 decode: %v", perr.Error())
	}
	// The consumer's check compares the receipt hash to the executed
	// request hash. They must differ, so the consumer refuses to run.
	if canonical.RequestHashEquals(canonical.HashRequest(req), canonical.HashRequest(req2)) {
		t.Errorf("argument substitution must not produce the same hash")
	}
	// and the receipt's stored hash equals the original only
	var stored []byte
	if err := st.QueryRow(`SELECT request_hash FROM receipts WHERE approval_id = ?`, appr.ID()).Scan(&stored); err != nil {
		t.Fatalf("receipt row: %v", err)
	}
	if !canonical.RequestHashEquals(stored, canonical.HashRequest(req)) {
		t.Errorf("receipt must bind the original request hash")
	}
	if canonical.RequestHashEquals(stored, canonical.HashRequest(req2)) {
		t.Errorf("receipt must not bind the altered request hash")
	}
}
