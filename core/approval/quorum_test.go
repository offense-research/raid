package approval_test

import (
	"testing"

	"github.com/offense-research/raid/core/approval"
	"github.com/offense-research/raid/core/canonical"
	"github.com/offense-research/raid/core/decision"
	"github.com/offense-research/raid/core/policy"
	"github.com/offense-research/raid/core/signing"
	"github.com/offense-research/raid/core/store"
	"github.com/offense-research/raid/core/stream"
)

const quorumBundleYAML = `
apiVersion: offense.dev/raid/v1alpha1
kind: PolicyBundle
metadata: {name: quorum, revision: 1}
defaults: {effect: deny}
rules:
  - id: two-person
    match:
      operations: [shell.execute]
    effect: require_approval
    approval:
      approver_groups: []
      quorum: 2
      ttl: 5m
      allow_scope: exact_request
`

func quorumSetup(t *testing.T) (*store.Store, *approval.Service, *decision.Decision, *canonical.ActionRequest) {
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
	svc := approval.NewService(st, key, hub, false)
	schema, lerr := policy.LoadBundle([]byte(quorumBundleYAML), "test")
	if lerr != nil {
		t.Fatalf("load: %v", lerr.Error())
	}
	b, cerr := policy.CompileBundle(schema, policy.CompileOptions{})
	if cerr != nil {
		t.Fatalf("compile: %v", cerr.Error())
	}
	e := decision.NewEngine()
	e.Activate(b)
	req, perr := canonical.DecodeRequest([]byte(execReq))
	if perr != nil {
		t.Fatalf("req: %v", perr.Error())
	}
	d := e.Evaluate(req)
	if d.Effect() != "require_approval" {
		t.Fatalf("expected require_approval, got %v", d.Effect())
	}
	return st, svc, d, req
}

var (
	alice = approval.Approver{SubjectID: "alice", Active: true}
	bob   = approval.Approver{SubjectID: "bob", Active: true}
)

// Quorum 2: one approve records a vote but issues no receipt; the second
// distinct approver completes quorum and issues the receipt.
func TestQuorumRequiresTwoApprovals(t *testing.T) {
	st, svc, d, req := quorumSetup(t)
	defer st.Close()
	appr, err := svc.Create(d, req, d.ApprovalConfig())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if appr.Quorum() != 2 {
		t.Fatalf("quorum: got %d want 2", appr.Quorum())
	}

	out1, rec1, _, err := svc.Resolve(appr.ID(), true, alice, appr.Version())
	if err != nil {
		t.Fatalf("vote1: %v", err)
	}
	if out1.State() != approval.StatePending {
		t.Errorf("after 1 vote state: got %v want pending", out1.State())
	}
	if rec1 != nil {
		t.Errorf("no receipt may be issued before quorum")
	}
	if out1.Votes() != 1 {
		t.Errorf("votes after 1: got %d want 1", out1.Votes())
	}

	out2, rec2, _, err := svc.Resolve(appr.ID(), true, bob, appr.Version())
	if err != nil {
		t.Fatalf("vote2: %v", err)
	}
	if out2.State() != approval.StateApproved {
		t.Errorf("after quorum state: got %v want approved", out2.State())
	}
	if rec2 == nil {
		t.Fatalf("receipt expected once quorum is reached")
	}
	if out2.Votes() != 2 {
		t.Errorf("votes after quorum: got %d want 2", out2.Votes())
	}
}

// A single approver cannot reach quorum alone by voting twice.
func TestQuorumOneApproverCannotDoubleVote(t *testing.T) {
	st, svc, d, req := quorumSetup(t)
	defer st.Close()
	appr, _ := svc.Create(d, req, d.ApprovalConfig())
	if _, rec, _, err := svc.Resolve(appr.ID(), true, alice, appr.Version()); err != nil || rec != nil {
		t.Fatalf("first vote: rec=%v err=%v", rec, err)
	}
	out, rec, _, err := svc.Resolve(appr.ID(), true, alice, appr.Version())
	if err != nil {
		t.Fatalf("second vote: %v", err)
	}
	if out.State() != approval.StatePending || rec != nil {
		t.Errorf("double vote must not reach quorum: state=%v rec=%v", out.State(), rec)
	}
	if out.Votes() != 1 {
		t.Errorf("votes: got %d want 1", out.Votes())
	}
}

// A single deny is a veto and resolves immediately, regardless of quorum.
func TestQuorumDenyIsVeto(t *testing.T) {
	st, svc, d, req := quorumSetup(t)
	defer st.Close()
	appr, _ := svc.Create(d, req, d.ApprovalConfig())
	out, rec, _, err := svc.Resolve(appr.ID(), false, alice, appr.Version())
	if err != nil {
		t.Fatalf("deny: %v", err)
	}
	if out.State() != approval.StateDenied {
		t.Errorf("state: got %v want denied", out.State())
	}
	if rec != nil {
		t.Errorf("deny must not issue a receipt")
	}
}
