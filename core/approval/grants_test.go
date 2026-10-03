package approval_test

import (
	"testing"

	"offense.dev/raid/core/approval"
	"offense.dev/raid/core/canonical"
	"offense.dev/raid/core/decision"
	"offense.dev/raid/core/policy"
	"offense.dev/raid/core/signing"
	"offense.dev/raid/core/store"
	"offense.dev/raid/core/stream"
)

const scopedBundleYAML = `
apiVersion: offense.dev/raid/v1alpha1
kind: PolicyBundle
metadata: {name: scoped, revision: 1}
defaults: {effect: deny}
rules:
  - id: exec-needs-approval
    match:
      operations: [shell.execute]
    effect: require_approval
    approval:
      approver_groups: [maintainers]
      ttl: 5m
      allow_scope: operation
`

const execReq = `{
  "schema_version": 1,
  "request_id": "claude:1",
  "principal": {"subject_id": "dev", "agent_id": "claude-code", "session_id": "ses_1", "runtime": "claude-code", "groups": [], "trust_level": "local-session", "revision": 1},
  "action": {"provider": "claude-code", "operation": "shell.execute", "effect": "execute"},
  "resource": {"type": "shell", "id": "/home/dev/proj", "environment": "development", "attributes": {}},
  "arguments": {"command": {"type": "string", "value": "go test ./..."}},
  "context": {"source_product": "claude-code", "source_request_id": "claude:1", "interactive": true}
}`

func scopedSetup(t *testing.T) (*store.Store, *approval.Service, *decision.Decision, *canonical.ActionRequest) {
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
	schema, lerr := policy.LoadBundle([]byte(scopedBundleYAML), "test")
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
	if got := d.ApprovalConfig().AllowScope(); got != "operation" {
		t.Fatalf("expected operation scope, got %q", got)
	}
	return st, svc, d, req
}

// A scoped approval mints a grant covering the same operation+environment for
// the same principal+agent, and nothing else.
func TestScopedGrantCoverage(t *testing.T) {
	st, svc, d, req := scopedSetup(t)
	defer st.Close()

	if g, err := svc.FindGrant("dev", "claude-code", "ses_1", "shell.execute", "development", d.PolicyBundleHash()); err != nil || g != nil {
		t.Fatalf("no grant should exist before approval (g=%v err=%v)", g, err)
	}

	appr, err := svc.Create(d, req, d.ApprovalConfig())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if appr.AllowScope() != "operation" {
		t.Errorf("approval allow_scope: got %q want operation", appr.AllowScope())
	}
	if _, _, _, rerr := svc.Resolve(appr.ID(), true, maintainer, appr.Version()); rerr != nil {
		t.Fatalf("resolve: %v", rerr)
	}

	g, err := svc.FindGrant("dev", "claude-code", "ses_1", "shell.execute", "development", d.PolicyBundleHash())
	if err != nil {
		t.Fatalf("find grant: %v", err)
	}
	if g == nil {
		t.Fatalf("expected a grant after approval")
	}
	if g.Scope() != approval.GrantScopeOperation || g.Operation() != "shell.execute" {
		t.Errorf("unexpected grant: scope=%s op=%s", g.Scope(), g.Operation())
	}

	// a grant is bound to the policy bundle that minted it
	if g, _ := svc.FindGrant("dev", "claude-code", "ses_1", "shell.execute", "development", []byte("other-bundle")); g != nil {
		t.Errorf("a grant must not cover a different policy bundle")
	}

	// wrong environment, principal, or agent must not be covered
	if g, _ := svc.FindGrant("dev", "claude-code", "ses_1", "shell.execute", "production", d.PolicyBundleHash()); g != nil {
		t.Errorf("production must not be covered by a development grant")
	}
	if g, _ := svc.FindGrant("other", "claude-code", "ses_1", "shell.execute", "development", d.PolicyBundleHash()); g != nil {
		t.Errorf("a different principal must not be covered")
	}
	if g, _ := svc.FindGrant("dev", "other-agent", "ses_1", "shell.execute", "development", d.PolicyBundleHash()); g != nil {
		t.Errorf("a different agent must not be covered")
	}

	// sweep reaps the grant once its window closes
	if _, err := st.Exec(`UPDATE grants SET expires_at_ns = 1`); err != nil {
		t.Fatalf("expire grant: %v", err)
	}
	if _, err := svc.SweepExpired(); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if g, _ := svc.FindGrant("dev", "claude-code", "ses_1", "shell.execute", "development", d.PolicyBundleHash()); g != nil {
		t.Errorf("expired grant must not be returned")
	}
}

// An exact_request approval must mint no grant.
func TestExactRequestMintsNoGrant(t *testing.T) {
	st, e, svc, key, req := setup(t)
	defer st.Close()
	appr, _ := makeApproval(t, st, e, svc, key, req)
	if appr.AllowScope() != "exact_request" {
		t.Errorf("allow_scope: got %q want exact_request", appr.AllowScope())
	}
	if _, _, _, err := svc.Resolve(appr.ID(), true, maintainer, appr.Version()); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	grants, err := svc.ListGrants()
	if err != nil {
		t.Fatalf("list grants: %v", err)
	}
	if len(grants) != 0 {
		t.Errorf("exact_request must mint no grants, got %d", len(grants))
	}
}

// Revoking a grant ends its coverage immediately.
func TestRevokeGrant(t *testing.T) {
	st, svc, d, req := scopedSetup(t)
	defer st.Close()
	appr, _ := svc.Create(d, req, d.ApprovalConfig())
	if _, _, _, err := svc.Resolve(appr.ID(), true, maintainer, appr.Version()); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	g, err := svc.FindGrant("dev", "claude-code", "ses_1", "shell.execute", "development", d.PolicyBundleHash())
	if err != nil || g == nil {
		t.Fatalf("grant expected (g=%v err=%v)", g, err)
	}
	if err := svc.RevokeGrant(g.ID()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if g2, _ := svc.FindGrant("dev", "claude-code", "ses_1", "shell.execute", "development", d.PolicyBundleHash()); g2 != nil {
		t.Errorf("a revoked grant must not cover requests")
	}
	if err := svc.RevokeGrant(g.ID()); err != approval.ErrGrantNotFound {
		t.Errorf("revoking again: got %v want ErrGrantNotFound", err)
	}
}

// A receipt is retrievable with its signed material and consumption state.
func TestReceiptStatus(t *testing.T) {
	st, svc, d, req := scopedSetup(t)
	defer st.Close()
	appr, _ := svc.Create(d, req, d.ApprovalConfig())
	_, rec, claims, err := svc.Resolve(appr.ID(), true, maintainer, appr.Version())
	if err != nil || rec == nil {
		t.Fatalf("resolve: %v", err)
	}
	got, err := svc.GetReceipt(claims.ReceiptID)
	if err != nil {
		t.Fatalf("get receipt: %v", err)
	}
	if got.Consumed() {
		t.Errorf("receipt should not be consumed yet")
	}
	if len(got.Signature()) == 0 || len(got.ClaimsBytes()) == 0 || got.KeyID() == "" {
		t.Errorf("receipt is missing signed material")
	}
	if err := svc.Consume(claims.ReceiptID, "test"); err != nil {
		t.Fatalf("consume: %v", err)
	}
	got2, err := svc.GetReceipt(claims.ReceiptID)
	if err != nil {
		t.Fatalf("get receipt 2: %v", err)
	}
	if !got2.Consumed() || got2.ConsumedAt() == nil {
		t.Errorf("receipt should be consumed")
	}
}
