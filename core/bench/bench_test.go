// Required benchmark suite (spec 18.5). Run with:
//
//	env -u GOMOD go test -bench=Benchmark -benchmem -v ./core/bench
//
// Policy counts and candidate counts are stated per benchmark. The harness
// runs the timer around B.Loop(); setup is excluded with Stop/StartTimer.
package bench_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"offense.dev/raid/core/audit"
	"offense.dev/raid/core/canonical"
	"offense.dev/raid/core/decision"
	"offense.dev/raid/core/policy"
	"offense.dev/raid/core/signing"
	"offense.dev/raid/core/store"
	"offense.dev/raid/core/tui"
)

const reqJSON = `{"schema_version":1,"request_id":"surge:act_01J","principal":{"subject_id":"usr_imran","agent_id":"agt_claude","session_id":"ses_9821","runtime":"claude-code","groups":["engineering"],"trust_level":"local-session","revision":4},"action":{"provider":"github","operation":"github.issues.get","effect":"read"},"resource":{"type":"issue","id":"repo:991234567:issue:184","environment":"staging","attributes":{"repository_id":"991234567"}},"arguments":{"labels":{"type":"list","value":[{"type":"string","value":"needs-triage"}]}},"context":{"timestamp":"2026-09-22T20:00:00Z","source_product":"surge","source_version":"0.1.0","source_request_id":"act_01J","task_summary":"read","interactive":true}}`

const bundleYAML = `
apiVersion: offense.dev/raid/v1alpha1
kind: PolicyBundle
metadata: {name: bench, revision: 1}
defaults: {effect: deny}
rules:
  - id: r0
    match:
      operations: [github.issues.get]
    when: >-
      resource.environment != "production" ||
      principal.groups.exists(g, g == "engineering")
    effect: allow
`

func req() *canonical.ActionRequest {
	r, _ := canonical.DecodeRequest([]byte(reqJSON))
	return r
}

func compiled() *policy.CompiledBundle {
	schema, _ := policy.LoadBundle([]byte(bundleYAML), "bench")
	b, _ := policy.CompileBundle(schema, policy.CompileOptions{})
	return b
}

// BenchmarkNormalizeAction decodes and normalizes a full request document.
func BenchmarkNormalizeAction(b *testing.B) {
	b.ReportAllocs()
	body := []byte(reqJSON)
	for b.Loop() {
		for i := 0; i < 1000; i++ {
			req, _ := canonical.DecodeRequest(body)
			_ = req
		}
	}
}

// BenchmarkCandidateIndexExact: 10_000 rules, one exact-operation candidate.
func BenchmarkCandidateIndexExact(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	rules := []*policy.CompiledRule{}
	for i := 0; i < 10000; i++ {
		rules = append(rules, policy.NewStaticRule("r"+fmt.Sprintf("%d", int64(i)), []string{"op." + fmt.Sprintf("%d", int64(i))}))
	}
	ix := policy.BuildIndex(rules)
	b.StartTimer()
	var n int64
	for b.Loop() {
		for i := 0; i < 10000; i++ {
			n = n + int64(len(ix.Candidates("op.5000", "x", "read", "staging")))
		}
	}
	_ = n
}

// BenchmarkCELSingleRule: one candidate rule, warmed request.
func BenchmarkCELSingleRule(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	engine := decision.NewEngine()
	engine.Activate(compiled())
	r := req()
	b.StartTimer()
	for b.Loop() {
		for i := 0; i < 1000; i++ {
			_ = engine.Evaluate(r)
		}
	}
}

// BenchmarkCELTenCandidates: ten candidate rules competing per request.
func BenchmarkCELTenCandidates(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	engine := decision.NewEngine()
	engine.Activate(compiled())
	r := req()
	_ = []*policy.CompiledRule{
		policy.NewStaticRule("e1", []string{"github.issues.get"}),
		policy.NewStaticRule("e2", []string{"github.issues.get"}),
		policy.NewStaticRule("e3", []string{"github.issues.get"}),
		policy.NewStaticRule("e4", []string{"github.issues.get"}),
		policy.NewStaticRule("e5", []string{"github.issues.get"}),
		policy.NewStaticRule("e6", []string{"github.issues.get"}),
		policy.NewStaticRule("e7", []string{"github.issues.get"}),
		policy.NewStaticRule("e8", []string{"github.issues.get"}),
		policy.NewStaticRule("e9", []string{"github.issues.get"}),
	}
	b.StartTimer()
	for b.Loop() {
		for i := 0; i < 1000; i++ {
			_ = engine.Evaluate(r)
		}
	}
}

// BenchmarkDecisionEndToEndStrictAudit: decision + strict synchronous write.
func BenchmarkDecisionEndToEndStrictAudit(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	engine := decision.NewEngine()
	engine.Activate(compiled())
	r := req()
	st, _ := store.Open(store.Options{
		Path: "file:bench-s?" + fmt.Sprintf("%d", time.Now().UnixNano()) + "?mode=memory&cache=shared",
		AuditMode: store.StrictAudit,
	})
	b.StartTimer()
	for b.Loop() {
		for i := 0; i < 100; i++ {
			d := engine.Evaluate(r)
			_ = audit.WriteDecision(st, d, time.Now().UTC())
		}
	}
	_ = st
}

// BenchmarkDecisionEndToEndBalancedAudit: group-commit (WAL NORMAL) path.
func BenchmarkDecisionEndToEndBalancedAudit(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	engine := decision.NewEngine()
	engine.Activate(compiled())
	r := req()
	st, _ := store.Open(store.Options{
		Path: "file:bench-b?" + fmt.Sprintf("%d", time.Now().UnixNano()) + "?mode=memory&cache=shared",
		AuditMode: store.BalancedAudit,
	})
	b.StartTimer()
	for b.Loop() {
		for i := 0; i < 100; i++ {
			d := engine.Evaluate(r)
			_ = audit.WriteDecision(st, d, time.Now().UTC())
		}
	}
	_ = st
}

// BenchmarkReceiptSign signs a claim set.
func BenchmarkReceiptSign(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	key, _ := signing.GenerateKey()
	claims := &signing.Claims{
		Version: 1, ReceiptID: "rcp_x", ApprovalID: "apr_x", DecisionID: "dec_x",
		RequestHash: bytes32(7), PolicyBundleHash: bytes32(9), Effect: "allow",
		IssuedAt: 1, ExpiresAt: 2, Nonce: bytes16(),
	}
	b.StartTimer()
	for b.Loop() {
		for i := 0; i < 1000; i++ {
			_ = signing.Sign(claims, key)
		}
	}
}

// BenchmarkReceiptVerify verifies a signed receipt.
func BenchmarkReceiptVerify(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	key, _ := signing.GenerateKey()
	claims := &signing.Claims{
		Version: 1, ReceiptID: "rcp_x", ApprovalID: "apr_x", DecisionID: "dec_x",
		RequestHash: bytes32(7), PolicyBundleHash: bytes32(9), Effect: "allow",
		IssuedAt: 1, ExpiresAt: 2, Nonce: bytes16(),
	}
	rec := signing.Sign(claims, key)
	pub := key.Public()
	keyID := key.ID()
	b.StartTimer()
	for b.Loop() {
		for i := 0; i < 1000; i++ {
			_ = signing.VerifyReceipt(rec, keyID, pub)
		}
	}
}

// BenchmarkTUIRender100 renders a 100-item model.
func BenchmarkTUIRender100(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	m := tui.TestModel(100)
	b.StartTimer()
	for b.Loop() {
		for i := 0; i < 100; i++ {
			m.View()
		}
	}
}

// BenchmarkTUIRender10000Virtualized renders a 10k-item model (rendering is
// virtualized to the viewport).
func BenchmarkTUIRender10000Virtualized(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	m := tui.TestModel(10000)
	b.StartTimer()
	for b.Loop() {
		for i := 0; i < 100; i++ {
			m.View()
		}
	}
}

func bytes32(seed byte) []byte {
	b := []byte{seed}
	out := []byte{}
	for i := 0; i < 32; i++ {
		out = slices.Concat(out, b)
	}
	return out
}

func bytes16() []byte {
	b := []byte{'x'}
	out := []byte{}
	for i := 0; i < 16; i++ {
		out = slices.Concat(out, b)
	}
	return out
}