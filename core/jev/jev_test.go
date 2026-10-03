// Jev invariant tests (spec 18.2) via the scripted fake evaluator.
package jev_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/offense-research/raid/core/canonical"
	"github.com/offense-research/raid/core/decision"
	"github.com/offense-research/raid/core/jev"
	"github.com/offense-research/raid/core/policy"
)

const doc = `
apiVersion: offense.dev/raid/v1alpha1
kind: PolicyBundle
metadata: {name: j, revision: 1}
defaults: {effect: deny}
rules:
  - id: reads
    match:
      operations: [github.issues.get]
    when: "true"
    effect: allow
  - id: deletes
    match:
      operations: [github.repository.delete]
    effect: deny
`

const reader = `{"schema_version":1,"request_id":"r1","principal":{"subject_id":"u","agent_id":"a","session_id":"s","runtime":"cli","groups":["eng"],"trust_level":"local","revision":1},"action":{"provider":"github","operation":"github.issues.get","effect":"read"},"resource":{"type":"issue","id":"i1","environment":"staging","attributes":{}},"arguments":{},"context":{"timestamp":"2026-09-22T20:00:00Z","source_product":"surge","source_version":"1","source_request_id":"r1","task_summary":"read","interactive":true}}`

const delReq = `{"schema_version":1,"request_id":"r2","principal":{"subject_id":"u","agent_id":"a","session_id":"s","runtime":"cli","groups":["eng"],"trust_level":"local","revision":1},"action":{"provider":"github","operation":"github.repository.delete","effect":"delete"},"resource":{"type":"repo","id":"r","environment":"production","attributes":{}},"arguments":{},"context":{"timestamp":"2026-09-22T20:00:00Z","source_product":"surge","source_version":"1","source_request_id":"r2","task_summary":"del","interactive":true}}`

func compile(t *testing.T) *policy.CompiledBundle {
	t.Helper()
	schema, lerr := policy.LoadBundle([]byte(doc), "t")
	if lerr != nil {
		t.Fatalf("load: %v", lerr.Error())
	}
	b, cerr := policy.CompileBundle(schema, policy.CompileOptions{})
	if cerr != nil {
		t.Fatalf("compile: %v", cerr.Error())
	}
	return b
}

func base(t *testing.T, reqJSON string) *decision.Decision {
	t.Helper()
	e := decision.NewEngine()
	e.Activate(compile(t))
	req, perr := canonical.DecodeRequest([]byte(reqJSON))
	if perr != nil {
		t.Fatalf("req: %v", perr.Error())
	}
	return e.Evaluate(req)
}

func thresholds() jev.Thresholds {
	return jev.FromConfig(map[string]float64{
		"intent_mismatch":     0.45,
		"credential_exposure": 0.20,
		"prompt_injection":    0.35,
		"impact":              0.60,
		"ambiguity":           2.0,
	})
}

func highRisk() map[string]jev.Answer {
	return map[string]jev.Answer{
		"intent_mismatch":     {Choice: "yes", Score: 0.91, Valid: true},
		"credential_exposure": {Choice: "no", Score: 0.02, Valid: true},
		"prompt_injection":    {Choice: "yes", Score: 0.60, Valid: true},
	}
}

func lowRisk() map[string]jev.Answer {
	return map[string]jev.Answer{
		"intent_mismatch":     {Choice: "no", Score: 0.05, Valid: true},
		"credential_exposure": {Choice: "no", Score: 0.01, Valid: true},
		"prompt_injection":    {Choice: "no", Score: 0.03, Valid: true},
	}
}

// J01: deterministic deny with a semantic guard -> zero Jev calls.
func TestJ01DenySkipsJev(t *testing.T) {
	eng := decision.NewEngine()
	eng.Activate(compile(t))
	req, _ := canonical.DecodeRequest([]byte(delReq))
	d := eng.Evaluate(req)
	if d.Effect() != "deny" {
		t.Fatalf("expected deny base")
	}
	guard := policy.NewGuardForTest("enforce", "require_approval", "require_approval", nil)
	fake := jev.NewFakeEvaluator(highRisk(), thresholds(), nil)
	final, skipped, err := decision.ApplySemantic(d, guard, fake, req)
	if err != nil {
		t.Fatalf("semantic: %v", err)
	}
	if !skipped {
		t.Errorf("deny must skip Jev")
	}
	if jev.Calls(fake) != 0 {
		t.Errorf("expected zero Jev calls, got %d", jev.Calls(fake))
	}
	if final.Effect() != "deny" {
		t.Errorf("final must be deny, got %v", final.Effect())
	}
}

// J02: no semantic guard -> zero Jev calls.
func TestJ02NoGuardSkipsJev(t *testing.T) {
	fake := jev.NewFakeEvaluator(highRisk(), thresholds(), nil)
	req, _ := canonical.DecodeRequest([]byte(reader))
	d := base(t, reader)
	final, skipped, _ := decision.ApplySemantic(d, nil, fake, req)
	if !skipped {
		t.Errorf("no guard must skip")
	}
	if jev.Calls(fake) != 0 {
		t.Errorf("expected zero calls, got %d", jev.Calls(fake))
	}
	if final.Effect() != "allow" {
		t.Errorf("expected allow, got %v", final.Effect())
	}
}

// J04: Jev detects risk after a base allow -> escalation (never allow).
func TestJ04RiskEscalatesAllow(t *testing.T) {
	guard := policy.NewGuardForTest("enforce", "require_approval", "require_approval", nil)
	fake := jev.NewFakeEvaluator(highRisk(), thresholds(), nil)
	req, _ := canonical.DecodeRequest([]byte(reader))
	d := base(t, reader)
	if d.Effect() != "allow" {
		t.Fatalf("expected allow base, got %v", d.Effect())
	}
	final, skipped, err := decision.ApplySemantic(d, guard, fake, req)
	if err != nil {
		t.Fatalf("semantic: %v", err)
	}
	if skipped {
		t.Errorf("allow with escalation-enabled guard must run Jev")
	}
	if jev.Calls(fake) != 1 {
		t.Errorf("expected exactly 1 call, got %d", jev.Calls(fake))
	}
	if final.Effect() != "require_approval" {
		t.Errorf("expected require_approval escalation, got %v", final.Effect())
	}
	// escalate-to-deny ceiling
	guard2 := policy.NewGuardForTest("enforce", "require_approval", "deny", nil)
	final2, _, _ := decision.ApplySemantic(d, guard2, fake, req)
	if final2.Effect() != "deny" {
		t.Errorf("expected deny ceiling escalation, got %v", final2.Effect())
	}
}

// J05: evaluator failure -> configured escalation, never allow.
func TestJ05FailureNeverAllows(t *testing.T) {
	guard := policy.NewGuardForTest("enforce", "require_approval", "require_approval", nil)
	req, _ := canonical.DecodeRequest([]byte(reader))
	d := base(t, reader)
	fake := jev.NewFakeEvaluator(nil, thresholds(), errors.New("timeout"))
	final, _, _ := decision.ApplySemantic(d, guard, fake, req)
	if final.Effect() != "require_approval" {
		t.Errorf("failure must escalate to require_approval, got %v", final.Effect())
	}
	// a deny-configured failure is also fine
	guard2 := policy.NewGuardForTest("enforce", "deny", "require_approval", nil)
	final2, _, _ := decision.ApplySemantic(d, guard2, fake, req)
	if final2.Effect() != "deny" {
		t.Errorf("failure_effect deny must deny, got %v", final2.Effect())
	}
}

// J08: secret canary is absent from state and the HTTP body.
func TestJ08NoSecrets(t *testing.T) {
	const canary = "tok_livesecret123456"
	reqJSON := strings.Replace(reader, `"arguments":{}`, `"arguments":{"labels":{"type":"list","value":[{"type":"string","value":"`+canary+`"}]}}`, 1)
	req, perr := canonical.DecodeRequest([]byte(reqJSON))
	if perr != nil {
		t.Fatalf("req: %v", perr.Error())
	}
	state, clean := jev.BuildState(req, []string{canary})
	if !clean {
		t.Errorf("canary leaked into state")
	}
	if strings.Contains(state, canary) {
		t.Errorf("secret canary present in sanitized state")
	}
	body := jev.BodyForRequest(state)
	if strings.Contains(body, canary) {
		t.Errorf("secret canary present in HTTP body")
	}
	if strings.Contains(body, "api_key") || strings.Contains(body, "token") {
		t.Errorf("sensitive field name leaked into body")
	}
}

// J11: shadow mode records the comparison without changing the outcome.
func TestJ11ShadowRecordsOnly(t *testing.T) {
	guard := policy.NewGuardForTest("shadow", "require_approval", "require_approval", nil)
	fake := jev.NewFakeEvaluator(highRisk(), thresholds(), nil)
	req, _ := canonical.DecodeRequest([]byte(reader))
	d := base(t, reader)
	final, skipped, _ := decision.ApplySemantic(d, guard, fake, req)
	if skipped {
		t.Errorf("shadow mode still runs the evaluator")
	}
	if jev.Calls(fake) != 1 {
		t.Errorf("expected 1 call in shadow, got %d", jev.Calls(fake))
	}
	if final.Effect() != "allow" {
		t.Errorf("shadow must not change outcome, got %v", final.Effect())
	}
	if final.Semantic() == nil {
		t.Errorf("shadow must record semantic evidence")
	}
}

// J12: a question-set change produces a different cache key (a miss).
func TestJ12CacheKeyMissOnChange(t *testing.T) {
	th := thresholds()
	key1 := jev.CacheKey("state-a", "agent-action-risk-v1", "jev-1.13.0", th.Hash())
	key2 := jev.CacheKey("state-a", "agent-action-risk-v2", "jev-1.13.0", th.Hash())
	if canonical.RequestHashEquals(key1, key2) {
		t.Errorf("question-set change must invalidate the cache key")
	}
	key3 := jev.CacheKey("state-a", "agent-action-risk-v1", "jev-1.13.0", th.Hash())
	if !canonical.RequestHashEquals(key1, key3) {
		t.Errorf("identical inputs must share a cache key")
	}
}

// The HTTP evaluator's default transport performs a real request with the
// bearer key, and decodes the System One answers schema.
func TestHTTPEvaluatorRealTransport(t *testing.T) {
	var gotAuth string
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"model":"jev-1.13.0","answers":{"a":{"choice":"yes","probability":0.9}}}`)
	}))
	defer srv.Close()

	e := jev.NewHttpEvaluator(srv.URL, "sk-jev", "jev-1.13.0", 1_000_000_000)
	res, err := e.Evaluate(jev.SemanticInput{State: `{"op":"shell.delete"}`, Ceiling: "require_approval"})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if res == nil || res.Answers == "" {
		t.Fatalf("expected decoded answers, got %+v", res)
	}
	if gotAuth != "Bearer sk-jev" {
		t.Errorf("authorization header: %q", gotAuth)
	}
	if !strings.Contains(gotBody, "actuals") && !strings.Contains(gotBody, "state") && gotBody == "" {
		t.Errorf("request body not sent: %q", gotBody)
	}
}
