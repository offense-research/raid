package policy_test

import (
	"strings"
	"testing"

	"offense.dev/raid/core/canonical"
	"offense.dev/raid/core/decision"
	"offense.dev/raid/core/policy"
)

// surgeDefault is the spec's demonstration bundle (section 6.2), adapted for
// the MVP (quorum 1 remains unimplemented in the open-source engine).
const surgeDefault = `
apiVersion: offense.dev/raid/v1alpha1
kind: PolicyBundle
metadata:
  name: surge-default
  revision: 7
defaults:
  effect: deny
rules:
  - id: github-issue-reads
    description: Allow issue reads in approved repositories
    match:
      providers: [github]
      operations:
        - github.issues.list
        - github.issues.get
      effects: [read]
    when: >-
      resource.environment != "production" ||
      principal.groups.exists(g, g == "engineering")
    effect: allow
  - id: production-label-write
    description: Ask before modifying production issue state
    match:
      providers: [github]
      operations: [github.issues.add_labels]
      environments: [production]
    when: >-
      arguments.labels.all(label,
        label in ["bug", "needs-triage", "security-review"])
    effect: require_approval
    approval:
      approver_groups: [maintainers]
      quorum: 1
      ttl: 5m
      allow_scope: exact_request
  - id: deny-repository-deletion
    match:
      operations: [github.repository.delete]
    effect: deny
`

const readerJSON = `{
  "schema_version": 1,
  "request_id": "surge:act_01J",
  "principal": {
    "subject_id": "usr_imran", "agent_id": "agt_claude", "session_id": "ses_9821",
    "runtime": "claude-code", "groups": ["engineering"], "trust_level": "local-session", "revision": 4
  },
  "action": {"provider": "github", "operation": "github.issues.get", "effect": "read"},
  "resource": {"type": "github.repository.issue", "id": "repo:991234567:issue:184", "environment": "staging", "attributes": {"repository_id": "991234567"}},
  "arguments": {},
  "context": {"timestamp": "2026-09-22T20:00:00Z", "source_product": "surge", "source_version": "0.1.0", "source_request_id": "act_01J", "task_summary": "read issues", "interactive": true}
}`

const labelWriteJSON = `{
  "schema_version": 1,
  "request_id": "surge:act_02J",
  "principal": {
    "subject_id": "usr_imran", "agent_id": "agt_claude", "session_id": "ses_9821",
    "runtime": "claude-code", "groups": ["engineering"], "trust_level": "local-session", "revision": 4
  },
  "action": {"provider": "github", "operation": "github.issues.add_labels", "effect": "write"},
  "resource": {"type": "github.repository.issue", "id": "repo:991234567:issue:184", "environment": "production", "attributes": {"repository_id": "991234567"}},
  "arguments": {"labels": {"type": "list", "value": [{"type": "string", "value": "needs-triage"}]}},
  "context": {"timestamp": "2026-09-22T20:00:00Z", "source_product": "surge", "source_version": "0.1.0", "source_request_id": "act_02J", "task_summary": "Summarize and triage open issues", "interactive": true}
}`

const deleteRepoJSON = `{
  "schema_version": 1,
  "request_id": "surge:act_03J",
  "principal": {"subject_id": "usr_imran", "agent_id": "agt_claude", "session_id": "ses_9821", "runtime": "claude-code", "groups": ["engineering"], "trust_level": "local-session", "revision": 4},
  "action": {"provider": "github", "operation": "github.repository.delete", "effect": "delete"},
  "resource": {"type": "github.repository", "id": "repo:991234567", "environment": "production", "attributes": {"repository_id": "991234567"}},
  "arguments": {},
  "context": {"timestamp": "2026-09-22T20:00:00Z", "source_product": "surge", "source_version": "0.1.0", "source_request_id": "act_03J", "task_summary": "delete repo", "interactive": true}
}`

func compileFixture(t *testing.T, yamlDoc string) *policy.CompiledBundle {
	t.Helper()
	schema, lerr := policy.LoadBundle([]byte(yamlDoc), "test")
	if lerr != nil {
		t.Fatalf("load: %v", lerr.Error())
	}
	b, cerr := policy.CompileBundle(schema, policy.CompileOptions{})
	if cerr != nil {
		t.Fatalf("compile: %v", cerr.Error())
	}
	return b
}

func decodeRequest(t *testing.T, jsonDoc string) *canonical.ActionRequest {
	t.Helper()
	req, perr := canonical.DecodeRequest([]byte(jsonDoc))
	if perr != nil {
		t.Fatalf("decode request: %v", perr.Error())
	}
	return req
}

func evalFixture(t *testing.T, yamlDoc, reqJSON string) *decision.Decision {
	t.Helper()
	b := compileFixture(t, yamlDoc)
	e := decision.NewEngine()
	e.Activate(b)
	return e.Evaluate(decodeRequest(t, reqJSON))
}

// P01: missing active bundle fails closed.
func TestP01MissingBundleFailsClosed(t *testing.T) {
	e := decision.NewEngine()
	d := e.Evaluate(decodeRequest(t, readerJSON))
	if d.Effect() != "deny" {
		t.Errorf("expected deny, got %v", d.Effect())
	}
	if d.ReasonCode() != decision.ReasonNoBundle {
		t.Errorf("expected POLICY_BUNDLE_UNAVAILABLE, got %v", d.ReasonCode())
	}
}

// P02: unknown input field is rejected before evaluation.
func TestP02UnknownFieldRejected(t *testing.T) {
	bad := strings.Replace(readerJSON, `"interactive": true`, `"interactive": true, "hack": 1`, 1)
	if _, perr := canonical.DecodeRequest([]byte(bad)); perr == nil {
		t.Errorf("unknown request field accepted")
	}
}

// P03: CEL compile type error fails activation.
func TestP03CelTypeErrorFailsActivation(t *testing.T) {
	doc := strings.Replace(surgeDefault,
		`resource.environment != "production"`, `resource.environment + 2`, 1)
	schema, lerr := policy.LoadBundle([]byte(doc), "test")
	if lerr != nil {
		t.Fatalf("load: %v", lerr.Error())
	}
	if _, cerr := policy.CompileBundle(schema, policy.CompileOptions{}); cerr == nil {
		t.Errorf("type error should fail activation")
	}
}

// P03b: unknown function fails activation.
func TestP03bUnknownFunctionFailsActivation(t *testing.T) {
	doc := strings.Replace(surgeDefault,
		`resource.environment != "production"`, `noSuchFunction(resource)`, 1)
	schema, lerr := policy.LoadBundle([]byte(doc), "test")
	if lerr != nil {
		t.Fatalf("load: %v", lerr.Error())
	}
	if _, cerr := policy.CompileBundle(schema, policy.CompileOptions{}); cerr == nil {
		t.Errorf("unknown function should fail activation")
	}
}

// P04: policy runtime error denies with POLICY_EVALUATION_ERROR.
func TestP04RuntimeUnknownDenies(t *testing.T) {
	// A rule whose `when` requires context.timestamp, evaluated against a
	// request that omits it: CEL yields a runtime error which must surface
	// as a fail-closed deny (never allow).
	doc := `
apiVersion: offense.dev/raid/v1alpha1
kind: PolicyBundle
metadata: {name: t, revision: 1}
defaults: {effect: deny}
rules:
  - id: ts-guarded-read
    match:
      operations: [github.issues.get]
    when: >-
      context.timestamp > timestamp("2020-01-01T00:00:00Z")
    effect: allow
`
	b := compileFixture(t, doc)
	e := decision.NewEngine()
	e.Activate(b)
	noTS := strings.Replace(readerJSON, `"timestamp": "2026-09-22T20:00:00Z", `, ``, 1)
	d := e.Evaluate(decodeRequest(t, noTS))
	if d.Effect() != "deny" {
		t.Errorf("runtime unknown must produce deny, got %v (%v)", d.Effect(), d.ReasonCode())
	}
}

// P05: require_approval wins over allow.
func TestP05ApprovalWinsOverAllow(t *testing.T) {
	// add an allow rule that also matches the label write
	doc := strings.Replace(surgeDefault, `- id: deny-repository-deletion`, `- id: label-anywhere-allow
    match:
      providers: [github]
      operations: [github.issues.add_labels]
    when: "true"
    effect: allow
  - id: deny-repository-deletion`, 1)
	d := evalFixture(t, doc, labelWriteJSON)
	if d.Effect() != "require_approval" {
		t.Errorf("expected require_approval, got %v (rules %v)", d.Effect(), d.MatchedRuleIDs())
	}
	if d.ApprovalConfig() == nil {
		t.Errorf("approval config missing on decision")
	}
}

// P06: any matching deny wins.
func TestP06DenyWins(t *testing.T) {
	// a deny rule for issue-writes outranks the approval rule
	doc := strings.Replace(surgeDefault, `- id: deny-repository-deletion`, `- id: deny-all-writes
    match:
      effects: [write]
    effect: deny
  - id: deny-repository-deletion`, 1)
	d := evalFixture(t, doc, labelWriteJSON)
	if d.Effect() != "deny" {
		t.Errorf("expected deny, got %v", d.Effect())
	}
}

// P08: 100k indexed rules with one candidate keeps lookup bounded.
func TestP08HugeIndexBounded(t *testing.T) {
	rules := make([]*policy.CompiledRule, 0, 100000)
	for i := 0; i < 100000; i++ {
		rules = append(rules, policy.NewStaticRule("rule-"+t_itoa(i), []string{"op." + t_itoa(i)}))
	}
	ix := policy.BuildIndex(rules)
	cands := ix.Candidates("op.50000", "other", "read", "staging")
	if len(cands) != 1 {
		t.Errorf("expected exactly 1 candidate, got %d", len(cands))
	}
	// after full static filtering, still exactly one
	matched := 0
	req := decodeRequest(t, strings.Replace(readerJSON, "github.issues.get", "op.50000", 1))
	act := req.Action()
	rsrc := req.Resource()
	for _, idx := range cands {
		if rules[int(idx)].MatchStatic(act.Operation(), act.Provider(), act.Effect(), rsrc.Environment()) {
			matched++
		}
	}
	if matched != 1 {
		t.Errorf("static filter: expected 1 match, got %d", matched)
	}
}

// P09: a failing embedded test rejects activation.
func TestP09EmbeddedTestGate(t *testing.T) {
	doc := surgeDefault + `
tests:
  - name: reader can list issues
    input: reader-list.json
    expect:
      effect: deny
`
	schema, lerr := policy.LoadBundle([]byte(doc), "test")
	if lerr != nil {
		t.Fatalf("load: %v", lerr.Error())
	}
	reader := func(path string) (*canonical.ActionRequest, error) {
		switch path {
		case "reader-list.json":
			return decodeRequest(t, readerJSON), nil
		case "label-prod.json":
			return decodeRequest(t, labelWriteJSON), nil
		}
		return nil, canonical.NewError("no such fixture", "input", 0)
	}
	if _, cerr := policy.CompileBundle(schema, policy.CompileOptions{RequestLoader: reader}); cerr == nil {
		t.Errorf("failing embedded test must reject activation")
	}
}

// P09b: passing embedded tests activate.
func TestP09bEmbeddedTestsPass(t *testing.T) {
	doc := surgeDefault + `
tests:
  - name: reader can list issues
    input: reader-list.json
    expect:
      effect: allow
      matched_rules: [github-issue-reads]
  - name: production label write requires approval
    input: label-prod.json
    expect:
      effect: require_approval
  - name: repository deletion denied
    input: delete-repo.json
    expect:
      effect: deny
`
	schema, lerr := policy.LoadBundle([]byte(doc), "test")
	if lerr != nil {
		t.Fatalf("load: %v", lerr.Error())
	}
	reader := func(path string) (*canonical.ActionRequest, error) {
		switch path {
		case "reader-list.json":
			return decodeRequest(t, readerJSON), nil
		case "label-prod.json":
			return decodeRequest(t, labelWriteJSON), nil
		case "delete-repo.json":
			return decodeRequest(t, deleteRepoJSON), nil
		}
		return nil, canonical.NewError("no such fixture", "input", 0)
	}
	if _, cerr := policy.CompileBundle(schema, policy.CompileOptions{RequestLoader: reader}); cerr != nil {
		t.Errorf("passing tests must activate: %v", cerr.Error())
	}
}

// Happy-path allow and deny against the demonstration bundle.
func TestAllowDenyBasics(t *testing.T) {
	d := evalFixture(t, surgeDefault, readerJSON)
	if d.Effect() != "allow" {
		t.Errorf("reader should be allowed, got %v (%v)", d.Effect(), d.ReasonCode())
	}
	d = evalFixture(t, surgeDefault, labelWriteJSON)
	if d.Effect() != "require_approval" {
		t.Errorf("label write should require approval, got %v", d.Effect())
	}
	d = evalFixture(t, surgeDefault, deleteRepoJSON)
	if d.Effect() != "deny" {
		t.Errorf("delete should be denied, got %v", d.Effect())
	}
}

// Deterministic hashing: same request hash, different arguments differ.
func TestRequestHashDeterminism(t *testing.T) {
	r1 := decodeRequest(t, readerJSON)
	h1 := canonical.HashRequest(r1)
	h2 := canonical.HashRequest(r1)
	if !canonical.RequestHashEquals(h1, h2) {
		t.Errorf("hash not deterministic")
	}
	other := strings.Replace(readerJSON, `"issue": 184"`, `"issue": 185"`, 1)
	_ = other
	// different arguments -> different hash
	withArg := strings.Replace(readerJSON, `"arguments": {},`, `"arguments": {"issue_number": {"type": "int64", "value": 185}},`, 1)
	r2 := decodeRequest(t, withArg)
	if canonical.RequestHashEquals(h1, canonical.HashRequest(r2)) {
		t.Errorf("argument change must change the hash")
	}
}

func t_itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
// P10: authority-widening diff detection.
func TestP10AuthorityWideningDiff(t *testing.T) {
	oldDoc := `
apiVersion: offense.dev/raid/v1alpha1
kind: PolicyBundle
metadata: {name: d, revision: 1}
defaults: {effect: deny}
rules:
  - id: allow-reads
    match:
      operations: [github.issues.get]
    when: "true"
    effect: allow
  - id: deny-delete
    match:
      operations: [github.repository.delete]
    effect: deny
`
	newWidening := `
apiVersion: offense.dev/raid/v1alpha1
kind: PolicyBundle
metadata: {name: d, revision: 2}
defaults: {effect: deny}
rules:
  - id: allow-reads
    match:
      operations: [github.issues.get]
    when: "true"
    effect: allow
  - id: deny-delete
    match:
      operations: [github.repository.delete]
    effect: deny
  - id: allow-labels
    match:
      operations: [github.issues.add_labels]
    effect: allow
`
	oldS, _ := policy.LoadBundle([]byte(oldDoc), "t")
	newS, _ := policy.LoadBundle([]byte(newWidening), "t")
	rep := policy.DiffPolicy(oldS, newS)
	text := rep.String()
	if !strings.Contains(text, "WIDENS AUTHORITY") {
		t.Errorf("expected widened authority warning, got: %v", text)
	}

	removed := strings.Replace(newWidening, "  - id: deny-delete\n    match:\n      operations: [github.repository.delete]\n    effect: deny\n", "", 1)
	newS2, _ := policy.LoadBundle([]byte(removed), "t")
	rep2 := policy.DiffPolicy(oldS, newS2)
	if !strings.Contains(rep2.String(), "REMOVES DENY") {
		t.Errorf("expected removed-deny warning, got: %v", rep2.String())
	}

	approved := strings.Replace(newWidening, "  - id: allow-labels\n    match:\n      operations: [github.issues.add_labels]\n    effect: allow\n", "  - id: allow-labels\n    match:\n      operations: [github.issues.add_labels]\n    effect: require_approval\n    approval:\n      approver_groups: [maintainers]\n      ttl: 5m\n      allow_scope: exact_request\n", 1)
	newS3, _ := policy.LoadBundle([]byte(approved), "t")
	// a rule changing from allow to require_approval reports ADDS APPROVAL
	rep3 := policy.DiffPolicy(newS, newS3)
	if !strings.Contains(rep3.String(), "ADDS APPROVAL") {
		t.Errorf("expected adds-approval warning, got: %v", rep3.String())
	}
}

// P07: bundle activation under load — every request sees exactly one complete
// bundle version (the atomic pointer swap is never torn).
func TestP07AtomicBundleSwap(t *testing.T) {
	const loDoc = `
apiVersion: offense.dev/raid/v1alpha1
kind: PolicyBundle
metadata: {name: swap, revision: 1}
defaults: {effect: deny}
rules:
  - id: lo-allow
    match:
      operations: [github.issues.get]
    when: "true"
    effect: allow
`
	const hiDoc = `
apiVersion: offense.dev/raid/v1alpha1
kind: PolicyBundle
metadata: {name: swap, revision: 2}
defaults: {effect: deny}
rules:
  - id: hi-deny
    match:
      operations: [github.issues.get]
    when: "true"
    effect: deny
`
	lo := compileFixture(t, loDoc)
	hi := compileFixture(t, hiDoc)
	eng := decision.NewEngine()
	eng.Activate(lo)
	req := decodeRequest(t, readerJSON)
	var stop bool
	var bad bool
	go func() {
		for i := 0; i < 200000 && !stop; i++ {
			d := eng.Evaluate(req)
			// the decision must be coherent with exactly one bundle:
			// revision 1 grants allow; revision 2 denies.
			if d.PolicyBundleID() == "swap:1" {
				if d.Effect() != "allow" {
					bad = true
				}
			} else if d.PolicyBundleID() == "swap:2" {
				if d.Effect() != "deny" {
					bad = true
				}
			} else {
				bad = true
			}
			if i % 1000 == 0 {
				eng.Activate(hi)
				eng.Activate(lo)
			}
		}
	}()
	// let the evaluator goroutine do a mixed workload too
	for j := 0; j < 200000 && !bad; j++ {
		d := eng.Evaluate(req)
		if d.PolicyBundleID() == "swap:1" && d.Effect() != "allow" {
			bad = true
		}
		if d.PolicyBundleID() == "swap:2" && d.Effect() != "deny" {
			bad = true
		}
		if j % 1000 == 0 {
			eng.Activate(hi)
			eng.Activate(lo)
		}
	}
	stop = true
	if bad {
		t.Errorf("torn bundle snapshot observed under concurrent activation")
	}
}
