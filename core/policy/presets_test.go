package policy_test

import (
	"strings"
	"testing"

	"github.com/offense-research/raid/core/canonical"
	"github.com/offense-research/raid/core/policy"
)

// req builds a normalized request for preset evaluation.
func req(t *testing.T, operation, effectClass, environment string, attrs map[string]string) *canonical.ActionRequest {
	t.Helper()
	var ab strings.Builder
	ab.WriteByte('{')
	first := true
	for k, v := range attrs {
		if !first {
			ab.WriteByte(',')
		}
		first = false
		ab.WriteString(`"` + k + `":"` + v + `"`)
	}
	ab.WriteByte('}')
	js := `{
		"schema_version": 1,
		"request_id": "t:1",
		"principal": {"subject_id":"dev","agent_id":"claude-code","session_id":"ses_1","runtime":"claude-code","groups":[],"trust_level":"local-session","revision":1},
		"action": {"provider":"claude-code","operation":"` + operation + `","effect":"` + effectClass + `"},
		"resource": {"type":"shell","id":".","environment":"` + environment + `","attributes":` + ab.String() + `},
		"arguments": {},
		"context": {"source_product":"claude-code","source_request_id":"t:1","interactive":true}
	}`
	r, perr := canonical.DecodeRequest([]byte(js))
	if perr != nil {
		t.Fatalf("decode request: %v", perr.Message())
	}
	return r
}

func evalPreset(t *testing.T, name string, r *canonical.ActionRequest) string {
	t.Helper()
	b, cerr, lerr := policy.CompilePreset(name)
	if lerr != nil {
		t.Fatalf("preset %s did not load: %v", name, lerr.Error())
	}
	if cerr != nil {
		t.Fatalf("preset %s did not compile: %v", name, cerr.Error())
	}
	res := policy.EvaluateBundle(b, r)
	if res.IsError() {
		t.Fatalf("preset %s evaluation error: %s", name, res.ReasonCode())
	}
	return res.Effect()
}

func TestPresetsLoad(t *testing.T) {
	names := policy.PresetNames()
	if len(names) < 3 {
		t.Fatalf("expected at least 3 presets, got %v", names)
	}
	for _, name := range names {
		if _, cerr, lerr := policy.CompilePreset(name); lerr != nil || cerr != nil {
			t.Fatalf("preset %s failed: load=%v compile=%v", name, lerr, cerr)
		}
		if policy.PresetDescription(name) == "" {
			t.Errorf("preset %s has no description", name)
		}
	}
}

func TestSoloDevSafeGuardrail(t *testing.T) {
	destructive := map[string]string{"destructive": "true", "protected_branch": "false", "exfil": "false"}
	benign := map[string]string{"destructive": "false", "protected_branch": "false", "exfil": "false"}

	cases := []struct {
		name string
		op   string
		fx   string
		env  string
		attr map[string]string
		want string
	}{
		{"read", "shell.read", "read", "development", benign, "allow"},
		{"dev write", "filesystem.write", "write", "development", benign, "allow"},
		{"prod write", "filesystem.write", "write", "production", benign, "require_approval"},
		{"exec", "container.exec", "execute", "development", benign, "require_approval"},
		{"delete", "shell.delete", "delete", "development", benign, "require_approval"},
		{"catastrophic delete", "shell.delete", "delete", "development", destructive, "deny"},
		{"force push feature", "git.force_push", "write", "development", benign, "require_approval"},
		{"first touch of destructive op", "shell.delete", "delete", "development", destructive, "deny"},
		{"dev push", "git.push", "write", "development", benign, "allow"},
	}
	for _, tc := range cases {
		got := evalPreset(t, "solo-dev-safe", req(t, tc.op, tc.fx, tc.env, tc.attr))
		if got != tc.want {
			t.Errorf("%s: op=%s env=%s got %s want %s", tc.name, tc.op, tc.env, got, tc.want)
		}
	}
}

func TestSoloDevSafeProtectedBranch(t *testing.T) {
	protected := map[string]string{"destructive": "false", "protected_branch": "true", "exfil": "false"}
	got := evalPreset(t, "solo-dev-safe", req(t, "git.force_push", "write", "development", protected))
	if got != "deny" {
		t.Errorf("force push to protected branch: got %s want deny", got)
	}
	got = evalPreset(t, "solo-dev-safe", req(t, "git.push", "write", "development", protected))
	if got != "require_approval" {
		t.Errorf("push to protected branch: got %s want require_approval", got)
	}
}

func TestSoloDevSafeExfil(t *testing.T) {
	exfil := map[string]string{"destructive": "false", "protected_branch": "false", "exfil": "true"}
	got := evalPreset(t, "solo-dev-safe", req(t, "network.fetch", "read", "development", exfil))
	if got != "deny" {
		t.Errorf("read fetch with exfil attr: got %s want deny", got)
	}
	got = evalPreset(t, "solo-dev-safe", req(t, "shell.write", "write", "development", exfil))
	if got != "deny" {
		t.Errorf("mutating op with exfil attr: got %s want deny", got)
	}
	benign := map[string]string{"destructive": "false", "protected_branch": "false", "exfil": "false"}
	if got := evalPreset(t, "solo-dev-safe", req(t, "shell.read", "read", "development", benign)); got != "allow" {
		t.Errorf("plain read: got %s want allow", got)
	}
}

func TestReviewOnly(t *testing.T) {
	benign := map[string]string{"destructive": "false", "protected_branch": "false", "exfil": "false"}
	if got := evalPreset(t, "review-only", req(t, "shell.read", "read", "development", benign)); got != "allow" {
		t.Errorf("read: got %s want allow", got)
	}
	if got := evalPreset(t, "review-only", req(t, "filesystem.write", "write", "development", benign)); got != "deny" {
		t.Errorf("write: got %s want deny", got)
	}
	if got := evalPreset(t, "review-only", req(t, "container.exec", "execute", "development", benign)); got != "deny" {
		t.Errorf("exec: got %s want deny", got)
	}
}

func TestCIAgent(t *testing.T) {
	benign := map[string]string{"destructive": "false", "protected_branch": "false", "exfil": "false"}
	destructive := map[string]string{"destructive": "true", "protected_branch": "false", "exfil": "false"}
	if got := evalPreset(t, "ci-agent", req(t, "shell.execute", "execute", "development", benign)); got != "allow" {
		t.Errorf("dev build/test: got %s want allow", got)
	}
	if got := evalPreset(t, "ci-agent", req(t, "shell.execute", "execute", "production", benign)); got != "require_approval" {
		t.Errorf("prod exec: got %s want require_approval", got)
	}
	if got := evalPreset(t, "ci-agent", req(t, "shell.delete", "delete", "development", destructive)); got != "deny" {
		t.Errorf("destructive: got %s want deny", got)
	}
}

// attr builds a full attribute map for the guardrail cases below, so each case
// states only what it is actually about.
func attr(pairs ...string) map[string]string {
	m := map[string]string{
		"destructive":      "false",
		"protected_branch": "false",
		"exfil":            "false",
		"egress":           "false",
		"outbound_secret":  "false",
		"tainted_egress":   "false",
		"untrusted_source": "false",
	}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i]] = pairs[i+1]
	}
	return m
}

func TestSoloDevSafeEgressGuardrails(t *testing.T) {
	outbound := attr("egress", "true", "outbound_secret", "true")
	tainted := attr("egress", "true", "tainted_egress", "true")
	plain := attr("egress", "true")

	// A recognised credential value on the way out is denied outright.
	if got := evalPreset(t, "solo-dev-safe", req(t, "network.fetch", "read", "development", outbound)); got != "deny" {
		t.Errorf("outbound secret: got %s want deny", got)
	}
	if got := evalPreset(t, "solo-dev-safe", req(t, "shell.read", "read", "development", outbound)); got != "deny" {
		t.Errorf("outbound secret via shell.read: got %s want deny", got)
	}
	// Egress from a session that has already handled credentials asks a human.
	if got := evalPreset(t, "solo-dev-safe", req(t, "network.fetch", "read", "development", tainted)); got != "require_approval" {
		t.Errorf("tainted egress: got %s want require_approval", got)
	}
	// Plain egress is left alone: gating every fetch would make the guardrail
	// unusable and teach the operator to approve without reading.
	if got := evalPreset(t, "solo-dev-safe", req(t, "network.fetch", "read", "development", plain)); got != "allow" {
		t.Errorf("plain egress: got %s want allow", got)
	}
}

func TestSoloDevSafeUntrustedSource(t *testing.T) {
	untrusted := attr("untrusted_source", "true")

	// A state-changing action after the session read outside content.
	for _, tc := range []struct{ op, fx string }{
		{"git.push", "write"},
		{"shell.delete", "delete"},
		{"filesystem.write", "write"},
		{"cloud.mutate", "write"},
	} {
		got := evalPreset(t, "solo-dev-safe", req(t, tc.op, tc.fx, "development", untrusted))
		if got != "require_approval" {
			t.Errorf("%s after untrusted input: got %s want require_approval", tc.op, got)
		}
	}
	// Reading is not a state-changing action; the taint alone must not gate it.
	if got := evalPreset(t, "solo-dev-safe", req(t, "shell.read", "read", "development", untrusted)); got != "allow" {
		t.Errorf("read after untrusted input: got %s want allow", got)
	}
}

func TestCIAgentEgressGuardrails(t *testing.T) {
	outbound := attr("egress", "true", "outbound_secret", "true")
	tainted := attr("egress", "true", "tainted_egress", "true")
	// A pipeline has no human to ask, so both are a flat deny rather than a
	// confirmation that would simply hang the build.
	if got := evalPreset(t, "ci-agent", req(t, "network.fetch", "read", "development", outbound)); got != "deny" {
		t.Errorf("ci outbound secret: got %s want deny", got)
	}
	if got := evalPreset(t, "ci-agent", req(t, "network.fetch", "read", "development", tainted)); got != "deny" {
		t.Errorf("ci tainted egress: got %s want deny", got)
	}
	// The agent's own fetch tooling is untouched when nothing is being carried.
	if got := evalPreset(t, "ci-agent", req(t, "network.fetch", "read", "development", attr("egress", "true"))); got != "allow" {
		t.Errorf("ci plain egress: got %s want allow", got)
	}
}

func TestCIAgentUntrustedSource(t *testing.T) {
	if got := evalPreset(t, "ci-agent", req(t, "shell.execute", "execute", "development", attr("untrusted_source", "true"))); got != "require_approval" {
		t.Errorf("ci exec after untrusted input: got %s want require_approval", got)
	}
	// An ordinary build step carries no taint and must stay allowed.
	if got := evalPreset(t, "ci-agent", req(t, "shell.execute", "execute", "development", attr())); got != "allow" {
		t.Errorf("ci plain build: got %s want allow", got)
	}
}

func TestReviewOnlyEgressGuardrail(t *testing.T) {
	outbound := attr("egress", "true", "outbound_secret", "true")
	if got := evalPreset(t, "review-only", req(t, "network.fetch", "read", "development", outbound)); got != "deny" {
		t.Errorf("review-only outbound secret: got %s want deny", got)
	}
	// Reviewing still fetches.
	if got := evalPreset(t, "review-only", req(t, "network.fetch", "read", "development", attr("egress", "true"))); got != "allow" {
		t.Errorf("review-only plain fetch: got %s want allow", got)
	}
}

// TestPresetsTolerateMissingGuardrailAttrs pins the compatibility property: a
// policy must not break when a caller does not emit the new attributes, since
// older adapters predate them.
func TestPresetsTolerateMissingGuardrailAttrs(t *testing.T) {
	legacy := map[string]string{"destructive": "false", "exfil": "false"}
	for _, name := range []string{"solo-dev-safe", "ci-agent", "review-only"} {
		got := evalPreset(t, name, req(t, "shell.read", "read", "development", legacy))
		if got != "allow" {
			t.Errorf("%s with legacy attrs: got %s want allow", name, got)
		}
	}
}
