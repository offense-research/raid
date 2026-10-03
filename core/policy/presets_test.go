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
