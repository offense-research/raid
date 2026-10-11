package policy_test

import (
	"strings"
	"testing"

	"github.com/offense-research/raid/core/canonical"
	"github.com/offense-research/raid/core/policy"
)

// TestEveryShippedAgentIsCoveredByEveryPreset pins the property that has now
// broken twice.
//
// Every rule in all three presets was scoped `providers: [claude-code]`. Because
// `defaults.effect` is deny, an adapter that stamps its own provider matched no
// rule at all, so EVERY action was blocked - including a benign read. The same
// class of bug reappeared as an omission: the lists were widened to the twelve
// CLI agents but not to `raider`, so a preset activated under Raider still
// denied every call.
//
// The list below is every provider Raid ships an adapter for or is embedded by.
// Each must be able to do ordinary, in-scope work under every preset; a preset
// that does not name a provider turns its guardrail into an outage for that
// agent, which is exactly the failure this test exists to catch.
var shippedAgents = []string{
	"claude-code", "codex", "aider", "opencode", "openclaw", "vscode",
	"windsurf", "crush", "cursor", "hermes", "pi", "omp", "raider",
}

// reqAs mirrors req (presets_test.go) but stamps the caller's own provider, the
// way a non-Claude-Code adapter does.
func reqAs(t *testing.T, provider, operation, effectClass string, attrs map[string]string) *canonical.ActionRequest {
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
		"principal": {"subject_id":"dev","agent_id":"` + provider + `","session_id":"ses_1","runtime":"` + provider + `","groups":[],"trust_level":"local-session","revision":1},
		"action": {"provider":"` + provider + `","operation":"` + operation + `","effect":"` + effectClass + `"},
		"resource": {"type":"shell","id":".","environment":"development","attributes":` + ab.String() + `},
		"arguments": {},
		"context": {"source_product":"` + provider + `","source_request_id":"t:1","interactive":true}
	}`
	r, perr := canonical.DecodeRequest([]byte(js))
	if perr != nil {
		t.Fatalf("decode request for %s: %v", provider, perr.Message())
	}
	return r
}

func TestEveryShippedAgentIsCoveredByEveryPreset(t *testing.T) {
	benign := attr()

	for _, preset := range policy.PresetNames() {
		for _, agent := range shippedAgents {
			// An ordinary in-scope read. Every preset in the box allows this;
			// if the preset does not name the provider, deny-by-default fires
			// and the agent cannot do anything at all.
			got := evalPreset(t, preset, reqAs(t, agent, "shell.read", "read", benign))
			if got != "allow" {
				t.Errorf("preset %s does not cover provider %s: a benign read got %s, want allow "+
					"(the rule lists need to name %q)", preset, agent, got, agent)
			}
		}
	}
}

// TestEveryShippedAgentCanWorkUnderSoloDevSafe is the stronger form of the same
// property: not just that reads pass, but that the ordinary development work
// solo-dev-safe exists to permit is permitted for every agent. A preset that
// allows only reads would still be unusable.
func TestEveryShippedAgentCanWorkUnderSoloDevSafe(t *testing.T) {
	benign := attr()

	for _, agent := range shippedAgents {
		for _, tc := range []struct{ op, fx string }{
			{"shell.read", "read"},
			{"filesystem.write", "write"},
			{"shell.write", "write"},
			{"git.push", "write"},
		} {
			got := evalPreset(t, "solo-dev-safe", reqAs(t, agent, tc.op, tc.fx, benign))
			if got != "allow" {
				t.Errorf("provider %s cannot do in-scope %s under solo-dev-safe: got %s, want allow",
					agent, tc.op, got)
			}
		}
	}
}
