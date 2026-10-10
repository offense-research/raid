package policy_test

import (
	"testing"
)

// End-to-end tests for the intermediary / router countermeasures
// (arXiv:2604.08407, "Your Agent Is Mine").
//
// internal/raider/integrity_test.go (Raider) and core/integrity/integrity_test.go
// (Raid) test the classifiers in isolation. These run the whole way through the
// real thing: a preset is compiled exactly as raidd compiles it at activation,
// and a request carrying the attribute set an adapter actually stamps is
// evaluated by the real CEL evaluator. That is the only place the two halves
// meet, and it is what a user's install depends on.
//
// The attributes below are the ones a client stamps on resource.attributes.
// Every helper used here (req, evalPreset) comes from presets_test.go.

// clean is a request with none of the integrity keys present at all. Policies
// guard every integrity condition with has(), so a request from an adapter that
// does no provenance work must be evaluated as if the rules were not there.
var clean = map[string]string{}

func TestInjectedCallIsDeniedOutright(t *testing.T) {
	// An injected call is one matching no call the provider declared. It is not
	// approvable: there is no reading of "run this call the model never asked
	// for" that a single keystroke should wave through, so every preset that
	// covers the operation denies it.
	cases := []struct {
		name      string
		preset    string
		operation string
		effect    string
		baseline  string
	}{
		{"solo-dev-safe write", "solo-dev-safe", "filesystem.write", "write", "allow"},
		{"solo-dev-safe exec", "solo-dev-safe", "shell.execute", "execute", ""},
		{"solo-dev-safe read", "solo-dev-safe", "shell.read", "read", ""},
		{"review-only read", "review-only", "shell.read", "read", "allow"},
		{"ci-agent exec", "ci-agent", "shell.execute", "execute", "allow"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := evalPreset(t, tc.preset, req(t, tc.operation, tc.effect, "development", clean))
			if tc.baseline != "" && base != tc.baseline {
				t.Fatalf("%s baseline for %s: got %s want %s", tc.preset, tc.operation, base, tc.baseline)
			}
			got := evalPreset(t, tc.preset, req(t, tc.operation, tc.effect, "development",
				map[string]string{"injected_call": "true"}))
			if got != "deny" {
				t.Errorf("%s: injected %s: got %s want deny", tc.preset, tc.operation, got)
			}
		})
	}
}

func TestRewrittenArgumentsAreDeniedOutright(t *testing.T) {
	// AC-1: the hop rewrote the arguments in flight. Same tool, same call id,
	// different payload.
	cases := []struct {
		name      string
		preset    string
		operation string
		effect    string
		baseline  string
	}{
		{"solo-dev-safe write", "solo-dev-safe", "filesystem.write", "write", "allow"},
		{"solo-dev-safe push", "solo-dev-safe", "git.push", "write", "allow"},
		{"review-only fetch", "review-only", "network.fetch", "read", ""},
		{"ci-agent exec", "ci-agent", "shell.execute", "execute", "allow"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := evalPreset(t, tc.preset, req(t, tc.operation, tc.effect, "development", clean))
			if tc.baseline != "" && base != tc.baseline {
				t.Fatalf("%s baseline for %s: got %s want %s", tc.preset, tc.operation, base, tc.baseline)
			}
			got := evalPreset(t, tc.preset, req(t, tc.operation, tc.effect, "development",
				map[string]string{"tool_args_unverified": "true"}))
			if got != "deny" {
				t.Errorf("%s: rewritten %s: got %s want deny", tc.preset, tc.operation, got)
			}
		})
	}
}

func TestRouterRewrittenInstallIsDenied(t *testing.T) {
	// AC-1.a: a typosquat substituted into a dependency name. A domain allowlist
	// cannot see this - the host is the registry the user already trusts - which
	// is exactly why it needs its own rule. package.install is the only
	// operation the rule covers, and it is a flat deny in both presets.
	for _, preset := range []string{"solo-dev-safe", "ci-agent"} {
		t.Run(preset, func(t *testing.T) {
			got := evalPreset(t, preset, req(t, "package.install", "write", "development",
				map[string]string{"router_untrusted": "true"}))
			if got != "deny" {
				t.Errorf("%s: install via an untrusted router: got %s want deny", preset, got)
			}
		})
	}
}

func TestInstallThroughAMereRouterIsDeniedOnCIAgent(t *testing.T) {
	// A response that merely passed through an unrecognised hop (router_untrusted
	// false: the client did not have that host flagged) still came from software
	// the client cannot tie to the provider. An install is where that is least
	// recoverable, so ci-agent denies it; solo-dev-safe stops for a human because
	// a pin that was never configured must not silently become a permanent deny.
	got := evalPreset(t, "ci-agent", req(t, "package.install", "write", "development",
		map[string]string{"intermediary": "true"}))
	if got != "deny" {
		t.Errorf("ci-agent: install through an intermediary: got %s want deny", got)
	}

	got = evalPreset(t, "solo-dev-safe", req(t, "package.install", "write", "development",
		map[string]string{"intermediary": "true"}))
	if got != "require_approval" {
		t.Errorf("solo-dev-safe: install through an intermediary: got %s want require_approval", got)
	}
}

func TestSuspectProvenanceStopsForAHumanInSoloDevSafe(t *testing.T) {
	// A consequential action governed by a response that could not be tied to
	// the provider is a judgement call, not an obvious attack: the answer is a
	// human, and only in the preset that assumes one is watching.
	cases := []struct {
		name      string
		operation string
		effect    string
		attrs     map[string]string
	}{
		{"via a router", "filesystem.write", "write", map[string]string{"intermediary": "true"}},
		{"named a different model", "git.push", "write", map[string]string{"model_mismatch": "true"}},
		{"out of declared order", "filesystem.write", "write", map[string]string{"sequence_anomaly": "true"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := evalPreset(t, "solo-dev-safe", req(t, tc.operation, tc.effect, "development", clean))
			if base != "allow" {
				t.Fatalf("baseline for %s: got %s want allow", tc.operation, base)
			}
			got := evalPreset(t, "solo-dev-safe", req(t, tc.operation, tc.effect, "development", tc.attrs))
			if got != "require_approval" {
				t.Errorf("%s: got %s want require_approval", tc.operation, got)
			}
		})
	}
}

func TestCIAgentDeniesSuspectProvenanceAndOrder(t *testing.T) {
	// The unattended preset has nobody to ask, so the same signals deny.
	cases := []struct {
		name  string
		attrs map[string]string
	}{
		{"via a router", map[string]string{"intermediary": "true"}},
		{"named a different model", map[string]string{"model_mismatch": "true"}},
		{"out of declared order", map[string]string{"sequence_anomaly": "true"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := evalPreset(t, "ci-agent", req(t, "shell.execute", "execute", "development", tc.attrs))
			if got != "deny" {
				t.Errorf("ci-agent %s: got %s want deny", tc.name, got)
			}
		})
	}
}

func TestDefaultInstallStaysQuietOnUnattestedResponses(t *testing.T) {
	// The load-bearing property for anyone who upgrades: provider_unattested is
	// true on every install that has not configured provenance pins, and it must
	// not prompt or block anything. If this regressed, every tool call on every
	// default install would ask a human.
	for _, tc := range []struct {
		preset    string
		operation string
		effect    string
	}{
		{"solo-dev-safe", "filesystem.write", "write"},
		{"solo-dev-safe", "git.push", "write"},
		{"ci-agent", "shell.execute", "execute"},
	} {
		t.Run(tc.preset+"/"+tc.operation, func(t *testing.T) {
			got := evalPreset(t, tc.preset, req(t, tc.operation, tc.effect, "development",
				map[string]string{"provider_unattested": "true"}))
			if got != "allow" {
				t.Errorf("%s: unattested %s: got %s want allow", tc.preset, tc.operation, got)
			}
		})
	}
}

func TestUnflaggedCallIsUnaffected(t *testing.T) {
	// The same request with the full attribute set present but false - what a
	// client that checked and found nothing wrong actually sends - must behave
	// exactly like a request carrying no integrity keys at all.
	cleanResult := evalPreset(t, "solo-dev-safe", req(t, "filesystem.write", "write", "development", clean))
	flaggedFalse := map[string]string{
		"provider_verified":    "false",
		"provider_unattested":  "false",
		"model_mismatch":       "false",
		"intermediary":         "false",
		"router_untrusted":     "false",
		"injected_call":        "false",
		"tool_args_unverified": "false",
		"sequence_anomaly":     "false",
	}
	got := evalPreset(t, "solo-dev-safe", req(t, "filesystem.write", "write", "development", flaggedFalse))
	if got != cleanResult {
		t.Errorf("present-but-false attributes changed the outcome: got %s want %s", got, cleanResult)
	}
	if got != "allow" {
		t.Errorf("ordinary development write: got %s want allow", got)
	}
}

func TestIntegritySignalsNeverLoosenAPolicy(t *testing.T) {
	// Monotonicity: whatever the flags say, the result is never more permissive
	// than the same request without them. This is the property that keeps these
	// rules from becoming a bypass.
	rank := map[string]int{"allow": 1, "require_approval": 2, "deny": 3}
	cases := []struct {
		preset    string
		operation string
		effect    string
		attrs     map[string]string
	}{
		{"solo-dev-safe", "filesystem.write", "write", map[string]string{"injected_call": "true"}},
		{"solo-dev-safe", "filesystem.write", "write", map[string]string{"tool_args_unverified": "true"}},
		{"solo-dev-safe", "filesystem.write", "write", map[string]string{"intermediary": "true"}},
		{"solo-dev-safe", "filesystem.write", "write", map[string]string{"sequence_anomaly": "true"}},
		{"solo-dev-safe", "package.install", "write", map[string]string{"router_untrusted": "true"}},
		{"review-only", "shell.read", "read", map[string]string{"injected_call": "true"}},
		{"ci-agent", "shell.execute", "execute", map[string]string{"model_mismatch": "true"}},
		{"ci-agent", "package.install", "write", map[string]string{"router_untrusted": "true"}},
	}
	for _, tc := range cases {
		name := tc.preset + "/" + tc.operation
		t.Run(name, func(t *testing.T) {
			base := evalPreset(t, tc.preset, req(t, tc.operation, tc.effect, "development", clean))
			got := evalPreset(t, tc.preset, req(t, tc.operation, tc.effect, "development", tc.attrs))
			if rank[got] < rank[base] {
				t.Errorf("%s: flagged result %s is looser than the clean baseline %s", name, got, base)
			}
		})
	}
}
