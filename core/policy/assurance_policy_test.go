package policy_test

import (
	"testing"
)

// End-to-end tests for the four agent-assurance classes
// (arXiv:2608.01558 trajectory assurance, 2606.10749 threat surfaces,
// 2608.10530 action-layer vulnerabilities).
//
// core/integrity/assurance_test.go tests the verifiers in isolation. These run
// the whole way through the real engine: each preset is compiled exactly as
// raidd compiles it at activation, and a request carrying the attribute set an
// adapter stamps is evaluated by the real CEL evaluator. Helpers req and
// evalPreset come from presets_test.go.

// allFalse is every assurance attribute present but false. A policy that
// reacted to a present-but-false attribute would make an adapter that stamps
// defaults behave differently from one that stamps nothing; both must be
// identical to the clean baseline.
var allFalse = map[string]string{
	"trajectory_tracked": "false", "trajectory_attested": "false",
	"trajectory_drift": "false", "trajectory_unplanned": "false",
	"trajectory_quota_exceeded": "false",
	"tool_schema_attested":      "false", "tool_schema_mutated": "false",
	"hidden_tool_injected": "false", "boundary_tampered": "false",
	"stream_audited": "false", "stream_prefix_mismatch": "false",
	"stream_suffix_injected": "false", "response_delta": "false",
	"confinement_tracked": "false", "confined": "false",
	"confinement_escape": "false", "confinement_widened": "false",
	"env_escape": "false",
}

func one(k, v string) map[string]string { return map[string]string{k: v} }

// baseline is the verdict with no assurance attributes at all, so a test can
// prove the rule fires on the signal rather than on the operation.
func baseline(t *testing.T, preset, op, effect string) string {
	t.Helper()
	return evalPreset(t, preset, req(t, op, effect, "development", clean))
}

func TestAssuranceFalseAttributesChangeNothing(t *testing.T) {
	// solo-dev-safe allows ordinary development work. Stamping the whole
	// assurance set as false must not move any of it.
	cases := []struct {
		op, effect string
	}{
		{"filesystem.read", "read"},
		{"filesystem.write", "write"},
		{"shell.execute", "execute"},
		{"git.push", "write"},
	}
	for _, tc := range cases {
		t.Run(tc.op, func(t *testing.T) {
			want := evalPreset(t, "solo-dev-safe", req(t, tc.op, tc.effect, "development", clean))
			got := evalPreset(t, "solo-dev-safe", req(t, tc.op, tc.effect, "development", allFalse))
			if got != want {
				t.Errorf("%s: all-false assurance attrs moved verdict from %s to %s", tc.op, want, got)
			}
		})
	}
}

func TestSchemaTamperDeniedInEveryPreset(t *testing.T) {
	// A mutated tool schema, an injected tool, or a tampered boundary means the
	// call is not the call it appears to be. Not approvable anywhere - including
	// on a read in review-only, because a rewritten read is how a review pass is
	// made to carry something out.
	signals := []string{"tool_schema_mutated", "hidden_tool_injected", "boundary_tampered"}
	cases := []struct {
		preset, op, effect string
	}{
		{"solo-dev-safe", "filesystem.write", "write"},
		{"solo-dev-safe", "shell.read", "read"},
		{"review-only", "shell.read", "read"},
		{"ci-agent", "shell.execute", "execute"},
	}
	for _, sig := range signals {
		for _, tc := range cases {
			t.Run(sig+"/"+tc.preset+"/"+tc.op, func(t *testing.T) {
				got := evalPreset(t, tc.preset, req(t, tc.op, tc.effect, "development", one(sig, "true")))
				if got != "deny" {
					t.Errorf("%s: %s on %s: got %s want deny", tc.preset, sig, tc.op, got)
				}
			})
		}
	}
}

func TestResponseTamperDeniedInEveryPreset(t *testing.T) {
	// A completion rewritten between the transport and the client, or content
	// appended after the declared stop: token manipulation in transit.
	signals := []string{"response_delta", "stream_suffix_injected"}
	cases := []struct {
		preset, op, effect string
	}{
		{"solo-dev-safe", "filesystem.write", "write"},
		{"solo-dev-safe", "shell.read", "read"},
		{"review-only", "network.fetch", "read"},
		{"ci-agent", "shell.read", "read"},
	}
	for _, sig := range signals {
		for _, tc := range cases {
			t.Run(sig+"/"+tc.preset+"/"+tc.op, func(t *testing.T) {
				got := evalPreset(t, tc.preset, req(t, tc.op, tc.effect, "development", one(sig, "true")))
				if got != "deny" {
					t.Errorf("%s: %s on %s: got %s want deny", tc.preset, sig, tc.op, got)
				}
			})
		}
	}
}

func TestTrajectoryQuotaBreachDeniedEverywhere(t *testing.T) {
	// The cumulative trajectory broke a declared invariant. Each step looked
	// benign; the trajectory did not.
	cases := []struct {
		preset, op, effect string
	}{
		{"solo-dev-safe", "filesystem.write", "write"},
		{"solo-dev-safe", "shell.read", "read"},
		{"review-only", "filesystem.read", "read"},
		{"ci-agent", "filesystem.write", "write"},
	}
	for _, tc := range cases {
		t.Run(tc.preset+"/"+tc.op, func(t *testing.T) {
			got := evalPreset(t, tc.preset, req(t, tc.op, tc.effect, "development", one("trajectory_quota_exceeded", "true")))
			if got != "deny" {
				t.Errorf("%s: quota breach on %s: got %s want deny", tc.preset, tc.op, got)
			}
		})
	}
}

func TestTrajectoryDriftConfirmsForAHumanOnlyInSoloDev(t *testing.T) {
	// Leaving the declared plan is a judgement call, not an obvious attack: a
	// human in solo-dev-safe, a flat deny in a pipeline that has nobody to ask.
	for _, sig := range []string{"trajectory_drift", "trajectory_unplanned"} {
		got := evalPreset(t, "solo-dev-safe", req(t, "filesystem.write", "write", "development", one(sig, "true")))
		if got != "require_approval" {
			t.Errorf("solo-dev-safe: %s: got %s want require_approval", sig, got)
		}
		got = evalPreset(t, "ci-agent", req(t, "filesystem.write", "write", "development", one(sig, "true")))
		if got != "deny" {
			t.Errorf("ci-agent: %s: got %s want deny", sig, got)
		}
	}
}

func TestConfinementWidenedDeniedEverywhere(t *testing.T) {
	// A sub-invocation asking for a broader scope than its parent's is privilege
	// escalation by construction.
	cases := []struct {
		preset, op, effect string
	}{
		{"solo-dev-safe", "container.exec", "execute"},
		{"solo-dev-safe", "shell.read", "read"},
		{"ci-agent", "filesystem.write", "write"},
	}
	for _, tc := range cases {
		t.Run(tc.preset+"/"+tc.op, func(t *testing.T) {
			got := evalPreset(t, tc.preset, req(t, tc.op, tc.effect, "development", one("confinement_widened", "true")))
			if got != "deny" {
				t.Errorf("%s: widened scope on %s: got %s want deny", tc.preset, tc.op, got)
			}
		})
	}
}

func TestConfinementEscapeConfirmsForAHumanOnlyInSoloDev(t *testing.T) {
	for _, sig := range []string{"confinement_escape", "env_escape"} {
		got := evalPreset(t, "solo-dev-safe", req(t, "shell.execute", "execute", "development", one(sig, "true")))
		if got != "require_approval" {
			t.Errorf("solo-dev-safe: %s: got %s want require_approval", sig, got)
		}
		got = evalPreset(t, "ci-agent", req(t, "shell.execute", "execute", "development", one(sig, "true")))
		if got != "deny" {
			t.Errorf("ci-agent: %s: got %s want deny", sig, got)
		}
	}
}

func TestStreamPrefixMismatchConfirmsForAHumanOnlyInSoloDev(t *testing.T) {
	got := evalPreset(t, "solo-dev-safe", req(t, "filesystem.write", "write", "development", one("stream_prefix_mismatch", "true")))
	if got != "require_approval" {
		t.Errorf("solo-dev-safe: prefix mismatch: got %s want require_approval", got)
	}
	got = evalPreset(t, "ci-agent", req(t, "filesystem.write", "write", "development", one("stream_prefix_mismatch", "true")))
	if got != "deny" {
		t.Errorf("ci-agent: prefix mismatch: got %s want deny", got)
	}
}

func TestAssuranceDenySignalsAreMonotonic(t *testing.T) {
	// Signals a preset denies outright must tighten every operation that preset
	// covers, including a plain read: a tampered schema, a rewritten completion,
	// or a breached quota means the call is not the call it appears to be.
	signals := []string{
		"tool_schema_mutated", "hidden_tool_injected", "boundary_tampered",
		"response_delta", "stream_suffix_injected", "trajectory_quota_exceeded",
	}
	cases := []struct {
		preset, op, effect string
	}{
		{"solo-dev-safe", "filesystem.write", "write"},
		{"solo-dev-safe", "filesystem.read", "read"},
		{"solo-dev-safe", "git.push", "write"},
		{"review-only", "filesystem.read", "read"},
		{"ci-agent", "shell.execute", "execute"},
		{"ci-agent", "filesystem.read", "read"},
	}
	for _, tc := range cases {
		base := baseline(t, tc.preset, tc.op, tc.effect)
		if base != "allow" {
			t.Fatalf("%s: %s baseline is %s, expected allow for this monotonicity check", tc.preset, tc.op, base)
		}
		for _, sig := range signals {
			got := evalPreset(t, tc.preset, req(t, tc.op, tc.effect, "development", one(sig, "true")))
			if got == "allow" {
				t.Errorf("%s: %s on %s did not tighten an allowed call (base allow, got allow)", tc.preset, sig, tc.op)
			}
		}
	}
}

func TestAssuranceWidenedScopeIsDeniedNotConfirmed(t *testing.T) {
	// Widening is escalation by construction, so it is denied rather than offered
	// for approval -- on a read as well, because the widened scope is what the
	// next call inherits.
	for _, tc := range []struct{ preset, op, effect string }{
		{"solo-dev-safe", "filesystem.read", "read"},
		{"solo-dev-safe", "container.exec", "execute"},
		{"ci-agent", "filesystem.write", "write"},
	} {
		t.Run(tc.preset+"/"+tc.op, func(t *testing.T) {
			got := evalPreset(t, tc.preset, req(t, tc.op, tc.effect, "development", one("confinement_widened", "true")))
			if got != "deny" {
				t.Errorf("%s: widened scope on %s: got %s want deny", tc.preset, tc.op, got)
			}
		})
	}
}

func TestAssuranceConfirmSignalsTightenPrivilegedOpsOnly(t *testing.T) {
	// The judgement-call signals are confirmed for a human on a state-changing
	// call: leaving the declared plan or acting outside the confinement scope is
	// suspicious but not an obvious attack. A read after the session drifted is
	// not consequential, and flagging it would train the operator to approve
	// without reading -- so a read stays allow on those signals, by design.
	for _, sig := range []string{"trajectory_drift", "trajectory_unplanned", "confinement_escape", "env_escape"} {
		got := evalPreset(t, "solo-dev-safe", req(t, "filesystem.write", "write", "development", one(sig, "true")))
		if got != "require_approval" {
			t.Errorf("solo-dev-safe: %s on a write: got %s want require_approval", sig, got)
		}
		got = evalPreset(t, "solo-dev-safe", req(t, "filesystem.read", "read", "development", one(sig, "true")))
		if got != "allow" {
			t.Errorf("solo-dev-safe: %s on a read: got %s want allow (a read is not consequential)", sig, got)
		}
		got = evalPreset(t, "ci-agent", req(t, "filesystem.write", "write", "development", one(sig, "true")))
		if got != "deny" {
			t.Errorf("ci-agent: %s on a write: got %s want deny", sig, got)
		}
	}

	// Prefix mismatch is a whole-response signal, so it covers reads too.
	got := evalPreset(t, "solo-dev-safe", req(t, "filesystem.read", "read", "development", one("stream_prefix_mismatch", "true")))
	if got != "require_approval" {
		t.Errorf("solo-dev-safe: prefix mismatch on a read: got %s want require_approval", got)
	}
}

func TestAssuranceLegacyAdapterUnaffected(t *testing.T) {
	// An adapter that emits none of these attributes must evaluate exactly as it
	// did before the rules existed.
	for _, preset := range []string{"solo-dev-safe", "review-only", "ci-agent"} {
		got := evalPreset(t, preset, req(t, "filesystem.read", "read", "development", clean))
		if got != "allow" {
			t.Errorf("%s: a legacy adapter's read is %s, want allow", preset, got)
		}
	}
}
