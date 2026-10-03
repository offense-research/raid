# Raid x omp (Oh My Pi)

Gate [omp](https://omp.sh)'s tool calls with Raid. omp (can1357/oh-my-pi) is a
terminal coding agent forked from Pi and shares Pi's extension event system, so
`hook_gate.py` speaks the same Claude Code-shaped hook contract as the Pi
adapter: it maps the call to a normalized Raid action and answers with
`permissionDecision: deny` (and exit 2) when the verdict is `deny` or
`require_approval`.

It reuses the shared `raidlib` normalization in `../lib/raidlib.py` — the same
classifier every other Raid agent adapter uses — so the guardrail attributes
behave identically across agents.

## Wire it up

omp's hooks come from an extension. The `pi-yaml-hooks` extension documents
both Pi and OMP and reads `~/.omp/agent/hook/hooks.yaml`:

```sh
npm install -g pi-yaml-hooks
```

```yaml
# ~/.omp/agent/hook/hooks.yaml
hooks:
  - id: raid-tool-gate
    event: tool.before.*
    action: bash
    command: python3 /abs/path/raid/integrations/omp/hook_gate.py
```

A JSON-shaped config for the Claude Code protocol runners is in
`settings.example.json`. Install the shim with `integrations/omp/install.sh`.

## Behavior

- `allow` -> prints no permission decision and exits 0, leaving omp's own
  guardrails in force.
- `deny` -> `permissionDecision: "deny"` with the policy reason, exit 2.
- `require_approval` -> **denied with instructions**, not an omp confirmation.
  An in-agent confirmation would authorize the action without a Raid receipt;
  keeping approval in Raid preserves the signed, single-use, request-bound
  evidence. A human approves out-of-band
  (`raid approval approve <id> --expected-version 0`) and the agent retries.
- Unreachable raidd or an adapter error -> **exit 2** (fail closed). A malformed
  payload -> exit 0 (fail open).

Administrative commands (`raid doctor`, `raid approval list`, …) are not gated.

## Environment

| var | meaning | default |
|---|---|---|
| `RAID_SOCKET` | raidd unix socket | `/run/offense/raid/raid.sock` |
| `RAID_ENV` | classified `resource.environment` | `development` |
| `RAID_PROVIDER` / `RAID_AGENT` / `RAID_RUNTIME` | recorded caller | `omp` |

## Security invariants (unchanged from Raid)

- Deterministic policy runs first; a model is never the arbiter of authority.
- `deny` never calls a model and never creates an approval.
- Missing/broken policy, an unreachable daemon, or an adapter error all fail
  closed — never a silent allow.
- Approvals are single-use, Ed25519-signed, bound to the exact request hash.
