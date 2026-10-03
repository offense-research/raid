# Raid x Pi

Gate the [Pi](https://pi.dev) coding agent's tool calls with Raid. Pi runs
extension events around tool calls; the community hook runners that reuse
Claude Code's hook protocol (`@fyeeme/pi-hooks`, `@hsingjui/pi-hooks`) read a
Claude Code-shaped `hooks` config and map `PreToolUse` to Pi's `tool_call`
event, which can block. `hook_gate.py` speaks that contract: it maps the call to
a normalized Raid action and answers with `permissionDecision: deny` (and exit 2)
when the verdict is `deny` or `require_approval`.

It reuses the shared `raidlib` normalization in `../lib/raidlib.py` — the same
classifier the Claude Code, Cursor, VS Code, Windsurf, Crush, OpenCode, and
OpenClaw adapters use — so the guardrail attributes behave identically across
agents.

## Wire it up

Pi's hooks are provided by an extension. Install a Claude Code protocol runner,
then point it at the Raid gate:

```sh
npm install -g @fyeeme/pi-hooks     # reads ~/.pi/agent/hook.json
```

Add this block to `~/.pi/agent/hook.json` (or the `hooks` block of your Pi
settings for `@hsingjui/pi-hooks`):

```jsonc
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "bash|edit|write|read|fetch|mcp_.*",
        "hooks": [
          { "type": "command", "command": "python3 /abs/path/raid/integrations/pi/hook_gate.py" }
        ]
      }
    ]
  }
}
```

A copy is in `settings.example.json`. Install the shim with
`integrations/pi/install.sh`.

> Alternative: the `pi-yaml-hooks` extension runs a `tool.before.*` bash action
> from `~/.pi/agent/hook/hooks.yaml` and blocks with exit 2. Point its `command`
> at the same `hook_gate.py`; this adapter's exit-2 path is compatible.

## Behavior

- `allow` -> prints no permission decision and exits 0, leaving Pi's own
  guardrails in force.
- `deny` -> `permissionDecision: "deny"` with the policy reason, exit 2.
- `require_approval` -> **denied with instructions**, not a Pi confirmation. An
  in-agent confirmation would authorize the action without a Raid receipt;
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
| `RAID_PROVIDER` / `RAID_AGENT` / `RAID_RUNTIME` | recorded caller | `pi` |

## Security invariants (unchanged from Raid)

- Deterministic policy runs first; a model is never the arbiter of authority.
- `deny` never calls a model and never creates an approval.
- Missing/broken policy, an unreachable daemon, or an adapter error all fail
  closed — never a silent allow.
- Approvals are single-use, Ed25519-signed, bound to the exact request hash.
