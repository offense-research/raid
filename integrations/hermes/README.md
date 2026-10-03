# Raid x Hermes

Gate [Hermes](https://hermes-agent.nousresearch.com)'s tool calls with Raid.
Hermes guardrails are plugins, not a hook config file: `plugin/` is a native
Hermes plugin that registers a `pre_tool_call` hook, maps the call to a
normalized Raid action, and returns `{"action": "block", "message": ...}` when
the verdict is `deny` or `require_approval`.

It reuses the shared `raidlib` normalization in `../lib/raidlib.py` — the same
classifier the Claude Code, Cursor, VS Code, Windsurf, Crush, OpenCode, and
OpenClaw adapters use — so the `destructive` / `exfil` / `protected_branch`
guardrail attributes behave identically across agents.

## Wire it up

```sh
integrations/hermes/install.sh
```

This copies the plugin to `~/.hermes/plugins/raid-guard/`. Enable it by adding
`raid-guard` to `plugins.enabled` in the Hermes config, then validate:

```sh
hermes plugins validate raid-guard
hermes plugins doctor raid-guard
```

## Files

```text
plugin/
  plugin.yaml    # native Hermes manifest (name, version, provides_hooks)
  __init__.py    # register(ctx) -> ctx.register_hook("pre_tool_call", ...)
```

## Behavior

- `allow` -> the hook returns `None` (no objection), leaving Hermes' own
  guardrails and approval surfaces in force.
- `deny` -> `{"action": "block", "message": "<policy reason>"}`.
- `require_approval` -> **blocked with instructions**, deliberately NOT Hermes'
  `approve` directive. An in-agent approval prompt would authorize the action
  without a Raid receipt; keeping approval in Raid preserves the signed,
  single-use, request-bound evidence. A human approves out-of-band
  (`raid approval approve <id> --expected-version 0`) and the agent retries.
- raidd unreachable or an adapter error -> **blocked** (fail closed).

Administrative commands (`raid doctor`, `raid approval list`, `raidd --version`,
…) are not gated, so you cannot lock yourself out of managing Raid.

## Environment

| var | meaning | default |
|---|---|---|
| `RAID_SOCKET` | raidd unix socket | `/run/offense/raid/raid.sock` |
| `RAID_ENV` | classified `resource.environment` | `development` |
| `RAID_PROVIDER` | provider recorded in the action | `hermes` |
| `RAID_LIB_DIR` | directory holding `raidlib.py` | `../../lib` |

If `raidlib` cannot be imported at all, the hook stays inert rather than
blocking every tool call — point `RAID_LIB_DIR` at `integrations/lib`.

## Security invariants (unchanged from Raid)

- Deterministic policy runs first; a model is never the arbiter of authority.
- `deny` never calls a model and never creates an approval.
- Missing/broken policy, an unreachable daemon, or an adapter error all fail
  closed — never a silent allow.
- Approvals are single-use, Ed25519-signed, bound to the exact request hash.
