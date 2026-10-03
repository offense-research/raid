# Raid x Windsurf

Gate Windsurf's Cascade agent actions with Raid. Windsurf runs configured hooks
around agent actions; `hook_gate.py` maps the action to a normalized Raid
action and exits with status 2 to block when the verdict is `deny` or
`require_approval`.

This adapter reuses the shared `raidlib` normalization in `../lib/raidlib.py`
(the same classifier the Cursor and Claude Code adapters use), so the
`destructive` / `exfil` / `protected_branch` guardrail attributes behave
identically across agents.

## Wire it up

Hooks live in `~/.codeium/windsurf/hooks.json`:

```jsonc
{
  "hooks": {
    "pre_run_command": [
      { "command": "python3 /abs/path/raid/integrations/windsurf/hook_gate.py", "show_output": true }
    ],
    "pre_write_code": [
      { "command": "python3 /abs/path/raid/integrations/windsurf/hook_gate.py", "show_output": true }
    ],
    "pre_read_code": [
      { "command": "python3 /abs/path/raid/integrations/windsurf/hook_gate.py", "show_output": true }
    ],
    "pre_mcp_tool_use": [
      { "command": "python3 /abs/path/raid/integrations/windsurf/hook_gate.py", "show_output": true }
    ]
  }
}
```

A copy is in `hooks.example.json`. Only the `pre_*` events gate; `post_*` events
are observational and the adapter always allows them.

## Environment

| var | meaning | default |
|---|---|---|
| `RAID_SOCKET` | raidd unix socket | `/run/offense/raid/raid.sock` |
| `RAID_ENV` | classified `resource.environment` | `development` |
| `RAID_PROVIDER` | provider recorded in the action | `claude-code` (set `windsurf`) |
| `RAID_SUBJECT` / `RAID_AGENT` | principal | `$USER` / `claude-code` |
| `RAID_STATE_DIR` | base dir for a `--solo` deployment | `~/.local/state/offense/raid` |

For an accurate audit trail, set `RAID_PROVIDER=windsurf` (and `RAID_AGENT`) in
the hook's environment.

Run a solo daemon with the deny-first preset (no root, self-approval):

```sh
./raidd --solo &
export RAID_SOCKET="${XDG_STATE_HOME:-$HOME/.local/state}/offense/raid/raid.sock"
./raid log      # what did the agent do?
./raid grants   # active scoped confirmations
```

## Behavior

- `allow` -> exit 0 (the action proceeds).
- `deny` -> exit 2 with the policy reason code, shown in Cascade.
- `require_approval` -> **exit 2 with instructions**, not a Cascade confirmation
  prompt. An in-editor confirmation would authorize the action without a Raid
  receipt; keeping approval in Raid preserves the signed, single-use,
  request-bound evidence. A human approves out-of-band
  (`raid approval approve <id> --expected-version 0`) and the agent retries — a
  retry of a *different* command fails verification.
- Unreachable raidd or an adapter error -> **exit 2** (fail closed). A malformed
  payload -> exit 0 (fail open, so a bad input never takes down Cascade).

## Security invariants (unchanged from Raid)

- Deterministic policy runs first; a model is never the arbiter of authority.
- `deny` never calls a model and never creates an approval.
- Missing/broken policy, an unreachable daemon, or an adapter error all fail
  closed — never a silent allow.
- Approvals are single-use, Ed25519-signed, bound to the exact request hash.
