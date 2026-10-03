# Raid x Charm Crush

Gate [Crush](https://github.com/charmbracelet/crush)'s tool calls with Raid.
Crush runs user-defined hooks around tool calls; `hook_gate.py` maps the call to
a normalized Raid action and blocks with exit status 2 when the verdict is
`deny` or `require_approval`.

This adapter reuses the shared `raidlib` normalization in `../lib/raidlib.py`
(the same classifier the Claude Code, Cursor, VS Code, and Windsurf adapters
use), so the `destructive` / `exfil` / `protected_branch` guardrail attributes
behave identically across agents.

## Wire it up

Add a `PreToolUse` hook to your project `.crush.json` (or, globally,
`~/.config/crush/crush.json`):

```jsonc
{
  "hooks": {
    "PreToolUse": [
      {
        "name": "raid-gate",
        "matcher": "^(bash|edit|write|read|fetch|mcp_.*)$",
        "command": "python3 /abs/path/raid/integrations/crush/hook_gate.py",
        "timeout": 30
      }
    ]
  }
}
```

A copy is in `crush.json.example`. Relative command paths resolve against your
working directory, so a **global** config needs an absolute path or an inline
command. Install the shim and write the block with:

```sh
integrations/crush/install.sh --write-config
```

## Environment

| var | meaning | default |
|---|---|---|
| `RAID_SOCKET` | raidd unix socket | `/run/offense/raid/raid.sock` |
| `RAID_ENV` | classified `resource.environment` | `development` |
| `RAID_PROVIDER` | provider recorded in the action | `crush` (set by the hook) |
| `RAID_AGENT` / `RAID_RUNTIME` | principal / runtime | `crush` |

Crush exports the call as JSON on stdin (`tool_name`, `tool_input`, `cwd`) and
as env vars (`CRUSH_TOOL_NAME`, `CRUSH_TOOL_INPUT_COMMAND`,
`CRUSH_TOOL_INPUT_FILE_PATH`, `CRUSH_CWD`); the hook reads either.

Run a solo daemon with the deny-first preset (no root, self-approval):

```sh
./raidd --solo &
export RAID_SOCKET="${XDG_STATE_HOME:-$HOME/.local/state}/offense/raid/raid.sock"
./raid log      # what did the agent do?
./raid grants   # active scoped confirmations
```

## Behavior

- `allow` -> exit 0, no output. The hook leaves Crush's own permission flow in
  force rather than pre-approving the call.
- `deny` -> exit 2 with the policy reason code (shown to the user).
- `require_approval` -> **exit 2 with instructions**, not a Crush confirmation
  prompt. An in-agent confirmation would authorize the action without a Raid
  receipt; keeping approval in Raid preserves the signed, single-use,
  request-bound evidence. A human approves out-of-band
  (`raid approval approve <id> --expected-version 0`) and the agent retries — a
  retry of a *different* command fails verification.
- Unreachable raidd or an adapter error -> **exit 2** (fail closed). A malformed
  payload -> exit 0 (fail open, so a bad input never takes down Crush).

Administrative commands (`raid doctor`, `raid approval list`, `raidd --version`,
…) are not gated, so you cannot lock yourself out of managing Raid.

## Security invariants (unchanged from Raid)

- Deterministic policy runs first; a model is never the arbiter of authority.
- `deny` never calls a model and never creates an approval.
- Missing/broken policy, an unreachable daemon, or an adapter error all fail
  closed — never a silent allow.
- Approvals are single-use, Ed25519-signed, bound to the exact request hash.
