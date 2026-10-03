# Raid × Cursor

Gate Cursor's agent tool calls with Raid. Cursor runs configured hooks before
a tool executes; `hook_gate.py` maps the call to a normalized Raid action and
answers with Cursor's permission object, so a `deny` or `require_approval`
verdict blocks the call.

This adapter reuses the shared `raidlib` normalization in `../lib/raidlib.py`
(the same one the Claude Code adapter uses), so the classifier and the
`destructive` / `exfil` / `protected_branch` guardrail attributes behave
identically across agents.

## Wire it up

Hooks (`~/.cursor/hooks.json`, or `.cursor/hooks.json` for a project):

```jsonc
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      { "command": "python3 /abs/path/raid/integrations/cursor/hook_gate.py", "failClosed": true }
    ],
    "preToolUse": [
      { "command": "python3 /abs/path/raid/integrations/cursor/hook_gate.py", "failClosed": true }
    ],
    "beforeReadFile": [
      { "command": "python3 /abs/path/raid/integrations/cursor/hook_gate.py", "failClosed": true }
    ],
    "beforeMCPExecution": [
      { "command": "python3 /abs/path/raid/integrations/cursor/hook_gate.py", "failClosed": true }
    ]
  }
}
```

`failClosed: true` ensures a crashing hook blocks rather than silently allows.
A copy is in `hooks.example.json`.

MCP (`~/.cursor/mcp.json`, or `.cursor/mcp.json`) — the shared Raid MCP server,
so the agent can also ask before acting (`raid_check`, `raid_pending`):

```jsonc
{
  "mcpServers": {
    "raid": {
      "command": "python3",
      "args": ["/abs/path/raid/integrations/claude-code/mcp_server.py"],
      "env": { "RAID_SOCKET": "/home/you/.local/state/offense/raid/raid.sock" }
    }
  }
}
```

## Environment

| var | meaning | default |
|---|---|---|
| `RAID_SOCKET` | raidd unix socket | `/run/offense/raid/raid.sock` |
| `RAID_ENV` | classified `resource.environment` | `development` |
| `RAID_SUBJECT` / `RAID_AGENT` | principal | `$USER` / `claude-code` |
| `RAID_STATE_DIR` | base dir for a `--solo` deployment | `~/.local/state/offense/raid` |

Run a solo daemon with the deny-first preset (no root, self-approval):

```sh
./raidd --solo &
export RAID_SOCKET="${XDG_STATE_HOME:-$HOME/.local/state}/offense/raid/raid.sock"
./raid log      # what did the agent do?
./raid grants   # active scoped confirmations
```

## Behavior

- `allow` → `{"permission": "allow"}`.
- `deny` → `{"permission": "deny", ...}` with the policy reason code.
- `require_approval` → **denied with instructions**, not an `ask`. Cursor's
  `ask` would let the user authorize the action without a Raid receipt; keeping
  approval in Raid preserves the signed, single-use, request-bound evidence.
  A human approves out-of-band (`raid approval approve <id> --expected-version 0`)
  and the agent retries — a retry of a *different* command fails verification.
- Unreachable raidd or an adapter error → **deny** (fail closed). A malformed
  hook payload → allow (fail open, so a bad input never takes down Cursor).

## Security invariants (unchanged from Raid)

- Deterministic policy runs first; a model is never the arbiter of authority.
- `deny` never calls a model and never creates an approval.
- Missing/broken policy, an unreachable daemon, or an adapter error all fail
  closed — never a silent allow.
- Approvals are single-use, Ed25519-signed, bound to the exact request hash.
