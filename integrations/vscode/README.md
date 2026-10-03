# Raid x VS Code

Gate VS Code's agent-mode (GitHub Copilot) tool calls with Raid. VS Code runs
configured agent hooks before a tool executes; `hook_gate.py` maps the call to a
normalized Raid action and answers with VS Code's `PreToolUse` decision, so a
`deny` or `require_approval` verdict blocks the call.

This adapter reuses the shared `raidlib` normalization in `../lib/raidlib.py`
(the same classifier the Cursor and Claude Code adapters use), so the
`destructive` / `exfil` / `protected_branch` guardrail attributes behave
identically across agents.

## Wire it up

VS Code agent hooks are configured through the same hook contract Copilot Chat
exposes for the agent. Add an entry to your user or workspace settings:

```jsonc
{
  "github.copilot.chat.hooks": {
    "PreToolUse": [
      {
        "type": "command",
        "command": "python3 /abs/path/raid/integrations/vscode/hook_gate.py"
      }
    ]
  }
}
```

A copy is in `settings.example.json`. Set the hook fail-closed so a crashing
hook blocks rather than silently allows.

The adapter understands VS Code's agent tool names (`runInTerminal`,
`editFiles`, `createFile`, `readFile`, `fetch`, and `mcp_*` tools) and maps them
onto the shared operation slugs (`shell.*`, `filesystem.write`, `network.fetch`).

## MCP

The shared Raid MCP server lets the agent *ask before acting* (`raid_check`,
`raid_pending`). VS Code reads MCP servers from `.vscode/mcp.json` (or user
settings) — the same server the Claude Code and Cursor adapters use:

```jsonc
{
  "servers": {
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
| `RAID_PROVIDER` | provider recorded in the action | `claude-code` (set `vscode`) |
| `RAID_SUBJECT` / `RAID_AGENT` | principal | `$USER` / `claude-code` |
| `RAID_STATE_DIR` | base dir for a `--solo` deployment | `~/.local/state/offense/raid` |

For an accurate audit trail, set `RAID_PROVIDER=vscode` (and `RAID_AGENT`) in the
hook's environment.

Run a solo daemon with the deny-first preset (no root, self-approval):

```sh
./raidd --solo &
export RAID_SOCKET="${XDG_STATE_HOME:-$HOME/.local/state}/offense/raid/raid.sock"
./raid log      # what did the agent do?
./raid grants   # active scoped confirmations
```

## Behavior

- `allow` -> `permissionDecision: "allow"`.
- `deny` -> `permissionDecision: "deny"` with the policy reason code.
- `require_approval` -> **denied with instructions**, not an in-editor `ask`.
  An editor prompt would let the user authorize the action without a Raid
  receipt; keeping approval in Raid preserves the signed, single-use,
  request-bound evidence. A human approves out-of-band
  (`raid approval approve <id> --expected-version 0`) and the agent retries — a
  retry of a *different* command fails verification.
- Unreachable raidd or an adapter error -> **deny** (fail closed). A malformed
  hook payload -> allow (fail open, so a bad input never takes down the editor).

## Security invariants (unchanged from Raid)

- Deterministic policy runs first; a model is never the arbiter of authority.
- `deny` never calls a model and never creates an approval.
- Missing/broken policy, an unreachable daemon, or an adapter error all fail
  closed — never a silent allow.
- Approvals are single-use, Ed25519-signed, bound to the exact request hash.
