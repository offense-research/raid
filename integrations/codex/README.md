# Raid x Codex CLI

Gate Codex CLI with Raid through its MCP support plus the shared `raid-exec`
shim for shell commands.

## MCP: let the agent ask before acting

Codex CLI reads MCP servers from `~/.codex/config.toml`. Register the shared
Raid MCP server so the agent gains `raid_check` (ask whether an action is
allowed before doing it) and `raid_pending` (list approvals awaiting a human):

```toml
[mcp_servers.raid]
command = "python3"
args = ["/abs/path/raid/integrations/claude-code/mcp_server.py"]
env = { RAID_SOCKET = "/home/you/.local/state/offense/raid/raid.sock", RAID_ENV = "development", RAID_AGENT = "codex", RAID_RUNTIME = "codex" }
```

A copy is in `config.toml.example`.

## Shell commands: the raid-exec shim

Codex CLI has no pre-tool shell hook, so gate the commands it runs with the
shared shim:

```sh
raid-exec -- <command>
```

`allow` runs the command; `deny` (exit 126) and `require_approval` (exit 125)
block it with the reason or the approval id.

## Install

```sh
/path/to/raid/integrations/codex/install.sh --write-config
```

This installs `raid-exec` into `~/.local/bin` and appends the
`[mcp_servers.raid]` block to `~/.codex/config.toml` (use `--config PATH` to
target another file, or omit `--write-config` to print the block instead).

## Keep Codex's own guardrails

Raid only ever restricts what Codex would already allow, so leave Codex's
approval and sandbox settings in place:

```toml
approval_policy = "on-request"
sandbox_mode = "workspace-write"
```

## Environment

| var | meaning | default |
|---|---|---|
| `RAID_SOCKET` | raidd unix socket | `/run/offense/raid/raid.sock` |
| `RAID_ENV` | classified `resource.environment` | `development` |
| `RAID_AGENT` / `RAID_RUNTIME` | agent id and runtime in the principal | `claude-code` (set `codex`) |
| `RAID_AGENT` | agent id in the principal | `claude-code` |

## Behavior

- MCP `raid_check` returns `allow | deny | require_approval`; on
  `require_approval` it returns the approval id, and a human approves
  out-of-band (`raid approval approve <id> --expected-version 0`).
- `raid-exec` never runs a denied command and fails closed (exit 126) when
  raidd is unreachable.

## Security invariants (unchanged from Raid)

- Deterministic policy runs first; a model is never the arbiter of authority.
- `deny` never calls a model and never creates an approval.
- Missing/broken policy, an unreachable daemon, or an adapter error all fail
  closed — never a silent allow.
- Approvals are single-use, Ed25519-signed, bound to the exact request hash.
