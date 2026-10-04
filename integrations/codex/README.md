# Raid x Codex

Gate Codex with Raid. This covers every Codex host, because they share one
configuration:

- **Codex CLI**
- **the Codex IDE extension**
- **Codex in the ChatGPT desktop app**

All three read MCP servers from `~/.codex/config.toml` and skills from
`~/.agents/skills`. Wire Raid once and each client picks it up — no per-app
adapter.

Raid reaches Codex in two places:

1. **MCP** — the agent gains `raid_check` (ask whether an action is allowed
   before doing it) and `raid_pending` (list approvals awaiting a human).
2. **Skill** — `skills/raid/SKILL.md` teaches the agent to consult Raid, and to
   provision a local daemon if none is running.

Plus the shared `raid-exec` shim for the shell commands the agent runs.

## MCP: let the agent ask before acting

Register the shared Raid MCP server so Codex can ask before acting:

```toml
[mcp_servers.raid]
command = "python3"
args = ["/abs/path/raid/integrations/claude-code/mcp_server.py"]
env = { RAID_SOCKET = "/home/you/.local/state/offense/raid/raid.sock", RAID_ENV = "development", RAID_PROVIDER = "codex", RAID_AGENT = "codex", RAID_RUNTIME = "codex" }
```

A copy is in `config.toml.example`. The server speaks JSON-RPC over stdio, so
it works as a local STDIO server in any of the three hosts.

**In the ChatGPT desktop app**, open **Settings → MCP servers**. The `raid`
server you added to `~/.codex/config.toml` is already listed there (it is the
same file); select **Restart** after the first install. Type `/mcp` in the
composer to confirm the connected servers.

## Skill: teach the agent to use Raid

Install the `raid` skill into the user-level directory Codex scans:

```sh
install -Dm644 skills/raid/SKILL.md ~/.agents/skills/raid/SKILL.md
```

Codex reads skills from several locations — `$CWD/.agents/skills` up to the
repository root, then `~/.agents/skills`, then `/etc/codex/skills` — so a copy
in `~/.agents/skills` is visible in every repository you work in, including
sessions started from the ChatGPT desktop app. In the desktop app the skills
appear in the sidebar; in the CLI and the IDE extension, run `/skills` or type
`$` to mention one.

The skill carries `agents/openai.yaml`, which supplies the display name, short
description, accent colour, and default prompt the ChatGPT desktop app shows in
its Skills list.

The `raid` MCP server is registered separately, through `[mcp_servers.raid]` in
`~/.codex/config.toml` (see the install step above). The dependency block in
`openai.yaml` describes remote MCP servers, so it is not used here - Raid's
server is a local stdio process.

## Shell commands: the raid-exec shim

Codex has no pre-tool shell hook, so gate the commands it runs with the shared
shim:

```sh
raid-exec -- <command>
```

`allow` runs the command; `deny` (exit 126) and `require_approval` (exit 125)
block it with the reason or the approval id. That applies equally to a Codex
session started from the CLI and one started from the desktop app — both run
commands in your local sandbox.

## Install

```sh
/path/to/raid/integrations/codex/install.sh --write-config --write-skill
```

This installs `raid-exec` into `~/.local/bin`, appends the
`[mcp_servers.raid]` block to `~/.codex/config.toml`, and copies the skill to
`~/.agents/skills/raid/`. Use `--config PATH` / `--skill-dir PATH` to target
other locations, or drop the flags to print the block instead of writing it.

Then restart Codex (and, in the desktop app, select **Restart** next to the
server) so the new config and skill are picked up.

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
| `RAID_PROVIDER` | provider recorded in the action | `claude-code` (install.sh sets `codex`) |
| `RAID_AGENT` | agent id in the principal | `claude-code` (install.sh sets `codex`) |
| `RAID_RUNTIME` | runtime recorded in the action | `claude-code` (install.sh sets `codex`) |

The installer records `codex` as the caller so the audit trail names the real
agent rather than the adapter default.

## Behavior and limits

- MCP `raid_check` returns `allow | deny | require_approval`; on
  `require_approval` it returns the approval id, and a human approves
  out-of-band (`raid approval approve <id> --expected-version 0`).
- `raid-exec` never runs a denied command and fails closed (exit 126) when
  raidd is unreachable.
- Raid restricts **local Codex sessions** — CLI, IDE, and the desktop app. A
  Codex task running in OpenAI's cloud does not read your local config, and
  neither does ChatGPT on the web, so Raid does not gate those.
- Codex has no pre-tool hook, so MCP and the skill are advisory: the agent
  gains the ability to ask Raid, and `raid-exec` is what makes a denial
  binding. Use the shim wherever a command must not run.

## Security invariants (unchanged from Raid)

- Deterministic policy runs first; a model is never the arbiter of authority.
- `deny` never calls a model and never creates an approval.
- Missing/broken policy, an unreachable daemon, or an adapter error all fail
  closed — never a silent allow.
- Approvals are single-use, Ed25519-signed, bound to the exact request hash.
