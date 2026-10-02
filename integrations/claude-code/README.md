# Raid × Claude Code

Turn Raid into a pre-tool-call **policy + approval guardrail** for Claude Code
(and other adapters that speak the same hook / MCP conventions).

**What you get**

1. **A `PreToolUse` hook gate** — Claude Code runs `hook_gate.py` before Bash /
   Edit / Write / Read calls. The call is turned into a normalized Raid action
   and the verdict is enforced:
   - `allow` — the tool call runs (exit 0),
   - `deny` — the call is **blocked** with the policy reason,
   - `require_approval` — the call is **blocked** and a human approves it in the
     Raid TUI or CLI, after which the agent retries.
2. **An MCP server** (`mcp_server.py`) — two tools the agent can call on demand:
   - `raid_check` — ask whether an action is allowed before doing it,
   - `raid_pending` — list approvals awaiting a human.
3. **A starter policy** (`coding-agent.policy.yaml`) — reads always allowed;
   file writes / package installs allowed in dev but approved in production;
   deletes, force-pushes, git rewrites, service/container exec, and db/cloud
   mutation always approved; anything unmatched fails closed (deny).
4. **An installer** (`install.sh`) — provisions and boots raidd, activates the
   starter policy, and writes `.claude/settings.json` with the hook + MCP.

## Install

```sh
cd raid/integrations/claude-code
RAID_ENV=development ./install.sh
```

The installer builds `raid`, boots `raidd` (data under `~/.offense/raid`),
activates `coding-agent.policy.yaml`, and prints the exact `.claude/settings.json`
it wrote. If `settings.json` already exists it skips the overwrite and tells you
what to merge by hand.

### Solo deployment (single engineer)

For a single engineer, skip the approver ceremony entirely:

```sh
./raidd --solo &                 # XDG state dir + self-approval + solo-dev-safe preset
export RAID_SOCKET="$HOME/.local/state/offense/raid/raid.sock"
./raid log                       # what did my agent do?
./raid grants                    # active operation/session confirmations
```

`--solo` defaults to the `solo-dev-safe` preset (deny-first guardrails, one-key
confirmations). Override with `--policy-preset review-only|ci-agent` or
`--policy <file>`.

### Manual wiring

Hook (`~/.claude/settings.json`):

```jsonc
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Edit|Write|Read",
        "hooks": [
          { "type": "command",
            "command": "python3 /abs/path/raid/integrations/claude-code/hook_gate.py" }
        ]
      }
    ]
  }
}
```

MCP (same file):

```jsonc
{
  "mcpServers": {
    "raid": {
      "type": "stdio",
      "command": "python3",
      "args": ["/abs/path/raid/integrations/claude-code/mcp_server.py"],
      "env": { "RAID_SOCKET": "/home/you/.offense/raid/raid.sock", "RAID_ENV": "development" }
    }
  }
}
```

## Environment

The adapter reads these from the environment (set them in shell or in the MCP
`env` block):

| var | meaning | default |
|---|---|---|
| `RAID_SOCKET` | raidd unix socket | `/run/offense/raid/raid.sock` |
| `RAID_ENV` | classified `resource.environment` | `development` |
| `RAID_SUBJECT` / `RAID_AGENT` | principal | `$USER` / `claude-code` |
| `RAID_SESSION` | session id | random |
| `RAID_GROUPS` | spaces/comma groups | empty |
| `RAID_CWD` | working dir for path resolution | `getcwd()` |
| `RAID_STATE_DIR` | base dir for a `--solo` deployment's socket/db/key | `~/.local/state/offense/raid` |

## How a tool call becomes a decision

`raidlib.tool_to_action()` maps a tool call to an operation slug with a small
regex classifier: `cat`/`grep` → `shell.read`, `rm -rf` → `shell.delete`,
`git push --force` → `git.force_push`, `pip install` → `package.install`,
`docker`/`kubectl` → `container.exec`, an Edit/Write → `filesystem.write`, and
so on. Unknown commands become `shell.execute` (which requires approval under
the starter policy). The real decision is always made by **raidd** against the
active policy — that is the one place authority lives.

**Do not** make the policy broader than you want: any operation not explicitly
matched fails closed to `deny` (the bundle default), and `require_approval`
never auto-runs.

### Normalized attributes (guardrails)

`raidlib.analyze_bash()` splits a compound shell command into segments and sets
explicit `resource.attributes` a policy can match on (always present, so a rule
never fails on a missing key):

| attribute | meaning |
|---|---|
| `destructive` | `"true"` for irreversible targets (`rm -rf /`, `~`, `/etc`, `/usr`, `/tmp/*`, `dd of=/dev/*`, `chmod -R 777 /`, fork bombs) |
| `exfil` | `"true"` when a secret (`.env`, `id_rsa`, `credentials`, `.pem`, …) is combined with a network command (`curl`, `wget`, `scp`, `ssh`, …) anywhere in the command |
| `protected_branch` | `"true"` when a git push/reset/clean targets `main`/`master`/`trunk`/`release`/`production` |
| `branch`, `verb`, `target`, `command` | context for finer rules |

The starter policy denies `destructive`/`exfil` outright and never merely
approves them; catastrophic commands are stopped before they happen and the
agent is told why (`[raid] blocked by policy (...)`).

## Approval flow

1. Hook blocks a call with a reason that names the approval id,
   e.g. `apr_…`.
2. A human approves once:
   ```sh
   export RAID_SOCKET=/home/you/.offense/raid/raid.sock
   ./raid approval list
   ./raid approval approve apr_… --expected-version 0
   ```
   (or in the Raid TUI: `./raidd` approval screen, key `y`.)
3. The agent retries the tool call; the replay / argument-substitution is
   rejected because the receipt is bound to the exact request hash.

To follow the outcome from the CLI:
`./raid decision wait <decision_id>`.

## Security invariants (unchanged from Raid)

- Deterministic policy runs first; a model is never the arbiter of authority.
- `deny` never calls a model and never creates an approval.
- Missing/broken policy, an unreachable daemon, or an adapter error all
  **fail closed** (the tool call is blocked) — never a silent allow.
- Approvals are single-use, Ed25519-signed, bound to the exact request hash.

## Files

- `raidlib.py` — raidd HTTP-over-unix client + tool→action classifier (shared).
- `hook_gate.py` — PreToolUse hook adapter (enforces the verdict).
- `mcp_server.py` — minimal stdio MCP server (`raid_check`, `raid_pending`).
- `coding-agent.policy.yaml` — starter policy bundle.
- `install.sh` — provision + boot + wire config.