# Raid x CLI coding agents

A single shim, `raid-exec.py`, for CLI agents that have no pre-tool hook API.
It classifies a shell command with the shared `raidlib`, asks the running raidd,
and runs the command only when the verdict is `allow`.

```
raid-exec -- <command> [args...]
```

Exit codes (so any wrapper/agent treats non-zero as blocked):

| verdict | exit | behavior |
|---|---|---|
| allow | 0 | execs the command, replacing the shim process |
| deny | 126 | prints the policy reason code; command not run |
| require_approval | 125 | prints the approval id and instructions; command not run |
| usage error | 64 | prints usage |

Modes:

```sh
raid-exec -- git push origin main        # run only if allowed
raid-exec --check -- rm -rf /            # decide only (0 allow / 126 deny / 125 approval)
raid-exec --dry-run -- git push          # print the normalized Raid action
raid-exec --dry-run --json -- git push   # ... as pretty JSON
```

## Install

```sh
install -Dm755 integrations/cli/raid-exec.py ~/.local/bin/raid-exec
```

Then call it wherever the agent would otherwise run a shell command directly.

## `raid-check` — judge a tool call (JSON verdict)

`raid-check.py` is the companion for hosts that run their guardrail hooks in a
JavaScript runtime (OpenCode, OpenClaw) and cannot import the Python classifier.
It reads one tool call as JSON on stdin, builds the normalized Raid action, and
prints a JSON verdict:

```sh
echo '{"tool_name":"bash","tool_input":{"command":"rm -rf /"},"cwd":"."}' \
  | raid-check --provider opencode
# {"effect":"deny","reason_code":"POLICY_DENY","reason":"blocked by policy (POLICY_DENY)"}
```

| verdict | exit |
|---|---|
| allow | 0 |
| deny | 126 |
| require_approval | 125 |

It maps common host tool names (`read`, `write`, `edit`, `terminal`, …) onto the
classifier's slugs, and a caller may override with a `tool_aliases` object in the
payload. `--dry-run` prints the normalized action instead of deciding.

```sh
install -Dm755 integrations/cli/raid-check.py ~/.local/bin/raid-check
```

## Environment

| var | meaning | default |
|---|---|---|
| `RAID_SOCKET` | raidd unix socket | `/run/offense/raid/raid.sock` |
| `RAID_ENV` | classified `resource.environment` | `development` |
| `RAID_PROVIDER` | provider recorded in the action | `claude-code` |
| `RAID_AGENT` | agent id in the principal | `claude-code` |
| `RAID_RUNTIME` | runtime recorded in the action | `claude-code` |
Set `RAID_PROVIDER` / `RAID_AGENT` / `RAID_RUNTIME` to the agent you are
wrapping (for example `aider` or `codex`) so the audit trail names the real
caller.

An unreachable raidd or a classification failure fails closed (exit 126) — never
a silent allow.
