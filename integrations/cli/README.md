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

## Environment

| var | meaning | default |
|---|---|---|
| `RAID_SOCKET` | raidd unix socket | `/run/offense/raid/raid.sock` |
| `RAID_ENV` | classified `resource.environment` | `development` |
| `RAID_AGENT` | agent id in the principal | `claude-code` |

| `RAID_AGENT` / `RAID_RUNTIME` | agent id and runtime in the principal | `claude-code` |

Set `RAID_AGENT` / `RAID_RUNTIME` to the agent you are wrapping (for example
`aider` or `codex`) so the audit trail names the real caller.

An unreachable raidd or a classification failure fails closed (exit 126) — never
a silent allow.
