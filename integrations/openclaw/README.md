# Raid x OpenClaw

Gate [OpenClaw](https://docs.openclaw.ai)'s tool calls with Raid. OpenClaw
native plugins register typed lifecycle hooks; `plugin/index.js` uses
`api.on("before_tool_call", ...)` to consult the running raidd before a tool
runs and blocks with `{ block: true, blockReason }` when the verdict is `deny`
or `require_approval`.

The classifier is the shared Python `raid-check` bridge over
`../lib/raidlib.py` — the same normalization the Claude Code, Cursor, VS Code,
Windsurf, Crush, and OpenCode adapters use — so the `destructive` / `exfil` /
`protected_branch` guardrail attributes behave identically across agents.

## Wire it up

Load the plugin from its directory. Add its path to the OpenClaw config and
reload:

```sh
plugins.load.paths = ['/abs/path/raid/integrations/openclaw/plugin/index.js']
openclaw plugins reload raid-guard
```

Equivalently:

```sh
openclaw plugins install --link /abs/path/raid/integrations/openclaw/plugin --force
openclaw plugins enable raid-guard
```

Install the shims with `integrations/openclaw/install.sh`.

## How it decides

For each tool call the plugin runs:

```sh
python3 integrations/cli/raid-check.py --provider openclaw
```

with `{"tool_name", "tool_input", "cwd"}` on stdin. The helper builds the
normalized Raid action, asks the running raidd, and returns a JSON verdict.
The plugin then:

- `allow` -> returns no directive, leaving OpenClaw's own tool policy in force
  (Raid only ever restricts what OpenClaw would already permit).
- `deny` -> `{ "block": true, "blockReason": "<policy reason>" }`.
- `require_approval` -> **blocked with instructions**, deliberately NOT
  OpenClaw's own `requireApproval` prompt. An in-agent prompt would authorize
  the action without a Raid receipt; keeping approval in Raid preserves the
  signed, single-use, request-bound evidence. A human approves out-of-band
  (`raid approval approve <id> --expected-version 0`) and the agent retries.
- Classifier cannot run, or returns nothing -> **blocked** (fail closed).

## Files

```text
plugin/
  openclaw.plugin.json  # plugin manifest (id, name, version, description)
  package.json          # ESM package metadata
  index.js              # definePluginEntry + before_tool_call hook
```

## Environment

| var | meaning | default |
|---|---|---|
| `RAID_SOCKET` | raidd unix socket | `/run/offense/raid/raid.sock` |
| `RAID_ENV` | classified `resource.environment` | `development` |
| `RAID_CHECK_PY` | path to `raid-check.py` | `../../cli/raid-check.py` |
| `RAID_PYTHON` | interpreter used to run the classifier | `python3` |

The helper records `RAID_PROVIDER=openclaw` so the audit trail names the real
caller.

## Security invariants (unchanged from Raid)

- Deterministic policy runs first; a model is never the arbiter of authority.
- `deny` never calls a model and never creates an approval.
- Missing/broken policy, an unreachable daemon, or an adapter error all fail
  closed — never a silent allow.
- Approvals are single-use, Ed25519-signed, bound to the exact request hash.
