# Raid x OpenCode

Gate [OpenCode](https://opencode.ai)'s tool calls with Raid. OpenCode loads
JavaScript/TypeScript plugin modules that can hook tool events; `raid-guard.js`
registers `tool.execute.before` and blocks the call by throwing when the verdict
is `deny` or `require_approval`.

The classifier itself is the shared Python `raid-check` bridge over
`../lib/raidlib.py` — the same normalization the Claude Code, Cursor, VS Code,
Windsurf, and Crush adapters use — so the `destructive` / `exfil` /
`protected_branch` guardrail attributes behave identically across agents.

## Wire it up

OpenCode auto-loads plugin modules from `.opencode/plugins/` (project) and
`~/.config/opencode/plugins/` (global). Drop the plugin in one of those:

```sh
integrations/opencode/install.sh            # ~/.config/opencode/plugins/
integrations/opencode/install.sh --project  # ./.opencode/plugins/
```

Or list it explicitly in `opencode.json`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["/abs/path/raid/integrations/opencode/plugin/raid-guard.js"]
}
```

A copy is in `opencode.json.example`.

## How it decides

For each tool call the plugin runs:

```sh
python3 integrations/cli/raid-check.py --provider opencode
```

with `{"tool_name", "tool_input", "cwd"}` on stdin. The helper builds the
normalized Raid action, asks the running raidd, and returns a JSON verdict.
The plugin then:

- `allow` -> returns without throwing, leaving OpenCode's own permission flow in
  force (Raid only ever restricts what OpenCode would already permit).
- `deny` -> **throws**, which blocks the tool call.
- `require_approval` -> **throws with instructions**, not an OpenCode prompt. An
  in-editor confirmation would authorize the action without a Raid receipt;
  keeping approval in Raid preserves the signed, single-use, request-bound
  evidence. A human approves out-of-band
  (`raid approval approve <id> --expected-version 0`) and the agent retries.
- Classifier cannot run, or returns nothing -> **blocked** (fail closed).

## Environment

| var | meaning | default |
|---|---|---|
| `RAID_SOCKET` | raidd unix socket | `/run/offense/raid/raid.sock` |
| `RAID_ENV` | classified `resource.environment` | `development` |
| `RAID_CHECK_PY` | path to `raid-check.py` | `../../cli/raid-check.py` |
| `RAID_PYTHON` | interpreter used to run the classifier | `python3` |

The helper records `RAID_PROVIDER=opencode` so the audit trail names the real
caller.

## Security invariants (unchanged from Raid)

- Deterministic policy runs first; a model is never the arbiter of authority.
- `deny` never calls a model and never creates an approval.
- Missing/broken policy, an unreachable daemon, or an adapter error all fail
  closed — never a silent allow.
- Approvals are single-use, Ed25519-signed, bound to the exact request hash.
