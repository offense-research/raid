# Raid x Aider

Aider has no pre-tool hook API, so Raid is wired in at the two points Aider
actually goes through: the shell commands it runs and the git commits it makes
for you.

Both use the shared `raid-exec` shim in `../cli/`, which classifies a command
with the shared `raidlib` and asks the running raidd.

## Install

From your project's git repository:

```sh
/path/to/raid/integrations/aider/install.sh --git-hooks
```

This installs `raid-exec` into `~/.local/bin` and drops `pre-push` and
`pre-commit` hooks into `.git/hooks/`. The hooks run
`raid-exec --check -- git push` / `git commit`, so a `deny` or
`require_approval` verdict blocks the git action. Pass `--socket PATH` to pin
the raidd socket the hooks use.

## Gating shell commands

Aider runs shell commands (for example `/run`, or commands you ask it to run)
in a subshell. Prefix them with the shim:

```sh
raid-exec -- <command>
```

You can also point Aider's own tooling at the shim in `.aider.conf.yml`:

```yaml
# .aider.conf.yml — gate the commands Aider runs on your behalf
lint-cmd: "raid-exec --check -- ruff check ."
test-cmd: "raid-exec --check -- pytest -q"
```

`raid-exec --check` decides without running anything, so a denied command stops
the step rather than being executed.

## Environment

| var | meaning | default |
|---|---|---|
| `RAID_SOCKET` | raidd unix socket | `/run/offense/raid/raid.sock` |
| `RAID_ENV` | classified `resource.environment` | `development` |
| `RAID_PROVIDER` | provider recorded in the action | `claude-code` (install.sh sets `aider`) |
| `RAID_AGENT` | agent id in the principal | `claude-code` (install.sh sets `aider`) |
| `RAID_RUNTIME` | runtime recorded in the action | `claude-code` (install.sh sets `aider`) |
The installer records `aider` as the caller so the audit trail names the real
agent rather than the adapter default.

Run a solo daemon with the deny-first preset (no root, self-approval):

```sh
./raidd --solo &
export RAID_SOCKET="${XDG_STATE_HOME:-$HOME/.local/state}/offense/raid/raid.sock"
./raid log      # what did the agent do?
```

## Behavior

- `allow` -> exit 0; the git action (or command) proceeds.
- `deny` -> exit 126 with the policy reason code; the git action is blocked.
- `require_approval` -> exit 125 with the approval id. A human approves
  out-of-band (`raid approval approve <id> --expected-version 0`) and you retry.
  Keeping approval in Raid preserves the signed, single-use, request-bound
  evidence rather than an in-editor confirmation.
- Unreachable raidd or a classification error -> exit 126 (fail closed).

## Security invariants (unchanged from Raid)

- Deterministic policy runs first; a model is never the arbiter of authority.
- `deny` never calls a model and never creates an approval.
- Missing/broken policy, an unreachable daemon, or an adapter error all fail
  closed — never a silent allow.
- Approvals are single-use, Ed25519-signed, bound to the exact request hash.
