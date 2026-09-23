# Install the Raid skill — paste this into your agent

> Install the Raid skill. If you're in Claude Code, run
> `claude plugin marketplace add offense/raid`,
> then `claude plugin install raid@offense/raid`. If you're in another agent,
> run `npx skills add offense/raid --skill raid` and select your agent. Use
> one installation method. You can read the skill directly at
> https://github.com/offense/raid/blob/main/skills/raid/SKILL.md
> (raw: https://raw.githubusercontent.com/offense/raid/main/skills/raid/SKILL.md).
> Then use the Raid skill when working on this project.

## Before the Raid repo is published to a marketplace

The instructions above assume the canonical `offense/raid` repository. Until
it is published (or when working in a private checkout), install the skill
from the local repository instead:

```text
Install the Raid skill. The Raid repository is at <repo-path>. Copy the
skill into the agent skill root and use it in this session:

    mkdir -p ~/.agents/skills/raid
    cp <repo-path>/skills/raid/SKILL.md ~/.agents/skills/raid/SKILL.md

Then follow the skill's Provisioning section end to end:
run `tools/raid-provision.sh` (or provision by hand with `raidd --socket …
--policy … --key … --uid … --approver …`), confirm `./raid doctor`, and only
report success after the demo flow (reader allow, label-write
require_approval → approve once → signed receipt → consume → replay 409,
delete deny) verifies.
```

The skill is read-only guidance; it does not install the binary or change
deployments by itself. Verify installs the same way the skill does: healthy
`./raid doctor` output plus the three-case demo.

## Files that make up the skill

- `skills/raid/SKILL.md` — the skill itself (drop-in at an agent skill root)
- `tools/raid-provision.sh` — one-command provisioning the skill drives
- `examples/` — starter policy and Surge demo requests the demo uses