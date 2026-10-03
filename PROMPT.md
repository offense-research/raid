# Onboard an agent to Raid — paste this prompt

## Public repo (the normal path)

Copy the whole block below into your agent. It installs the Raid skill and has
the agent provision and verify a local deployment end to end.

```text
Install the Raid skill and use it for this project.

If you're in Claude Code:
    claude plugin marketplace add offense-research/raid
    claude plugin install raid@offense-research
In another agent:
    npx skills add offense-research/raid --skill raid
Use one installation method. The skill text is at
https://github.com/offense-research/raid/blob/main/skills/raid/SKILL.md
(raw: https://raw.githubusercontent.com/offense-research/raid/main/skills/raid/SKILL.md).

Then follow the skill's Provisioning section end to end: build the single
binary, provision and boot `raidd` (or use `./raidd --solo` for a single
engineer), confirm `./raid doctor`, and only report success after the demo flow
verifies:

  - reader request -> effect: allow (no prompt)
  - label-write request -> effect: require_approval + approval object
  - approve once -> approval state: approved + signed receipt (key_id,
    signature, claims_bytes)
  - consume the receipt once -> {"consumed":true}; replaying returns HTTP 409
  - delete request -> effect: deny

Do not report the build alone as provisioning.
```

## Local checkout (private clone or unpublished)

When the repo isn't published yet, point the agent at the checkout instead:

```text
Install the Raid skill. The Raid repository is at <repo-path>. Copy the skill
into the agent skill root and use it in this session:

    mkdir -p ~/.agents/skills/raid
    cp <repo-path>/skills/raid/SKILL.md ~/.agents/skills/raid/SKILL.md

Then follow the skill's Provisioning section end to end (see above) and verify
with `./raid doctor` plus the demo flow before reporting success.
```

## Gate a coding agent (optional)

Provisioning the engine is separate from gating an agent's tool calls. Once a
daemon is running:

- Claude Code: `cd integrations/claude-code && RAID_ENV=development ./install.sh`
- Cursor: copy `integrations/cursor/hooks.example.json` to `~/.cursor/hooks.json`
  and point the command paths at the checkout.
- Codex (the CLI, the IDE extension, and Codex in the ChatGPT desktop app share
  one config): `integrations/codex/install.sh --write-config --write-skill`

Details in `integrations/*/README.md`.

## Files that make up the skill

- `skills/raid/SKILL.md` — the skill itself (drop-in at an agent skill root)
- `skills/raid/agents/openai.yaml` — Codex / ChatGPT desktop UI metadata: the
  display name, short description, accent colour, and default prompt
- `tools/raid-provision.sh` — one-command provisioning the skill drives
- `examples/` — starter policy and demo requests the demo uses

The skill is read-only guidance: it does not install the binary or change
deployments by itself. Verify installs the same way the skill does — a healthy
`./raid doctor` plus the demo flow.
