# Raid

[![License](https://img.shields.io/badge/License-Apache_2.0-blue)](LICENSE)
[![CI](https://github.com/offense/raid/actions/workflows/ci.yml/badge.svg)](https://github.com/offense/raid/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.26+-blue)](go.mod)

Raid is a fast, agent-native **policy and approval engine**. An agent (or
Surge, an execution proxy) submits a normalized proposed action; Raid
evaluates precompiled deterministic policy (CEL) and returns
`allow | deny | require_approval`. When approval is required, a human
approves from a keyboard-first terminal UI and Raid returns a **signed,
single-use receipt** bound to the exact request.

```
Code defines authority.      # Go + precompiled CEL, microseconds
Jev identifies ambiguity.    # optional TypeSafe Jev, escalation-only
Humans resolve consequence.  # Charm Bubble Tea approval TUI
```

## The problem

Agents can act, but nobody can answer one question cheaply: *"is this
specific agent allowed to perform this exact action, under these
conditions, right now?"* Teams end up with either blanket
"confirm every tool call" prompts (which developers burn out on and click
through) or no guardrails at all (which turns one prompt-injection mistake
into a production write).

Raid is the middle path: **safe, routine actions pass in microseconds
without a prompt; consequential ones surface once, to a human, with a
signed, single-use receipt bound to the exact request.** The decision
engine is deterministic policy (Go + precompiled CEL) — a model is never
the arbiter of authority. A configured semantic guard can escalate
ambiguous actions to approval, but it can never reduce a deterministic
restriction.

Who this is for: teams building agents, automation, or execution proxies
(Surge-style) who want auditable bounds on what those agents may do —
without making developers wait on routine work.

- **Fast by construction** — policies compile before activation; active
  bundles are immutable behind an atomic pointer; the deterministic path
  avoids SQLite reads; Unix-socket transport.
- **Deterministic first** — Jev only runs when policy asks, can only
  escalate, and a deterministic deny never calls it.
- **Exact approvals** — receipts bind the canonical request hash; replay
  and argument substitution fail.
- **Fail closed** — missing policy, CEL errors, Jev outages, and storage
  failures all yield `deny` or the configured escalation, never a silent
  allow.

## Build

Requires Go 1.26+.

```sh
make            # builds ./raid and ./raidd (raidd is a symlink)
make test       # unit + integration suites
make bench      # spec benchmark suite
```

License: Apache-2.0 (`LICENSE`). Reporting: `SECURITY.md`. Contributing:
`CONTRIBUTING.md`. Changes: `CHANGELOG.md`. Agent instructions:
`llms.txt`. Business model: `docs/open-source-and-pricing.md`.

## Quick demo (10 steps from the spec)

```sh
mkdir -p /tmp/raid-demo
./raidd --socket /tmp/raid-demo/raid.sock \
        --db /tmp/raid-demo/raid.db \
        --policy examples/policies/surge-default.yaml \
        --key /tmp/raid-demo/ed25519.seed --uid "$(id -u)" \
        --approver "$(id -un):maintainers,admins" &

export RAID_SOCKET=/tmp/raid-demo/raid.sock
./raid doctor

# 1. safe read — allowed instantly, no prompt
./raid decision eval --request examples/surge/reader-list.json

# 2. production write — requires approval
./raid decision eval --request examples/surge/label-write-prod.json

# 3. watch the approval land in the TUI (or list it noninteractively)
./raid approval list

# 4. approve once (the TUI 'y' / automation equivalent)
./raid approval approve apr_... --expected-version 0

# 5. a deterministic deny never prompts
./raid decision eval --request examples/surge/delete-repo.json
```

The SSE stream (`/v1/approvals/stream`), signed receipt issuance, and
at-most-once consumption are exercised end-to-end in
`core/api/e2e_test.go`.

## Layout

Single Go module (`offense.dev/raid`):

- `main/` — unified entry point (`raidd` dispatch by argv[0])
- `core/canonical` — strict JSON decoder, deterministic CBOR, request hash
- `core/policy` — schema, loader, CEL compiler, index, evaluator, diff
- `core/decision` — engine, effect combination, semantic combine
- `core/approval` — model, state machine, durable service, receipts
- `core/signing` — Ed25519 keys and signed claims
- `core/store` — SQLite WAL schema + migrations, audit modes
- `core/stream` — bounded SSE hub and subscriber
- `core/api` — HTTP/Unix-socket surface and error model
- `core/tui` — Charm Bubble Tea v2 approval UI + sanitizer
- `core/jev` — TypeSafe System One adapter, sanitizer, thresholds, cache
- `core/server` — daemon boot
- `pkg/raidclient` — Go client for CLI / TUI / Surge
- `api/` — OpenAPI and JSON schemas · `docs/` — threat model, policy
  language, approvals, Jev, performance · `examples/` — demo policy + requests

## Configuration

`raidd` flags: `--socket`, `--db`, `--policy`, `--key`, `--tcp`,
`--uid`, `--approver <subject:groups>`, `--forbid-self-approval`.
Environment: `RAID_SOCKET`, `RAID_APPROVER`, `RAID_DB`, `RAID_KEY`,
`TYPESAFE_API_KEY` (enables the Jev adapter), `RAID_SESSION`.

## Provisioning skill

A drop-in agent skill for installing and provisioning Raid is included at
`skills/raid/SKILL.md` (install it as a skill root entry, e.g.
`$HOME/.agents/skills/raid/SKILL.md`). It drives
`tools/raid-provision.sh`, which builds the binary, prepares the data
directory, boots `raidd` with a seeded approver and the starter policy, and
runs a verifiable demo (allow / require_approval→approve→consume / deny).

**Paste this into any agent to install the skill** (see `PROMPT.md` for
the unpublished-repo fallback):

> Install the Raid skill. If you're in Claude Code, run
> `claude plugin marketplace add offense/raid`,
> then `claude plugin install raid@offense/raid`. If you're in another agent,
> run `npx skills add offense/raid --skill raid` and select your agent. Use
> one installation method. You can read the skill directly at
> https://github.com/offense/raid/blob/main/skills/raid/SKILL.md
> (raw: https://raw.githubusercontent.com/offense/raid/main/skills/raid/SKILL.md).
> Then use the Raid skill when working on this project.

## Documentation

- `docs/threat-model.md` — security invariants (RAID-SEC-001..015) and accepted MVP limitations
- `docs/policy-language.md` — policy bundles, the CEL environment, rule combination
- `docs/approvals.md` — approval lifecycle, TTLs, receipts, events
- `docs/jev.md` — TypeSafe Jev integration, escalation rules, sanitizer
- `docs/performance.md` — latency contract, audit modes, benchmarks
- `docs/open-source-and-pricing.md` — OSS/hosted boundary and pricing model
- `api/openapi.yaml` + `api/*.schema.json` — wire contracts

## Security

See `docs/threat-model.md` for the invariants and accepted MVP limitations.
The core position: Raid can restrict Surge, never grant what Surge did not
already authorize, and a model is never the arbiter of authority.