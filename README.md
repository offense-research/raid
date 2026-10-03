# Raid

[![License](https://img.shields.io/badge/License-Apache_2.0-blue)](LICENSE)
[![CI](https://github.com/offense-research/raid/actions/workflows/ci.yml/badge.svg)](https://github.com/offense-research/raid/actions/workflows/ci.yml)
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

## Usage

Raid is two commands in one binary: `raidd` is the daemon, `raid` is the CLI.
They talk over a Unix socket — point the CLI at the daemon with `RAID_SOCKET`
(or the default `/run/offense/raid/raid.sock`, else the solo state socket).
`./raid help` and `./raidd --help` list the flags.

### 1. Start the daemon

Multi-approver (teams):

```sh
mkdir -p /tmp/raid-demo
./raidd --socket /tmp/raid-demo/raid.sock \
        --db     /tmp/raid-demo/raid.db \
        --policy examples/policies/surge-default.yaml \
        --key    /tmp/raid-demo/ed25519.seed \
        --uid "$(id -u)" \
        --approver "$(id -un):maintainers,admins" &
export RAID_SOCKET=/tmp/raid-demo/raid.sock
```

Single engineer (no root, self-approval, deny-first preset):

```sh
./raidd --solo &
export RAID_SOCKET="${XDG_STATE_HOME:-$HOME/.local/state}/offense/raid/raid.sock"
```

Confirm it is up:

```sh
./raid doctor        # raidd: reachable  +  active policy JSON
```

### 2. Evaluate an action

Actions are normalized JSON (schema in `api/openapi.yaml`). Evaluate one from a
file and read the decision (`effect`, `reason_code`, matched rules, and on
`require_approval` the approval `id`):

```sh
./raid decision eval --request examples/surge/reader-list.json       # allow
./raid decision eval --request examples/surge/label-write-prod.json  # require_approval
./raid decision eval --request examples/surge/delete-repo.json       # deny
```

### 3. Resolve approvals

```sh
./raid approval list                                   # pending approvals (JSON)
./raid approve                                         # interactive TUI (needs a TTY)
./raid approval approve apr_... --expected-version 0   # noninteractive
./raid approval deny    apr_... --expected-version 0
```

Read the `version` from the approval first; a stale version returns `409`.
Approving an exact-request approval returns a **signed receipt bound to the
request hash** — replaying it for different arguments fails. Add
`--forbid-self-approval` to require a different person than the requester. A
rule with `approval.quorum > 1` records a vote and stays `pending` until enough
approvers approve; a single deny is a veto.

### 4. See what happened

```sh
./raid log --limit 20                    # merged decisions + approvals + audit
./raid log --kind decision --limit 20    # filter by kind (decision|approval|audit)
./raid grants                            # active scoped confirmations
./raid grants revoke gnt_...             # end a scoped confirmation now
./raid receipt get rcp_...               # receipt status (issued|consumed|expired)
./raid receipt verify rcp_...            # verify the signature + binding
./raid receipt verify --receipt r.json --request req.json   # offline; add --pubkey
```

### 5. Author and activate policy

```sh
./raid policy presets                                # list onboarding presets
./raid policy init --preset solo-dev-safe my.yaml    # write one to edit
./raid policy validate my.yaml
./raid policy test     my.yaml                        # run embedded tests
./raid policy diff old.yaml new.yaml                  # what authority changed
./raid policy activate my.yaml                        # admin approver only
```

A bundle that fails to compile, or whose embedded tests fail, never becomes
active. Plain-language drafting (`./raid policy from-language --statement ...`)
emits YAML only after it passes the same gate — see `docs/policy-language.md`.

### 6. Gate a coding agent

```sh
cd integrations/claude-code && RAID_ENV=development ./install.sh   # Claude Code
```

For Cursor, copy `integrations/cursor/hooks.example.json` to
`~/.cursor/hooks.json` and point the command paths at your checkout. Both
adapters share `integrations/lib/raidlib.py`; see `integrations/*/README.md`.

### 7. Connect and secure clients

Any client sets `RAID_SOCKET` to reach a daemon. For a remote daemon,
`raidd --tcp host:port` serves the same API over TCP; unlike the Unix socket
(peer-UID authenticated), the network surface requires a token and can be
locked down further:

```sh
./raidd --tcp 127.0.0.1:8788 --tcp-token "$(openssl rand -hex 32)" \
        --rate-limit 50 --rate-burst 100                      # bearer + rate limit
./raidd --tcp 0.0.0.0:8788 --tcp-cert cert.pem --tcp-key key.pem \
        --tcp-client-ca ca.pem                                # TLS + mTLS
```

Clients send `Authorization: Bearer <token>` (or `X-Raid-Token`). Without a
token, bind TCP to loopback only.

## Quick demo

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
- `core/policy` — schema, loader, CEL compiler, index, evaluator, diff, presets
- `core/decision` — engine, effect combination, semantic combine
- `core/approval` — model, state machine, votes/quorum, grants, receipts
- `core/signing` — Ed25519 keys and signed claims
- `core/store` — SQLite WAL schema + migrations, audit modes
- `core/stream` — bounded SSE hub and subscriber
- `core/api` — HTTP/Unix-socket surface, auth/rate-limit middleware, error model
- `core/authn` — approver identity; `core/audit` — decision/audit events
- `core/tui` — Charm Bubble Tea v2 approvals + grants UI and sanitizer
- `core/jev` — TypeSafe System One adapter, sanitizer, thresholds, cache
- `core/nlpolicy` — OpenRouter natural-language → policy draft (authoring aid)
- `core/server` — daemon boot; `core/cli` — the `raid` command surface
- `pkg/raidclient` — Go client for CLI / TUI / Surge
- `integrations/` — coding-agent adapters (Claude Code, Cursor) + shared
  `lib/raidlib.py` · `skills/` — drop-in provisioning skill · `api/` — OpenAPI
  and JSON schemas · `docs/` — threat model, policy language, approvals, Jev,
  performance · `examples/` — demo policy + requests

## Configuration

`raidd` flags: `--socket`, `--db`, `--policy`, `--policy-preset <name>`, `--key`,
`--tcp`, `--uid`, `--approver <subject:groups>`, `--solo`,
`--forbid-self-approval`, plus TCP hardening flags
(`--tcp-token`, `--tcp-cert`, `--tcp-key`, `--tcp-client-ca`, `--rate-limit`,
`--rate-burst`; see §7 of Usage).
Environment: `RAID_SOCKET`, `RAID_APPROVER`, `RAID_DB`, `RAID_KEY`,
`RAID_STATE_DIR`, `RAID_ENV`, `RAID_TCP_TOKEN`, `TYPESAFE_API_KEY` (enables the
Jev adapter), `OPENROUTER_API_KEY` (enables `raid policy from-language`),
`RAID_SESSION`.

## Solo mode for individual engineers

A single engineer has no second reviewer, so Raid's value shifts from
authorization to **guardrail + confirm + journal**. `--solo` gives you exactly
that, with no root and no approver setup:

```sh
./raidd --solo &            # XDG state dir, self-approval, deny-first preset
./raid doctor
./raid log                  # what did my agent do? (decisions/approvals/audit)
./raid grants               # active operation/session confirmations
```

- **Guardrail first.** The `solo-dev-safe` preset *denies outright* the
  irreversible commands (`rm -rf /`, `rm -rf ~`, `/etc`/`/usr` wipes,
  secret exfiltration, force-push to `main`/`master`). The agent sees the
  reason and reroutes — no human latency.
- **One-keypress confirmations.** Everything consequential (deletes, exec,
  force-push, prod writes) is `require_approval`; approving in the TUI is a
  single key. `allow_scope: operation` mints a time-boxed grant so a repetitive
  low-risk action is not re-approved for every invocation.
- **A journal.** `raid log` merges decisions, approvals, and audit events into
  one timeline — the second pair of eyes on your own agent.

Pick a posture with presets:

```sh
./raid policy presets                       # list
./raid policy init --preset solo-dev-safe   # write a bundle you can edit
./raidd --policy-preset review-only         # boot straight from a preset
```

`review-only` (inspect, change nothing) and `ci-agent` (build/test in dev,
confirm in prod, never rewrite history) cover the other common postures.

## Writing policies in plain language

Connect an OpenRouter key and describe your permissions in English instead of
writing YAML+CEL by hand:

```sh
export OPENROUTER_API_KEY=sk-or-...
./raid policy from-language \
  --statement "allow GitHub issue reads on staging, require approval before modifying production issues, deny repository deletion" \
  --out my-policy.yaml
./raid policy validate my-policy.yaml
```

The drafted policy only takes effect after passing the same deterministic
load + compile gate as a hand-written one, and a draft that fails that gate is
discarded. See `docs/policy-language.md`.

For a Charm-stack terminal UI, run the same command interactively (needs a
TTY): `./raid policy from-language --interactive` — set the key, describe your
permissions, `d` to draft, review the YAML, then `s` to save or `a` to activate
(`tab` switches fields, `i` edits, `q` quits).

## Using with coding agents

Raid can gate a coding agent's tool calls. Adapters share one normalization
library (`integrations/lib/raidlib.py`) and speak the daemon's Unix-socket API.

**Claude Code** (`integrations/claude-code/`): a `PreToolUse` hook
(`hook_gate.py`) maps each Bash/Edit/Write call to a normalized action and
blocks on `deny`/`require_approval`, plus an MCP server (`raid_check`,
`raid_pending`), a starter policy (`coding-agent.policy.yaml`), and an installer
that boots raidd and writes `.claude/settings.json`.

```sh
cd integrations/claude-code && RAID_ENV=development ./install.sh
```

**Cursor** (`integrations/cursor/`): one hooks adapter for
`beforeShellExecution`, `preToolUse`, `beforeReadFile`, and `beforeMCPExecution`
that answers with Cursor's permission object (`require_approval` is answered as
deny-with-instructions, so approval stays inside Raid).

```sh
# copy integrations/cursor/hooks.example.json to ~/.cursor/hooks.json and
# point the command paths at your checkout (see integrations/cursor/README.md)
```

See each adapter's README for details and security invariants.

## Roadmap

- **More agent adapters** (Codex CLI, Gemini CLI, Crush) on the shared library.
- **Packaging:** `go install`, a Homebrew tap, and an npm/PyPI wrapper.
- **Policy simulation:** dry-run a request corpus against a candidate bundle.

## Provisioning skill

A drop-in agent skill for installing and provisioning Raid is included at
`skills/raid/SKILL.md`

**Paste this into any agent to install the skill** (see `PROMPT.md` for
the unpublished-repo fallback):

> Install the Raid skill. If you're in Claude Code, run
> `claude plugin marketplace add offense-research/raid`,
> then `claude plugin install raid@offense-research/raid`. If you're in another
> agent, run `npx skills add offense-research/raid --skill raid` and select your
> agent. Use one installation method. You can read the skill directly at
> https://github.com/offense-research/raid/blob/main/skills/raid/SKILL.md
> (raw: https://raw.githubusercontent.com/offense-research/raid/main/skills/raid/SKILL.md).
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