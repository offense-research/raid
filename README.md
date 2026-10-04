# Raid

[![License](https://img.shields.io/badge/License-Apache_2.0-blue)](LICENSE)
[![CI](https://github.com/offense-research/raid/actions/workflows/ci.yml/badge.svg)](https://github.com/offense-research/raid/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/offense-research/raid)](https://goreportcard.com/report/github.com/offense-research/raid)
[![Release](https://img.shields.io/github/v/release/offense-research/raid?sort=semver)](https://github.com/offense-research/raid/releases)
[![codecov](https://codecov.io/gh/offense-research/raid/branch/main/graph/badge.svg)](https://codecov.io/gh/offense-research/raid)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/offense-research/raid/badge)](https://securityscorecards.dev/viewer/?uri=github.com/offense-research/raid)
[![Go](https://img.shields.io/badge/Go-1.26+-blue)](go.mod)

**Raid decides what your coding agents are allowed to do.** You write the rules
once; after that, ordinary actions pass straight through, and anything
consequential pauses for a quick human yes - no blanket "approve every single
step" prompts, and no unguarded free-for-all.

Raid is a fast, agent-native **policy and approval engine**. An agent (or
an execution proxy) submits a normalized proposed action; Raid
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
(proxy-style) who want auditable bounds on what those agents may do —
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

## What Raid is not

- **Not a sandbox** — it decides whether an action may run; it does not isolate
  the process. Pair it with OS-level sandboxing.
- **Not an LLM judge** — the decision is deterministic policy; a model is never
  the arbiter of authority.
- **Not a secrets manager or credential broker** — it gates actions, not the
  credentials an agent holds.
- **Not vendor-locked** — a local Unix-socket service any agent or execution
  proxy can call (see `integrations/`).

## Install with your agent

Copy the prompt below into Claude Code, Cursor, Codex (the CLI, the IDE
extension, or Codex in the ChatGPT desktop app), or any other coding agent. It
installs the Raid skill and has the agent provision a guarded local deployment
for you:

```text
Install the Raid skill and use it for this project.

If you're in Claude Code:
    claude plugin marketplace add offense-research/raid
    claude plugin install raid@offense-research
In another agent:
    npx skills add offense-research/raid --skill raid
Use one installation method.

Codex hosts - the CLI, the IDE extension, and Codex in the ChatGPT desktop app -
share one configuration, so the skill above covers all three. To also add the
raid_check / raid_pending guardrail, from a checkout:
    integrations/codex/install.sh --write-config --write-skill

The skill text is at
https://github.com/offense-research/raid/blob/main/skills/raid/SKILL.md
(raw: https://raw.githubusercontent.com/offense-research/raid/main/skills/raid/SKILL.md).

Then follow the skill's provisioning section end to end: build the single
binary, boot `raidd` (or use `./raidd --solo` for a single engineer), confirm
`raid doctor`, and verify the demo flow (reader allowed, prod write requires
approval and issues a signed receipt, replay rejected, destructive command
denied) before reporting success.
```

Prefer to do it by hand? The three manual steps are below. `PROMPT.md` carries
the same prompt plus a local-checkout fallback for private or unpublished
clones.

## Quickstart

Three steps to a guarded agent.

**1. Install Raid** - puts `raid` (CLI) and `raidd` (daemon) on your PATH:

```sh
curl -fsSL https://raw.githubusercontent.com/offense-research/raid/main/install.sh | sh
```

**2. Start Raid** - single engineer: self-approval and deny-first defaults:

```sh
raidd --solo &
export RAID_SOCKET="${XDG_STATE_HOME:-$HOME/.local/state}/offense/raid/raid.sock"
raid doctor        # confirms the daemon is up and a policy is active
```

**3. Point your coding agent at it.** Most people use Claude Code or Codex (the
CLI, the IDE extension, or Codex in the ChatGPT desktop app).
The adapters live in the repo, so grab a checkout first:

```sh
git clone https://github.com/offense-research/raid && cd raid
```

Pick the one you use; each is a single command.

Claude Code - pre-tool-call hook plus an MCP guardrail:

```sh
RAID_SOLO=1 integrations/claude-code/install.sh
```

Codex - MCP guardrail plus the `raid-exec` shim. The CLI, the IDE extension, and
Codex in the ChatGPT desktop app share this one configuration, so this single
command covers all three:

```sh
integrations/codex/install.sh --write-config --write-skill
```

That is the whole setup. Routine actions pass straight through; anything
consequential pauses for a one-key approval, and `raid log` shows what your
agent did.

Teams (multi-approver quorum), Cursor, VS Code, Windsurf, Aider, and the full
CLI reference are covered below.

## Install

One-line install (downloads the release binary for your OS/arch, verifies its
checksum, and puts `raid` + `raidd` on your PATH):

```sh
curl -fsSL https://raw.githubusercontent.com/offense-research/raid/main/install.sh | sh
```

Homebrew:

```sh
brew install --formula ./packaging/homebrew/raid.rb
# or tap it: brew tap offense-research/raid https://github.com/offense-research/raid && brew install raid
```

Prebuilt binaries for **linux** and **macOS** (amd64/arm64) are attached to each
[release](https://github.com/offense-research/raid/releases). Or install from
source with [Go 1.26+](https://go.dev/dl/):

```sh
go install github.com/offense-research/raid@latest   # installs `raid`
ln -sf "$(go env GOPATH)/bin/raid" "$(go env GOPATH)/bin/raidd"   # daemon entry
```

`raid` and `raidd` are the same binary; `raidd` selects server mode by its
argv[0] name.

Building from a checkout gives you both in the working tree:

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
        --policy examples/policies/demo-default.yaml \
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
./raid decision eval --request examples/proxy/reader-list.json       # allow
./raid decision eval --request examples/proxy/label-write-prod.json  # require_approval
./raid decision eval --request examples/proxy/delete-repo.json       # deny
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
`~/.cursor/hooks.json` and point the command paths at your checkout. VS Code and
Windsurf use their own `settings.example.json` / `hooks.example.json`; terminal
agents (Aider, Codex) go through the `raid-exec` shim in `integrations/cli/`.
Crush, OpenCode, OpenClaw, Hermes, Pi, and omp each have their own adapter under
`integrations/` (a hook or a plugin, per agent).
Every adapter shares `integrations/lib/raidlib.py`; see `integrations/*/README.md`.

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
        --policy examples/policies/demo-default.yaml \
        --key /tmp/raid-demo/ed25519.seed --uid "$(id -u)" \
        --approver "$(id -un):maintainers,admins" &

export RAID_SOCKET=/tmp/raid-demo/raid.sock
./raid doctor

# 1. safe read — allowed instantly, no prompt
./raid decision eval --request examples/proxy/reader-list.json

# 2. production write — requires approval
./raid decision eval --request examples/proxy/label-write-prod.json

# 3. watch the approval land in the TUI (or list it noninteractively)
./raid approval list

# 4. approve once (the TUI 'y' / automation equivalent)
./raid approval approve apr_... --expected-version 0

# 5. a deterministic deny never prompts
./raid decision eval --request examples/proxy/delete-repo.json
```

The SSE stream (`/v1/approvals/stream`), signed receipt issuance, and
at-most-once consumption are exercised end-to-end in
`core/api/e2e_test.go`.

## Layout

Single Go module (`github.com/offense-research/raid`):

- `main.go` — unified entry point (`raidd` dispatch by argv[0])
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
- `pkg/raidclient` — Go client for the CLI, TUI, and proxies
- `integrations/` — coding-agent adapters (Claude Code, Cursor, VS Code,
  Windsurf, Aider, Codex (CLI, IDE extension, ChatGPT desktop app), Crush,
  OpenCode, OpenClaw, Hermes, Pi, omp) +
  shared `lib/raidlib.py` and the `cli/`
  `raid-exec` / `raid-check` shims · `skills/` — drop-in provisioning skill · `api/` — OpenAPI
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

**VS Code** (`integrations/vscode/`): a `PreToolUse` hook answering with VS
Code's `permissionDecision` object, mapped from the same normalization library.

**Windsurf** (`integrations/windsurf/`): a Cascade hooks adapter for
`pre_run_command`, `pre_write_code`, `pre_read_code`, and `pre_mcp_tool_use`
that blocks with exit status 2 on `deny`/`require_approval`.

**Aider / Codex** (`integrations/aider/`, `integrations/codex/`): agents with no
pre-tool hook API are gated through the shared `raid-exec` shim
(`integrations/cli/`), which runs a command only when Raid allows it. Codex also
picks up the shared MCP server for `raid_check`/`raid_pending` — and because the
Codex CLI, the Codex IDE extension, and Codex in the ChatGPT desktop app read the
same `~/.codex/config.toml` and `~/.agents/skills`, that one install covers all
three.

**Crush** (`integrations/crush/`): a `PreToolUse` hook in `crush.json` that
blocks with exit status 2 on `deny`/`require_approval`.

**OpenCode** (`integrations/opencode/`): a `tool.execute.before` plugin that
blocks by throwing; it reaches the shared classifier through the `raid-check`
helper.

**OpenClaw** (`integrations/openclaw/`): a `before_tool_call` plugin returning
`{block: true, blockReason}`.

**Hermes** (`integrations/hermes/`): a native Hermes plugin whose
`pre_tool_call` hook returns `{"action": "block", "message": ...}`.

**Pi / omp** (`integrations/pi/`, `integrations/omp/`): Claude Code-shaped
`PreToolUse` hooks answering with `permissionDecision` (exit 2 blocks).

See each adapter's README for details and security invariants.

## Roadmap

- **More agent adapters** (Gemini CLI, Amp, Goose) on the shared library.
- **Packaging:** an npm/PyPI wrapper.
- **Policy simulation:** dry-run a request corpus against a candidate bundle.

## Provisioning skill

A drop-in agent skill for installing and provisioning Raid is included at
`skills/raid/SKILL.md`. The repository is also its own Claude Code plugin
marketplace (`.claude-plugin/marketplace.json`), so the skill installs as the
`raid` plugin from the `offense-research` marketplace.

**Paste this into any agent to install the skill** (see `PROMPT.md` for
the unpublished-repo fallback, and the [Install with your agent](#install-with-your-agent)
prompt to have the agent provision as well):

> Install the Raid skill. If you're in Claude Code, run
> `claude plugin marketplace add offense-research/raid`,
> then `claude plugin install raid@offense-research`. If you're in another
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
The core position: Raid can restrict a caller, never grant what it did not
already authorize, and a model is never the arbiter of authority.