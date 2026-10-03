# AGENTS.md

Raid is a fast, agent-native **policy and approval engine**: a single Go
binary acts as both the `raidd` daemon and the `raid` CLI. Agents (or Surge,
an execution proxy) submit a normalized proposed action over a Unix socket;
Raid evaluates precompiled deterministic policy (CEL) and returns
`allow | deny | require_approval`. When approval is required, a human
approves from a keyboard-first terminal UI and Raid returns a **signed,
single-use receipt** bound to the exact request.

This file is for AI agents and humans working in the codebase. Read
`README.md` for the product pitch, `llms.txt` for agent-facing invariants,
and `docs/threat-model.md` (`RAID-SEC-001..015`) for the security contract.

## Language and build (read this first)

This is the **Go language (go.dev), version 1.26+** — *not* the conventional
Golang toolchain. Syntax is `var`, `func`, `type X struct`, `map[K]V`,
ranges, backtick free-form literals. The "go" binary is managed via mise
(`~/.local/share/mise/...`).

- It is a **single module** declared in `go.mod`: `module offense.dev/raid`.
- Dependency resolution is **hermetic via a committed `go.sum`**. Do **not**
  edit it, do not ignore it. If a build reports "missing go.sum entry", run
  `go get -u ./...` at the repo root, then rebuild.
- **There is no `internal/` tree**: Go reserves that name. All implementation
  lives under `core/`.
- **Backtick string literals do NOT process escapes.** JSON / HTTP / SSE
  framing strings containing `\n` or `\r` must use regular quoted strings
  with explicit escapes, or the bytes are wrong. (e.g. `core/stream/sse.go`.)

Required commands (see `Makefile`):

```sh
make            # go build -o raid ./main && ln -sf raid raidd
make test       # go test -count=1 ./core/canonical ./core/policy ./core/decision
                #   ./core/store ./core/approval ./core/api ./core/jev ./core/nlpolicy ./core/tui ./pkg/raidclient
make bench      # go test -bench=Benchmark -benchmem -v ./core/bench
make run-demo   # builds + boots raidd against a temp data dir
```

CI (`.github/workflows/ci.yml`) runs: build → unit+integration tests →
provisioning smoke (`tools/raid-provision.sh` + `./raid doctor`) → bench job.
It caches deps via `go.sum`. Go version pinned `1.26.x`.

`raidd` and `raid` are the **same binary**, dispatched by `argv[0]` basename
(`main/main.go`). `raidd` is a symlink; renaming/hardlinking selects the
daemon mode.

## Architecture and control/data flow

Request path: raw JSON → HTTP-on-Unix-socket → `core/api/server.go`
(`/v1/...`) → `core/decision` engine → (optional) `core/jev` semantic
escalation → `core/approval` durable service (SQLite) → `core/signing`
Ed25519 receipt. `core/server/boot.go` wires everything.

Module map (all under `core/`):

- `canonical` — strict JSON decoder, deterministic CBOR, SHA-256 request hash
- `policy` — schema, loader, CEL compiler, index, evaluator, diff
- `decision` — `Engine`, effect combination, semantic combine (`combine.go`)
- `approval` — model, state machine, durable service, receipts
- `signing` — Ed25519 keys + signed claims; `store` — SQLite WAL schema + migrations
- `stream` — bounded SSE hub (`/v1/approvals/stream`); `api` — HTTP surface + error model
- `authn` — Unix peer / approver seeding; `tui` — Bubble Tea approval UI + sanitizer
- `jev` — TypeSafe System One adapter, sanitizer, thresholds, cache
- `cli` — `./core/cli` (dispatch, `cmd.go`, `policy.go`) · `pkg/raidclient` — Go client
- `nlpolicy` — OpenRouter natural-language → policy draft (authoring aid only);
  `core/nlpolicy/tui.go` is an interactive Charm Bubble Tea v2 + Lipgloss UI
  (`raid policy from-language --interactive`)
- `util`, `audit` — small shared + durable audit-event writer

### Non-obvious invariants (do not break these)

- **Deterministic first, fail closed.** A `deny` never calls Jev and never
  creates an approval (`decision/combine.go` Rule 3/5). Missing policy, CEL
  errors, Jev outages, storage failures → `deny` or the configured
  escalation, never a silent `allow`.
- **Monotonic effect rank**: `allow(0) < require_approval(1) < deny(2)`.
  Semantic escalation only ever raises the rank (`rankFx` / `CombineEffects`
  in `decision/model.go`).
- **Jev is escalation-only and optional.** Without `TYPESAFE_API_KEY` env,
  the evaluator is null and any `semantic_guard` is effectively `off`
  (`server/boot.go`). Jev failure escalates to `require_approval` minimum.
- **Natural language is authoring aid, not authority.** `raid policy from-language`
  (OpenRouter, key via `OPENROUTER_API_KEY`/`--key`) drafts policy YAML, but
  the draft is only emitted/activated after passing the same deterministic
  `policy.LoadBundle` + `CompileBundle` gate as a hand-written file
  (`core/nlpolicy`). Never bypass that gate. `--interactive` runs the same
  flow in a Bubble Tea TUI.
- **Request hash binds exact identity.** `canonical/hash.go`: hash covers
  schema version, principal (deliberately **excludes groups**), action,
  resource (sorted attrs), typed key-sorted arguments, and context —
  but **excludes `context.timestamp`** unless a policy references it. Any
  change to hash inputs, schema, receipt claims, or policy language is a
  **breaking wire change**: update `api/*.yaml|json`, canonical tests, and
  `CHANGELOG.md`.
- **Fail-closed reason codes** are constants in `decision/engine.go`
  (`POLICY_ALLOW`, `POLICY_DENY`, `POLICY_REQUIRES_APPROVAL`,
  `POLICY_EVALUATION_ERROR`, `POLICY_BUNDLE_UNAVAILABLE`,
  `POLICY_INPUT_INVALID`).
- **Approval state machine** (`approval/state_machine.go`):
  `pending → approved/denied/expired/cancelled/superseded`;
  `approved → consumed/expired`. Resolves via **optimistic concurrency**
  (`state = ? AND version = ? AND expires_at_ns > ?`); first valid write
  wins (`approval/service.go`).
- **Receipts** (`signing/receipt.go`) are Ed25519-signed over a deterministic
  CBOR claims stream, single-use, at-most-once `Consume`, TTL 60s.
- **Atomic policy swap**: the engine holds exactly one immutable
  `CompiledBundle` behind an atomic pointer; one bundle version is used for
  the whole request. Compilation/validation happens off the hot path.
- **Audit modes**: `strict` (synchronous=FULL fsync per decision) vs
  `balanced` (NORMAL, group-committed; tail loss on crash is documented).
  Approvals and receipt consumption are always synchronous.
- **`--forbid-self-approval`** enforces separation of duty (rejects the
  requester as approver). `--uid` allowlists Unix-socket peers.
- **Signing key** is auto-generated when missing (mode `0600`). Deleting the
  seed file invalidates all outstanding receipts.
- A policy that **fails compilation or any embedded policy test aborts the
  daemon at boot** — check `raidd.log`.
- A background sweep loop every 5s marks expired approvals (`sweepLoop`).

## Code organization and tests

- Tests are **inline and adjacent**: `<module>_test.go` next to the code it
  tests (`core/policy/policy_test.go`, `core/approval/approval_test.go`,
  `core/canonical/json_test.go`, `core/tui/sanitize_test.go`).
  End-to-end HTTP/SSE/receipt flow lives in `core/api/e2e_test.go`.
- `make test` targets specific directories — note `./core/bench` is **not**
  part of it (run `make bench`). Benchmarks use `-bench=Benchmark -benchmem`.
- `core/bench/bench_test.go` has a benchmark discipline contract in
  `docs/performance.md`: record CPU, Go version, rule counts, candidates,
  argument size, audit mode.
- Add/update a test alongside any change to the areas covered above.

## Conventions

- Kebab-case file names; PascalCase types; `lowerCamel` functions; UPPER
  constants for states/effects/reason codes.
- Each `core/*` module opens with a comment block stating the spec section it
  implements (e.g. "spec 7.6", "spec 8.1") — keep those annotations in sync.
- Wire/API contracts live in `api/openapi.yaml`, `api/action.schema.json`,
  `api/policy.schema.json`; keep them in lockstep with code.
- Example policy and requests under `examples/policies/` and `examples/surge/`
  are the demo and smoke-test fixtures.

## Provisioning / operating (reference)

`tools/raid-provision.sh` builds, seeds an approver, activates the starter
policy, boots `raidd`, and runs a three-case demo. Full drop-in agent skill at
`skills/raid/SKILL.md`. Env knobs: `RAID_SOCKET`, `RAID_DB`, `RAID_KEY`,
`RAID_POLICY`, `RAID_APPROVERS`, `RAID_UID`, `RAID_SESSION`,
`RAID_STATE_DIR`, `TYPESAFE_API_KEY`, `RAID_ADMIN`. `raidd` flags mirror these
(`--socket --db --policy --policy-preset --key --tcp --uid --approver --solo --forbid-self-approval`).
Use `./raid doctor` to verify daemon readiness.

### Solo posture, presets, scopes, journal

- **`--solo`** is the unprivileged single-user posture: XDG state dir paths,
  `ForbidSelfApproval=false`, the local user auto-seeded as approver, and the
  `solo-dev-safe` preset active by default. It exists because a single engineer
  has no second reviewer; the value there is guardrail + confirm + journal.
- **Presets** are complete bundles embedded via `//go:embed`
  (`core/policy/presets/`, `core/policy/presets.go`): `solo-dev-safe`,
  `review-only`, `ci-agent`. They pass the identical load+compile gate as a
  file; `raid policy init --preset <name>` writes one.
- **Scoped approvals** (`allow_scope: operation | session`) mint a durable
  `grants` row on resolution. The API server short-circuits a matching
  `require_approval` into `allow`/`POLICY_GRANT_COVERED` when a grant covers it
  (`core/approval/grants.go`, `handleDecisions`). Keep destructive tiers on
  `exact_request`.
- **`raid log` / `GET /v1/journal`** is the merged activity timeline. Wire/API
  additions: endpoints `/v1/journal` and `/v1/grants`; the `decisions` JSON may
  now carry `grant_id`, and the `approvals` JSON now carries `allow_scope`.

## Coding-agent integrations

`integrations/` lets Raid gate a coding agent's tool calls (no Go code
involved — it's stdlib Python + the raidd Unix-socket HTTP API). A shared
library lives in `integrations/lib/`; each agent gets a thin adapter.

### Shared library

- `integrations/lib/raidlib.py` — the `Raid` HTTP-over-`AF_UNIX` client
  (`http.client.HTTPConnection` subclass) + `tool_to_action()` /
  `analyze_bash()` classifier. Bash/Write/Read map to `shell.read|write|delete`,
  `git.force_push`, `container.exec`, `package.install`, … and compound shell
  commands also emit `destructive` / `exfil` / `protected_branch` / `branch` /
  `verb` / `target` / `command` attributes for policy to match precisely.
  Adapters add `integrations/lib` to `sys.path`.

### Claude Code (`integrations/claude-code/`)

- `hook_gate.py` — a Claude Code `PreToolUse` hook adapter: maps a tool call to
  a normalized action, asks raidd, and blocks on `deny`/`require_approval` or
  passes on `allow`. Fail-closed if raidd is unreachable.
- `mcp_server.py` — a stdio MCP server (`raid_check`, `raid_pending`), Stdlib
  JSON-RPC, no SDK. `_check` builds the action directly with the caller's
  operation slug (`_typed` values) rather than reclassifying.
- `coding-agent.policy.yaml` — starter policy (reads allowed; dev writes OK,
  prod writes / deletes / force-push / exec always `require_approval`; the
  `destructive`/`exfil` guardrail is denied outright).
- `install.sh` — provisions/boots raidd, activates the policy, writes
  `.claude/settings.json`. `RAID_SOLO=1` boots a solo daemon instead.

### Cursor (`integrations/cursor/`)

- `hook_gate.py` — Cursor hooks adapter, one script for `beforeShellExecution`,
  `preToolUse`, `beforeReadFile`, and `beforeMCPExecution`. Answers with
  Cursor's permission object. `require_approval` is answered as **deny with the
  approval id**, never Cursor's `ask`, so approval stays inside Raid and keeps a
  receipt. `hooks.example.json` shows `.cursor/hooks.json`.
- Cursor MCP reuses `integrations/claude-code/mcp_server.py`.

Key gotcha: the `require_approval` verdict cannot block while awaiting a human
(hooks time out), so the hook declines the call and the human approves
out-of-band (`raid approval approve <id> --expected-version 0`), then the agent
retries. Approvals are human-only — never expose a self-approve path to the
agent (separation of duty).

## Gotchas quick list

- `go.sum` is committed and hermetic — never hand-edit; regenerate with
  `go get -u ./...`. When a new module starts importing an already-declared
  dependency, run `go get <module>` to register the entry (this added
  `charm.land/lipgloss/v2` for `core/nlpolicy`).
- `internal/` is a reserved module name in this Go — don't create it.
- Backtick strings don't escape `\n`/`\r` — use quoted strings for framing
  data.
- `[]byte` does not support `+`; concatenate byte slices with `slices.Concat`
  or build via `strings.Builder` (`nlpolicy_test.go` `okResponse`).
- Outbound HTTPS is an injected concern: `core/jev` and `core/nlpolicy` ship a
  real `netClient` (bounded deadline + response size) behind a
  `SetTransport`/`SetHttpClient` seam. It fails closed on any transport error,
  and the API key is only sent to the configured endpoint. Tests inject a
  scripted transport or a local `httptest` server, never the public network.
- Import visibility is by case: leading-uppercase identifiers (functions,
  types, struct fields, methods) are public/exported; leading-lowercase are
  module-private. Use capitalized exported helpers (e.g. `nlpolicy.NewModel`)
  to build fixtures for tests.
- `#` key constants for Bubble Tea are strings from `KeyPressMsg.String()`:
  `"ctrl+c"`, `"enter"`, `"tab"`, `"backspace"`, `"esc"`/`"escape"`.
  Lipgloss styling: `lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Bold(true).Render(s)`.
  Import path is `"charm.land/lipgloss/v2"`.
- `make test` ≠ full suite; bench lives elsewhere. CI is the authoritative
  full pass.
- `context.timestamp` is excluded from the request hash unless the policy
  references it; `groups` is always excluded from the hash.
- A boot policy that fails to compile/tests kills the daemon.