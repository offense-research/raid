# Changelog

All notable changes to Raid are documented here.

## [Unreleased] 0.1.0-draft — first sprint MVP

First engineering handoff build of the open-source MVP.

### Added

- Real outbound HTTPS transports for `core/jev` and `core/nlpolicy`
  - The default `netClient` now performs a real HTTPS request (bounded deadline
    and response size) instead of a stub that always failed closed, so the
    semantic guard and `raid policy from-language` work in a normal deployment
  - The API key is sent only to the configured endpoint; errors stay fail-closed
  - Injectable via `SetHttpClient`/`SetTransport`; tests use a local
    `httptest` server, never the public network
- Cursor coding-agent adapter (`integrations/cursor/`)
  - One hooks adapter (`hook_gate.py`) for `beforeShellExecution`,
    `preToolUse`, `beforeReadFile`, and `beforeMCPExecution`, answering with
    Cursor's permission object; `require_approval` is answered as deny with the
    approval id (never Cursor's `ask`), keeping approval inside Raid
  - `hooks.example.json` for `.cursor/hooks.json`
- Shared adapter library (`integrations/lib/raidlib.py`): the HTTP-over-unix
  client and the shell-command classifier now live in one place reused by every
  agent adapter
- OpenAPI updated for the new surface: `/v1/journal`, `/v1/grants`, and the
  `grant_id` (decisions) and `allow_scope` (approvals) fields, with typed
  `Approval`/`Grant`/`JournalEntry` schemas
- Solo mode for individual engineers (`raidd --solo`)
  - Unprivileged single-user deployment under the XDG state dir
    (`RAID_STATE_DIR`/`$XDG_STATE_HOME`), self-approval enabled, and the local
    user auto-seeded as their own approver
  - Defaults to the `solo-dev-safe` preset on boot
  - `raid log` (and `GET /v1/journal`) merges decisions, approvals, and audit
    events into one activity timeline
  - `raid grants` (and `GET /v1/grants`) lists active scoped confirmations
- Embedded policy presets and one-command onboarding
  - `raid policy presets` lists `solo-dev-safe`, `review-only`, `ci-agent`
  - `raid policy init --preset <name> [file]` writes one for editing
  - `raidd --policy-preset <name>` boots straight from a preset
  - `solo-dev-safe` denies catastrophic commands outright (`rm -rf /`, `~`,
    `/etc`/`/usr` wipes, secret exfiltration) and confirms the rest
- Scoped approvals (`allow_scope: operation | session`)
  - A resolved scoped approval mints a durable, time-boxed grant covering the
    same principal+agent+operation+environment (or session)
  - Covered requests return `allow` with `reason_code: POLICY_GRANT_COVERED`;
    the destructive tier stays on `exact_request`
  - New `grants` table and expiry sweep; `decision` carries an optional
    `grant_id`
- Coding-agent normalization (`raidlib.analyze_bash`)
  - Compound commands are segmented; `destructive`, `exfil`,
    `protected_branch`, `branch`, `verb`, `target`, and `command` attributes are
    emitted for policies to match precisely
  - The starter Claude Code policy denies `destructive`/`exfil` outright and
    never merely approves them
- Coding-agent integration for Claude Code (`integrations/claude-code/`)
  - `hook_gate.py`: a `PreToolUse` hook that maps a tool call to a normalized
    Raid action and blocks on `deny` / `require_approval`, or passes on `allow`
  - `mcp_server.py`: a stdio MCP server exposing `raid_check` and `raid_pending`
  - `raidlib.py`: shared HTTP-over-`AF_UNIX` client + tool→action classifier
  - `coding-agent.policy.yaml`: starter policy (reads allowed; prod writes,
    deletes, force-push, and exec always require approval)
  - `install.sh`: provisions/boots raidd, activates the policy, writes
    `.claude/settings.json`
- OpenRouter-backed natural-language policy authoring
  - `raid policy from-language --statement "<permissions>" [--key] [--model] [--out] [--activate]`
    drafts a policy bundle from plain-English permissions using an LLM over
    OpenRouter (key via `OPENROUTER_API_KEY` or `--key`)
  - `raid policy from-language --interactive` launches a Charm Bubble Tea +
    Lipgloss TUI for key entry, plain-language drafting, YAML review, and
    save/activate
  - The draft is only trusted after it passes the deterministic load + compile
    gate; it is emitted/activated only then (an LLM can never become authority)
  - `core/nlpolicy` module with an injectable transport for offline tests and
    a TUI renderer
- Deterministic policy engine
  - Strict JSON request decoder (unknown fields, duplicate keys, malformed
    numbers, invalid UTF-8, size/depth limits rejected before evaluation)
  - Canonical request hash: SHA-256 over deterministic CBOR of bound fields
    (decimals/timestamps/durations tagged so they cannot collide)
  - CEL-Go environment (fixed 5-variable surface, bool result enforcement,
    unknown variable/function rejection at compile time)
  - Policy bundles: strict YAML, loader, compiler, immutable candidate
    indexes, embedded tests as an activation gate, canonical bundle hash
  - Decision combination (deny > require_approval > allow > default) and an
    atomic active-bundle pointer
  - Authority-widening policy diff
- Approval service
  - SQLite WAL store with migrations and strict/balanced audit modes
  - Approval state machine with optimistic-concurrency resolution
  - Durable create-in-transaction (RAID-SEC-010); policy-change
    supersession (A06)
  - Ed25519 signed receipts bound to the exact canonical request hash;
    at-most-once consumption
  - Approver identities and optional separation of duty
- API and clients
  - HTTP/Unix-socket API (decisions, approvals, receipts, policies, SSE
    stream, public keys) with safe error model
  - `raid` CLI: policy/decision/approval/doctor; `raidd` daemon; both from
    one binary via argv[0] dispatch
  - `raid approve` Bubble Tea v2 TUI with safe terminal rendering and
    virtualized list
  - `raidclient` Go package (CLI, TUI, Surge)
- Jev (TypeSafe System One) adapter, escalation-only
  - Allowlist state sanitizer with canary scrubbing
  - Versioned question set, threshold combiner, monotonic combination,
    circuit breaker, cache keys, HTTP transport + scriptable fake
- Assets: OpenAPI + JSON schemas, example policy and Surge requests,
  provisioning skill (`skills/raid`) and provisioner (`tools/raid-provision.sh`)

### Tests

- Policy P01-P10, Jev J01-J05/J08/J11/J12, Approvals A01-A08, TUI U05,
  full end-to-end flow (allow/approve/sign/verify/consume/replay) and the
  spec benchmark suite (10 benchmarks).

### Known limitations

- Quorum > 1 is schema-ready but not exposed (MVP: quorum 1 only).
- Remote mTLS transport and live TypeSafe calls are protocol-ready but not
  enabled-by-default or integration-tested.
- Balanced audit mode may lose the final event tail on catastrophic host
  failure (documented).
- Approver identity on the local socket is header-based and validated
  against the approvers table.

### Security

- Deterministic deny never calls Jev and never creates an approval.
- Jev failures escalate to `require_approval` (minimum), never allow.
- Receipt replay and argument substitution fail (RAID-SEC-005).
- Missing/invalid policy fails closed (RAID-SEC-007).

For the security invariants see `docs/threat-model.md`.