# Changelog

All notable changes to Raid are documented here.

## [Unreleased] 0.1.0-draft — first sprint MVP

First engineering handoff build of the open-source MVP.

### Added

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