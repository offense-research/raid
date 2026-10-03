# Raid Threat Model

Document version: 0.1-draft. Status: engineering handoff.

## Trust boundaries

Raid runs as a local daemon (`raidd`) on the same host as its agents
(the execution proxy). The open-source MVP trusts the host administrator and the local
approver surface; its job is to make *agent* authority auditable and
bounded, not to defend against the host admin (see non-goals).

Trusted:
- host administrator
- the approver human (keyboard-first TUI / CLI with approver identity)
- the daemon binary and its SQLite store

Untrusted:
- agent requests (an execution proxy or any local process reaching the socket)
- any remote callers on the TCP listener
- free-form text in requests (agent ids, task summaries, argument values)

## Security invariants (RAID-SEC-001..015)

| ID | Invariant | Enforcement |
| --- | --- | --- |
| RAID-SEC-001 | No request without deterministic authority | Default deny; engine never constructs allow; only `decision.Engine` combines |
| RAID-SEC-002 | Jev never reduces restriction | Monotonic `max(base, semantic)`; no config can lower the result |
| RAID-SEC-003 | Deterministic deny skips Jev and approval | `decision.combine` rule 3; verified by J01 |
| RAID-SEC-004 | Approval binds canonical exact request hash | SHA-256 over deterministic CBOR of bound fields; approval row stores it |
| RAID-SEC-005 | Receipt reuse / substitution fails | Ed25519 signature over claims bytes binding request + bundle hashes; at-most-once consume (409 on replay) |
| RAID-SEC-006 | Compile before activate, never on hot path | `policy.CompileBundle` runs only at activation; the daemon swaps an immutable pointer |
| RAID-SEC-007 | Missing/invalid policy fails closed | No bundle => `POLICY_BUNDLE_UNAVAILABLE` deny; CEL runtime errors are deny, never false |
| RAID-SEC-008 | Untrusted text cannot inject terminal controls | `tui.Sanitize` strips ESC/C0/OSC before rendering (U05) |
| RAID-SEC-009 | Jev never receives secret fields | Allowlist state builder; secret-classified fields excluded; canary scrubbing (J08) |
| RAID-SEC-010 | Approval durable before visible/actionable | Approval create commits synchronously (SQLite fsync) before any response/event |
| RAID-SEC-011 | Activation separate from agent/approver authority | `/v1/policies/activate` requires an active approver in the `admins` group |
| RAID-SEC-012 | Approver decisions: authenticated identity + optimistic concurrency | Approver resolved from the approvers table (never client claims); version predicate update |
| RAID-SEC-013 | The caller reauthorizes its grant after approval | Caller-side contract; `raidclient` exposes the receipt for verification, the caller rechecks its grant before dispatch |
| RAID-SEC-014 | Slow TUI client cannot block decisions | Bounded per-subscriber queues; slow subscribers dropped; events resume from sequence |
| RAID-SEC-015 | Backpressure => safe unavailability | Explicit limits (request size, subscriber cap, queue caps); failures return 503 rather than dropping |

## Key mechanisms

- **Strict decoding** (`core/canonical`): unknown fields, duplicate keys,
  oversized docs, malformed UTF-8, and non-decimal numbers are rejected with
  a precise path before any policy runs.
- **Canonical hashing**: deterministic CBOR (RFC 8949 canonical map sorting,
  definite lengths) over bound fields; decimals/timestamps/durations are
  tagged so `Decimal("1.5")` cannot collide with `String("1.5")`.
- **Receipt signing**: Ed25519 over the exact claims bytes. Consumers
  verify with the public key from `/v1/keys`, check the request hash and
  expiry, then consume exactly once.
- **Fail-closed Jev**: any Jev failure yields the configured escalation
  (minimum `require_approval`), never the deterministic allow (J05).

## Known MVP limitations (accepted, documented)

- No tamper-proof audit against the host administrator (explicit non-goal).
- mTLS/HTTPS transport and per-client request MACs are part of the protocol
  contract but the local Unix-socket path is the shipped default.
- Approver identity on the local unix socket is header-based, validated
  against the approvers table; remote mode is explicitly post-MVP.
- Balanced audit mode may lose the final event tail on catastrophic host
  failure (documented in `docs/performance.md`).

## Threats in scope for future work

- Nonce replay protection for signed request envelopes (bounded TTL cache).
- Receipt key rotation with overlap.
- Rate limiting per source client on the agent listener.