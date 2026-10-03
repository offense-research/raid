# Raid Approvals

## Lifecycle

```
pending ─┬─► approved ──► consumed
         ├─► approved ──► expired
         ├─► denied
         ├─► expired
         ├─► cancelled     (by the requesting session)
         └─► superseded    (policy changed while pending)
```

`approved` is intentionally non-terminal: the receipt may still be
consumed. Approvals are exact-request bound: the receipt's claims embed the
SHA-256 of the canonical request hash, so replaying it for different
arguments fails verification.

## Durability (RAID-SEC-010)

Creating an approval commits the decision row, the approval row, and its
creation audit event in **one synchronous transaction** before the response
is sent or any event is published. There is no path where an approval exists
only in TUI memory.

## TTLs

| Item | Default | Min | Max |
| --- | --- | --- | --- |
| Pending approval | 5m | 30s | 30m |
| Approved, unconsumed receipt | 60s | — | ≤ source session expiration |

## Resolution

Approval mutation uses optimistic concurrency:

```json
POST /v1/approvals/{id}/approve
{"expected_version": 0}
```

The commit uses a version predicate (`state='pending' AND version=? AND
expires_at_ns > now`); exactly one row must update. The first valid
resolution wins; later attempts receive `409 APPROVAL_CONFLICT`.
Approval authorization: active approver, group intersection with
`approver_groups`, not expired, correct version, no double resolution, and
(optionally) no self-approval. The daemon flag `--forbid-self-approval`
enables the separation-of-duty check; the TUI flow allows a developer to
approve their own agent's request by default.

## Policy changes while pending (A06)

When a resolution arrives and the active bundle hash differs from the
approval's recorded bundle hash, the approval is transit `superseded` and
the resolution is rejected. An approval never outlives its policy version.

## Receipts

Signed (Ed25519) after the approval transaction commits. Claims:

```
version, receipt_id, approval_id, decision_id,
request_hash[32], policy_bundle_hash[32], effect, issued_at, expires_at, nonce[16]
```

Consumers:
1. fetch the public key from `/v1/keys`;
2. verify the signature over the exact `claims_bytes`;
3. compare the request hash to the executed action;
4. confirm the effect is `allow` and times are valid;
5. consume once via `POST /v1/receipts/{id}/consume` (at-most-once; replay
   returns 409).

## Events

Approval events stream on `/v1/approvals/stream` (SSE):
`approval.created`, `approval.updated` (`approved`/`denied`/`expired`),
`approval.consumed`, plus heartbeats. Reconnects resume with `Last-Event-ID`;
a full snapshot replaces local state when history is unavailable. Slow
clients are dropped, never allowed to block resolution.

## Quorum

A rule's `approval.quorum` (default 1) sets how many distinct approvers must
approve before the request is authorized. Each approve records a vote
(`approval_votes`, one per approver); the approval stays `pending` until
`quorum` votes are recorded, then transitions to `approved` and issues the
receipt in one transaction. A single **deny is a veto** and resolves
immediately. Re-approving does not double-count an approver. Approver groups,
the version predicate, and `--forbid-self-approval` all still apply to every
vote.

## Scopes and grants

`allow_scope` decides how far an approval reaches:

| scope | receipt binding | extra authorization |
| --- | --- | --- |
| `exact_request` | exact request hash | none |
| `operation` | exact request hash | a durable grant for the same principal+agent+operation+environment |
| `session` | exact request hash | a durable grant for the same principal+agent+session |

On approval, a scoped approval mints a **grant** (table `grants`) that expires
with the approval. A later request whose operation (or session) matches is
authorized without a new approval: the decision is returned as
`allow` with `reason_code: POLICY_GRANT_COVERED` and a `grant_id`, and is
audited like any other decision. Grants are reaped by the expiry sweep.

Grants exist for the single-user case (`raidd --solo`), where a human has no
second reviewer and re-approving every similar command is pure friction. They
are operation/session-scoped and time-boxed; the destructive tier should stay
on `exact_request`. `raid grants` lists active grants (`GET /v1/grants`) and
`raid grants revoke <id>` ends one immediately (`DELETE /v1/grants/{id}`).

## Journal

`GET /v1/journal?limit=N[&kind=decision|approval|audit]` (and `raid log`) returns
a merged, time-ordered activity log of decisions, approvals, and audit events —
the "what did my agent do" view for an individual engineer.

## Receipt status

`GET /v1/receipts/{id}` returns a receipt's status (`issued`/`consumed`/
`expired`) plus its `key_id`, `signature`, and `claims_bytes`, so a consumer can
verify it independently with `raid receipt verify <id>` (or offline with
`--receipt <file> --pubkey <hex>`) without trusting the daemon.