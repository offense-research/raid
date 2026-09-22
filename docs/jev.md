# Raid Jev Integration (TypeSafe System One)

## What Jev is for

Jev answers atomic semantic questions that deterministic policy cannot
express: intent mismatch, credential exposure, prompt-injection indicators,
impact, ambiguity. It never answers arithmetic, membership, identity, or
rate questions — those are deterministic.

## Authority rule

`final = max(deterministic, semantic)` under `allow < require_approval <
deny`. Jev is advisory and escalation-only (RAID-SEC-002). No Jev answer can
create allow authority absent a deterministic allow, and a deterministic
deny returns before any Jev call (J01).

## Execution strategy (spec 7.6)

1. Fixed checks.
2. Deterministic policy.
3. Deny → return immediately (no Jev, no approval).
4. No matched semantic guard → return.
5. Base `require_approval` with no deny ceiling → skip Jev.
6. Otherwise: one request, all atomic questions.
7. Thresholds in Go; combine monotonically.

## Sanitizer (data minimization)

State is built from an allowlist: principal identity/runtime/trust level,
provider/operation/effect, resource type/environment, task summary, and
allowlisted arguments. Anything classified `secret` or `sensitive` is never
serialized. Planted secret canaries are scrubbed from the final state as a
defense-in-depth backstop (J08).

## Failures never allow

| Failure | Result |
| --- | --- |
| Timeout / 429 / 5xx | configured `failure_effect`, minimum `require_approval` |
| Invalid JSON | `require_approval` or `deny` |
| Missing / invalid probability | escalation |
| Transport unavailable | escalation |

Jev failure never silently falls back to the deterministic allow when the
policy required semantic evaluation.

## Modes

- `off` — no evaluator work.
- `shadow` — sends the request, records evidence (decision gains a
  `semantic` summary), outcome unchanged (J11).
- `enforce` — escalation applies; model must be pinned.

## Calibration path

Labelled dataset → offline thresholds → shadow → false-positive/negative
review → owner activation → version-pinned enforcement. Each run records:
question set, model version, thresholds hash, sanitized state hash, answers
and probabilities, latency, and the final escalation (raw state is not
stored).

## Cache

Optional; keyed by SHA-256(sanitized state || question set || model ||
thresholds hash). Successful pinned-model responses only; TTL 60s; a
question-set or policy change always misses (J12).

## Circuit breaker

Bounded concurrency (default max 32, per-source limits), no automatic
retries in enforcement mode, and a breaker that opens after a configured
failure threshold. An open breaker yields the configured escalation
immediately.