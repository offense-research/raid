# Raid Policy Language

`apiVersion: offense.dev/raid/v1alpha1`, `kind: PolicyBundle`.

## Document shape

```yaml
apiVersion: offense.dev/raid/v1alpha1
kind: PolicyBundle
metadata: {name: demo-default, revision: 7}
defaults: {effect: deny}
rules: [ ... ]
semantic_guard: { ... }   # optional
tests: [ ... ]            # optional, activation gate
```

Activation (boot or `raid policy activate`) runs: strict YAML decode (unknown
keys rejected), schema checks, duplicate-rule rejection, CEL compilation with
type checking, index construction, embedded test execution, canonicalization,
and SHA-256 hashing. **Activation fails if any embedded test fails.**

## Rules

Each rule has static `match` filters and a CEL `when` condition:

```yaml
- id: production-label-write
  match:
    providers: [github]
    operations: [github.issues.add_labels]
    environments: [production]
  when: >-
    arguments.labels.all(label,
      label in ["bug", "needs-triage", "security-review"])
  effect: require_approval
  approval:
    approver_groups: [maintainers]
    quorum: 1            # distinct approvers required (>= 1)
    ttl: 5m              # 30s..30m
    allow_scope: exact_request   # exact_request | operation | session
```

`allow_scope` controls how far an approval's authority reaches:

- `exact_request` (default, strongest) — the signed receipt is bound to the
  exact request hash; a retry of a *different* request is rejected.
- `operation` — approving also mints a durable, time-boxed grant covering the
  same principal+agent+operation+environment until the approval expires.
- `session` — the grant covers the same principal+agent+session regardless of
  operation.

Grants reduce re-approval friction for a single engineer driving an agent
(see `raidd --solo`). Keep the destructive tier on `exact_request`.

- A rule matches when **every non-empty** `match` field contains the
  request's value (AND across fields, OR within a field) **and** the `when`
  condition evaluates to `true`. An empty `when` matches always.
- `match` fields drive the immutable candidate index; `when` runs only over
  indexed candidates.

## Rule combination

`DENY > REQUIRE_APPROVAL > ALLOW > default`. All matching rule IDs are
recorded; there is no first-match. A policy evaluation error is never
`false`: it produces `POLICY_EVALUATION_ERROR` and a deny.

## CEL environment

Exactly five variables, nothing else:

```
principal   principal.subject_id agent_id session_id runtime groups trust_level revision
action      action.provider operation effect
resource    resource.type id environment attributes(map[string]string)
arguments   arguments.<any>         # typed values, see below
context     context.timestamp source_product source_version source_request_id task_summary interactive
```

- No network, filesystem, clock, env, randomness, or side effects.
- Unknown variables/functions are compile errors (activation fails).
- The `when` expression must type-check to `bool`.

## Guardrail attributes

`resource.attributes` is a free `map[string]string`, so an adapter can add
classifications without a schema change. The shared classifier in
`integrations/lib/raidlib.py` emits a fixed set for every tool call, and
Raider's `internal/raider/classify.go` mirrors it, so one policy works under
every adapter.

| attribute | true when | intended use |
|---|---|---|
| `destructive` | the command is irreversible or wipes a system path | deny outright |
| `exfil` | a credential path and a network verb appear in one command | deny outright |
| `protected_branch` | the target is `main`/`master`/`release`/... | confirm history rewrites |
| `secret` | the target path is `.env`, a private key, a credential store | confirm before touching |
| `egress` | the call sends data to the network | pair with the two below |
| `outbound_secret` | an outbound payload carries a recognised credential *value* | deny outright |
| `tainted_egress` | the session handled credential material and this call egresses | confirm |
| `untrusted_source` | the session read outside content and this call changes state | confirm |
| `session_tracked` | the session ledger was readable | see below |

Attributes are always present as the strings `"true"`/`"false"`, so a policy can
write `resource.attributes.egress == "true"`. Keep the `has(...)` guard when a
bundle may also run under an adapter that predates a given attribute.

`egress`, `outbound_secret`, `tainted_egress` and `untrusted_source` are
**session-scoped**. raidd itself is stateless, so the *adapter* keeps a small
per-session taint ledger — keyed on `RAID_SESSION`, or principal+agent+cwd when
the host sets nothing — and carries the conclusion in the request. The ledger is
read before a call's own effects are recorded, so a credential read or an
untrusted fetch taints what happens *next*, never the call that did it. Entries
expire after 12 hours.

An unreadable ledger is treated as fully tainted — fail closed — and
`session_tracked` is `"false"`, which lets a policy tell "clean session" apart
from "no session tracking in effect" rather than trusting a state it cannot see.

Because `DENY` outranks every other effect, a `deny` on any of these attributes
cannot be shadowed by an `allow` elsewhere in the bundle.

## Typed arguments

Values are a closed union: `string`, `int64`, `uint64`, `bool`, `decimal`
(text with validated scale — no floats), `timestamp` (RFC 3339), `duration`,
`list`, `map`. Plain JSON is normalized to the union; the typed wrapper
`{"type": "...", "value": ...}` is also accepted.

Floats are forbidden for money and identity values at the encoding level;
inside the CEL environment decimals become float64 because CEL-Go has no
decimal type. Exactness is preserved in the typed value layer and the
request hash.

## Built-in hard rules (before policy, cannot be overridden)

Unsupported schema → deny; malformed principal → deny; invalid operation
format → deny; request too large → deny; missing active bundle → deny;
untrusted approver identity → deny.

## Embedded tests

```yaml
tests:
  - name: reader can list issues
    input: testdata/reader-list.json    # path relative to the bundle file
    expect:
      effect: allow
      matched_rules: [github-issue-reads]
```

## Semantic guard (optional)

`semantic_guard` configures Jev; modes `off` (default), `shadow`, `enforce`.
In `enforce`, the model must be pinned (no `jev-latest`). Jev can only
escalate: final = `max(deterministic, semantic)`; deterministic deny skips
Jev entirely.

## Diff

`raid policy diff old.yaml new.yaml` describes authority changes:
`WIDENS AUTHORITY`, `ADDS APPROVAL`, `REMOVES DENY`, `RESTRICTS`, and
`REVIEW_REQUIRED` when equivalence cannot be proven statically (e.g. the
CEL text changed).
## Natural-language authoring (via OpenRouter)

`raid policy from-language --statement "<permissions>" --key <OPENROUTER_KEY>`
drafts a PolicyBundle from a plain-English description instead of writing YAML
by hand. A constrained LLM (OpenRouter chat/completions, default
`openrouter/auto`) emits a single YAML document; the CLI then runs that draft
through the **identical deterministic gate as a file on disk** — strict YAML
decode, schema checks, CEL compilation — and only writes (`--out FILE`) or
activates (`--activate`) the draft if it validates and compiles.

The model is an authoring aid, not an authority: a draft can never grant or
loosen beyond what passes the deterministic compiler, and a failing draft is
discarded with the error reported. The key is read from `OPENROUTER_API_KEY`
or `--key`; `--model` overrides the model. The default transport performs a real
HTTPS request to the endpoint (OpenRouter by default) with a bounded deadline
and response size, fails closed on any error, and sends the key only to that
endpoint. A deployment can swap the transport via `nlpolicy.SetTransport`
(`docs/jev.md` describes the analogous Jev seam).
