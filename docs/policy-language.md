# Raid Policy Language

`apiVersion: offense.dev/raid/v1alpha1`, `kind: PolicyBundle`.

## Document shape

```yaml
apiVersion: offense.dev/raid/v1alpha1
kind: PolicyBundle
metadata: {name: surge-default, revision: 7}
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
    quorum: 1            # MVP supports quorum 1 only
    ttl: 5m              # 30s..30m
    allow_scope: exact_request
```

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