# Raid

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

## Quick demo (10 steps from the spec)

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
- `core/policy` — schema, loader, CEL compiler, index, evaluator, diff
- `core/decision` — engine, effect combination, semantic combine
- `core/approval` — model, state machine, durable service, receipts
- `core/signing` — Ed25519 keys and signed claims
- `core/store` — SQLite WAL schema + migrations, audit modes
- `core/stream` — bounded SSE hub and subscriber
- `core/api` — HTTP/Unix-socket surface and error model
- `core/tui` — Charm Bubble Tea v2 approval UI + sanitizer
- `core/jev` — TypeSafe System One adapter, sanitizer, thresholds, cache
- `core/server` — daemon boot
- `pkg/raidclient` — Go client for CLI / TUI / Surge
- `api/` — OpenAPI and JSON schemas · `docs/` — threat model, policy
  language, approvals, Jev, performance · `examples/` — demo policy + requests

## Configuration

`raidd` flags: `--socket`, `--db`, `--policy`, `--key`, `--tcp`,
`--uid`, `--approver <subject:groups>`, `--forbid-self-approval`.
Environment: `RAID_SOCKET`, `RAID_APPROVER`, `RAID_DB`, `RAID_KEY`,
`TYPESAFE_API_KEY` (enables the Jev adapter), `RAID_SESSION`.

## Security

See `docs/threat-model.md` for the invariants and accepted MVP limitations.
The core position: Raid can restrict Surge, never grant what Surge did not
already authorize, and a model is never the arbiter of authority.