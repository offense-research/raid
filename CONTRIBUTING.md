# Contributing

Thanks for contributing to Raid. This project is a security-sensitive policy
engine: deterministic checks decide whether an agent may act. Small,
verifiable changes beat clever ones.

## Before you start

- Read `docs/threat-model.md` (RAID-SEC-001..015) and `docs/performance.md`.
- Open an issue (or comment on one) for non-trivial design change. The
  maintainers review authority semantics carefully: Raid can only restrict,
  never silently widen, what a caller already authorized.

## Development environment

Go 1.26+ only — no other toolchain is required (YAML, CEL, SQLite, and
Bubble Tea are modules). The test suite and benchmark suite run offline:

```sh
go test            # all unit + integration suites
go test -bench=Benchmark -benchmem -v ./core/bench
go build -o raid ./main && ln -sf raid raidd
```

CI runs exactly these commands. Do not add dependencies without a review:
each new module is trust, supply-chain surface, and startup cost on the
agent hot path.

## Code conventions

- Go idioms: struct fields are package-private; public surface is
  Capitalized accessors and methods (see `core/canonical`).
- Raw string literals (backticks) do not process `\n`/`\t` escapes — only
  use them for text that has no escapes; JSON/HTTP/SSE framing needs regular
  strings with explicit escapes.
- Never loosen a fail-closed default to make a test pass. A test that
  demands an insecure outcome is a product bug, not a reason to change code.
- No reflection in the per-rule evaluation loop; no unbounded queues or
  goroutines per request.
- New behavior needs a reproduction test that fails before the fix (P/J/A/U
  numbering in `docs/` maps to the spec test plan).

## Testing expectations

- `go test` must pass (use `-count=1` to bypass the suite cache when
  results matter).
- Benchmark changes must follow `docs/performance.md` discipline: record
  CPU, Go version, rule counts, candidate counts, argument size, audit
  mode — and never present an empty-policy microbenchmark as end-to-end
  latency.
- A change that alters the request schema, request hash, receipt claims, or
  policy schema is a **breaking change**: update the OpenAPI/JSON schemas in
  `api/`, the canonical tests, and `CHANGELOG.md`.

## Pull requests

- One logical change per PR, with tests and a `CHANGELOG.md` entry.
- Describe impact on the decision semantics (what restriction level changed
  and why).
- No force-pushes after review; rebase conservatively.

## License and DCO

Contributions are accepted under the repository license (Apache-2.0). Sign
off commits (`git commit -s`) to certify you wrote or may legally
contribute the change.

## The trust rule

If an approach would reduce how much code an auditor must trust, prefer it.
Raid earns its place by being small, deterministic, and auditable — not by
being clever.