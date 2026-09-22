# Raid Performance

## Contract

Measured on a 2-vCPU, 2 GiB Linux VM, release build, warmed bundle. The MVP
promise: a normal local call completes in under one millisecond; the Surge
read path adds less than 2 ms p99.

| Path | Target p50 | Target p99 | Hard timeout |
| --- | --- | --- | --- |
| Fixed validation only | < 25 µs | < 100 µs | 1 ms |
| Indexed CEL evaluation | < 100 µs | < 1 ms | 5 ms |
| Surge→Raid over unix socket | < 250 µs | < 2 ms | 10 ms |
| Local decision + event enqueue | < 500 µs | < 3 ms | 15 ms |
| Jev semantic evaluation | measure | < 500 ms | 650 ms |
| TUI event propagation | < 20 ms | < 100 ms | 1 s |
| Signed approval after keypress | < 10 ms | < 50 ms | 250 ms |

Jev numbers are external-service targets, measured against pinned model
versions before enforcement is enabled.

## Design for speed

- Policies compile once at activation into immutable bundles; the active
  bundle is an `atomic.Pointer` swapped in one step. One request sees
  exactly one bundle version.
- Candidate selection is index-only (no CEL) until a rule passes its static
  match fields.
- No SQLite reads on the deterministic path; decisions are written per
  audit mode; approvals and receipt consumption are synchronous.
- The TUI renders from in-memory snapshots; all network I/O runs in
  `tea.Cmd` goroutines so `Update` never blocks.
- Bounded queues/groups everywhere: event subscriber queue (64), hub
  subscribers (256), semantic concurrency (32).

## Audit modes

| | strict | balanced |
| --- | --- | --- |
| Durability | fsync per decision commit (synchronous=FULL) | OS write ack, group commit (synchronous=NORMAL) |
| Decision fsync before response | yes | no |
| Approvals / receipt consumption | always synchronous | always synchronous |
| Documented loss window | none | final event tail on catastrophic host failure |

## Benchmarks

Run:

```sh
env -u GOMOD go test -bench=Benchmark -benchmem -v ./core/bench
```

Sample numbers (this machine: 12th Gen Intel i5-12600KF, Go 1.26.3, 1 rule /
10,000-index entries / warmed):

| Benchmark | ns/op (per operation) |
| --- | --- |
| BenchmarkNormalizeAction | ~12,900 (1,000 decodes/op) |
| BenchmarkCandidateIndexExact | ~39 per lookup (10k rules) |
| BenchmarkCELSingleRule | ~8,900 (1k evals/op) |
| BenchmarkCELTenCandidates | ~7,600 |
| BenchmarkDecisionEndToEndStrictAudit | ~2,950,000 (100 decisions/op) |
| BenchmarkDecisionEndToEndBalancedAudit | ~68,200 |
| BenchmarkReceiptSign | ~25,600 (1k signs/op) |
| BenchmarkReceiptVerify | ~30,700 |
| BenchmarkTUIRender100 | ~185,000 |
| BenchmarkTUIRender10000Virtualized | ~986,000 for 100 renders (≈9.9 ms/render, viewport-windowed) |

Interpretation: the deterministic in-process path (decode + indexed CEL +
decision) sits around 10–25 µs per call; the strict-audit end-to-end path is
dominated by fsync. Benchmark discipline: record CPU, Go version, rule
count, candidate count, argument size, and audit mode — never publish an
empty-policy microbenchmark as end-to-end latency.

## Soak

Run the in-process engine at 10,000 deterministic evaluations/second for 30
minutes; confirm stable heap, goroutine count, and queue depth. The engine
allocates per request during decode and hash (maps for activation); the
candidate lookup itself is allocation-free after request decoding (P08).