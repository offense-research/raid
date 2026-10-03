# Open Source and Pricing

The MVP spec's position (section 20): the open-source repository ships the
full deterministic engine and approval experience, and Offense charges for
**operating and coordinating** Raid — not for correcting insecure behavior.
This document translates that into mechanics.

## What ships free (the trust anchor)

Everything a single team needs to run Raid forever without Offense:

- Full deterministic policy engine (CEL) and policy tooling
- Local approvals, the Bubble Tea TUI, SQLite storage, signed receipts
- Local audit log, SSE events, execution-proxy integration, SDKs and API schemas
- The Jev adapter with a user-supplied TypeSafe key
- **All security fixes**, to every supported version

Value equation for customers: Raid's authority decisions are auditable,
deterministic, and verifiable locally. The paid product must never cast
doubt on the free core — it coordinates what a single node cannot.

## What the hosted product charges for

Each row is something a single-node open-source install structurally cannot
provide well, which keeps the boundary honest:

| Capability | Why it is not in the OSS core |
| --- | --- |
| Org-wide policy distribution (signed bundles) | Needs a fleet + CDN + trust anchors |
| SSO / SCIM provisioning | Identity integrations per org |
| Slack / Teams / email / mobile approvals | Multi-channel push infrastructure |
| Approver schedules + escalation | Operator policy, not engine semantics |
| Multi-approver quorum / org approvals | Already schema-ready; UI+coordination live in Cloud |
| Long-term audit retention + compliance exports | Storage + access controls at org scale |
| Policy simulation against historical decisions | Needs the history store |
| Centralized Jev credentials, budgets, calibration | Shared metered access to a paid model API |

## Pricing mechanics

**Recommended: per-seat SaaS with a usage-bounded semantic tier.**

1. **Free — Indie tier.** Self-hosted OSS forever. Optional anonymous usage
   telemetry (opt-in, no policy/request content) so product can see shape:
   rule counts, decision rates, approval rates.
2. **Paid — Team/Org tier (per seat / month).** Hosted management +
   coordination features above, plus SSO/SCIM, mobile/Slack approvals, and
   signed bundle distribution to self-hosted daemons. The local daemon keeps
   enforcing even offline (cached signed bundle) — so Raid cloud only ever
   *distributes* policy; it never becomes a request-time dependency for
   safe local reads.
3. **Metered add-on — Jev evaluations.** Jev is the one genuinely
   variable-cost component (TypeSafe per-call API). Sell metered semantic
   evaluations from the cloud (centralized key, budgets, calibration) at
   cost-plus, priced per 1,000 evaluations or a monthly evaluation cap.
   Nobody pays for a deterministic decision — only for model judgment, and
   only when policy explicitly requests it.
4. **Support/SLA retainer** for teams who run Raid in their product's own
   agent loop (on-call, security-fix hotline, custom policy review).

Pricing guardrails that protect the project:

- Never matrix-gate the deterministic engine, CEL, receipts, or the TUI.
  Removing safety from free users to sell back the same safety is the exact
  anti-pattern this repo exists to avoid ("charge for not-insecure", never
  "charge to be secure").
- The free tier must remain unprompted-fast; hosted signup must never make
  the local path slower (unix socket, no phone-home on the decision path
  unless the operator explicitly opts into signed-bundle distribution).
- Keep the protocol cloud-precludable (spec 3.3): local enforcement with a
  cached signed bundle is designed in; do not add host-cloud coupling
  without keeping an offline migration path.

## Why this works for Raid specifically

- **Trust asymmetry is the product.** A policy engine's value grows with
  auditability. Fully open deterministic code + verifiable signed receipts
  makes "why did this run" answerable; the hosted layer coordinates
  *multiple* humans and *multiple* agents, which is coordination cost, not
  safety rent.
- **The demonstration is the funnel.** The repo's demo (allow → approve →
  signed receipt → consume → replay-409) is repeatable in ten minutes; the
  natural upgrade is "now do that across your org, from Slack, with SSO".
- **Jev metering is honest usage-based pricing.** The only marginal cost in
  the stack is the semantic model call; charging for consumed evaluations is
  cost-transparent and scales with value (the 1% of actions that genuinely
  need judgment).
- **Enterprise requirements (SSO/SCIM, audit, SLA) are coordination**, and
  enterprises pay for coordination. Restricting those from OSS does not
  reduce anyone's safety; it reduces the free product's *convenience surface*,
  which is exactly the open-core line.

## Operating notes

- License: Apache-2.0, DCO-signed contributions (`make` docs in
  `CONTRIBUTING.md`), Apache file headers on all sources.
- Telemetry: opt-in, content-free, only in the hosted tier.
- Compliance: local audit events use the same schema the cloud ingests, so
  migrating from OSS to hosted keeps history (see `docs/approvals.md` and
  the `api/` schemas).
- First commercial milestone (suggested): signed bundle distribution +
  Slack approvals + SSO behind a login wall; start charging at a pilot with
  3 design partners (matches the MVP acceptance criterion of 3 teams
  replacing blanket "confirm every tool call" prompts).