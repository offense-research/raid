# Security Policy

## Reporting a vulnerability

Raid is a policy and approval engine: a vulnerability here can weaken the
authorization boundary around agent actions. Please report issues privately
and do not file a public issue first.

- **Email** `<security@offense.dev>` (or your Offense security contact)
- **Include** — repository commit you tested, the failing scenario (request,
  policy, and expected vs actual decision), and whether a receipt or
  approval was involved.
- **Do NOT include** — live API keys, agent session tokens, private policy
  files, or production data. Reproduce with synthetic content.

We will acknowledge within 48 hours and send a fix plan within 7 days.
Critical authorization issues are prioritized over features.

## Supported versions

| Version | Support |
| --- | --- |
| HEAD (`main`) | Best effort, security fixes on merge |
| Tagged releases | Security fixes for the latest minor |
| Older tags | No guaranteed backports |

## Bounty / disclosure

No bug bounty program yet. Security researchers may request credit in the
release notes; responsible disclosure is always credited in `CHANGELOG.md`.

## Security-relevant areas

Issues in any of these are treated with highest priority:

- `core/canonical` — request decoding and request-hash binding
- `core/policy` — CEL compilation and evaluation (fail-closed behavior)
- `core/decision` — effect combination and semantic escalation
- `core/approval`, `core/signing` — approval durability, receipt signature
  and consumption
- `core/tui` — terminal sanitization of untrusted fields
- `core/jev` — data minimization of semantic state
- `core/authn`, `core/api` — approver identity and API authorization

See `docs/threat-model.md` for the full invariant list (RAID-SEC-001..015).