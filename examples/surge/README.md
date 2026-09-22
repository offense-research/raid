# Fake Surge adapter

This directory holds the demonstration Surge integration: normalized request
documents plus a scripted client that behaves exactly like Surge's Raid
layer (step 6-13 of the spec call order).

## Requests

- `reader-list.json` — a github issue read (staging, engineering group): the
  deterministic policy allows it immediately, no approval.
- `label-write-prod.json` — a production label-add: deterministic policy
  requires approval.
- `delete-repo.json` — repository deletion: deterministic deny.

## Call order (spec 11.2) as exercised here

1. (Surge authenticates the agent — out of band)
2. Decode + normalize (raidclient sends the JSON document)
3. Surge grant check (out of band; Raid can only restrict)
4. `POST /v1/decisions`
5. allowed → Surge dispatches
6. denied → Surge records the denial
7. approval required → Surge persists its waiting state, polls
   `GET /v1/decisions/{id}/wait`
8. human approves (TUI `y` or `raid approval approve`)
9. Surge verifies the receipt:
   - signature over `claims_bytes` against `/v1/keys` public key
   - request hash == executed action's canonical hash
   - effect `allow`, times valid
10. `POST /v1/receipts/{id}/consume` (once)
11. Surge rechecks its grant, then dispatches

## Script

```sh
SOCK=${RAID_SOCKET:-/run/offense/raid/raid.sock}
req() { curl -s --unix-socket "$SOCK" -X POST http://localhost/v1/decisions \
  -H 'Content-Type: application/json' --data @"$1"; }

req reader-list.json          # -> allow
req delete-repo.json          # -> deny (never prompts)
req label-write-prod.json     # -> require_approval (+ approval id)
curl -s --unix-socket "$SOCK" -N http://localhost/v1/approvals/stream &
curl -s --unix-socket "$SOCK" -X POST http://localhost/v1/approvals/APR_ID/approve \
  -H 'X-Raid-Approver: usr_omar' --data '{"expected_version":0}'
```

Receipt generation and verification are covered automatically by
`core/api/e2e_test.go`.