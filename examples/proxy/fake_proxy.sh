#!/usr/bin/env sh
# Fake execution proxy: drives the spec 1.2 demo against a running raidd.
# Usage: RAID_SOCKET=/tmp/raid-demo/raid.sock ./fake_proxy.sh
set -e
SOCK="${RAID_SOCKET:-/tmp/raid-demo/raid.sock}"
HERE="$(cd "$(dirname "$0")" && pwd)"

req() {
  curl -s --max-time 5 --unix-socket "$SOCK" -X POST http://localhost/v1/decisions \
    -H 'Content-Type: application/json' --data @"$HERE/$1"
}

echo "== 1. the proxy submits an issue read (should ALLOW, no prompt)"
req reader-list.json | head -c 200; echo

echo
echo "== 2. the proxy submits a production label write (should REQUIRE_APPROVAL)"
RESP=$(req label-write-prod.json)
echo "$RESP" | head -c 220; echo
APR=$(echo "$RESP" | sed -n 's/.*"approval":{"id":"\([a-z0-9_]*\)".*/\1/p')

echo
echo "== 3. the approval appears in the queue"
curl -s --max-time 5 --unix-socket "$SOCK" http://localhost/v1/approvals | head -c 120; echo

echo
echo "== 4. the developer approves once (TUI 'y' / noninteractive)"
curl -s --max-time 5 --unix-socket "$SOCK" -X POST "http://localhost/v1/approvals/$APR/approve" \
  -H 'Content-Type: application/json' -H "X-Raid-Approver: ${RAID_APPROVER:-$(id -un)}" \
  --data '{"expected_version":0}' | sed 's/,"signature":"[^"]*"/,"signature":"<sig>"/' | head -c 340; echo

echo
echo "== 5. a deterministic deny never prompts"
req delete-repo.json | head -c 160; echo