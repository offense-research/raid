---
name: raid
description: Use to install, provision, boot, and operate the Raid policy and approval engine (raidd daemon + raid CLI). Covers single-binary build, deployment directory, approver seeding, starter policy activation, boot readiness, demo and troubleshooting. Use when a host needs a local policy/approval layer for agent actions, or when an existing raidd socket is unreachable or misconfigured.
metadata:
  version: "0.1.0-draft"
  compatibility: Requires Go 1.26+ and curl. Data lives under /var/lib/offense/raid by default.
---

# Raid

Raid is a Go policy and approval engine. An agent submits a normalized JSON
action; Raid evaluates precompiled CEL policy and returns `allow`, `deny`, or
`require_approval`. Approvals appear in a terminal UI; approval produces a
signed, single-use receipt bound to the exact request.

The one command path is `tools/raid-provision.sh` from the Raid repository; it
builds the binary, prepares the data directory, boots `raidd`, and runs a
verifiable demo. Every step below is also doable by hand.

## Prerequisites

- Go 1.26+ (`go version`) and `curl`.
- The Raid repository, or a clone of it.
- Go module resolution uses the local `go.sum`; do not edit it. If a build
  reports `missing go.sum entry`, run `go get -u ./...` at the repo root,
  then rebuild (go.sum is committed; do not ignore it).

## 1. Install

```sh
cd <raid-repo>
go build -o raid ./main
ln -sf raid raidd        # argv[0]-dispatched daemon entry
```

`raidd` and `raid` are the same binary; `raidd` selects server mode by its
name. Verify: `./raid version` and `./raidd --help`.

## 2. Provision (recommended)

```sh
RAID_PREFIX=/var/lib/offense/raid sh tools/raid-provision.sh
```

Defaults: socket `$PREFIX/raid.sock`, DB `$PREFIX/raid.db`, Ed25519 seed
`$PREFIX/ed25519.seed` (generated on first boot), policy
`examples/policies/surge-default.yaml`, approver `<user>:maintainers,admins`,
socket UID allowlist `0 <uid>`. All overridable: `RAID_SOCKET`, `RAID_DB`,
`RAID_KEY`, `RAID_POLICY`, `RAID_APPROVER_SUBJECT`, `RAID_UID`,
`RAID_APPROVER`. The script ends by running `raid doctor` and a three-case
demo (allow, require_approval → approve, deny).

## 3. Provision by hand

```sh
mkdir -p /var/lib/offense/raid
./raidd --socket /var/lib/offense/raid/raid.sock \
        --db     /var/lib/offense/raid/raid.db \
        --policy examples/policies/surge-default.yaml \
        --key    /var/lib/offense/raid/ed25519.seed \
        --uid 0 --uid "$(id -u)" \
        --approver "$(id -un):maintainers,admins" &
export RAID_SOCKET=/var/lib/offense/raid/raid.sock
export RAID_APPROVER="$(id -un)"
./raid doctor
```

Key points:

- The policy is compiled and its embedded tests run at boot; a policy that
  fails compilation or any embedded test aborts the daemon — read
  `raidd.log`.
- The signing key seed is generated automatically when missing (mode 0600).
  Deleting it invalidates outstanding receipts.
- `--uid` allowlists unix-socket peers. Include `0` if agents run as root;
  omit it on shared hosts.
- `--forbid-self-approval` adds separation of duty (rejects the requesting
  subject as approver).
- `TYPESAFE_API_KEY` (env) enables the Jev adapter when a policy declares a
  `semantic_guard`; without a key the guard is effectively `off`.

## 3b. Solo mode (single engineer, no root)

For one person driving a coding agent there is no second reviewer. `--solo`
sets the unprivileged posture in one flag:

```sh
./raidd --solo &                 # XDG state dir, self-approval, solo-dev-safe preset
export RAID_SOCKET="${XDG_STATE_HOME:-$HOME/.local/state}/offense/raid/raid.sock"
./raid doctor
./raid log                       # activity journal (decisions/approvals/audit)
./raid grants                    # active scoped confirmations
```

- Defaults: socket/db/key under `RAID_STATE_DIR` (or
  `$XDG_STATE_HOME/offense/raid`, else `~/.local/state/offense/raid`); the local
  user is auto-seeded as their own approver; `forbid-self-approval` is off.
- Policy defaults to the `solo-dev-safe` preset (deny-first guardrails +
  one-key confirmations). Override with `--policy-preset review-only|ci-agent`
  or `--policy <file>`.
- List/write presets: `raid policy presets`,
  `raid policy init --preset <name> [file]`.
- Consequential, low-risk ops can use `allow_scope: operation` so one approval
  mints a time-boxed grant instead of re-approving every invocation. Keep the
  destructive tier on `exact_request`.

## 3c. Gate a coding agent

With a daemon running, wire an agent's tool calls through Raid (adapters share
`integrations/lib/raidlib.py`):

- Claude Code: `cd integrations/claude-code && RAID_ENV=development ./install.sh`
  (writes a `PreToolUse` hook + MCP server into `.claude/settings.json`).
- Cursor: copy `integrations/cursor/hooks.example.json` to `~/.cursor/hooks.json`
  and point the command paths at the checkout.

`require_approval` cannot block a hook while a human decides, so the hook
declines the call and the human approves out-of-band
(`raid approval approve <id> --expected-version 0`), then the agent retries; the
receipt is bound to the exact request, so a different retry is rejected.

## 4. Readiness and operation

- Check: `raid doctor` → `raidd: reachable` + active bundle JSON.
- Eval: `raid decision eval --request examples/surge/reader-list.json`.
- List approvals: `raid approval list` (JSON; the TUI is `raid approve`, TTY
  required — non-TTY exit is an explicit error by design).
- Approve: `raid approval approve <id> --expected-version 0` (read the
  `version` field first; conflicts return 409 with the current state).
- Policy workflow: `raid policy validate <file>` → `raid policy test <file>`
  → `raid policy diff <old> <new>` → `raid policy activate <file>`.
  Activation is admin-gated: the caller must be an active approver in the
  `admins` group.
- Endpoints (all JSON, unix socket): `POST /v1/decisions`,
  `GET /v1/decisions/{id}/wait`, `GET /v1/approvals`,
  `POST /v1/approvals/{id}/approve|deny|cancel`,
  `GET /v1/receipts/{id}`, `POST /v1/receipts/{id}/consume`,
  `GET /v1/approvals/stream` (SSE),
  `GET /v1/policies/active`, `POST /v1/policies/validate|activate`,
  `GET /v1/keys`, `GET /v1/journal`, `GET /v1/grants`, `DELETE /v1/grants/{id}`.
- Quorum: `approval.quorum > 1` records a vote per approver and stays `pending`
  until enough approve; one deny is a veto. Verify a receipt independently with
  `raid receipt verify <id>`.

## 5. Verification

For an install to count as provisioned, demonstrate, not just report:

1. `raid doctor` shows the active bundle (id + hash + rule count).
2. Reader request → `effect: allow` (no prompt).
3. Label-write request → `effect: require_approval` + approval object.
4. Approve at the listed version → approval `state: approved` + a receipt
   with `key_id`, `signature`, and `claims_bytes`.
5. Consume the receipt once: `POST /v1/receipts/{id}/consume` →
   `{"consumed":true}`; replaying returns HTTP 409.
6. Delete request → `effect: deny`.

Do not report the build alone as provisioning.

## 6. Troubleshooting

- Socket file exists but `curl` is refused: a stale daemon owns the path.
  Kill it, remove the socket and database-owned state, reboot.
- `permission denied` on the socket: peer UID not in `--uid` allowlist.
- Daemon exits immediately at boot: read the log — usually a policy compile
  or embedded-test failure, or a locked DB (another raidd running).
- Policy changes while approvals are pending: resolutions are rejected with
  409 and the approval is superseded. Re-prompt the agent.
- No approver: the `admins`/`maintainers` group require seeding via
  `--approver subject:groups` at boot.
- Approval propagation: `GET /v1/decisions/{id}/wait` long-polls; TUI
  subscribers resume from `Last-Event-ID` and replace state on gaps.

## 7. Guardrails (do not bypass)

- Never activate a policy without `raid policy validate` + embedded tests
  passing (activation itself runs them; a failed bundle aborts).
- Never approve without seeing the exact request/version; the receipt binds
  the canonical request hash — an altered request fails verification.
- Do not create secrets, or edit the seed, DB, or policy to "make the demo
  pass". Raid fails closed; a missing bundle denies.
- Do not expose the TCP listener (`--tcp`) without `--tcp-token` and/or TLS:
  it is a network surface, unlike the peer-UID-authenticated Unix socket. For
  remote use set `--tcp-token` (or `RAID_TCP_TOKEN`), and prefer `--tcp-cert`/
  `--tcp-key` with `--tcp-client-ca` (mTLS); add `--rate-limit`/`--rate-burst`.
- Verify exact behavior against `docs/` in the repository (threat model,
  policy language, approvals, Jev, performance) before claiming capabilities
  beyond what the demo shows.