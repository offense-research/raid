#!/usr/bin/env sh
# install.sh — wire Raid into Claude Code (hook gate + MCP + skill).
#
# What it does:
#   1. Builds the raid binary if needed (via make) and locates the repo.
#   2. Provisions a data dir, boots raidd with a seeded approver and the
#      coding-agent starter policy, and verifies with `raid doctor`.
#   3. Writes the Claude Code hook (PreToolUse -> hook_gate.py) and MCP server
#      (mcp_server.py) into .claude/settings.json.
#   4. Prints the two lines to paste into Claude Code to install the skill.
#
# Env overrides: RAID_PREFIX, RAID_SOCKET, RAID_DB, RAID_KEY, RAID_POLICY,
# RAID_ENV, RAID_APPROVER_SUBJECT, RAID_UID. All optional.
# Single engineer? Set RAID_SOLO=1: unprivileged XDG state dir, self-approval,
# and the solo-dev-safe preset (override the posture with RAID_PRESET).
set -e

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SOLO="${RAID_SOLO:-0}"
if [ "$SOLO" = "1" ]; then
  PREFIX="${RAID_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/offense/raid}"
  SOCK="${RAID_SOCKET:-$PREFIX/raid.sock}"
  DB="${RAID_DB:-$PREFIX/raid.db}"
  KEY="${RAID_KEY:-$PREFIX/ed25519.seed}"
  APPROVER="${RAID_APPROVER_SUBJECT:-$(id -un):maintainers,admins}"
else
  PREFIX="${RAID_PREFIX:-$HOME/.offense/raid}"
  SOCK="${RAID_SOCKET:-$PREFIX/raid.sock}"
  DB="${RAID_DB:-$PREFIX/raid.db}"
  KEY="${RAID_KEY:-$PREFIX/ed25519.seed}"
  POLICY="${RAID_POLICY:-$REPO/integrations/claude-code/coding-agent.policy.yaml}"
  APPROVER="${RAID_APPROVER_SUBJECT:-$(id -un):maintainers,admins}"
fi
ENV_NAME="${RAID_ENV:-development}"

echo "== building raid (if needed)"
[ -x "$REPO/raid" ] || (cd "$REPO" && make >/dev/null)
RAID="$REPO/raid"
ln -sf "$RAID" "$REPO/raidd" 2>/dev/null || true

echo "== provisioning $PREFIX"
mkdir -p "$PREFIX"

echo "== booting raidd"
if [ "$SOLO" = "1" ]; then
  if ! pgrep -f "raidd --solo" >/dev/null 2>&1; then
    RAID_STATE_DIR="$PREFIX" \
      "$REPO/raidd" --solo ${RAID_PRESET:+--policy-preset "$RAID_PRESET"} &
    sleep 1
  else
    echo "   raidd (solo) already running on $SOCK"
  fi
elif ! pgrep -f "raidd --socket $SOCK" >/dev/null 2>&1; then
  "$REPO/raidd" \
    --socket "$SOCK" \
    --db "$DB" \
    --policy "$POLICY" \
    --key "$KEY" \
    --uid 0 --uid "$(id -u)" \
    --approver "$APPROVER" &
  sleep 1
else
  echo "   raidd already running on $SOCK"
fi

export RAID_SOCKET="$SOCK"
echo "== verifying daemon"
"$RAID" doctor

echo "== classifying environment as: $ENV_NAME (set RAID_ENV to change)"

# Hook + MCP config for Claude Code.
CC_HOME="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
SETTINGS="$CC_HOME/settings.json"
HOOK_ABS="$(python3 -c 'import os,sys;print(os.path.abspath(sys.argv[1]))' "$REPO/integrations/claude-code/hook_gate.py")"
MCP_ABS="$(python3 -c 'import os,sys;print(os.path.abspath(sys.argv[1]))' "$REPO/integrations/claude-code/mcp_server.py")"

if [ -f "$SETTINGS" ]; then
  echo "== $SETTINGS exists; merging hooks + mcpServers by hand is recommended."
  echo "   Add a PreToolUse hook and the 'raid' MCP entry per the README."
else
  cat > "$SETTINGS" <<EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Edit|Write|Read|read|Readahead|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "python3 $HOOK_ABS"
          }
        ]
      }
    ]
  },
  "mcpServers": {
    "raid": {
      "type": "stdio",
      "command": "python3",
      "args": ["$MCP_ABS"],
      "env": { "RAID_SOCKET": "$SOCK", "RAID_ENV": "$ENV_NAME" }
    }
  }
}
EOF
  echo "== wrote $SETTINGS"
fi

cat <<EOF

== Raid is wired into Claude Code ==

Hooks:   PreToolUse gate at $HOOK_ABS
MCP:     raid/raid_check, raid/raid_pending at $MCP_ABS
Data:    $PREFIX   socket: $SOCK

To install the Raid skill (so the agent knows how to translate its own tool
calls and check raidd), paste this into Claude:

> Install the Raid skill. In Claude Code run:
>   claude plugin marketplace add offense/raid
>   claude plugin install raid@offense/raid
> (or read it directly: $REPO/skills/raid/SKILL.md)

Manual CLI, no daemon surprises:
  export RAID_SOCKET=$SOCK
  $RAID decision eval --request examples/proxy/reader-list.json
  $RAID approval list
  $RAID approval approve <id> --expected-version 0
EOF