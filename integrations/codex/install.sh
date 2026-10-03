#!/bin/sh
# Install the Raid guardrail for Codex.
#
# Every Codex host shares one configuration: the ChatGPT desktop app, Codex
# CLI, and the IDE extension all read MCP servers from ~/.codex/config.toml and
# skills from ~/.agents/skills. So this script wires both once and all three
# clients pick them up:
#
#   1. installs the `raid-exec` shim for shell commands the agent runs,
#   2. writes the [mcp_servers.raid] block (raid_check / raid_pending) into
#      ~/.codex/config.toml,
#   3. copies the `raid` skill into ~/.agents/skills/raid.
#
# Usage:
#   ./install.sh [--write-config] [--write-skill] [--socket PATH]
#                [--config PATH] [--skill-dir PATH]
#
# With neither --write-config nor --write-skill it prints what it would do.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
CLI_DIR="$REPO/integrations/cli"
MCP_SERVER="$REPO/integrations/claude-code/mcp_server.py"
SKILL_SRC="$REPO/skills/raid/SKILL.md"

BINDIR="${RAID_BINDIR:-$HOME/.local/bin}"
SOCKET="${RAID_SOCKET:-$HOME/.local/state/offense/raid/raid.sock}"
CONFIG="${CODEX_CONFIG:-$HOME/.codex/config.toml}"
SKILLDIR="${CODEX_SKILL_DIR:-$HOME/.agents/skills}"
WRITE_CONFIG=0
WRITE_SKILL=0

while [ $# -gt 0 ]; do
	case "$1" in
	--write-config) WRITE_CONFIG=1 ;;
	--write-skill) WRITE_SKILL=1 ;;
	--socket)
		SOCKET="$2"
		shift
		;;
	--config)
		CONFIG="$2"
		shift
		;;
	--skill-dir)
		SKILLDIR="$2"
		shift
		;;
	*)
		echo "unknown option: $1" >&2
		exit 64
		;;
	esac
	shift
done

mkdir -p "$BINDIR"
install -m 0755 "$CLI_DIR/raid-exec.py" "$BINDIR/raid-exec"
echo "installed $BINDIR/raid-exec"

BLOCK="[mcp_servers.raid]
command = \"python3\"
args = [\"$MCP_SERVER\"]
env = { RAID_SOCKET = \"$SOCKET\", RAID_ENV = \"development\", RAID_PROVIDER = \"codex\", RAID_AGENT = \"codex\", RAID_RUNTIME = \"codex\" }
"

if [ "$WRITE_CONFIG" = "1" ]; then
	mkdir -p "$(dirname "$CONFIG")"
	if grep -q '^\[mcp_servers\.raid\]' "$CONFIG" 2>/dev/null; then
		echo "note: [mcp_servers.raid] already present in $CONFIG; leaving it unchanged"
	else
		printf '\n%s\n' "$BLOCK" >>"$CONFIG"
		echo "appended [mcp_servers.raid] to $CONFIG"
	fi
else
	echo
	echo "Add this to $CONFIG (or re-run with --write-config):"
	echo
	printf '%s\n' "$BLOCK"
fi

if [ "$WRITE_SKILL" = "1" ]; then
	mkdir -p "$SKILLDIR/raid"
	install -m 0644 "$SKILL_SRC" "$SKILLDIR/raid/SKILL.md"
	echo "installed the raid skill at $SKILLDIR/raid/SKILL.md"
else
	echo
	echo "Install the raid skill (or re-run with --write-skill):"
	echo
	echo "    install -Dm644 $SKILL_SRC $SKILLDIR/raid/SKILL.md"
fi

cat <<'EOF'

Every Codex host picks both up, because they share this configuration:
  - Codex CLI
  - the Codex IDE extension
  - Codex in the ChatGPT desktop app

In the ChatGPT desktop app, Settings -> MCP servers lists the same servers
(use Restart after the first install), and skills appear in the sidebar.
Codex has no pre-tool hook, so `raid-exec` is still how shell commands get
gated -- see integrations/cli/README.md.
EOF
