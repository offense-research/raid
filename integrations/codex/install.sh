#!/bin/sh
# Install the Raid guardrail for Codex CLI.
#
# Codex CLI supports MCP servers, so the agent can ask Raid before acting
# (raid_check / raid_pending). This script:
#   1. installs the `raid-exec` shim for shell commands the agent runs, and
#   2. prints the [mcp_servers.raid] block to add to ~/.codex/config.toml.
#
# Usage:
#   ./install.sh [--write-config] [--socket PATH] [--config PATH]
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
CLI_DIR=$(cd "$HERE/../cli" && pwd)
MCP_SERVER=$(cd "$HERE/../claude-code" && pwd)/mcp_server.py

BINDIR="${RAID_BINDIR:-$HOME/.local/bin}"
SOCKET="${RAID_SOCKET:-$HOME/.local/state/offense/raid/raid.sock}"
CONFIG="${CODEX_CONFIG:-$HOME/.codex/config.toml}"
WRITE=0

while [ $# -gt 0 ]; do
	case "$1" in
	--write-config) WRITE=1 ;;
	--socket)
		SOCKET="$2"
		shift
		;;
	--config)
		CONFIG="$2"
		shift
		;;
	*) echo "unknown option: $1" >&2; exit 64 ;;
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

if [ "$WRITE" = "1" ]; then
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
