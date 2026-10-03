#!/bin/sh
# Install the Raid guardrail for Charm Crush.
#
# Crush runs user-defined shell hooks around tool calls. This wires the Raid
# PreToolUse gate into Crush:
#   1. installs the `raid-exec` shim (so shell commands the agent runs can be
#      gated directly too), and
#   2. writes (or prints) the `hooks.PreToolUse` block for crush.json.
#
# Usage:
#   ./install.sh [--write-config] [--config PATH] [--socket PATH]
#
#   --write-config   create the config file (default: print the block)
#   --config PATH    target config
#                    (default: $CRUSH_GLOBAL_CONFIG or ~/.config/crush/crush.json)
#   --socket PATH    raidd socket to note for the hook environment
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
CLI_DIR=$(cd "$HERE/../cli" && pwd)
HOOK="$HERE/hook_gate.py"

BINDIR="${RAID_BINDIR:-$HOME/.local/bin}"
CONFIG="${CRUSH_GLOBAL_CONFIG:-$HOME/.config/crush/crush.json}"
SOCKET="${RAID_SOCKET:-}"
WRITE=0

while [ $# -gt 0 ]; do
	case "$1" in
	--write-config) WRITE=1 ;;
	--config)
		CONFIG="$2"
		shift
		;;
	--socket)
		SOCKET="$2"
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

HOOK_ABS=$(python3 -c 'import os,sys;print(os.path.abspath(sys.argv[1]))' "$HOOK")
BLOCK=$(cat <<EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "name": "raid-gate",
        "matcher": "^(bash|shell|execute|edit|multiedit|write|create|view|read|ls|grep|glob|fetch|mcp_.*)\$",
        "command": "python3 $HOOK_ABS",
        "timeout": 30
      }
    ]
  }
}
EOF
)

if [ "$WRITE" = "1" ]; then
	mkdir -p "$(dirname "$CONFIG")"
	if [ -f "$CONFIG" ]; then
		echo "note: $CONFIG exists; merge the block below by hand (Crush reads a single hooks list):"
		printf '%s\n' "$BLOCK"
	else
		printf '%s\n' "$BLOCK" >"$CONFIG"
		echo "wrote $CONFIG"
	fi
else
	echo
	echo "Add this to $CONFIG (or re-run with --write-config):"
	echo
	printf '%s\n' "$BLOCK"
fi
[ -n "$SOCKET" ] && echo "note: export RAID_SOCKET=\"$SOCKET\" in the environment Crush runs in"
echo
echo "The gate honours RAID_ENV / RAID_PROVIDER / RAID_AGENT in its environment."
