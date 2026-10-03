#!/bin/sh
# Install the Raid guardrail for the Pi coding agent.
#
# Pi hooks come from extensions. This installs the shared shims and prints the
# Claude Code-shaped hooks block that the community hook runners read, plus
# where to put it.
#
# Usage:
#   ./install.sh [--socket PATH]
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
CLI_DIR=$(cd "$HERE/../cli" && pwd)
HOOK="$HERE/hook_gate.py"

BINDIR="${RAID_BINDIR:-$HOME/.local/bin}"
SOCKET="${RAID_SOCKET:-}"

while [ $# -gt 0 ]; do
	case "$1" in
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
cat <<EOF

== Raid is ready for Pi ==

Pi's hooks are provided by an extension. Install one of the Claude Code
protocol runners, then point it at the Raid gate:

  npm install -g @fyeeme/pi-hooks          # reads ~/.pi/agent/hook.json

Add this block to ~/.pi/agent/hook.json (a copy is in settings.example.json):

  {
    "hooks": {
      "PreToolUse": [
        { "matcher": "bash|edit|write|read|fetch|mcp_.*",
          "hooks": [ { "type": "command", "command": "python3 $HOOK_ABS" } ] }
      ]
    }
  }
EOF
[ -n "$SOCKET" ] && echo "and export RAID_SOCKET=\"$SOCKET\" in the environment Pi runs in"
echo
echo "The gate calls $CLI_DIR/raid-check.py's Python classifier directly and honours"
echo "RAID_SOCKET / RAID_ENV / RAID_PROVIDER / RAID_AGENT."
