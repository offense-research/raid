#!/bin/sh
# Install the Raid guardrail for OpenClaw.
#
# OpenClaw loads native plugins that can register the `before_tool_call` hook.
# This makes sure the shared `raid-check` helper and `raid-exec` shim are on
# PATH and prints the config you add to let OpenClaw load the linked plugin.
#
# Usage:
#   ./install.sh [--socket PATH]
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
CLI_DIR=$(cd "$HERE/../cli" && pwd)
PLUGIN_DIR="$HERE/plugin"

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
install -m 0755 "$CLI_DIR/raid-check.py" "$BINDIR/raid-check"
echo "installed $BINDIR/raid-exec and $BINDIR/raid-check"

PLUGIN_ABS=$(python3 -c 'import os,sys;print(os.path.abspath(sys.argv[1]))' "$PLUGIN_DIR/index.js")
echo
echo "Load the linked plugin by adding its path to the OpenClaw config, then reload:"
echo
echo "  plugins.load.paths = ['$PLUGIN_ABS']"
echo "  openclaw plugins reload raid-guard"
echo
echo "(equivalently: openclaw plugins install --link $PLUGIN_DIR --force && openclaw plugins enable raid-guard)"
[ -n "$SOCKET" ] && echo "note: export RAID_SOCKET=\"$SOCKET\" in the environment the OpenClaw gateway runs in"
echo
echo "The plugin calls $CLI_DIR/raid-check.py and honours RAID_SOCKET / RAID_ENV /"
echo "RAID_CHECK_PY / RAID_PYTHON in its environment."
