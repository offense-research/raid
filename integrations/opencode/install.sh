#!/bin/sh
# Install the Raid guardrail for OpenCode.
#
# OpenCode auto-loads plugin modules from `.opencode/plugins/` (project) and
# `~/.config/opencode/plugins/` (global). This copies the Raid guard plugin in
# and makes sure the shared `raid-check` helper and `raid-exec` shim are on
# PATH.
#
# Usage:
#   ./install.sh [--project] [--dir PATH] [--socket PATH]
#
#   --project     install into ./.opencode/plugins in the current directory
#                 (default: the global ~/.config/opencode/plugins)
#   --dir PATH    explicit plugin directory to install into
#   --socket PATH raidd socket to note for the environment
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
CLI_DIR=$(cd "$HERE/../cli" && pwd)

BINDIR="${RAID_BINDIR:-$HOME/.local/bin}"
DEST="${OPENCODE_PLUGIN_DIR:-$HOME/.config/opencode/plugins}"
SOCKET="${RAID_SOCKET:-}"

while [ $# -gt 0 ]; do
	case "$1" in
	--project) DEST="$(pwd)/.opencode/plugins" ;;
	--dir)
		DEST="$2"
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
install -m 0755 "$CLI_DIR/raid-check.py" "$BINDIR/raid-check"
echo "installed $BINDIR/raid-exec and $BINDIR/raid-check"

mkdir -p "$DEST"
install -m 0644 "$HERE/plugin/raid-guard.js" "$DEST/raid-guard.js"
echo "installed $DEST/raid-guard.js"

echo
echo "OpenCode auto-loads plugins from this directory; restart OpenCode to pick it up."
[ -n "$SOCKET" ] && echo "export RAID_SOCKET=\"$SOCKET\" in the environment OpenCode runs in"
echo
echo "The plugin calls $CLI_DIR/raid-check.py and honours RAID_SOCKET / RAID_ENV /"
echo "RAID_CHECK_PY / RAID_PYTHON in its environment."
