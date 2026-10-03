#!/bin/sh
# Install the Raid guardrail for Hermes (Nous Research).
#
# Hermes has no pre-tool hook config file; guardrails are plugins. This copies
# the Raid guard plugin into the Hermes plugin directory, installs the shared
# shims, and prints the enable step.
#
# Usage:
#   ./install.sh [--dest DIR] [--socket PATH]
#
#   --dest DIR    Hermes plugin dir (default: ${HERMES_HOME:-$HOME/.hermes}/plugins)
#   --socket PATH raidd socket to note for the environment
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
CLI_DIR=$(cd "$HERE/../cli" && pwd)
PLUGIN_SRC="$HERE/plugin"

BINDIR="${RAID_BINDIR:-$HOME/.local/bin}"
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
DEST="${HERMES_HOME}/plugins"
SOCKET="${RAID_SOCKET:-}"

while [ $# -gt 0 ]; do
	case "$1" in
	--dest)
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
echo "installed $BINDIR/raid-exec"

mkdir -p "$DEST/raid-guard"
install -m 0644 "$PLUGIN_SRC/plugin.yaml" "$DEST/raid-guard/plugin.yaml"
install -m 0644 "$PLUGIN_SRC/__init__.py" "$DEST/raid-guard/__init__.py"
echo "installed $DEST/raid-guard (plugin.yaml, __init__.py)"

echo
echo "Enable the plugin (add 'raid-guard' to plugins.enabled in the Hermes config),"
echo "then validate it:"
echo
echo "  hermes plugins validate raid-guard"
echo "  hermes plugins doctor raid-guard"
echo
echo "The plugin resolves the shared normalizer from the Raid checkout; set"
echo "RAID_LIB_DIR=/abs/path/raid/integrations/lib if the checkout moved."
[ -n "$SOCKET" ] && echo "note: export RAID_SOCKET=\"$SOCKET\" in the environment Hermes runs in"
