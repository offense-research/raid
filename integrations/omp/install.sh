#!/bin/sh
# Install the Raid guardrail for omp (Oh My Pi).
#
# omp shares Pi's extension event system. This installs the shared shims and
# prints the Claude Code-shaped hooks block the community hook runners read,
# plus where to put it.
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

== Raid is ready for omp ==

omp hooks come from an extension. Install a Claude Code protocol runner (for
example the pi-yaml-hooks extension, which documents Pi and OMP), then point it
at the Raid gate:

  npm install -g pi-yaml-hooks

Add this block to ~/.omp/agent/hook/hooks.yaml (a copy is in
settings.example.json for the JSON-shaped runners):

  hooks:
    - id: raid-tool-gate
      event: tool.before.*
      action: bash
      command: python3 $HOOK_ABS
EOF
[ -n "$SOCKET" ] && echo "and export RAID_SOCKET=\"$SOCKET\" in the environment omp runs in"
echo
echo "The gate honours RAID_SOCKET / RAID_ENV / RAID_PROVIDER / RAID_AGENT, and"
echo "blocks with exit status 2 (and permissionDecision: deny)."
