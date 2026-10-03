#!/bin/sh
# Install the Raid guardrail for Aider in the current git repository.
#
# Aider has no pre-tool hook API, so this wires Raid in at the two points Aider
# actually goes through:
#   1. the `raid-exec` shim, to gate shell commands the agent runs; and
#   2. git pre-push / pre-commit hooks, since Aider commits for you.
#
# Usage:
#   ./install.sh [--git-hooks] [--socket PATH]
#
#   --git-hooks   also install .git/hooks/pre-push and pre-commit
#   --socket PATH set RAID_SOCKET recorded in the hooks (default: env or raidd default)
set -eu

GIT_HOOKS=0
SOCKET="${RAID_SOCKET:-}"
BINDIR="${RAID_BINDIR:-$HOME/.local/bin}"
HERE=$(cd "$(dirname "$0")" && pwd)
CLI_DIR=$(cd "$HERE/../cli" && pwd)

while [ $# -gt 0 ]; do
	case "$1" in
	--git-hooks) GIT_HOOKS=1 ;;
	--socket)
		SOCKET="$2"
		shift
		;;
	*) echo "unknown option: $1" >&2; exit 64 ;;
	esac
	shift
done

mkdir -p "$BINDIR"
install -m 0755 "$CLI_DIR/raid-exec.py" "$BINDIR/raid-exec"
echo "installed $BINDIR/raid-exec"

if [ "$GIT_HOOKS" = "1" ]; then
	root=$(git rev-parse --show-toplevel 2>/dev/null) || {
		echo "not inside a git repository; run this from your project (or omit --git-hooks)" >&2
		exit 1
	}
	hooks="$root/.git/hooks"
	mkdir -p "$hooks"
	sock_line=""
	[ -n "$SOCKET" ] && sock_line="export RAID_SOCKET=\"$SOCKET\"
"
	cat >"$hooks/pre-push" <<EOF
#!/bin/sh
# Raid guardrail: ask the policy engine before pushing.
${sock_line}export RAID_PROVIDER=aider RAID_AGENT=aider RAID_RUNTIME=aider
exec "$BINDIR/raid-exec" --check -- git push
EOF
	cat >"$hooks/pre-commit" <<EOF
#!/bin/sh
# Raid guardrail: ask the policy engine before committing.
${sock_line}export RAID_PROVIDER=aider RAID_AGENT=aider RAID_RUNTIME=aider
exec "$BINDIR/raid-exec" --check -- git commit
EOF
	chmod +x "$hooks/pre-push" "$hooks/pre-commit"
	echo "installed git hooks in $hooks (pre-push, pre-commit)"
fi

echo
echo "Next: gate shell commands Aider runs by prefixing them with raid-exec, e.g."
echo "  raid-exec -- <command>"
echo "Or set Aider's lint/test commands through the shim in .aider.conf.yml."
