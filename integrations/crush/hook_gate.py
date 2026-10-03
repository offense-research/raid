#!/usr/bin/env python3
"""hook_gate.py — Charm Crush PreToolUse hook for Raid.

Crush (charmbracelet/crush) runs user-defined hooks around tool calls. A
`PreToolUse` hook receives the call on stdin and can stop it:

    stdin   {"event":"PreToolUse","session_id":"...","cwd":"...",
             "tool_name":"bash","tool_input":{"command":"rm -rf /"}}
    env     CRUSH_TOOL_NAME, CRUSH_TOOL_INPUT_COMMAND, CRUSH_CWD, ...
    exit 0  no objection — Crush's own permission flow still applies
    exit 2  block the tool call (stderr is shown to the user)
    exit 49 halt the session

This adapter turns the call into a normalized Raid action with the shared
`raidlib`, asks the running raidd, and blocks on `deny` / `require_approval`.

Raid approval is deliberately NOT mapped to Crush's own confirmation prompt: an
in-agent confirmation would authorize the action without a Raid receipt,
defeating the evidence model. Approval stays in Raid — a human approves
out-of-band — and the agent retries.

Fail-closed: an unreachable raidd or an adapter error exits 2 (blocked). A
malformed payload exits 0 (fail open, so a bad input never takes down Crush).
On `allow` the hook stays silent and exits 0, leaving Crush's own guardrails in
force rather than pre-approving the call.

Debug (never contacts raidd):
    echo '{"tool_name":"bash","tool_input":{"command":"rm -rf /"}}' \
        | python3 hook_gate.py --dry-run
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
import raidlib  # noqa: E402

EXIT_ALLOW = 0
EXIT_BLOCK = 2

# Crush tool names -> the slugs raidlib.tool_to_action understands.
_TOOL_ALIASES = {
    "bash": "bash",
    "shell": "bash",
    "execute": "bash",
    "writetoterminal": "bash",
    "edit": "edit",
    "multiedit": "edit",
    "write": "write",
    "create": "write",
    "view": "readfile",
    "read": "readfile",
    "readfile": "readfile",
    "ls": "readfile",
    "grep": "readfile",
    "glob": "readfile",
    "fetch": "webfetch",
    "webfetch": "webfetch",
}

# Administrative commands are not gated: don't lock yourself out of managing
# Raid or of configuring the guardrail.
_ADMIN_COMMANDS = (
    "raid version", "raid doctor", "raid approval list", "raidd --help",
    "raidd --version", "raid policy from-language", "raid policy presets",
    "raid log", "raid grants",
)


def _cwd_of(payload):
    for key in ("cwd", "working_directory"):
        if payload.get(key):
            return str(payload[key])
    return os.environ.get("RAID_CWD") or os.environ.get("CRUSH_CWD") or os.getcwd()


def _to_call(payload):
    """Map a Crush PreToolUse payload to (tool_name, tool_input) for raidlib."""
    name = str(payload.get("tool_name") or os.environ.get("CRUSH_TOOL_NAME") or "").lower()
    raw = payload.get("tool_input")
    tool_input = raw if isinstance(raw, dict) else {}
    # Crush also exports the hot fields as env vars; fall back to them.
    if not tool_input.get("command") and os.environ.get("CRUSH_TOOL_INPUT_COMMAND"):
        tool_input.setdefault("command", os.environ["CRUSH_TOOL_INPUT_COMMAND"])
    if not (tool_input.get("file_path") or tool_input.get("path")) and os.environ.get(
        "CRUSH_TOOL_INPUT_FILE_PATH"
    ):
        tool_input.setdefault("file_path", os.environ["CRUSH_TOOL_INPUT_FILE_PATH"])
    tool_input.setdefault("cwd", _cwd_of(payload))
    return _TOOL_ALIASES.get(name, name), tool_input


def _is_admin(tool_name, tool_input):
    if (tool_name or "").lower() != "bash":
        return False
    raw = str((tool_input or {}).get("command", "")).strip().lower()
    return any(raw.startswith(cmd) for cmd in _ADMIN_COMMANDS)


def _block(reason):
    print(reason, file=sys.stderr)
    return EXIT_BLOCK


def main(argv):
    os.environ.setdefault("RAID_PROVIDER", "crush")
    os.environ.setdefault("RAID_AGENT", "crush")
    os.environ.setdefault("RAID_RUNTIME", "crush")

    if "--dry-run" in argv:
        try:
            payload = json.load(sys.stdin)
        except Exception:  # noqa: BLE001
            payload = {"tool_name": "bash", "tool_input": {"command": "true"}}
        tool_name, tool_input = _to_call(payload)
        action = raidlib.tool_to_action(
            tool_name, tool_input,
            request_id="crush:dryrun",
            environment=os.environ.get("RAID_ENV", "development"),
            cwd=_cwd_of(payload),
        )
        print(json.dumps(action, indent=2, sort_keys=True))
        return EXIT_ALLOW

    try:
        payload = json.load(sys.stdin)
    except Exception:  # noqa: BLE001
        # Fail open on a malformed payload: never take down Crush.
        return EXIT_ALLOW

    tool_name, tool_input = _to_call(payload)
    if _is_admin(tool_name, tool_input):
        return EXIT_ALLOW

    environment = os.environ.get("RAID_ENV", "development")
    cwd = _cwd_of(payload)
    try:
        action = raidlib.tool_to_action(
            tool_name, tool_input,
            request_id="crush:" + os.urandom(4).hex(),
            environment=environment,
            cwd=cwd,
        )
        verdict = raidlib.Raid().decide(action)
    except raidlib.RaidError as exc:
        # raidd unreachable or errored: fail closed (block), as Raid specifies.
        return _block(f"[raid] raidd unavailable, action blocked: {exc}")
    except Exception as exc:  # noqa: BLE001
        return _block(f"[raid] unexpected adapter error, action blocked: {exc}")

    effect = str(verdict.get("effect", "deny"))
    if effect == "allow":
        return EXIT_ALLOW
    if effect == "deny":
        return _block(f"[raid] blocked by policy ({verdict.get('reason_code', 'POLICY_DENY')}).")

    # require_approval: block, name the approval, and instruct a retry.
    appr = verdict.get("approval") or {}
    appr_id = appr.get("id", "")
    return _block(
        f"[raid] this action requires approval ({verdict.get('reason_code','')}, "
        f"approval {appr_id}). Approve it in the Raid TUI or with "
        f"`raid approval approve {appr_id} --expected-version 0`, then retry."
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
