#!/usr/bin/env python3
"""hook_gate.py — VS Code (GitHub Copilot agent mode) hooks adapter for Raid.

VS Code runs configured agent hooks before a tool executes. This script mirrors
the Cursor adapter (`../cursor/hook_gate.py`): it maps the call to a normalized
Raid action via the shared `raidlib`, asks the running raidd, and answers with
VS Code's PreToolUse decision.

Output (VS Code PreToolUse contract):

    {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow" | "deny",
        "permissionDecisionReason": "..."}}

A `deny` or `require_approval` verdict blocks the call. Raid approval is
deliberately NOT mapped to VS Code's "ask" prompt: an in-editor prompt would
authorize the action without a Raid receipt, defeating the evidence model.
Approval stays in Raid (a human approves out-of-band) and the agent retries.

Transport: one JSON payload on stdin. Configure the hook as fail-closed so a
crashing hook blocks rather than silently allows. A malformed payload fails
open (never take down the editor); an unreachable raidd fails closed (deny).
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
import raidlib  # noqa: E402

# Administrative commands are not gated: don't lock yourself out of managing
# Raid or of configuring the guardrail.
_ADMIN_COMMANDS = (
    "raid version", "raid doctor", "raid approval list", "raidd --help",
    "raidd --version", "raid policy from-language", "raid policy presets",
    "raid log", "raid grants",
)

# VS Code / Copilot tool names -> the slugs raidlib.tool_to_action understands.
_TOOL_ALIASES = {
    "run_in_terminal": "bash",
    "runinterminal": "bash",
    "terminal": "bash",
    "shell": "bash",
    "exec": "bash",
    "editfiles": "edit",
    "edit_files": "edit",
    "edit": "edit",
    "applypatch": "edit",
    "createfile": "write",
    "create_file": "write",
    "write": "write",
    "newfile": "write",
    "readfile": "readfile",
    "read_file": "readfile",
    "read": "readfile",
    "fetch": "webfetch",
    "websearch": "websearch",
    "web_search": "websearch",
}


def _decision(perm, reason=""):
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": perm,
        }
    }
    if reason:
        out["hookSpecificOutput"]["permissionDecisionReason"] = reason
    return out


def _allow():
    return _decision("allow")


def _deny(reason):
    return _decision("deny", reason)


def _is_admin(tool_name, tool_input):
    if (tool_name or "").lower() != "bash":
        return False
    raw = str((tool_input or {}).get("command", "")).strip().lower()
    return any(raw.startswith(cmd) for cmd in _ADMIN_COMMANDS)


def _cwd_of(payload):
    cwd = payload.get("cwd")
    if cwd:
        return str(cwd)
    roots = payload.get("workspace_roots") or []
    if roots:
        return str(roots[0])
    return os.environ.get("RAID_CWD", os.getcwd())


def _to_call(payload):
    """Map a VS Code hook payload to (tool_name, tool_input) for raidlib."""
    event = str(payload.get("hook_event_name") or payload.get("hook") or "")
    cwd = _cwd_of(payload)
    name = str(payload.get("tool_name") or "").lower()
    raw = payload.get("tool_input")
    tool_input = raw if isinstance(raw, dict) else {}

    if event in ("PreToolUse", "preToolUse", "") and "command" in tool_input:
        # Terminal tool: keep the command and cwd together.
        tool_input.setdefault("cwd", cwd)
    if "working_directory" in tool_input and "cwd" not in tool_input:
        tool_input["cwd"] = tool_input["working_directory"]
    if "cwd" not in tool_input:
        tool_input["cwd"] = cwd
    return _TOOL_ALIASES.get(name, name), tool_input


def main(argv):
    try:
        payload = json.load(sys.stdin)
    except Exception:  # noqa: BLE001
        # Fail open on a malformed hook payload: never take down the editor.
        print(json.dumps(_allow()))
        return 0

    tool_name, tool_input = _to_call(payload)
    if _is_admin(tool_name, tool_input):
        print(json.dumps(_allow()))
        return 0

    environment = os.environ.get("RAID_ENV", "development")
    cwd = _cwd_of(payload)
    try:
        action = raidlib.tool_to_action(
            tool_name, tool_input,
            request_id="vscode:" + os.urandom(4).hex(),
            environment=environment,
            cwd=cwd,
        )
        verdict = raidlib.Raid().decide(action)
    except raidlib.RaidError as exc:
        # raidd unreachable or errored: fail closed (deny), as Raid specifies.
        print(json.dumps(_deny(f"[raid] raidd unavailable, action blocked: {exc}")))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_deny(f"[raid] unexpected adapter error, action blocked: {exc}")))
        return 0

    effect = str(verdict.get("effect", "deny"))
    if effect == "allow":
        print(json.dumps(_allow()))
        return 0
    if effect == "deny":
        reason = verdict.get("reason_code", "POLICY_DENY")
        print(json.dumps(_deny(f"[raid] blocked by policy ({reason}).")))
        return 0

    # require_approval: block, name the approval, and instruct a retry.
    appr = verdict.get("approval") or {}
    appr_id = appr.get("id", "")
    msg = (
        f"[raid] this action requires approval ({verdict.get('reason_code','')}, "
        f"approval {appr_id}). Approve it in the Raid TUI or with "
        f"`raid approval approve {appr_id} --expected-version 0`, then retry."
    )
    print(json.dumps(_deny(msg)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
