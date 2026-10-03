#!/usr/bin/env python3
"""hook_gate.py — Cursor hooks adapter for Raid.

Cursor runs configured hooks (see `.cursor/hooks.json` or `~/.cursor/hooks.json`)
before a tool is executed. This single script handles several events:

  beforeShellExecution   -> Bash tool call
  preToolUse             -> any tool call (Shell/Edit/Write/Read/...)
  beforeReadFile         -> Read
  beforeMCPExecution     -> MCP tool call

It maps the call to a normalized Raid action (via the shared raidlib), asks the
running raidd, and answers with Cursor's permission object:

  allow            -> {"permission": "allow"}
  deny             -> {"permission": "deny", agent_message: reason}
  require_approval -> {"permission": "deny", ...} naming the approval id; a human
                      approves in Raid and the agent retries (the receipt is
                      bound to the exact request, so a retry of a *different*
                      command is rejected).

Raid approval is intentionally NOT mapped to Cursor's "ask": a Cursor prompt
would authorize the action without a Raid receipt, defeating the evidence model.

Config (`hooks.json`): set `failClosed: true` on each entry so that a crashing
hook blocks rather than silently allows. Malformed hook input fails open (never
take down the agent); an unreachable raidd fails closed (deny).
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

# Cursor tool names -> the slugs raidlib.tool_to_action understands.
_TOOL_ALIASES = {
    "shell": "bash",
    "terminal": "bash",
    "read": "readfile",
    "readfile": "readfile",
    "edit": "edit",
    "write": "write",
    "edit_file": "edit",
}


def _permission(perm, user_message="", agent_message=""):
    out = {"permission": perm}
    if user_message:
        out["user_message"] = user_message
    if agent_message:
        out["agent_message"] = agent_message
    return out


def _allow():
    return _permission("allow")


def _deny(reason):
    return _permission("deny", user_message=reason, agent_message=reason)


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
    """Map a Cursor hook payload to (tool_name, tool_input) for raidlib."""
    event = str(payload.get("hook_event_name") or payload.get("hook") or "")
    cwd = _cwd_of(payload)
    if event == "beforeShellExecution":
        return "bash", {"command": str(payload.get("command", "")), "cwd": cwd}
    if event == "beforeReadFile":
        return "readfile", {"file_path": str(payload.get("file_path", ""))}
    if event == "beforeMCPExecution":
        raw = payload.get("tool_input")
        tool_input = raw if isinstance(raw, dict) else {}
        name = str(payload.get("tool_name") or "mcp")
        return name.lower(), tool_input
    # preToolUse and anything else: tool_name/tool_input are present.
    name = str(payload.get("tool_name") or "").lower()
    raw = payload.get("tool_input")
    tool_input = raw if isinstance(raw, dict) else {}
    if "working_directory" in tool_input and "cwd" not in tool_input:
        tool_input["cwd"] = tool_input["working_directory"]
    if "cwd" not in tool_input:
        tool_input["cwd"] = cwd
    return _TOOL_ALIASES.get(name, name), tool_input


def main(argv):
    try:
        payload = json.load(sys.stdin)
    except Exception:  # noqa: BLE001
        # Fail open on a malformed hook payload: never take down the agent.
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
            request_id="cursor:" + os.urandom(4).hex(),
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
