#!/usr/bin/env python3
"""hook_gate.py — Windsurf (Cascade) hooks adapter for Raid.

Windsurf Cascade runs configured hooks (see `~/.codeium/windsurf/hooks.json`)
around agent actions. This script mirrors the Cursor adapter
(`../cursor/hook_gate.py`): it maps the action to a normalized Raid action via
the shared `raidlib`, asks the running raidd, and blocks when the verdict is
`deny` or `require_approval`.

Hook contract: a pre-hook that exits with status 2 blocks the action and its
output is shown to the user; exit 0 allows it. So:

  allow            -> exit 0, no output
  deny             -> exit 2, reason printed
  require_approval -> exit 2, reason + approval id printed

Raid approval is deliberately NOT mapped to Cascade's own confirmation prompt:
an in-editor confirmation would authorize the action without a Raid receipt,
defeating the evidence model. Approval stays in Raid and the agent retries.

Unreachable raidd or an adapter error -> exit 2 (fail closed). A malformed
payload -> exit 0 (fail open, never take down Cascade).
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

# Windsurf Cascade event -> the slug raidlib.tool_to_action understands.
_EVENT_TOOL = {
    "pre_run_command": "bash",
    "post_run_command": "bash",
    "pre_write_code": "write",
    "post_write_code": "write",
    "pre_read_code": "readfile",
    "post_read_code": "readfile",
}

# Only pre-hooks gate; post-hooks are observational and must never block.
_POST_EVENTS = {"post_run_command", "post_write_code", "post_read_code",
                "post_cascade_response", "post_user_prompt", "post_mcp_tool_use"}


def _cwd_of(payload):
    for key in ("cwd", "working_directory", "workspace_path"):
        if payload.get(key):
            return str(payload[key])
    roots = payload.get("workspace_roots") or []
    if roots:
        return str(roots[0])
    return os.environ.get("RAID_CWD", os.getcwd())


def _to_call(payload):
    """Map a Windsurf hook payload to (tool_name, tool_input) for raidlib."""
    event = str(payload.get("agent_action_name") or payload.get("hook") or "")
    info = payload.get("tool_info")
    info = info if isinstance(info, dict) else {}

    if event == "pre_mcp_tool_use" or "mcp_tool_name" in info:
        name = str(info.get("mcp_tool_name") or "mcp").lower()
        args = info.get("mcp_tool_arguments")
        return name, (args if isinstance(args, dict) else {})

    if event in ("pre_run_command", "post_run_command") or "command_line" in info:
        cmd = str(info.get("command_line") or info.get("command") or "")
        return "bash", {"command": cmd, "cwd": _cwd_of(payload)}

    if "file_path" in info or event in ("pre_write_code", "pre_read_code",
                                        "post_write_code", "post_read_code"):
        path = str(info.get("file_path") or info.get("path") or "")
        tool = "write" if "write" in event else "readfile"
        return tool, {"file_path": path, "cwd": _cwd_of(payload)}

    # Unknown event: treat as a generic tool call.
    return _EVENT_TOOL.get(event, event or "tool"), {"cwd": _cwd_of(payload)}


def _block(reason):
    print(reason)
    return 2


def _is_admin(tool_name, tool_input):
    if (tool_name or "").lower() != "bash":
        return False
    raw = str((tool_input or {}).get("command", "")).strip().lower()
    return any(raw.startswith(cmd) for cmd in _ADMIN_COMMANDS)


def main(argv):
    try:
        payload = json.load(sys.stdin)
    except Exception:  # noqa: BLE001
        # Fail open on a malformed payload: never take down Cascade.
        return 0

    event = str(payload.get("agent_action_name") or payload.get("hook") or "")
    if event in _POST_EVENTS:
        return 0

    tool_name, tool_input = _to_call(payload)
    if _is_admin(tool_name, tool_input):
        return 0

    environment = os.environ.get("RAID_ENV", "development")
    cwd = _cwd_of(payload)
    try:
        action = raidlib.tool_to_action(
            tool_name, tool_input,
            request_id="windsurf:" + os.urandom(4).hex(),
            environment=environment,
            cwd=cwd,
        )
        verdict = raidlib.Raid().decide(action)
    except raidlib.RaidError as exc:
        return _block(f"[raid] raidd unavailable, action blocked: {exc}")
    except Exception as exc:  # noqa: BLE001
        return _block(f"[raid] unexpected adapter error, action blocked: {exc}")

    effect = str(verdict.get("effect", "deny"))
    if effect == "allow":
        return 0
    if effect == "deny":
        return _block(f"[raid] blocked by policy ({verdict.get('reason_code', 'POLICY_DENY')}).")

    appr = verdict.get("approval") or {}
    appr_id = appr.get("id", "")
    return _block(
        f"[raid] this action requires approval ({verdict.get('reason_code','')}, "
        f"approval {appr_id}). Approve it in the Raid TUI or with "
        f"`raid approval approve {appr_id} --expected-version 0`, then retry."
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
