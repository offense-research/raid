#!/usr/bin/env python3
"""hook_gate.py — Claude Code PreToolUse hook for Raid.

Claude Code runs this before Bash/Edit/Write-style tool calls. It turns the
tool call into a normalized ActionRequest, asks the running raidd, and
enforces the verdict:

  allow            -> exit 0 (permit the tool to run)
  deny             -> exit with a Claude Code block JSON (call is stopped)
  require_approval -> exit with a block JSON + instructions; a human approves
                      in the Raid TUI/CLI, then the agent retries (optionally
                      via `raid decision wait <id>` for the receipt).

Hooks cannot block while awaiting a human, so require_approval is non-blocking:
the call is declined and the human approves out-of-band. This matches Raid's
async approval model. A model is never the arbiter of authority.

Install (see install.sh): point a PreToolUse hook at this file, e.g.
  {"hooks": {"PreToolUse": [{"matcher": "Bash|Edit|Write|Read",
                              "hooks": [{"type": "command",
                                         "command": "python3 <abs path>/hook_gate.py"}]}]}}
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
import raidlib  # noqa: E402


def _block_json(reason):
    """The block verdict, in the shape this host actually enforces.

    Claude Code validates a PreToolUse hook's output against a schema whose
    hookSpecificOutput accepts exactly hookEventName, permissionDecision,
    permissionDecisionReason, updatedInput and additionalContext. A `decision`
    key placed *inside* hookSpecificOutput is not part of that schema and is
    dropped by validation, which silently turns a block into a no-op - the call
    runs and the operator believes it was denied. The current field is
    permissionDecision; the legacy top-level `decision` is kept alongside it for
    hosts that predate the change.
    """
    return {
        "decision": "block",
        "reason": reason,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
    }


_ADMIN_COMMANDS = (
    "raid version", "raid doctor", "raid approval list", "raidd --help",
    "raidd --version", "raid policy from-language", "raid policy presets",
    "raid log", "raid grants",
)


def _is_admin(tool_name, tool_input):
    tn = (tool_name or "").lower()
    if tn in ("read", "readfile", "glob", "grep", "ls"):
        # assume reading is fine generally
        return False
    if tn not in ("bash", "writetoterminal"):
        return False
    raw = (tool_input or {}).get("command", "")
    low = raw.strip().lower()
    return any(low.startswith(cmd) for cmd in _ADMIN_COMMANDS)


def main(argv):
    try:
        payload = json.load(sys.stdin)
    except Exception as exc:  # noqa: BLE001
        # Fail open on a malformed hook payload: never take down the agent.
        print(json.dumps({"hookSpecificOutput": {}}))
        return 0

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})
    cwd = os.environ.get("RAID_CWD", os.getcwd())
    environment = os.environ.get("RAID_ENV", "development")

    # Administrative commands are not gated: don't lock yourself out of
    # managing Raid (version/doctor/approval lists) or of configuring it.
    if _is_admin(tool_name, tool_input):
        print(json.dumps({"hookSpecificOutput": {}}))
        return 0

    try:
        action = raidlib.tool_to_action(
            tool_name, tool_input,
            request_id="claude:" + os.urandom(4).hex(),
            environment=environment,
            cwd=cwd,
        )
        verdict = raidlib.Raid().decide(action)
    except raidlib.RaidError as exc:
        # raidd unreachable or errored: fail closed (deny), as Raid specifies.
        print(json.dumps(_block_json(f"[raid] raidd unavailable, action blocked: {exc}")))
        return 2
    except Exception as exc:  # noqa: BLE001
        print(json.dumps(_block_json(f"[raid] unexpected adapter error, action blocked: {exc}")))
        return 2

    effect = str(verdict.get("effect", "deny"))
    if effect == "allow":
        print(json.dumps({"hookSpecificOutput": {}}))
        return 0

    # A non-zero exit is the blocking signal; permissionDecision repeats it in
    # the structured field, so a host reading either one refuses the call.
    if effect == "deny":
        reason = verdict.get("reason_code", "POLICY_DENY")
        print(json.dumps(_block_json(f"[raid] blocked by policy ({reason}).")))
        return 2

    # require_approval
    appr = verdict.get("approval") or {}
    appr_id = appr.get("id", "")
    wait = ""
    if appr_id:
        wait = f" Then confirm the outcome with: raid decision wait {appr_id}"
    reason = (
        f"[raid] this action requires approval ({verdict.get('reason_code','')}, "
        f"approval {appr_id}). Have a human review it in the Raid TUI, "
        f"approve with: raid approval approve {appr_id} --expected-version 0, "
        f"then retry the tool call.{wait}"
    )
    print(json.dumps(_block_json(reason)))
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))