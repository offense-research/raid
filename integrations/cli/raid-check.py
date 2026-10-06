#!/usr/bin/env python3
"""raid-check — judge a coding-agent tool call and print the verdict as JSON.

Some agents run their guardrail hooks in a JavaScript runtime (OpenCode,
OpenClaw), so they cannot import the Python `raidlib` classifier directly. This
helper is the bridge: it reads one tool call as JSON on stdin, builds the
normalized Raid action with the shared `raidlib`, asks the running raidd, and
prints a small machine-readable verdict on stdout.

Input (stdin, one JSON object):
  {"tool_name": "bash", "tool_input": {"command": "rm -rf /"}, "cwd": "/repo"}

Output (stdout, one JSON object):
  {"effect": "allow|deny|require_approval", "reason_code": "...",
   "reason": "human-readable", "approval": {"id": "apr_..."}}

Exit codes mirror `raid-exec` (0 allow / 126 deny / 125 require_approval) so a
shell caller can branch on the exit status too.

Options:
  --provider NAME   provider recorded in the action (default: RAID_PROVIDER)
  --env NAME        classified environment (default: RAID_ENV)
  --dry-run         print the normalized Raid action instead of deciding

Environment:
    RAID_SOCKET     raidd unix socket (default /run/offense/raid/raid.sock)
    RAID_ENV        classified environment (default development)
    RAID_PROVIDER   provider recorded in the action (default claude-code)
    RAID_SESSION    session id the taint ledger is keyed on. Without it the
                    ledger falls back to principal+agent+cwd, so cross-call
                    taint still works within one project.
    RAID_LEDGER_DIR where session taint files live (default the XDG state dir)
    RAID_NO_LEDGER  set to 1 to skip taint tracking entirely; the action then
                    carries session_tracked=false rather than pretending

A classification failure, an unreachable raidd, or an adapter error all fail
closed: the verdict is `deny` and the exit status is 126 — never a silent allow.
A model is never the arbiter of authority.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
import raidlib  # noqa: E402

EXIT_ALLOW = 0
EXIT_DENY = 126
EXIT_APPROVAL = 125

# Host tool names -> the slugs raidlib.tool_to_action understands. JS hosts
# (OpenCode, OpenClaw) and others pass their own tool names; normalize here so
# the classifier sees a shape it recognizes. A caller may override per call by
# sending a `tool_aliases` object in the payload.
_TOOL_ALIASES = {
    "bash": "bash",
    "shell": "bash",
    "terminal": "bash",
    "execute": "bash",
    "run_in_terminal": "bash",
    "runinterminal": "bash",
    "writetoterminal": "bash",
    "edit": "edit",
    "multiedit": "edit",
    "editfiles": "edit",
    "edit_files": "edit",
    "applypatch": "edit",
    "apply_patch": "edit",
    "write": "write",
    "create": "write",
    "createfile": "write",
    "create_file": "write",
    "newfile": "write",
    "read": "readfile",
    "view": "readfile",
    "readfile": "readfile",
    "read_file": "readfile",
    "ls": "ls",
    "grep": "readfile",
    "glob": "readfile",
    "fetch": "webfetch",
    "webfetch": "webfetch",
    "web_fetch": "webfetch",
    "websearch": "websearch",
    "web_search": "websearch",
}


def _normalize_tool(name, overrides=None):
    key = str(name or "").strip().lower()
    if isinstance(overrides, dict) and key in overrides:
        return str(overrides[key])
    return _TOOL_ALIASES.get(key, name)


def _verdict(effect, reason_code="", reason="", approval_id=""):
    out = {"effect": effect, "reason_code": reason_code, "reason": reason}
    if approval_id:
        out["approval"] = {"id": approval_id}
    return out


def _emit(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _fail_closed(msg):
    # raidd unreachable, or an adapter/classification error: never allow.
    _emit(_verdict("deny", "ADAPTER_ERROR", msg))
    return EXIT_DENY


def main(argv):
    parser = argparse.ArgumentParser(prog="raid-check", add_help=True)
    parser.add_argument("--provider", default=os.environ.get("RAID_PROVIDER", "claude-code"))
    parser.add_argument("--env", dest="environment", default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    # The adapter names the real caller so the audit trail is accurate.
    os.environ["RAID_PROVIDER"] = args.provider
    os.environ.setdefault("RAID_AGENT", args.provider)
    os.environ.setdefault("RAID_RUNTIME", args.provider)

    try:
        raw = sys.stdin.read()
        call = json.loads(raw) if raw.strip() else {}
    except Exception as exc:  # noqa: BLE001
        return _fail_closed(f"could not parse tool call: {exc}")
    if not isinstance(call, dict):
        return _fail_closed("tool call must be a JSON object")

    tool_name = _normalize_tool(call.get("tool_name"), call.get("tool_aliases"))
    tool_input = call.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    cwd = str(call.get("cwd") or os.environ.get("RAID_CWD") or os.getcwd())
    environment = args.environment or call.get("environment") or os.environ.get("RAID_ENV", "development")

    # A dry run inspects the normalized request; it must not advance the
    # session's taint ledger, so a preview cannot change what a later real call
    # is judged against.
    if args.dry_run:
        os.environ["RAID_NO_LEDGER"] = "1"

    try:
        action = raidlib.tool_to_action(
            tool_name, tool_input,
            request_id=args.provider + ":" + os.urandom(4).hex(),
            environment=environment,
            cwd=cwd,
        )
    except Exception as exc:  # noqa: BLE001
        return _fail_closed(f"could not build a request: {exc}")

    if args.dry_run:
        print(json.dumps(action, indent=2, sort_keys=True))
        return EXIT_ALLOW

    try:
        verdict = raidlib.Raid().decide(action)
    except raidlib.RaidError as exc:
        return _fail_closed(f"raidd unavailable: {exc}")
    except Exception as exc:  # noqa: BLE001
        return _fail_closed(f"unexpected adapter error: {exc}")

    effect = str(verdict.get("effect", "deny"))
    reason_code = verdict.get("reason_code", "")
    if effect == "allow":
        _emit(_verdict("allow", reason_code))
        return EXIT_ALLOW
    if effect == "deny":
        code = reason_code or "POLICY_DENY"
        _emit(_verdict("deny", code, f"blocked by policy ({code})"))
        return EXIT_DENY

    appr = verdict.get("approval") or {}
    appr_id = appr.get("id", "")
    msg = (
        f"this action requires approval ({reason_code}, approval {appr_id}). "
        f"Approve it in the Raid TUI or with "
        f"`raid approval approve {appr_id} --expected-version 0`, then retry."
    )
    _emit(_verdict("require_approval", reason_code, msg, appr_id))
    return EXIT_APPROVAL


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
