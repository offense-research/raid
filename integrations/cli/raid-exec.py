#!/usr/bin/env python3
"""raid-exec — run a shell command only if Raid allows it.

A tiny shim for CLI coding agents (Aider, Codex CLI, Gemini CLI, and anything
else that shells out) that have no pre-tool hook API. It classifies the command
with the shared `raidlib`, asks the running raidd, and:

  allow            -> execs the command, replacing this process
  deny             -> prints the policy reason and exits 126
  require_approval -> prints the approval id and exits 125

Exit codes are chosen so a wrapping shell/agent treats any non-zero result as a
blocked action.

Usage:
  raid-exec [options] -- <command> [args...]

Options:
  --check     decide only; never run the command (exit 0 allow / 126 deny / 125 approval)
  --dry-run   print the normalized Raid action and exit 0
  --json      with --dry-run, print the action as pretty JSON

Environment:
  RAID_SOCKET     raidd unix socket (default /run/offense/raid/raid.sock)
  RAID_ENV        classified environment (default development)
  RAID_AGENT      agent id in the principal (default claude-code)

An unreachable raidd fails closed (exit 126) — never a silent allow.
"""

import json
import os
import shlex
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
import raidlib  # noqa: E402

EXIT_DENY = 126
EXIT_APPROVAL = 125
EXIT_USAGE = 64


def _usage(msg=""):
    if msg:
        print(f"raid-exec: {msg}", file=sys.stderr)
    print(__doc__.strip(), file=sys.stderr)
    return EXIT_USAGE


def _parse(argv):
    mode = "run"
    rest = list(argv)
    while rest and rest[0].startswith("-"):
        opt = rest.pop(0)
        if opt == "--":
            break
        if opt == "--check":
            mode = "check"
        elif opt == "--dry-run":
            mode = "dry-run"
        elif opt == "--json":
            mode = "dry-run-json"
        elif opt in ("-h", "--help"):
            return None, None
        else:
            raise ValueError(f"unknown option: {opt}")
    return mode, rest


def main(argv):
    try:
        mode, command = _parse(argv)
    except ValueError as exc:
        return _usage(str(exc))
    if mode is None:
        return _usage()
    if not command:
        return _usage("no command given (use `-- <command>`)")

    cmd = " ".join(shlex.quote(a) for a in command)
    environment = os.environ.get("RAID_ENV", "development")

    try:
        action = raidlib.tool_to_action(
            "bash", {"command": cmd, "cwd": os.getcwd()},
            request_id="cli:" + os.urandom(4).hex(),
            environment=environment,
            cwd=os.getcwd(),
        )
    except Exception as exc:  # noqa: BLE001
        # A classification failure must not silently allow the command.
        print(f"raid-exec: [raid] could not build a request, blocked: {exc}", file=sys.stderr)
        return EXIT_DENY

    if mode == "dry-run":
        print(json.dumps(action, indent=2, sort_keys=True) if mode == "dry-run-json" else action)
        return 0

    try:
        verdict = raidlib.Raid().decide(action)
    except raidlib.RaidError as exc:
        print(f"raid-exec: [raid] raidd unavailable, blocked: {exc}", file=sys.stderr)
        return EXIT_DENY
    except Exception as exc:  # noqa: BLE001
        print(f"raid-exec: [raid] unexpected adapter error, blocked: {exc}", file=sys.stderr)
        return EXIT_DENY

    effect = str(verdict.get("effect", "deny"))
    if effect == "allow":
        if mode == "check":
            return 0
        os.execvp(command[0], command)  # noqa: S606 - deliberate hand-off
        return 0
    if effect == "deny":
        print(f"raid-exec: [raid] blocked by policy ({verdict.get('reason_code', 'POLICY_DENY')}).",
              file=sys.stderr)
        return EXIT_DENY

    appr = verdict.get("approval") or {}
    appr_id = appr.get("id", "")
    print(
        f"raid-exec: [raid] this action requires approval "
        f"({verdict.get('reason_code','')}, approval {appr_id}).\n"
        f"  Approve it in the Raid TUI or with "
        f"`raid approval approve {appr_id} --expected-version 0`, then retry.",
        file=sys.stderr,
    )
    return EXIT_APPROVAL


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
