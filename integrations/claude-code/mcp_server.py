#!/usr/bin/env python3
"""mcp_server.py — a minimal Model Context Protocol (stdio) server for Raid.

Exposes two tools to a coding agent like Claude Code:

  raid_check
      Ask raidd whether a proposed action is allowed. Inputs: operation,
      effect, path, description/arguments, environment. Returns the verdict
      (allow | deny | require_approval) plus, on require_approval, the
      approval id so a human can approve it in the TUI/CLI.

  raid_pending
      List approvals currently awaiting a human, so the agent can report them.

Approval itself is performed by a human (TUI / `raid approval approve`), never
by the agent — preserving separation of duty. This server speaks JSON-RPC 2.0
over stdin/stdout with Content-Length framing; no third-party MCP SDK required.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import raidlib  # noqa: E402

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "raid"
SERVER_VERSION = "0.1.0"

_TOOLS = [
    {
        "name": "raid_check",
        "description": (
            "Ask the Raid policy engine whether an action is allowed before "
            "performing it. Provide operation (e.g. shell.write, git.push, "
            "filesystem.write, shell.delete, package.install, shell.read), "
            "effect (read|write|delete|execute), and the path/description. "
            "Result is allow, deny, or require_approval."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "operation": {"type": "string", "description": "Operation slug, e.g. shell.write or git.push"},
                "effect": {"type": "string", "enum": ["read", "write", "delete", "execute"], "default": "write"},
                "path": {"type": "string", "description": "Resource id/path, e.g. the file or repo"},
                "arguments": {"type": "object", "description": "Extra arguments"},
                "environment": {"type": "string", "description": "development|staging|production"},
            },
            "required": ["operation"],
        },
    },
    {
        "name": "raid_pending",
        "description": "List approvals currently waiting on a human reviewer.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _read_message():
    content_length = None
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            break
        key, _, value = line.partition(b":")
        headers[key.strip().decode().lower()] = value.strip().decode()
    cl = headers.get("content-length")
    if cl is None:
        return None
    body = sys.stdin.buffer.read(int(cl))
    if not body:
        return None
    return json.loads(body)


def _write(obj):
    data = json.dumps(obj).encode()
    sys.stdout.buffer.write(b"Content-Length: " + str(len(data)).encode() + b"\r\n\r\n" + data)
    sys.stdout.buffer.flush()


def _text_result(text, is_error=False):
    return {"result": {"content": [{"type": "text", "text": text}], "isError": is_error}}


def _check(args):
    operation = str(args.get("operation", "")).strip()
    if not operation:
        return _text_result("raid_check: 'operation' is required.", is_error=True)
    effect = args.get("effect", "write")
    if effect not in ("read", "write", "delete", "execute"):
        effect = "write"
    path = args.get("path") or ""
    environment = args.get("environment", os.environ.get("RAID_ENV", "development"))
    request_id = "mcp:" + os.urandom(4).hex()
    action = {
        "schema_version": 1,
        "request_id": request_id,
        "principal": raidlib.principal(),
        "action": {"provider": "claude-code", "operation": operation, "effect": effect},
        "resource": {
            "type": "tool",
            "id": path or ".",
            "environment": environment,
            "attributes": {},
        },
        "arguments": {k: raidlib._typed(v) for k, v in (args.get("arguments") or {}).items() if v is not None},
        "context": raidlib.context(request_id),
    }
    try:
        verdict = raidlib.Raid().decide(action)
    except raidlib.RaidError as exc:
        return _text_result(f"[raid] raidd unavailable (fail closed): {exc}", is_error=True)

    effect_verdict = str(verdict.get("effect", "deny"))
    lines = [f"verdict: {effect_verdict}"]
    if effect_verdict == "deny":
        lines.append(f"reason: {verdict.get('reason_code')}")
    elif effect_verdict == "require_approval":
        appr = verdict.get("approval") or {}
        lines.append(f"approval: {appr.get('id')}")
        lines.append("Have a human approve it in the Raid TUI or with "
                     f"`raid approval approve {appr.get('id')} --expected-version 0`.")
    return _text_result("\n".join(lines))


def _pending():
    try:
        data = raidlib.Raid().approvals()
    except raidlib.RaidError as exc:
        return _text_result(f"[raid] raidd unavailable: {exc}", is_error=True)
    items = data if isinstance(data, list) else []
    pending = [a for a in items if a.get("state") == "pending"]
    if not pending:
        return _text_result("no approvals pending.")
    return _text_result("\n".join(f"- {a.get('id')} {a.get('operation')} "
                                  f"[{a.get('environment')}]" for a in pending))


def _handle(message):
    method = message.get("method")
    msg_id = message.get("id")
    if method == "initialize":
        _write({
            "jsonrpc": "2.0", "id": msg_id,
            "result": {
                "protocolVersion": (message.get("params") or {}).get("protocolVersion", PROTOCOL_VERSION),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        })
        return
    if method == "notifications/initialized":
        return
    if method == "tools/list":
        _write({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": _TOOLS}})
        return
    if method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "raid_check":
            _write({"jsonrpc": "2.0", "id": msg_id, **_check(args)})
        elif name == "raid_pending":
            _write({"jsonrpc": "2.0", "id": msg_id, **_pending()})
        else:
            _write({"jsonrpc": "2.0", "id": msg_id,
                    "result": {"content": [{"type": "text", "text": f"unknown tool: {name}"}],
                               "isError": True}})
        return
    if msg_id is not None:
        _write({"jsonrpc": "2.0", "id": msg_id,
                "result": {"content": [{"type": "text", "text": "unknown method"}], "isError": True}})


def main():
    while True:
        message = _read_message()
        if message is None:
            break
        try:
            _handle(message)
        except Exception as exc:  # noqa: BLE001
            _write({"jsonrpc": "2.0",
                    "result": {"content": [{"type": "text", "text": f"mcp error: {exc}"}],
                               "isError": True}})
    return 0


if __name__ == "__main__":
    sys.exit(main())