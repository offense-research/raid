#!/usr/bin/env python3
"""raidlib: shared logic for Raid coding-agent integrations (Claude Code).

Two jobs:
  1. A tiny HTTP-over-unix-socket client for the raidd daemon (stdlib only,
     no curl). See RaidHTTP.
  2. tool_to_action(): translate an agent tool call (name + input) into the
     normalized Raid ActionRequest so a policy can gate it deterministically.

The mapping is intentionally coarse: the adapter classifies a call into a
small, closed set of operation slugs (shell.write, git.push, ...). The real
decision always happens in raidd against the active policy; this file only
builds the request. A model is never the arbiter of authority.
"""

import http.client
import json
import os
import re
import shlex
import socket

# ---------------------------------------------------------------------------
# raidd HTTP client (unix socket)
# ---------------------------------------------------------------------------


class RaidError(Exception):
    """Raised on transport errors or a non-2xx raidd response."""


class RaidUnixConnection(http.client.HTTPConnection):
    """HTTPConnection that dials an AF_UNIX socket (raidd's default)."""

    def __init__(self, sock_path):
        super().__init__("localhost")
        self._raid_sock = sock_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self._raid_sock)


def socket_path():
    return os.environ.get("RAID_SOCKET", "/run/offense/raid/raid.sock")


class Raid:
    """Minimal raidd client bound to a socket."""

    def __init__(self, sock=None):
        self.sock = sock or socket_path()

    def _request(self, method, path, body=None, approver=None):
        conn = RaidUnixConnection(self.sock)
        headers = {"Content-Type": "application/json"}
        if approver:
            headers["X-Raid-Approver"] = approver
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            status = resp.status
        except OSError as exc:
            raise RaidError(f"cannot reach raidd at {self.sock}: {exc}") from exc
        except Exception:
            raise
        finally:
            conn.close()
        if status < 200 or status >= 300:
            raise RaidError(f"raidd {method} {path}: HTTP {status}: {data[:300]!r}")
        try:
            return json.loads(data) if data else None
        except json.JSONDecodeError:
            return {"_raw": data.decode("utf-8", "replace")}

    def decide(self, action):
        return self._request("POST", "/v1/decisions", json.dumps(action).encode())

    def decision_get(self, decision_id):
        return self._request("GET", f"/v1/decisions/{decision_id}")

    def decision_wait(self, decision_id, timeout_ns=None):
        q = f"?timeout_ns={timeout_ns}" if timeout_ns else ""
        return self._request("GET", f"/v1/decisions/{decision_id}/wait{q}")

    def approvals(self, approver=None):
        return self._request("GET", "/v1/approvals", approver=approver)


# ---------------------------------------------------------------------------
# principal / context from the environment
# ---------------------------------------------------------------------------


def principal():
    return {
        "subject_id": os.environ.get("RAID_SUBJECT", os.environ.get("USER", "local")),
        "agent_id": os.environ.get("RAID_AGENT", "claude-code"),
        "session_id": os.environ.get("RAID_SESSION", "ses_" + os.urandom(4).hex()),
        "runtime": os.environ.get("RAID_RUNTIME", "claude-code"),
        "groups": [g for g in os.environ.get("RAID_GROUPS", "").replace(",", " ").split()],
        "trust_level": os.environ.get("RAID_TRUST", "local-session"),
        "revision": int(os.environ.get("RAID_REVISION", "1") or "1"),
    }


def provider():
    """The agent product this adapter speaks for.

    Defaults to "claude-code" so the existing Claude Code/Cursor adapters are
    unchanged; newer adapters (VS Code, Windsurf, ...) set RAID_PROVIDER so the
    audit trail names the real caller.
    """
    return os.environ.get("RAID_PROVIDER", "claude-code")


def context(source_request_id, interactive=True):
    return {
        "timestamp": _now_rfc3339(),
        "source_product": provider(),
        "source_version": "0.1.0",
        "source_request_id": source_request_id,
        "task_summary": os.environ.get("RAID_TASK", ""),
        "interactive": interactive,
    }


def _now_rfc3339():
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# tool call -> normalized action
# ---------------------------------------------------------------------------

# (regex, operation, effect) applied in order; first match wins.
# Force-push and history-rewrite are matched before a plain push so the
# narrower slug wins.
_BASH_RULES = [
    (re.compile(r"\brm\b|\brmdir\b|\btruncate\b"), "shell.delete", "delete"),
    (re.compile(r"\bgit\s+push\b[^\n]*(?:\s-f\b|--force(?:-with-lease)?\b)"), "git.force_push", "write"),
    (re.compile(r"\bgit\s+(reset\s+--hard|clean\s+-[fdx]|branch\s+-D|tag\s+-d|filter-branch)"), "git.rewrite", "write"),
    (re.compile(r"\bgit\s+push\b"), "git.push", "write"),
    (re.compile(r"\bgit\s+(merge|rebase|revert|cherry-pick)\b"), "git.push", "write"),
    (re.compile(r"\b(pip|uv|poetry|npm|yarn|pnpm|cargo|go|apt|apt-get|brew|apk|dnf|yum|gem)\s+(install|add|remove|uninstall|update|upgrade)\b"), "package.install", "write"),
    (re.compile(r"\b(systemctl|service|init|rc\.d)\b"), "service.exec", "execute"),
    (re.compile(r"\b(docker|kubectl|podman|helm)\b"), "container.exec", "execute"),
    (re.compile(r"\b(psql|mysql|sqlite3|sqlcmd|mongo(?:sh)?)\b"), "db.mutate", "write"),
    (re.compile(r"\b(aws|gcloud|az|heroku|flyctl|vercel|gh\s+.*(?:release|label|pr\s+merge|repo\s+delete))\b"), "cloud.mutate", "write"),
    (re.compile(r"\b(curl|wget|ftp|git\s+clone)\b"), "network.fetch", "read"),
    (re.compile(r"\b(cat|ls|head|tail|grep|rg|find|stat|wc|du|df|which|type|pwd|echo|printf)\b|\bgit\s+(status|log|diff|show|branch|remote|config|stash\s+list)\b"), "shell.read", "read"),
    (re.compile(r"\b(chmod|chown|dd|mkfs|mount|sudo|su)\b"), "shell.execute", "execute"),
    (re.compile(r"\b(sed\s+-i|cp|mv|mkdir|touch|tee|install|ln)\b"), "shell.write", "write"),
]

_WRITE_OPS = {"cat", "tee", "cp", "mv", "mkdir", "touch", "install", "unzip", "tar", "sed"}
_READ_OPS = {"cat", "ls", "head", "tail", "grep", "rg", "find", "stat", "wc", "du", "df", "which", "type", "pwd", "echo", "printf", "jq", "awk"}

# Higher rank = more consequential; used to pick the command's operation when
# a compound command has several segments.
_EFFECT_RANK = {"read": 0, "write": 1, "execute": 2, "delete": 3}

# Paths whose subtree must never be deleted by an agent.
_HARD_SYSTEM_PREFIXES = (
    "/etc", "/usr", "/var", "/boot", "/dev", "/lib", "/lib64",
    "/bin", "/sbin", "/root", "/proc", "/sys",
)
# Whole-directory targets that are always destructive to remove.
_SYSTEM_ROOTS = {
    "/", "/home", "/tmp", "/opt", "/srv", "/*", "/.",
    "~", "~/*", "$HOME", "${HOME}", ".", "..", "*",
}

# Credential / secret material that must not leave the machine.
_SECRET_RX = re.compile(
    r"(\.env(\.[a-z0-9]+)?|id_rsa|id_ed25519|id_ecdsa|\.pem\b|\.key\b|"
    r"\.aws/credentials|\.netrc|\.git-credentials|\.npmrc|"
    r"\.docker/config\.json|credentials\.json|secrets?\.(ya?ml|json|txt|env))"
)
_NETWORK_VERBS = {"curl", "wget", "nc", "ncat", "netcat", "scp", "sftp", "rsync", "ssh", "telnet", "ftp"}
_PROTECTED_BRANCHES = {"main", "master", "trunk", "release", "production", "prod"}


def _split_segments(cmd):
    """Split a shell command on control operators (loose, quote-unaware)."""
    parts = re.split(r"(?:&&|\|\||;|\n|\|)", cmd)
    return [p.strip() for p in parts if p.strip()]


def _tokens(segment):
    """Tokenize a segment, dropping leading env assignments and wrappers."""
    try:
        toks = shlex.split(segment)
    except ValueError:
        toks = segment.split()
    out = []
    for t in toks:
        if t in ("sudo", "command", "env", "nohup", "time"):
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t):
            continue
        out.append(t)
    return out


def _rm_targets_destructive(toks):
    targets = [t for t in toks[1:] if not t.startswith("-")]
    if not targets:
        return False
    for t in targets:
        if t in _SYSTEM_ROOTS:
            return True
        if t.startswith("~"):
            return True
        stripped = t.rstrip("/") or "/"
        if stripped in _SYSTEM_ROOTS or stripped == "/":
            return True
        if stripped.startswith(_HARD_SYSTEM_PREFIXES):
            return True
        # /tmp/*, /var/*: wiping a whole system directory's contents.
        if stripped.endswith("/*") and stripped.startswith("/"):
            if os.path.dirname(stripped) in _SYSTEM_ROOTS:
                return True
    return False


def _segment_destructive(toks, joined):
    if not toks:
        return False
    verb = os.path.basename(toks[0])
    rest = toks[1:]
    if verb in ("rm", "rmdir", "unlink"):
        return _rm_targets_destructive(toks)
    if verb == "dd" and any(t.startswith("of=/dev/") for t in rest):
        return True
    if verb.startswith("mkfs"):
        return True
    if verb in ("chmod", "chown") and any(t.startswith("-") and "R" in t for t in rest):
        return any((t in _SYSTEM_ROOTS) for t in rest if not t.startswith("-"))
    if verb == "find" and any(t in ("-delete",) for t in rest):
        return any((t in _SYSTEM_ROOTS or t.startswith(_HARD_SYSTEM_PREFIXES)) for t in rest)
    if verb == "truncate" and any(t in _SYSTEM_ROOTS for t in rest):
        return True
    if ":(){" in joined:
        return True
    if re.search(r">\s*/dev/(sd|nvme|hd|vd)", joined):
        return True
    return False


def _segment_exfil(toks, joined):
    if not _SECRET_RX.search(joined):
        return False
    if any(os.path.basename(t) in _NETWORK_VERBS for t in toks):
        return True
    return bool(re.search(r"\b(curl|wget|nc|ncat|scp|sftp|rsync|ssh|ftp)\b", joined))


def _protected_branch(toks):
    if not toks or os.path.basename(toks[0]) != "git":
        return "false"
    sub = toks[1] if len(toks) > 1 else ""
    if sub not in ("push", "reset", "clean", "branch", "tag"):
        return "false"
    for t in toks[2:]:
        if t.startswith("-"):
            continue
        name = t.split(":")[-1]
        if name in _PROTECTED_BRANCHES:
            return "true"
    return "false"


def _branch_of(toks):
    if not toks or os.path.basename(toks[0]) != "git":
        return ""
    sub = toks[1] if len(toks) > 1 else ""
    if sub in ("push",):
        cand = [t for t in toks[2:] if not t.startswith("-")]
        if len(cand) >= 2:
            return cand[-1].split(":")[-1]
    if sub in ("checkout", "switch"):
        cand = [t for t in toks[2:] if not t.startswith("-")]
        if cand:
            return cand[-1]
    return ""


def classify_segment(segment):
    """Return (operation, effect, resource_type, attrs) for one segment."""
    low = segment.strip().lower()
    toks = _tokens(segment)
    verb = os.path.basename(toks[0]) if toks else ""
    if not low:
        return "shell.read", "read", "shell", {}
    op, fx, rtype = None, None, "shell"
    for rx, o, f in _BASH_RULES:
        if rx.search(low):
            op, fx = o, f
            break
    if op is None:
        if verb in _WRITE_OPS:
            op, fx = "shell.write", "write"
        elif verb in _READ_OPS:
            op, fx = "shell.read", "read"
        else:
            op, fx = "shell.execute", "execute"
    attrs = {
        "verb": verb,
        "destructive": "true" if _segment_destructive(toks, low) else "false",
        "exfil": "true" if _segment_exfil(toks, low) else "false",
        "protected_branch": _protected_branch(toks),
    }
    branch = _branch_of(toks)
    if branch:
        attrs["branch"] = branch
    target = _primary_target(toks)
    if target:
        attrs["target"] = target
    return op, fx, rtype, attrs


def _primary_target(toks):
    for t in toks[1:]:
        if not t.startswith("-") and not re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t):
            return t
    return ""


def classify_bash(cmd):
    """Return (operation, effect, resource_type) for a shell command.

    Backwards-compatible wrapper over analyze_bash.
    """
    op, fx, rtype, _attrs = analyze_bash(cmd)
    return op, fx, rtype


def analyze_bash(cmd):
    """Classify a (possibly compound) shell command.

    Returns (operation, effect, resource_type, attributes). The operation is
    taken from the most consequential segment; ``destructive``/``exfil``/
    ``protected_branch`` attributes are set to explicit "true"/"false" strings
    so policies can match them without failing on a missing key.
    """
    segments = _split_segments(cmd)
    if not segments:
        return "shell.read", "read", "shell", _base_attrs(cmd, {})
    best = None
    destructive = False
    exfil = False
    protected = "false"
    branch = ""
    verb = ""
    for seg in segments:
        op, fx, rtype, attrs = classify_segment(seg)
        if not verb:
            verb = attrs.get("verb", "")
        if attrs.get("destructive") == "true":
            destructive = True
        if attrs.get("exfil") == "true":
            exfil = True
        if attrs.get("protected_branch") == "true":
            protected = "true"
        if not branch and attrs.get("branch"):
            branch = attrs["branch"]
        rank = _EFFECT_RANK.get(fx, 0)
        if best is None or rank > best[3]:
            best = (op, fx, rtype, rank)
    op, fx, rtype, _ = best
    # Cross-segment exfiltration: a secret referenced anywhere plus a network
    # command or outbound pipe anywhere in the compound command.
    joined_all = cmd.lower()
    if not exfil and _SECRET_RX.search(joined_all):
        if re.search(r"\b(curl|wget|nc|ncat|netcat|scp|sftp|rsync|ssh|ftp|telnet)\b", joined_all):
            exfil = True
    if destructive and _EFFECT_RANK.get(fx, 0) < _EFFECT_RANK["delete"]:
        op, fx = "shell.delete", "delete"
    attrs = {
        "verb": verb,
        "destructive": "true" if destructive else "false",
        "exfil": "true" if exfil else "false",
        "protected_branch": protected,
    }
    if branch:
        attrs["branch"] = branch
    attrs["command"] = cmd.strip()[:512]
    return op, fx, rtype, attrs


def _base_attrs(cmd, extra):
    attrs = {"verb": "", "destructive": "false", "exfil": "false", "protected_branch": "false"}
    attrs["command"] = (cmd or "").strip()[:512]
    attrs.update(extra)
    return attrs


def _typed(value, key=""):
    """Coerce a Python value into Raid's typed argument shape as best we can."""
    if isinstance(value, bool):
        return {"type": "bool", "value": value}
    if isinstance(value, int):
        return {"type": "number", "value": value}
    if isinstance(value, float):
        return {"type": "number", "value": value}
    if isinstance(value, str):
        return {"type": "string", "value": value}
    if isinstance(value, list):
        return {"type": "list", "value": [_typed(v) for v in value[:16]]}
    if isinstance(value, dict):
        return {"type": "list", "value": [_typed(v, k) for k, v in list(value.items())[:16]]}
    return {"type": "string", "value": str(value)}


def tool_to_action(tool_name, tool_input, request_id, environment="development", cwd=""):
    """Translate a Claude Code tool call into a Raid ActionRequest."""
    tool_name = (tool_name or "").lower()
    tin = tool_input or {}
    args = {}
    bash_attrs = {}

    if tool_name in ("bash", "writetoterminal"):
        raw = str(tin.get("command") or tin.get("description") or "")
        op, fx, rtype, bash_attrs = analyze_bash(raw)
        resource_id = str(tin.get("cwd") or cwd or ".")
        if raw.strip():
            args = {"command": raw}
    elif tool_name in ("edit", "write", "notebookedit"):
        op, fx, rtype = "filesystem.write", "write", "path"
        resource_id = str(tin.get("file_path") or tin.get("path") or ".")
        args = {"old_string": tin.get("old_string"), "new_string": tin.get("new_string")}
    elif tool_name in ("readfile", "multigetfile", "ls"):
        op, fx, rtype = "shell.read", "read", "path"
        resource_id = str(tin.get("file_path") or tin.get("path") or cwd or ".")
        args = {}
    elif tool_name in ("websearch", "webfetch"):
        op, fx, rtype = "network.fetch", "read", "url"
        resource_id = str(tin.get("url") or "search")
    else:
        op, fx, rtype = "shell.execute", "execute", "tool"
        resource_id = tool_name

    operation = op if op.startswith("shell.") or "." in op else f"shell.{op}"
    attrs = {}
    if tin.get("cwd"):
        attrs["cwd"] = str(tin.get("cwd"))
    if cwd:
        attrs.setdefault("cwd", cwd)
    attrs.update(bash_attrs)
    environment = environment or os.environ.get("RAID_ENV", "development")
    auth = principal()
    action = {
        "schema_version": 1,
        "request_id": request_id,
        "principal": auth,
        "action": {
            "provider": provider(),
            "operation": operation,
            "effect": fx if fx != "execute" else "execute",
        },
        "resource": {
            "type": rtype,
            "id": resource_id,
            "environment": environment,
            "attributes": attrs,
        },
        "arguments": {
            k: _typed(v) for k, v in (args or {}).items() if v is not None
        },
        "context": context(request_id),
    }
    return action