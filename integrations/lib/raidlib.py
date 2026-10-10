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

import hashlib
import http.client
import json
import os
import re
import shlex
import socket
import time
import urllib.parse

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

# ---------------------------------------------------------------------------
# Egress & exfiltration guardrails, and session taint
# ---------------------------------------------------------------------------
#
# Two things sit on top of the filename-based secret regex above:
#
#   * secret *values* -- the shapes a credential takes once it is on a command
#     line, in a URL, or in a request body. The filename regex catches "the
#     agent touched .env"; these catch "the agent is about to send the key".
#   * a per-session taint ledger -- cross-call context that no single command
#     can express. Reading credential material, or pulling in outside content,
#     marks the session; a later egress or a later privileged action is then
#     judged by the policy in that light.
#
# raidd itself stays stateless. The session belongs to the adapter, and the
# ledger is how it is carried between calls. Both are additions to the
# free-form resource.attributes string map, so no schema change is involved.

# Credential *value* shapes. These match case-sensitively against the original
# text: base64url and the provider prefixes are case-bearing, so lowercasing
# the payload first would silently stop matching them.
_SECRET_VALUE_RX = [
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),                       # OpenAI
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),                  # GitHub
    re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),                # GitHub fine-grained
    re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),                    # GitLab
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),                # Slack
    re.compile(r"AKIA[0-9A-Z]{16}"),                            # AWS access key id
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),                       # Google API key
    re.compile(r"npm_[A-Za-z0-9]{36}"),                         # npm
    re.compile(r"pypi-[A-Za-z0-9_-]{50,}"),                     # PyPI
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),  # JWT
    re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----"),           # PEM private key
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*", re.I),   # bearer token
    # name = <long opaque value>: requires both a letter and a digit, so prose
    # like `token: documentation` does not trip it.
    re.compile(
        r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
        r"private[_-]?key|passwd|password)\b[\"']?\s*[:=]\s*[\"']?"
        r"(?=[A-Za-z0-9_\-/+]*[0-9])(?=[A-Za-z0-9_\-/+]*[A-Za-z])[A-Za-z0-9_\-/]{20,}"
    ),
]

# Outbound network text in a shell command.
_NET_EGRESS_RX = re.compile(
    r"\b(curl|wget|nc|ncat|netcat|scp|sftp|rsync|ssh|telnet|ftp|"
    r"invoke-webrequest|invoke-restmethod)\b"
)

# Operations whose effect is durable, privileged, or credential-bearing: what
# an injected instruction reaches for. Ordinary reads of source are not here.
_PRIVILEGED_OPS = frozenset({
    "shell.execute", "shell.write", "shell.delete",
    "filesystem.write", "filesystem.delete",
    "git.push", "git.force_push", "git.rewrite",
    "package.install",
    "service.exec", "container.exec",
    "db.mutate", "cloud.mutate",
})

# How long a session's taint survives without activity: long enough to cover a
# working session, short enough that a stale file cannot haunt a machine.
_LEDGER_TTL_SECONDS = 12 * 3600


def _ledger_enabled():
    return os.environ.get("RAID_NO_LEDGER", "").lower() not in ("1", "true", "yes")


def _secret_values(text):
    """True when text carries something shaped like a credential value."""
    if not text:
        return False
    return any(rx.search(text) for rx in _SECRET_VALUE_RX)


def _segment_egress(toks, joined):
    """True when a segment sends data to the network."""
    if any(os.path.basename(t) in _NETWORK_VERBS for t in toks):
        return True
    return bool(_NET_EGRESS_RX.search(joined))


def _is_privileged(op, attrs):
    """Whether an operation is worth gating once the session is tainted."""
    if op in _PRIVILEGED_OPS:
        return True
    # Touching credential material is privileged whatever the operation slug:
    # an injected "print the .env" is the canonical credential-access move.
    return attrs.get("secret") == "true"


def _ledger_key():
    """The key the taint ledger is filed under.

    ``RAID_SESSION`` when the host sets it. Otherwise a stable key derived from
    principal + agent + working directory, so taint still spans the calls of
    one session without the host wiring anything. It is deliberately *not* the
    principal's own session_id: that field falls back to a fresh random value
    per call, which would file every call under a new key and turn cross-call
    taint into a silent no-op.
    """
    sid = os.environ.get("RAID_SESSION", "").strip()
    if sid:
        return "session:" + sid
    p = principal()
    cwd = os.environ.get("RAID_CWD") or os.getcwd()
    return "principal:%s:%s:%s" % (p["subject_id"], p["agent_id"], cwd)


def _ledger_dir():
    base = os.environ.get("RAID_LEDGER_DIR")
    if not base:
        state = os.environ.get("XDG_STATE_HOME") or os.path.join(
            os.path.expanduser("~"), ".local", "state"
        )
        base = os.path.join(state, "offense", "raid", "sessions")
    return base


def _ledger_path(key):
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", key)[:160] or "default"
    return os.path.join(_ledger_dir(), safe + ".json")


def ledger_load(key):
    """Read a session's taint. Returns (state, readable).

    Never raises. An unreadable ledger is returned as *fully* tainted so a
    caller cannot mistake an unknown session for a clean one; an absent or
    expired ledger is a clean session, which is the honest reading of
    "nothing has happened yet".
    """
    state = {"secret_touched": False, "untrusted": False}
    if not _ledger_enabled():
        return state, False
    try:
        with open(_ledger_path(key), "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        return state, True
    except Exception:
        return {"secret_touched": True, "untrusted": True}, False
    if not isinstance(raw, dict):
        return {"secret_touched": True, "untrusted": True}, False
    updated = raw.get("updated_at")
    if isinstance(updated, (int, float)) and (time.time() - updated) > _LEDGER_TTL_SECONDS:
        return state, True
    if raw.get("secret_touched") is True:
        state["secret_touched"] = True
    if raw.get("untrusted") is True:
        state["untrusted"] = True
    return state, True


def ledger_update(key, secret_touched=False, untrusted=False):
    """Fold this call's effects into the session ledger. Never raises."""
    if not _ledger_enabled() or not (secret_touched or untrusted):
        return True
    state, _ok = ledger_load(key)
    if secret_touched:
        state["secret_touched"] = True
    if untrusted:
        state["untrusted"] = True
    try:
        d = _ledger_dir()
        os.makedirs(d, mode=0o700, exist_ok=True)
        path = _ledger_path(key)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({
                "secret_touched": state["secret_touched"],
                "untrusted": state["untrusted"],
                "updated_at": time.time(),
            }, fh)
        os.replace(tmp, path)
        return True
    except Exception:
        # A ledger that cannot be written fails closed at the policy layer:
        # the next call reads an unreadable ledger and is judged tainted.
        return False


def session_guard_attrs(op, attrs, egress=False, outbound_secret=False,
                        secret_touched=False, untrusted_input=False):
    """Session-scoped guardrail attributes for one call, and the ledger step.

    The ledger is read *before* this call's own effects are recorded, so a
    credential read or an untrusted fetch taints what happens next -- never the
    call that did it.
    """
    key = _ledger_key()
    state, readable = ledger_load(key)
    out = {
        "egress": "true" if egress else "false",
        "outbound_secret": "true" if (egress and outbound_secret) else "false",
        "tainted_egress": "true" if (egress and state["secret_touched"]) else "false",
        "untrusted_source": "true"
        if (_is_privileged(op, attrs) and state["untrusted"])
        else "false",
        # Surfaces the honest limit: when the host neither sets RAID_SESSION nor
        # offers a writable ledger, cross-call taint is not in effect, and a
        # policy can say so rather than silently trusting nothing.
        "session_tracked": "true" if readable else "false",
    }
    ledger_update(key, secret_touched=secret_touched, untrusted=untrusted_input)
    return out


# ---------------------------------------------------------------------------
# Intermediary / router integrity (arXiv:2604.08407, "Your Agent Is Mine")
# ---------------------------------------------------------------------------
#
# The client sits behind a chain of routers; every hop re-originates TLS and so
# sees each in-flight JSON payload. Nothing in the deployed stack binds the
# tool-call arguments the provider returned to the arguments the client finally
# executes, so one hop can inject a call the model never made, rewrite one it
# did, or reorder a declared sequence.
#
# This mirrors core/integrity in the Go engine, attribute for attribute, so one
# policy bundle behaves the same under every adapter. Like the taint ledger it
# decides nothing: it stamps conclusions onto resource.attributes, and the
# policy in raidd decides, deterministically and fail-closed.
#
# The pins come from the environment, because the adapter is the only layer that
# knows what it asked for and what came back:
#
#   RAID_ENDPOINT          URL/host a response actually came from
#   RAID_TRUSTED_HOSTS     comma/space separated provider endpoints
#   RAID_ROUTER_HOSTS      comma/space separated third-party routers
#   RAID_EXPECT_PROVIDER   the provider that was requested
#   RAID_EXPECT_MODEL      the model that was requested
#   RAID_OBSERVED_PROVIDER the provider the response claimed
#   RAID_OBSERVED_MODEL    the model the response claimed
#   RAID_ATTESTED=1        the response carried a verifiable provider signature
#   RAID_DECLARED_CALLS    JSON list of {"tool": str, "input": {...}} the model declared
#   RAID_CALL_INDEX        this call's position in that declared sequence
#   RAID_INTEGRITY_LOG     append-only transparency log file (off when unset)
#
# Everything defaults to "false". An adapter that knows nothing about provenance
# says so rather than implying the response was verified.

_INTEGRITY_DEFAULTS = (
    "provider_verified",
    "provider_unattested",
    "model_mismatch",
    "intermediary",
    "router_untrusted",
    "injected_call",
    "tool_args_unverified",
    "sequence_anomaly",
)


def _env_list(name):
    raw = os.environ.get(name, "")
    return [p for p in re.split(r"[,\s]+", raw.strip()) if p]


def _env_true(name):
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _same_name(a, b):
    return (a or "").strip().lower() == (b or "").strip().lower()


def host_of(endpoint):
    """Lowercase host of a URL, host:port, or bare host."""
    e = (endpoint or "").strip()
    if not e:
        return ""
    if "://" not in e:
        e = "//" + e
    try:
        return (urllib.parse.urlsplit(e).hostname or "").lower()
    except ValueError:
        return ""


def host_matches(host, patterns):
    """Whether host is a pattern or a subdomain of one."""
    h = (host or "").strip().lower()
    if not h:
        return False
    for p in patterns or ():
        p = (p or "").strip().lower()
        if p.startswith("*."):
            p = p[2:]
        if p.startswith("."):
            p = p[1:]
        if not p:
            continue
        if h == p or h.endswith("." + p):
            return True
    return False


def classify_host(host, trusted, routers):
    """(intermediary, untrusted) for an endpoint host.

    A trusted host is not an intermediary; a listed router is untrusted by
    definition; any other host is still an intermediary hop but unflagged. An
    unknown host accuses nobody -- the provenance attributes fail closed.
    """
    if not (host or "").strip():
        return False, False
    if host_matches(host, trusted):
        return False, False
    if host_matches(host, routers):
        return True, True
    return True, False


def provenance_attrs(endpoint=None, provider=None, model=None,
                     observed_provider=None, observed_model=None,
                     trusted=None, routers=None, attested=None):
    """Provenance attributes: which upstream produced the response.

    provider_verified requires an attested response from a pinned provider host
    naming the requested provider and model. Everything else is
    provider_unattested, so a policy fails closed rather than trusting silence.
    """
    env = os.environ
    endpoint = env.get("RAID_ENDPOINT", "") if endpoint is None else endpoint
    provider = env.get("RAID_EXPECT_PROVIDER", "") if provider is None else provider
    model = env.get("RAID_EXPECT_MODEL", "") if model is None else model
    observed_provider = (
        env.get("RAID_OBSERVED_PROVIDER", "")
        if observed_provider is None
        else observed_provider
    )
    observed_model = (
        env.get("RAID_OBSERVED_MODEL", "") if observed_model is None else observed_model
    )
    trusted = _env_list("RAID_TRUSTED_HOSTS") if trusted is None else trusted
    routers = _env_list("RAID_ROUTER_HOSTS") if routers is None else routers
    attested = _env_true("RAID_ATTESTED") if attested is None else bool(attested)

    if not (endpoint or provider or model or observed_provider or observed_model
            or trusted or routers or attested):
        # Nothing is configured, so make no provenance claim at all. An adapter
        # that does no provenance check says nothing rather than accusing every
        # response; the policy stays quiet instead of prompting on every call.
        return {
            "provider_verified": "false",
            "provider_unattested": "false",
            "model_mismatch": "false",
            "intermediary": "false",
            "router_untrusted": "false",
        }

    host = host_of(endpoint)
    intermediary, untrusted = classify_host(host, trusted, routers)

    verified = bool(
        attested
        and not intermediary
        and observed_provider
        and _same_name(observed_provider, provider)
        and (not observed_model or not model or _same_name(observed_model, model))
    )
    mismatch = bool(
        attested
        and not intermediary
        and observed_model
        and model
        and not _same_name(observed_model, model)
    )
    return {
        "provider_verified": "true" if verified else "false",
        "provider_unattested": "false" if verified else "true",
        "model_mismatch": "true" if mismatch else "false",
        "intermediary": "true" if intermediary else "false",
        "router_untrusted": "true" if untrusted else "false",
    }


def call_digest(tool_name, tool_input):
    """Canonical SHA-256 digest of a tool call.

    Mirrors core/integrity.Digest. Digests are only ever compared inside one
    adapter, so a caller never needs two languages to agree byte for byte.
    """
    payload = json.dumps(
        {"tool": (tool_name or "").strip().lower(), "arguments": tool_input or {}},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def screen_calls(declared, received_tool, received_input):
    """(injected, args_unverified) against the calls the model declared.

    injected: no declared call names the tool. args_unverified: a declared call
    names it with different arguments. Nothing declared is not a judgement.
    """
    if not declared:
        return False, False
    rf = call_digest(received_tool, received_input)
    same_tool = False
    for d in declared:
        if not _same_name(d.get("tool"), received_tool):
            continue
        same_tool = True
        if call_digest(d.get("tool"), d.get("input")) == rf:
            return False, False
    if same_tool:
        return False, True
    return True, False


def screen_sequence(declared, index, received_tool, received_input):
    """Whether the call at index differs from what the model declared there."""
    if not declared or index is None or index < 0 or index >= len(declared):
        return False
    d = declared[index]
    return (
        not _same_name(d.get("tool"), received_tool)
        or call_digest(d.get("tool"), d.get("input"))
        != call_digest(received_tool, received_input)
    )


def declared_calls():
    """The calls the model declared for this turn, from RAID_DECLARED_CALLS."""
    raw = os.environ.get("RAID_DECLARED_CALLS", "").strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except Exception:
        return []
    if not isinstance(parsed, list):
        return []
    out = []
    for item in parsed:
        if isinstance(item, dict) and item.get("tool"):
            out.append({"tool": item.get("tool"), "input": item.get("input") or {}})
    return out


def call_index():
    """This call's position in the declared sequence, or None."""
    try:
        return int(os.environ.get("RAID_CALL_INDEX", "").strip())
    except (TypeError, ValueError):
        return None


def integrity_attrs(tool_name, tool_input, declared=None, index=None, **provenance):
    """All eight intermediary-integrity attributes for one call."""
    attrs = {name: "false" for name in _INTEGRITY_DEFAULTS}
    attrs.update(provenance_attrs(**provenance))
    injected, unverified = screen_calls(declared, tool_name, tool_input)
    attrs["injected_call"] = "true" if injected else "false"
    attrs["tool_args_unverified"] = "true" if unverified else "false"
    attrs["sequence_anomaly"] = (
        "true" if screen_sequence(declared, index, tool_name, tool_input) else "false"
    )
    return attrs


def integrity_log(entry, path=None):
    """Append one event to the transparency log. Never raises.

    The paper's third deployable client-side defense: an append-only record of
    what the client received, for audit against the provider's own view.
    Disabled unless RAID_INTEGRITY_LOG names a file or a path is passed.
    """
    target = path if path is not None else os.environ.get("RAID_INTEGRITY_LOG", "")
    if not target:
        return False
    try:
        d = os.path.dirname(target)
        if d:
            os.makedirs(d, mode=0o700, exist_ok=True)
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"time": time.time(), "entry": entry}, sort_keys=True))
            fh.write("\n")
        os.chmod(target, 0o600)
        return True
    except Exception:
        return False


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
    egress = _segment_egress(toks, low)
    attrs = {
        "verb": verb,
        "destructive": "true" if _segment_destructive(toks, low) else "false",
        "exfil": "true" if _segment_exfil(toks, low) else "false",
        "protected_branch": _protected_branch(toks),
        "egress": "true" if egress else "false",
        # Matched against the original-case segment: these patterns are
        # case-bearing (base64url, provider prefixes).
        "outbound_secret": "true"
        if (egress and _secret_values(segment))
        else "false",
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
    ``protected_branch``/``egress``/``outbound_secret`` attributes are set to
    explicit "true"/"false" strings so policies can match them without failing
    on a missing key.
    """
    segments = _split_segments(cmd)
    if not segments:
        return "shell.read", "read", "shell", _base_attrs(cmd, {})
    best = None
    destructive = False
    exfil = False
    egress = False
    outbound_secret = False
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
        if attrs.get("egress") == "true":
            egress = True
        if attrs.get("outbound_secret") == "true":
            outbound_secret = True
        if attrs.get("protected_branch") == "true":
            protected = "true"
        if not branch and attrs.get("branch"):
            branch = attrs["branch"]
        rank = _EFFECT_RANK.get(fx, 0)
        if best is None or rank > best[3]:
            best = (op, fx, rtype, rank)
    op, fx, rtype, _ = best
    # Cross-segment exfiltration: a secret referenced anywhere plus a network
    # command or outbound pipe anywhere in the compound command. The second
    # clause extends this from "named a credential path" to "carried an actual
    # credential value", which the filename regex alone would miss.
    joined_all = cmd.lower()
    if not exfil and (_SECRET_RX.search(joined_all) or _secret_values(cmd)):
        if _NET_EGRESS_RX.search(joined_all):
            exfil = True
    if egress:
        outbound_secret = outbound_secret or _secret_values(cmd)
    if destructive and _EFFECT_RANK.get(fx, 0) < _EFFECT_RANK["delete"]:
        op, fx = "shell.delete", "delete"
    attrs = {
        "verb": verb,
        "destructive": "true" if destructive else "false",
        "exfil": "true" if exfil else "false",
        "protected_branch": protected,
        "egress": "true" if egress else "false",
        "outbound_secret": "true" if (egress and outbound_secret) else "false",
    }
    if branch:
        attrs["branch"] = branch
    attrs["command"] = cmd.strip()[:512]
    return op, fx, rtype, attrs


def _base_attrs(cmd, extra):
    attrs = {
        "verb": "", "destructive": "false", "exfil": "false",
        "protected_branch": "false", "egress": "false", "outbound_secret": "false",
    }
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

    # A path argument aimed at credential material is marked the same way the
    # shell classifier marks it from the command text; without this a file tool
    # pointed at .env would go unremarked.
    if rtype == "path":
        attrs.setdefault("secret", "false")
        if resource_id and _SECRET_RX.search(str(resource_id).lower()):
            attrs["secret"] = "true"

    # --- session guardrails: egress/exfiltration and untrusted-input taint ---
    cmd_text = str(tin.get("command") or tin.get("description") or "")
    egress = bash_attrs.get("egress") == "true"
    outbound_secret = bash_attrs.get("outbound_secret") == "true"
    secret_touched = attrs.get("secret") == "true" or bool(
        _SECRET_RX.search(cmd_text.lower())
    )
    untrusted_input = False

    if tool_name in ("websearch", "webfetch"):
        # Pulling in outside content is both the untrusted-input case the
        # injection guardrail keys on, and egress in its own right.
        egress = True
        untrusted_input = True
        outbound_secret = outbound_secret or _secret_values(str(resource_id))
        secret_touched = secret_touched or _secret_values(str(resource_id))

    attrs.update(session_guard_attrs(
        operation, attrs,
        egress=egress,
        outbound_secret=outbound_secret,
        secret_touched=secret_touched,
        untrusted_input=untrusted_input,
    ))

    attrs.update(integrity_attrs(
        tool_name, tin,
        declared=declared_calls(),
        index=call_index(),
    ))

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