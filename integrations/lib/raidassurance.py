#!/usr/bin/env python3
"""raidassurance.py - agent-assurance ledgers for the Python adapters.

The Python half of the four defense classes in the Raid engine
(`core/integrity/assurance.go`): trajectory assurance, tool-schema
attestation, response-delta auditing, and sub-invocation confinement.

Raid stays stateless. An adapter holds the session state and stamps its
*conclusion* into `resource.attributes` - a free string map - so no schema
change is needed and an adapter that emits none of these behaves exactly as
before. Every attribute defaults to "false" and the policy guards each
condition with `has(...) == "true"`, so a present-but-false attribute changes
nothing.

Which surface can see which class
---------------------------------
A pre-tool-call hook (Claude Code's PreToolUse, and the equivalent in the
other hosts) is handed a *tool call* and nothing else. It therefore can
observe only:

    trajectory_*    - is this call, in the context of the calls before it,
                      still inside the plan the session declared?
    confinement_*   - does this call's target sit inside the scope the
                      session declared?

It can never observe the tool *manifest* the provider presented, nor the
completion the provider returned: those exist only at the transport layer.
`screen_schema` and `audit_stream` implement the second pair for a caller
that *does* sit on the transport (a proxy, an executor, a replay harness).
This module implements all four; the hook wires up the two it can see.

Nothing here decides anything. It only reports.
"""

import hashlib
import json
import os
import re
import time

# ---------------------------------------------------------------------------
# attribute names (must match core/integrity/assurance.go)
# ---------------------------------------------------------------------------

ATTR_TRAJECTORY_TRACKED = "trajectory_tracked"
ATTR_TRAJECTORY_ATTESTED = "trajectory_attested"
ATTR_TRAJECTORY_DRIFT = "trajectory_drift"
ATTR_TRAJECTORY_UNPLANNED = "trajectory_unplanned"
ATTR_TRAJECTORY_QUOTA_EXCEEDED = "trajectory_quota_exceeded"

ATTR_TOOL_SCHEMA_ATTESTED = "tool_schema_attested"
ATTR_TOOL_SCHEMA_MUTATED = "tool_schema_mutated"
ATTR_HIDDEN_TOOL_INJECTED = "hidden_tool_injected"
ATTR_BOUNDARY_TAMPERED = "boundary_tampered"

ATTR_STREAM_AUDITED = "stream_audited"
ATTR_STREAM_PREFIX_MISMATCH = "stream_prefix_mismatch"
ATTR_STREAM_SUFFIX_INJECTED = "stream_suffix_injected"
ATTR_RESPONSE_DELTA = "response_delta"

ATTR_CONFINEMENT_TRACKED = "confinement_tracked"
ATTR_CONFINED = "confined"
ATTR_CONFINEMENT_ESCAPE = "confinement_escape"
ATTR_CONFINEMENT_WIDENED = "confinement_widened"
ATTR_ENV_ESCAPE = "env_escape"

ASSURANCE_ATTRIBUTES = (
    ATTR_TRAJECTORY_TRACKED, ATTR_TRAJECTORY_ATTESTED, ATTR_TRAJECTORY_DRIFT,
    ATTR_TRAJECTORY_UNPLANNED, ATTR_TRAJECTORY_QUOTA_EXCEEDED,
    ATTR_TOOL_SCHEMA_ATTESTED, ATTR_TOOL_SCHEMA_MUTATED,
    ATTR_HIDDEN_TOOL_INJECTED, ATTR_BOUNDARY_TAMPERED,
    ATTR_STREAM_AUDITED, ATTR_STREAM_PREFIX_MISMATCH,
    ATTR_STREAM_SUFFIX_INJECTED, ATTR_RESPONSE_DELTA,
    ATTR_CONFINEMENT_TRACKED, ATTR_CONFINED, ATTR_CONFINEMENT_ESCAPE,
    ATTR_CONFINEMENT_WIDENED, ATTR_ENV_ESCAPE,
)

_LEDGER_TTL_SECONDS = 12 * 3600


def _env_list(name):
    raw = os.environ.get(name, "")
    return [p for p in re.split(r"[,\s]+", raw.strip()) if p]


def _env_int(name):
    raw = os.environ.get(name, "").strip()
    return int(raw) if raw.isdigit() else 0


def _bool(value):
    return "true" if value else "false"


# ---------------------------------------------------------------------------
# trajectory (arXiv:2608.01558)
# ---------------------------------------------------------------------------


def _plan():
    """The plan the session declared, or None when nothing was declared.

    Declared through the environment so a deployment can set it without a code
    change, and so the ledger makes no claim until an operator opts in.
    """
    ops = _env_list("RAID_TRAJECTORY_OPS")
    max_actions = _env_int("RAID_TRAJECTORY_MAX_ACTIONS")
    max_targets = _env_int("RAID_TRAJECTORY_MAX_TARGETS")
    if not ops and not max_actions and not max_targets:
        return None
    return {"operations": ops, "max_actions": max_actions, "max_targets": max_targets}


def _step_path(ledger_dir, key):
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", key or "default")[:160] or "default"
    return os.path.join(ledger_dir, safe + ".assurance.json")


def _load_steps(ledger_dir, key):
    """Read the session's observed trajectory. Never raises.

    An unreadable or absent ledger is an empty trajectory: the honest reading
    of "this session has no record yet". The failure mode that matters here is
    the opposite one - a ledger that *claims* clean when it is not - and that
    is why every conclusion stays false when the store cannot be trusted.
    """
    path = _step_path(ledger_dir, key)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if time.time() - float(data.get("ts", 0)) > _LEDGER_TTL_SECONDS:
            return {"steps": [], "targets": []}
        steps = [s for s in data.get("steps", []) if isinstance(s, dict)]
        targets = [t for t in data.get("targets", []) if isinstance(t, str)]
        return {"steps": steps, "targets": targets}
    except (OSError, ValueError, TypeError):
        return {"steps": [], "targets": []}


def _save_steps(ledger_dir, key, state):
    path = _step_path(ledger_dir, key)
    try:
        os.makedirs(ledger_dir, exist_ok=True)
        state = {**state, "ts": time.time()}
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh)
        os.replace(tmp, path)
    except OSError:
        pass


def trajectory_attrs(operation, target, ledger_dir, key):
    """Stamp the trajectory ledger for a call about to run.

    The call is recorded *first*, so drift is a property of the trajectory
    that includes it - this call is where the invariant broke.
    """
    attrs = {
        ATTR_TRAJECTORY_TRACKED: "false",
        ATTR_TRAJECTORY_ATTESTED: "false",
        ATTR_TRAJECTORY_DRIFT: "false",
        ATTR_TRAJECTORY_UNPLANNED: "false",
        ATTR_TRAJECTORY_QUOTA_EXCEEDED: "false",
    }
    plan = _plan()
    if plan is None:
        return attrs

    state = _load_steps(ledger_dir, key)
    state["steps"].append({"op": operation, "target": target or ""})
    if target and target not in state["targets"]:
        state["targets"].append(target)
    _save_steps(ledger_dir, key, state)

    unplanned = False
    if plan["operations"]:
        allowed = set(plan["operations"])
        unplanned = any(s.get("op") not in allowed for s in state["steps"])

    quota = (
        (plan["max_actions"] > 0 and len(state["steps"]) > plan["max_actions"])
        or (plan["max_targets"] > 0 and len(state["targets"]) > plan["max_targets"])
    )

    attrs[ATTR_TRAJECTORY_TRACKED] = "true"
    attrs[ATTR_TRAJECTORY_UNPLANNED] = _bool(unplanned)
    attrs[ATTR_TRAJECTORY_QUOTA_EXCEEDED] = _bool(quota)
    attrs[ATTR_TRAJECTORY_DRIFT] = _bool(quota)
    attrs[ATTR_TRAJECTORY_ATTESTED] = _bool(not unplanned and not quota)
    return attrs


# ---------------------------------------------------------------------------
# confinement (arXiv:2608.10530)
# ---------------------------------------------------------------------------


def _scope_from_env(prefix="RAID_CONFINE_"):
    paths = _env_list(prefix + "PATHS")
    hosts = _env_list(prefix + "HOSTS")
    envvars = _env_list(prefix + "ENV")
    if not paths and not hosts and not envvars:
        return None
    return {"paths": paths, "hosts": hosts, "env": envvars}


def within_roots(target, roots):
    t = os.path.normpath(str(target).strip())
    if not t:
        return False
    for root in roots:
        r = os.path.normpath(str(root).strip())
        if not r:
            continue
        if t == r or t.startswith(r.rstrip(os.sep) + os.sep):
            return True
    return False


def host_of(endpoint):
    s = str(endpoint or "").strip()
    if not s:
        return ""
    if "://" in s:
        s = s.split("://", 1)[1]
    s = re.split(r"[/?#]", s, 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    s = s.split(":", 1)[0]
    return s.strip().lower()


def host_allowed(host, patterns):
    h = str(host or "").strip().lower()
    for p in patterns:
        p = str(p).strip().lower()
        if not p:
            continue
        if h == p or h.endswith("." + p):
            return True
    return False


def _env_refs_in(cmd):
    """Environment variables a shell command references ($VAR / ${VAR})."""
    out, seen = [], set()
    for m in re.finditer(r"\$\{?([A-Za-z_][A-Za-z0-9_]*|[0-9])", str(cmd or "")):
        name = m.group(1)
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _shell_targets(cmd):
    """Filesystem paths a shell command names.

    A pre-tool-call hook receives a Bash call as one opaque command string, so a
    path that appears only inside it -- `echo x > /etc/hosts` -- is invisible to
    a screen that reads path *arguments*. Without this, a shell redirect steps
    straight around the confinement ledger; the target has to be pulled back out
    of the command text.
    """
    s = str(cmd or "")
    if not s:
        return []
    out, seen = [], set()

    def add(p):
        p = str(p or "").strip().strip("'\"")
        # A variable or a URL is not a resolvable local path.
        if p and p not in seen and not p.startswith("$") and "://" not in p:
            seen.add(p)
            out.append(p)

    toks = s.split()
    for i, t in enumerate(toks):
        if t in (">", ">>", "1>", "2>", "&>", "1>>", "2>>"):
            if i + 1 < len(toks):
                add(toks[i + 1])
        elif t.startswith(">") and len(t) > 1:
            add(t[1:])

    if toks:
        verb = os.path.basename(toks[0])
        if verb == "tee":
            for t in toks[1:]:
                if not t.startswith("-"):
                    add(t)

    for t in toks:
        if t.startswith(("/", "~", "./", "../")) or "/" in t:
            add(t)
    return out


def _scope_widens(parent, child):
    if parent["paths"]:
        for p in child["paths"]:
            if not within_roots(p, parent["paths"]):
                return True
    if parent["hosts"]:
        for h in child["hosts"]:
            if not host_allowed(h, parent["hosts"]):
                return True
    if parent["env"]:
        allowed = set(parent["env"])
        for v in child["env"]:
            if v not in allowed:
                return True
    return False


def _resolve_targets(paths, cwd):
    """Make each candidate absolute, so a relative path is judged where it lands.

    A relative path resolves against the session's own working directory, which
    is normally inside the scope; only an absolute path (or an expansion of one)
    can leave it.
    """
    out = []
    for p in paths or []:
        p = str(p or "").strip().strip("'\"")
        if not p or p.startswith("$"):
            continue
        if p.startswith("~"):
            p = os.path.expanduser(p)
        if os.path.isabs(p):
            out.append(os.path.normpath(p))
        elif cwd:
            out.append(os.path.normpath(os.path.join(str(cwd), p)))
    return out


def confinement_attrs(targets, host, env_refs, child_scope=None, cwd=""):
    attrs = {
        ATTR_CONFINEMENT_TRACKED: "false",
        ATTR_CONFINED: "false",
        ATTR_CONFINEMENT_ESCAPE: "false",
        ATTR_CONFINEMENT_WIDENED: "false",
        ATTR_ENV_ESCAPE: "false",
    }
    scope = _scope_from_env()
    if scope is None:
        return attrs

    resolved = _resolve_targets(targets, cwd)
    escape = False
    if scope["paths"] and resolved:
        escape = any(not within_roots(t, scope["paths"]) for t in resolved)
    if not escape and host and scope["hosts"]:
        escape = not host_allowed(host, scope["hosts"])

    env_escape = False
    if scope["env"]:
        allowed = set(scope["env"])
        env_escape = any(ref not in allowed for ref in env_refs)

    widened = bool(child_scope) and _scope_widens(scope, child_scope)

    attrs[ATTR_CONFINEMENT_TRACKED] = "true"
    attrs[ATTR_CONFINEMENT_ESCAPE] = _bool(escape)
    attrs[ATTR_ENV_ESCAPE] = _bool(env_escape)
    attrs[ATTR_CONFINEMENT_WIDENED] = _bool(widened)
    attrs[ATTR_CONFINED] = _bool(not escape and not env_escape and not widened)
    return attrs


# ---------------------------------------------------------------------------
# tool-schema attestation (arXiv:2604.08407, 2606.10749)
# ---------------------------------------------------------------------------


def canonical_json(text):
    """Re-marshal JSON through an encoder that sorts keys.

    Key order and incidental whitespace are not mutations: a serialiser that
    reorders keys must not read as a tampered schema.
    """
    t = str(text or "").strip()
    if not t:
        return ""
    try:
        return json.dumps(json.loads(t), sort_keys=True, separators=(",", ":"))
    except ValueError:
        return t


def schema_digest(name, schema):
    h = hashlib.sha256()
    h.update(str(name or "").strip().encode())
    h.update(b"\x00")
    h.update(canonical_json(schema).encode())
    return h.hexdigest()


def response_digest(text):
    return hashlib.sha256(canonical_json(text).encode()).hexdigest()


def pin_manifest(tools, boundary):
    """Pin the manifest a session expects: {name: digest} plus boundary digest."""
    pinned = {str(t.get("name", "")).strip(): schema_digest(t.get("name"), t.get("schema"))
              for t in (tools or [])}
    return {"tools": pinned, "boundary": response_digest(boundary) if boundary else ""}


def screen_schema(pinned, presented_tools, presented_boundary=""):
    attrs = {
        ATTR_TOOL_SCHEMA_ATTESTED: "false",
        ATTR_TOOL_SCHEMA_MUTATED: "false",
        ATTR_HIDDEN_TOOL_INJECTED: "false",
        ATTR_BOUNDARY_TAMPERED: "false",
    }
    if not pinned or not (pinned.get("tools") or pinned.get("boundary")):
        return attrs

    mutated = hidden = False
    for t in presented_tools or []:
        name = str(t.get("name", "")).strip()
        want = pinned["tools"].get(name)
        if want is None:
            hidden = True
            continue
        if schema_digest(name, t.get("schema")) != want:
            mutated = True

    tampered = bool(pinned["boundary"]) and response_digest(presented_boundary) != pinned["boundary"]

    attrs[ATTR_TOOL_SCHEMA_MUTATED] = _bool(mutated)
    attrs[ATTR_HIDDEN_TOOL_INJECTED] = _bool(hidden)
    attrs[ATTR_BOUNDARY_TAMPERED] = _bool(tampered)
    attrs[ATTR_TOOL_SCHEMA_ATTESTED] = _bool(not mutated and not hidden and not tampered)
    return attrs


# ---------------------------------------------------------------------------
# response-delta / stream auditing (arXiv:2604.08407)
# ---------------------------------------------------------------------------


def audit_stream(delivered, parsed, anchor="", stop=""):
    """Compare the completion as delivered with the one the client went on to use.

    `delivered` is what the transport handed over; `parsed` is what the calling
    agent actually acted on. A difference between them is a rewrite in flight.
    """
    attrs = {
        ATTR_STREAM_AUDITED: "false",
        ATTR_STREAM_PREFIX_MISMATCH: "false",
        ATTR_STREAM_SUFFIX_INJECTED: "false",
        ATTR_RESPONSE_DELTA: "false",
    }
    if delivered is None or parsed is None:
        return attrs

    body = str(delivered).lstrip(" \t\r\n")
    prefix_mismatch = bool(anchor) and not body.startswith(str(anchor))

    suffix_injected = False
    if stop:
        i = str(delivered).find(str(stop))
        if i >= 0 and str(delivered)[i + len(str(stop)):].strip():
            suffix_injected = True

    attrs[ATTR_STREAM_AUDITED] = "true"
    attrs[ATTR_STREAM_PREFIX_MISMATCH] = _bool(prefix_mismatch)
    attrs[ATTR_STREAM_SUFFIX_INJECTED] = _bool(suffix_injected)
    attrs[ATTR_RESPONSE_DELTA] = _bool(str(delivered) != str(parsed))
    return attrs


def defaults():
    """Every assurance attribute present and false, for a request with no ledger."""
    return {name: "false" for name in ASSURANCE_ATTRIBUTES}


# ---------------------------------------------------------------------------
# the per-call stamp used by a pre-tool-call hook
# ---------------------------------------------------------------------------


def _inputs(tool_name, tool_input):
    tin = tool_input or {}
    targets = []
    for k in ("file_path", "path", "filepath", "file", "target", "dir", "notebook_path"):
        if isinstance(tin.get(k), str) and tin[k].strip():
            targets.append(tin[k])
            break
    cmd = tin.get("command") or tin.get("cmd") or tin.get("script") or ""
    targets.extend(_shell_targets(cmd))
    raw = tin.get("url") or tin.get("uri") or tin.get("endpoint") or tin.get("host") or ""
    host = host_of(raw) if isinstance(raw, str) else ""
    return targets, host, _env_refs_in(cmd)


def assurance_attrs(operation, tool_name, tool_input, ledger_dir, key,
                    child_scope=None, cwd=""):
    """Stamp the two ledgers a pre-tool-call hook can actually observe.

    Trajectory and confinement, for the call about to run. The schema and
    stream ledgers are deliberately absent here: a hook is handed neither the
    tool manifest nor the completion, so it cannot screen them. Their names are
    still returned as false, so the attribute set is identical to the one a
    transport-layer adapter emits.
    """
    targets, host, env_refs = _inputs(tool_name, tool_input)
    attrs = {}
    attrs.update(trajectory_attrs(
        operation,
        (targets[0] if targets else "") or str((tool_input or {}).get("cwd") or ""),
        ledger_dir, key))
    attrs.update(confinement_attrs(targets, host, env_refs, child_scope, cwd))
    attrs[ATTR_TOOL_SCHEMA_ATTESTED] = "false"
    attrs[ATTR_TOOL_SCHEMA_MUTATED] = "false"
    attrs[ATTR_HIDDEN_TOOL_INJECTED] = "false"
    attrs[ATTR_BOUNDARY_TAMPERED] = "false"
    attrs[ATTR_STREAM_AUDITED] = "false"
    attrs[ATTR_STREAM_PREFIX_MISMATCH] = "false"
    attrs[ATTR_STREAM_SUFFIX_INJECTED] = "false"
    attrs[ATTR_RESPONSE_DELTA] = "false"
    return attrs
