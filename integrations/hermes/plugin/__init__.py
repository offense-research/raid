"""Raid guard — a native Hermes plugin that gates tool calls with Raid.

Hermes plugins are a directory with a `plugin.yaml` manifest and an
`__init__.py` exposing `register(ctx)`. This plugin registers a `pre_tool_call`
hook: it maps the tool call to a normalized Raid action with the shared
`raidlib`, asks the running raidd, and returns a block directive on `deny` /
`require_approval`.

`pre_tool_call` directives (per the Hermes hooks reference):
    return None                                    -> no objection
    return {"action": "block", "message": "..."}   -> stop the tool call
    return {"action": "approve", ...}              -> escalate to Hermes' own gate

Raid approval is deliberately NOT mapped to Hermes' `approve` directive: an
in-agent approval prompt would authorize the action without a Raid receipt,
defeating the evidence model. Approval stays in Raid — a human approves
out-of-band — and the agent retries.

Fail-closed: if raidd is unreachable, or the adapter errors, the call is
blocked. If the shared `raidlib` cannot be imported at all, the hook stays
inert (returns None) rather than bricking every tool call — install the plugin
where `integrations/lib/raidlib.py` is reachable, or set RAID_LIB_DIR.

Install: copy this directory to `~/.hermes/plugins/raid-guard/` and enable it
via `plugins.enabled` in the Hermes config (see ../README.md).
"""

import os
import sys

# Locate the shared Raid normalizer. The plugin ships inside the Raid checkout,
# so `integrations/lib` is three levels up: plugin/ -> hermes/ -> integrations/
# -> repo root. RAID_LIB_DIR overrides this for out-of-tree installs.
_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_LIB = os.path.abspath(os.path.join(_HERE, "..", "..", "lib"))
_LIB_DIR = os.environ.get("RAID_LIB_DIR", _DEFAULT_LIB)
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

try:  # noqa: SIM105 - import failure must degrade, not crash the agent
    import raidlib
except Exception:  # noqa: BLE001
    raidlib = None

# Hermes tool names -> the slugs raidlib.tool_to_action understands.
_TOOL_ALIASES = {
    "terminal": "bash",
    "shell": "bash",
    "bash": "bash",
    "execute": "bash",
    "code_execution": "bash",
    "read_file": "readfile",
    "readfile": "readfile",
    "read": "readfile",
    "view": "readfile",
    "write_file": "write",
    "write": "write",
    "create_file": "write",
    "edit_file": "edit",
    "edit": "edit",
    "apply_patch": "edit",
    "web_fetch": "webfetch",
    "fetch": "webfetch",
    "web_search": "websearch",
}

_ADMIN_COMMANDS = (
    "raid version", "raid doctor", "raid approval list", "raidd --help",
    "raidd --version", "raid policy from-language", "raid policy presets",
    "raid log", "raid grants",
)


def _is_admin(tool_name, args):
    if (tool_name or "").lower() != "bash":
        return False
    raw = str((args or {}).get("command", "")).strip().lower()
    return any(raw.startswith(cmd) for cmd in _ADMIN_COMMANDS)


def _on_pre_tool_call(tool_name=None, args=None, task_id=None, **kwargs):
    """pre_tool_call hook: consult Raid before a tool executes."""
    if raidlib is None:
        # Normalizer unavailable: do not brick the agent. Fail open, and note it.
        return None
    if _is_admin(tool_name, args):
        return None

    os.environ.setdefault("RAID_PROVIDER", "hermes")
    os.environ.setdefault("RAID_AGENT", "hermes")
    os.environ.setdefault("RAID_RUNTIME", "hermes")

    tool_input = args if isinstance(args, dict) else {}
    environment = os.environ.get("RAID_ENV", "development")
    cwd = os.environ.get("RAID_CWD", os.getcwd())
    normalized = _TOOL_ALIASES.get(str(tool_name or "").strip().lower(), tool_name or "")

    try:
        action = raidlib.tool_to_action(
            normalized,
            tool_input,
            request_id="hermes:" + os.urandom(4).hex(),
            environment=environment,
            cwd=cwd,
        )
        verdict = raidlib.Raid().decide(action)
    except Exception as exc:  # noqa: BLE001
        # raidd unreachable or an adapter error: fail closed.
        return {
            "action": "block",
            "message": f"[raid] raidd unavailable or adapter error, blocked: {exc}",
        }

    effect = str(verdict.get("effect", "deny"))
    if effect == "allow":
        return None
    if effect == "deny":
        return {
            "action": "block",
            "message": f"[raid] blocked by policy ({verdict.get('reason_code', 'POLICY_DENY')}).",
        }

    appr = verdict.get("approval") or {}
    appr_id = appr.get("id", "")
    return {
        "action": "block",
        "message": (
            f"[raid] this action requires approval ({verdict.get('reason_code', '')}, "
            f"approval {appr_id}). Approve it in the Raid TUI or with "
            f"`raid approval approve {appr_id} --expected-version 0`, then retry."
        ),
    }


def register(ctx):
    """Wire the Raid guard into Hermes' pre_tool_call hook."""
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
