#!/usr/bin/env python3
"""assurance-matrix.py - run the hook-layer defense fixtures across every adapter.

One adapter passing proves very little about the others: each ships its own gate
script and each host reads a different field to decide whether to honour a
block. The bug worth catching is therefore not "did it say deny" but "did it say
deny in a field this host actually enforces" - a denial written into a field the
host ignores is silently discarded and the tool call runs anyway.

For each host this harness drives the adapter's *real* gate with the *real*
stdin payload that host sends, and asserts:

  * an in-scope write is allowed
  * an out-of-scope write is blocked, AND the block is expressed in the field
    this host reads
  * a shell redirect that leaves the scope is blocked (the classifier bug where
    `echo x > /etc/hosts` read as a *read*)
  * an undeclared env var in a state-changing call is blocked
  * a benign in-scope read is allowed

Surfaces, and what each can observe:

  hook hosts   claude-code, crush, pi, omp, cursor, windsurf
               trajectory + confinement, at the tool call.
  shim hosts   codex, aider  (no pre-tool hook)
               confinement + trajectory for shell commands, via raid-exec.
  plugins      opencode, hermes, openclaw
               config-level check only here; their gate runs in-process and
               needs the host binary.

Not coverable at any adapter surface, for any host: tool-schema attestation and
response-delta auditing. Both live on the API transport. See the Claude Code
harness for those.

Usage:  python3 assurance-matrix.py [--root DIR] [--keep]
Exit:   0 all scenarios passed, 1 one or more failed.
"""

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
EXEC = REPO / "integrations" / "cli" / "raid-exec.py"
PRESET = REPO / "core" / "policy" / "presets" / "solo-dev-safe.yaml"
RAIDD = REPO / "raidd"

HOOK_HOSTS = ("claude-code", "crush", "pi", "omp", "cursor", "windsurf")
SHIM_HOSTS = ("codex", "aider")
PLUGIN_HOSTS = ("opencode", "hermes", "openclaw")


# --- per-host payload shapes -------------------------------------------------

def p_pretooluse(tool, inp, cwd):
    """The Claude-Code-shaped PreToolUse payload: claude-code, crush, pi, omp."""
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": inp, "cwd": str(cwd)}


def p_cursor(tool, inp, cwd):
    if tool == "bash":
        return {"hook_event_name": "beforeShellExecution", "command": inp.get("command", ""),
                "cwd": str(cwd)}
    return {"hook_event_name": "preToolUse", "tool_name": tool, "tool_input": inp, "cwd": str(cwd)}


def p_windsurf(tool, inp, cwd):
    if tool == "bash":
        return {"agent_action_name": "pre_run_command",
                "tool_info": {"command_line": inp.get("command", "")}, "cwd": str(cwd)}
    return {"agent_action_name": "pre_write_code",
            "tool_info": {"file_path": inp.get("file_path", "")}, "cwd": str(cwd)}


PAYLOAD = {"claude-code": p_pretooluse, "crush": p_pretooluse, "pi": p_pretooluse,
           "omp": p_pretooluse, "cursor": p_cursor, "windsurf": p_windsurf}


def blocked_by(host, rc, out):
    """Would this host refuse the call?

    Only signals that host actually honours count, and they differ per host:
    a denial written into a field the host ignores is silently discarded and the
    tool call runs anyway, which is exactly the bug worth catching. So the
    honoured signal is named per host rather than guessed:

      claude-code  blocking exit, or hookSpecificOutput.permissionDecision
                   (schema-validated; a `decision` key nested there is DROPPED)
      pi / omp     blocking exit, or permissionDecision
      crush        the exit status is the contract (README: deny -> exit 2)
      windsurf     Cascade blocks on exit 2
      cursor       the stdout permission object; the exit status stays 0 even
                   for a denial, so requiring non-zero here would be wrong
    """
    try:
        j = json.loads((out or "").strip() or "{}")
    except ValueError:
        j = {}
    hso = j.get("hookSpecificOutput") or {}
    if host == "cursor":
        return j.get("permission") == "deny"
    if host in ("crush", "windsurf"):
        return rc == 2
    return (rc == 2 or hso.get("permissionDecision") == "deny"
            or j.get("decision") == "block")


def said_deny_anywhere(out):
    """Did the adapter say deny at all, in any field?

    Used only to sharpen the diagnosis when a block did not take effect: it
    separates 'denied in a field the host ignores' from 'never denied'.
    """
    try:
        j = json.loads((out or "").strip() or "{}")
    except ValueError:
        return False
    hso = j.get("hookSpecificOutput") or {}
    return (hso.get("permissionDecision") == "deny" or hso.get("decision") == "block"
            or j.get("decision") == "block" or j.get("permission") == "deny")


class Matrix:
    def __init__(self, root):
        self.root = pathlib.Path(root)
        self.scope = self.root / "scope"
        self.outside = self.root / "outside"
        self.ledger = self.root / "ledger"
        self.sock = self.root / "raid.sock"
        self.results = []
        self.skips = []
        self.daemon = None

    def setup(self):
        shutil.rmtree(self.root, ignore_errors=True)
        for d in (self.root, self.scope, self.outside, self.ledger):
            d.mkdir(parents=True, exist_ok=True)
        (self.scope / "ok.txt").write_text("seed\n")

    def boot(self):
        log = open(self.root / "raidd.log", "w")
        self.daemon = subprocess.Popen(
            [str(RAIDD), "--solo", "--socket", str(self.sock),
             "--db", str(self.root / "raid.db"), "--policy", str(PRESET)],
            stdout=log, stderr=subprocess.STDOUT)
        for _ in range(80):
            if self.sock.exists():
                return True
            time.sleep(0.25)
        return False

    def stop(self):
        if self.daemon and self.daemon.poll() is None:
            self.daemon.terminate()
            try:
                self.daemon.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.daemon.kill()

    def env(self, host, **extra):
        env = dict(os.environ)
        env.update({
            "RAID_SOCKET": str(self.sock),
            "RAID_LEDGER_DIR": str(self.ledger),
            "RAID_ENV": "development",
            "RAID_CWD": str(self.scope),
            "RAID_CONFINE_PATHS": str(self.scope),
            "RAID_CONFINE_ENV": "HOME,PATH",
            "RAID_PROVIDER": host,
        })
        env.pop("RAID_SESSION", None)
        env.update({k: v for k, v in extra.items() if v is not None})
        return env

    def hook(self, host, tool, inp, **extra):
        gate = REPO / "integrations" / host / "hook_gate.py"
        payload = PAYLOAD[host](tool, inp, self.scope)
        proc = subprocess.run([sys.executable, str(gate)], input=json.dumps(payload),
                              capture_output=True, text=True,
                              env=self.env(host, **extra), cwd=str(self.scope), timeout=60)
        blocked = blocked_by(host, proc.returncode, proc.stdout)
        return blocked, proc.returncode, (proc.stdout or proc.stderr or "").strip()

    def shim(self, host, argv, **extra):
        proc = subprocess.run([sys.executable, str(EXEC), "--", *argv],
                              capture_output=True, text=True,
                              env=self.env(host, **extra), cwd=str(self.scope), timeout=60)
        return proc.returncode, (proc.stderr or proc.stdout or "").strip()

    def check(self, group, name, passed, detail=""):
        self.results.append({"group": group, "name": name, "pass": bool(passed), "detail": detail})
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))
        return passed

    def skip(self, group, name, detail=""):
        self.skips.append({"group": group, "name": name, "detail": detail})
        print(f"  [SKIP] {name}" + (f" - {detail}" if detail else ""))


def group_hook_host(h, host):
    print(f"\n[{host}] hook layer, real gate + real payload")
    gate = REPO / "integrations" / host / "hook_gate.py"
    if not gate.exists():
        h.skip(host, f"{host} hook gate present", "no hook_gate.py in this adapter")
        return

    blocked, rc, out = h.hook(host, "write",
                              {"file_path": str(h.scope / "ok2.txt"), "content": "x"})
    h.check(host, "an in-scope write is allowed", not blocked, f"exit={rc}")

    blocked, rc, out = h.hook(host, "write",
                              {"file_path": str(h.outside / "esc.txt"), "content": "x"})
    h.check(host, "an out-of-scope write is blocked", blocked, f"exit={rc}")
    if not blocked:
        h.check(host, "the denial is in a field this host honours",
                not said_deny_anywhere(out),
                "denied in a field the host ignores - the call would still run"
                if said_deny_anywhere(out) else "no denial emitted at all")

    blocked, rc, out = h.hook(host, "bash",
                              {"command": f"echo pwned > {h.outside}/redir.txt"})
    h.check(host, "a shell redirect out of scope is blocked", blocked, f"exit={rc}")
    if not blocked:
        h.check(host, "the redirect denial is in a field this host honours",
                not said_deny_anywhere(out),
                "denied in a field the host ignores" if said_deny_anywhere(out)
                else "no denial emitted at all")

    blocked, rc, out = h.hook(host, "bash",
                              {"command": f"printf %s $AWS_SECRET_ACCESS_KEY > {h.scope}/leak2.txt"})
    h.check(host, "an undeclared env var in a state-changing call is blocked", blocked, f"exit={rc}")

    blocked, rc, out = h.hook(host, "bash",
                              {"command": f"echo ok > {h.scope}/in2.txt"})
    h.check(host, "an in-scope redirect is allowed", not blocked, f"exit={rc}")

    blocked, rc, out = h.hook(host, "read", {"file_path": str(h.scope / "ok.txt")})
    h.check(host, "a benign in-scope read is allowed", not blocked, f"exit={rc}")

    # The trajectory ledger, at the hook layer this host has.
    envs = {"RAID_SESSION": "traj", "RAID_TRAJECTORY_MAX_ACTIONS": "2",
            "RAID_TRAJECTORY_OPS": "shell.write"}
    saw_block = False
    for i in range(3):
        blocked, rc, out = h.hook(host, "bash",
                                  {"command": f"echo x > {h.scope}/q{i}.txt"}, **envs)
        if i == 2:
            saw_block = blocked
    h.check(host, "a call past the declared quota is blocked", saw_block,
            "trajectory quota enforced at the hook")


def group_shim_host(h, host):
    print(f"\n[{host}] shim layer (no pre-tool hook), via raid-exec")
    rc, out = h.shim(host, ["sh", "-c", f"echo ok > {h.scope}/shim.txt"])
    h.check(host, "an in-scope command runs", rc == 0, f"exit={rc}")
    target = h.outside / f"shim-{host}.txt"
    if target.exists():
        target.unlink()
    rc, out = h.shim(host, ["sh", "-c", f"echo pwned > {target}"])
    h.check(host, "an out-of-scope redirect is refused", rc == 125, f"exit={rc}")
    h.check(host, "and it did not run", not target.exists(),
            "target absent" if not target.exists() else "target created")


def group_plugin_host(h, host):
    print(f"\n[{host}] plugin adapter (static check, no execution)")
    d = REPO / "integrations" / host
    install = d / "install.sh"
    h.check(host, "the adapter ships an installer", install.exists(), str(install))

    # The gate is a host plugin, not a hook script: its manifest is the artifact.
    plugin = d / "plugin"
    manifests = []
    if plugin.is_dir():
        manifests = [p for p in plugin.iterdir()
                     if p.name.endswith((".json", ".yaml", ".yml", ".js", ".py"))]
    examples = sorted(d.glob("*.example")) + sorted(d.glob("*/*.example"))
    h.check(host, "it ships a gate artifact (plugin manifest or example config)",
            bool(manifests or examples),
            ", ".join(p.name for p in manifests) or ",".join(e.name for e in examples) or "none")

    # Static, and deliberately so: running these installers writes into $HOME,
    # and their gate needs the host binary, which is not installed here.
    body = install.read_text() if install.exists() else ""
    h.check(host, "its installer references the gate and a Raid socket",
            "RAID_SOCKET" in body and ("plugin" in body or "hook" in body),
            "wires the plugin to raidd" if "RAID_SOCKET" in body else "no RAID_SOCKET wiring")
    h.skip(host, f"{host} gate exercised end to end",
           "its gate runs in-process in the host and needs the host binary, which "
           "is not installed here; only the adapter's own artifacts are checked")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="/home/nebula/matrix-test")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--hosts", default="")
    args = ap.parse_args()

    h = Matrix(args.root)
    h.setup()
    if not h.boot():
        print("FATAL: raidd did not come up; see", h.root / "raidd.log")
        return 1
    print(f"raidd up on {h.sock} with {PRESET.name}")
    try:
        for host in HOOK_HOSTS:
            group_hook_host(h, host)
        for host in SHIM_HOSTS:
            group_shim_host(h, host)
        for host in PLUGIN_HOSTS:
            group_plugin_host(h, host)
    finally:
        h.stop()
        if not args.keep:
            shutil.rmtree(h.root, ignore_errors=True)

    passed = sum(1 for r in h.results if r["pass"])
    failed = [r for r in h.results if not r["pass"]]
    print(f"\n=== {passed}/{len(h.results)} checks passed, {len(h.skips)} skipped ===")
    for r in failed:
        print(f"  FAIL {r['group']}: {r['name']} ({r['detail']})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
