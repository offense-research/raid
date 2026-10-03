/**
 * raid-guard.js — OpenCode plugin that gates tool calls with Raid.
 *
 * OpenCode loads JavaScript/TypeScript plugin modules that can hook tool
 * events. This plugin registers `tool.execute.before`, bridges the call to the
 * shared Raid classifier, and blocks the call by throwing when the verdict is
 * `deny` or `require_approval`.
 *
 * The classifier itself lives in Python (`integrations/cli/raid-check.py`), so
 * this plugin shells out to it rather than reimplementing the normalization —
 * there is exactly one classifier across every Raid agent adapter.
 *
 * OpenCode's own permission flow is left in force on `allow` (the hook returns
 * without throwing), so Raid only ever *restricts* what OpenCode would already
 * permit. Raid approval is deliberately NOT mapped to an OpenCode prompt: an
 * in-editor confirmation would authorize the action without a Raid receipt.
 * Approval stays in Raid and the agent retries.
 *
 * Fail-closed: if the classifier cannot be run, or returns no verdict, the call
 * is blocked. A model is never the arbiter of authority.
 *
 * Place this file in `.opencode/plugins/` (project) or
 * `~/.config/opencode/plugins/` (global). See README.md.
 */

import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PROVIDER = "opencode";

// integrations/opencode/plugin/raid-guard.js -> integrations/cli/raid-check.py
const HERE = path.dirname(fileURLToPath(import.meta.url));
const RAID_CHECK =
  process.env.RAID_CHECK_PY || path.resolve(HERE, "..", "..", "cli", "raid-check.py");
const RAID_PYTHON = process.env.RAID_PYTHON || "python3";

/** Ask Raid whether this tool call may run. Never throws; never allows on error. */
function judge(tool, args, cwd) {
  let res;
  try {
    res = spawnSync(RAID_PYTHON, [RAID_CHECK, "--provider", PROVIDER], {
      input: JSON.stringify({ tool_name: tool, tool_input: args || {}, cwd }),
      encoding: "utf8",
      timeout: 10000,
    });
  } catch (err) {
    return { effect: "deny", reason: `[raid] could not run the Raid classifier: ${err}` };
  }
  if (res.error || res.status === null) {
    return {
      effect: "deny",
      reason: `[raid] could not run the Raid classifier: ${res.error || "no exit status"}`,
    };
  }
  const out = (res.stdout || "").trim();
  if (!out) {
    return {
      effect: "deny",
      reason: `[raid] classifier returned no verdict, blocked: ${(res.stderr || "").trim()}`,
    };
  }
  try {
    const verdict = JSON.parse(out.split("\n").pop());
    if (!verdict || !verdict.effect) {
      return { effect: "deny", reason: "[raid] classifier returned an empty verdict, blocked" };
    }
    return verdict;
  } catch (err) {
    return { effect: "deny", reason: `[raid] unparseable verdict, blocked: ${out}` };
  }
}

function approvalMessage(reasonCode, approvalId) {
  const id = approvalId || "<id>";
  return (
    `[raid] this action requires approval (${reasonCode || ""}, approval ${id}). ` +
    `Approve it in the Raid TUI or with \`raid approval approve ${id} --expected-version 0\`, ` +
    `then retry.`
  );
}

export const RaidGuard = async ({ directory, worktree }) => {
  const cwd = worktree || directory || process.cwd();
  return {
    "tool.execute.before": async (input, output) => {
      const tool = (input && input.tool) || "tool";
      const args = (output && output.args) || {};
      const verdict = judge(tool, args, cwd);

      if (verdict.effect === "deny") {
        throw new Error(verdict.reason || `[raid] blocked by policy (${verdict.reason_code || "POLICY_DENY"})`);
      }
      if (verdict.effect === "require_approval") {
        throw new Error(approvalMessage(verdict.reason_code, verdict.approval && verdict.approval.id));
      }
      // allow: return normally, leaving OpenCode's own permission flow in force.
    },
  };
};

export default RaidGuard;
