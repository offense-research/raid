/**
 * index.js — OpenClaw plugin that gates tool calls with Raid.
 *
 * OpenClaw native plugins register typed lifecycle hooks. This plugin uses
 * `api.on("before_tool_call", ...)` to consult the running raidd before a tool
 * runs, and blocks with `{ block: true, blockReason }` when the verdict is
 * `deny` or `require_approval`.
 *
 * The classifier lives in Python (`integrations/cli/raid-check.py`) so there is
 * exactly one normalization across every Raid agent adapter; this plugin shells
 * out to it.
 *
 * Raid approval is deliberately NOT mapped to OpenClaw's own `requireApproval`
 * prompt: an in-agent confirmation would authorize the action without a Raid
 * receipt. Approval stays in Raid and the agent retries.
 *
 * Fail-closed: if the classifier cannot be run, or returns no verdict, the call
 * is blocked. A model is never the arbiter of authority.
 */

import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

const PROVIDER = "openclaw";

// integrations/openclaw/plugin/index.js -> integrations/cli/raid-check.py
const HERE = path.dirname(fileURLToPath(import.meta.url));
const RAID_CHECK =
  process.env.RAID_CHECK_PY || path.resolve(HERE, "..", "..", "cli", "raid-check.py");
const RAID_PYTHON = process.env.RAID_PYTHON || "python3";

/** Ask Raid whether this tool call may run. Never throws; never allows on error. */
function judge(tool, params, cwd) {
  let res;
  try {
    res = spawnSync(RAID_PYTHON, [RAID_CHECK, "--provider", PROVIDER], {
      input: JSON.stringify({ tool_name: tool, tool_input: params || {}, cwd }),
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

export default definePluginEntry({
  id: "raid-guard",
  name: "Raid guard",
  description: "Gate OpenClaw tool calls with the Raid policy engine.",
  register(api) {
    api.on("before_tool_call", (event, ctx) => {
      const tool = (event && (event.toolName || event.tool)) || "tool";
      const params = (event && (event.params || event.args)) || {};
      const cwd =
        (event && (event.cwd || event.workingDirectory)) ||
        (ctx && ctx.cwd) ||
        process.cwd();

      const verdict = judge(tool, params, cwd);

      if (verdict.effect === "deny") {
        return {
          block: true,
          blockReason:
            verdict.reason || `[raid] blocked by policy (${verdict.reason_code || "POLICY_DENY"})`,
        };
      }
      if (verdict.effect === "require_approval") {
        // Block with instructions rather than OpenClaw's `requireApproval`, so
        // the authorization stays inside Raid and produces a signed receipt.
        return {
          block: true,
          blockReason: approvalMessage(verdict.reason_code, verdict.approval && verdict.approval.id),
        };
      }
      // allow: return without a directive, leaving OpenClaw's own tool policy in force.
      return;
    });
  },
});
