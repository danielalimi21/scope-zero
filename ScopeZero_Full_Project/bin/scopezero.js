#!/usr/bin/env node
import { parseArgs } from "node:util";

const BASE_URL = process.env.SCOPEZERO_URL || "http://localhost:8788";
const API_KEY = process.env.SCOPEZERO_API_KEY || "";

async function api(method, path, body) {
  const headers = { "content-type": "application/json" };
  if (API_KEY) headers.authorization = `Bearer ${API_KEY}`;
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  const payload = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const msg = payload?.error?.message || `HTTP ${res.status}`;
    process.stderr.write(`Error: ${msg}\n`);
    process.exit(1);
  }
  return payload;
}

function out(data) {
  process.stdout.write(JSON.stringify(data, null, 2) + "\n");
}

function fail(msg) {
  process.stderr.write(`Error: ${msg}\n`);
  process.exit(1);
}

const USAGE = `
ScopeZero CLI — agent action authorization gateway

Usage:
  scopezero status
  scopezero agent register --tenant <id> --agent <id> --owner <email> [--tools tool1,tool2]
  scopezero mission create --tenant <id> --agent <id> --by <email> --objective <text> --tools tool1,tool2
  scopezero authorize --tenant <id> --agent <id> --mission <id> --tool <name> --action <action>
  scopezero ledger verify
  scopezero approvals
  scopezero approval approve <id> [--actor <email>]
  scopezero approval deny <id> [--actor <email>]

Environment:
  SCOPEZERO_URL      Gateway URL (default: http://localhost:8788)
  SCOPEZERO_API_KEY  Bearer token for authenticated gateways
`.trim();

const [,, command, subcommand, ...rest] = process.argv;

if (!command || command === "--help" || command === "-h") {
  process.stdout.write(USAGE + "\n");
  process.exit(0);
}

const { values, positionals } = parseArgs({
  args: [subcommand, ...rest].filter(Boolean),
  options: {
    tenant:    { type: "string" },
    agent:     { type: "string" },
    owner:     { type: "string" },
    tools:     { type: "string" },
    by:        { type: "string" },
    objective: { type: "string" },
    mission:   { type: "string" },
    tool:      { type: "string" },
    action:    { type: "string" },
    actor:     { type: "string" }
  },
  allowPositionals: true,
  strict: false
});

switch (command) {
  case "status": {
    const [health, ready] = await Promise.all([
      api("GET", "/v1/health"),
      api("GET", "/v1/ready")
    ]);
    out({ health, ready });
    break;
  }

  case "agent": {
    if (subcommand !== "register") fail(`Unknown agent subcommand: ${subcommand}. Try: register`);
    if (!values.tenant) fail("--tenant is required");
    if (!values.agent)  fail("--agent is required");
    if (!values.owner)  fail("--owner is required");
    const tools = values.tools ? values.tools.split(",").map((s) => s.trim()) : [];
    out(await api("POST", "/v1/agents", {
      tenant_id: values.tenant,
      agent_id: values.agent,
      owner: values.owner,
      allowed_tools: tools
    }));
    break;
  }

  case "mission": {
    if (subcommand !== "create") fail(`Unknown mission subcommand: ${subcommand}. Try: create`);
    if (!values.tenant)    fail("--tenant is required");
    if (!values.agent)     fail("--agent is required");
    if (!values.by)        fail("--by is required (human delegator email)");
    if (!values.objective) fail("--objective is required");
    if (!values.tools)     fail("--tools is required (comma-separated tool names)");
    const allowed_tools = values.tools.split(",").map((s) => s.trim());
    const result = await api("POST", "/v1/missions", {
      tenant_id: values.tenant,
      agent_id: values.agent,
      delegated_by: values.by,
      objective: values.objective,
      allowed_tools
    });
    out(result);
    break;
  }

  case "authorize": {
    if (!values.tenant)  fail("--tenant is required");
    if (!values.agent)   fail("--agent is required");
    if (!values.mission) fail("--mission is required");
    if (!values.tool)    fail("--tool is required");
    if (!values.action)  fail("--action is required");
    const result = await api("POST", "/v1/action-authorizations", {
      tenant_id: values.tenant,
      agent_id: values.agent,
      mission_id: values.mission,
      tool: values.tool,
      action: values.action
    });
    const decision = result.decision;
    const color = { allow: "\x1b[32m", block: "\x1b[31m", approval: "\x1b[33m" }[decision] || "\x1b[0m";
    process.stdout.write(`\nDecision: ${color}${decision.toUpperCase()}\x1b[0m\n\n`);
    out(result);
    break;
  }

  case "ledger": {
    if (subcommand !== "verify") fail(`Unknown ledger subcommand: ${subcommand}. Try: verify`);
    out(await api("GET", "/v1/ledger/verify"));
    break;
  }

  case "approvals": {
    const state = await api("GET", "/v1/state");
    const pending = (state.approvals || []).filter((a) => a.status === "pending");
    if (!pending.length) {
      process.stdout.write("No pending approvals.\n");
    } else {
      process.stdout.write(`${pending.length} pending approval(s):\n\n`);
      for (const a of pending) {
        process.stdout.write(`  ${a.id}  agent=${a.agent_id}  tool=${a.tool}  action=${a.action}\n`);
      }
      process.stdout.write("\n");
    }
    break;
  }

  case "approval": {
    const id = positionals[0];
    if (!id) fail(`Usage: scopezero approval ${subcommand || "<approve|deny>"} <approval-id>`);
    if (subcommand !== "approve" && subcommand !== "deny") {
      fail(`Unknown approval subcommand: ${subcommand}. Try: approve or deny`);
    }
    out(await api("POST", `/v1/approvals/${encodeURIComponent(id)}/${subcommand}`, {
      actor: values.actor || "cli.operator"
    }));
    break;
  }

  default:
    process.stderr.write(`Unknown command: ${command}\n\n${USAGE}\n`);
    process.exit(1);
}
