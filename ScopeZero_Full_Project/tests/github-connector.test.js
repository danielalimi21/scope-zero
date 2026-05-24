import test from "node:test";
import assert from "node:assert/strict";
import { ConnectorRegistry } from "../src/connectors.js";

test("github connector stays in local mode when credentials are absent", async () => {
  const registry = new ConnectorRegistry({ env: {}, fetchImpl: unreachableFetch });
  const github = registry.list().find((connector) => connector.name === "github.pr");

  assert.equal(github.mode, "local-adapter");

  const result = await registry.execute("github.pr", {
    tenant_id: "tenant_contoso",
    agent_id: "agent.test",
    mission_id: "mission_test",
    action: "Create demo PR"
  }, {
    evidence_hash: "hash_test"
  });

  assert.equal(result.isError, false);
  assert.equal(result.structuredContent.configured, false);
});

test("github connector creates branch, file commit, and draft pull request", async () => {
  const calls = [];
  const registry = new ConnectorRegistry({
    env: {
      SCOPEZERO_GITHUB_TOKEN: "test-github-token",
      SCOPEZERO_GITHUB_OWNER: "octo",
      SCOPEZERO_GITHUB_REPO: "scopezero-demo-repo"
    },
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      if (options.method === "GET" && url.endsWith("/repos/octo/scopezero-demo-repo")) {
        return jsonResponse({ default_branch: "main" });
      }
      if (options.method === "GET" && url.endsWith("/git/ref/heads/main")) {
        return jsonResponse({ object: { sha: "base-sha" } });
      }
      if (options.method === "POST" && url.endsWith("/git/refs")) {
        return jsonResponse({ ref: "refs/heads/scopezero/test" }, 201);
      }
      if (options.method === "GET" && url.includes("/contents/scopezero-demo.md?ref=scopezero%2Ftest")) {
        return jsonResponse({ message: "Not Found" }, 404);
      }
      if (options.method === "PUT" && url.endsWith("/contents/scopezero-demo.md")) {
        return jsonResponse({ content: { path: "scopezero-demo.md" } }, 201);
      }
      if (options.method === "POST" && url.endsWith("/pulls")) {
        return jsonResponse({ number: 7, html_url: "https://github.com/octo/scopezero-demo-repo/pull/7" }, 201);
      }
      return jsonResponse({ message: `Unexpected call: ${options.method} ${url}` }, 500);
    }
  });

  const github = registry.list().find((connector) => connector.name === "github.pr");
  assert.equal(github.mode, "github-api");

  const result = await registry.execute("github.pr", {
    tenant_id: "tenant_contoso",
    agent_id: "agent.test",
    mission_id: "mission_test",
    action: "Create demo PR",
    payload: {
      title: "Demo PR",
      branch: "scopezero/test",
      files: [{ path: "scopezero-demo.md", content: "hello" }]
    }
  }, {
    evidence_hash: "hash_test",
    verdict: { authorization_id: "authz_test" }
  });

  assert.equal(result.isError, false);
  assert.equal(result.structuredContent.pull_request_number, 7);
  assert.equal(result.structuredContent.pull_request_url, "https://github.com/octo/scopezero-demo-repo/pull/7");
  assert.equal(JSON.parse(calls.find((call) => call.options.method === "POST" && call.url.endsWith("/pulls")).options.body).draft, true);
});

test("slack connector stays in local mode when credentials are absent", async () => {
  const registry = new ConnectorRegistry({ env: {}, fetchImpl: unreachableFetch });
  const slack = registry.list().find((connector) => connector.name === "slack.draft");

  assert.equal(slack.mode, "local-adapter");

  const result = await registry.execute("slack.draft", {
    tenant_id: "tenant_contoso",
    agent_id: "agent.test",
    mission_id: "mission_test",
    action: "Post safe Slack summary"
  }, {
    evidence_hash: "hash_test"
  });

  assert.equal(result.isError, false);
  assert.equal(result.structuredContent.configured, false);
});

test("slack connector posts only to the configured channel", async () => {
  const calls = [];
  const registry = new ConnectorRegistry({
    env: {
      SCOPEZERO_SLACK_BOT_TOKEN: "test-slack-token",
      SCOPEZERO_SLACK_CHANNEL_ID: "C123",
      SCOPEZERO_SLACK_ALLOWED_CHANNEL: "scopezero-demo"
    },
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      if (url === "https://slack.com/api/chat.postMessage") {
        return jsonResponse({ ok: true, channel: "C123", ts: "1779193000.000100" });
      }
      return jsonResponse({ ok: false, error: "unexpected_call" }, 500);
    }
  });

  const slack = registry.list().find((connector) => connector.name === "slack.draft");
  assert.equal(slack.mode, "slack-api");

  const result = await registry.execute("slack.draft", {
    tenant_id: "tenant_contoso",
    agent_id: "agent.test",
    mission_id: "mission_test",
    action: "Post safe Slack summary",
    payload: {
      title: "Safe summary",
      text: "Approved internal summary."
    },
    destination: {
      type: "slack",
      address: "scopezero-demo"
    }
  }, {
    evidence_hash: "hash_test",
    verdict: { decision: "allow" }
  });

  assert.equal(result.isError, false);
  assert.equal(result.structuredContent.slack_message_ts, "1779193000.000100");
  assert.equal(JSON.parse(calls[0].options.body).channel, "C123");

  const denied = await registry.execute("slack.draft", {
    tenant_id: "tenant_contoso",
    agent_id: "agent.test",
    mission_id: "mission_test",
    action: "Post elsewhere",
    destination: {
      type: "slack",
      address: "other-channel"
    }
  }, {
    evidence_hash: "hash_test",
    verdict: { decision: "allow" }
  });

  assert.equal(denied.isError, true);
  assert.equal(denied.structuredContent.executed, false);
});

test("aws iam connector simulates policy attachment without mutating aws", async () => {
  const registry = new ConnectorRegistry({ env: {}, fetchImpl: unreachableFetch });
  const aws = registry.list().find((connector) => connector.name === "aws.iam.attachPolicy");

  assert.equal(aws.mode, "simulate");

  const result = await registry.execute("aws.iam.attachPolicy", {
    tenant_id: "tenant_contoso",
    agent_id: "agent.test",
    mission_id: "mission_test",
    action: "Attach AdministratorAccess",
    payload: {
      role_name: "agent-role",
      policy_name: "AdministratorAccess"
    }
  }, {
    evidence_hash: "hash_test"
  });

  assert.equal(result.isError, false);
  assert.equal(result.structuredContent.executed, true);
  assert.equal(result.structuredContent.mutated_aws, false);
  assert.equal(result.structuredContent.admin_like_policy, true);
});

function jsonResponse(payload, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async text() {
      return JSON.stringify(payload);
    }
  };
}

async function unreachableFetch() {
  throw new Error("fetch should not be called");
}
