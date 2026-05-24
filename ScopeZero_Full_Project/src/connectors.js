export class ConnectorRegistry {
  constructor({ env = process.env, fetchImpl = globalThis.fetch } = {}) {
    this.connectors = new Map();
    this.env = env;
    this.fetchImpl = fetchImpl;
    this.registerDefaults();
  }

  register(connector) {
    this.connectors.set(connector.name, connector);
  }

  list() {
    return [...this.connectors.values()].map(({ name, description, inputSchema, vendor, mode }) => ({
      name,
      description,
      inputSchema,
      vendor,
      mode
    }));
  }

  get(name) {
    return this.connectors.get(name);
  }

  async execute(name, args, context) {
    const connector = this.get(name);
    if (!connector) {
      return {
        isError: true,
        content: [{ type: "text", text: `Connector ${name} is not registered.` }]
      };
    }
    return connector.execute(args, context);
  }

  registerDefaults() {
    const toolSchema = {
      type: "object",
      properties: {
        tenant_id: { type: "string" },
        agent_id: { type: "string" },
        mission_id: { type: "string" },
        action: { type: "string" },
        payload: { type: "object" },
        destination: { type: "object" },
        context: { type: "object" }
      },
      required: ["tenant_id", "agent_id", "mission_id", "action"]
    };

    for (const connector of [
      ["drive.search", "Search enterprise drive documents.", "Google Drive / Microsoft 365", "local-adapter"],
      ["drive.read", "Read a mission-scoped enterprise document.", "Google Drive / Microsoft 365", "local-adapter"],
      ["sheets.export", "Export structured spreadsheet rows.", "Google Sheets / Excel", "guarded-adapter"],
      ["gmail.send", "Send email through a governed mail connector.", "Gmail / Exchange", "guarded-adapter"],
      ["servicenow.case", "Open a ServiceNow security or finance case.", "ServiceNow", "local-adapter"]
    ]) {
      const [name, description, vendor, mode] = connector;
      this.register({
        name,
        description,
        vendor,
        mode,
        inputSchema: toolSchema,
        async execute(args, context) {
          return {
            content: [
              {
                type: "text",
                text: `${name} executed in ${mode} mode for ${args.agent_id}. Evidence hash: ${context.evidence_hash}.`
              }
            ],
            structuredContent: {
              connector: name,
              mode,
              executed: true,
              tenant_id: args.tenant_id,
              agent_id: args.agent_id,
              evidence_hash: context.evidence_hash
            },
            isError: false
          };
        }
      });
    }

    this.register(createSlackDraftConnector({ env: this.env, fetchImpl: this.fetchImpl }));
    this.register(createGitHubPrConnector({ env: this.env, fetchImpl: this.fetchImpl }));
    this.register(createAwsIamAttachPolicyConnector({ env: this.env }));
  }
}

function createAwsIamAttachPolicyConnector({ env }) {
  const mode = env.SCOPEZERO_AWS_MODE || "simulate";
  return {
    name: "aws.iam.attachPolicy",
    description: "Simulate an AWS IAM policy attachment request after ScopeZero authorization.",
    vendor: "AWS IAM",
    mode: mode === "live" ? "disabled-live-readonly-required" : "simulate",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: { type: "string" },
        agent_id: { type: "string" },
        mission_id: { type: "string" },
        action: { type: "string" },
        payload: {
          type: "object",
          properties: {
            role_name: { type: "string" },
            policy_arn: { type: "string" },
            policy_name: { type: "string" },
            account_id: { type: "string" }
          }
        },
        destination: { type: "object" },
        context: { type: "object" }
      },
      required: ["tenant_id", "agent_id", "mission_id", "action"]
    },
    async execute(args, context) {
      const payload = args.payload || {};
      const policyName = String(payload.policy_name || payload.policy || payload.policy_arn || "AdministratorAccess");
      const roleName = String(payload.role_name || "agent-execution-role");
      const adminLike = /administratoraccess|\badmin\b|\*:\*|\"action\"\s*:\s*\"\*\"/i.test(policyName);
      return {
        content: [
          {
            type: "text",
            text: `AWS IAM attachPolicy simulated for ${roleName}. No AWS mutation was performed. Evidence hash: ${context.evidence_hash}.`
          }
        ],
        structuredContent: {
          connector: "aws.iam.attachPolicy",
          mode: "simulate",
          executed: true,
          mutated_aws: false,
          tenant_id: args.tenant_id,
          agent_id: args.agent_id,
          role_name: roleName,
          requested_policy: policyName,
          admin_like_policy: adminLike,
          evidence_hash: context.evidence_hash
        },
        isError: false
      };
    }
  };
}

function createSlackDraftConnector({ env, fetchImpl }) {
  const configured = Boolean(env.SCOPEZERO_SLACK_BOT_TOKEN && env.SCOPEZERO_SLACK_CHANNEL_ID);
  const allowedChannel = normalizeSlackChannel(env.SCOPEZERO_SLACK_ALLOWED_CHANNEL || "scopezero-demo");
  return {
    name: "slack.draft",
    description: "Post a governed Slack message to the configured demo channel.",
    vendor: "Slack",
    mode: configured ? "slack-api" : "local-adapter",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: { type: "string" },
        agent_id: { type: "string" },
        mission_id: { type: "string" },
        action: { type: "string" },
        payload: {
          type: "object",
          properties: {
            text: { type: "string" },
            title: { type: "string" },
            summary: { type: "string" }
          }
        },
        destination: { type: "object" },
        context: { type: "object" }
      },
      required: ["tenant_id", "agent_id", "mission_id", "action"]
    },
    async execute(args, context) {
      if (!configured) {
        return localConnectorResult("slack.draft", "local-adapter", args, context, {
          configured: false,
          next_step: "Set SCOPEZERO_SLACK_BOT_TOKEN and SCOPEZERO_SLACK_CHANNEL_ID to enable the live Slack API connector."
        });
      }

      try {
        const requestedChannel = normalizeSlackChannel(args.destination?.address || args.destination?.channel || args.destination?.name || allowedChannel);
        if (requestedChannel && requestedChannel !== allowedChannel && requestedChannel !== normalizeSlackChannel(env.SCOPEZERO_SLACK_CHANNEL_ID)) {
          throw new Error(`Slack destination ${requestedChannel} is outside the configured ScopeZero demo channel.`);
        }

        const client = new SlackApiClient({
          token: env.SCOPEZERO_SLACK_BOT_TOKEN,
          channelId: env.SCOPEZERO_SLACK_CHANNEL_ID,
          fetchImpl
        });
        const message = normalizeSlackMessage(args, context);
        const posted = await client.postMessage(message);
        return {
          content: [
            {
              type: "text",
              text: `Slack message posted to ${allowedChannel}. Evidence hash: ${context.evidence_hash}.`
            }
          ],
          structuredContent: {
            connector: "slack.draft",
            mode: "slack-api",
            executed: true,
            tenant_id: args.tenant_id,
            agent_id: args.agent_id,
            channel: allowedChannel,
            slack_channel_id: env.SCOPEZERO_SLACK_CHANNEL_ID,
            slack_message_ts: posted.ts,
            evidence_hash: context.evidence_hash
          },
          isError: false
        };
      } catch (error) {
        return {
          content: [{ type: "text", text: `Slack connector failed: ${error.message}` }],
          structuredContent: {
            connector: "slack.draft",
            mode: "slack-api",
            executed: false,
            error: error.message,
            evidence_hash: context.evidence_hash
          },
          isError: true
        };
      }
    }
  };
}

function normalizeSlackMessage(args, context) {
  const payload = args.payload || {};
  const title = String(payload.title || "ScopeZero governed Slack summary").slice(0, 120);
  const text = String(payload.text || payload.summary || payload.body || args.action || "ScopeZero authorized this Slack message.").slice(0, 3000);
  return [
    `*${title}*`,
    "",
    text,
    "",
    `ScopeZero decision: ${context.verdict?.decision || "allow"}`,
    `Evidence hash: ${context.evidence_hash}`
  ].join("\n");
}

function normalizeSlackChannel(channel) {
  return String(channel || "").trim().replace(/^#/, "").toLowerCase();
}

function createGitHubPrConnector({ env, fetchImpl }) {
  const configured = Boolean(env.SCOPEZERO_GITHUB_TOKEN && env.SCOPEZERO_GITHUB_OWNER && env.SCOPEZERO_GITHUB_REPO);
  return {
    name: "github.pr",
    description: "Create a governed GitHub draft pull request.",
    vendor: "GitHub",
    mode: configured ? "github-api" : "local-adapter",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: { type: "string" },
        agent_id: { type: "string" },
        mission_id: { type: "string" },
        action: { type: "string" },
        payload: {
          type: "object",
          properties: {
            title: { type: "string" },
            body: { type: "string" },
            branch: { type: "string" },
            base: { type: "string" },
            files: { type: "array" }
          }
        },
        destination: { type: "object" },
        context: { type: "object" }
      },
      required: ["tenant_id", "agent_id", "mission_id", "action"]
    },
    async execute(args, context) {
      if (!configured) {
        return localConnectorResult("github.pr", "local-adapter", args, context, {
          configured: false,
          next_step: "Set SCOPEZERO_GITHUB_TOKEN, SCOPEZERO_GITHUB_OWNER, and SCOPEZERO_GITHUB_REPO to enable the live GitHub API connector."
        });
      }

      try {
        const client = new GitHubApiClient({
          token: env.SCOPEZERO_GITHUB_TOKEN,
          owner: env.SCOPEZERO_GITHUB_OWNER,
          repo: env.SCOPEZERO_GITHUB_REPO,
          fetchImpl
        });
        const payload = normalizeGitHubPayload(args.payload || {}, context);
        const pullRequest = await client.createDraftPullRequest(payload);
        return {
          content: [
            {
              type: "text",
              text: `GitHub draft PR created: ${pullRequest.html_url}. Evidence hash: ${context.evidence_hash}.`
            }
          ],
          structuredContent: {
            connector: "github.pr",
            mode: "github-api",
            executed: true,
            tenant_id: args.tenant_id,
            agent_id: args.agent_id,
            repository: `${env.SCOPEZERO_GITHUB_OWNER}/${env.SCOPEZERO_GITHUB_REPO}`,
            branch: payload.branch,
            base: payload.base,
            pull_request_number: pullRequest.number,
            pull_request_url: pullRequest.html_url,
            evidence_hash: context.evidence_hash
          },
          isError: false
        };
      } catch (error) {
        return {
          content: [{ type: "text", text: `GitHub connector failed: ${error.message}` }],
          structuredContent: {
            connector: "github.pr",
            mode: "github-api",
            executed: false,
            error: error.message,
            evidence_hash: context.evidence_hash
          },
          isError: true
        };
      }
    }
  };
}

function normalizeGitHubPayload(payload, context) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const title = String(payload.title || "ScopeZero governed demo change").slice(0, 240);
  const branch = sanitizeBranchName(payload.branch || `scopezero/governed-demo-${timestamp}`);
  const files = Array.isArray(payload.files) && payload.files.length
    ? payload.files.map(normalizeFileChange)
    : [
        {
          path: "scopezero-evidence.md",
          content: [
            "# ScopeZero Governed Change",
            "",
            "This file was committed by the ScopeZero GitHub connector after pre-execution authorization.",
            "",
            `Evidence hash: ${context.evidence_hash}`,
            `Created at: ${new Date().toISOString()}`
          ].join("\n")
        }
      ];

  return {
    title,
    body: String(payload.body || `Created by ScopeZero after authorization ${context.verdict?.authorization_id || "unknown"}.`),
    branch,
    base: payload.base ? sanitizeBranchName(payload.base) : null,
    files
  };
}

function normalizeFileChange(file) {
  if (!file || typeof file !== "object") {
    throw new Error("Each GitHub file change must be an object.");
  }
  const path = String(file.path || "").trim().replace(/^\/+/, "");
  if (!path || path.includes("..")) {
    throw new Error("GitHub file path must be relative and cannot contain '..'.");
  }
  return {
    path,
    content: String(file.content || "")
  };
}

function sanitizeBranchName(value) {
  const branch = String(value || "")
    .trim()
    .replace(/[^a-zA-Z0-9._/-]+/g, "-")
    .replace(/\/+/g, "/")
    .replace(/^\/+|\/+$/g, "")
    .slice(0, 120);
  if (!branch || branch.includes("..")) {
    throw new Error("Invalid GitHub branch name.");
  }
  return branch;
}

function localConnectorResult(name, mode, args, context, extra = {}) {
  return {
    content: [
      {
        type: "text",
        text: `${name} executed in ${mode} mode for ${args.agent_id}. Evidence hash: ${context.evidence_hash}.`
      }
    ],
    structuredContent: {
      connector: name,
      mode,
      executed: true,
      tenant_id: args.tenant_id,
      agent_id: args.agent_id,
      evidence_hash: context.evidence_hash,
      ...extra
    },
    isError: false
  };
}

class GitHubApiClient {
  constructor({ token, owner, repo, fetchImpl }) {
    this.token = token;
    this.owner = owner;
    this.repo = repo;
    this.fetchImpl = fetchImpl;
    this.baseUrl = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
  }

  async createDraftPullRequest({ title, body, branch, base, files }) {
    const repoInfo = await this.request("GET", "");
    const baseBranch = base || repoInfo.default_branch || "main";
    const baseRef = await this.request("GET", `/git/ref/heads/${encodeURIComponent(baseBranch)}`);
    await this.request("POST", "/git/refs", {
      ref: `refs/heads/${branch}`,
      sha: baseRef.object.sha
    });

    for (const file of files) {
      await this.putFile({ branch, file });
    }

    return this.request("POST", "/pulls", {
      title,
      body,
      head: branch,
      base: baseBranch,
      draft: true
    });
  }

  async putFile({ branch, file }) {
    const existing = await this.request("GET", `/contents/${encodePath(file.path)}?ref=${encodeURIComponent(branch)}`, null, {
      allowNotFound: true
    });
    const body = {
      message: `ScopeZero governed update: ${file.path}`,
      content: Buffer.from(file.content, "utf8").toString("base64"),
      branch
    };
    if (existing?.sha) {
      body.sha = existing.sha;
    }
    return this.request("PUT", `/contents/${encodePath(file.path)}`, body);
  }

  async request(method, pathSuffix, body = null, options = {}) {
    const url = pathSuffix ? `${this.baseUrl}${pathSuffix}` : this.baseUrl;
    const response = await this.fetchImpl(url, {
      method,
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${this.token}`,
        "content-type": "application/json",
        "x-github-api-version": "2022-11-28",
        "user-agent": "scopezero-gateway"
      },
      body: body ? JSON.stringify(body) : undefined
    });
    const text = await response.text();
    const payload = text ? JSON.parse(text) : null;
    if (response.status === 404 && options.allowNotFound) {
      return null;
    }
    if (!response.ok) {
      const message = payload?.message || `GitHub API returned ${response.status}`;
      throw new Error(message);
    }
    return payload;
  }
}

function encodePath(filePath) {
  return String(filePath).split("/").map(encodeURIComponent).join("/");
}

class SlackApiClient {
  constructor({ token, channelId, fetchImpl }) {
    this.token = token;
    this.channelId = channelId;
    this.fetchImpl = fetchImpl;
  }

  async postMessage(text) {
    const response = await this.fetchImpl("https://slack.com/api/chat.postMessage", {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.token}`,
        "content-type": "application/json; charset=utf-8",
        "user-agent": "scopezero-gateway"
      },
      body: JSON.stringify({
        channel: this.channelId,
        text,
        unfurl_links: false,
        unfurl_media: false
      })
    });
    const raw = await response.text();
    const payload = raw ? JSON.parse(raw) : {};
    if (!response.ok || payload.ok === false) {
      throw new Error(payload.error || `Slack API returned ${response.status}`);
    }
    return payload;
  }
}
