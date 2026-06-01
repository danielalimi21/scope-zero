// Google Workspace connector: Drive (search, read) + Gmail (send)
// Requires: SCOPEZERO_GOOGLE_CLIENT_ID, SCOPEZERO_GOOGLE_CLIENT_SECRET, SCOPEZERO_GOOGLE_REFRESH_TOKEN

const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const DRIVE_API = "https://www.googleapis.com/drive/v3/files";
const GMAIL_SEND = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send";

class GoogleTokenManager {
  constructor({ clientId, clientSecret, refreshToken, fetchImpl }) {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.refreshToken = refreshToken;
    this.fetchImpl = fetchImpl;
    this._token = null;
    this._expiresAt = 0;
  }

  async token() {
    if (this._token && Date.now() < this._expiresAt - 30_000) return this._token;
    const res = await this.fetchImpl(GOOGLE_TOKEN_URL, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: this.clientId,
        client_secret: this.clientSecret,
        refresh_token: this.refreshToken,
        grant_type: "refresh_token"
      }).toString()
    });
    const data = await res.json();
    if (!res.ok) throw new Error(`Google OAuth failed: ${data.error_description || data.error || res.status}`);
    this._token = data.access_token;
    this._expiresAt = Date.now() + (data.expires_in || 3600) * 1000;
    return this._token;
  }

  async fetch(url, options = {}) {
    const t = await this.token();
    return this.fetchImpl(url, {
      ...options,
      headers: { ...options.headers, authorization: `Bearer ${t}`, "user-agent": "scopezero-gateway" }
    });
  }
}

const BASE_SCHEMA = {
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

export function createGoogleWorkspaceConnectors({ env, fetchImpl = globalThis.fetch }) {
  const configured = Boolean(
    env.SCOPEZERO_GOOGLE_CLIENT_ID &&
    env.SCOPEZERO_GOOGLE_CLIENT_SECRET &&
    env.SCOPEZERO_GOOGLE_REFRESH_TOKEN
  );
  if (!configured) return [];

  const gauth = new GoogleTokenManager({
    clientId: env.SCOPEZERO_GOOGLE_CLIENT_ID,
    clientSecret: env.SCOPEZERO_GOOGLE_CLIENT_SECRET,
    refreshToken: env.SCOPEZERO_GOOGLE_REFRESH_TOKEN,
    fetchImpl
  });

  return [
    {
      name: "drive.search",
      description: "Search Google Drive files within a mission-authorized scope.",
      vendor: "Google Drive",
      mode: "google-api",
      inputSchema: BASE_SCHEMA,
      async execute(args, context) {
        try {
          const q = String(args.payload?.query || args.payload?.q || "trashed=false").slice(0, 500);
          const params = new URLSearchParams({
            q,
            pageSize: String(Math.min(Number(args.payload?.limit || 10), 50)),
            fields: "files(id,name,mimeType,modifiedTime,size,owners)",
            orderBy: "modifiedTime desc"
          });
          const res = await gauth.fetch(`${DRIVE_API}?${params}`);
          const data = await res.json();
          if (!res.ok) throw new Error(data.error?.message || `Drive API ${res.status}`);
          return {
            content: [{ type: "text", text: `Found ${data.files?.length || 0} Drive files. Evidence hash: ${context.evidence_hash}.` }],
            structuredContent: {
              connector: "drive.search", mode: "google-api", executed: true,
              files: data.files || [], evidence_hash: context.evidence_hash
            },
            isError: false
          };
        } catch (error) {
          return googleErrorResult("drive.search", error, context);
        }
      }
    },
    {
      name: "drive.read",
      description: "Read a Google Drive file after ScopeZero authorization.",
      vendor: "Google Drive",
      mode: "google-api",
      inputSchema: BASE_SCHEMA,
      async execute(args, context) {
        try {
          const fileId = String(args.payload?.file_id || args.payload?.id || "");
          if (!fileId) throw new Error("payload.file_id is required for drive.read");

          const metaRes = await gauth.fetch(`${DRIVE_API}/${encodeURIComponent(fileId)}?fields=id,name,mimeType,size`);
          const meta = await metaRes.json();
          if (!metaRes.ok) throw new Error(meta.error?.message || `Drive API ${metaRes.status}`);

          let content = null;
          const isGoogleDoc = meta.mimeType?.startsWith("application/vnd.google-apps.");
          if (isGoogleDoc) {
            const exportMime = meta.mimeType === "application/vnd.google-apps.spreadsheet" ? "text/csv" : "text/plain";
            const exportRes = await gauth.fetch(`${DRIVE_API}/${encodeURIComponent(fileId)}/export?mimeType=${encodeURIComponent(exportMime)}`);
            if (!exportRes.ok) throw new Error(`Drive export failed: ${exportRes.status}`);
            content = (await exportRes.text()).slice(0, 50_000);
          } else if (Number(meta.size || 0) < 5_000_000) {
            const dlRes = await gauth.fetch(`${DRIVE_API}/${encodeURIComponent(fileId)}?alt=media`);
            if (!dlRes.ok) throw new Error(`Drive download failed: ${dlRes.status}`);
            content = Buffer.from(await dlRes.arrayBuffer()).toString("utf8", 0, 50_000);
          }

          return {
            content: [{ type: "text", text: `Read ${meta.name}. Evidence hash: ${context.evidence_hash}.` }],
            structuredContent: {
              connector: "drive.read", mode: "google-api", executed: true,
              file: meta, content, evidence_hash: context.evidence_hash
            },
            isError: false
          };
        } catch (error) {
          return googleErrorResult("drive.read", error, context);
        }
      }
    },
    {
      name: "gmail.send",
      description: "Send email via Gmail after ScopeZero authorization.",
      vendor: "Gmail",
      mode: "google-api",
      inputSchema: {
        ...BASE_SCHEMA,
        properties: {
          ...BASE_SCHEMA.properties,
          payload: {
            type: "object",
            properties: {
              to: { type: "string" },
              subject: { type: "string" },
              body: { type: "string" },
              cc: { type: "string" }
            }
          }
        }
      },
      async execute(args, context) {
        try {
          const { to, subject, body: bodyText, cc } = args.payload || {};
          if (!to) throw new Error("payload.to is required for gmail.send");
          const lines = [
            `To: ${to}`,
            cc ? `Cc: ${cc}` : null,
            `Subject: ${subject || "(no subject)"}`,
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=UTF-8",
            "",
            bodyText || ""
          ].filter(Boolean);
          const raw = Buffer.from(lines.join("\r\n")).toString("base64url");
          const res = await gauth.fetch(GMAIL_SEND, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ raw })
          });
          const data = await res.json();
          if (!res.ok) throw new Error(data.error?.message || `Gmail API ${res.status}`);
          return {
            content: [{ type: "text", text: `Email sent to ${to}. Message ID: ${data.id}. Evidence hash: ${context.evidence_hash}.` }],
            structuredContent: {
              connector: "gmail.send", mode: "google-api", executed: true,
              message_id: data.id, to, subject, evidence_hash: context.evidence_hash
            },
            isError: false
          };
        } catch (error) {
          return googleErrorResult("gmail.send", error, context);
        }
      }
    }
  ];
}

function googleErrorResult(name, error, context) {
  return {
    content: [{ type: "text", text: `${name} failed: ${error.message}` }],
    structuredContent: {
      connector: name, mode: "google-api", executed: false,
      error: error.message, evidence_hash: context.evidence_hash
    },
    isError: true
  };
}
