import { createId, hmacSha256, nowIso, stableStringify } from "./crypto.js";
import { httpError } from "./runtime.js";

const CONNECTOR_OAUTH = {
  slack: {
    authorize_url: "https://slack.com/oauth/v2/authorize",
    scopes: ["chat:write", "channels:read"]
  },
  github: {
    authorize_url: "https://github.com/login/oauth/authorize",
    scopes: ["repo", "read:org"]
  },
  google: {
    authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
    scopes: ["https://www.googleapis.com/auth/drive.readonly", "https://www.googleapis.com/auth/gmail.compose"]
  },
  microsoft: {
    authorize_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    scopes: ["Files.Read.All", "Mail.Send", "offline_access"]
  }
};

export class OAuthBroker {
  constructor({ secret, redirectBaseUrl }) {
    this.secret = secret;
    this.redirectBaseUrl = redirectBaseUrl;
  }

  start({ provider, tenant_id, subject }) {
    const config = CONNECTOR_OAUTH[provider];
    if (!config) {
      throw httpError(404, "unknown_provider", "OAuth provider is not registered.");
    }
    const clientId = process.env[`SCOPEZERO_${provider.toUpperCase()}_CLIENT_ID`];
    if (!clientId) {
      throw httpError(400, "oauth_not_configured", `Missing SCOPEZERO_${provider.toUpperCase()}_CLIENT_ID.`);
    }
    const statePayload = {
      state_id: createId("oauth", provider),
      tenant_id,
      subject,
      provider,
      issued_at: nowIso()
    };
    const state = encodeState(statePayload, this.secret);
    const url = new URL(config.authorize_url);
    url.searchParams.set("client_id", clientId);
    url.searchParams.set("redirect_uri", `${this.redirectBaseUrl}/v1/connectors/oauth/callback`);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", config.scopes.join(" "));
    url.searchParams.set("state", state);
    return {
      provider,
      authorize_url: url.toString(),
      state_id: statePayload.state_id,
      scopes: config.scopes
    };
  }

  callback({ code, state }) {
    if (!code || !state) {
      throw httpError(400, "missing_oauth_fields", "OAuth callback requires code and state.");
    }
    const payload = decodeState(state, this.secret);
    return {
      status: "received_authorization_code",
      provider: payload.provider,
      tenant_id: payload.tenant_id,
      subject: payload.subject,
      state_id: payload.state_id,
      next_step: "Exchange code for tokens in a vault-backed connector worker."
    };
  }
}

function encodeState(payload, secret) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = hmacSha256(secret, stableStringify(payload)).slice(0, 32);
  return `${encoded}.${signature}`;
}

function decodeState(state, secret) {
  const [encoded, signature] = state.split(".");
  if (!encoded || !signature) {
    throw httpError(400, "invalid_oauth_state", "OAuth state format is invalid.");
  }
  const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  const expected = hmacSha256(secret, stableStringify(payload)).slice(0, 32);
  if (signature !== expected) {
    throw httpError(400, "invalid_oauth_state", "OAuth state signature is invalid.");
  }
  return payload;
}
