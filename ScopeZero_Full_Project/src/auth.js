import { hmacSha256, nowIso, stableStringify } from "./crypto.js";
import { httpError } from "./runtime.js";

const ROLE_PERMISSIONS = {
  platform_admin: ["*"],
  tenant_admin: ["tenant:read", "agent:write", "mission:write", "tool:evaluate", "policy:write", "ledger:read", "approval:write", "siem:read", "mcp:proxy"],
  security_operator: ["tenant:read", "agent:write", "mission:write", "tool:evaluate", "ledger:read", "approval:write", "siem:read", "mcp:proxy"],
  agent_runtime: ["mission:write", "tool:evaluate", "mcp:proxy"],
  auditor: ["tenant:read", "ledger:read", "siem:read"]
};

export class AuthService {
  constructor({ secret, apiKey = "", requireAuth = false, oidcIssuer = "", oidcAudience = "", jwksUrl = "" }) {
    this.secret = secret;
    this.apiKey = apiKey;
    this.requireAuth = requireAuth;
    this.oidcIssuer = oidcIssuer;
    this.oidcAudience = oidcAudience;
    this.jwksUrl = jwksUrl;
    this.jwksCache = null;
    this.jwksCacheUntil = 0;
  }

  issueToken({ subject, tenant_id, roles = ["security_operator"], ttl_seconds = 3600 }) {
    const header = { alg: "HS256", typ: "SZJWT" };
    const payload = {
      iss: "scopezero.local",
      sub: subject,
      tenant_id,
      tenants: tenant_id === "*" ? ["*"] : [tenant_id],
      roles,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + Number(ttl_seconds),
      issued_at: nowIso()
    };
    const unsigned = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
    const signature = base64urlHex(hmacSha256(this.secret, unsigned));
    return `${unsigned}.${signature}`;
  }

  async authenticate(req) {
    const authorization = req.headers.authorization || "";
    if (this.apiKey && authorization === `Bearer ${this.apiKey}`) {
      return {
        subject: "api-key",
        tenant_id: "*",
        tenants: ["*"],
        roles: ["platform_admin"],
        auth_type: "api_key"
      };
    }

    if (authorization.startsWith("Bearer ")) {
      return this.verifyToken(authorization.slice("Bearer ".length));
    }

    if (this.requireAuth) {
      throw httpError(401, "unauthenticated", "Missing bearer token.");
    }

    return {
      subject: "dev.local",
      tenant_id: "tenant_contoso",
      tenants: ["tenant_contoso"],
      roles: ["platform_admin"],
      auth_type: "dev"
    };
  }

  async verifyToken(token) {
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw httpError(401, "invalid_token", "Invalid token format.");
    }
    const [encodedHeader, encodedPayload, signature] = parts;
    const header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString("utf8"));
    if (header.alg === "RS256" && this.jwksUrl) {
      return this.verifyOidcToken({ token, encodedHeader, encodedPayload, signature, header });
    }
    const expected = base64urlHex(hmacSha256(this.secret, `${encodedHeader}.${encodedPayload}`));
    if (signature !== expected) {
      throw httpError(401, "invalid_token", "Token signature failed verification.");
    }
    const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8"));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      throw httpError(401, "expired_token", "Token is expired.");
    }
    return {
      subject: payload.sub,
      tenant_id: payload.tenant_id,
      tenants: payload.tenants || [payload.tenant_id],
      roles: payload.roles || [],
      auth_type: "bearer",
      claims: payload
    };
  }

  async verifyOidcToken({ encodedHeader, encodedPayload, signature, header }) {
    const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8"));
    if (this.oidcIssuer && payload.iss !== this.oidcIssuer) {
      throw httpError(401, "invalid_issuer", "OIDC issuer does not match configuration.");
    }
    if (this.oidcAudience) {
      const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!aud.includes(this.oidcAudience)) {
        throw httpError(401, "invalid_audience", "OIDC audience does not match configuration.");
      }
    }
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      throw httpError(401, "expired_token", "Token is expired.");
    }

    const jwks = await this.getJwks();
    const jwk = jwks.keys?.find((key) => key.kid === header.kid && key.kty === "RSA");
    if (!jwk) {
      throw httpError(401, "unknown_key", "OIDC key id was not found in JWKS.");
    }

    const key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const ok = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      Buffer.from(signature, "base64url"),
      Buffer.from(`${encodedHeader}.${encodedPayload}`)
    );
    if (!ok) {
      throw httpError(401, "invalid_token", "OIDC token signature failed verification.");
    }

    const roles = payload.roles || payload.role || payload.groups || ["security_operator"];
    const tenantId = payload.tenant_id || payload.tid || payload.org_id || "tenant_contoso";
    return {
      subject: payload.sub || payload.email || "oidc-subject",
      tenant_id: tenantId,
      tenants: payload.tenants || [tenantId],
      roles: Array.isArray(roles) ? roles : [roles],
      auth_type: "oidc",
      claims: payload
    };
  }

  async getJwks() {
    if (this.jwksCache && Date.now() < this.jwksCacheUntil) {
      return this.jwksCache;
    }
    const response = await fetch(this.jwksUrl);
    if (!response.ok) {
      throw httpError(503, "jwks_unavailable", "Could not fetch OIDC JWKS.");
    }
    this.jwksCache = await response.json();
    this.jwksCacheUntil = Date.now() + 10 * 60 * 1000;
    return this.jwksCache;
  }

  authorize(principal, action, tenantId) {
    if (!principal) {
      throw httpError(401, "unauthenticated", "Authentication required.");
    }
    const permissions = new Set(principal.roles.flatMap((role) => ROLE_PERMISSIONS[role] || []));
    if (!permissions.has("*") && !permissions.has(action)) {
      throw httpError(403, "forbidden", `Role cannot perform ${action}.`);
    }
    if (tenantId && !principal.tenants.includes("*") && !principal.tenants.includes(tenantId)) {
      throw httpError(403, "tenant_forbidden", "Principal cannot access this tenant.");
    }
    return true;
  }

  publicJwks() {
    return {
      keys: [
        {
          kty: "oct",
          kid: "scopezero-local-hs256",
          alg: "HS256",
          use: "sig",
          note: "Local development HMAC key. Configure enterprise OIDC/JWKS before production."
        }
      ]
    };
  }
}

export function base64url(value) {
  return Buffer.from(String(value)).toString("base64url");
}

function base64urlHex(hex) {
  return Buffer.from(hex, "hex").toString("base64url");
}

export function auditPrincipal(principal) {
  return {
    subject: principal.subject,
    tenant_id: principal.tenant_id,
    roles: principal.roles,
    auth_type: principal.auth_type
  };
}

export function redactForLog(value) {
  if (!value || typeof value !== "object") {
    return value;
  }
  const copy = JSON.parse(stableStringify(value));
  for (const key of Object.keys(copy)) {
    if (/token|secret|key|password/i.test(key)) {
      copy[key] = "[redacted]";
    }
  }
  return copy;
}
