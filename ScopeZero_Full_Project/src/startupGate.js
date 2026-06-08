// Fail-closed boot gate. In production the gateway refuses to start when a
// security-critical setting is missing, instead of silently falling back to a
// dev default (shared-secret-derived signing key, no egress lockdown, dev tokens
// on). Returns { fatal[], warnings[] } so the caller can log and exit. Pure +
// env-injectable so it is unit-testable.

const DEV_SIGNING_SECRET = "dev-scopezero-signing-secret-change-me";

export function assessStartupReadiness(env = process.env) {
  const fatal = [];
  const warnings = [];
  const production = env.NODE_ENV === "production";

  if (production) {
    // Crypto: the private key must be explicit, never derived from a shared
    // secret. Without it the "verifiers hold only the public key and cannot
    // forge" property does not hold.
    if (!env.SCOPEZERO_SIGNING_PRIVATE_KEY) {
      fatal.push("SCOPEZERO_SIGNING_PRIVATE_KEY is required in production — the signing key must not be derived from a shared secret. Generate one with `node tools/gen-keys.js`.");
    }
    if (!env.SCOPEZERO_SIGNING_SECRET || env.SCOPEZERO_SIGNING_SECRET === DEV_SIGNING_SECRET) {
      fatal.push("SCOPEZERO_SIGNING_SECRET must be set to a non-default value in production (it keys the tamper-evident ledger chain unless SCOPEZERO_LEDGER_SECRET is set).");
    }

    // Enforcement: a kernel-level egress lockdown must be declared, or the
    // bare-SDK tier is honor-system (an agent can ignore HTTP_PROXY).
    const lockdown = String(env.SCOPEZERO_EGRESS_LOCKDOWN || "none").toLowerCase();
    if (!["k8s", "docker"].includes(lockdown)) {
      fatal.push("SCOPEZERO_EGRESS_LOCKDOWN must be 'k8s' or 'docker' in production — apply the kernel egress lockdown (see /v1/deployment/lockdown) and declare it, or agents can bypass the gateway with a raw socket. Verify with `node tools/lockdown-selftest.js`.");
    }

    // Auth: an open gateway in production is a fatal misconfiguration.
    if (env.SCOPEZERO_REQUIRE_AUTH !== "true") {
      fatal.push("SCOPEZERO_REQUIRE_AUTH must be 'true' in production.");
    }
    if (env.SCOPEZERO_ALLOW_DEV_TOKEN !== "false") {
      fatal.push("SCOPEZERO_ALLOW_DEV_TOKEN must be 'false' in production.");
    }

    if (!env.SCOPEZERO_OIDC_JWKS_URL) {
      warnings.push("SCOPEZERO_OIDC_JWKS_URL is not set — enterprise SSO/JWKS validation is disabled.");
    }
    if (env.SCOPEZERO_STORE === "postgres" && !env.DATABASE_URL) {
      fatal.push("DATABASE_URL is required when SCOPEZERO_STORE=postgres.");
    }
  } else {
    if (!env.SCOPEZERO_SIGNING_PRIVATE_KEY) {
      warnings.push("dev mode: signing keypair is derived from the shared secret. Set SCOPEZERO_SIGNING_PRIVATE_KEY (node tools/gen-keys.js) to mirror production.");
    }
  }

  return { fatal, warnings, ok: fatal.length === 0 };
}
