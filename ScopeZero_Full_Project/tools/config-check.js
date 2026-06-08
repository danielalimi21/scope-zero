const requiredInProduction = [
  "SCOPEZERO_SIGNING_SECRET",
  "SCOPEZERO_AUTH_SECRET",
  "SCOPEZERO_CORS_ORIGIN",
  "SCOPEZERO_SECRETS_MASTER_KEY"
];

const warnings = [];
if (process.env.NODE_ENV === "production") {
  for (const key of requiredInProduction) {
    if (!process.env[key]) {
      warnings.push(`${key} is required in production.`);
    }
  }
  if (process.env.SCOPEZERO_ALLOW_DEV_TOKEN !== "false") {
    warnings.push("SCOPEZERO_ALLOW_DEV_TOKEN should be false in production.");
  }
  if (process.env.SCOPEZERO_REQUIRE_AUTH !== "true") {
    warnings.push("SCOPEZERO_REQUIRE_AUTH should be true in production.");
  }
  if (!process.env.SCOPEZERO_OIDC_JWKS_URL) {
    warnings.push("SCOPEZERO_OIDC_JWKS_URL should be configured for enterprise SSO.");
  }
  if (process.env.SCOPEZERO_STORE === "postgres" && !process.env.DATABASE_URL) {
    warnings.push("DATABASE_URL is required when SCOPEZERO_STORE=postgres.");
  }
  if (!process.env.OTEL_EXPORTER_OTLP_ENDPOINT) {
    warnings.push("OTEL_EXPORTER_OTLP_ENDPOINT should be configured for production traces.");
  }
  // Without a kernel-level egress lockdown, an agent that ignores the SDK and the
  // HTTP_PROXY env can open a raw socket straight past the gateway — the bare-SDK
  // tier is then honor-system. The app can't enforce topology, so make the operator
  // declare it and flag loudly when it's undeclared.
  const lockdown = String(process.env.SCOPEZERO_EGRESS_LOCKDOWN || "none").toLowerCase();
  if (!["k8s", "docker"].includes(lockdown)) {
    warnings.push("SCOPEZERO_EGRESS_LOCKDOWN is not 'k8s' or 'docker' — agents are contained only if they honor HTTP_PROXY (bare-SDK tier is honor-system). Apply the K8s NetworkPolicy or Docker internal-network lockdown and declare it. See /v1/deployment/lockdown.");
  }
}

if (warnings.length) {
  console.error("ScopeZero configuration warnings:");
  for (const warning of warnings) {
    console.error(`- ${warning}`);
  }
  process.exit(1);
}

console.log("ScopeZero configuration check passed.");
