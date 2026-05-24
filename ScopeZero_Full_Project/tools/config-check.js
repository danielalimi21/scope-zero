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
}

if (warnings.length) {
  console.error("ScopeZero configuration warnings:");
  for (const warning of warnings) {
    console.error(`- ${warning}`);
  }
  process.exit(1);
}

console.log("ScopeZero configuration check passed.");
