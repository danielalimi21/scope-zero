import { httpError } from "./runtime.js";

// Ensures tenant_id in request body matches the authenticated principal's tenant.
// Platform admins (tenants: ["*"]) are exempt — they can act on any tenant.
export function enforceTenant(principal, requestedTenantId) {
  if (!requestedTenantId) {
    throw httpError(400, "missing_tenant", "tenant_id is required.");
  }
  if (principal.tenants.includes("*")) return requestedTenantId;
  if (principal.tenants.includes(requestedTenantId)) return requestedTenantId;
  throw httpError(403, "tenant_mismatch", "Token tenant does not match the requested tenant.");
}
