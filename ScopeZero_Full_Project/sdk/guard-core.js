// Shared authorize-then-execute core for the ScopeZero SDK wrappers.
//
// Enforcement rules (fail-closed by design):
//   - Execute ONLY on an explicit "allow", or on "redact" when a redactor is
//     supplied (the redaction control must actually be applied — running a
//     redact verdict on the raw payload would silently drop it).
//   - Any other verdict (block / approval / quarantine_context) → do not execute.
//   - If the gateway errors or is unreachable, treat it as a denial. Never
//     execute on an unknown authorization state.

export async function authorizeAndExecute({
  sz,
  tenantId,
  agentId,
  missionId,
  tool,
  action,
  payload,
  handler,
  redactor = null
}) {
  let authorization;
  try {
    authorization = await sz.authorizeAction({
      tenant_id: tenantId,
      agent_id: agentId,
      mission_id: missionId,
      tool,
      action,
      payload
    });
  } catch (error) {
    // Fail closed: an unreachable or erroring gateway must block, not pass.
    return {
      decision: "error",
      executed: false,
      authorization_id: null,
      result: { scopezero_blocked: true, decision: "error", reason: `ScopeZero gateway error: ${error.message}` }
    };
  }

  const decision = authorization?.decision;
  const authorizationId = authorization?.authorization_id || null;
  const reasons = (authorization?.verdict?.reasons || []).map((r) => r.message).filter(Boolean);

  if (decision === "allow") {
    return { decision, executed: true, authorization_id: authorizationId, result: await runHandler(handler, payload, tool) };
  }

  if (decision === "redact") {
    if (typeof redactor !== "function") {
      return {
        decision,
        executed: false,
        authorization_id: authorizationId,
        result: {
          scopezero_blocked: true,
          decision,
          reason: "Redaction required but no redactor was provided; refusing to execute with the raw payload.",
          reasons
        }
      };
    }
    const redacted = await redactor(payload, authorization.verdict);
    return { decision, executed: true, redacted: true, authorization_id: authorizationId, result: await runHandler(handler, redacted, tool) };
  }

  // block / approval / quarantine_context / anything unrecognized → no execution.
  return {
    decision: decision || "block",
    executed: false,
    authorization_id: authorizationId,
    result: { scopezero_blocked: true, decision: decision || "block", reasons, authorization_id: authorizationId }
  };
}

async function runHandler(handler, args, tool) {
  if (typeof handler !== "function") {
    return { error: `No handler registered for tool: ${tool}` };
  }
  try {
    return await handler(args);
  } catch (error) {
    return { error: error.message };
  }
}
