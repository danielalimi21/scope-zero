export async function handleMcpRequest({ body, runtime, registry, auth, principal }) {
  if (!body || body.jsonrpc !== "2.0") {
    return jsonRpcError(null, -32600, "Invalid JSON-RPC request.");
  }

  try {
    if (body.method === "initialize") {
      return {
        jsonrpc: "2.0",
        id: body.id,
        result: {
          protocolVersion: "2025-11-25",
          capabilities: {
            tools: { listChanged: true }
          },
          serverInfo: {
            name: "scopezero-action-authorization-proxy",
            version: "0.2.0"
          }
        }
      };
    }

    if (body.method === "notifications/initialized") {
      return null;
    }

    if (body.method === "tools/list") {
      return {
        jsonrpc: "2.0",
        id: body.id,
        result: {
          tools: registry.list()
        }
      };
    }

    if (body.method === "tools/call") {
      const params = body.params || {};
      const name = params.name;
      const args = params.arguments || {};
      auth.authorize(principal, "mcp:proxy", args.tenant_id);

      const verdict = await runtime.evaluateToolCall({
        ...args,
        tool: name,
        action: args.action || `MCP tools/call ${name}`
      });

      if (!verdict.verdict.safe_to_execute) {
        return {
          jsonrpc: "2.0",
          id: body.id,
          result: {
            isError: true,
            content: [
              {
                type: "text",
                text: `ScopeZero ${verdict.decision}: ${verdict.verdict.reasons.map((reason) => reason.message).join(" ")}`
              }
            ],
            structuredContent: {
              decision: verdict.decision,
              verdict: verdict.verdict,
              authorization_id: verdict.authorization_id,
              evidence_hash: verdict.evidence_hash,
              approval_id: verdict.approval?.id || null
            }
          }
        };
      }

      const result = await registry.execute(name, args, {
        verdict,
        evidence_hash: verdict.evidence_hash,
        principal
      });
      return {
        jsonrpc: "2.0",
        id: body.id,
        result: {
          ...result,
          structuredContent: {
            ...(result.structuredContent || {}),
            scopezero_decision: verdict.decision,
            scopezero_authorization_id: verdict.authorization_id,
            scopezero_evidence_hash: verdict.evidence_hash
          }
        }
      };
    }

    return jsonRpcError(body.id, -32601, `Method not found: ${body.method}`);
  } catch (error) {
    return jsonRpcError(body.id, error.status === 403 ? -32003 : -32000, error.message, {
      code: error.code || "scopezero_error",
      status: error.status || 500
    });
  }
}

function jsonRpcError(id, code, message, data = undefined) {
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code,
      message,
      data
    }
  };
}
