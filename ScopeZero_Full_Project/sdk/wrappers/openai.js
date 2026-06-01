/**
 * ScopeZero wrapper for the OpenAI SDK.
 *
 * Usage:
 *   import OpenAI from "openai";
 *   import { ScopeZeroClient } from "../../sdk/scopezero-sdk.js";
 *   import { guardOpenAI } from "../../sdk/wrappers/openai.js";
 *
 *   const openai = new OpenAI();
 *   const sz = new ScopeZeroClient({ baseUrl: "http://localhost:8788" });
 *   const guarded = guardOpenAI(openai, sz, {
 *     tenantId: "tenant_contoso",
 *     agentId: "my-agent",
 *     missionId: "mission_123"
 *   });
 *
 *   // Run the full agentic loop — ScopeZero authorizes every tool call before execution
 *   const result = await guarded.runLoop({
 *     model: "gpt-4o",
 *     messages: [{ role: "user", content: "Summarize the Q3 report" }],
 *     tools: openaiToolDefinitions,
 *     toolHandlers: {
 *       "drive.search": async (args) => { ... },
 *       "gmail.send":   async (args) => { ... }
 *     }
 *   });
 */

export function guardOpenAI(openai, sz, { tenantId, agentId, missionId }) {
  return {
    /**
     * Runs an agentic tool-call loop.
     * Intercepts every tool_calls response, authorizes each call through ScopeZero,
     * executes only the allowed ones, and feeds results back to the model.
     *
     * @param {object} params
     * @param {string} params.model
     * @param {Array}  params.messages
     * @param {Array}  params.tools         OpenAI tool definitions
     * @param {object} params.toolHandlers  { [toolName]: async (args) => result }
     * @param {number} [params.maxRounds=10]
     * @returns {{ messages: Array, decisions: Array }}
     */
    async runLoop({ model, messages, tools, toolHandlers, maxRounds = 10 }) {
      const history = [...messages];
      const decisions = [];

      for (let round = 0; round < maxRounds; round++) {
        const response = await openai.chat.completions.create({
          model,
          messages: history,
          tools,
          tool_choice: "auto"
        });

        const message = response.choices[0].message;
        history.push(message);

        if (!message.tool_calls || message.tool_calls.length === 0) {
          return { messages: history, decisions };
        }

        for (const call of message.tool_calls) {
          const toolName = call.function.name;
          let args;
          try {
            args = JSON.parse(call.function.arguments || "{}");
          } catch {
            args = {};
          }

          const authorization = await sz.authorizeAction({
            tenant_id: tenantId,
            agent_id: agentId,
            mission_id: missionId,
            tool: toolName,
            action: `openai.tool_call.${toolName}`,
            payload: args
          });

          decisions.push({ tool: toolName, decision: authorization.decision, authorization_id: authorization.authorization_id });

          let toolResult;
          if (authorization.verdict?.safe_to_execute) {
            const handler = toolHandlers[toolName];
            if (!handler) {
              toolResult = { error: `No handler registered for tool: ${toolName}` };
            } else {
              try {
                toolResult = await handler(args);
              } catch (error) {
                toolResult = { error: error.message };
              }
            }
          } else {
            toolResult = {
              scopezero_blocked: true,
              decision: authorization.decision,
              reasons: authorization.verdict?.reasons?.map((r) => r.message) || [],
              authorization_id: authorization.authorization_id
            };
          }

          history.push({
            role: "tool",
            tool_call_id: call.id,
            content: typeof toolResult === "string" ? toolResult : JSON.stringify(toolResult)
          });
        }
      }

      return { messages: history, decisions };
    },

    /**
     * Authorizes a single OpenAI tool call without executing it.
     * Returns the ScopeZero authorization result.
     */
    async authorize(toolName, args) {
      return sz.authorizeAction({
        tenant_id: tenantId,
        agent_id: agentId,
        mission_id: missionId,
        tool: toolName,
        action: `openai.tool_call.${toolName}`,
        payload: args
      });
    }
  };
}
