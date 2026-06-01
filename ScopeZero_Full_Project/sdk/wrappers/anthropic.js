/**
 * ScopeZero wrapper for the Anthropic SDK.
 *
 * Usage:
 *   import Anthropic from "@anthropic-ai/sdk";
 *   import { ScopeZeroClient } from "../../sdk/scopezero-sdk.js";
 *   import { guardAnthropic } from "../../sdk/wrappers/anthropic.js";
 *
 *   const anthropic = new Anthropic();
 *   const sz = new ScopeZeroClient({ baseUrl: "http://localhost:8788" });
 *   const guarded = guardAnthropic(anthropic, sz, {
 *     tenantId: "tenant_contoso",
 *     agentId: "my-agent",
 *     missionId: "mission_123"
 *   });
 *
 *   const result = await guarded.runLoop({
 *     model: "claude-sonnet-4-6",
 *     system: "You are a diligence agent.",
 *     messages: [{ role: "user", content: "Summarize the Q3 report" }],
 *     tools: anthropicToolDefinitions,
 *     toolHandlers: {
 *       "drive_search": async (input) => { ... },
 *       "gmail_send":   async (input) => { ... }
 *     }
 *   });
 */

export function guardAnthropic(anthropic, sz, { tenantId, agentId, missionId }) {
  return {
    /**
     * Runs an agentic tool-use loop.
     * Intercepts every tool_use block, authorizes each through ScopeZero,
     * executes only allowed ones, and feeds tool_result blocks back to the model.
     *
     * @param {object} params
     * @param {string} params.model
     * @param {string} [params.system]
     * @param {Array}  params.messages
     * @param {Array}  params.tools           Anthropic tool definitions
     * @param {object} params.toolHandlers    { [toolName]: async (input) => result }
     * @param {number} [params.maxRounds=10]
     * @param {number} [params.maxTokens=4096]
     * @returns {{ messages: Array, decisions: Array, finalText: string }}
     */
    async runLoop({ model, system, messages, tools, toolHandlers, maxRounds = 10, maxTokens = 4096 }) {
      const history = [...messages];
      const decisions = [];
      let finalText = "";

      for (let round = 0; round < maxRounds; round++) {
        const response = await anthropic.messages.create({
          model,
          system,
          messages: history,
          tools,
          max_tokens: maxTokens
        });

        // Collect any text content
        for (const block of response.content) {
          if (block.type === "text") finalText = block.text;
        }

        history.push({ role: "assistant", content: response.content });

        if (response.stop_reason !== "tool_use") {
          return { messages: history, decisions, finalText };
        }

        const toolUseBlocks = response.content.filter((b) => b.type === "tool_use");
        const toolResults = [];

        for (const block of toolUseBlocks) {
          const toolName = block.name;
          const toolInput = block.input || {};

          const authorization = await sz.authorizeAction({
            tenant_id: tenantId,
            agent_id: agentId,
            mission_id: missionId,
            tool: toolName,
            action: `anthropic.tool_use.${toolName}`,
            payload: toolInput
          });

          decisions.push({ tool: toolName, decision: authorization.decision, authorization_id: authorization.authorization_id });

          let resultContent;
          if (authorization.verdict?.safe_to_execute) {
            const handler = toolHandlers[toolName];
            if (!handler) {
              resultContent = JSON.stringify({ error: `No handler registered for tool: ${toolName}` });
            } else {
              try {
                const result = await handler(toolInput);
                resultContent = typeof result === "string" ? result : JSON.stringify(result);
              } catch (error) {
                resultContent = JSON.stringify({ error: error.message });
              }
            }
          } else {
            resultContent = JSON.stringify({
              scopezero_blocked: true,
              decision: authorization.decision,
              reasons: authorization.verdict?.reasons?.map((r) => r.message) || [],
              authorization_id: authorization.authorization_id
            });
          }

          toolResults.push({
            type: "tool_result",
            tool_use_id: block.id,
            content: resultContent
          });
        }

        history.push({ role: "user", content: toolResults });
      }

      return { messages: history, decisions, finalText };
    },

    /**
     * Authorizes a single Anthropic tool_use block without executing it.
     */
    async authorize(toolName, input) {
      return sz.authorizeAction({
        tenant_id: tenantId,
        agent_id: agentId,
        mission_id: missionId,
        tool: toolName,
        action: `anthropic.tool_use.${toolName}`,
        payload: input
      });
    }
  };
}
