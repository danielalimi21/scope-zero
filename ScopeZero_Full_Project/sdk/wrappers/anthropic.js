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

import { authorizeAndExecute } from "../guard-core.js";

export function guardAnthropic(anthropic, sz, { tenantId, agentId, missionId, redactors = {} }) {
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

          const outcome = await authorizeAndExecute({
            sz,
            tenantId,
            agentId,
            missionId,
            tool: toolName,
            action: `anthropic.tool_use.${toolName}`,
            payload: toolInput,
            handler: toolHandlers[toolName],
            redactor: redactors[toolName] || null
          });

          decisions.push({ tool: toolName, decision: outcome.decision, executed: outcome.executed, authorization_id: outcome.authorization_id });

          toolResults.push({
            type: "tool_result",
            tool_use_id: block.id,
            content: typeof outcome.result === "string" ? outcome.result : JSON.stringify(outcome.result)
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
