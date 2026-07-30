import { resolveMemoryEgressCapabilityId } from "../plugins/memory-egress-registry.js";
/** Runtime guard for the constrained Phase 1D memory-egress pilot. */
import {
  isMemoryScopedToolEgressBlocked,
  type MemoryInvocationToken,
} from "../plugins/memory-invocation.js";
import type { AnyAgentTool } from "./agent-tools.types.js";

const READ_ONLY_TOOL_NAMES = new Set([
  "memory_get",
  "memory_search",
  "read",
  "tool_describe",
  "tool_search",
]);

/**
 * Once memory is exposed, a model may continue reading or reasoning, but no
 * tool may create a second delivery route. Final reply delivery is guarded at
 * the run boundary because it is bound to the original authenticated route.
 */
export function wrapToolWithMemoryEgressPolicy(
  tool: AnyAgentTool,
  token: MemoryInvocationToken | undefined,
): AnyAgentTool {
  if (!token || READ_ONLY_TOOL_NAMES.has(tool.name)) {
    return tool;
  }
  const capability = resolveMemoryEgressCapabilityId(tool.name);
  return {
    ...tool,
    execute: async (toolCallId, args, signal, onUpdate) => {
      if (isMemoryScopedToolEgressBlocked(token)) {
        const label = capability ?? "unclassified side-effect";
        throw new Error(`Memory egress capability ${label} is unavailable after scoped exposure.`);
      }
      return await tool.execute(toolCallId, args, signal, onUpdate);
    },
  };
}
