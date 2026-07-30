import { isMemoryIsolationCutoverAgent } from "../plugins/memory-cutover.js";

const SCOPED_MEMORY_DELEGATION_UNAVAILABLE_REASON =
  "Subagent delegation is unavailable because scoped-memory delegation is not yet authorized.";

/**
 * A child inherits its session subject, but not the parent memory plan. Until
 * the plugin can issue and recheck that per-hop capability, deny cutover hops.
 */
export function resolveScopedMemoryDelegationDenial(params: {
  requesterAgentId: string;
  targetAgentId: string;
}): typeof SCOPED_MEMORY_DELEGATION_UNAVAILABLE_REASON | undefined {
  const agentIds = new Set([params.requesterAgentId.trim(), params.targetAgentId.trim()]);
  for (const agentId of agentIds) {
    if (agentId && isMemoryIsolationCutoverAgent(agentId)) {
      return SCOPED_MEMORY_DELEGATION_UNAVAILABLE_REASON;
    }
  }
  return undefined;
}
