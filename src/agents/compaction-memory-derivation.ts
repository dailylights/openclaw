import { isMemoryIsolationCutoverAgent } from "../plugins/memory-cutover.js";

const SCOPED_MEMORY_COMPACTION_DERIVATION_UNAVAILABLE_REASON =
  "Compaction is unavailable because scoped-memory derivation is not yet authorized.";

/**
 * Scoped-memory cutover forbids legacy compaction until its source-policy
 * derivation can be authorized before transcript content reaches a model.
 */
export function resolveScopedMemoryCompactionDenial(agentId: string | undefined):
  | {
      ok: false;
      compacted: false;
      reason: typeof SCOPED_MEMORY_COMPACTION_DERIVATION_UNAVAILABLE_REASON;
      failure: { reason: "scoped_memory_derivation_unavailable" };
    }
  | undefined {
  if (!agentId?.trim() || !isMemoryIsolationCutoverAgent(agentId)) {
    return undefined;
  }
  return {
    ok: false,
    compacted: false,
    reason: SCOPED_MEMORY_COMPACTION_DERIVATION_UNAVAILABLE_REASON,
    failure: { reason: "scoped_memory_derivation_unavailable" },
  };
}
