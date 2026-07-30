import {
  authorizeTranscriptCompactionSources,
  isTranscriptMemoryPolicyEnforcedInDatabase,
} from "../../config/sessions/session-transcript-memory-policy.js";
import { openOpenClawAgentDatabase } from "../../state/openclaw-agent-db.js";
import type { ExtensionAPI, ReadonlySessionManager } from "../sessions/index.js";
import { setCompactionSafeguardCancelReason } from "./compaction-safeguard-runtime.js";

const DENIED_COMPACTION_REASON =
  "Compaction cancelled because its transcript sources are not authorized for this delivery.";

function openSessionDatabase(sessionManager: ReadonlySessionManager) {
  const target = sessionManager.getSessionTarget();
  return target
    ? openOpenClawAgentDatabase({ agentId: target.agentId, path: target.storePath })
    : undefined;
}

/**
 * A database failure is treated as enforced so a later safeguard hook cannot
 * replace planner-approved input with an unverified branch-wide fallback.
 */
export function isCompactionMemoryPolicyEnforced(sessionManager: ReadonlySessionManager): boolean {
  try {
    const database = openSessionDatabase(sessionManager);
    return database ? isTranscriptMemoryPolicyEnforcedInDatabase(database.db) : false;
  } catch {
    return true;
  }
}

/** Blocks compaction before any summarizer can receive transcript content. */
export default function compactionMemoryPolicyExtension(api: ExtensionAPI): void {
  api.on("session_before_compact", (event, ctx) => {
    const target = ctx.sessionManager.getSessionTarget();
    if (!target) {
      return undefined;
    }
    try {
      const database = openOpenClawAgentDatabase({
        agentId: target.agentId,
        path: target.storePath,
      });
      if (
        authorizeTranscriptCompactionSources({
          database,
          sessionId: target.sessionId,
          sourceEntryIds: event.preparation.sourceEntryIds,
        })
      ) {
        return undefined;
      }
    } catch {
      // The shared denial reason avoids leaking transcript-policy storage details.
    }
    setCompactionSafeguardCancelReason(ctx.sessionManager, DENIED_COMPACTION_REASON);
    return { cancel: true };
  });
}
