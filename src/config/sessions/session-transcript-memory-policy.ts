import type { OpenClawAgentDatabase } from "../../state/openclaw-agent-db.js";
import {
  readTranscriptMemoryPolicyExportManifestFromDatabase as readArchiveManifestFromDatabase,
  type TranscriptMemoryPolicyExportManifest,
} from "./session-transcript-memory-policy-archive.js";
import { resetTranscriptMemoryPolicyEnforcementForTest } from "./session-transcript-memory-policy-core.js";

export { isTranscriptMemoryPolicyEnforcedInDatabase } from "./session-transcript-memory-policy-core.js";
export { authorizeTranscriptCompactionSources } from "./session-transcript-memory-policy-authorization.js";
export {
  captureAuthorizedTranscriptCompactionPoliciesInTransaction,
  captureAuthorizedTranscriptMemoryArchivePoliciesInTransaction,
  captureAuthorizedTranscriptMemoryPoliciesInTransaction,
  clearTranscriptCompactionPoliciesInTransaction,
  persistTranscriptMemoryArchiveInTransaction,
  rebuildTranscriptCompactionPoliciesInTransaction,
  restoreTranscriptMemoryPolicyInTransaction,
  type PreservedTranscriptCompactionPolicy,
  type PreservedTranscriptMemoryPolicy,
  type TranscriptMemoryArchivePolicySnapshot,
  type TranscriptMemoryPolicyExportManifest,
} from "./session-transcript-memory-policy-archive.js";
export {
  copyTranscriptMemoryPolicyInTransaction,
  invalidateTranscriptMemoryPolicyInTransaction,
  readAuthorizedTranscriptEventSeqs,
  recordTranscriptCompactionPolicyInTransaction,
  recordTranscriptMemoryPolicyInTransaction,
  type TranscriptMemoryPolicyTransitionKind,
} from "./session-transcript-memory-policy-operations.js";

/**
 * A fenced transcript read must not export the admitted row or later rows.
 * Archive construction owns policy validation; the public barrel owns
 * the caller's read fence while the split archive module stays reusable.
 */
export function readTranscriptMemoryPolicyExportManifestFromDatabase(params: {
  beforeEventSeq?: number;
  database: OpenClawAgentDatabase;
  sessionId: string;
}): TranscriptMemoryPolicyExportManifest | undefined {
  const manifest = readArchiveManifestFromDatabase(params);
  const beforeEventSeq = params.beforeEventSeq;
  if (!manifest || beforeEventSeq === undefined) {
    return manifest;
  }
  return {
    ...manifest,
    events: manifest.events.filter((event) => event.eventSeq < beforeEventSeq),
  };
}

const transcriptMemoryPolicyTesting = {
  resetDatabase: resetTranscriptMemoryPolicyEnforcementForTest,
};

if (process.env.VITEST || process.env.NODE_ENV === "test") {
  (globalThis as Record<PropertyKey, unknown>)[
    Symbol.for("openclaw.transcriptMemoryPolicyTestApi")
  ] = transcriptMemoryPolicyTesting;
}
