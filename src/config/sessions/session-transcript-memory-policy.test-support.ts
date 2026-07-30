import "./session-transcript-memory-policy.js";

type TranscriptMemoryPolicyTesting = {
  resetDatabase(db: import("node:sqlite").DatabaseSync): void;
};

function getTesting(): TranscriptMemoryPolicyTesting {
  return (globalThis as Record<PropertyKey, unknown>)[
    Symbol.for("openclaw.transcriptMemoryPolicyTestApi")
  ] as TranscriptMemoryPolicyTesting;
}

export const transcriptMemoryPolicyTesting: TranscriptMemoryPolicyTesting = {
  resetDatabase: (db) => getTesting().resetDatabase(db),
};
