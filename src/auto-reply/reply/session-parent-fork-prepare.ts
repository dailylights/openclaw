// Prepares parent-context fork metadata for guarded reply session initialization.
import { buildMainSessionRecoveryClearPatch } from "../../agents/main-session-recovery-clear.js";
import type { InternalSessionEntry, SessionEntry } from "../../config/sessions.js";
import {
  prepareSessionMemorySubjectLineageSeed,
  readCurrentSessionMemorySubject,
  type ReplySessionInitializationPreparedEntry,
} from "../../config/sessions/session-accessor.js";
import { forkSessionFromParent, resolveParentForkDecision } from "./session-fork.js";

export async function prepareReplySessionParentFork(params: {
  agentId: string;
  alreadyForked: boolean;
  parentSessionKey?: string;
  readEntry: (sessionKey: string) => SessionEntry | undefined;
  sessionEntry: SessionEntry;
  sessionKey: string;
  storePath: string;
  warn: (message: string) => void;
}): Promise<ReplySessionInitializationPreparedEntry> {
  if (
    !params.parentSessionKey ||
    params.parentSessionKey === params.sessionKey ||
    params.alreadyForked
  ) {
    return { sessionEntry: params.sessionEntry };
  }
  const parentEntry = params.readEntry(params.parentSessionKey);
  if (!parentEntry?.sessionId) {
    return { sessionEntry: params.sessionEntry };
  }
  const decision = await resolveParentForkDecision({
    parentEntry,
    agentId: params.agentId,
    storePath: params.storePath,
  });
  if (decision.status === "skip") {
    // The parent branch is too large to inherit usefully. Start fresh and
    // mark as handled so the thread does not retry this decision every turn.
    params.warn(
      `skipping parent fork (parent too large): parentKey=${params.parentSessionKey} → sessionKey=${params.sessionKey} ` +
        `parentTokens=${decision.parentTokens} maxTokens=${decision.maxTokens}`,
    );
    const parentSubject = readCurrentSessionMemorySubject({
      agentId: params.agentId,
      sessionKey: params.parentSessionKey,
      storePath: params.storePath,
    });
    return {
      sessionEntry: { ...params.sessionEntry, forkedFromParent: true },
      ...(parentSubject
        ? { memorySubjectSeed: prepareSessionMemorySubjectLineageSeed(parentSubject) }
        : {}),
    };
  }
  const fork = await forkSessionFromParent({
    parentEntry,
    agentId: params.agentId,
    parentSessionKey: params.parentSessionKey,
    sessionKey: params.sessionKey,
    storePath: params.storePath,
  });
  if (!fork) {
    return { sessionEntry: params.sessionEntry };
  }
  params.warn(
    `forking from parent session: parentKey=${params.parentSessionKey} → sessionKey=${params.sessionKey} ` +
      `parentTokens=${decision.parentTokens ?? "unknown"}`,
  );
  // The fork replaces this thread's transcript identity; recovery state from
  // the preseed row must not govern a later interruption of the fork.
  const forkedEntry: InternalSessionEntry = {
    ...params.sessionEntry,
    ...buildMainSessionRecoveryClearPatch(params.sessionEntry),
    sessionId: fork.sessionId,
    lifecycleRunId: undefined,
    forkSource: {
      sessionKey: params.parentSessionKey,
      sessionId: parentEntry.sessionId,
    },
    forkedFromParent: true,
    totalTokens: undefined,
    totalTokensFresh: false,
    totalTokensVersion: undefined,
  };
  return {
    sessionEntry: forkedEntry,
    memorySubjectSeed: fork.memorySubjectSeed,
  };
}
