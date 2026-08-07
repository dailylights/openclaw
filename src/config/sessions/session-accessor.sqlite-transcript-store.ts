import { createHash } from "node:crypto";
import type { AgentMessage } from "../../agents/runtime/index.js";
import { redactTranscriptMessage } from "../../agents/transcript-redact.js";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
} from "../../infra/kysely-sync.js";
import { redactSecrets } from "../../logging/redact.js";
import { canonicalizePersistedUserMessageMedia } from "../../media/media-facts.js";
import type { OpenClawAgentDatabase } from "../../state/openclaw-agent-db.js";
import type {
  TranscriptEvent,
  TranscriptMessageAppendOptions,
} from "./session-accessor.sqlite-contract.js";
import {
  findSqliteTranscriptEventInDatabase,
  loadSqliteTranscriptEventsFromDatabase,
  readTranscriptEventId,
  readTranscriptEventMessage,
} from "./session-accessor.sqlite-read.js";
import { getSessionKysely, type ResolvedTranscriptScope } from "./session-accessor.sqlite-scope.js";
import {
  advanceTranscriptMutationAtInTransaction,
  deleteSqliteTranscriptEventsInTransaction,
  ensureTranscriptGenerationInTransaction,
  ensureTranscriptSessionRoot,
  readTranscriptGenerationInTransaction,
  readTranscriptMutationStateInTransaction,
  readNextTranscriptSeq,
  rotateTranscriptGenerationInTransaction,
  touchTranscriptMutationInTransaction,
} from "./session-accessor.sqlite-transcript-state.js";
import type { TrustedSessionMemorySubjectSeed } from "./session-memory-subject.js";
import {
  deleteSessionTranscriptIndexInTransaction,
  indexAppendedTranscriptEventInTransaction,
  reconcileSessionTranscriptIndexInTransaction,
} from "./session-transcript-index.js";
import {
  captureAuthorizedTranscriptCompactionPoliciesInTransaction,
  captureAuthorizedTranscriptMemoryPoliciesInTransaction,
  clearTranscriptCompactionPoliciesInTransaction,
  copyTranscriptMemoryPolicyInTransaction,
  invalidateTranscriptMemoryPolicyInTransaction,
  recordTranscriptMemoryPolicyInTransaction,
  recordTranscriptCompactionPolicyInTransaction,
  readAuthorizedTranscriptEventSeqs,
  rebuildTranscriptCompactionPoliciesInTransaction,
  restoreTranscriptMemoryPolicyInTransaction,
  isTranscriptMemoryPolicyEnforcedInDatabase,
  type PreservedTranscriptMemoryPolicy,
  type TranscriptMemoryPolicyTransitionKind,
} from "./session-transcript-memory-policy.js";
import { startSessionTranscriptIndexReconcile } from "./session-transcript-reconcile.js";
import { createSessionTranscriptHeader } from "./transcript-header.js";
import {
  isSessionTranscriptLeafControl,
  parseSessionTranscriptTreeEntry,
} from "./transcript-tree.js";
import { resolveVisibleTranscriptAppendParentId } from "./transcript-visible-events.js";

/** Immutable source-row binding for a maintenance rewrite that retains an existing companion. */
type TranscriptMemoryPolicyRewriteBinding = Readonly<{
  sourceContentSha256: string;
  sourceEventSeq: number;
  targetEventIndex: number;
}>;

export function createTranscriptMemoryPolicyRewriteBinding(params: {
  sourceEventJson: string;
  sourceEventSeq: number;
  targetEventIndex: number;
}): TranscriptMemoryPolicyRewriteBinding {
  return {
    sourceContentSha256: sha256(params.sourceEventJson),
    sourceEventSeq: params.sourceEventSeq,
    targetEventIndex: params.targetEventIndex,
  };
}

export function appendTranscriptEventInTransaction(
  database: OpenClawAgentDatabase,
  scope: ResolvedTranscriptScope,
  event: TranscriptEvent,
  options: {
    allowStoredAlias?: boolean;
    dedupeByMessageIdempotency?: boolean;
    /** Forks must bind copied lineage before the transcript root seals its write-once subject. */
    memorySubjectSeed?: TrustedSessionMemorySubjectSeed;
    /** A transition may copy only a persisted, currently valid policy companion. */
    memoryPolicySource?: {
      sessionId: string;
      transitionKind: TranscriptMemoryPolicyTransitionKind;
    };
    /** Doctor imports can restore only a byte-bound, currently-evaluable companion. */
    preservedMemoryPolicy?: PreservedTranscriptMemoryPolicy;
    /** Imports and cross-store transitions lack a locally evaluable source companion. */
    forceMemoryPolicyPending?: boolean;
    onProjectionReconcileNeeded?: () => void;
    scheduleProjectionReconcile?: boolean;
    touchMutation?: boolean;
  } = {},
): boolean {
  const persistedEvent = canonicalizeTranscriptEventMedia(event);
  const db = getSessionKysely(database.db);
  const createdAt = readEventTimestamp(persistedEvent) ?? Date.now();
  ensureTranscriptSessionRoot(database, scope, createdAt, {
    allowStoredAlias: options.allowStoredAlias === true,
    ...(options.memorySubjectSeed ? { memorySubjectSeed: options.memorySubjectSeed } : {}),
  });
  ensureTranscriptGenerationInTransaction(database, scope.sessionId);
  const identity = readTranscriptEventIdentity(persistedEvent);
  if (identity && readTranscriptIdentityByEventId(database, scope.sessionId, identity.eventId)) {
    return false;
  }
  if (
    identity?.messageIdempotencyKey &&
    options.dedupeByMessageIdempotency &&
    readTranscriptIdentityByMessageIdempotencyKey(
      database,
      scope.sessionId,
      identity.messageIdempotencyKey,
    )
  ) {
    return false;
  }
  const seq = readNextTranscriptSeq(database, scope.sessionId);
  const sourceEventSeq =
    options.memoryPolicySource && identity
      ? readTranscriptIdentityByEventId(
          database,
          options.memoryPolicySource.sessionId,
          identity.eventId,
        )?.seq
      : undefined;
  executeSqliteQuerySync(
    database.db,
    db.insertInto("transcript_events").values({
      session_id: scope.sessionId,
      seq,
      event_json: JSON.stringify(persistedEvent),
      created_at: createdAt,
    }),
  );
  const compactionId = readCompactionEventId(persistedEvent);
  // A newly appended pending import must not reuse an orphaned binding from a
  // previous partial target. Retries return above before this can clear valid state.
  if (options.forceMemoryPolicyPending === true && compactionId) {
    clearTranscriptCompactionPoliciesInTransaction({
      compactionId,
      database,
      sessionId: scope.sessionId,
    });
  }
  const initiallyAuthorized = recordTranscriptMemoryPolicyInTransaction({
    database,
    sessionId: scope.sessionId,
    eventSeq: seq,
    createdAt,
    forcePending:
      options.forceMemoryPolicyPending === true ||
      options.memoryPolicySource !== undefined ||
      options.preservedMemoryPolicy !== undefined,
  });
  let memoryPolicyAuthorized =
    options.preservedMemoryPolicy && !initiallyAuthorized
      ? restoreTranscriptMemoryPolicyInTransaction({
          database,
          preserved: options.preservedMemoryPolicy,
          sessionId: scope.sessionId,
          eventSeq: seq,
        })
      : sourceEventSeq !== undefined && options.memoryPolicySource
        ? copyTranscriptMemoryPolicyInTransaction({
            database,
            sourceSessionId: options.memoryPolicySource.sessionId,
            sourceEventSeq,
            targetSessionId: scope.sessionId,
            targetEventSeq: seq,
            transitionKind: options.memoryPolicySource.transitionKind,
            createdAt,
          })
        : initiallyAuthorized;
  // A forced-pending import needs its manifest's sequence binding. Payload
  // sourceEntryIds must not reconstruct that authority alone.
  if (memoryPolicyAuthorized && compactionId && options.forceMemoryPolicyPending !== true) {
    const sourceEventSeqs = readCompactionSourceEventSeqs({
      database,
      event: persistedEvent,
      sessionId: scope.sessionId,
    });
    memoryPolicyAuthorized = Boolean(
      sourceEventSeqs &&
      recordTranscriptCompactionPolicyInTransaction({
        compactionId,
        database,
        eventSeq: seq,
        sessionId: scope.sessionId,
        sourceEventSeqs,
      }),
    );
    if (!memoryPolicyAuthorized) {
      invalidateTranscriptMemoryPolicyInTransaction({
        database,
        eventSeq: seq,
        sessionId: scope.sessionId,
      });
    }
  }
  if (options.touchMutation !== false) {
    touchTranscriptMutationInTransaction(database, scope.sessionId);
  }
  const projectionNeedsRebuild = indexAppendedTranscriptEventInTransaction(database.db, {
    sessionId: scope.sessionId,
    seq,
    event: persistedEvent,
    eventId: identity?.eventId ?? null,
    createdAt,
    memoryPolicyAuthorized,
  });
  if (projectionNeedsRebuild) {
    options.onProjectionReconcileNeeded?.();
  }
  if (!identity) {
    scheduleTranscriptProjectionReconcile(database, scope, projectionNeedsRebuild, options);
    return true;
  }
  // Caller-checked appends may retain a duplicate key in the payload, but the
  // identity index can point at only one row.
  const indexedMessageIdempotencyKey =
    identity.messageIdempotencyKey &&
    !options.dedupeByMessageIdempotency &&
    readTranscriptIdentityByMessageIdempotencyKey(
      database,
      scope.sessionId,
      identity.messageIdempotencyKey,
    )
      ? undefined
      : identity.messageIdempotencyKey;
  executeSqliteQuerySync(
    database.db,
    db
      .insertInto("transcript_event_identities")
      .values({
        session_id: scope.sessionId,
        event_id: identity.eventId,
        seq,
        event_type: identity.eventType,
        parent_id: identity.parentId,
        message_idempotency_key: indexedMessageIdempotencyKey,
        created_at: createdAt,
      })
      .onConflict((conflict) => conflict.columns(["session_id", "event_id"]).doNothing()),
  );
  scheduleTranscriptProjectionReconcile(database, scope, projectionNeedsRebuild, options);
  return true;
}

function scheduleTranscriptProjectionReconcile(
  database: OpenClawAgentDatabase,
  scope: ResolvedTranscriptScope,
  projectionNeedsRebuild: boolean,
  options: { scheduleProjectionReconcile?: boolean },
): void {
  if (!projectionNeedsRebuild || options.scheduleProjectionReconcile === false) {
    return;
  }
  // setImmediate in the reconcile owner runs only after this synchronous
  // SQLite transaction commits, keeping full-tree work off the writer stack.
  startSessionTranscriptIndexReconcile({
    agentId: scope.agentId,
    path: database.path,
    preferredSessionId: scope.sessionId,
  });
}

function readCompactionEventId(event: TranscriptEvent): string | undefined {
  if (!event || typeof event !== "object" || Array.isArray(event)) {
    return undefined;
  }
  const { id, type } = event as { id?: unknown; type?: unknown };
  return type === "compaction" && typeof id === "string" && id.trim() ? id : undefined;
}

function readCompactionSourceEventSeqs(params: {
  database: OpenClawAgentDatabase;
  event: TranscriptEvent;
  sessionId: string;
}): number[] | undefined {
  if (!params.event || typeof params.event !== "object" || Array.isArray(params.event)) {
    return undefined;
  }
  const { sourceEntryIds, type } = params.event as {
    sourceEntryIds?: unknown;
    type?: unknown;
  };
  if (
    type !== "compaction" ||
    !Array.isArray(sourceEntryIds) ||
    sourceEntryIds.length === 0 ||
    sourceEntryIds.some((entryId) => typeof entryId !== "string" || !entryId.trim())
  ) {
    return undefined;
  }
  const normalizedSourceEntryIds = sourceEntryIds.map((entryId) => entryId.trim());
  if (new Set(normalizedSourceEntryIds).size !== normalizedSourceEntryIds.length) {
    return undefined;
  }
  const db = getSessionKysely(params.database.db);
  const sourceEventSeqs: number[] = [];
  for (const entryId of normalizedSourceEntryIds) {
    const identity = executeSqliteQueryTakeFirstSync(
      params.database.db,
      db
        .selectFrom("transcript_event_identities")
        .select("seq")
        .where("session_id", "=", params.sessionId)
        .where("event_id", "=", entryId),
    );
    if (!identity || !Number.isSafeInteger(identity.seq) || identity.seq < 0) {
      return undefined;
    }
    sourceEventSeqs.push(identity.seq);
  }
  return sourceEventSeqs;
}

export function appendTranscriptEventsInTransaction(
  database: OpenClawAgentDatabase,
  scope: ResolvedTranscriptScope,
  events: readonly TranscriptEvent[],
  options: {
    memoryPolicySource?: {
      sessionId: string;
      transitionKind: TranscriptMemoryPolicyTransitionKind;
    };
    memorySubjectSeed?: TrustedSessionMemorySubjectSeed;
    forceMemoryPolicyPending?: boolean;
  } = {},
): number {
  // A replay with an existing target cannot prove a complete sequence map for
  // its already-deduped rows; retain its bindings instead of clearing them.
  const targetTranscriptIsFresh = readNextTranscriptSeq(database, scope.sessionId) === 0;
  const capturedCompactionPolicies =
    options.memoryPolicySource && targetTranscriptIsFresh
      ? captureAuthorizedTranscriptCompactionPoliciesInTransaction({
          database,
          sessionId: options.memoryPolicySource.sessionId,
        })
      : undefined;
  if (options.memoryPolicySource && targetTranscriptIsFresh) {
    clearTranscriptCompactionPoliciesInTransaction({ database, sessionId: scope.sessionId });
  }
  let appended = 0;
  let projectionNeedsRebuild = false;
  const eventSeqBySourceEventSeq = new Map<number, number>();
  for (const event of events) {
    const identity = readTranscriptEventIdentity(event);
    const sourceEventSeq =
      identity && options.memoryPolicySource
        ? readTranscriptIdentityByEventId(
            database,
            options.memoryPolicySource.sessionId,
            identity.eventId,
          )?.seq
        : undefined;
    const eventSeq = readNextTranscriptSeq(database, scope.sessionId);
    if (
      appendTranscriptEventInTransaction(database, scope, event, {
        ...(options.memorySubjectSeed ? { memorySubjectSeed: options.memorySubjectSeed } : {}),
        ...(options.memoryPolicySource ? { memoryPolicySource: options.memoryPolicySource } : {}),
        ...(options.forceMemoryPolicyPending ? { forceMemoryPolicyPending: true } : {}),
        onProjectionReconcileNeeded: () => {
          projectionNeedsRebuild = true;
        },
        scheduleProjectionReconcile: false,
        touchMutation: false,
      })
    ) {
      appended += 1;
      if (sourceEventSeq !== undefined) {
        eventSeqBySourceEventSeq.set(sourceEventSeq, eventSeq);
      }
    }
  }
  if (targetTranscriptIsFresh && capturedCompactionPolicies?.size) {
    rebuildTranscriptCompactionPoliciesInTransaction({
      captured: capturedCompactionPolicies,
      database,
      eventSeqBySourceEventSeq,
      sessionId: scope.sessionId,
    });
    // Replays initially index summaries as unavailable while their sequence
    // bindings are absent. Rebuild after all old-to-new mappings are known.
    reconcileSessionTranscriptIndexInTransaction(database.db, scope.sessionId);
  }
  if (appended > 0) {
    touchTranscriptMutationInTransaction(database, scope.sessionId);
    scheduleTranscriptProjectionReconcile(database, scope, projectionNeedsRebuild, {});
  }
  return appended;
}

function appendTranscriptEventRowInTransaction(
  database: OpenClawAgentDatabase,
  scope: ResolvedTranscriptScope,
  event: TranscriptEvent,
  seq: number,
  state: { seenEventIds: Set<string>; seenMessageIdempotencyKeys: Set<string> },
  createdAtOverride?: number,
  options: {
    forceMemoryPolicyPending?: boolean;
    preservedMemoryPolicy?: PreservedTranscriptMemoryPolicy;
  } = {},
): boolean {
  const persistedEvent = canonicalizeTranscriptEventMedia(event);
  const db = getSessionKysely(database.db);
  const createdAt = createdAtOverride ?? readEventTimestamp(persistedEvent) ?? Date.now();
  const identity = readTranscriptEventIdentity(persistedEvent);
  if (identity && state.seenEventIds.has(identity.eventId)) {
    return false;
  }
  executeSqliteQuerySync(
    database.db,
    db.insertInto("transcript_events").values({
      session_id: scope.sessionId,
      seq,
      event_json: JSON.stringify(persistedEvent),
      created_at: createdAt,
    }),
  );
  const memoryPolicyAuthorized = recordTranscriptMemoryPolicyInTransaction({
    database,
    sessionId: scope.sessionId,
    eventSeq: seq,
    createdAt,
    forcePending: options.forceMemoryPolicyPending === true,
  });
  const restoredMemoryPolicyAuthorized =
    options.preservedMemoryPolicy && !memoryPolicyAuthorized
      ? restoreTranscriptMemoryPolicyInTransaction({
          database,
          preserved: options.preservedMemoryPolicy,
          sessionId: scope.sessionId,
          eventSeq: seq,
        })
      : memoryPolicyAuthorized;
  indexAppendedTranscriptEventInTransaction(database.db, {
    sessionId: scope.sessionId,
    seq,
    event: persistedEvent,
    eventId: identity?.eventId ?? null,
    createdAt,
    memoryPolicyAuthorized: restoredMemoryPolicyAuthorized,
  });
  if (!identity) {
    return true;
  }
  state.seenEventIds.add(identity.eventId);
  const indexedMessageIdempotencyKey =
    identity.messageIdempotencyKey &&
    !state.seenMessageIdempotencyKeys.has(identity.messageIdempotencyKey)
      ? identity.messageIdempotencyKey
      : undefined;
  if (indexedMessageIdempotencyKey) {
    state.seenMessageIdempotencyKeys.add(indexedMessageIdempotencyKey);
  }
  executeSqliteQuerySync(
    database.db,
    db.insertInto("transcript_event_identities").values({
      session_id: scope.sessionId,
      event_id: identity.eventId,
      seq,
      event_type: identity.eventType,
      parent_id: identity.parentId,
      message_idempotency_key: indexedMessageIdempotencyKey,
      created_at: createdAt,
    }),
  );
  return true;
}

export function ensureTranscriptHeader(
  database: OpenClawAgentDatabase,
  scope: ResolvedTranscriptScope,
  cwd: string | undefined,
  now: number,
): void {
  const db = getSessionKysely(database.db);
  const existing = executeSqliteQueryTakeFirstSync(
    database.db,
    db
      .selectFrom("transcript_events")
      .select("seq")
      .where("session_id", "=", scope.sessionId)
      .limit(1),
  );
  if (existing) {
    return;
  }
  appendTranscriptEventInTransaction(
    database,
    scope,
    createSessionTranscriptHeader({ cwd, sessionId: scope.sessionId }),
  );
  ensureTranscriptSessionRoot(database, scope, now);
}

export function readActiveTranscriptAppendParentId(
  database: OpenClawAgentDatabase,
  sessionId: string,
): string | null {
  const db = getSessionKysely(database.db);
  const latest = executeSqliteQueryTakeFirstSync(
    database.db,
    db
      .selectFrom("transcript_event_identities as ti")
      .innerJoin("transcript_events as te", (join) =>
        join.onRef("te.session_id", "=", "ti.session_id").onRef("te.seq", "=", "ti.seq"),
      )
      .select(["ti.event_type", "te.event_json"])
      .where("ti.session_id", "=", sessionId)
      .orderBy("ti.seq", "desc")
      .limit(1),
  );
  if (!latest) {
    return null;
  }
  try {
    const event = JSON.parse(latest.event_json) as unknown;
    const treeEntry = parseSessionTranscriptTreeEntry(event);
    if (!treeEntry) {
      return resolveVisibleTranscriptAppendParentId(
        loadSqliteTranscriptEventsFromDatabase(database, sessionId),
      );
    }
    if (latest.event_type !== "leaf") {
      return treeEntry.appendParentId;
    }
    const leafReferencesKnown =
      treeEntry.leafId !== undefined &&
      transcriptTreeReferenceExists(database, sessionId, treeEntry.leafId) &&
      transcriptTreeReferenceExists(database, sessionId, treeEntry.appendParentId);
    if (isSessionTranscriptLeafControl(event) && leafReferencesKnown) {
      return treeEntry.appendParentId;
    }
  } catch {
    // Fall through to the tolerant full-tree resolver.
  }
  return resolveVisibleTranscriptAppendParentId(
    loadSqliteTranscriptEventsFromDatabase(database, sessionId),
  );
}

function transcriptTreeReferenceExists(
  database: OpenClawAgentDatabase,
  sessionId: string,
  eventId: string | null,
): boolean {
  return (
    eventId === null || readTranscriptIdentityByEventId(database, sessionId, eventId) !== undefined
  );
}

export function replaceSqliteTranscriptEventsInTransaction(
  database: OpenClawAgentDatabase,
  resolved: ResolvedTranscriptScope,
  events: readonly TranscriptEvent[],
  options: {
    createdAtByIndex?: readonly number[];
    /** New transcript roots must receive trusted lineage before their subject becomes write-once. */
    memorySubjectSeed?: TrustedSessionMemorySubjectSeed;
    /** Keep maintenance rewrites at their existing recency while invalidating stale projections. */
    preserveSessionWindowRecency?: boolean;
    /** Byte-bound source-row bindings for a maintenance rewrite. */
    preservedMemoryPolicyBindings?: readonly TranscriptMemoryPolicyRewriteBinding[];
  } = {},
): void {
  const preservedTranscriptUpdatedAt =
    options.preserveSessionWindowRecency === true
      ? readTranscriptMutationStateInTransaction(database, resolved.sessionId).updatedAt
      : undefined;
  const preservedPoliciesByEventIndex = collectPreservedTranscriptPoliciesForRewrite({
    database,
    events,
    preservedMemoryPolicyBindings: options.preservedMemoryPolicyBindings,
    sessionId: resolved.sessionId,
  });
  const capturedCompactionPolicies = captureAuthorizedTranscriptCompactionPoliciesInTransaction({
    database,
    sessionId: resolved.sessionId,
  });
  const memoryPolicyEnforced = isTranscriptMemoryPolicyEnforcedInDatabase(database.db);
  const previousGeneration = readTranscriptGenerationInTransaction(database, resolved.sessionId);
  const deleted = deleteSqliteTranscriptEventsInTransaction(database, resolved.sessionId);
  if (events.length === 0) {
    if (deleted || previousGeneration) {
      rotateTranscriptGenerationInTransaction(database, resolved.sessionId);
      recordTranscriptReplacementMutation(
        database,
        resolved.sessionId,
        preservedTranscriptUpdatedAt,
      );
    }
    return;
  }
  if (!deleted || options.preserveSessionWindowRecency !== true) {
    ensureTranscriptSessionRoot(database, resolved, readEventTimestamp(events[0]) ?? Date.now(), {
      ...(options.memorySubjectSeed ? { memorySubjectSeed: options.memorySubjectSeed } : {}),
    });
  }
  if (deleted || previousGeneration) {
    rotateTranscriptGenerationInTransaction(database, resolved.sessionId);
  } else {
    ensureTranscriptGenerationInTransaction(database, resolved.sessionId);
  }
  let seq = 0;
  const seenEventIds = new Set<string>();
  const seenMessageIdempotencyKeys = new Set<string>();
  const eventSeqBySourceEventSeq = new Map<number, number>();
  for (const [eventIndex, event] of events.entries()) {
    const preserved = preservedPoliciesByEventIndex?.get(eventIndex);
    if (
      appendTranscriptEventRowInTransaction(
        database,
        resolved,
        event,
        seq,
        {
          seenEventIds,
          seenMessageIdempotencyKeys,
        },
        options.createdAtByIndex?.[eventIndex],
        {
          forceMemoryPolicyPending: memoryPolicyEnforced,
          ...(preserved ? { preservedMemoryPolicy: preserved.policy } : {}),
        },
      )
    ) {
      if (preserved) {
        eventSeqBySourceEventSeq.set(preserved.sourceEventSeq, seq);
      }
      seq += 1;
    }
  }
  rebuildTranscriptCompactionPoliciesInTransaction({
    captured: capturedCompactionPolicies,
    database,
    eventSeqBySourceEventSeq,
    sessionId: resolved.sessionId,
  });
  if (deleted || seq > 0) {
    recordTranscriptReplacementMutation(database, resolved.sessionId, preservedTranscriptUpdatedAt);
    reconcileSessionTranscriptIndexInTransaction(database.db, resolved.sessionId);
  }
}

function collectPreservedTranscriptPoliciesForRewrite(params: {
  database: OpenClawAgentDatabase;
  events: readonly TranscriptEvent[];
  preservedMemoryPolicyBindings: readonly TranscriptMemoryPolicyRewriteBinding[] | undefined;
  sessionId: string;
}):
  | Map<number, Readonly<{ policy: PreservedTranscriptMemoryPolicy; sourceEventSeq: number }>>
  | undefined {
  const { database, events, preservedMemoryPolicyBindings, sessionId } = params;
  if (!preservedMemoryPolicyBindings) {
    return undefined;
  }
  const preserved = captureAuthorizedTranscriptMemoryPoliciesInTransaction({ database, sessionId });
  if (!preserved) {
    return undefined;
  }
  const rows = executeSqliteQuerySync(
    database.db,
    getSessionKysely(database.db)
      .selectFrom("transcript_events")
      .select(["event_json", "seq"])
      .where("session_id", "=", sessionId)
      .orderBy("seq", "asc"),
  ).rows;
  const sourceEventJsonBySeq = new Map(rows.map((row) => [row.seq, row.event_json]));
  const boundPolicies = new Map<
    number,
    Readonly<{ policy: PreservedTranscriptMemoryPolicy; sourceEventSeq: number }>
  >();
  const usedSourceSeqs = new Set<number>();
  for (const binding of preservedMemoryPolicyBindings) {
    if (
      !Number.isSafeInteger(binding.targetEventIndex) ||
      binding.targetEventIndex < 0 ||
      binding.targetEventIndex >= events.length ||
      !Number.isSafeInteger(binding.sourceEventSeq) ||
      usedSourceSeqs.has(binding.sourceEventSeq) ||
      boundPolicies.has(binding.targetEventIndex)
    ) {
      continue;
    }
    const sourceEventJson = sourceEventJsonBySeq.get(binding.sourceEventSeq);
    const policy = preserved.get(binding.sourceEventSeq);
    const targetEventJson = JSON.stringify(
      canonicalizeTranscriptEventMedia(events[binding.targetEventIndex] as TranscriptEvent),
    );
    if (
      !sourceEventJson ||
      !policy ||
      sha256(sourceEventJson) !== binding.sourceContentSha256 ||
      sha256(targetEventJson) !== binding.sourceContentSha256
    ) {
      continue;
    }
    usedSourceSeqs.add(binding.sourceEventSeq);
    boundPolicies.set(binding.targetEventIndex, {
      policy,
      sourceEventSeq: binding.sourceEventSeq,
    });
  }
  return boundPolicies;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function recordTranscriptReplacementMutation(
  database: OpenClawAgentDatabase,
  sessionId: string,
  preservedUpdatedAt: number | null | undefined,
): void {
  if (preservedUpdatedAt === undefined || preservedUpdatedAt === null) {
    touchTranscriptMutationInTransaction(database, sessionId);
    return;
  }
  // Maintenance rewrites must invalidate in-flight projections without making an old session
  // look newly active. A one-tick advance preserves ordering while changing the snapshot key.
  advanceTranscriptMutationAtInTransaction(database, sessionId, preservedUpdatedAt, {
    strictly: true,
  });
}

/** Rewrite existing transcript rows exactly, without append-time deduplication. */
export function rewriteSqliteTranscriptEventRowsInTransaction(
  database: OpenClawAgentDatabase,
  resolved: ResolvedTranscriptScope,
  rows: readonly {
    event: TranscriptEvent;
    expectedEventJson: string;
    seq: number;
  }[],
): void {
  if (rows.length === 0) {
    return;
  }
  const db = getSessionKysely(database.db);
  const capturedCompactionPolicies = captureAuthorizedTranscriptCompactionPoliciesInTransaction({
    database,
    sessionId: resolved.sessionId,
  });
  const rewrittenSeqs = new Set(rows.map((row) => row.seq));
  const eventSeqBySourceEventSeq = new Map(
    executeSqliteQuerySync(
      database.db,
      db
        .selectFrom("transcript_events")
        .select("seq")
        .where("session_id", "=", resolved.sessionId)
        .orderBy("seq", "asc"),
    ).rows.flatMap((row) => (rewrittenSeqs.has(row.seq) ? [] : [[row.seq, row.seq] as const])),
  );
  clearTranscriptCompactionPoliciesInTransaction({ database, sessionId: resolved.sessionId });
  for (const row of rows) {
    const persistedEvent = canonicalizeTranscriptEventMedia(row.event);
    const persistedEventJson = JSON.stringify(persistedEvent);
    const result = executeSqliteQuerySync(
      database.db,
      db
        .updateTable("transcript_events")
        .set({ event_json: persistedEventJson })
        .where("session_id", "=", resolved.sessionId)
        .where("seq", "=", row.seq)
        .where("event_json", "=", row.expectedEventJson),
    );
    if (result.numAffectedRows !== 1n) {
      throw new Error(
        `Transcript row ${resolved.sessionId}:${row.seq} changed before exact rewrite`,
      );
    }
    if (persistedEventJson === row.expectedEventJson) {
      eventSeqBySourceEventSeq.set(row.seq, row.seq);
    } else {
      invalidateTranscriptMemoryPolicyInTransaction({
        database,
        eventSeq: row.seq,
        sessionId: resolved.sessionId,
      });
    }
  }
  rebuildTranscriptCompactionPoliciesInTransaction({
    captured: capturedCompactionPolicies,
    database,
    eventSeqBySourceEventSeq,
    sessionId: resolved.sessionId,
  });
  rotateTranscriptGenerationInTransaction(database, resolved.sessionId);
  touchTranscriptMutationInTransaction(database, resolved.sessionId);
  reconcileSessionTranscriptIndexInTransaction(database.db, resolved.sessionId);
}

// Text-only transcript repair: rewrites event_json for specific rows in place.
// Preserves seq, created_at, session_key, and session activity recency; rotates the transcript
// generation and rebuilds the index so readers/search pick up the new text.
export function updateSqliteTranscriptEventJsonInTransaction(
  database: OpenClawAgentDatabase,
  sessionId: string,
  updates: ReadonlyArray<{ seq: number; eventJson: string }>,
): void {
  if (updates.length === 0) {
    return;
  }
  const db = getSessionKysely(database.db);
  const capturedCompactionPolicies = captureAuthorizedTranscriptCompactionPoliciesInTransaction({
    database,
    sessionId,
  });
  const updatedSeqs = new Set(updates.map((update) => update.seq));
  const eventSeqBySourceEventSeq = new Map(
    executeSqliteQuerySync(
      database.db,
      db
        .selectFrom("transcript_events")
        .select("seq")
        .where("session_id", "=", sessionId)
        .orderBy("seq", "asc"),
    ).rows.flatMap((row) => (updatedSeqs.has(row.seq) ? [] : [[row.seq, row.seq] as const])),
  );
  clearTranscriptCompactionPoliciesInTransaction({ database, sessionId });
  for (const { seq, eventJson } of updates) {
    executeSqliteQuerySync(
      database.db,
      db
        .updateTable("transcript_events")
        .set({ event_json: eventJson })
        .where("session_id", "=", sessionId)
        .where("seq", "=", seq),
    );
    invalidateTranscriptMemoryPolicyInTransaction({
      database,
      eventSeq: seq,
      sessionId,
    });
  }
  rebuildTranscriptCompactionPoliciesInTransaction({
    captured: capturedCompactionPolicies,
    database,
    eventSeqBySourceEventSeq,
    sessionId,
  });
  rotateTranscriptGenerationInTransaction(database, sessionId);
  deleteSessionTranscriptIndexInTransaction(database.db, sessionId);
  reconcileSessionTranscriptIndexInTransaction(database.db, sessionId);
  // Minimally advance transcript_updated_at (prev+1), NOT to now. This is a one-time maintenance
  // rewrite: bumping to now would reorder legacy sessions to the top of every recency view
  // (sqlite-history.ts orders by transcript_updated_at). But the watermark must still change,
  // because it is the in-flight projection-rebuild worker's stale-snapshot key
  // (session-transcript-projection-rebuild.ts sourceSnapshotMatches) and seq is unchanged here;
  // leaving it identical would let a concurrent worker apply a stale pre-rewrite index. A null
  // watermark (session absent from recency views) has no recency to preserve, so touch to now.
  const currentUpdatedAt = readTranscriptMutationStateInTransaction(database, sessionId).updatedAt;
  if (currentUpdatedAt === null) {
    touchTranscriptMutationInTransaction(database, sessionId);
  } else {
    advanceTranscriptMutationAtInTransaction(database, sessionId, currentUpdatedAt, {
      strictly: true,
    });
  }
}

export function readTranscriptIdentityByEventId(
  database: OpenClawAgentDatabase,
  sessionId: string,
  eventId: string,
): { eventId: string; parentId: string | null; seq: number } | undefined {
  const db = getSessionKysely(database.db);
  const row = executeSqliteQueryTakeFirstSync(
    database.db,
    db
      .selectFrom("transcript_event_identities")
      .select(["event_id", "parent_id", "seq"])
      .where("session_id", "=", sessionId)
      .where("event_id", "=", eventId),
  );
  return row ? { eventId: row.event_id, parentId: row.parent_id, seq: row.seq } : undefined;
}

function readTranscriptIdentityByMessageIdempotencyKey(
  database: OpenClawAgentDatabase,
  sessionId: string,
  idempotencyKey: string,
): { eventId: string; seq: number } | undefined {
  const db = getSessionKysely(database.db);
  const row = executeSqliteQueryTakeFirstSync(
    database.db,
    db
      .selectFrom("transcript_event_identities")
      .select(["event_id", "seq"])
      .where("session_id", "=", sessionId)
      .where("message_idempotency_key", "=", idempotencyKey)
      .orderBy("seq", "desc")
      .limit(1),
  );
  return row ? { eventId: row.event_id, seq: row.seq } : undefined;
}

function readTranscriptMessageByIdempotencyKey(
  database: OpenClawAgentDatabase,
  scope: ResolvedTranscriptScope,
  idempotencyKey: string,
): { messageId: string; message: unknown } | undefined {
  const identity = readTranscriptIdentityByMessageIdempotencyKey(
    database,
    scope.sessionId,
    idempotencyKey,
  );
  return identity ? readTranscriptMessageByIdentity(database, scope, identity) : undefined;
}

export function readTranscriptMessageByScopedIdempotencyKey(
  database: OpenClawAgentDatabase,
  scope: ResolvedTranscriptScope,
  idempotencyKey: string,
  lookup: TranscriptMessageAppendOptions<unknown>["idempotencyLookup"],
): { messageId: string; message: unknown } | undefined {
  if (lookup !== "scan-assistant") {
    return readTranscriptMessageByIdempotencyKey(database, scope, idempotencyKey);
  }
  const found = findSqliteTranscriptEventInDatabase(database, scope.sessionId, (event) => {
    const message = readTranscriptEventMessage(event);
    return message?.role === "assistant" && message.idempotencyKey === idempotencyKey;
  });
  if (!found) {
    return undefined;
  }
  const message = readTranscriptEventMessage(found.event);
  return message
    ? { messageId: readTranscriptEventId(found.event) ?? idempotencyKey, message }
    : undefined;
}

export function readTranscriptMessageByEventId(
  database: OpenClawAgentDatabase,
  scope: ResolvedTranscriptScope,
  eventId: string,
): { messageId: string; message: unknown } | undefined {
  const identity = readTranscriptIdentityByEventId(database, scope.sessionId, eventId);
  return identity ? readTranscriptMessageByIdentity(database, scope, identity) : undefined;
}

function readTranscriptMessageByIdentity(
  database: OpenClawAgentDatabase,
  scope: ResolvedTranscriptScope,
  identity: { eventId: string; seq: number },
): { messageId: string; message: unknown } | undefined {
  const authorizedSeqs = readAuthorizedTranscriptEventSeqs(database.db, scope.sessionId);
  if (authorizedSeqs && !authorizedSeqs.has(identity.seq)) {
    return undefined;
  }
  const db = getSessionKysely(database.db);
  const eventRow = executeSqliteQueryTakeFirstSync(
    database.db,
    db
      .selectFrom("transcript_events")
      .select(["event_json"])
      .where("session_id", "=", scope.sessionId)
      .where("seq", "=", identity.seq),
  );
  if (!eventRow) {
    return undefined;
  }
  const event = JSON.parse(eventRow.event_json) as { message?: unknown };
  return { messageId: identity.eventId, message: event.message };
}

function readTranscriptEventIdentity(event: unknown):
  | {
      eventId: string;
      eventType: string | null;
      parentId: string | null;
      messageIdempotencyKey: string | null;
    }
  | undefined {
  if (!event || typeof event !== "object" || Array.isArray(event)) {
    return undefined;
  }
  const record = event as Record<string, unknown>;
  const eventId = typeof record.id === "string" && record.id.trim() ? record.id.trim() : undefined;
  return eventId
    ? {
        eventId,
        eventType: typeof record.type === "string" ? record.type : null,
        parentId: typeof record.parentId === "string" ? record.parentId : null,
        messageIdempotencyKey: readMessageIdempotencyKey(record.message),
      }
    : undefined;
}

function canonicalizeTranscriptEventMedia(event: TranscriptEvent): TranscriptEvent {
  if (!event || typeof event !== "object" || Array.isArray(event)) {
    return event;
  }
  const record = event as Record<string, unknown>;
  const message = record.message;
  if (
    record.type !== "message" ||
    !message ||
    typeof message !== "object" ||
    Array.isArray(message)
  ) {
    return event;
  }
  const canonical = canonicalizePersistedUserMessageMedia(message);
  return canonical.changed ? { ...record, message: canonical.message } : event;
}

export function readMessageIdempotencyKey(message: unknown): string | null {
  if (!message || typeof message !== "object" || Array.isArray(message)) {
    return null;
  }
  const value = (message as { idempotencyKey?: unknown }).idempotencyKey;
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function readEventTimestamp(event: unknown): number | undefined {
  if (!event || typeof event !== "object" || Array.isArray(event)) {
    return undefined;
  }
  const value = (event as { timestamp?: unknown }).timestamp;
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value !== "string" || !value.trim()) {
    return undefined;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

export function redactTranscriptMessageForStorage<TMessage>(
  message: TMessage,
  options: Pick<TranscriptMessageAppendOptions<TMessage>, "config">,
): TMessage {
  return isTranscriptAgentMessage(message)
    ? (redactTranscriptMessage(message, options.config) as TMessage)
    : redactSecrets(message);
}

function isTranscriptAgentMessage(value: unknown): value is AgentMessage {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    typeof (value as { role?: unknown }).role === "string"
  );
}
