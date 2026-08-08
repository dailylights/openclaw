import { createHash } from "node:crypto";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
} from "../../infra/kysely-sync.js";
import type { OpenClawAgentDatabase } from "../../state/openclaw-agent-db.js";
import type { TranscriptEvent } from "./session-accessor.sqlite-contract.js";
import { getSessionKysely, type ResolvedTranscriptScope } from "./session-accessor.sqlite-scope.js";
import {
  appendTranscriptEventRowInTransaction,
  canonicalizeTranscriptEventMedia,
  readCompactionEventId,
  readCompactionSourceEventSeqs,
  readEventTimestamp,
  readTranscriptEventIdentity,
  readTranscriptIdentityByEventId,
  readTranscriptIdentityByMessageIdempotencyKey,
  scheduleTranscriptProjectionReconcile,
} from "./session-accessor.sqlite-transcript-events.js";
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
  rebuildTranscriptCompactionPoliciesInTransaction,
  restoreTranscriptMemoryPolicyInTransaction,
  isTranscriptMemoryPolicyEnforcedInDatabase,
  type PreservedTranscriptMemoryPolicy,
  type TranscriptMemoryPolicyTransitionKind,
} from "./session-transcript-memory-policy.js";
import { createSessionTranscriptHeader } from "./transcript-header.js";

export {
  readActiveTranscriptAppendParentId,
  readMessageIdempotencyKey,
  readTranscriptIdentityByEventId,
  readTranscriptMessageByEventId,
  readTranscriptMessageByScopedIdempotencyKey,
  redactTranscriptMessageForStorage,
} from "./session-accessor.sqlite-transcript-events.js";

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
  const memoryPolicyEnforced = isTranscriptMemoryPolicyEnforcedInDatabase(database.db);
  const compactionId = readCompactionEventId(persistedEvent);
  // A newly appended pending import must not reuse an orphaned binding from a
  // previous partial target. Retries return above before this can clear valid state.
  if (memoryPolicyEnforced && options.forceMemoryPolicyPending === true && compactionId) {
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
  if (
    memoryPolicyEnforced &&
    memoryPolicyAuthorized &&
    compactionId &&
    options.forceMemoryPolicyPending !== true
  ) {
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
    ensureTranscriptSessionRoot(
      database,
      resolved,
      readEventTimestamp(events[0]) ?? Date.now(),
      options.memorySubjectSeed ? { memorySubjectSeed: options.memorySubjectSeed } : {},
    );
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
