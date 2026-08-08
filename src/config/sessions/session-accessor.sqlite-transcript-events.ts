// Event storage owns canonical payloads, identities, and projection scheduling.
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
import { indexAppendedTranscriptEventInTransaction } from "./session-transcript-index.js";
import {
  readAuthorizedTranscriptEventSeqs,
  recordTranscriptMemoryPolicyInTransaction,
  restoreTranscriptMemoryPolicyInTransaction,
  type PreservedTranscriptMemoryPolicy,
} from "./session-transcript-memory-policy.js";
import { startSessionTranscriptIndexReconcile } from "./session-transcript-reconcile.js";
import {
  isSessionTranscriptLeafControl,
  parseSessionTranscriptTreeEntry,
} from "./transcript-tree.js";
import { resolveVisibleTranscriptAppendParentId } from "./transcript-visible-events.js";

export function scheduleTranscriptProjectionReconcile(
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

export function readCompactionEventId(event: TranscriptEvent): string | undefined {
  if (!event || typeof event !== "object" || Array.isArray(event)) {
    return undefined;
  }
  const { id, type } = event as { id?: unknown; type?: unknown };
  return type === "compaction" && typeof id === "string" && id.trim() ? id : undefined;
}

export function readCompactionSourceEventSeqs(params: {
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

export function appendTranscriptEventRowInTransaction(
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

export function readTranscriptIdentityByMessageIdempotencyKey(
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

export function readTranscriptEventIdentity(event: unknown):
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

export function canonicalizeTranscriptEventMedia(event: TranscriptEvent): TranscriptEvent {
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

export function readEventTimestamp(event: unknown): number | undefined {
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
