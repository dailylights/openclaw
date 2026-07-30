import { sql } from "kysely";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
} from "../../infra/kysely-sync.js";
import { runSqliteDeferredTransactionSync } from "../../infra/sqlite-transaction.js";
import { openOpenClawAgentDatabase } from "../../state/openclaw-agent-db.js";
import type {
  SessionTranscriptRawDeltaLimits,
  SessionTranscriptRawDeltaResult,
  SessionTranscriptReadScope,
  TranscriptEvent,
} from "./session-accessor.sqlite-contract.js";
import { normalizeSqliteNumber } from "./session-accessor.sqlite-normalize.js";
import {
  getSessionKysely,
  resolveSqliteTranscriptReadScope,
  toDatabaseOptions,
} from "./session-accessor.sqlite-scope.js";
import {
  resolveSqliteSessionTranscriptReadFence,
  SessionTranscriptReadFenceError,
} from "./session-transcript-read-fence.js";
import { readAuthorizedTranscriptEventSeqs } from "./session-transcript-memory-policy.js";

const RAW_TRANSCRIPT_CURSOR_VERSION = 1;
const ENFORCED_TRANSCRIPT_CURSOR_VERSION = 2;
const DEFAULT_RAW_TRANSCRIPT_MAX_EVENTS = 1_000;
const DEFAULT_RAW_TRANSCRIPT_MAX_BYTES = 1_000_000;
const MAX_RAW_TRANSCRIPT_EVENTS = 10_000;
const MAX_RAW_TRANSCRIPT_BYTES = 64 * 1024 * 1024;

type RawTranscriptCursor = {
  agentId: string;
  generation: string;
  lastSeq: number;
  sessionId: string;
  version: typeof RAW_TRANSCRIPT_CURSOR_VERSION;
};

type EnforcedTranscriptCursor = {
  agentId: string;
  generation: string;
  lastAuthorizedOrdinal: number;
  sessionId: string;
  version: typeof ENFORCED_TRANSCRIPT_CURSOR_VERSION;
};

type ResolvedTranscriptReadScope = ReturnType<typeof resolveSqliteTranscriptReadScope>;

function normalizeRawDeltaLimit(
  value: number | undefined,
  fallback: number,
  maximum: number,
  name: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isInteger(resolved) || resolved < 1 || resolved > maximum) {
    throw new RangeError(`${name} must be an integer between 1 and ${String(maximum)}`);
  }
  return resolved;
}

function encodeRawTranscriptCursor(cursor: RawTranscriptCursor): string {
  return Buffer.from(JSON.stringify(cursor), "utf8").toString("base64url");
}

function parseRawTranscriptCursor(value: string): RawTranscriptCursor | undefined {
  if (value.length > 4_096) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(
      Buffer.from(value, "base64url").toString("utf8"),
    ) as Partial<RawTranscriptCursor>;
    if (
      parsed.version !== RAW_TRANSCRIPT_CURSOR_VERSION ||
      typeof parsed.agentId !== "string" ||
      typeof parsed.sessionId !== "string" ||
      typeof parsed.generation !== "string" ||
      !Number.isSafeInteger(parsed.lastSeq) ||
      (parsed.lastSeq ?? -2) < -1
    ) {
      return undefined;
    }
    return parsed as RawTranscriptCursor;
  } catch {
    return undefined;
  }
}

function encodeEnforcedTranscriptCursor(cursor: EnforcedTranscriptCursor): string {
  return Buffer.from(JSON.stringify(cursor), "utf8").toString("base64url");
}

function parseEnforcedTranscriptCursor(value: string): EnforcedTranscriptCursor | undefined {
  if (value.length > 4_096) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(
      Buffer.from(value, "base64url").toString("utf8"),
    ) as Partial<EnforcedTranscriptCursor>;
    if (
      parsed.version !== ENFORCED_TRANSCRIPT_CURSOR_VERSION ||
      typeof parsed.agentId !== "string" ||
      typeof parsed.sessionId !== "string" ||
      typeof parsed.generation !== "string" ||
      !Number.isSafeInteger(parsed.lastAuthorizedOrdinal) ||
      (parsed.lastAuthorizedOrdinal ?? -2) < -1
    ) {
      return undefined;
    }
    return parsed as EnforcedTranscriptCursor;
  } catch {
    return undefined;
  }
}

function bootstrapCursor(
  scope: ResolvedTranscriptReadScope,
  generation: string,
): RawTranscriptCursor {
  return {
    agentId: scope.agentId,
    generation,
    lastSeq: -1,
    sessionId: scope.sessionId,
    version: RAW_TRANSCRIPT_CURSOR_VERSION,
  };
}

/** Read one generation-consistent raw transcript page without parsing excluded payload rows. */
export function readSqliteTranscriptRawDelta(
  scope: SessionTranscriptReadScope,
  limits: SessionTranscriptRawDeltaLimits = {},
): SessionTranscriptRawDeltaResult {
  const resolved = resolveSqliteTranscriptReadScope(scope);
  const maxEvents = normalizeRawDeltaLimit(
    limits.maxEvents,
    DEFAULT_RAW_TRANSCRIPT_MAX_EVENTS,
    MAX_RAW_TRANSCRIPT_EVENTS,
    "maxEvents",
  );
  const maxBytes = normalizeRawDeltaLimit(
    limits.maxBytes,
    DEFAULT_RAW_TRANSCRIPT_MAX_BYTES,
    MAX_RAW_TRANSCRIPT_BYTES,
    "maxBytes",
  );
  const database = openOpenClawAgentDatabase(toDatabaseOptions(resolved));
  return runSqliteDeferredTransactionSync(
    database.db,
    () => {
      const beforeEventSeq = resolveSqliteSessionTranscriptReadFence({
        database,
        ...resolved,
      })?.beforeRawSeq;
      return readRawDeltaInTransaction(
        database.db,
        resolved,
        limits.cursor,
        maxEvents,
        maxBytes,
        beforeEventSeq,
      );
    },
    {
      databaseLabel: database.path,
      operationLabel: "session transcript raw delta",
    },
  );
}

function readRawDeltaInTransaction(
  database: import("node:sqlite").DatabaseSync,
  scope: ResolvedTranscriptReadScope,
  encodedCursor: string | undefined,
  maxEvents: number,
  maxBytes: number,
  beforeEventSeq: number | undefined,
): SessionTranscriptRawDeltaResult {
  const db = getSessionKysely(database);
  const authorizedSeqs = readAuthorizedTranscriptEventSeqs(database, scope.sessionId);
  const state = executeSqliteQueryTakeFirstSync(
    database,
    db
      .selectFrom("transcript_rewrite_watermarks")
      .select("generation")
      .where("session_id", "=", scope.sessionId),
  );
  if (!state) {
    return { kind: "missing" };
  }
  if (authorizedSeqs) {
    return readEnforcedRawDeltaInTransaction({
      database,
      scope,
      generation: state.generation,
      authorizedSeqs,
      encodedCursor,
      maxEvents,
      maxBytes,
      beforeEventSeq,
    });
  }

  const initialCursor = bootstrapCursor(scope, state.generation);
  const reset = (
    reason: Extract<SessionTranscriptRawDeltaResult, { kind: "reset" }>["reason"],
  ) => ({
    kind: "reset" as const,
    cursor: encodeRawTranscriptCursor(initialCursor),
    reason,
  });
  const cursor =
    encodedCursor !== undefined ? parseRawTranscriptCursor(encodedCursor) : initialCursor;
  if (!cursor) {
    return reset("invalid_cursor");
  }
  if (cursor.agentId !== scope.agentId || cursor.sessionId !== scope.sessionId) {
    return reset("scope_mismatch");
  }
  if (cursor.generation !== state.generation) {
    return reset("generation_mismatch");
  }
  const frontier = executeSqliteQueryTakeFirstSync(
    database,
    db
      .selectFrom("transcript_events")
      .select("seq")
      .where("session_id", "=", scope.sessionId)
      .orderBy("seq", "desc")
      .limit(1),
  );
  const maxSeq = Math.min(
    frontier ? normalizeSqliteNumber(frontier.seq) : -1,
    beforeEventSeq === undefined ? Number.POSITIVE_INFINITY : beforeEventSeq - 1,
  );
  if (cursor.lastSeq > maxSeq) {
    if (beforeEventSeq !== undefined) {
      throw new SessionTranscriptReadFenceError(
        "Transcript read cursor has crossed the current-turn admission fence",
      );
    }
    return reset("invalid_cursor");
  }

  const metadata = executeSqliteQuerySync(
    database,
    db
      .selectFrom("transcript_events")
      .select([
        "seq",
        /* kysely-allow-raw: SQLite byte length avoids fetching or parsing excluded JSON. */
        sql<number>`LENGTH(CAST(event_json AS BLOB)) + 1`.as("serialized_bytes"),
      ])
      .where("session_id", "=", scope.sessionId)
      .where("seq", ">", cursor.lastSeq)
      .$if(beforeEventSeq !== undefined, (query) => query.where("seq", "<", beforeEventSeq!))
      .orderBy("seq", "asc")
      .limit(maxEvents + 1),
  ).rows.map((row) => ({
    seq: normalizeSqliteNumber(row.seq),
    serializedBytes: normalizeSqliteNumber(row.serialized_bytes),
  }));

  let serializedBytes = 0;
  let selectedCount = 0;
  for (const row of metadata) {
    if (selectedCount >= maxEvents || serializedBytes + row.serializedBytes > maxBytes) {
      break;
    }
    serializedBytes += row.serializedBytes;
    selectedCount += 1;
  }
  const selectedMetadata = metadata.slice(0, selectedCount);
  const lastSeq = selectedMetadata.at(-1)?.seq ?? cursor.lastSeq;
  const rows =
    selectedCount === 0
      ? []
      : executeSqliteQuerySync(
          database,
          db
            .selectFrom("transcript_events")
            .select(["event_json", "seq"])
            .where("session_id", "=", scope.sessionId)
            .where("seq", ">", cursor.lastSeq)
            .where("seq", "<=", lastSeq)
            .orderBy("seq", "asc"),
        ).rows.map((row) => ({
          event: JSON.parse(row.event_json) as TranscriptEvent,
          seq: normalizeSqliteNumber(row.seq),
        }));
  const nextCursor = encodeRawTranscriptCursor({ ...cursor, lastSeq });
  const requiredBytes =
    selectedCount === 0 && metadata[0] ? metadata[0].serializedBytes : undefined;
  return {
    kind: "page",
    cursor: nextCursor,
    events: rows,
    hasMore: selectedCount < metadata.length,
    ...(requiredBytes !== undefined ? { requiredBytes } : {}),
    serializedBytes,
  };
}

function readEnforcedRawDeltaInTransaction(params: {
  database: import("node:sqlite").DatabaseSync;
  scope: ResolvedTranscriptReadScope;
  generation: string;
  authorizedSeqs: ReadonlySet<number>;
  encodedCursor: string | undefined;
  maxEvents: number;
  maxBytes: number;
  beforeEventSeq: number | undefined;
}): SessionTranscriptRawDeltaResult {
  const initialCursor: EnforcedTranscriptCursor = {
    agentId: params.scope.agentId,
    generation: params.generation,
    lastAuthorizedOrdinal: -1,
    sessionId: params.scope.sessionId,
    version: ENFORCED_TRANSCRIPT_CURSOR_VERSION,
  };
  const reset = (
    reason: Extract<SessionTranscriptRawDeltaResult, { kind: "reset" }>["reason"],
  ) => ({
    kind: "reset" as const,
    cursor: encodeEnforcedTranscriptCursor(initialCursor),
    reason,
  });
  const cursor =
    params.encodedCursor === undefined
      ? initialCursor
      : parseEnforcedTranscriptCursor(params.encodedCursor);
  if (!cursor) {
    return reset("invalid_cursor");
  }
  if (cursor.agentId !== params.scope.agentId || cursor.sessionId !== params.scope.sessionId) {
    return reset("scope_mismatch");
  }
  if (cursor.generation !== params.generation) {
    return reset("generation_mismatch");
  }
  const db = getSessionKysely(params.database);
  const authorizedMetadata = executeSqliteQuerySync(
    params.database,
    db
      .selectFrom("transcript_events")
      .select([
        "seq",
        /* kysely-allow-raw: SQLite byte length avoids parsing excluded JSON. */
        sql<number>`LENGTH(CAST(event_json AS BLOB)) + 1`.as("serialized_bytes"),
      ])
      .where("session_id", "=", params.scope.sessionId)
      .orderBy("seq", "asc"),
  )
    .rows.filter(
      (row) =>
        params.authorizedSeqs.has(row.seq) &&
        (params.beforeEventSeq === undefined || row.seq < params.beforeEventSeq),
    )
    .map((row, authorizedOrdinal) => ({
      authorizedOrdinal,
      rawSeq: normalizeSqliteNumber(row.seq),
      serializedBytes: normalizeSqliteNumber(row.serialized_bytes),
    }));
  const maxAuthorizedOrdinal = authorizedMetadata.length - 1;
  if (cursor.lastAuthorizedOrdinal > maxAuthorizedOrdinal) {
    if (params.beforeEventSeq !== undefined) {
      throw new SessionTranscriptReadFenceError(
        "Transcript read cursor has crossed the current-turn admission fence",
      );
    }
    return reset("invalid_cursor");
  }
  const remaining = authorizedMetadata.slice(cursor.lastAuthorizedOrdinal + 1);
  let serializedBytes = 0;
  let selectedCount = 0;
  for (const row of remaining) {
    if (
      selectedCount >= params.maxEvents ||
      serializedBytes + row.serializedBytes > params.maxBytes
    ) {
      break;
    }
    serializedBytes += row.serializedBytes;
    selectedCount += 1;
  }
  const selectedMetadata = remaining.slice(0, selectedCount);
  const denseSeqByRawSeq = new Map(
    selectedMetadata.map((row) => [row.rawSeq, row.authorizedOrdinal] as const),
  );
  const rows =
    selectedMetadata.length === 0
      ? []
      : executeSqliteQuerySync(
          params.database,
          db
            .selectFrom("transcript_events")
            .select(["event_json", "seq"])
            .where("session_id", "=", params.scope.sessionId)
            .where("seq", ">=", selectedMetadata[0]!.rawSeq)
            .where("seq", "<=", selectedMetadata.at(-1)!.rawSeq)
            .orderBy("seq", "asc"),
        ).rows.flatMap((row) => {
          const denseSeq = denseSeqByRawSeq.get(row.seq);
          return denseSeq === undefined
            ? []
            : [{ event: JSON.parse(row.event_json) as TranscriptEvent, seq: denseSeq }];
        });
  const lastAuthorizedOrdinal =
    selectedMetadata.at(-1)?.authorizedOrdinal ?? cursor.lastAuthorizedOrdinal;
  const requiredBytes =
    selectedCount === 0 && remaining[0] ? remaining[0].serializedBytes : undefined;
  return {
    kind: "page",
    cursor: encodeEnforcedTranscriptCursor({ ...cursor, lastAuthorizedOrdinal }),
    events: rows,
    hasMore: selectedCount < remaining.length,
    ...(requiredBytes !== undefined ? { requiredBytes } : {}),
    serializedBytes,
  };
}
