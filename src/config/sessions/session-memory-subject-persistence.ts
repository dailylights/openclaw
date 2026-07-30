import type { DatabaseSync } from "node:sqlite";
import type { Selectable } from "kysely";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
} from "../../infra/kysely-sync.js";
import { generateSecureUuid } from "../../infra/secure-random.js";
import type { SessionMemorySubject } from "../../memory-host-sdk/host/authorization.js";
import type { DB as OpenClawAgentKyselyDatabase } from "../../state/openclaw-agent-db.generated.js";
import type { OpenClawAgentDatabase } from "../../state/openclaw-agent-db.js";
import { AGENT_SESSION_MEMORY_SCHEMA_SQL } from "../../state/openclaw-agent-session-memory-schema.js";
import { tableExists } from "../../state/openclaw-state-db-schema-helpers.js";
import {
  createTrustedSessionMemorySubjectSeed,
  createTrustedSessionMemorySubjectSnapshot,
  InvalidSessionMemorySubjectSeedError,
  isTrustedSessionMemorySubjectSeed,
  prepareSessionMemorySubjectLineageSeed,
  requireSessionMemorySubjectText,
  SessionMemorySubjectReboundError,
  type SessionMemoryScope,
  type TrustedSessionMemorySubjectSeed,
  type TrustedSessionMemorySubjectSnapshot,
} from "./session-memory-subject-trust.js";

type SessionMemoryDatabase = Pick<
  OpenClawAgentKyselyDatabase,
  | "session_memory_subject_snapshots"
  | "session_memory_subjects"
  | "session_nodes"
  | "session_windows"
>;
type SessionMemorySubjectRow = Selectable<SessionMemoryDatabase["session_memory_subjects"]>;

const ensuredDatabases = new WeakSet<DatabaseSync>();

function sessionMemoryDb(db: DatabaseSync) {
  return getNodeSqliteKysely<SessionMemoryDatabase>(db);
}

function ensureSessionMemorySubjectSchema(database: OpenClawAgentDatabase): void {
  if (ensuredDatabases.has(database.db)) {
    return;
  }
  const alreadyPresent =
    tableExists(database.db, "session_memory_subjects") &&
    tableExists(database.db, "session_memory_subject_snapshots");
  if (alreadyPresent) {
    ensuredDatabases.add(database.db);
    return;
  }
  database.db.exec(AGENT_SESSION_MEMORY_SCHEMA_SQL); // sqlite-allow-raw -- Additive canonical DDL only.
  // DDL inside a larger session mutation rolls back with that mutation. Mark it
  // only when this call owns an autocommit boundary; the next successful write
  // observes both tables and then caches the committed ensure.
  if (!database.db.isTransaction) {
    ensuredDatabases.add(database.db);
  }
}

function subjectFromRow(row: SessionMemorySubjectRow): SessionMemorySubject {
  switch (row.subject_kind) {
    case "user":
      if (!row.principal_id || !row.creation_evidence_kind || !row.creation_evidence_revision) {
        break;
      }
      return {
        version: 1,
        kind: "user",
        principalId: row.principal_id,
        creationEvidence: {
          kind: row.creation_evidence_kind as Extract<
            SessionMemorySubject,
            { kind: "user" }
          >["creationEvidence"]["kind"],
          revision: row.creation_evidence_revision,
        },
      };
    case "conversation":
      if (!row.conversation_principal_id || !row.channel || !row.account_id) {
        break;
      }
      return {
        version: 1,
        kind: "conversation",
        conversationPrincipalId: row.conversation_principal_id,
        channel: row.channel,
        accountId: row.account_id,
      };
    case "service":
    case "agent":
    case "system":
      if (!row.principal_id) {
        break;
      }
      return { version: 1, kind: row.subject_kind, principalId: row.principal_id };
    case "ambiguous":
      if (!row.ambiguous_reason) {
        break;
      }
      return {
        version: 1,
        kind: "ambiguous",
        reason: row.ambiguous_reason as Extract<
          SessionMemorySubject,
          { kind: "ambiguous" }
        >["reason"],
      };
  }
  throw new Error(`corrupt session memory subject row: ${row.session_key}`);
}

function subjectValues(params: {
  sessionKey: string;
  seed: TrustedSessionMemorySubjectSeed;
  createdAt: number;
}): SessionMemoryDatabase["session_memory_subjects"] {
  const { subject } = params.seed;
  return {
    session_key: params.sessionKey,
    subject_revision: params.seed.subjectRevision,
    subject_kind: subject.kind,
    principal_id:
      subject.kind === "user" ||
      subject.kind === "service" ||
      subject.kind === "agent" ||
      subject.kind === "system"
        ? subject.principalId
        : null,
    conversation_principal_id:
      subject.kind === "conversation" ? subject.conversationPrincipalId : null,
    channel: subject.kind === "conversation" ? subject.channel : null,
    account_id: subject.kind === "conversation" ? subject.accountId : null,
    ambiguous_reason: subject.kind === "ambiguous" ? subject.reason : null,
    creation_evidence_kind: subject.kind === "user" ? subject.creationEvidence.kind : null,
    creation_evidence_revision: subject.kind === "user" ? subject.creationEvidence.revision : null,
    creation_binding_id: params.seed.creationBindingId ?? null,
    canonical_conversation_ref: params.seed.canonicalConversationRef ?? null,
    created_at: params.createdAt,
  };
}

function readSubjectRow(
  database: OpenClawAgentDatabase,
  sessionKey: string,
): SessionMemorySubjectRow | undefined {
  ensureSessionMemorySubjectSchema(database);
  return executeSqliteQueryTakeFirstSync(
    database.db,
    sessionMemoryDb(database.db)
      .selectFrom("session_memory_subjects")
      .selectAll()
      .where("session_key", "=", sessionKey),
  );
}

function assertEquivalentSubjectRows(
  target: SessionMemorySubjectRow,
  source: SessionMemorySubjectRow,
): void {
  if (!sessionMemorySubjectRowsEqual(target, source)) {
    throw new Error("conflicting immutable session memory subjects during alias rehome");
  }
}

function sessionMemorySubjectRowsEqual(
  left: SessionMemorySubjectRow,
  right: SessionMemorySubjectRow,
): boolean {
  const comparable = (row: SessionMemorySubjectRow) => ({
    subject_revision: row.subject_revision,
    subject_kind: row.subject_kind,
    principal_id: row.principal_id,
    conversation_principal_id: row.conversation_principal_id,
    channel: row.channel,
    account_id: row.account_id,
    ambiguous_reason: row.ambiguous_reason,
    creation_evidence_kind: row.creation_evidence_kind,
    creation_evidence_revision: row.creation_evidence_revision,
    creation_binding_id: row.creation_binding_id,
    canonical_conversation_ref: row.canonical_conversation_ref,
  });
  return JSON.stringify(comparable(left)) === JSON.stringify(comparable(right));
}

/** Rehomes exact alias provenance after the canonical node exists and before its snapshot write. */
export function rehomeSessionMemorySubjectAliases(
  database: OpenClawAgentDatabase,
  targetSessionKey: string,
  sourceSessionKeys: Iterable<string>,
): void {
  ensureSessionMemorySubjectSchema(database);
  const targetKey = requireSessionMemorySubjectText(targetSessionKey, "targetSessionKey");
  const sourceKeys = [...new Set([...sourceSessionKeys].map((key) => key.trim()))].filter(
    (key) => key && key !== targetKey,
  );
  if (sourceKeys.length === 0) {
    return;
  }
  const db = sessionMemoryDb(database.db);
  const sources = executeSqliteQuerySync(
    database.db,
    db.selectFrom("session_memory_subjects").selectAll().where("session_key", "in", sourceKeys),
  ).rows;
  if (sources.length === 0) {
    return;
  }
  let target = readSubjectRow(database, targetKey);
  const source = sources[0];
  if (!source) {
    return;
  }
  if (!target) {
    executeSqliteQuerySync(
      database.db,
      db.insertInto("session_memory_subjects").values({
        ...source,
        session_key: targetKey,
      }),
    );
    target = readSubjectRow(database, targetKey);
  }
  if (!target) {
    throw new Error("canonical session memory subject could not be rehomed");
  }
  for (const candidate of sources) {
    assertEquivalentSubjectRows(target, candidate);
  }
  const snapshots = executeSqliteQuerySync(
    database.db,
    db
      .selectFrom("session_memory_subject_snapshots")
      .select(["session_id", "session_key", "subject_revision"])
      .where("session_key", "in", sourceKeys),
  ).rows;
  for (const snapshot of snapshots) {
    if (snapshot.subject_revision !== target.subject_revision) {
      throw new SessionMemorySubjectReboundError(snapshot.session_id);
    }
    executeSqliteQuerySync(
      database.db,
      db
        .updateTable("session_memory_subject_snapshots")
        .set({ session_key: targetKey })
        .where("session_id", "=", snapshot.session_id)
        .where("session_key", "=", snapshot.session_key),
    );
  }
}

/**
 * Moves one retained window snapshot only when the destination logical session
 * has the same immutable subject. A mismatch keeps the source tombstone alive.
 */
export function tryRehomeSessionMemorySubjectSnapshot(params: {
  database: OpenClawAgentDatabase;
  sessionId: string;
  sourceSessionKey: string;
  targetSessionKey: string;
}): boolean {
  const { database } = params;
  ensureSessionMemorySubjectSchema(database);
  const sessionId = requireSessionMemorySubjectText(params.sessionId, "sessionId");
  const sourceSessionKey = requireSessionMemorySubjectText(
    params.sourceSessionKey,
    "sourceSessionKey",
  );
  const targetSessionKey = requireSessionMemorySubjectText(
    params.targetSessionKey,
    "targetSessionKey",
  );
  if (sourceSessionKey === targetSessionKey) {
    return true;
  }
  const db = sessionMemoryDb(database.db);
  const sourceWindow = executeSqliteQueryTakeFirstSync(
    database.db,
    db
      .selectFrom("session_windows")
      .select(["session_key", "session_scope"])
      .where("session_id", "=", sessionId),
  );
  if (!sourceWindow || sourceWindow.session_key !== sourceSessionKey) {
    throw new SessionMemorySubjectReboundError(sessionId);
  }
  persistSessionMemorySubjectInTransaction({
    database,
    sessionKey: sourceSessionKey,
    sessionId,
    sessionScope: sourceWindow.session_scope as SessionMemoryScope,
  });
  const source = readSubjectRow(database, sourceSessionKey);
  if (!source) {
    throw new Error("retained session memory subject could not be materialized");
  }
  let target = readSubjectRow(database, targetSessionKey);
  if (!target) {
    // A cross-key reference alone is not proof of lineage. Legacy/imported
    // destinations backfill as ambiguous instead of inheriting private authority.
    readOrCreateSessionMemorySubjectInTransaction(database, targetSessionKey);
    target = readSubjectRow(database, targetSessionKey);
  }
  if (!target) {
    throw new Error("retained session memory subject destination could not be materialized");
  }
  if (!sessionMemorySubjectRowsEqual(target, source)) {
    return false;
  }
  const snapshot = executeSqliteQueryTakeFirstSync(
    database.db,
    db
      .selectFrom("session_memory_subject_snapshots")
      .select(["session_key", "subject_revision"])
      .where("session_id", "=", sessionId),
  );
  if (
    !snapshot ||
    snapshot.session_key !== sourceSessionKey ||
    snapshot.subject_revision !== source.subject_revision
  ) {
    throw new SessionMemorySubjectReboundError(sessionId);
  }
  executeSqliteQuerySync(
    database.db,
    db
      .updateTable("session_memory_subject_snapshots")
      .set({ session_key: targetSessionKey })
      .where("session_id", "=", sessionId)
      .where("session_key", "=", sourceSessionKey),
  );
  return true;
}

export function persistSessionMemorySubjectInTransaction(params: {
  database: OpenClawAgentDatabase;
  sessionKey: string;
  sessionId: string;
  sessionScope: SessionMemoryScope;
  seed?: TrustedSessionMemorySubjectSeed;
  aliasSourceSessionKeys?: Iterable<string>;
  now?: number;
}): TrustedSessionMemorySubjectSnapshot | undefined {
  const { database } = params;
  ensureSessionMemorySubjectSchema(database);
  if (params.seed !== undefined && !isTrustedSessionMemorySubjectSeed(params.seed)) {
    throw new InvalidSessionMemorySubjectSeedError();
  }
  const sessionKey = requireSessionMemorySubjectText(params.sessionKey, "sessionKey");
  const sessionId = params.sessionId.trim();
  if (params.aliasSourceSessionKeys) {
    rehomeSessionMemorySubjectAliases(database, sessionKey, params.aliasSourceSessionKeys);
  }
  const db = sessionMemoryDb(database.db);
  let snapshot = sessionId
    ? executeSqliteQueryTakeFirstSync(
        database.db,
        db
          .selectFrom("session_memory_subject_snapshots")
          .selectAll()
          .where("session_id", "=", sessionId),
      )
    : undefined;
  let row = readSubjectRow(database, sessionKey);
  if (!row) {
    const aliasSubject = snapshot ? readSubjectRow(database, snapshot.session_key) : undefined;
    const canPreserveAmbiguousAlias =
      params.seed === undefined &&
      aliasSubject?.subject_kind === "ambiguous" &&
      (params.sessionScope !== "shared-main" || aliasSubject.ambiguous_reason === "shared-main");
    if (canPreserveAmbiguousAlias) {
      // Legacy aliases can share a transcript ID without proving private lineage.
      // Preserve only an already-denied subject; never inherit user authority here.
      executeSqliteQuerySync(
        database.db,
        db.insertInto("session_memory_subjects").values({
          ...aliasSubject,
          session_key: sessionKey,
        }),
      );
    } else {
      const seed =
        params.sessionScope === "shared-main"
          ? createTrustedSessionMemorySubjectSeed({
              subject: { version: 1, kind: "ambiguous", reason: "shared-main" },
            })
          : (params.seed ??
            createTrustedSessionMemorySubjectSeed({
              subject: { version: 1, kind: "ambiguous", reason: "unbound" },
            }));
      executeSqliteQuerySync(
        database.db,
        db
          .insertInto("session_memory_subjects")
          .values(subjectValues({ sessionKey, seed, createdAt: params.now ?? Date.now() })),
      );
    }
    row = readSubjectRow(database, sessionKey);
  }
  if (!row) {
    throw new Error("session memory subject could not be persisted");
  }
  // Empty IDs are durable placeholder entries, not transcript windows. Keep
  // their logical subject write-once, but deny access until an ID materializes.
  if (!sessionId) {
    return undefined;
  }
  if (snapshot) {
    const snapshotSubject = readSubjectRow(database, snapshot.session_key);
    if (
      !snapshotSubject ||
      snapshot.subject_revision !== row.subject_revision ||
      !sessionMemorySubjectRowsEqual(snapshotSubject, row)
    ) {
      throw new SessionMemorySubjectReboundError(sessionId);
    }
    if (snapshot.session_key !== sessionKey) {
      // session_windows already moved the canonical alias owner. Keep the
      // audit snapshot attached to that owner without changing its identity.
      executeSqliteQuerySync(
        database.db,
        db
          .updateTable("session_memory_subject_snapshots")
          .set({ session_key: sessionKey })
          .where("session_id", "=", sessionId)
          .where("session_key", "=", snapshot.session_key),
      );
      snapshot = { ...snapshot, session_key: sessionKey };
    }
  } else {
    executeSqliteQuerySync(
      database.db,
      db.insertInto("session_memory_subject_snapshots").values({
        session_id: sessionId,
        session_key: sessionKey,
        subject_revision: row.subject_revision,
        session_identity_revision: generateSecureUuid(),
        created_at: params.now ?? Date.now(),
      }),
    );
    snapshot = executeSqliteQueryTakeFirstSync(
      database.db,
      db
        .selectFrom("session_memory_subject_snapshots")
        .selectAll()
        .where("session_id", "=", sessionId),
    );
  }
  if (!snapshot) {
    throw new Error("session memory subject snapshot could not be persisted");
  }
  return createTrustedSessionMemorySubjectSnapshot({
    sessionKey,
    sessionId,
    sessionScope: params.sessionScope,
    sessionIdentityRevision: snapshot.session_identity_revision,
    subjectRevision: row.subject_revision,
    subject: subjectFromRow(row),
    ...(row.creation_binding_id ? { creationBindingId: row.creation_binding_id } : {}),
    ...(row.canonical_conversation_ref
      ? { canonicalConversationRef: row.canonical_conversation_ref }
      : {}),
  });
}

export function readSessionMemorySubjectFromDatabase(
  database: OpenClawAgentDatabase,
  sessionKey: string,
): TrustedSessionMemorySubjectSnapshot | undefined {
  ensureSessionMemorySubjectSchema(database);
  const key = requireSessionMemorySubjectText(sessionKey, "sessionKey");
  const row = executeSqliteQueryTakeFirstSync(
    database.db,
    sessionMemoryDb(database.db)
      .selectFrom("session_nodes as node")
      .innerJoin("session_windows as window", "window.session_id", "node.current_session_id")
      .innerJoin("session_memory_subjects as subject", "subject.session_key", "node.session_key")
      .innerJoin(
        "session_memory_subject_snapshots as snapshot",
        "snapshot.session_id",
        "node.current_session_id",
      )
      .select([
        "node.session_key as session_key",
        "node.current_session_id as session_id",
        "window.session_scope as session_scope",
        "snapshot.session_identity_revision as session_identity_revision",
        "snapshot.subject_revision as snapshot_subject_revision",
        "subject.subject_revision as subject_revision",
        "subject.subject_kind as subject_kind",
        "subject.principal_id as principal_id",
        "subject.conversation_principal_id as conversation_principal_id",
        "subject.channel as channel",
        "subject.account_id as account_id",
        "subject.ambiguous_reason as ambiguous_reason",
        "subject.creation_evidence_kind as creation_evidence_kind",
        "subject.creation_evidence_revision as creation_evidence_revision",
        "subject.creation_binding_id as creation_binding_id",
        "subject.canonical_conversation_ref as canonical_conversation_ref",
        "subject.created_at as created_at",
      ])
      .where("node.session_key", "=", key)
      // Alias nodes share one transcript window. The snapshot follows that
      // window's canonical owner while each alias must retain its revision.
      .whereRef("snapshot.session_key", "=", "window.session_key"),
  );
  if (!row) {
    return undefined;
  }
  if (row.snapshot_subject_revision !== row.subject_revision) {
    throw new SessionMemorySubjectReboundError(row.session_id);
  }
  const subjectRow: SessionMemorySubjectRow = {
    session_key: row.session_key,
    subject_revision: row.subject_revision,
    subject_kind: row.subject_kind,
    principal_id: row.principal_id,
    conversation_principal_id: row.conversation_principal_id,
    channel: row.channel,
    account_id: row.account_id,
    ambiguous_reason: row.ambiguous_reason,
    creation_evidence_kind: row.creation_evidence_kind,
    creation_evidence_revision: row.creation_evidence_revision,
    creation_binding_id: row.creation_binding_id,
    canonical_conversation_ref: row.canonical_conversation_ref,
    created_at: row.created_at,
  };
  return createTrustedSessionMemorySubjectSnapshot({
    sessionKey: row.session_key,
    sessionId: row.session_id,
    sessionScope: row.session_scope as SessionMemoryScope,
    sessionIdentityRevision: row.session_identity_revision,
    subjectRevision: row.subject_revision,
    subject: subjectFromRow(subjectRow),
    ...(row.creation_binding_id ? { creationBindingId: row.creation_binding_id } : {}),
    ...(row.canonical_conversation_ref
      ? { canonicalConversationRef: row.canonical_conversation_ref }
      : {}),
  });
}

export function readOrCreateSessionMemorySubjectInTransaction(
  database: OpenClawAgentDatabase,
  sessionKey: string,
): TrustedSessionMemorySubjectSnapshot | undefined {
  const current = readSessionMemorySubjectFromDatabase(database, sessionKey);
  if (current) {
    return current;
  }
  const identity = executeSqliteQueryTakeFirstSync(
    database.db,
    sessionMemoryDb(database.db)
      .selectFrom("session_nodes as node")
      .innerJoin("session_windows as window", "window.session_id", "node.current_session_id")
      .select([
        "node.session_key as session_key",
        "node.current_session_id as session_id",
        "window.session_scope as session_scope",
      ])
      .where("node.session_key", "=", requireSessionMemorySubjectText(sessionKey, "sessionKey")),
  );
  return identity
    ? persistSessionMemorySubjectInTransaction({
        database,
        sessionKey: identity.session_key,
        sessionId: identity.session_id,
        sessionScope: identity.session_scope as SessionMemoryScope,
      })
    : undefined;
}

/** Captures exact persisted lineage while the caller owns the source agent transaction. */
export function prepareCurrentSessionMemorySubjectLineageSeedInTransaction(
  database: OpenClawAgentDatabase,
  sessionKey: string,
): TrustedSessionMemorySubjectSeed | undefined {
  const snapshot = readOrCreateSessionMemorySubjectInTransaction(database, sessionKey);
  return snapshot ? prepareSessionMemorySubjectLineageSeed(snapshot) : undefined;
}
