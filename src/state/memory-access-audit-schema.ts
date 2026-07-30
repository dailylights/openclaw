import type { DatabaseSync } from "node:sqlite";
import { executeSqliteQuerySync, getNodeSqliteKysely } from "../infra/kysely-sync.js";
import { runSqliteImmediateTransactionSync } from "../infra/sqlite-transaction.js";
import { runOpenClawStateWriteTransaction } from "./openclaw-state-db.js";
import { OPENCLAW_STATE_SCHEMA_SQL } from "./openclaw-state-schema.generated.js";

const MEMORY_ACCESS_AUDIT_SCHEMA_START = "CREATE TABLE IF NOT EXISTS memory_access_audit (";
const MEMORY_ACCESS_AUDIT_SCHEMA_END = "CREATE TABLE IF NOT EXISTS session_state_events (";
const ensuredDatabases = new WeakSet<DatabaseSync>();

function extractMemoryAccessAuditSchema(): string {
  const start = OPENCLAW_STATE_SCHEMA_SQL.indexOf(MEMORY_ACCESS_AUDIT_SCHEMA_START);
  const end = OPENCLAW_STATE_SCHEMA_SQL.indexOf(MEMORY_ACCESS_AUDIT_SCHEMA_END, start);
  if (start < 0 || end <= start) {
    throw new Error("canonical memory access audit schema markers are missing");
  }
  return OPENCLAW_STATE_SCHEMA_SQL.slice(start, end).trim();
}

/** Canonical lazy shared schema for redacted multiplayer-memory audit delivery. */
export const MEMORY_ACCESS_AUDIT_SCHEMA_SQL = extractMemoryAccessAuditSchema();

export type MemoryAccessAuditEntry = Readonly<{
  eventId: string;
  agentId: string;
  requestId: string;
  runId: string;
  actorRef: string;
  subjectRef: string;
  operation: string;
  decision: "committed" | "quarantined" | "tombstoned";
  reasonCode: string;
  resourceRevisionId: string | null;
  contentHash: string | null;
  occurredAt: number;
  receivedAt: number;
}>;

type MemoryAccessAuditDatabase = {
  memory_access_audit: {
    event_id: string;
    agent_id: string;
    request_id: string;
    run_id: string;
    actor_ref: string;
    subject_ref: string;
    operation: string;
    decision: "committed" | "quarantined" | "tombstoned";
    reason_code: string;
    resource_revision_id: string | null;
    content_hash: string | null;
    occurred_at: number;
    received_at: number;
  };
};

/** Install the idempotent audit sink only when a scoped-memory writer needs it. */
export function ensureMemoryAccessAuditSchema(db: DatabaseSync): void {
  if (ensuredDatabases.has(db)) {
    return;
  }
  const ensure = () => {
    db.exec(MEMORY_ACCESS_AUDIT_SCHEMA_SQL); // sqlite-allow-raw -- Canonical additive DDL only.
  };
  if (db.isTransaction) {
    ensure();
    ensuredDatabases.add(db);
    return;
  }
  runSqliteImmediateTransactionSync(db, ensure);
  ensuredDatabases.add(db);
}

/** Idempotently drains one redacted plugin-local audit event into shared state. */
export function writeMemoryAccessAudit(entry: MemoryAccessAuditEntry): void {
  runOpenClawStateWriteTransaction(
    ({ db: database }) => {
      ensureMemoryAccessAuditSchema(database);
      const db = getNodeSqliteKysely<MemoryAccessAuditDatabase>(database);
      executeSqliteQuerySync(
        database,
        db
          .insertInto("memory_access_audit")
          .values({
            event_id: entry.eventId,
            agent_id: entry.agentId,
            request_id: entry.requestId,
            run_id: entry.runId,
            actor_ref: entry.actorRef,
            subject_ref: entry.subjectRef,
            operation: entry.operation,
            decision: entry.decision,
            reason_code: entry.reasonCode,
            resource_revision_id: entry.resourceRevisionId,
            content_hash: entry.contentHash,
            occurred_at: entry.occurredAt,
            received_at: entry.receivedAt,
          })
          .onConflict((conflict) => conflict.column("event_id").doNothing()),
      );
    },
    {},
    { operationLabel: "memory-audit.outbox.drain" },
  );
}
