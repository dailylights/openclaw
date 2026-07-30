import {
  openOpenClawAgentDatabase,
  runOpenClawAgentWriteTransaction,
} from "../../state/openclaw-agent-db.js";
import type { OpenClawStateDatabaseOptions } from "../../state/openclaw-state-db.js";
import { resolveSqliteScope, toDatabaseOptions } from "./session-accessor.sqlite-scope.js";
import type { SessionAccessScope } from "./session-accessor.types.js";
import {
  readOrCreateSessionMemorySubjectInTransaction,
  readSessionMemorySubjectFromDatabase,
  resolveSessionMemorySubjectAuthority,
  SessionMemorySubjectReboundError,
  type SessionMemorySubjectAuthority,
  type TrustedSessionMemorySubjectSnapshot,
} from "./session-memory-subject.js";

/** Reads the canonical subject, lazily backfilling an explicit ambiguous row for old sessions. */
export function readCurrentSessionMemorySubject(
  scope: SessionAccessScope,
): TrustedSessionMemorySubjectSnapshot | undefined {
  const resolved = resolveSqliteScope(scope);
  const options = toDatabaseOptions(resolved);
  const database = openOpenClawAgentDatabase(options);
  const existing = readSessionMemorySubjectFromDatabase(database, resolved.sessionKey);
  if (existing) {
    return existing;
  }
  return runOpenClawAgentWriteTransaction(
    (transactionDb) =>
      readOrCreateSessionMemorySubjectInTransaction(transactionDb, resolved.sessionKey),
    options,
    { operationLabel: "session.memory-subject.backfill" },
  );
}

/**
 * Rechecks shared identity evidence without holding an agent transaction, then
 * rereads the agent mapping and identity authority so either database changing
 * across the check fails closed.
 */
export function readCurrentSessionMemorySubjectAuthority(
  scope: SessionAccessScope,
  stateOptions: OpenClawStateDatabaseOptions = {},
  now = Date.now(),
):
  | Readonly<{
      snapshot: TrustedSessionMemorySubjectSnapshot;
      authority: SessionMemorySubjectAuthority;
    }>
  | undefined {
  const snapshot = readCurrentSessionMemorySubject(scope);
  if (!snapshot) {
    return undefined;
  }
  resolveSessionMemorySubjectAuthority(snapshot, stateOptions, now);
  const current = readCurrentSessionMemorySubject(scope);
  if (
    !current ||
    current.sessionId !== snapshot.sessionId ||
    current.sessionIdentityRevision !== snapshot.sessionIdentityRevision ||
    current.subjectRevision !== snapshot.subjectRevision
  ) {
    throw new SessionMemorySubjectReboundError(snapshot.sessionId);
  }
  const authority = resolveSessionMemorySubjectAuthority(current, stateOptions, now);
  return { snapshot: current, authority };
}
