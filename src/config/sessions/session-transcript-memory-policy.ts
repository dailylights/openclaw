import type { DatabaseSync } from "node:sqlite";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
} from "../../infra/kysely-sync.js";
import type { TranscriptMemoryRunExposureSnapshot } from "../../plugins/memory-invocation-receipts.js";
import {
  createEffectiveMemoryPolicySetId,
  parseCanonicalMemoryAudiences,
  parseCanonicalMemoryStringArray,
} from "../../plugins/memory-invocation-serialization.js";
import {
  readCurrentTranscriptMemoryPolicyLabel,
  type TranscriptMemoryPolicyLabel,
} from "../../plugins/memory-transcript-policy-label.js";
import type {
  DB as OpenClawAgentDatabaseSchema,
  MemoryPolicySets,
  MemoryRunExposures,
  SessionMemorySubjectSnapshots,
  TranscriptEventMemoryPolicies,
} from "../../state/openclaw-agent-db.generated.js";
import type { OpenClawAgentDatabase } from "../../state/openclaw-agent-db.js";
import { ensureOpenClawAgentScopedMemorySchema } from "../../state/openclaw-agent-scoped-memory-schema.js";

type TranscriptMemoryPolicyDatabase = Pick<
  OpenClawAgentDatabaseSchema,
  | "memory_migrations"
  | "memory_policy_sets"
  | "memory_run_exposures"
  | "session_memory_subject_snapshots"
  | "transcript_event_memory_policies"
>;

const enforcementByDatabase = new WeakMap<DatabaseSync, boolean>();
const SQLITE_ID_BATCH_SIZE = 400;
type SubjectSnapshotBinding = Pick<
  SessionMemorySubjectSnapshots,
  "session_id" | "session_identity_revision" | "subject_revision"
>;

function matchesPolicySetSnapshot(
  row: MemoryPolicySets,
  snapshot: TranscriptMemoryRunExposureSnapshot,
): boolean {
  return (
    row.policy_set_id === snapshot.effectiveSourcePolicySetId &&
    row.agent_id === snapshot.agentId &&
    row.memory_policy_revision === snapshot.memoryPolicyRevision &&
    row.member_policy_set_ids_json === snapshot.sourcePolicySetIdsJson
  );
}

function matchesRunExposureSnapshot(
  row: MemoryRunExposures,
  snapshot: TranscriptMemoryRunExposureSnapshot,
): boolean {
  return (
    row.exposure_set_id === snapshot.exposureSetId &&
    row.agent_id === snapshot.agentId &&
    row.run_id === snapshot.runId &&
    row.context_fingerprint === snapshot.contextFingerprint &&
    row.plan_id === snapshot.planId &&
    row.revision_number === snapshot.revisionNumber &&
    row.previous_exposure_set_id === (snapshot.previous?.exposureSetId ?? null) &&
    row.source_policy_set_ids_json === snapshot.sourcePolicySetIdsJson &&
    row.effective_source_policy_set_id === snapshot.effectiveSourcePolicySetId &&
    row.exposed_resource_revisions_json === snapshot.exposedResourceRevisionsJson &&
    row.exposure_receipt_ids_json === snapshot.exposureReceiptIdsJson &&
    row.egress_receipt_ids_json === snapshot.egressReceiptIdsJson &&
    row.delivery_audiences_json === snapshot.deliveryAudiencesJson &&
    row.delivery_revision === snapshot.deliveryRevision &&
    row.egress_registry_revision === snapshot.egressRegistryRevision &&
    row.created_at === snapshot.createdAt
  );
}

function isValidRunExposureSnapshot(snapshot: TranscriptMemoryRunExposureSnapshot): boolean {
  const memberPolicySetIds = parseCanonicalMemoryStringArray(snapshot.sourcePolicySetIdsJson);
  return Boolean(
    snapshot.exposureSetId.trim() &&
    snapshot.agentId.trim() &&
    snapshot.runId.trim() &&
    snapshot.contextFingerprint.trim() &&
    snapshot.planId.trim() &&
    snapshot.memoryPolicyRevision.trim() &&
    snapshot.deliveryRevision.trim() &&
    snapshot.egressRegistryRevision.trim() &&
    Number.isSafeInteger(snapshot.revisionNumber) &&
    snapshot.revisionNumber === (snapshot.previous?.revisionNumber ?? 0) + 1 &&
    memberPolicySetIds &&
    parseCanonicalMemoryStringArray(snapshot.exposedResourceRevisionsJson) &&
    parseCanonicalMemoryStringArray(snapshot.exposureReceiptIdsJson) &&
    parseCanonicalMemoryStringArray(snapshot.egressReceiptIdsJson) &&
    parseCanonicalMemoryAudiences(snapshot.deliveryAudiencesJson) &&
    createEffectiveMemoryPolicySetId({
      memoryPolicyRevision: snapshot.memoryPolicyRevision,
      memberPolicySetIds,
    }) === snapshot.effectiveSourcePolicySetId &&
    (!snapshot.previous ||
      (snapshot.previous.agentId === snapshot.agentId &&
        snapshot.previous.runId === snapshot.runId &&
        snapshot.previous.contextFingerprint === snapshot.contextFingerprint &&
        snapshot.previous.planId === snapshot.planId &&
        snapshot.previous.memoryPolicyRevision === snapshot.memoryPolicyRevision &&
        snapshot.previous.deliveryAudiencesJson === snapshot.deliveryAudiencesJson &&
        snapshot.previous.deliveryRevision === snapshot.deliveryRevision &&
        snapshot.previous.egressRegistryRevision === snapshot.egressRegistryRevision)),
  );
}

function persistPolicySetSnapshotInTransaction(params: {
  db: DatabaseSync;
  snapshot: TranscriptMemoryRunExposureSnapshot;
}): boolean {
  const kysely = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(params.db);
  executeSqliteQuerySync(
    params.db,
    kysely
      .insertInto("memory_policy_sets")
      .values({
        policy_set_id: params.snapshot.effectiveSourcePolicySetId,
        agent_id: params.snapshot.agentId,
        memory_policy_revision: params.snapshot.memoryPolicyRevision,
        member_policy_set_ids_json: params.snapshot.sourcePolicySetIdsJson,
        created_at: params.snapshot.createdAt,
      })
      .onConflict((conflict) => conflict.column("policy_set_id").doNothing()),
  );
  const row = executeSqliteQueryTakeFirstSync(
    params.db,
    kysely
      .selectFrom("memory_policy_sets")
      .selectAll()
      .where("policy_set_id", "=", params.snapshot.effectiveSourcePolicySetId),
  );
  return Boolean(row && matchesPolicySetSnapshot(row, params.snapshot));
}

function persistRunExposureLineageInTransaction(params: {
  db: DatabaseSync;
  agentId: string;
  current: TranscriptMemoryRunExposureSnapshot;
}): boolean {
  const kysely = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(params.db);
  const missing: TranscriptMemoryRunExposureSnapshot[] = [];
  const seen = new Set<string>();
  let cursor: TranscriptMemoryRunExposureSnapshot | undefined = params.current;
  while (cursor) {
    if (
      cursor.agentId !== params.agentId ||
      seen.has(cursor.exposureSetId) ||
      !isValidRunExposureSnapshot(cursor)
    ) {
      return false;
    }
    seen.add(cursor.exposureSetId);
    const existing = executeSqliteQueryTakeFirstSync(
      params.db,
      kysely
        .selectFrom("memory_run_exposures")
        .selectAll()
        .where("exposure_set_id", "=", cursor.exposureSetId),
    );
    if (existing) {
      if (
        !matchesRunExposureSnapshot(existing, cursor) ||
        !persistPolicySetSnapshotInTransaction({ db: params.db, snapshot: cursor })
      ) {
        return false;
      }
      break;
    }
    missing.push(cursor);
    cursor = cursor.previous;
  }

  for (const snapshot of missing.toReversed()) {
    if (!persistPolicySetSnapshotInTransaction({ db: params.db, snapshot })) {
      return false;
    }
    executeSqliteQuerySync(
      params.db,
      kysely
        .insertInto("memory_run_exposures")
        .values({
          exposure_set_id: snapshot.exposureSetId,
          agent_id: snapshot.agentId,
          run_id: snapshot.runId,
          context_fingerprint: snapshot.contextFingerprint,
          plan_id: snapshot.planId,
          revision_number: snapshot.revisionNumber,
          previous_exposure_set_id: snapshot.previous?.exposureSetId ?? null,
          source_policy_set_ids_json: snapshot.sourcePolicySetIdsJson,
          effective_source_policy_set_id: snapshot.effectiveSourcePolicySetId,
          exposed_resource_revisions_json: snapshot.exposedResourceRevisionsJson,
          exposure_receipt_ids_json: snapshot.exposureReceiptIdsJson,
          egress_receipt_ids_json: snapshot.egressReceiptIdsJson,
          delivery_audiences_json: snapshot.deliveryAudiencesJson,
          delivery_revision: snapshot.deliveryRevision,
          egress_registry_revision: snapshot.egressRegistryRevision,
          created_at: snapshot.createdAt,
        })
        .onConflict((conflict) => conflict.column("exposure_set_id").doNothing()),
    );
    const stored = executeSqliteQueryTakeFirstSync(
      params.db,
      kysely
        .selectFrom("memory_run_exposures")
        .selectAll()
        .where("exposure_set_id", "=", snapshot.exposureSetId),
    );
    if (!stored || !matchesRunExposureSnapshot(stored, snapshot)) {
      return false;
    }
  }
  return true;
}

function labelMatchesExposure(label: TranscriptMemoryPolicyLabel, agentId: string): boolean {
  const exposure = label.runExposure;
  return (
    exposure.agentId === agentId &&
    label.sourcePolicySetId === exposure.effectiveSourcePolicySetId &&
    label.runExposureSetId === exposure.exposureSetId &&
    label.runExposureRevision === exposure.revisionNumber &&
    label.deliveryAudiencesJson === exposure.deliveryAudiencesJson &&
    label.runId === exposure.runId &&
    label.contextFingerprint === exposure.contextFingerprint
  );
}

/** Cutover is process-stable, so this feature-local probe is cached per open database. */
export function isTranscriptMemoryPolicyEnforcedInDatabase(db: DatabaseSync): boolean {
  const cached = enforcementByDatabase.get(db);
  if (cached !== undefined) {
    return cached;
  }
  let enforced: boolean;
  try {
    ensureOpenClawAgentScopedMemorySchema(db);
    enforced =
      executeSqliteQueryTakeFirstSync(
        db,
        getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(db)
          .selectFrom("memory_migrations")
          .select("migration_id")
          .where("phase", "=", "cutover")
          .limit(1),
      ) !== undefined;
  } catch {
    // An unreadable policy store cannot safely expose unlabeled transcript content.
    enforced = true;
  }
  enforcementByDatabase.set(db, enforced);
  return enforced;
}

function isAuthorizedTranscriptPolicyBinding(params: {
  row: TranscriptEventMemoryPolicies;
  snapshot: SubjectSnapshotBinding | undefined;
  exposure: MemoryRunExposures | undefined;
  policySet: MemoryPolicySets | undefined;
}): boolean {
  const { row, snapshot, exposure, policySet } = params;
  if (
    row.authorization_status !== "authorized" ||
    typeof row.source_policy_set_id !== "string" ||
    typeof row.run_exposure_set_id !== "string" ||
    typeof row.run_exposure_revision !== "number" ||
    typeof row.delivery_audiences_json !== "string" ||
    typeof row.session_identity_revision !== "string" ||
    typeof row.subject_revision !== "string" ||
    typeof row.run_id !== "string" ||
    typeof row.context_fingerprint !== "string" ||
    !snapshot ||
    !exposure ||
    !policySet
  ) {
    return false;
  }
  const memberPolicySetIds = parseCanonicalMemoryStringArray(exposure.source_policy_set_ids_json);
  const audiences = parseCanonicalMemoryAudiences(exposure.delivery_audiences_json);
  return Boolean(
    memberPolicySetIds &&
    audiences?.length &&
    parseCanonicalMemoryStringArray(exposure.exposed_resource_revisions_json) &&
    parseCanonicalMemoryStringArray(exposure.exposure_receipt_ids_json) &&
    parseCanonicalMemoryStringArray(exposure.egress_receipt_ids_json) &&
    parseCanonicalMemoryStringArray(policySet.member_policy_set_ids_json) &&
    snapshot.session_id === row.session_id &&
    snapshot.session_identity_revision === row.session_identity_revision &&
    snapshot.subject_revision === row.subject_revision &&
    exposure.agent_id === policySet.agent_id &&
    exposure.run_id === row.run_id &&
    exposure.context_fingerprint === row.context_fingerprint &&
    exposure.revision_number === row.run_exposure_revision &&
    exposure.effective_source_policy_set_id === row.source_policy_set_id &&
    exposure.delivery_audiences_json === row.delivery_audiences_json &&
    policySet.member_policy_set_ids_json === exposure.source_policy_set_ids_json &&
    createEffectiveMemoryPolicySetId({
      memoryPolicyRevision: policySet.memory_policy_revision,
      memberPolicySetIds,
    }) === policySet.policy_set_id &&
    policySet.policy_set_id === exposure.effective_source_policy_set_id &&
    exposure.exposure_set_id === row.run_exposure_set_id &&
    exposure.plan_id.trim() &&
    exposure.delivery_revision.trim() &&
    exposure.egress_registry_revision.trim(),
  );
}

function isStoredTranscriptEventAuthorized(
  db: DatabaseSync,
  sessionId: string,
  eventSeq: number,
): boolean {
  const kysely = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(db);
  const row = executeSqliteQueryTakeFirstSync(
    db,
    kysely
      .selectFrom("transcript_event_memory_policies")
      .selectAll()
      .where("session_id", "=", sessionId)
      .where("event_seq", "=", eventSeq),
  );
  if (!row) {
    return false;
  }
  const snapshot = executeSqliteQueryTakeFirstSync(
    db,
    kysely
      .selectFrom("session_memory_subject_snapshots")
      .select(["session_id", "session_identity_revision", "subject_revision"])
      .where("session_id", "=", sessionId),
  );
  const exposure =
    typeof row.run_exposure_set_id === "string"
      ? executeSqliteQueryTakeFirstSync(
          db,
          kysely
            .selectFrom("memory_run_exposures")
            .selectAll()
            .where("exposure_set_id", "=", row.run_exposure_set_id),
        )
      : undefined;
  const policySet =
    typeof row.source_policy_set_id === "string"
      ? executeSqliteQueryTakeFirstSync(
          db,
          kysely
            .selectFrom("memory_policy_sets")
            .selectAll()
            .where("policy_set_id", "=", row.source_policy_set_id),
        )
      : undefined;
  return isAuthorizedTranscriptPolicyBinding({ row, snapshot, exposure, policySet });
}

/** Writes the companion immediately after its transcript row in the same transaction. */
export function recordTranscriptMemoryPolicyInTransaction(params: {
  database: OpenClawAgentDatabase;
  sessionId: string;
  eventSeq: number;
  createdAt: number;
}): boolean {
  const { database } = params;
  if (!isTranscriptMemoryPolicyEnforcedInDatabase(database.db)) {
    return true;
  }
  const db = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(database.db);
  const existing = executeSqliteQueryTakeFirstSync(
    database.db,
    db
      .selectFrom("transcript_event_memory_policies")
      .select("event_seq")
      .where("session_id", "=", params.sessionId)
      .where("event_seq", "=", params.eventSeq),
  );
  if (existing) {
    return isStoredTranscriptEventAuthorized(database.db, params.sessionId, params.eventSeq);
  }
  let label: TranscriptMemoryPolicyLabel | undefined;
  let authorized: boolean;
  try {
    label = readCurrentTranscriptMemoryPolicyLabel({
      agentId: database.agentId,
      sessionId: params.sessionId,
    });
    authorized = Boolean(
      label &&
      labelMatchesExposure(label, database.agentId) &&
      persistRunExposureLineageInTransaction({
        db: database.db,
        agentId: database.agentId,
        current: label.runExposure,
      }),
    );
  } catch {
    authorized = false;
  }
  executeSqliteQuerySync(
    database.db,
    db
      .insertInto("transcript_event_memory_policies")
      .values(
        authorized && label
          ? {
              session_id: params.sessionId,
              event_seq: params.eventSeq,
              authorization_status: "authorized",
              source_policy_set_id: label.sourcePolicySetId,
              run_exposure_set_id: label.runExposureSetId,
              run_exposure_revision: label.runExposureRevision,
              delivery_audiences_json: label.deliveryAudiencesJson,
              session_identity_revision: label.sessionIdentityRevision,
              subject_revision: label.subjectRevision,
              run_id: label.runId,
              context_fingerprint: label.contextFingerprint,
              created_at: params.createdAt,
            }
          : {
              session_id: params.sessionId,
              event_seq: params.eventSeq,
              authorization_status: "pending",
              source_policy_set_id: null,
              run_exposure_set_id: null,
              run_exposure_revision: null,
              delivery_audiences_json: null,
              session_identity_revision: null,
              subject_revision: null,
              run_id: null,
              context_fingerprint: null,
              created_at: params.createdAt,
            },
      )
      // Rewrites preserve the original policy decision. A pending event cannot
      // become authorized merely because later code rewrote its payload.
      .onConflict((conflict) => conflict.columns(["session_id", "event_seq"]).doNothing()),
  );
  return isStoredTranscriptEventAuthorized(database.db, params.sessionId, params.eventSeq);
}

/** Undefined means legacy/unrestricted; otherwise only these raw rows may carry content outward. */
export function readAuthorizedTranscriptEventSeqs(
  db: DatabaseSync,
  sessionId: string,
): Set<number> | undefined {
  if (!isTranscriptMemoryPolicyEnforcedInDatabase(db)) {
    return undefined;
  }
  try {
    const kysely = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(db);
    const policyRows = executeSqliteQuerySync(
      db,
      kysely
        .selectFrom("transcript_event_memory_policies")
        .selectAll()
        .where("session_id", "=", sessionId),
    ).rows;
    const snapshot = executeSqliteQueryTakeFirstSync(
      db,
      kysely
        .selectFrom("session_memory_subject_snapshots")
        .select(["session_id", "session_identity_revision", "subject_revision"])
        .where("session_id", "=", sessionId),
    );
    const exposureIds = [
      ...new Set(
        policyRows.flatMap((row) =>
          typeof row.run_exposure_set_id === "string" ? [row.run_exposure_set_id] : [],
        ),
      ),
    ];
    const policySetIds = [
      ...new Set(
        policyRows.flatMap((row) =>
          typeof row.source_policy_set_id === "string" ? [row.source_policy_set_id] : [],
        ),
      ),
    ];
    const exposures = [];
    for (let offset = 0; offset < exposureIds.length; offset += SQLITE_ID_BATCH_SIZE) {
      exposures.push(
        ...executeSqliteQuerySync(
          db,
          kysely
            .selectFrom("memory_run_exposures")
            .selectAll()
            .where(
              "exposure_set_id",
              "in",
              exposureIds.slice(offset, offset + SQLITE_ID_BATCH_SIZE),
            ),
        ).rows,
      );
    }
    const policySets = [];
    for (let offset = 0; offset < policySetIds.length; offset += SQLITE_ID_BATCH_SIZE) {
      policySets.push(
        ...executeSqliteQuerySync(
          db,
          kysely
            .selectFrom("memory_policy_sets")
            .selectAll()
            .where(
              "policy_set_id",
              "in",
              policySetIds.slice(offset, offset + SQLITE_ID_BATCH_SIZE),
            ),
        ).rows,
      );
    }
    const exposureById = new Map(exposures.map((row) => [row.exposure_set_id, row]));
    const policySetById = new Map(policySets.map((row) => [row.policy_set_id, row]));
    const authorized = new Set<number>();
    for (const row of policyRows) {
      const exposure =
        typeof row.run_exposure_set_id === "string"
          ? exposureById.get(row.run_exposure_set_id)
          : undefined;
      const policySet =
        typeof row.source_policy_set_id === "string"
          ? policySetById.get(row.source_policy_set_id)
          : undefined;
      if (isAuthorizedTranscriptPolicyBinding({ row, snapshot, exposure, policySet })) {
        authorized.add(row.event_seq);
      }
    }
    return authorized;
  } catch {
    return new Set();
  }
}

const transcriptMemoryPolicyTesting = {
  resetDatabase(db: DatabaseSync): void {
    enforcementByDatabase.delete(db);
  },
};

if (process.env.VITEST || process.env.NODE_ENV === "test") {
  (globalThis as Record<PropertyKey, unknown>)[
    Symbol.for("openclaw.transcriptMemoryPolicyTestApi")
  ] = transcriptMemoryPolicyTesting;
}
