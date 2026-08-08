import type { DatabaseSync } from "node:sqlite";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
} from "../../infra/kysely-sync.js";
import {
  canonicalMemoryStringArrayJson,
  parseCanonicalMemoryAudiences,
} from "../../plugins/memory-invocation-serialization.js";
import {
  readCurrentTranscriptMemoryPolicyLabel,
  type TranscriptMemoryPolicyLabel,
} from "../../plugins/memory-transcript-policy-label.js";
import type { OpenClawAgentDatabase } from "../../state/openclaw-agent-db.js";
import {
  createDerivedCompactionPolicySet,
  isStoredTranscriptEventAuthorized,
  memoryAudienceKey,
  persistDerivedCompactionPolicySetInTransaction,
  readEffectiveTranscriptEventPolicySetId,
  readStoredPolicySetFacts,
  type StoredPolicySetFacts,
} from "./session-transcript-memory-policy-authorization.js";
import {
  type TranscriptMemoryPolicyDatabase,
  isTranscriptMemoryPolicyEnforcedInDatabase,
  labelHasPreparedPolicy,
  labelMatchesExposure,
  persistPreparedPolicySetInTransaction,
  persistRunExposureLineageInTransaction,
} from "./session-transcript-memory-policy-core.js";

/** Writes the companion immediately after its transcript row in the same transaction. */
export function recordTranscriptMemoryPolicyInTransaction(params: {
  database: OpenClawAgentDatabase;
  sessionId: string;
  eventSeq: number;
  createdAt: number;
  forcePending?: boolean;
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
    label = params.forcePending
      ? undefined
      : readCurrentTranscriptMemoryPolicyLabel({
          agentId: database.agentId,
          sessionId: params.sessionId,
        });
    authorized = Boolean(
      label &&
      labelMatchesExposure(label, database.agentId) &&
      labelHasPreparedPolicy(label) &&
      persistRunExposureLineageInTransaction({
        db: database.db,
        agentId: database.agentId,
        current: label.runExposure,
      }) &&
      persistPreparedPolicySetInTransaction({ db: database.db, label }),
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
  if (authorized && label) {
    executeSqliteQuerySync(
      database.db,
      db
        .insertInto("transcript_event_memory_policy_details")
        .values({
          session_id: params.sessionId,
          event_seq: params.eventSeq,
          policy_set_revision: label.policySetRevision,
          actor_evidence_json: label.actorEvidenceJson,
          delegation_json: label.delegationJson,
          finalized_egress_audiences_json: label.finalizedEgressAudiencesJson,
          exposed_resource_revisions_json: label.exposedResourceRevisionsJson,
          origin_session_id: params.sessionId,
          origin_event_seq: params.eventSeq,
          created_at: params.createdAt,
        })
        .onConflict((conflict) => conflict.columns(["session_id", "event_seq"]).doNothing()),
    );
    executeSqliteQuerySync(
      database.db,
      db
        .insertInto("transcript_event_memory_policy_lineage")
        .values({
          session_id: params.sessionId,
          event_seq: params.eventSeq,
          source_session_id: params.sessionId,
          source_event_seq: params.eventSeq,
          origin_session_id: params.sessionId,
          origin_event_seq: params.eventSeq,
          transition_kind: "append",
          created_at: params.createdAt,
        })
        .onConflict((conflict) => conflict.columns(["session_id", "event_seq"]).doNothing()),
    );
  }
  return isStoredTranscriptEventAuthorized(database.db, params.sessionId, params.eventSeq);
}

/** A changed raw event has no source-bound authorization until a new policy is established. */
export function invalidateTranscriptMemoryPolicyInTransaction(params: {
  database: OpenClawAgentDatabase;
  sessionId: string;
  eventSeq: number;
}): void {
  if (!isTranscriptMemoryPolicyEnforcedInDatabase(params.database.db)) {
    return;
  }
  const db = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(params.database.db);
  executeSqliteQuerySync(
    params.database.db,
    db
      .deleteFrom("transcript_event_memory_policy_details")
      .where("session_id", "=", params.sessionId)
      .where("event_seq", "=", params.eventSeq),
  );
  executeSqliteQuerySync(
    params.database.db,
    db
      .deleteFrom("transcript_event_memory_policy_lineage")
      .where("session_id", "=", params.sessionId)
      .where("event_seq", "=", params.eventSeq),
  );
  executeSqliteQuerySync(
    params.database.db,
    db
      .updateTable("transcript_event_memory_policies")
      .set({
        authorization_status: "pending",
        context_fingerprint: null,
        delivery_audiences_json: null,
        run_exposure_revision: null,
        run_exposure_set_id: null,
        run_id: null,
        session_identity_revision: null,
        source_policy_set_id: null,
        subject_revision: null,
      })
      .where("session_id", "=", params.sessionId)
      .where("event_seq", "=", params.eventSeq),
  );
}

/** Records the summary's authoritative source companions before exposing a compaction event. */
export function recordTranscriptCompactionPolicyInTransaction(params: {
  compactionId: string;
  database: OpenClawAgentDatabase;
  eventSeq: number;
  sessionId: string;
  sourceEventSeqs: readonly number[];
}): boolean {
  if (!isTranscriptMemoryPolicyEnforcedInDatabase(params.database.db)) {
    return true;
  }
  const compactionId = params.compactionId.trim();
  const sourceEventSeqs = [...new Set(params.sourceEventSeqs)].toSorted(
    (left, right) => left - right,
  );
  if (
    !compactionId ||
    sourceEventSeqs.length === 0 ||
    sourceEventSeqs.some(
      (sourceEventSeq) =>
        !Number.isSafeInteger(sourceEventSeq) ||
        sourceEventSeq < 0 ||
        sourceEventSeq >= params.eventSeq,
    ) ||
    !isStoredTranscriptEventAuthorized(params.database.db, params.sessionId, params.eventSeq, {
      skipCompactionPolicy: true,
    }) ||
    !sourceEventSeqs.every((sourceEventSeq) =>
      isStoredTranscriptEventAuthorized(params.database.db, params.sessionId, sourceEventSeq),
    )
  ) {
    return false;
  }
  const db = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(params.database.db);
  const policy = executeSqliteQueryTakeFirstSync(
    params.database.db,
    db
      .selectFrom("transcript_event_memory_policies")
      .select(["source_policy_set_id"])
      .where("session_id", "=", params.sessionId)
      .where("event_seq", "=", params.eventSeq),
  );
  const outputPolicy = policy?.source_policy_set_id
    ? readStoredPolicySetFacts(params.database.db, policy.source_policy_set_id)
    : undefined;
  if (!policy?.source_policy_set_id || !outputPolicy) {
    return false;
  }
  const sourcePolicySetIds = [policy.source_policy_set_id];
  for (const sourceEventSeq of sourceEventSeqs) {
    const sourcePolicySetId = readEffectiveTranscriptEventPolicySetId(
      params.database.db,
      params.sessionId,
      sourceEventSeq,
    );
    if (!sourcePolicySetId) {
      return false;
    }
    sourcePolicySetIds.push(sourcePolicySetId);
  }
  const sourceFacts = sourcePolicySetIds.map((policySetId) =>
    readStoredPolicySetFacts(params.database.db, policySetId),
  );
  if (!sourceFacts.every((source): source is StoredPolicySetFacts => source !== undefined)) {
    return false;
  }
  const derived = createDerivedCompactionPolicySet({
    agentId: outputPolicy.policySet.agent_id,
    compactionId,
    eventSeq: params.eventSeq,
    sessionId: params.sessionId,
    sources: sourceFacts,
  });
  const outputAudiences = executeSqliteQueryTakeFirstSync(
    params.database.db,
    db
      .selectFrom("transcript_event_memory_policies")
      .select("delivery_audiences_json")
      .where("session_id", "=", params.sessionId)
      .where("event_seq", "=", params.eventSeq),
  )?.delivery_audiences_json;
  const deliveryAudiences =
    typeof outputAudiences === "string"
      ? parseCanonicalMemoryAudiences(outputAudiences)
      : undefined;
  if (
    !derived ||
    !deliveryAudiences?.length ||
    !deliveryAudiences.every((audience) =>
      derived.audiences.some(
        (candidate) => memoryAudienceKey(candidate) === memoryAudienceKey(audience),
      ),
    ) ||
    !persistDerivedCompactionPolicySetInTransaction({
      db: params.database.db,
      agentId: outputPolicy.policySet.agent_id,
      createdAt: Date.now(),
      policy: derived,
    })
  ) {
    return false;
  }
  const sourceEventSeqsJson = canonicalMemoryStringArrayJson(sourceEventSeqs.map(String));
  executeSqliteQuerySync(
    params.database.db,
    db
      .insertInto("memory_compaction_policy_bindings")
      .values({
        authorization_status: "authorized",
        compaction_id: compactionId,
        created_at: Date.now(),
        policy_set_revision: derived.policySetRevision,
        session_id: params.sessionId,
        source_event_seqs_json: sourceEventSeqsJson,
        source_policy_set_id: derived.policySetId,
      })
      .onConflict((conflict) => conflict.columns(["session_id", "compaction_id"]).doNothing()),
  );
  const persisted = executeSqliteQueryTakeFirstSync(
    params.database.db,
    db
      .selectFrom("memory_compaction_policy_bindings")
      .selectAll()
      .where("session_id", "=", params.sessionId)
      .where("compaction_id", "=", compactionId),
  );
  return Boolean(
    persisted &&
    persisted.session_id === params.sessionId &&
    persisted.authorization_status === "authorized" &&
    persisted.source_policy_set_id === derived.policySetId &&
    persisted.policy_set_revision === derived.policySetRevision &&
    persisted.source_event_seqs_json === sourceEventSeqsJson,
  );
}

export type TranscriptMemoryPolicyTransitionKind =
  | "append"
  | "archive"
  | "branch"
  | "checkpoint"
  | "export"
  | "fork"
  | "import"
  | "reset"
  | "rewind";

/**
 * Copies an already-evaluated companion only after its target event exists.
 * The source is revalidated first, so a copied event cannot retain a stale
 * historical allow merely because the transition itself was once authorized.
 */
export function copyTranscriptMemoryPolicyInTransaction(params: {
  database: OpenClawAgentDatabase;
  sourceSessionId: string;
  sourceEventSeq: number;
  targetSessionId: string;
  targetEventSeq: number;
  transitionKind: TranscriptMemoryPolicyTransitionKind;
  createdAt: number;
}): boolean {
  if (!isTranscriptMemoryPolicyEnforcedInDatabase(params.database.db)) {
    return true;
  }
  const db = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(params.database.db);
  const target = executeSqliteQueryTakeFirstSync(
    params.database.db,
    db
      .selectFrom("transcript_event_memory_policies")
      .selectAll()
      .where("session_id", "=", params.targetSessionId)
      .where("event_seq", "=", params.targetEventSeq),
  );
  if (!target) {
    return false;
  }
  const source = executeSqliteQueryTakeFirstSync(
    params.database.db,
    db
      .selectFrom("transcript_event_memory_policies")
      .selectAll()
      .where("session_id", "=", params.sourceSessionId)
      .where("event_seq", "=", params.sourceEventSeq),
  );
  const sourceDetail = source
    ? executeSqliteQueryTakeFirstSync(
        params.database.db,
        db
          .selectFrom("transcript_event_memory_policy_details")
          .selectAll()
          .where("session_id", "=", params.sourceSessionId)
          .where("event_seq", "=", params.sourceEventSeq),
      )
    : undefined;
  const originSessionId = sourceDetail?.origin_session_id ?? params.sourceSessionId;
  const originEventSeq = sourceDetail?.origin_event_seq ?? params.sourceEventSeq;
  const existingLineage = executeSqliteQueryTakeFirstSync(
    params.database.db,
    db
      .selectFrom("transcript_event_memory_policy_lineage")
      .selectAll()
      .where("session_id", "=", params.targetSessionId)
      .where("event_seq", "=", params.targetEventSeq),
  );
  if (!existingLineage) {
    executeSqliteQuerySync(
      params.database.db,
      db.insertInto("transcript_event_memory_policy_lineage").values({
        session_id: params.targetSessionId,
        event_seq: params.targetEventSeq,
        source_session_id: params.sourceSessionId,
        source_event_seq: params.sourceEventSeq,
        origin_session_id: originSessionId,
        origin_event_seq: originEventSeq,
        transition_kind: params.transitionKind,
        created_at: params.createdAt,
      }),
    );
  } else if (
    existingLineage.source_session_id !== params.sourceSessionId ||
    existingLineage.source_event_seq !== params.sourceEventSeq ||
    existingLineage.origin_session_id !== originSessionId ||
    existingLineage.origin_event_seq !== originEventSeq ||
    existingLineage.transition_kind !== params.transitionKind
  ) {
    return false;
  }
  if (
    !source ||
    !sourceDetail ||
    !isStoredTranscriptEventAuthorized(
      params.database.db,
      params.sourceSessionId,
      params.sourceEventSeq,
    )
  ) {
    return false;
  }
  if (target.authorization_status !== "pending") {
    return isStoredTranscriptEventAuthorized(
      params.database.db,
      params.targetSessionId,
      params.targetEventSeq,
    );
  }
  executeSqliteQuerySync(
    params.database.db,
    db
      .updateTable("transcript_event_memory_policies")
      .set({
        authorization_status: source.authorization_status,
        source_policy_set_id: source.source_policy_set_id,
        run_exposure_set_id: source.run_exposure_set_id,
        run_exposure_revision: source.run_exposure_revision,
        delivery_audiences_json: source.delivery_audiences_json,
        session_identity_revision: source.session_identity_revision,
        subject_revision: source.subject_revision,
        run_id: source.run_id,
        context_fingerprint: source.context_fingerprint,
      })
      .where("session_id", "=", params.targetSessionId)
      .where("event_seq", "=", params.targetEventSeq)
      .where("authorization_status", "=", "pending"),
  );
  executeSqliteQuerySync(
    params.database.db,
    db.insertInto("transcript_event_memory_policy_details").values({
      session_id: params.targetSessionId,
      event_seq: params.targetEventSeq,
      policy_set_revision: sourceDetail.policy_set_revision,
      actor_evidence_json: sourceDetail.actor_evidence_json,
      delegation_json: sourceDetail.delegation_json,
      finalized_egress_audiences_json: sourceDetail.finalized_egress_audiences_json,
      exposed_resource_revisions_json: sourceDetail.exposed_resource_revisions_json,
      origin_session_id: sourceDetail.origin_session_id,
      origin_event_seq: sourceDetail.origin_event_seq,
      created_at: params.createdAt,
    }),
  );
  return isStoredTranscriptEventAuthorized(
    params.database.db,
    params.targetSessionId,
    params.targetEventSeq,
  );
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
    const authorized = new Set<number>();
    for (const row of policyRows) {
      if (isStoredTranscriptEventAuthorized(db, sessionId, row.event_seq)) {
        authorized.add(row.event_seq);
      }
    }
    return authorized;
  } catch {
    return new Set();
  }
}
