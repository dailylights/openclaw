import type { DatabaseSync } from "node:sqlite";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
} from "../../infra/kysely-sync.js";
import type { TranscriptMemoryRunExposureSnapshot } from "../../plugins/memory-invocation-receipts.js";
import {
  canonicalMemoryAudiencesJson,
  canonicalMemoryStringArrayJson,
  createEffectiveMemoryPolicySetId,
  equalMemoryAudiences,
  parseCanonicalMemoryAudiences,
  parseCanonicalMemoryStringArray,
} from "../../plugins/memory-invocation-serialization.js";
import type { TranscriptMemoryPolicyLabel } from "../../plugins/memory-transcript-policy-label.js";
import type {
  DB as OpenClawAgentDatabaseSchema,
  MemoryPolicySetMetadata,
  MemoryPolicySetRequirements,
  MemoryPolicySets,
  MemoryRunExposures,
  SessionMemorySubjectSnapshots,
  TranscriptEventMemoryPolicyDetails,
  TranscriptEventMemoryPolicies,
} from "../../state/openclaw-agent-db.generated.js";
import { ensureOpenClawAgentScopedMemorySchema } from "../../state/openclaw-agent-scoped-memory-schema.js";

export type TranscriptMemoryPolicyDatabase = Pick<
  OpenClawAgentDatabaseSchema,
  | "memory_migrations"
  | "memory_compaction_policies"
  | "memory_compaction_policy_bindings"
  | "memory_policies"
  | "memory_policy_revisions"
  | "memory_policy_set_metadata"
  | "memory_policy_set_requirements"
  | "memory_policy_sets"
  | "memory_run_exposures"
  | "session_memory_subject_snapshots"
  | "transcript_event_identities"
  | "transcript_events"
  | "transcript_event_memory_policy_details"
  | "transcript_event_memory_policy_lineage"
  | "transcript_event_memory_policies"
  | "transcript_memory_archive_events"
  | "transcript_memory_archives"
>;

const enforcementByDatabase = new WeakMap<DatabaseSync, boolean>();
type SubjectSnapshotBinding = Pick<
  SessionMemorySubjectSnapshots,
  "session_id" | "session_identity_revision" | "subject_revision"
>;

function isCanonicalJson(value: string): boolean {
  try {
    JSON.parse(value);
    return true;
  } catch {
    return false;
  }
}

export function hasCurrentPolicyRequirements(params: {
  db: DatabaseSync;
  agentId: string;
  requirements: readonly MemoryPolicySetRequirements[];
}): boolean {
  if (params.requirements.length === 0) {
    return false;
  }
  const kysely = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(params.db);
  const seenPolicies = new Set<string>();
  for (const requirement of params.requirements) {
    if (
      !requirement.stable_policy_id.trim() ||
      !requirement.captured_revision_id.trim() ||
      !requirement.expected_active_revision_id.trim() ||
      !Number.isSafeInteger(requirement.expected_revocation_epoch) ||
      requirement.expected_revocation_epoch < 0 ||
      seenPolicies.has(requirement.stable_policy_id)
    ) {
      return false;
    }
    seenPolicies.add(requirement.stable_policy_id);
    const policy = executeSqliteQueryTakeFirstSync(
      params.db,
      kysely
        .selectFrom("memory_policies")
        .selectAll()
        .where("policy_id", "=", requirement.stable_policy_id),
    );
    const expectedRevision = executeSqliteQueryTakeFirstSync(
      params.db,
      kysely
        .selectFrom("memory_policy_revisions")
        .selectAll()
        .where("revision_id", "=", requirement.expected_active_revision_id),
    );
    const capturedRevision = executeSqliteQueryTakeFirstSync(
      params.db,
      kysely
        .selectFrom("memory_policy_revisions")
        .selectAll()
        .where("revision_id", "=", requirement.captured_revision_id),
    );
    if (
      !policy ||
      !expectedRevision ||
      !capturedRevision ||
      policy.agent_id !== params.agentId ||
      policy.lifecycle_state !== "active" ||
      policy.current_revision_id !== requirement.expected_active_revision_id ||
      policy.revocation_epoch !== requirement.expected_revocation_epoch ||
      expectedRevision.policy_id !== requirement.stable_policy_id ||
      expectedRevision.lifecycle_state !== "active" ||
      expectedRevision.revocation_epoch !== requirement.expected_revocation_epoch ||
      capturedRevision.policy_id !== requirement.stable_policy_id
    ) {
      return false;
    }
  }
  return true;
}

export function labelHasPreparedPolicy(label: TranscriptMemoryPolicyLabel): boolean {
  const policy = label.transcriptPolicy;
  const sourcePolicySetIds = parseCanonicalMemoryStringArray(
    canonicalMemoryStringArrayJson(policy.sourcePolicySetIds),
  );
  const normalizedAudiences = parseCanonicalMemoryAudiences(
    canonicalMemoryAudiencesJson(policy.normalizedAudienceIntersection),
  );
  const deliveryAudiences = parseCanonicalMemoryAudiences(label.deliveryAudiencesJson);
  return Boolean(
    policy.version === 1 &&
    policy.policySetId === label.sourcePolicySetId &&
    policy.policySetRevision.trim() &&
    policy.retentionState === "active" &&
    sourcePolicySetIds &&
    sourcePolicySetIds.length > 0 &&
    sourcePolicySetIds.every((policySetId) => policySetId.trim()) &&
    normalizedAudiences &&
    normalizedAudiences.length > 0 &&
    deliveryAudiences &&
    policy.sourcePolicySetIds.length === sourcePolicySetIds.length &&
    policy.requirements.length > 0 &&
    new Set(policy.requirements.map((requirement) => requirement.stablePolicyId)).size ===
      policy.requirements.length &&
    policy.requirements.every(
      (requirement) =>
        requirement.stablePolicyId.trim() &&
        requirement.capturedRevisionId.trim() &&
        requirement.expectedActiveRevisionId.trim() &&
        Number.isSafeInteger(requirement.expectedRevocationEpoch) &&
        requirement.expectedRevocationEpoch >= 0,
    ) &&
    isCanonicalJson(label.actorEvidenceJson) &&
    isCanonicalJson(label.delegationJson) &&
    label.finalizedEgressAudiencesJson === label.deliveryAudiencesJson &&
    parseCanonicalMemoryStringArray(label.exposedResourceRevisionsJson),
  );
}

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

export function persistPreparedPolicySetInTransaction(params: {
  db: DatabaseSync;
  label: TranscriptMemoryPolicyLabel;
}): boolean {
  const { label } = params;
  const policy = label.transcriptPolicy;
  const sourcePolicySetIdsJson = canonicalMemoryStringArrayJson(policy.sourcePolicySetIds);
  const normalizedAudienceIntersectionJson = canonicalMemoryAudiencesJson(
    policy.normalizedAudienceIntersection,
  );
  const exposureSourcePolicySetIds = parseCanonicalMemoryStringArray(
    label.runExposure.sourcePolicySetIdsJson,
  );
  if (
    !labelHasPreparedPolicy(label) ||
    !exposureSourcePolicySetIds ||
    sourcePolicySetIdsJson !== label.runExposure.sourcePolicySetIdsJson
  ) {
    return false;
  }
  const kysely = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(params.db);
  executeSqliteQuerySync(
    params.db,
    kysely
      .insertInto("memory_policy_set_metadata")
      .values({
        policy_set_id: label.sourcePolicySetId,
        policy_set_revision: policy.policySetRevision,
        source_policy_set_ids_json: sourcePolicySetIdsJson,
        normalized_audience_intersection_json: normalizedAudienceIntersectionJson,
        retention_state: policy.retentionState,
        created_at: label.runExposure.createdAt,
      })
      .onConflict((conflict) => conflict.column("policy_set_id").doNothing()),
  );
  const metadata = executeSqliteQueryTakeFirstSync(
    params.db,
    kysely
      .selectFrom("memory_policy_set_metadata")
      .selectAll()
      .where("policy_set_id", "=", label.sourcePolicySetId),
  );
  if (
    !metadata ||
    metadata.policy_set_revision !== policy.policySetRevision ||
    metadata.source_policy_set_ids_json !== sourcePolicySetIdsJson ||
    metadata.normalized_audience_intersection_json !== normalizedAudienceIntersectionJson ||
    metadata.retention_state !== policy.retentionState
  ) {
    return false;
  }
  for (const requirement of policy.requirements) {
    executeSqliteQuerySync(
      params.db,
      kysely
        .insertInto("memory_policy_set_requirements")
        .values({
          policy_set_id: label.sourcePolicySetId,
          stable_policy_id: requirement.stablePolicyId,
          captured_revision_id: requirement.capturedRevisionId,
          expected_active_revision_id: requirement.expectedActiveRevisionId,
          expected_revocation_epoch: requirement.expectedRevocationEpoch,
        })
        .onConflict((conflict) =>
          conflict.columns(["policy_set_id", "stable_policy_id"]).doNothing(),
        ),
    );
  }
  const requirements = executeSqliteQuerySync(
    params.db,
    kysely
      .selectFrom("memory_policy_set_requirements")
      .selectAll()
      .where("policy_set_id", "=", label.sourcePolicySetId),
  ).rows;
  return (
    requirements.length === policy.requirements.length &&
    requirements.every((requirement) => {
      const prepared = policy.requirements.find(
        (candidate) => candidate.stablePolicyId === requirement.stable_policy_id,
      );
      return (
        prepared !== undefined &&
        prepared.capturedRevisionId === requirement.captured_revision_id &&
        prepared.expectedActiveRevisionId === requirement.expected_active_revision_id &&
        prepared.expectedRevocationEpoch === requirement.expected_revocation_epoch
      );
    })
  );
}

export function persistRunExposureLineageInTransaction(params: {
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

export function labelMatchesExposure(label: TranscriptMemoryPolicyLabel, agentId: string): boolean {
  const exposure = label.runExposure;
  return (
    exposure.agentId === agentId &&
    label.sourcePolicySetId === exposure.effectiveSourcePolicySetId &&
    label.runExposureSetId === exposure.exposureSetId &&
    label.runExposureRevision === exposure.revisionNumber &&
    label.deliveryAudiencesJson === exposure.deliveryAudiencesJson &&
    label.finalizedEgressAudiencesJson === exposure.deliveryAudiencesJson &&
    label.exposedResourceRevisionsJson === exposure.exposedResourceRevisionsJson &&
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

export function isAuthorizedTranscriptPolicyBinding(params: {
  db: DatabaseSync;
  row: TranscriptEventMemoryPolicies;
  snapshot: SubjectSnapshotBinding | undefined;
  exposure: MemoryRunExposures | undefined;
  policySet: MemoryPolicySets | undefined;
  metadata: MemoryPolicySetMetadata | undefined;
  requirements: readonly MemoryPolicySetRequirements[];
  detail: TranscriptEventMemoryPolicyDetails | undefined;
  lineage:
    | {
        source_session_id: string;
        source_event_seq: number;
        origin_session_id: string;
        origin_event_seq: number;
      }
    | undefined;
}): boolean {
  const { row, snapshot, exposure, policySet, metadata, requirements, detail, lineage } = params;
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
    !policySet ||
    !metadata ||
    !detail ||
    !lineage
  ) {
    return false;
  }
  const memberPolicySetIds = parseCanonicalMemoryStringArray(exposure.source_policy_set_ids_json);
  const audiences = parseCanonicalMemoryAudiences(exposure.delivery_audiences_json);
  const normalizedAudiences = parseCanonicalMemoryAudiences(
    metadata.normalized_audience_intersection_json,
  );
  const finalizedEgressAudiences = parseCanonicalMemoryAudiences(
    detail.finalized_egress_audiences_json,
  );
  return Boolean(
    memberPolicySetIds &&
    audiences?.length &&
    normalizedAudiences?.length &&
    finalizedEgressAudiences &&
    equalMemoryAudiences(finalizedEgressAudiences, audiences) &&
    parseCanonicalMemoryStringArray(exposure.exposed_resource_revisions_json) &&
    parseCanonicalMemoryStringArray(exposure.exposure_receipt_ids_json) &&
    parseCanonicalMemoryStringArray(exposure.egress_receipt_ids_json) &&
    parseCanonicalMemoryStringArray(policySet.member_policy_set_ids_json) &&
    parseCanonicalMemoryStringArray(detail.exposed_resource_revisions_json) &&
    isCanonicalJson(detail.actor_evidence_json) &&
    isCanonicalJson(detail.delegation_json) &&
    detail.origin_session_id.trim() &&
    Number.isSafeInteger(detail.origin_event_seq) &&
    detail.origin_event_seq >= 0 &&
    lineage.source_session_id.trim() &&
    Number.isSafeInteger(lineage.source_event_seq) &&
    lineage.source_event_seq >= 0 &&
    lineage.origin_session_id === detail.origin_session_id &&
    lineage.origin_event_seq === detail.origin_event_seq &&
    snapshot.session_id === detail.origin_session_id &&
    snapshot.session_identity_revision === row.session_identity_revision &&
    snapshot.subject_revision === row.subject_revision &&
    exposure.agent_id === policySet.agent_id &&
    exposure.run_id === row.run_id &&
    exposure.context_fingerprint === row.context_fingerprint &&
    exposure.revision_number === row.run_exposure_revision &&
    exposure.effective_source_policy_set_id === row.source_policy_set_id &&
    exposure.delivery_audiences_json === row.delivery_audiences_json &&
    policySet.member_policy_set_ids_json === exposure.source_policy_set_ids_json &&
    metadata.policy_set_id === policySet.policy_set_id &&
    metadata.policy_set_revision === detail.policy_set_revision &&
    metadata.source_policy_set_ids_json === exposure.source_policy_set_ids_json &&
    metadata.retention_state === "active" &&
    createEffectiveMemoryPolicySetId({
      memoryPolicyRevision: policySet.memory_policy_revision,
      memberPolicySetIds,
    }) === policySet.policy_set_id &&
    policySet.policy_set_id === exposure.effective_source_policy_set_id &&
    exposure.exposure_set_id === row.run_exposure_set_id &&
    exposure.plan_id.trim() &&
    exposure.delivery_revision.trim() &&
    exposure.egress_registry_revision.trim() &&
    hasCurrentPolicyRequirements({
      db: params.db,
      agentId: policySet.agent_id,
      requirements,
    }),
  );
}

export function resetTranscriptMemoryPolicyEnforcementForTest(db: DatabaseSync): void {
  enforcementByDatabase.delete(db);
}
