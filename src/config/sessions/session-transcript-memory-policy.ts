import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
} from "../../infra/kysely-sync.js";
import type { AudienceRef } from "../../memory-host-sdk/host/authorization.js";
import type { TranscriptMemoryRunExposureSnapshot } from "../../plugins/memory-invocation-receipts.js";
import {
  canonicalMemoryAudiencesJson,
  canonicalMemoryStringArrayJson,
  createEffectiveMemoryPolicySetId,
  equalMemoryAudiences,
  hashMemoryRevision,
  parseCanonicalMemoryAudiences,
  parseCanonicalMemoryStringArray,
} from "../../plugins/memory-invocation-serialization.js";
import {
  readCurrentTranscriptMemoryPolicyLabel,
  type TranscriptMemoryPolicyLabel,
} from "../../plugins/memory-transcript-policy-label.js";
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
import type { OpenClawAgentDatabase } from "../../state/openclaw-agent-db.js";
import { ensureOpenClawAgentScopedMemorySchema } from "../../state/openclaw-agent-scoped-memory-schema.js";

type TranscriptMemoryPolicyDatabase = Pick<
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

function hasCurrentPolicyRequirements(params: {
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

function labelHasPreparedPolicy(label: TranscriptMemoryPolicyLabel): boolean {
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

function persistPreparedPolicySetInTransaction(params: {
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

function isAuthorizedTranscriptPolicyBinding(params: {
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

type StoredPolicySetFacts = Readonly<{
  policySet: MemoryPolicySets;
  metadata: MemoryPolicySetMetadata;
  requirements: readonly MemoryPolicySetRequirements[];
  sourcePolicySetIds: readonly string[];
  audiences: readonly AudienceRef[];
}>;

type DerivedCompactionPolicySet = Readonly<{
  policySetId: string;
  policySetRevision: string;
  memoryPolicyRevision: string;
  sourcePolicySetIds: readonly string[];
  audiences: readonly AudienceRef[];
  requirements: readonly MemoryPolicySetRequirements[];
}>;

function memoryAudienceKey(audience: AudienceRef): string {
  return `${audience.kind}\0${audience.id}`;
}

function sameMemoryStringArrays(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function samePolicySetRequirements(
  left: readonly MemoryPolicySetRequirements[],
  right: readonly MemoryPolicySetRequirements[],
): boolean {
  return (
    left.length === right.length &&
    left.every((requirement, index) => {
      const candidate = right[index];
      return (
        candidate !== undefined &&
        requirement.stable_policy_id === candidate.stable_policy_id &&
        requirement.captured_revision_id === candidate.captured_revision_id &&
        requirement.expected_active_revision_id === candidate.expected_active_revision_id &&
        requirement.expected_revocation_epoch === candidate.expected_revocation_epoch
      );
    })
  );
}

function sortedPolicySetRequirements(
  requirements: readonly MemoryPolicySetRequirements[],
): MemoryPolicySetRequirements[] {
  return [...requirements].toSorted((left, right) =>
    left.stable_policy_id.localeCompare(right.stable_policy_id),
  );
}

function readStoredPolicySetFacts(
  db: DatabaseSync,
  policySetId: string,
): StoredPolicySetFacts | undefined {
  const kysely = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(db);
  const policySet = executeSqliteQueryTakeFirstSync(
    db,
    kysely.selectFrom("memory_policy_sets").selectAll().where("policy_set_id", "=", policySetId),
  );
  const metadata = policySet
    ? executeSqliteQueryTakeFirstSync(
        db,
        kysely
          .selectFrom("memory_policy_set_metadata")
          .selectAll()
          .where("policy_set_id", "=", policySetId),
      )
    : undefined;
  const requirements = policySet
    ? sortedPolicySetRequirements(
        executeSqliteQuerySync(
          db,
          kysely
            .selectFrom("memory_policy_set_requirements")
            .selectAll()
            .where("policy_set_id", "=", policySetId),
        ).rows,
      )
    : [];
  if (!policySet || !metadata || metadata.retention_state !== "active") {
    return undefined;
  }
  const sourcePolicySetIds = parseCanonicalMemoryStringArray(metadata.source_policy_set_ids_json);
  const policySetMembers = parseCanonicalMemoryStringArray(policySet.member_policy_set_ids_json);
  const audiences = parseCanonicalMemoryAudiences(metadata.normalized_audience_intersection_json);
  if (
    !sourcePolicySetIds ||
    !policySetMembers ||
    !audiences?.length ||
    !metadata.policy_set_revision.trim() ||
    !sameMemoryStringArrays(sourcePolicySetIds, policySetMembers) ||
    createEffectiveMemoryPolicySetId({
      memoryPolicyRevision: policySet.memory_policy_revision,
      memberPolicySetIds: sourcePolicySetIds,
    }) !== policySet.policy_set_id ||
    requirements.length === 0 ||
    new Set(requirements.map((requirement) => requirement.stable_policy_id)).size !==
      requirements.length
  ) {
    return undefined;
  }
  return { policySet, metadata, requirements, sourcePolicySetIds, audiences };
}

function mergeCompactionPolicyRequirements(
  sources: readonly StoredPolicySetFacts[],
): MemoryPolicySetRequirements[] | undefined {
  const merged = new Map<string, MemoryPolicySetRequirements>();
  for (const source of sources) {
    for (const requirement of source.requirements) {
      const existing = merged.get(requirement.stable_policy_id);
      if (
        existing &&
        (existing.captured_revision_id !== requirement.captured_revision_id ||
          existing.expected_active_revision_id !== requirement.expected_active_revision_id ||
          existing.expected_revocation_epoch !== requirement.expected_revocation_epoch)
      ) {
        return undefined;
      }
      merged.set(requirement.stable_policy_id, requirement);
    }
  }
  const requirements = sortedPolicySetRequirements([...merged.values()]);
  return requirements.length > 0 ? requirements : undefined;
}

function intersectCompactionAudiences(
  sources: readonly StoredPolicySetFacts[],
): AudienceRef[] | undefined {
  const first = sources[0]?.audiences;
  if (!first) {
    return undefined;
  }
  const intersection = first.filter((audience) =>
    sources.every((source) =>
      source.audiences.some(
        (candidate) => memoryAudienceKey(candidate) === memoryAudienceKey(audience),
      ),
    ),
  );
  return intersection.length > 0 ? intersection : undefined;
}

function createDerivedCompactionPolicySet(params: {
  agentId: string;
  compactionId: string;
  eventSeq: number;
  sessionId: string;
  sources: readonly StoredPolicySetFacts[];
}): DerivedCompactionPolicySet | undefined {
  if (
    !params.agentId.trim() ||
    !params.compactionId.trim() ||
    !params.sessionId.trim() ||
    !Number.isSafeInteger(params.eventSeq) ||
    params.eventSeq < 0 ||
    params.sources.length === 0 ||
    params.sources.some((source) => source.policySet.agent_id !== params.agentId)
  ) {
    return undefined;
  }
  const sourcePolicySetIds = [
    ...new Set(params.sources.map((source) => source.policySet.policy_set_id)),
  ].toSorted();
  const audiences = intersectCompactionAudiences(params.sources);
  const requirements = mergeCompactionPolicyRequirements(params.sources);
  if (!audiences || !requirements) {
    return undefined;
  }
  const requirementSnapshot = requirements.map((requirement) => ({
    stablePolicyId: requirement.stable_policy_id,
    capturedRevisionId: requirement.captured_revision_id,
    expectedActiveRevisionId: requirement.expected_active_revision_id,
    expectedRevocationEpoch: requirement.expected_revocation_epoch,
  }));
  const memoryPolicyRevision = hashMemoryRevision("mpsr2", {
    agentId: params.agentId,
    compactionId: params.compactionId,
    eventSeq: params.eventSeq,
    sessionId: params.sessionId,
    sourcePolicySetIds,
    audiences,
    requirements: requirementSnapshot,
  });
  const policySetId = createEffectiveMemoryPolicySetId({
    memoryPolicyRevision,
    memberPolicySetIds: sourcePolicySetIds,
  });
  const policySetRevision = hashMemoryRevision("mpsetrev2", {
    policySetId,
    memoryPolicyRevision,
    sourcePolicySetIds,
    audiences,
    requirements: requirementSnapshot,
  });
  return {
    policySetId,
    policySetRevision,
    memoryPolicyRevision,
    sourcePolicySetIds,
    audiences,
    requirements,
  };
}

function persistDerivedCompactionPolicySetInTransaction(params: {
  db: DatabaseSync;
  agentId: string;
  createdAt: number;
  policy: DerivedCompactionPolicySet;
}): boolean {
  const kysely = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(params.db);
  const sourcePolicySetIdsJson = canonicalMemoryStringArrayJson(params.policy.sourcePolicySetIds);
  const audiencesJson = canonicalMemoryAudiencesJson(params.policy.audiences);
  executeSqliteQuerySync(
    params.db,
    kysely
      .insertInto("memory_policy_sets")
      .values({
        policy_set_id: params.policy.policySetId,
        agent_id: params.agentId,
        memory_policy_revision: params.policy.memoryPolicyRevision,
        member_policy_set_ids_json: sourcePolicySetIdsJson,
        created_at: params.createdAt,
      })
      .onConflict((conflict) => conflict.column("policy_set_id").doNothing()),
  );
  executeSqliteQuerySync(
    params.db,
    kysely
      .insertInto("memory_policy_set_metadata")
      .values({
        policy_set_id: params.policy.policySetId,
        policy_set_revision: params.policy.policySetRevision,
        source_policy_set_ids_json: sourcePolicySetIdsJson,
        normalized_audience_intersection_json: audiencesJson,
        retention_state: "active",
        created_at: params.createdAt,
      })
      .onConflict((conflict) => conflict.column("policy_set_id").doNothing()),
  );
  for (const requirement of params.policy.requirements) {
    executeSqliteQuerySync(
      params.db,
      kysely
        .insertInto("memory_policy_set_requirements")
        .values({
          policy_set_id: params.policy.policySetId,
          stable_policy_id: requirement.stable_policy_id,
          captured_revision_id: requirement.captured_revision_id,
          expected_active_revision_id: requirement.expected_active_revision_id,
          expected_revocation_epoch: requirement.expected_revocation_epoch,
        })
        .onConflict((conflict) =>
          conflict.columns(["policy_set_id", "stable_policy_id"]).doNothing(),
        ),
    );
  }
  const persisted = readStoredPolicySetFacts(params.db, params.policy.policySetId);
  return Boolean(
    persisted &&
    persisted.policySet.agent_id === params.agentId &&
    persisted.policySet.memory_policy_revision === params.policy.memoryPolicyRevision &&
    persisted.metadata.policy_set_revision === params.policy.policySetRevision &&
    sameMemoryStringArrays(persisted.sourcePolicySetIds, params.policy.sourcePolicySetIds) &&
    equalMemoryAudiences(persisted.audiences, params.policy.audiences) &&
    samePolicySetRequirements(persisted.requirements, params.policy.requirements),
  );
}

function isStoredTranscriptEventAuthorized(
  db: DatabaseSync,
  sessionId: string,
  eventSeq: number,
  options: { skipCompactionPolicy?: boolean } = {},
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
  const metadata =
    policySet === undefined
      ? undefined
      : executeSqliteQueryTakeFirstSync(
          db,
          kysely
            .selectFrom("memory_policy_set_metadata")
            .selectAll()
            .where("policy_set_id", "=", policySet.policy_set_id),
        );
  const requirements =
    policySet === undefined
      ? []
      : executeSqliteQuerySync(
          db,
          kysely
            .selectFrom("memory_policy_set_requirements")
            .selectAll()
            .where("policy_set_id", "=", policySet.policy_set_id),
        ).rows;
  const detail = executeSqliteQueryTakeFirstSync(
    db,
    kysely
      .selectFrom("transcript_event_memory_policy_details")
      .selectAll()
      .where("session_id", "=", sessionId)
      .where("event_seq", "=", eventSeq),
  );
  const lineage = executeSqliteQueryTakeFirstSync(
    db,
    kysely
      .selectFrom("transcript_event_memory_policy_lineage")
      .select(["source_session_id", "source_event_seq", "origin_session_id", "origin_event_seq"])
      .where("session_id", "=", sessionId)
      .where("event_seq", "=", eventSeq),
  );
  const snapshot =
    detail === undefined
      ? undefined
      : executeSqliteQueryTakeFirstSync(
          db,
          kysely
            .selectFrom("session_memory_subject_snapshots")
            .select(["session_id", "session_identity_revision", "subject_revision"])
            .where("session_id", "=", detail.origin_session_id),
        );
  const basicPolicyAuthorized = isAuthorizedTranscriptPolicyBinding({
    db,
    row,
    snapshot,
    exposure,
    policySet,
    metadata,
    requirements,
    detail,
    lineage,
  });
  if (!basicPolicyAuthorized || options.skipCompactionPolicy === true) {
    return basicPolicyAuthorized;
  }
  const compaction = readTranscriptCompactionIdentity(db, sessionId, eventSeq);
  if (!compaction) {
    return true;
  }
  // The binding check proves both companions exist, but its boolean result
  // cannot carry that narrowing into the compaction-specific revalidation.
  if (!detail || !policySet) {
    return false;
  }
  return isStoredCompactionPolicyAuthorized({
    db,
    compactionId: compaction.id,
    detail,
    eventSeq,
    policySet,
    row,
    sessionId,
  });
}

function readTranscriptCompactionIdentity(
  db: DatabaseSync,
  sessionId: string,
  eventSeq: number,
): { id: string } | undefined {
  // The event supplies only its immutable identity; authorization comes from
  // the companion record and its revalidated source companions below.
  const row = executeSqliteQueryTakeFirstSync(
    db,
    getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(db)
      .selectFrom("transcript_events")
      .select("event_json")
      .where("session_id", "=", sessionId)
      .where("seq", "=", eventSeq),
  );
  if (!row) {
    return undefined;
  }
  try {
    const event = JSON.parse(row.event_json) as { id?: unknown; type?: unknown };
    return event.type === "compaction" && typeof event.id === "string" && event.id.trim()
      ? { id: event.id }
      : undefined;
  } catch {
    return undefined;
  }
}

function readEffectiveTranscriptEventPolicySetId(
  db: DatabaseSync,
  sessionId: string,
  eventSeq: number,
): string | undefined {
  const kysely = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(db);
  const policy = executeSqliteQueryTakeFirstSync(
    db,
    kysely
      .selectFrom("transcript_event_memory_policies")
      .select("source_policy_set_id")
      .where("session_id", "=", sessionId)
      .where("event_seq", "=", eventSeq),
  );
  if (!policy?.source_policy_set_id) {
    return undefined;
  }
  const compaction = readTranscriptCompactionIdentity(db, sessionId, eventSeq);
  if (!compaction) {
    return policy.source_policy_set_id;
  }
  const binding = executeSqliteQueryTakeFirstSync(
    db,
    kysely
      .selectFrom("memory_compaction_policy_bindings")
      .select(["authorization_status", "source_policy_set_id"])
      .where("session_id", "=", sessionId)
      .where("compaction_id", "=", compaction.id),
  );
  return binding?.authorization_status === "authorized" ? binding.source_policy_set_id : undefined;
}

function isStoredCompactionPolicyAuthorized(params: {
  db: DatabaseSync;
  compactionId: string;
  detail: TranscriptEventMemoryPolicyDetails;
  eventSeq: number;
  policySet: MemoryPolicySets;
  row: TranscriptEventMemoryPolicies;
  sessionId: string;
}): boolean {
  const { db } = params;
  const kysely = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(db);
  const binding = executeSqliteQueryTakeFirstSync(
    db,
    kysely
      .selectFrom("memory_compaction_policy_bindings")
      .selectAll()
      .where("session_id", "=", params.sessionId)
      .where("compaction_id", "=", params.compactionId),
  );
  if (
    !binding ||
    binding.authorization_status !== "authorized" ||
    !params.row.source_policy_set_id ||
    !params.row.delivery_audiences_json
  ) {
    return false;
  }
  const sourceEventSeqs = parseCanonicalMemoryStringArray(binding.source_event_seqs_json)?.map(
    (value) => Number(value),
  );
  if (
    !sourceEventSeqs ||
    sourceEventSeqs.length === 0 ||
    sourceEventSeqs.some(
      (sourceEventSeq) =>
        !Number.isSafeInteger(sourceEventSeq) ||
        sourceEventSeq < 0 ||
        sourceEventSeq >= params.eventSeq,
    )
  ) {
    return false;
  }
  const sourcePolicySetIds = [params.row.source_policy_set_id];
  for (const sourceEventSeq of sourceEventSeqs) {
    if (!isStoredTranscriptEventAuthorized(db, params.sessionId, sourceEventSeq)) {
      return false;
    }
    const sourcePolicySetId = readEffectiveTranscriptEventPolicySetId(
      db,
      params.sessionId,
      sourceEventSeq,
    );
    if (!sourcePolicySetId) {
      return false;
    }
    sourcePolicySetIds.push(sourcePolicySetId);
  }
  const sourceFacts = sourcePolicySetIds.map((policySetId) =>
    readStoredPolicySetFacts(db, policySetId),
  );
  if (!sourceFacts.every((source): source is StoredPolicySetFacts => source !== undefined)) {
    return false;
  }
  const derived = createDerivedCompactionPolicySet({
    agentId: params.policySet.agent_id,
    compactionId: params.compactionId,
    eventSeq: params.eventSeq,
    sessionId: params.sessionId,
    sources: sourceFacts,
  });
  const deliveryAudiences = parseCanonicalMemoryAudiences(params.row.delivery_audiences_json);
  const persisted = derived
    ? readStoredPolicySetFacts(db, binding.source_policy_set_id)
    : undefined;
  return Boolean(
    derived &&
    persisted &&
    binding.source_policy_set_id === derived.policySetId &&
    binding.policy_set_revision === derived.policySetRevision &&
    persisted.policySet.agent_id === params.policySet.agent_id &&
    persisted.policySet.memory_policy_revision === derived.memoryPolicyRevision &&
    persisted.metadata.policy_set_revision === derived.policySetRevision &&
    sameMemoryStringArrays(persisted.sourcePolicySetIds, derived.sourcePolicySetIds) &&
    equalMemoryAudiences(persisted.audiences, derived.audiences) &&
    samePolicySetRequirements(persisted.requirements, derived.requirements) &&
    hasCurrentPolicyRequirements({
      db,
      agentId: params.policySet.agent_id,
      requirements: persisted.requirements,
    }) &&
    deliveryAudiences?.length &&
    deliveryAudiences.every((audience) =>
      persisted.audiences.some(
        (candidate) => memoryAudienceKey(candidate) === memoryAudienceKey(audience),
      ),
    ) &&
    params.detail.policy_set_revision.trim(),
  );
}

/**
 * Verifies the exact entries a compaction planner will disclose before its
 * summarizer runs. The later persisted binding is evidence, not authorization:
 * by then a compaction model request has already received its transcript input.
 */
export function authorizeTranscriptCompactionSources(params: {
  database: OpenClawAgentDatabase;
  sessionId: string;
  sourceEntryIds: readonly string[];
}): boolean {
  if (!isTranscriptMemoryPolicyEnforcedInDatabase(params.database.db)) {
    return true;
  }
  try {
    const sessionId = params.sessionId.trim();
    const sourceEntryIds = params.sourceEntryIds.map((entryId) => entryId.trim());
    if (
      !sessionId ||
      sourceEntryIds.length === 0 ||
      sourceEntryIds.some((entryId) => !entryId) ||
      new Set(sourceEntryIds).size !== sourceEntryIds.length
    ) {
      return false;
    }
    const label = readCurrentTranscriptMemoryPolicyLabel({
      agentId: params.database.agentId,
      sessionId,
    });
    if (
      !label ||
      !labelMatchesExposure(label, params.database.agentId) ||
      !labelHasPreparedPolicy(label)
    ) {
      return false;
    }
    const deliveryAudiences = parseCanonicalMemoryAudiences(label.deliveryAudiencesJson);
    if (!deliveryAudiences?.length) {
      return false;
    }
    const db = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(params.database.db);
    const sourceEventSeqs: number[] = [];
    for (const entryId of sourceEntryIds) {
      const identity = executeSqliteQueryTakeFirstSync(
        params.database.db,
        db
          .selectFrom("transcript_event_identities")
          .select("seq")
          .where("session_id", "=", sessionId)
          .where("event_id", "=", entryId),
      );
      if (
        !identity ||
        !Number.isSafeInteger(identity.seq) ||
        identity.seq < 0 ||
        !isStoredTranscriptEventAuthorized(params.database.db, sessionId, identity.seq)
      ) {
        return false;
      }
      sourceEventSeqs.push(identity.seq);
    }
    const sources = sourceEventSeqs.map((eventSeq) => {
      const policySetId = readEffectiveTranscriptEventPolicySetId(
        params.database.db,
        sessionId,
        eventSeq,
      );
      return policySetId ? readStoredPolicySetFacts(params.database.db, policySetId) : undefined;
    });
    if (!sources.every((source): source is StoredPolicySetFacts => source !== undefined)) {
      return false;
    }
    const audiences = intersectCompactionAudiences(sources);
    const requirements = mergeCompactionPolicyRequirements(sources);
    return Boolean(
      audiences?.length &&
      requirements &&
      hasCurrentPolicyRequirements({
        db: params.database.db,
        agentId: params.database.agentId,
        requirements,
      }) &&
      deliveryAudiences.every((audience) =>
        audiences.some((candidate) => memoryAudienceKey(candidate) === memoryAudienceKey(audience)),
      ),
    );
  } catch {
    // Missing policy evidence cannot safely defer an egress authorization decision.
    return false;
  }
}

export type PreservedTranscriptMemoryPolicy = {
  detail: TranscriptEventMemoryPolicyDetails;
  lineage: {
    created_at: number;
    event_seq: number;
    origin_event_seq: number;
    origin_session_id: string;
    session_id: string;
    source_event_seq: number;
    source_session_id: string;
    transition_kind: TranscriptMemoryPolicyTransitionKind;
  };
  policy: TranscriptEventMemoryPolicies;
};

/** Immutable source-row evidence for rebuilding a sequence-bound compaction companion. */
export type PreservedTranscriptCompactionPolicy = Readonly<{
  compactionId: string;
  eventSeq: number;
  sourceEventSeqs: readonly number[];
}>;

/** One archived transcript row's immutable, currently-evaluable policy evidence. */
export type TranscriptMemoryArchivePolicySnapshot = Readonly<{
  eventSeq: number;
  preserved: PreservedTranscriptMemoryPolicy;
}>;

/** Portable policy evidence for a transcript export, never reconstructed from event payloads. */
export type TranscriptMemoryPolicyExportManifest = Readonly<{
  /** Optional so earlier manifests remain safe inputs; absent bindings leave summaries pending. */
  compactionBindings?: readonly PreservedTranscriptCompactionPolicy[];
  events: readonly TranscriptMemoryPolicyExportEvent[];
  schemaVersion: 1;
  sessionId: string;
}>;

type TranscriptMemoryPolicyExportEvent = Readonly<{
  contentSha256: string;
  eventSeq: number;
  preserved: PreservedTranscriptMemoryPolicy;
}>;

/**
 * Captures only currently evaluable companions before a same-database rewrite.
 * Rewrites may move sequence numbers, but must never turn historic payloads
 * into a fresh authorization decision based on the replacement caller.
 */
export function captureAuthorizedTranscriptMemoryPoliciesInTransaction(params: {
  database: OpenClawAgentDatabase;
  sessionId: string;
}): Map<number, PreservedTranscriptMemoryPolicy> | undefined {
  if (!isTranscriptMemoryPolicyEnforcedInDatabase(params.database.db)) {
    return undefined;
  }
  const db = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(params.database.db);
  const policyRows = executeSqliteQuerySync(
    params.database.db,
    db
      .selectFrom("transcript_event_memory_policies")
      .selectAll()
      .where("session_id", "=", params.sessionId),
  ).rows;
  const policies = new Map<number, PreservedTranscriptMemoryPolicy>();
  for (const policy of policyRows) {
    if (
      !isStoredTranscriptEventAuthorized(params.database.db, params.sessionId, policy.event_seq)
    ) {
      continue;
    }
    const detail = executeSqliteQueryTakeFirstSync(
      params.database.db,
      db
        .selectFrom("transcript_event_memory_policy_details")
        .selectAll()
        .where("session_id", "=", params.sessionId)
        .where("event_seq", "=", policy.event_seq),
    );
    const lineage = executeSqliteQueryTakeFirstSync(
      params.database.db,
      db
        .selectFrom("transcript_event_memory_policy_lineage")
        .selectAll()
        .where("session_id", "=", params.sessionId)
        .where("event_seq", "=", policy.event_seq),
    );
    if (!detail || !lineage) {
      continue;
    }
    policies.set(policy.event_seq, {
      detail,
      lineage: {
        created_at: lineage.created_at,
        event_seq: lineage.event_seq,
        origin_event_seq: lineage.origin_event_seq,
        origin_session_id: lineage.origin_session_id,
        session_id: lineage.session_id,
        source_event_seq: lineage.source_event_seq,
        source_session_id: lineage.source_session_id,
        transition_kind: lineage.transition_kind as TranscriptMemoryPolicyTransitionKind,
      },
      policy,
    });
  }
  return policies;
}

/** Captures only compaction bindings that still authorize their source rows. */
export function captureAuthorizedTranscriptCompactionPoliciesInTransaction(params: {
  database: OpenClawAgentDatabase;
  sessionId: string;
}): Map<number, PreservedTranscriptCompactionPolicy> | undefined {
  if (!isTranscriptMemoryPolicyEnforcedInDatabase(params.database.db)) {
    return undefined;
  }
  const db = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(params.database.db);
  const policies = executeSqliteQuerySync(
    params.database.db,
    db
      .selectFrom("transcript_event_memory_policies")
      .select("event_seq")
      .where("session_id", "=", params.sessionId)
      .orderBy("event_seq", "asc"),
  ).rows;
  const captured = new Map<number, PreservedTranscriptCompactionPolicy>();
  for (const policy of policies) {
    const compaction = readTranscriptCompactionIdentity(
      params.database.db,
      params.sessionId,
      policy.event_seq,
    );
    if (
      !compaction ||
      !isStoredTranscriptEventAuthorized(params.database.db, params.sessionId, policy.event_seq)
    ) {
      continue;
    }
    const binding = executeSqliteQueryTakeFirstSync(
      params.database.db,
      db
        .selectFrom("memory_compaction_policy_bindings")
        .select(["authorization_status", "source_event_seqs_json"])
        .where("session_id", "=", params.sessionId)
        .where("compaction_id", "=", compaction.id),
    );
    const sourceEventSeqs = binding
      ? parseCanonicalMemoryStringArray(binding.source_event_seqs_json)
          ?.map((value) => Number(value))
          .toSorted((left, right) => left - right)
      : undefined;
    if (
      binding?.authorization_status !== "authorized" ||
      !sourceEventSeqs ||
      sourceEventSeqs.length === 0 ||
      sourceEventSeqs.some(
        (sourceEventSeq) =>
          !Number.isSafeInteger(sourceEventSeq) ||
          sourceEventSeq < 0 ||
          sourceEventSeq >= policy.event_seq,
      )
    ) {
      continue;
    }
    captured.set(policy.event_seq, {
      compactionId: compaction.id,
      eventSeq: policy.event_seq,
      sourceEventSeqs,
    });
  }
  return captured;
}

/** Removes non-FK compaction rows before a transcript owner is replaced or reclaimed. */
export function clearTranscriptCompactionPoliciesInTransaction(params: {
  compactionId?: string;
  database: OpenClawAgentDatabase;
  sessionId: string;
}): void {
  if (!isTranscriptMemoryPolicyEnforcedInDatabase(params.database.db)) {
    return;
  }
  const compactionId = params.compactionId?.trim();
  if (params.compactionId !== undefined && !compactionId) {
    return;
  }
  const query = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(params.database.db)
    .deleteFrom("memory_compaction_policy_bindings")
    .where("session_id", "=", params.sessionId);
  executeSqliteQuerySync(
    params.database.db,
    compactionId ? query.where("compaction_id", "=", compactionId) : query,
  );
}

/** Rebuilds only bindings whose captured output and every captured source mapped exactly. */
export function rebuildTranscriptCompactionPoliciesInTransaction(params: {
  captured: ReadonlyMap<number, PreservedTranscriptCompactionPolicy> | undefined;
  database: OpenClawAgentDatabase;
  eventSeqBySourceEventSeq: ReadonlyMap<number, number>;
  sessionId: string;
}): void {
  if (!isTranscriptMemoryPolicyEnforcedInDatabase(params.database.db) || !params.captured) {
    return;
  }
  for (const [, captured] of [...params.captured].toSorted(([left], [right]) => left - right)) {
    const eventSeq = params.eventSeqBySourceEventSeq.get(captured.eventSeq);
    if (eventSeq === undefined) {
      continue;
    }
    const sourceEventSeqs: number[] = [];
    for (const sourceEventSeq of captured.sourceEventSeqs) {
      const mappedSourceEventSeq = params.eventSeqBySourceEventSeq.get(sourceEventSeq);
      if (mappedSourceEventSeq === undefined) {
        break;
      }
      sourceEventSeqs.push(mappedSourceEventSeq);
    }
    const compaction = readTranscriptCompactionIdentity(
      params.database.db,
      params.sessionId,
      eventSeq,
    );
    if (
      compaction?.id !== captured.compactionId ||
      sourceEventSeqs.length !== captured.sourceEventSeqs.length ||
      !recordTranscriptCompactionPolicyInTransaction({
        compactionId: captured.compactionId,
        database: params.database,
        eventSeq,
        sessionId: params.sessionId,
        sourceEventSeqs,
      })
    ) {
      // A replay that cannot prove the old sequence graph must never keep a
      // summary visible merely because its payload still names old source ids.
      invalidateTranscriptMemoryPolicyInTransaction({
        database: params.database,
        eventSeq,
        sessionId: params.sessionId,
      });
    }
  }
}

/** Captures the policy companions that may safely leave the live transcript as an archive. */
export function captureAuthorizedTranscriptMemoryArchivePoliciesInTransaction(params: {
  database: OpenClawAgentDatabase;
  sessionId: string;
}): readonly TranscriptMemoryArchivePolicySnapshot[] | undefined {
  const policies = captureAuthorizedTranscriptMemoryPoliciesInTransaction(params);
  return policies
    ? [...policies.entries()]
        .toSorted(([leftEventSeq], [rightEventSeq]) => leftEventSeq - rightEventSeq)
        .map(([eventSeq, preserved]) => ({ eventSeq, preserved }))
    : undefined;
}

/** Returns only the current-policy-evaluable companions for a portable export. */
export function readTranscriptMemoryPolicyExportManifestFromDatabase(params: {
  beforeEventSeq?: number;
  database: OpenClawAgentDatabase;
  sessionId: string;
}): TranscriptMemoryPolicyExportManifest | undefined {
  const policies = captureAuthorizedTranscriptMemoryPoliciesInTransaction(params);
  if (!policies) {
    return undefined;
  }
  const db = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(params.database.db);
  const events = executeSqliteQuerySync(
    params.database.db,
    db
      .selectFrom("transcript_events")
      .select(["event_json", "seq"])
      .where("session_id", "=", params.sessionId)
      .$if(params.beforeEventSeq !== undefined, (query) =>
        query.where("seq", "<", params.beforeEventSeq!),
      )
      .orderBy("seq", "asc"),
  ).rows.flatMap((row): TranscriptMemoryPolicyExportEvent[] => {
    const preserved = policies.get(row.seq);
    return preserved
      ? [
          {
            contentSha256: createHash("sha256").update(row.event_json, "utf8").digest("hex"),
            eventSeq: row.seq,
            preserved,
          },
        ]
      : [];
  });
  const compactionBindings = captureAuthorizedTranscriptCompactionPoliciesInTransaction(params);
  return {
    ...(compactionBindings?.size ? { compactionBindings: [...compactionBindings.values()] } : {}),
    events,
    schemaVersion: 1,
    sessionId: params.sessionId,
  };
}

function archivePolicySnapshotsEqual(
  left: readonly TranscriptMemoryArchivePolicySnapshot[],
  right: readonly TranscriptMemoryArchivePolicySnapshot[],
): boolean {
  return (
    left.length === right.length &&
    left.every(
      (entry, index) =>
        entry.eventSeq === right[index]?.eventSeq &&
        JSON.stringify(entry.preserved) === JSON.stringify(right[index]?.preserved),
    )
  );
}

function archivedPolicyRowsMatchSnapshots(params: {
  rows: ReadonlyArray<{
    actor_evidence_json: string;
    archive_event_index: number;
    context_fingerprint: string;
    delegation_json: string;
    delivery_audiences_json: string;
    detail_created_at: number;
    exposed_resource_revisions_json: string;
    finalized_egress_audiences_json: string;
    lineage_created_at: number;
    origin_event_seq: number;
    origin_session_id: string;
    policy_created_at: number;
    policy_set_revision: string;
    run_exposure_revision: number;
    run_exposure_set_id: string;
    run_id: string;
    session_identity_revision: string;
    source_event_seq: number;
    source_lineage_event_seq: number;
    source_policy_set_id: string;
    source_session_id: string;
    subject_revision: string;
    transition_kind: string;
  }>;
  snapshots: readonly TranscriptMemoryArchivePolicySnapshot[];
}): boolean {
  return (
    params.rows.length === params.snapshots.length &&
    params.rows.every((row, index) => {
      const snapshot = params.snapshots[index];
      const policy = snapshot?.preserved.policy;
      const detail = snapshot?.preserved.detail;
      const lineage = snapshot?.preserved.lineage;
      return Boolean(
        snapshot &&
        policy &&
        detail &&
        lineage &&
        row.archive_event_index === index &&
        row.source_event_seq === snapshot.eventSeq &&
        row.source_policy_set_id === policy.source_policy_set_id &&
        row.run_exposure_set_id === policy.run_exposure_set_id &&
        row.run_exposure_revision === policy.run_exposure_revision &&
        row.delivery_audiences_json === policy.delivery_audiences_json &&
        row.session_identity_revision === policy.session_identity_revision &&
        row.subject_revision === policy.subject_revision &&
        row.run_id === policy.run_id &&
        row.context_fingerprint === policy.context_fingerprint &&
        row.policy_set_revision === detail.policy_set_revision &&
        row.actor_evidence_json === detail.actor_evidence_json &&
        row.delegation_json === detail.delegation_json &&
        row.finalized_egress_audiences_json === detail.finalized_egress_audiences_json &&
        row.exposed_resource_revisions_json === detail.exposed_resource_revisions_json &&
        row.source_session_id === lineage.source_session_id &&
        row.source_lineage_event_seq === lineage.source_event_seq &&
        row.origin_session_id === lineage.origin_session_id &&
        row.origin_event_seq === lineage.origin_event_seq &&
        row.transition_kind === lineage.transition_kind &&
        row.policy_created_at === policy.created_at &&
        row.detail_created_at === detail.created_at &&
        row.lineage_created_at === lineage.created_at,
      );
    })
  );
}

/**
 * Records an archive's companion rows before its live source rows are reclaimed.
 * The artifact was materialized outside this transaction; this synchronous check
 * binds its exact bytes to the same policy snapshot that authorized extraction.
 */
export function persistTranscriptMemoryArchiveInTransaction(params: {
  archivePath: string;
  content: string;
  database: OpenClawAgentDatabase;
  reason: "bak" | "deleted" | "reset";
  sessionId: string;
  snapshots: readonly TranscriptMemoryArchivePolicySnapshot[];
}): boolean {
  if (!isTranscriptMemoryPolicyEnforcedInDatabase(params.database.db)) {
    return true;
  }
  const current = captureAuthorizedTranscriptMemoryArchivePoliciesInTransaction({
    database: params.database,
    sessionId: params.sessionId,
  });
  if (!current || !archivePolicySnapshotsEqual(current, params.snapshots)) {
    return false;
  }
  const db = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(params.database.db);
  const contentHash = createHash("sha256").update(params.content, "utf8").digest("hex");
  executeSqliteQuerySync(
    params.database.db,
    db
      .insertInto("transcript_memory_archives")
      .values({
        archive_path: params.archivePath,
        source_session_id: params.sessionId,
        archive_reason: params.reason,
        content_sha256: contentHash,
        created_at: Date.now(),
      })
      .onConflict((conflict) => conflict.column("archive_path").doNothing()),
  );
  const archive = executeSqliteQueryTakeFirstSync(
    params.database.db,
    db
      .selectFrom("transcript_memory_archives")
      .selectAll()
      .where("archive_path", "=", params.archivePath),
  );
  if (
    !archive ||
    archive.source_session_id !== params.sessionId ||
    archive.archive_reason !== params.reason ||
    archive.content_sha256 !== contentHash
  ) {
    return false;
  }
  const existingRows = executeSqliteQuerySync(
    params.database.db,
    db
      .selectFrom("transcript_memory_archive_events")
      .selectAll()
      .where("archive_path", "=", params.archivePath)
      .orderBy("archive_event_index", "asc"),
  ).rows;
  if (existingRows.length > 0) {
    return archivedPolicyRowsMatchSnapshots({ rows: existingRows, snapshots: params.snapshots });
  }
  for (const [archiveEventIndex, snapshot] of params.snapshots.entries()) {
    const { policy, detail, lineage } = snapshot.preserved;
    if (
      policy.authorization_status !== "authorized" ||
      policy.source_policy_set_id === null ||
      policy.run_exposure_set_id === null ||
      policy.run_exposure_revision === null ||
      policy.delivery_audiences_json === null ||
      policy.session_identity_revision === null ||
      policy.subject_revision === null ||
      policy.run_id === null ||
      policy.context_fingerprint === null
    ) {
      return false;
    }
    executeSqliteQuerySync(
      params.database.db,
      db.insertInto("transcript_memory_archive_events").values({
        archive_path: params.archivePath,
        archive_event_index: archiveEventIndex,
        source_event_seq: snapshot.eventSeq,
        source_policy_set_id: policy.source_policy_set_id,
        run_exposure_set_id: policy.run_exposure_set_id,
        run_exposure_revision: policy.run_exposure_revision,
        delivery_audiences_json: policy.delivery_audiences_json,
        session_identity_revision: policy.session_identity_revision,
        subject_revision: policy.subject_revision,
        run_id: policy.run_id,
        context_fingerprint: policy.context_fingerprint,
        policy_set_revision: detail.policy_set_revision,
        actor_evidence_json: detail.actor_evidence_json,
        delegation_json: detail.delegation_json,
        finalized_egress_audiences_json: detail.finalized_egress_audiences_json,
        exposed_resource_revisions_json: detail.exposed_resource_revisions_json,
        source_session_id: lineage.source_session_id,
        source_lineage_event_seq: lineage.source_event_seq,
        origin_session_id: lineage.origin_session_id,
        origin_event_seq: lineage.origin_event_seq,
        transition_kind: lineage.transition_kind,
        policy_created_at: policy.created_at,
        detail_created_at: detail.created_at,
        lineage_created_at: lineage.created_at,
      }),
    );
  }
  const persistedRows = executeSqliteQuerySync(
    params.database.db,
    db
      .selectFrom("transcript_memory_archive_events")
      .selectAll()
      .where("archive_path", "=", params.archivePath)
      .orderBy("archive_event_index", "asc"),
  ).rows;
  return archivedPolicyRowsMatchSnapshots({ rows: persistedRows, snapshots: params.snapshots });
}

/** Restores an exact, still-evaluable policy companion after a guarded rewrite. */
export function restoreTranscriptMemoryPolicyInTransaction(params: {
  database: OpenClawAgentDatabase;
  preserved: PreservedTranscriptMemoryPolicy;
  sessionId: string;
  eventSeq: number;
}): boolean {
  if (!isTranscriptMemoryPolicyEnforcedInDatabase(params.database.db)) {
    return true;
  }
  const db = getNodeSqliteKysely<TranscriptMemoryPolicyDatabase>(params.database.db);
  const target = executeSqliteQueryTakeFirstSync(
    params.database.db,
    db
      .selectFrom("transcript_event_memory_policies")
      .select("authorization_status")
      .where("session_id", "=", params.sessionId)
      .where("event_seq", "=", params.eventSeq),
  );
  if (!target || target.authorization_status !== "pending") {
    return false;
  }
  executeSqliteQuerySync(
    params.database.db,
    db
      .updateTable("transcript_event_memory_policies")
      .set({
        authorization_status: params.preserved.policy.authorization_status,
        source_policy_set_id: params.preserved.policy.source_policy_set_id,
        run_exposure_set_id: params.preserved.policy.run_exposure_set_id,
        run_exposure_revision: params.preserved.policy.run_exposure_revision,
        delivery_audiences_json: params.preserved.policy.delivery_audiences_json,
        session_identity_revision: params.preserved.policy.session_identity_revision,
        subject_revision: params.preserved.policy.subject_revision,
        run_id: params.preserved.policy.run_id,
        context_fingerprint: params.preserved.policy.context_fingerprint,
        created_at: params.preserved.policy.created_at,
      })
      .where("session_id", "=", params.sessionId)
      .where("event_seq", "=", params.eventSeq)
      .where("authorization_status", "=", "pending"),
  );
  executeSqliteQuerySync(
    params.database.db,
    db.insertInto("transcript_event_memory_policy_details").values({
      session_id: params.sessionId,
      event_seq: params.eventSeq,
      policy_set_revision: params.preserved.detail.policy_set_revision,
      actor_evidence_json: params.preserved.detail.actor_evidence_json,
      delegation_json: params.preserved.detail.delegation_json,
      finalized_egress_audiences_json: params.preserved.detail.finalized_egress_audiences_json,
      exposed_resource_revisions_json: params.preserved.detail.exposed_resource_revisions_json,
      origin_session_id: params.preserved.detail.origin_session_id,
      origin_event_seq: params.preserved.detail.origin_event_seq,
      created_at: params.preserved.detail.created_at,
    }),
  );
  executeSqliteQuerySync(
    params.database.db,
    db.insertInto("transcript_event_memory_policy_lineage").values({
      session_id: params.sessionId,
      event_seq: params.eventSeq,
      source_session_id: params.preserved.lineage.source_session_id,
      source_event_seq: params.preserved.lineage.source_event_seq,
      origin_session_id: params.preserved.lineage.origin_session_id,
      origin_event_seq: params.preserved.lineage.origin_event_seq,
      transition_kind: params.preserved.lineage.transition_kind,
      created_at: params.preserved.lineage.created_at,
    }),
  );
  return isStoredTranscriptEventAuthorized(params.database.db, params.sessionId, params.eventSeq);
}

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
