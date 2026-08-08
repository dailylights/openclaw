import type { DatabaseSync } from "node:sqlite";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
} from "../../infra/kysely-sync.js";
import type { AudienceRef } from "../../memory-host-sdk/host/authorization.js";
import {
  canonicalMemoryAudiencesJson,
  canonicalMemoryStringArrayJson,
  createEffectiveMemoryPolicySetId,
  equalMemoryAudiences,
  hashMemoryRevision,
  parseCanonicalMemoryAudiences,
  parseCanonicalMemoryStringArray,
} from "../../plugins/memory-invocation-serialization.js";
import { readCurrentTranscriptMemoryPolicyLabel } from "../../plugins/memory-transcript-policy-label.js";
import type {
  MemoryPolicySetMetadata,
  MemoryPolicySetRequirements,
  MemoryPolicySets,
  TranscriptEventMemoryPolicyDetails,
  TranscriptEventMemoryPolicies,
} from "../../state/openclaw-agent-db.generated.js";
import type { OpenClawAgentDatabase } from "../../state/openclaw-agent-db.js";
import {
  type TranscriptMemoryPolicyDatabase,
  hasCurrentPolicyRequirements,
  isAuthorizedTranscriptPolicyBinding,
  isTranscriptMemoryPolicyEnforcedInDatabase,
  labelHasPreparedPolicy,
  labelMatchesExposure,
} from "./session-transcript-memory-policy-core.js";

export type StoredPolicySetFacts = Readonly<{
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

export function memoryAudienceKey(audience: AudienceRef): string {
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

export function readStoredPolicySetFacts(
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

export function createDerivedCompactionPolicySet(params: {
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

export function persistDerivedCompactionPolicySetInTransaction(params: {
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

export function isStoredTranscriptEventAuthorized(
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

export function readTranscriptCompactionIdentity(
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

export function readEffectiveTranscriptEventPolicySetId(
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
