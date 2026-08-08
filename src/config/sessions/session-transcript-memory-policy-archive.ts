import { createHash } from "node:crypto";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
} from "../../infra/kysely-sync.js";
import { parseCanonicalMemoryStringArray } from "../../plugins/memory-invocation-serialization.js";
import type {
  TranscriptEventMemoryPolicyDetails,
  TranscriptEventMemoryPolicies,
} from "../../state/openclaw-agent-db.generated.js";
import type { OpenClawAgentDatabase } from "../../state/openclaw-agent-db.js";
import {
  isStoredTranscriptEventAuthorized,
  readTranscriptCompactionIdentity,
} from "./session-transcript-memory-policy-authorization.js";
import {
  type TranscriptMemoryPolicyDatabase,
  isTranscriptMemoryPolicyEnforcedInDatabase,
} from "./session-transcript-memory-policy-core.js";
import {
  invalidateTranscriptMemoryPolicyInTransaction,
  recordTranscriptCompactionPolicyInTransaction,
  type TranscriptMemoryPolicyTransitionKind,
} from "./session-transcript-memory-policy-operations.js";

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
