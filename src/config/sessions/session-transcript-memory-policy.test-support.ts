import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createEffectiveMemoryPolicySetId } from "../../plugins/memory-invocation-serialization.js";
import {
  setTranscriptMemoryPolicyLabelReader,
  type TranscriptMemoryPolicyLabel,
} from "../../plugins/memory-transcript-policy-label.js";
import {
  closeOpenClawAgentDatabasesForTest,
  openOpenClawAgentDatabase,
} from "../../state/openclaw-agent-db.js";
import "./session-transcript-memory-policy.js";

type TranscriptMemoryPolicyTesting = {
  resetDatabase(db: import("node:sqlite").DatabaseSync): void;
};

function getTesting(): TranscriptMemoryPolicyTesting {
  return (globalThis as Record<PropertyKey, unknown>)[
    Symbol.for("openclaw.transcriptMemoryPolicyTestApi")
  ] as TranscriptMemoryPolicyTesting;
}

export const transcriptMemoryPolicyTesting: TranscriptMemoryPolicyTesting = {
  resetDatabase: (db) => getTesting().resetDatabase(db),
};

type TestScope = {
  agentId: string;
  env: NodeJS.ProcessEnv;
  sessionId: string;
  sessionKey: string;
};

export function createTranscriptMemoryPolicyTestHarness(): {
  cleanup(): Promise<void>;
  createScope(label: string): Promise<TestScope>;
  trackTempDir(dir: string): void;
} {
  const tempDirs: string[] = [];
  return {
    async cleanup(): Promise<void> {
      setTranscriptMemoryPolicyLabelReader(() => undefined);
      closeOpenClawAgentDatabasesForTest();
      await Promise.all(
        tempDirs.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })),
      );
    },
    async createScope(label: string): Promise<TestScope> {
      const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), `openclaw-memory-policy-${label}-`));
      tempDirs.push(stateDir);
      const agentId = `agent-${label}`;
      return {
        agentId,
        env: { OPENCLAW_STATE_DIR: stateDir },
        sessionId: `session-${label}`,
        sessionKey: `agent:${agentId}:dashboard:${label}`,
      };
    },
    trackTempDir(dir: string): void {
      tempDirs.push(dir);
    },
  };
}

export function insertCutover(scope: TestScope): ReturnType<typeof openOpenClawAgentDatabase> {
  const database = openOpenClawAgentDatabase({ agentId: scope.agentId, env: scope.env });
  database.db
    .prepare(
      `INSERT INTO memory_migrations
        (migration_id, source_kind, source_hash, phase, classification_json, plan_hash,
         verified_at, cutover_at, updated_at)
       VALUES (?, ?, ?, 'cutover', '{}', ?, 1, 1, 1)`,
    )
    .run(`migration-${scope.agentId}`, "test", `source-${scope.agentId}`, `plan-${scope.agentId}`);
  transcriptMemoryPolicyTesting.resetDatabase(database.db);
  return database;
}

export function insertPolicyFixture(params: {
  scope: TestScope;
  eventSeq: number;
  labelRunId?: string;
  stablePolicyId?: string;
  policyRevisionId?: string;
  memoryPolicyRevision?: string;
  memberPolicySetIds?: readonly string[];
  audiences?: readonly { kind: string; id: string }[];
  policySetRevision?: string;
  exposureSetId?: string;
  exposureRunId?: string;
}): void {
  const database = openOpenClawAgentDatabase({
    agentId: params.scope.agentId,
    env: params.scope.env,
  });
  const snapshot = database.db
    .prepare(
      `SELECT session_identity_revision, subject_revision
         FROM session_memory_subject_snapshots
        WHERE session_id = ?`,
    )
    .get(params.scope.sessionId) as
    | { session_identity_revision: string; subject_revision: string }
    | undefined;
  if (!snapshot) {
    throw new Error("missing test subject snapshot");
  }
  const stablePolicyId = params.stablePolicyId ?? "stable-policy-1";
  const policyRevisionId = params.policyRevisionId ?? "stable-policy-revision-1";
  const memoryPolicyRevision = params.memoryPolicyRevision ?? "policy-revision-1";
  const memberPolicySetIds = params.memberPolicySetIds ?? ["source-policy-1"];
  const policySetId = createEffectiveMemoryPolicySetId({
    memoryPolicyRevision,
    memberPolicySetIds,
  });
  const exposureSetId = params.exposureSetId ?? "exposure-set-1";
  const exposureRunId = params.exposureRunId ?? "run-1";
  const policySetRevision = params.policySetRevision ?? "policy-set-revision-1";
  const audiencesJson = JSON.stringify(params.audiences ?? [{ kind: "user", id: "principal-1" }]);
  database.db
    .prepare(
      `INSERT OR IGNORE INTO memory_policies
        (policy_id, agent_id, current_revision_id, revocation_epoch, lifecycle_state, created_at, updated_at)
       VALUES (?, ?, ?, 0, 'active', 1, 1)`,
    )
    .run(stablePolicyId, params.scope.agentId, policyRevisionId);
  database.db
    .prepare(
      `INSERT OR IGNORE INTO memory_policy_revisions
        (revision_id, policy_id, revision_number, revocation_epoch, lifecycle_state,
         actor_kind, actor_id, reason, created_at)
       VALUES (?, ?, 1, 0, 'active', 'system', NULL, 'test', 1)`,
    )
    .run(policyRevisionId, stablePolicyId);
  database.db
    .prepare(
      `INSERT OR IGNORE INTO memory_policy_sets
        (policy_set_id, agent_id, memory_policy_revision, member_policy_set_ids_json, created_at)
       VALUES (?, ?, ?, ?, 1)`,
    )
    .run(
      policySetId,
      params.scope.agentId,
      memoryPolicyRevision,
      JSON.stringify(memberPolicySetIds),
    );
  database.db
    .prepare(
      `INSERT OR IGNORE INTO memory_policy_set_metadata
        (policy_set_id, policy_set_revision, source_policy_set_ids_json,
         normalized_audience_intersection_json, retention_state, created_at)
       VALUES (?, ?, ?, ?, 'active', 1)`,
    )
    .run(policySetId, policySetRevision, JSON.stringify(memberPolicySetIds), audiencesJson);
  database.db
    .prepare(
      `INSERT OR IGNORE INTO memory_policy_set_requirements
        (policy_set_id, stable_policy_id, captured_revision_id, expected_active_revision_id,
         expected_revocation_epoch)
       VALUES (?, ?, ?, ?, 0)`,
    )
    .run(policySetId, stablePolicyId, policyRevisionId, policyRevisionId);
  database.db
    .prepare(
      `INSERT OR IGNORE INTO memory_run_exposures
        (exposure_set_id, agent_id, run_id, context_fingerprint, plan_id, revision_number,
         previous_exposure_set_id, source_policy_set_ids_json, effective_source_policy_set_id,
         exposed_resource_revisions_json, exposure_receipt_ids_json, egress_receipt_ids_json,
         delivery_audiences_json, delivery_revision, egress_registry_revision, created_at)
       VALUES (?, ?, ?, 'context-1', 'plan-1', 1, NULL, ?, ?, '[]', '[]', '[]', ?,
               'delivery-1', 'registry-1', 1)`,
    )
    .run(
      exposureSetId,
      params.scope.agentId,
      exposureRunId,
      JSON.stringify(memberPolicySetIds),
      policySetId,
      audiencesJson,
    );
  database.db
    .prepare(
      `INSERT INTO transcript_event_memory_policies
        (session_id, event_seq, authorization_status, source_policy_set_id,
         run_exposure_set_id, run_exposure_revision, delivery_audiences_json,
         session_identity_revision, subject_revision, run_id, context_fingerprint, created_at)
       VALUES (?, ?, 'authorized', ?, ?, 1, ?, ?, ?, ?, 'context-1', 1)`,
    )
    .run(
      params.scope.sessionId,
      params.eventSeq,
      policySetId,
      exposureSetId,
      audiencesJson,
      snapshot.session_identity_revision,
      snapshot.subject_revision,
      params.labelRunId ?? exposureRunId,
    );
  database.db
    .prepare(
      `INSERT INTO transcript_event_memory_policy_details
        (session_id, event_seq, policy_set_revision, actor_evidence_json, delegation_json,
         finalized_egress_audiences_json, exposed_resource_revisions_json,
         origin_session_id, origin_event_seq, created_at)
       VALUES (?, ?, ?, '{}', 'null', ?, '[]', ?, ?, 1)`,
    )
    .run(
      params.scope.sessionId,
      params.eventSeq,
      policySetRevision,
      audiencesJson,
      params.scope.sessionId,
      params.eventSeq,
    );
  database.db
    .prepare(
      `INSERT INTO transcript_event_memory_policy_lineage
        (session_id, event_seq, source_session_id, source_event_seq,
         origin_session_id, origin_event_seq, transition_kind, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'append', 1)`,
    )
    .run(
      params.scope.sessionId,
      params.eventSeq,
      params.scope.sessionId,
      params.eventSeq,
      params.scope.sessionId,
      params.eventSeq,
    );
}

export function setCurrentCompactionPolicyLabel(params: {
  audiences?: readonly { kind: string; id: string }[];
  scope: TestScope;
}): void {
  const audiences = params.audiences ?? [{ kind: "user", id: "principal-1" }];
  const sourcePolicySetIds = ["source-policy-1"];
  const memoryPolicyRevision = "policy-revision-1";
  const sourcePolicySetId = createEffectiveMemoryPolicySetId({
    memoryPolicyRevision,
    memberPolicySetIds: sourcePolicySetIds,
  });
  const deliveryAudiencesJson = JSON.stringify(audiences);
  const database = openOpenClawAgentDatabase({
    agentId: params.scope.agentId,
    env: params.scope.env,
  });
  const snapshot = database.db
    .prepare(
      `SELECT session_identity_revision, subject_revision
         FROM session_memory_subject_snapshots
        WHERE session_id = ?`,
    )
    .get(params.scope.sessionId) as
    | { session_identity_revision: string; subject_revision: string }
    | undefined;
  if (!snapshot) {
    throw new Error("missing test subject snapshot");
  }
  const label = {
    sourcePolicySetId,
    policySetRevision: "policy-set-revision-1",
    runExposureSetId: "exposure-set-1",
    runExposureRevision: 1,
    deliveryAudiencesJson,
    actorEvidenceJson: "{}",
    delegationJson: "null",
    finalizedEgressAudiencesJson: deliveryAudiencesJson,
    exposedResourceRevisionsJson: "[]",
    sessionIdentityRevision: snapshot.session_identity_revision,
    subjectRevision: snapshot.subject_revision,
    runId: "run-1",
    contextFingerprint: "context-1",
    runExposure: {
      exposureSetId: "exposure-set-1",
      revisionNumber: 1,
      agentId: params.scope.agentId,
      runId: "run-1",
      contextFingerprint: "context-1",
      planId: "plan-1",
      memoryPolicyRevision,
      sourcePolicySetIdsJson: JSON.stringify(sourcePolicySetIds),
      effectiveSourcePolicySetId: sourcePolicySetId,
      exposedResourceRevisionsJson: "[]",
      exposureReceiptIdsJson: "[]",
      egressReceiptIdsJson: "[]",
      deliveryAudiencesJson,
      deliveryRevision: "delivery-1",
      egressRegistryRevision: "registry-1",
      createdAt: 1,
    },
    transcriptPolicy: {
      version: 1,
      policySetId: sourcePolicySetId,
      policySetRevision: "policy-set-revision-1",
      sourcePolicySetIds,
      normalizedAudienceIntersection: audiences,
      retentionState: "active",
      requirements: [
        {
          stablePolicyId: "stable-policy-1",
          capturedRevisionId: "stable-policy-revision-1",
          expectedActiveRevisionId: "stable-policy-revision-1",
          expectedRevocationEpoch: 0,
        },
      ],
    },
  } as TranscriptMemoryPolicyLabel;
  setTranscriptMemoryPolicyLabelReader(({ agentId, sessionId }) =>
    agentId === params.scope.agentId && sessionId === params.scope.sessionId ? label : undefined,
  );
}
