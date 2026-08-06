import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createEffectiveMemoryPolicySetId } from "../../plugins/memory-invocation-serialization.js";
import {
  setTranscriptMemoryPolicyLabelReader,
  type TranscriptMemoryPolicyLabel,
} from "../../plugins/memory-transcript-policy-label.js";
import {
  closeOpenClawAgentDatabasesForTest,
  openOpenClawAgentDatabase,
  runOpenClawAgentWriteTransaction,
} from "../../state/openclaw-agent-db.js";
import { readSessionArchiveContentSync } from "./archive-compression.js";
import {
  appendTranscriptMessage,
  forkSessionAtMessage,
  forkSessionFromParentTranscript,
  loadTranscriptEvents,
  readCurrentSessionMemorySubject,
  readTranscriptMemoryPolicyExportManifest,
  readTranscriptRawDelta,
  readTranscriptStatsSync,
  replaceSessionEntry,
  replaceTranscriptEvents,
  upsertSessionEntry,
  withTranscriptWriteLock,
} from "./session-accessor.js";
import { materializeSqliteSessionStateDeletePlans } from "./session-accessor.sqlite-archive.js";
import { copySqliteSessionOwnedStateForCanonicalRepair } from "./session-accessor.sqlite-canonical-repair.js";
import { importSqliteSessionRows } from "./session-accessor.sqlite-import.js";
import {
  deleteMaterializedSqliteSessionStatePlans,
  planSqliteSessionStateDeleteIfUnreferenced,
} from "./session-accessor.sqlite-lifecycle-state.js";
import { resolveSqliteScope, toDatabaseOptions } from "./session-accessor.sqlite-scope.js";
import {
  createTranscriptMemoryPolicyRewriteBinding,
  replaceSqliteTranscriptEventsInTransaction,
  rewriteSqliteTranscriptEventRowsInTransaction,
} from "./session-accessor.sqlite-transcript-store.js";
import { replaceSqliteTranscriptEvents } from "./session-accessor.sqlite-transcript-write.js";
import { prepareSessionMemorySubjectLineageSeed } from "./session-memory-subject.js";
import {
  authorizeTranscriptCompactionSources,
  copyTranscriptMemoryPolicyInTransaction,
  recordTranscriptCompactionPolicyInTransaction,
} from "./session-transcript-memory-policy.js";
import { transcriptMemoryPolicyTesting } from "./session-transcript-memory-policy.test-support.js";

type TestScope = {
  agentId: string;
  env: NodeJS.ProcessEnv;
  sessionId: string;
  sessionKey: string;
};

const tempDirs: string[] = [];

async function createScope(label: string): Promise<TestScope> {
  const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), `openclaw-memory-policy-${label}-`));
  tempDirs.push(stateDir);
  const agentId = `agent-${label}`;
  return {
    agentId,
    env: { OPENCLAW_STATE_DIR: stateDir },
    sessionId: `session-${label}`,
    sessionKey: `agent:${agentId}:dashboard:${label}`,
  };
}

function insertCutover(scope: TestScope): ReturnType<typeof openOpenClawAgentDatabase> {
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

function insertPolicyFixture(params: {
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

function setCurrentCompactionPolicyLabel(params: {
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

describe("transcript memory policy", () => {
  afterEach(async () => {
    setTranscriptMemoryPolicyLabelReader(() => undefined);
    closeOpenClawAgentDatabasesForTest();
    await Promise.all(
      tempDirs.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })),
    );
  });

  it("hides missing, mismatched, and pending labels behind a dense v2 cursor", async () => {
    const scope = await createScope("visibility");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    for (const [eventId, content] of [
      ["message-1", "missing label"],
      ["message-2", "mismatched label"],
      ["message-3", "authorized content"],
    ] as const) {
      await appendTranscriptMessage(scope, {
        eventId,
        message: { role: "user", content },
      });
    }
    const legacyPage = readTranscriptRawDelta(scope, { maxEvents: 20, maxBytes: 100_000 });
    expect(legacyPage.kind).toBe("page");
    if (legacyPage.kind !== "page") {
      throw new Error("expected legacy cursor page");
    }

    insertCutover(scope);
    insertPolicyFixture({ scope, eventSeq: 0 });
    insertPolicyFixture({ scope, eventSeq: 2, labelRunId: "wrong-run" });
    insertPolicyFixture({ scope, eventSeq: 3 });
    await appendTranscriptMessage(scope, {
      eventId: "message-4",
      message: { role: "user", content: "pending content" },
    });

    expect(readTranscriptRawDelta(scope, { cursor: legacyPage.cursor })).toMatchObject({
      kind: "reset",
      reason: "invalid_cursor",
    });
    const first = readTranscriptRawDelta(scope, { maxEvents: 1, maxBytes: 100_000 });
    expect(first).toMatchObject({ kind: "page", hasMore: true });
    if (first.kind !== "page") {
      throw new Error("expected first enforced cursor page");
    }
    expect(first.events).toHaveLength(1);
    expect(first.events[0]?.seq).toBe(0);
    const decodedCursor = JSON.parse(Buffer.from(first.cursor, "base64url").toString("utf8")) as {
      version?: unknown;
      lastSeq?: unknown;
    };
    expect(decodedCursor).toMatchObject({ version: 2 });
    expect(decodedCursor).not.toHaveProperty("lastSeq");

    const second = readTranscriptRawDelta(scope, {
      cursor: first.cursor,
      maxEvents: 1,
      maxBytes: 100_000,
    });
    expect(second).toMatchObject({ kind: "page", hasMore: false });
    if (second.kind !== "page") {
      throw new Error("expected second enforced cursor page");
    }
    expect(second.events).toHaveLength(1);
    expect(second.events[0]?.seq).toBe(1);
    expect(second.events[0]?.event).toMatchObject({ id: "message-3" });
    expect(
      (await loadTranscriptEvents(scope)).map((event) => (event as { id?: string }).id),
    ).toEqual([scope.sessionId, "message-3"]);
    expect(readTranscriptStatsSync(scope)).toMatchObject({ eventCount: 2, maxSeq: 1 });

    const database = openOpenClawAgentDatabase({ agentId: scope.agentId, env: scope.env });
    expect(
      database.db
        .prepare(
          `SELECT authorization_status
             FROM transcript_event_memory_policies
            WHERE session_id = ? AND event_seq = 4`,
        )
        .get(scope.sessionId),
    ).toEqual({ authorization_status: "pending" });
  });

  it("rolls back the transcript row when its companion write fails", async () => {
    const scope = await createScope("atomicity");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "existing-message",
      message: { role: "user", content: "existing" },
    });
    const database = insertCutover(scope);
    const before = database.db
      .prepare("SELECT COUNT(*) AS count FROM transcript_events WHERE session_id = ?")
      .get(scope.sessionId) as { count: number };
    database.db.exec(`
      CREATE TRIGGER reject_test_memory_policy
      BEFORE INSERT ON transcript_event_memory_policies
      BEGIN
        SELECT RAISE(ABORT, 'companion write blocked');
      END;
    `);

    await expect(
      appendTranscriptMessage(scope, {
        eventId: "rolled-back-message",
        message: { role: "user", content: "must not persist" },
      }),
    ).rejects.toThrow("companion write blocked");

    expect(
      database.db
        .prepare("SELECT COUNT(*) AS count FROM transcript_events WHERE session_id = ?")
        .get(scope.sessionId),
    ).toEqual(before);
    expect(
      database.db
        .prepare("SELECT 1 FROM transcript_events WHERE session_id = ? AND event_json LIKE ?")
        .get(scope.sessionId, "%rolled-back-message%"),
    ).toBeUndefined();
  });

  it("invalidates captured policy labels after a stable policy is revoked", async () => {
    const scope = await createScope("revoked");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "revoked-message",
      message: { role: "user", content: "must disappear after revocation" },
    });
    const database = insertCutover(scope);
    insertPolicyFixture({ scope, eventSeq: 0 });
    insertPolicyFixture({ scope, eventSeq: 1 });

    expect(
      (await loadTranscriptEvents(scope)).map((event) => (event as { id?: string }).id),
    ).toEqual([scope.sessionId, "revoked-message"]);

    database.db
      .prepare(
        "UPDATE memory_policies SET revocation_epoch = 1, updated_at = 2 WHERE policy_id = 'stable-policy-1'",
      )
      .run();

    await expect(loadTranscriptEvents(scope)).resolves.toEqual([]);
  });

  it("invalidates captured policy labels after their stable policy advances revision", async () => {
    const scope = await createScope("revised");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "revised-message",
      message: { role: "user", content: "must disappear after revision change" },
    });
    const database = insertCutover(scope);
    insertPolicyFixture({ scope, eventSeq: 0 });
    insertPolicyFixture({ scope, eventSeq: 1 });

    await expect(loadTranscriptEvents(scope)).resolves.toHaveLength(2);

    database.db
      .prepare(
        "UPDATE memory_policies SET current_revision_id = 'stable-policy-revision-2', updated_at = 2 WHERE policy_id = 'stable-policy-1'",
      )
      .run();

    await expect(loadTranscriptEvents(scope)).resolves.toEqual([]);
  });

  it("requires a compaction record that remains bound to authorized source events", async () => {
    const scope = await createScope("compaction-policy");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "compaction-source-user",
      message: { role: "user", content: "source user" },
    });
    await appendTranscriptMessage(scope, {
      eventId: "compaction-source-assistant",
      message: { role: "assistant", content: "source assistant" },
    });
    await replaceSqliteTranscriptEvents(scope, [
      ...(await loadTranscriptEvents(scope)),
      {
        firstKeptEntryId: "compaction-source-user",
        id: "compaction-policy-event",
        parentId: "compaction-source-assistant",
        summary: "authorized source summary",
        tokensBefore: 10,
        type: "compaction",
      },
    ]);
    const database = insertCutover(scope);
    for (const eventSeq of [0, 1, 2, 3]) {
      insertPolicyFixture({ scope, eventSeq });
    }
    runOpenClawAgentWriteTransaction(
      (writeDatabase) => {
        expect(
          recordTranscriptCompactionPolicyInTransaction({
            compactionId: "compaction-policy-event",
            database: writeDatabase,
            eventSeq: 3,
            sessionId: scope.sessionId,
            sourceEventSeqs: [0, 1, 2],
          }),
        ).toBe(true);
      },
      { agentId: scope.agentId, env: scope.env },
    );

    expect(
      database.db
        .prepare(
          `SELECT authorization_status, policy_set_revision, source_event_seqs_json, source_policy_set_id
             FROM memory_compaction_policy_bindings
            WHERE session_id = ? AND compaction_id = ?`,
        )
        .get(scope.sessionId, "compaction-policy-event"),
    ).toMatchObject({
      authorization_status: "authorized",
      source_event_seqs_json: '["0","1","2"]',
    });
    const binding = database.db
      .prepare(
        `SELECT policy_set_revision, source_policy_set_id
           FROM memory_compaction_policy_bindings
          WHERE session_id = ? AND compaction_id = ?`,
      )
      .get(scope.sessionId, "compaction-policy-event") as {
      policy_set_revision: string;
      source_policy_set_id: string;
    };
    expect(binding.source_policy_set_id).not.toBe(
      createEffectiveMemoryPolicySetId({
        memoryPolicyRevision: "policy-revision-1",
        memberPolicySetIds: ["source-policy-1"],
      }),
    );
    expect(
      database.db
        .prepare(
          `SELECT normalized_audience_intersection_json, policy_set_revision, source_policy_set_ids_json
             FROM memory_policy_set_metadata
            WHERE policy_set_id = ?`,
        )
        .get(binding.source_policy_set_id),
    ).toEqual({
      normalized_audience_intersection_json: '[{"kind":"user","id":"principal-1"}]',
      policy_set_revision: binding.policy_set_revision,
      source_policy_set_ids_json: JSON.stringify([
        createEffectiveMemoryPolicySetId({
          memoryPolicyRevision: "policy-revision-1",
          memberPolicySetIds: ["source-policy-1"],
        }),
      ]),
    });
    await expect(loadTranscriptEvents(scope)).resolves.toHaveLength(4);

    database.db
      .prepare(
        "UPDATE memory_policies SET revocation_epoch = 1, updated_at = 2 WHERE policy_id = 'stable-policy-1'",
      )
      .run();
    await expect(loadTranscriptEvents(scope)).resolves.toEqual([]);
  });

  it("authorizes only exact planner sources for the current delivery audience", async () => {
    const scope = await createScope("compaction-preflight");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "preflight-source-user",
      message: { role: "user", content: "source user" },
    });
    await appendTranscriptMessage(scope, {
      eventId: "preflight-source-assistant",
      message: { role: "assistant", content: "source assistant" },
    });
    await replaceSqliteTranscriptEvents(scope, [
      ...(await loadTranscriptEvents(scope)),
      {
        firstKeptEntryId: "preflight-source-assistant",
        id: "preflight-compaction",
        parentId: "preflight-source-assistant",
        sourceEntryIds: ["preflight-source-user", "preflight-source-assistant"],
        summary: "authorized source summary",
        tokensBefore: 10,
        type: "compaction",
      },
    ]);
    const database = insertCutover(scope);
    insertPolicyFixture({ scope, eventSeq: 1 });
    insertPolicyFixture({ scope, eventSeq: 2 });
    insertPolicyFixture({ scope, eventSeq: 3 });
    setCurrentCompactionPolicyLabel({ scope });

    expect(
      authorizeTranscriptCompactionSources({
        database,
        sessionId: scope.sessionId,
        sourceEntryIds: ["preflight-source-user", "preflight-source-assistant"],
      }),
    ).toBe(true);
    expect(
      authorizeTranscriptCompactionSources({
        database,
        sessionId: scope.sessionId,
        sourceEntryIds: ["preflight-source-user", "missing-source"],
      }),
    ).toBe(false);

    setCurrentCompactionPolicyLabel({
      scope,
      audiences: [{ kind: "conversation", id: "outside-common-audience" }],
    });
    expect(
      authorizeTranscriptCompactionSources({
        database,
        sessionId: scope.sessionId,
        sourceEntryIds: ["preflight-source-user", "preflight-source-assistant"],
      }),
    ).toBe(false);

    setCurrentCompactionPolicyLabel({ scope });
    runOpenClawAgentWriteTransaction(
      (writeDatabase) => {
        expect(
          recordTranscriptCompactionPolicyInTransaction({
            compactionId: "preflight-compaction",
            database: writeDatabase,
            eventSeq: 3,
            sessionId: scope.sessionId,
            sourceEventSeqs: [1, 2],
          }),
        ).toBe(true);
      },
      { agentId: scope.agentId, env: scope.env },
    );
    const compactionBinding = database.db
      .prepare(
        `SELECT source_event_seqs_json
           FROM memory_compaction_policy_bindings
          WHERE session_id = ? AND compaction_id = ?`,
      )
      .get(scope.sessionId, "preflight-compaction");
    expect(compactionBinding).toEqual({ source_event_seqs_json: '["1","2"]' });

    database.db
      .prepare(
        "UPDATE memory_policies SET revocation_epoch = 1, updated_at = 2 WHERE policy_id = 'stable-policy-1'",
      )
      .run();
    expect(
      authorizeTranscriptCompactionSources({
        database,
        sessionId: scope.sessionId,
        sourceEntryIds: ["preflight-source-user", "preflight-source-assistant"],
      }),
    ).toBe(false);
  });

  it("derives compaction authority from the common source audience and stable requirements", async () => {
    const scope = await createScope("compaction-derived-policy");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "derived-source-user",
      message: { role: "user", content: "source user" },
    });
    await appendTranscriptMessage(scope, {
      eventId: "derived-source-assistant",
      message: { role: "assistant", content: "source assistant" },
    });
    await replaceSqliteTranscriptEvents(scope, [
      ...(await loadTranscriptEvents(scope)),
      {
        firstKeptEntryId: "derived-source-user",
        id: "derived-compaction-event",
        parentId: "derived-source-assistant",
        summary: "authorized source summary",
        tokensBefore: 10,
        type: "compaction",
      },
    ]);
    const database = insertCutover(scope);
    insertPolicyFixture({ scope, eventSeq: 0 });
    insertPolicyFixture({ scope, eventSeq: 1 });
    insertPolicyFixture({
      scope,
      eventSeq: 2,
      stablePolicyId: "stable-policy-conversation",
      policyRevisionId: "stable-policy-conversation-revision-1",
      memoryPolicyRevision: "policy-revision-conversation-1",
      memberPolicySetIds: ["source-policy-conversation"],
      audiences: [
        { kind: "conversation", id: "conversation-1" },
        { kind: "user", id: "principal-1" },
      ],
      policySetRevision: "policy-set-revision-conversation-1",
      exposureSetId: "exposure-set-conversation",
      exposureRunId: "run-conversation",
    });
    insertPolicyFixture({ scope, eventSeq: 3 });

    runOpenClawAgentWriteTransaction(
      (writeDatabase) => {
        expect(
          recordTranscriptCompactionPolicyInTransaction({
            compactionId: "derived-compaction-event",
            database: writeDatabase,
            eventSeq: 3,
            sessionId: scope.sessionId,
            sourceEventSeqs: [0, 1, 2],
          }),
        ).toBe(true);
      },
      { agentId: scope.agentId, env: scope.env },
    );

    const binding = database.db
      .prepare(
        `SELECT source_policy_set_id
           FROM memory_compaction_policy_bindings
          WHERE session_id = ? AND compaction_id = ?`,
      )
      .get(scope.sessionId, "derived-compaction-event") as { source_policy_set_id: string };
    expect(
      database.db
        .prepare(
          `SELECT normalized_audience_intersection_json, source_policy_set_ids_json
             FROM memory_policy_set_metadata
            WHERE policy_set_id = ?`,
        )
        .get(binding.source_policy_set_id),
    ).toEqual({
      normalized_audience_intersection_json: '[{"kind":"user","id":"principal-1"}]',
      source_policy_set_ids_json: JSON.stringify(
        [
          createEffectiveMemoryPolicySetId({
            memoryPolicyRevision: "policy-revision-1",
            memberPolicySetIds: ["source-policy-1"],
          }),
          createEffectiveMemoryPolicySetId({
            memoryPolicyRevision: "policy-revision-conversation-1",
            memberPolicySetIds: ["source-policy-conversation"],
          }),
        ].toSorted(),
      ),
    });
    expect(
      database.db
        .prepare(
          `SELECT stable_policy_id
             FROM memory_policy_set_requirements
            WHERE policy_set_id = ?
            ORDER BY stable_policy_id`,
        )
        .all(binding.source_policy_set_id),
    ).toEqual([
      { stable_policy_id: "stable-policy-1" },
      { stable_policy_id: "stable-policy-conversation" },
    ]);
    await expect(loadTranscriptEvents(scope)).resolves.toHaveLength(4);

    database.db
      .prepare(
        `UPDATE memory_policies
            SET revocation_epoch = 1, updated_at = 2
          WHERE policy_id = 'stable-policy-conversation'`,
      )
      .run();
    await expect(
      loadTranscriptEvents(scope).then((events) =>
        events.map((event) => (event as { id?: string }).id),
      ),
    ).resolves.toEqual([scope.sessionId, "derived-source-user"]);
  });

  it("denies compaction when source audiences have no common target", async () => {
    const scope = await createScope("compaction-mixed-audience");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "mixed-source-user",
      message: { role: "user", content: "source user" },
    });
    await appendTranscriptMessage(scope, {
      eventId: "mixed-source-assistant",
      message: { role: "assistant", content: "source assistant" },
    });
    await replaceSqliteTranscriptEvents(scope, [
      ...(await loadTranscriptEvents(scope)),
      {
        firstKeptEntryId: "mixed-source-user",
        id: "mixed-compaction-event",
        parentId: "mixed-source-assistant",
        summary: "must remain unavailable",
        tokensBefore: 10,
        type: "compaction",
      },
    ]);
    insertCutover(scope);
    insertPolicyFixture({ scope, eventSeq: 0 });
    insertPolicyFixture({ scope, eventSeq: 1 });
    insertPolicyFixture({
      scope,
      eventSeq: 2,
      stablePolicyId: "stable-policy-channel",
      policyRevisionId: "stable-policy-channel-revision-1",
      memoryPolicyRevision: "policy-revision-channel-1",
      memberPolicySetIds: ["source-policy-channel"],
      audiences: [{ kind: "conversation", id: "conversation-1" }],
      policySetRevision: "policy-set-revision-channel-1",
      exposureSetId: "exposure-set-channel",
      exposureRunId: "run-channel",
    });
    insertPolicyFixture({ scope, eventSeq: 3 });

    runOpenClawAgentWriteTransaction(
      (database) => {
        expect(
          recordTranscriptCompactionPolicyInTransaction({
            compactionId: "mixed-compaction-event",
            database,
            eventSeq: 3,
            sessionId: scope.sessionId,
            sourceEventSeqs: [0, 1, 2],
          }),
        ).toBe(false);
      },
      { agentId: scope.agentId, env: scope.env },
    );
    await expect(
      loadTranscriptEvents(scope).then((events) =>
        events.map((event) => (event as { id?: string }).id),
      ),
    ).resolves.not.toContain("mixed-compaction-event");
  });

  it("keeps identical compaction IDs isolated to their own transcript sessions", async () => {
    const scope = await createScope("compaction-session-binding");
    const target = {
      ...scope,
      sessionId: `${scope.sessionId}-target`,
      sessionKey: `${scope.sessionKey}-target`,
    };
    for (const current of [scope, target]) {
      await upsertSessionEntry(current, {
        sessionFile: "sqlite",
        sessionId: current.sessionId,
        updatedAt: 1,
      });
      await appendTranscriptMessage(current, {
        eventId: "shared-compaction-source-user",
        message: { role: "user", content: "source user" },
      });
      await appendTranscriptMessage(current, {
        eventId: "shared-compaction-source-assistant",
        message: { role: "assistant", content: "source assistant" },
      });
      await replaceSqliteTranscriptEvents(current, [
        ...(await loadTranscriptEvents(current)),
        {
          firstKeptEntryId: "shared-compaction-source-user",
          id: "copied-compaction-id",
          parentId: "shared-compaction-source-assistant",
          summary: "session-specific summary",
          tokensBefore: 10,
          type: "compaction",
        },
      ]);
    }
    const database = insertCutover(scope);
    for (const current of [scope, target]) {
      for (const eventSeq of [0, 1, 2, 3]) {
        insertPolicyFixture({ scope: current, eventSeq });
      }
      runOpenClawAgentWriteTransaction(
        (writeDatabase) => {
          expect(
            recordTranscriptCompactionPolicyInTransaction({
              compactionId: "copied-compaction-id",
              database: writeDatabase,
              eventSeq: 3,
              sessionId: current.sessionId,
              sourceEventSeqs: [0, 1, 2],
            }),
          ).toBe(true);
        },
        { agentId: scope.agentId, env: scope.env },
      );
    }
    expect(
      database.db
        .prepare(
          `SELECT session_id
             FROM memory_compaction_policy_bindings
            WHERE compaction_id = ?
            ORDER BY session_id`,
        )
        .all("copied-compaction-id"),
    ).toEqual([{ session_id: scope.sessionId }, { session_id: target.sessionId }]);
  });

  it("carries a prior summary's derived policy into the next compaction", async () => {
    const scope = await createScope("nested-compaction-policy");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "nested-source-user",
      message: { role: "user", content: "source user" },
    });
    await appendTranscriptMessage(scope, {
      eventId: "nested-source-assistant",
      message: { role: "assistant", content: "source assistant" },
    });
    await replaceSqliteTranscriptEvents(scope, [
      ...(await loadTranscriptEvents(scope)),
      {
        firstKeptEntryId: "nested-source-user",
        id: "nested-compaction-first",
        parentId: "nested-source-assistant",
        summary: "first summary",
        tokensBefore: 10,
        type: "compaction",
      },
      {
        firstKeptEntryId: "nested-source-user",
        id: "nested-compaction-second",
        parentId: "nested-compaction-first",
        summary: "second summary",
        tokensBefore: 20,
        type: "compaction",
      },
    ]);
    const database = insertCutover(scope);
    for (const eventSeq of [0, 1, 2, 3, 4]) {
      insertPolicyFixture({ scope, eventSeq });
    }
    runOpenClawAgentWriteTransaction(
      (writeDatabase) => {
        expect(
          recordTranscriptCompactionPolicyInTransaction({
            compactionId: "nested-compaction-first",
            database: writeDatabase,
            eventSeq: 3,
            sessionId: scope.sessionId,
            sourceEventSeqs: [0, 1, 2],
          }),
        ).toBe(true);
        expect(
          recordTranscriptCompactionPolicyInTransaction({
            compactionId: "nested-compaction-second",
            database: writeDatabase,
            eventSeq: 4,
            sessionId: scope.sessionId,
            sourceEventSeqs: [0, 1, 2, 3],
          }),
        ).toBe(true);
      },
      { agentId: scope.agentId, env: scope.env },
    );
    const first = database.db
      .prepare(
        `SELECT source_policy_set_id
           FROM memory_compaction_policy_bindings
          WHERE session_id = ? AND compaction_id = ?`,
      )
      .get(scope.sessionId, "nested-compaction-first") as { source_policy_set_id: string };
    const second = database.db
      .prepare(
        `SELECT source_policy_set_id
           FROM memory_compaction_policy_bindings
          WHERE session_id = ? AND compaction_id = ?`,
      )
      .get(scope.sessionId, "nested-compaction-second") as { source_policy_set_id: string };
    expect(
      database.db
        .prepare(
          `SELECT source_policy_set_ids_json
             FROM memory_policy_set_metadata
            WHERE policy_set_id = ?`,
        )
        .get(second.source_policy_set_id),
    ).toEqual({
      source_policy_set_ids_json: JSON.stringify(
        [
          first.source_policy_set_id,
          createEffectiveMemoryPolicySetId({
            memoryPolicyRevision: "policy-revision-1",
            memberPolicySetIds: ["source-policy-1"],
          }),
        ].toSorted(),
      ),
    });
  });

  it("preserves a copied event's origin policy lineage without reauthorizing it", async () => {
    const scope = await createScope("copy");
    const target = {
      ...scope,
      sessionId: `${scope.sessionId}-target`,
      sessionKey: `${scope.sessionKey}-target`,
    };
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await upsertSessionEntry(target, {
      sessionFile: "sqlite",
      sessionId: target.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "copied-message",
      message: { role: "user", content: "copied source" },
    });
    insertCutover(scope);
    insertPolicyFixture({ scope, eventSeq: 0 });
    insertPolicyFixture({ scope, eventSeq: 1 });
    await appendTranscriptMessage(target, {
      eventId: "copied-message",
      message: { role: "user", content: "copied source" },
    });

    runOpenClawAgentWriteTransaction(
      (database) => {
        expect(
          copyTranscriptMemoryPolicyInTransaction({
            database,
            sourceSessionId: scope.sessionId,
            sourceEventSeq: 1,
            targetSessionId: target.sessionId,
            targetEventSeq: 1,
            transitionKind: "fork",
            createdAt: 2,
          }),
        ).toBe(true);
      },
      { agentId: scope.agentId, env: scope.env },
    );

    expect(
      (await loadTranscriptEvents(target)).map((event) => (event as { id?: string }).id),
    ).toEqual(["copied-message"]);
    const database = openOpenClawAgentDatabase({ agentId: scope.agentId, env: scope.env });
    expect(
      database.db
        .prepare(
          `SELECT source_session_id, source_event_seq, origin_session_id, origin_event_seq, transition_kind
             FROM transcript_event_memory_policy_lineage
            WHERE session_id = ? AND event_seq = 1`,
        )
        .get(target.sessionId),
    ).toEqual({
      source_session_id: scope.sessionId,
      source_event_seq: 1,
      origin_session_id: scope.sessionId,
      origin_event_seq: 1,
      transition_kind: "fork",
    });
  });

  it("preserves authorized companions through a same-database parent fork retry", async () => {
    const scope = await createScope("same-database-fork");
    const childSessionId = `${scope.sessionId}-child`;
    const childSessionKey = `${scope.sessionKey}-child`;
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "source-user",
      message: { role: "user", content: "forked source prompt" },
    });
    await appendTranscriptMessage(scope, {
      eventId: "source-assistant",
      message: { role: "assistant", content: "forked source response" },
    });
    await replaceTranscriptEvents(scope, [
      ...(await loadTranscriptEvents(scope)),
      {
        firstKeptEntryId: "source-user",
        id: "forked-compaction",
        parentId: "source-assistant",
        sourceEntryIds: ["source-user", "source-assistant"],
        summary: "forked summary",
        tokensBefore: 10,
        type: "compaction",
      },
    ]);
    const database = insertCutover(scope);
    for (const eventSeq of [0, 1, 2, 3]) {
      insertPolicyFixture({ scope, eventSeq });
    }
    runOpenClawAgentWriteTransaction(
      (writeDatabase) => {
        expect(
          recordTranscriptCompactionPolicyInTransaction({
            compactionId: "forked-compaction",
            database: writeDatabase,
            eventSeq: 3,
            sessionId: scope.sessionId,
            sourceEventSeqs: [1, 2],
          }),
        ).toBe(true);
      },
      { agentId: scope.agentId, env: scope.env },
    );

    const forked = await forkSessionFromParentTranscript({
      agentId: scope.agentId,
      parentEntry: { sessionId: scope.sessionId, updatedAt: 1 },
      parentSessionKey: scope.sessionKey,
      sessionKey: childSessionKey,
      storePath: database.path,
      targetSessionId: childSessionId,
    });
    if (forked.status !== "created") {
      throw new Error("expected same-database parent fork");
    }

    await expect(
      loadTranscriptEvents({
        agentId: scope.agentId,
        env: scope.env,
        sessionId: childSessionId,
        sessionKey: childSessionKey,
        storePath: database.path,
      }),
    ).resolves.toMatchObject([
      { id: "source-user" },
      { id: "source-assistant" },
      { id: "forked-compaction" },
    ]);
    expect(
      database.db
        .prepare(
          `SELECT event_seq, source_session_id, source_event_seq, origin_session_id,
                  origin_event_seq, transition_kind
             FROM transcript_event_memory_policy_lineage
            WHERE session_id = ?
            ORDER BY event_seq ASC`,
        )
        .all(childSessionId),
    ).toEqual([
      {
        event_seq: 1,
        source_session_id: scope.sessionId,
        source_event_seq: 1,
        origin_session_id: scope.sessionId,
        origin_event_seq: 1,
        transition_kind: "fork",
      },
      {
        event_seq: 2,
        source_session_id: scope.sessionId,
        source_event_seq: 2,
        origin_session_id: scope.sessionId,
        origin_event_seq: 2,
        transition_kind: "fork",
      },
      {
        event_seq: 3,
        source_session_id: scope.sessionId,
        source_event_seq: 3,
        origin_session_id: scope.sessionId,
        origin_event_seq: 3,
        transition_kind: "fork",
      },
    ]);
    expect(
      database.db
        .prepare(
          `SELECT source_event_seqs_json
             FROM memory_compaction_policy_bindings
            WHERE session_id = ? AND compaction_id = ?`,
        )
        .get(childSessionId, "forked-compaction"),
    ).toEqual({ source_event_seqs_json: '["1","2"]' });
    await expect(
      loadTranscriptEvents({
        agentId: scope.agentId,
        env: scope.env,
        sessionId: childSessionId,
        sessionKey: childSessionKey,
        storePath: database.path,
      }).then((events) => events.map((event) => (event as { id?: string }).id)),
    ).resolves.toContain("forked-compaction");

    const replayed = await forkSessionFromParentTranscript({
      agentId: scope.agentId,
      parentEntry: { sessionId: scope.sessionId, updatedAt: 1 },
      parentSessionKey: scope.sessionKey,
      sessionKey: childSessionKey,
      storePath: database.path,
      targetSessionId: childSessionId,
    });
    expect(replayed.status).toBe("created");
    expect(
      database.db
        .prepare(
          `SELECT source_event_seqs_json
             FROM memory_compaction_policy_bindings
            WHERE session_id = ? AND compaction_id = ?`,
        )
        .get(childSessionId, "forked-compaction"),
    ).toEqual({ source_event_seqs_json: '["1","2"]' });
    await expect(
      loadTranscriptEvents({
        agentId: scope.agentId,
        env: scope.env,
        sessionId: childSessionId,
        sessionKey: childSessionKey,
        storePath: database.path,
      }).then((events) => events.map((event) => (event as { id?: string }).id)),
    ).resolves.toContain("forked-compaction");
  });

  it("blocks message forks for cutover sessions", async () => {
    const scope = await createScope("message-cut-fork");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "message-cut-user-1",
      message: { role: "user", content: "first visible prompt" },
    });
    await appendTranscriptMessage(scope, {
      eventId: "message-cut-assistant-1",
      message: { role: "assistant", content: "first visible response" },
      parentId: "message-cut-user-1",
    });
    await appendTranscriptMessage(scope, {
      eventId: "message-cut-user-2",
      message: { role: "user", content: "edited prompt" },
      parentId: "message-cut-assistant-1",
    });
    const database = insertCutover(scope);
    for (const eventSeq of [0, 1, 2, 3]) {
      insertPolicyFixture({ scope, eventSeq });
    }

    const originalStateDir = process.env.OPENCLAW_STATE_DIR;
    process.env.OPENCLAW_STATE_DIR = scope.env.OPENCLAW_STATE_DIR;
    try {
      const fork = await forkSessionAtMessage({
        agentId: scope.agentId,
        env: scope.env,
        entryId: "message-cut-user-2",
        sessionKey: scope.sessionKey,
        targetKey: `agent:${scope.agentId}:dashboard:message-cut-child`,
      });
      expect(fork.status).toBe("failed");
      expect(
        database.db
          .prepare("SELECT COUNT(*) AS count FROM session_windows WHERE session_key = ?")
          .get(`agent:${scope.agentId}:dashboard:message-cut-child`),
      ).toEqual({ count: 0 });
    } finally {
      if (originalStateDir === undefined) {
        delete process.env.OPENCLAW_STATE_DIR;
      } else {
        process.env.OPENCLAW_STATE_DIR = originalStateDir;
      }
    }
  });

  it("persists immutable policy lineage with an archive before reclaiming source rows", async () => {
    const scope = await createScope("archive-lineage");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "archive-message",
      message: { role: "user", content: "retained with its policy lineage" },
    });
    const database = insertCutover(scope);
    insertPolicyFixture({ scope, eventSeq: 0 });
    insertPolicyFixture({ scope, eventSeq: 1 });

    const plan = planSqliteSessionStateDeleteIfUnreferenced({
      archiveDirectory: path.join(scope.env.OPENCLAW_STATE_DIR ?? "", "archives"),
      archiveTranscript: true,
      database,
      reason: "deleted",
      referencedSessionIds: new Set(),
      sessionId: scope.sessionId,
    });
    expect(readTranscriptMemoryPolicyExportManifest(scope)).toMatchObject({
      sessionId: scope.sessionId,
      events: [
        { eventSeq: 0, preserved: { lineage: { transition_kind: "append" } } },
        { eventSeq: 1, preserved: { lineage: { transition_kind: "append" } } },
      ],
    });
    expect(plan?.archivePolicySnapshots?.map((snapshot) => snapshot.eventSeq)).toEqual([0, 1]);
    if (!plan) {
      throw new Error("expected an archive deletion plan");
    }
    const [materialized] = await materializeSqliteSessionStateDeletePlans([plan]);
    if (!materialized?.archivedTranscript) {
      throw new Error("expected a materialized archive");
    }

    runOpenClawAgentWriteTransaction(
      (transactionDb) => {
        expect(
          deleteMaterializedSqliteSessionStatePlans(
            transactionDb,
            [materialized],
            undefined,
            new Set([scope.sessionKey]),
          ),
        ).toHaveLength(1);
      },
      { agentId: scope.agentId, env: scope.env },
    );

    expect(
      database.db
        .prepare(
          "SELECT COUNT(*) AS count FROM transcript_event_memory_policies WHERE session_id = ?",
        )
        .get(scope.sessionId),
    ).toEqual({ count: 0 });
    expect(
      database.db
        .prepare(
          `SELECT source_session_id, archive_reason
             FROM transcript_memory_archives
            WHERE archive_path = ?`,
        )
        .get(materialized.archivedTranscript.archivedPath),
    ).toEqual({ source_session_id: scope.sessionId, archive_reason: "deleted" });
    expect(
      database.db
        .prepare(
          `SELECT archive_event_index, source_event_seq, source_policy_set_id,
                  source_session_id, origin_session_id, transition_kind
             FROM transcript_memory_archive_events
            WHERE archive_path = ?
            ORDER BY archive_event_index ASC`,
        )
        .all(materialized.archivedTranscript.archivedPath),
    ).toEqual([
      expect.objectContaining({
        archive_event_index: 0,
        source_event_seq: 0,
        source_session_id: scope.sessionId,
        origin_session_id: scope.sessionId,
        transition_kind: "append",
      }),
      expect.objectContaining({
        archive_event_index: 1,
        source_event_seq: 1,
        source_session_id: scope.sessionId,
        origin_session_id: scope.sessionId,
        transition_kind: "append",
      }),
    ]);
  });

  it("cleans a compaction binding only after its authorized archive is durable", async () => {
    const scope = await createScope("archive-compaction-cleanup");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "archive-compaction-source",
      message: { role: "user", content: "archived compaction source" },
    });
    await replaceTranscriptEvents(scope, [
      ...(await loadTranscriptEvents(scope)),
      {
        firstKeptEntryId: scope.sessionId,
        id: "archive-compaction",
        parentId: "archive-compaction-source",
        sourceEntryIds: [scope.sessionId, "archive-compaction-source"],
        summary: "archived compaction summary",
        tokensBefore: 10,
        type: "compaction",
      },
    ]);
    const database = insertCutover(scope);
    for (const eventSeq of [0, 1, 2]) {
      insertPolicyFixture({ scope, eventSeq });
    }
    runOpenClawAgentWriteTransaction(
      (writeDatabase) => {
        expect(
          recordTranscriptCompactionPolicyInTransaction({
            compactionId: "archive-compaction",
            database: writeDatabase,
            eventSeq: 2,
            sessionId: scope.sessionId,
            sourceEventSeqs: [0, 1],
          }),
        ).toBe(true);
      },
      { agentId: scope.agentId, env: scope.env },
    );
    const plan = planSqliteSessionStateDeleteIfUnreferenced({
      archiveDirectory: path.join(scope.env.OPENCLAW_STATE_DIR ?? "", "archives"),
      archiveTranscript: true,
      database,
      reason: "deleted",
      referencedSessionIds: new Set(),
      sessionId: scope.sessionId,
    });
    if (!plan) {
      throw new Error("expected an archive deletion plan");
    }
    const [materialized] = await materializeSqliteSessionStateDeletePlans([plan]);
    if (!materialized?.archivedTranscript) {
      throw new Error("expected a materialized archive");
    }
    runOpenClawAgentWriteTransaction(
      (transactionDb) => {
        deleteMaterializedSqliteSessionStatePlans(
          transactionDb,
          [materialized],
          undefined,
          new Set([scope.sessionKey]),
        );
      },
      { agentId: scope.agentId, env: scope.env },
    );

    expect(readSessionArchiveContentSync(materialized.archivedTranscript.archivedPath)).toContain(
      "archived compaction summary",
    );
    expect(
      database.db
        .prepare(
          `SELECT 1
             FROM memory_compaction_policy_bindings
            WHERE session_id = ? AND compaction_id = ?`,
        )
        .get(scope.sessionId, "archive-compaction"),
    ).toBeUndefined();
  });

  it("fails closed when an archive policy changes after materialization", async () => {
    const scope = await createScope("archive-revocation");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "archive-message",
      message: { role: "user", content: "must not be reclaimed after revocation" },
    });
    const database = insertCutover(scope);
    insertPolicyFixture({ scope, eventSeq: 0 });
    insertPolicyFixture({ scope, eventSeq: 1 });
    const plan = planSqliteSessionStateDeleteIfUnreferenced({
      archiveDirectory: path.join(scope.env.OPENCLAW_STATE_DIR ?? "", "archives"),
      archiveTranscript: true,
      database,
      reason: "deleted",
      referencedSessionIds: new Set(),
      sessionId: scope.sessionId,
    });
    if (!plan) {
      throw new Error("expected an archive deletion plan");
    }
    const [materialized] = await materializeSqliteSessionStateDeletePlans([plan]);
    if (!materialized) {
      throw new Error("expected a materialized archive plan");
    }
    database.db
      .prepare(
        "UPDATE memory_policies SET revocation_epoch = 1, updated_at = 2 WHERE policy_id = 'stable-policy-1'",
      )
      .run();

    expect(() =>
      runOpenClawAgentWriteTransaction(
        (transactionDb) => {
          deleteMaterializedSqliteSessionStatePlans(
            transactionDb,
            [materialized],
            undefined,
            new Set([scope.sessionKey]),
          );
        },
        { agentId: scope.agentId, env: scope.env },
      ),
    ).toThrow("SQLite transcript policy changed before archive deletion");
    expect(
      database.db
        .prepare("SELECT COUNT(*) AS count FROM transcript_events WHERE session_id = ?")
        .get(scope.sessionId),
    ).toEqual({ count: 2 });
    expect(
      database.db.prepare("SELECT COUNT(*) AS count FROM transcript_memory_archives").get(),
    ).toEqual({ count: 0 });
  });

  it("excludes pending rows from archive content and companion metadata", async () => {
    const scope = await createScope("archive-pending");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "pending-message",
      message: { role: "user", content: "must not enter the archive" },
    });
    const database = insertCutover(scope);
    insertPolicyFixture({ scope, eventSeq: 0 });

    const plan = planSqliteSessionStateDeleteIfUnreferenced({
      archiveDirectory: path.join(scope.env.OPENCLAW_STATE_DIR ?? "", "archives"),
      archiveTranscript: true,
      database,
      reason: "deleted",
      referencedSessionIds: new Set(),
      sessionId: scope.sessionId,
    });
    expect(plan?.archivePolicySnapshots?.map((snapshot) => snapshot.eventSeq)).toEqual([0]);
    if (!plan) {
      throw new Error("expected an archive deletion plan");
    }
    const [materialized] = await materializeSqliteSessionStateDeletePlans([plan]);
    if (!materialized?.archivedTranscript) {
      throw new Error("expected a materialized archive");
    }
    expect(
      readSessionArchiveContentSync(materialized.archivedTranscript.archivedPath),
    ).not.toContain("pending-message");
    runOpenClawAgentWriteTransaction(
      (transactionDb) => {
        deleteMaterializedSqliteSessionStatePlans(
          transactionDb,
          [materialized],
          undefined,
          new Set([scope.sessionKey]),
        );
      },
      { agentId: scope.agentId, env: scope.env },
    );

    expect(
      database.db
        .prepare(
          `SELECT source_event_seq
             FROM transcript_memory_archive_events
            WHERE archive_path = ?`,
        )
        .all(materialized.archivedTranscript.archivedPath),
    ).toEqual([{ source_event_seq: 0 }]);
  });

  it("restores a confirmed import only when its manifest binds the exact event bytes", async () => {
    const scope = await createScope("confirmed-import");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "confirmed-message",
      message: { role: "user", content: "restore only with companion evidence" },
    });
    await replaceTranscriptEvents(scope, [
      ...(await loadTranscriptEvents(scope)),
      {
        firstKeptEntryId: scope.sessionId,
        id: "confirmed-import-compaction",
        parentId: "confirmed-message",
        sourceEntryIds: [scope.sessionId, "confirmed-message"],
        summary: "restored only through manifest bindings",
        tokensBefore: 10,
        type: "compaction",
      },
    ]);
    const database = insertCutover(scope);
    for (const eventSeq of [0, 1, 2]) {
      insertPolicyFixture({ scope, eventSeq });
    }
    runOpenClawAgentWriteTransaction(
      (writeDatabase) => {
        expect(
          recordTranscriptCompactionPolicyInTransaction({
            compactionId: "confirmed-import-compaction",
            database: writeDatabase,
            eventSeq: 2,
            sessionId: scope.sessionId,
            sourceEventSeqs: [0, 1],
          }),
        ).toBe(true);
      },
      { agentId: scope.agentId, env: scope.env },
    );
    const manifest = readTranscriptMemoryPolicyExportManifest(scope);
    const subject = readCurrentSessionMemorySubject(scope);
    const events = await loadTranscriptEvents(scope);
    if (!manifest || !subject) {
      throw new Error("expected a current-policy manifest and source subject");
    }

    // Keep policy-set and run-exposure history, but make this a genuine import
    // into a newly materialized transcript generation with the same identity.
    database.db.prepare("DELETE FROM session_windows WHERE session_id = ?").run(scope.sessionId);
    const restoreConfirmedImport = () =>
      importSqliteSessionRows({
        agentId: scope.agentId,
        confirmedMemorySubjectLineage: prepareSessionMemorySubjectLineageSeed(subject),
        confirmedTranscriptPolicyManifest: manifest,
        entry: { sessionId: scope.sessionId, updatedAt: 2 },
        env: scope.env,
        readTranscriptEvents(append) {
          for (const event of events) {
            append(event);
          }
        },
        sessionKey: scope.sessionKey,
      });
    await restoreConfirmedImport();

    expect(
      (await loadTranscriptEvents(scope)).map((event) => (event as { id?: string }).id),
    ).toEqual([scope.sessionId, "confirmed-message", "confirmed-import-compaction"]);
    expect(
      database.db
        .prepare(
          `SELECT authorization_status, source_policy_set_id
             FROM transcript_event_memory_policies
            WHERE session_id = ? AND event_seq = 1`,
        )
        .get(scope.sessionId),
    ).toMatchObject({ authorization_status: "authorized" });
    expect(
      database.db
        .prepare(
          `SELECT source_event_seqs_json
             FROM memory_compaction_policy_bindings
            WHERE session_id = ? AND compaction_id = ?`,
        )
        .get(scope.sessionId, "confirmed-import-compaction"),
    ).toEqual({ source_event_seqs_json: '["0","1"]' });
    const repeatedImport = await restoreConfirmedImport();
    expect(repeatedImport.transcriptEvents).toBe(0);
    expect(
      database.db
        .prepare(
          `SELECT source_event_seqs_json
             FROM memory_compaction_policy_bindings
            WHERE session_id = ? AND compaction_id = ?`,
        )
        .get(scope.sessionId, "confirmed-import-compaction"),
    ).toEqual({ source_event_seqs_json: '["0","1"]' });
    await expect(
      loadTranscriptEvents(scope).then((events) =>
        events.map((event) => (event as { id?: string }).id),
      ),
    ).resolves.toContain("confirmed-import-compaction");
  });

  it("requires manifest bindings and round-trips multi-digit compaction source sequences", async () => {
    const scope = await createScope("multi-digit-compaction-import");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    for (let index = 1; index <= 10; index += 1) {
      await appendTranscriptMessage(scope, {
        eventId: `numeric-source-${index}`,
        message: { role: "user", content: `numeric source ${index}` },
      });
    }
    await replaceTranscriptEvents(scope, [
      ...(await loadTranscriptEvents(scope)),
      {
        firstKeptEntryId: "numeric-source-2",
        id: "numeric-compaction",
        parentId: "numeric-source-10",
        sourceEntryIds: ["numeric-source-2", "numeric-source-10"],
        summary: "numeric source sequence summary",
        tokensBefore: 10,
        type: "compaction",
      },
    ]);
    const database = insertCutover(scope);
    for (let eventSeq = 0; eventSeq <= 11; eventSeq += 1) {
      insertPolicyFixture({ scope, eventSeq });
    }
    runOpenClawAgentWriteTransaction(
      (writeDatabase) => {
        expect(
          recordTranscriptCompactionPolicyInTransaction({
            compactionId: "numeric-compaction",
            database: writeDatabase,
            eventSeq: 11,
            sessionId: scope.sessionId,
            sourceEventSeqs: [2, 10],
          }),
        ).toBe(true);
      },
      { agentId: scope.agentId, env: scope.env },
    );
    const staleBinding = database.db
      .prepare(
        `SELECT authorization_status, compaction_id, created_at, policy_set_revision,
                source_event_seqs_json, source_policy_set_id
           FROM memory_compaction_policy_bindings
          WHERE session_id = ? AND compaction_id = ?`,
      )
      .get(scope.sessionId, "numeric-compaction") as
      | {
          authorization_status: string;
          compaction_id: string;
          created_at: number;
          policy_set_revision: string;
          source_event_seqs_json: string;
          source_policy_set_id: string;
        }
      | undefined;
    if (!staleBinding) {
      throw new Error("expected a source compaction binding");
    }
    const manifest = readTranscriptMemoryPolicyExportManifest(scope);
    const subject = readCurrentSessionMemorySubject(scope);
    const events = await loadTranscriptEvents(scope);
    if (!manifest || !subject) {
      throw new Error("expected a current-policy manifest and source subject");
    }
    expect(manifest.compactionBindings).toEqual([
      expect.objectContaining({
        compactionId: "numeric-compaction",
        eventSeq: 11,
        sourceEventSeqs: [2, 10],
      }),
    ]);

    const importTranscript = (confirmedTranscriptPolicyManifest: typeof manifest) =>
      importSqliteSessionRows({
        agentId: scope.agentId,
        confirmedMemorySubjectLineage: prepareSessionMemorySubjectLineageSeed(subject),
        confirmedTranscriptPolicyManifest,
        entry: { sessionId: scope.sessionId, updatedAt: 2 },
        env: scope.env,
        readTranscriptEvents(append) {
          for (const event of events) {
            append(event);
          }
        },
        sessionKey: scope.sessionKey,
      });
    database.db.prepare("DELETE FROM session_windows WHERE session_id = ?").run(scope.sessionId);
    await importTranscript({ ...manifest, compactionBindings: undefined });
    expect(
      database.db
        .prepare(
          `SELECT 1
             FROM memory_compaction_policy_bindings
            WHERE session_id = ? AND compaction_id = ?`,
        )
        .get(scope.sessionId, "numeric-compaction"),
    ).toBeUndefined();
    await expect(
      loadTranscriptEvents(scope).then((events) =>
        events.map((event) => (event as { id?: string }).id),
      ),
    ).resolves.not.toContain("numeric-compaction");

    // A prior partial target can retain this non-FK row after its output event
    // is gone. Continuing an omitted-binding import must not restore through it.
    database.db
      .prepare("DELETE FROM transcript_events WHERE session_id = ? AND seq = ?")
      .run(scope.sessionId, 11);
    database.db
      .prepare(
        `INSERT INTO memory_compaction_policy_bindings
          (authorization_status, compaction_id, created_at, policy_set_revision, session_id,
           source_event_seqs_json, source_policy_set_id)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        staleBinding.authorization_status,
        staleBinding.compaction_id,
        staleBinding.created_at,
        staleBinding.policy_set_revision,
        scope.sessionId,
        staleBinding.source_event_seqs_json,
        staleBinding.source_policy_set_id,
      );
    await importTranscript({ ...manifest, compactionBindings: undefined });
    expect(
      database.db
        .prepare(
          `SELECT 1
             FROM memory_compaction_policy_bindings
            WHERE session_id = ? AND compaction_id = ?`,
        )
        .get(scope.sessionId, "numeric-compaction"),
    ).toBeUndefined();
    await expect(
      loadTranscriptEvents(scope).then((events) =>
        events.map((event) => (event as { id?: string }).id),
      ),
    ).resolves.not.toContain("numeric-compaction");

    database.db.prepare("DELETE FROM session_windows WHERE session_id = ?").run(scope.sessionId);
    await importTranscript(manifest);

    expect(
      database.db
        .prepare(
          `SELECT source_event_seqs_json
             FROM memory_compaction_policy_bindings
            WHERE session_id = ? AND compaction_id = ?`,
        )
        .get(scope.sessionId, "numeric-compaction"),
    ).toEqual({ source_event_seqs_json: '["10","2"]' });
    await expect(
      loadTranscriptEvents(scope).then((events) =>
        events.map((event) => (event as { id?: string }).id),
      ),
    ).resolves.toContain("numeric-compaction");
  });

  it("leaves a manifest-mismatched import pending", async () => {
    const scope = await createScope("mismatched-import");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "confirmed-message",
      message: { role: "user", content: "original bytes" },
    });
    await replaceTranscriptEvents(scope, [
      ...(await loadTranscriptEvents(scope)),
      {
        firstKeptEntryId: scope.sessionId,
        id: "mismatched-import-compaction",
        parentId: "confirmed-message",
        sourceEntryIds: [scope.sessionId, "confirmed-message"],
        summary: "must stay unavailable after tampering",
        tokensBefore: 10,
        type: "compaction",
      },
    ]);
    const database = insertCutover(scope);
    for (const eventSeq of [0, 1, 2]) {
      insertPolicyFixture({ scope, eventSeq });
    }
    runOpenClawAgentWriteTransaction(
      (writeDatabase) => {
        expect(
          recordTranscriptCompactionPolicyInTransaction({
            compactionId: "mismatched-import-compaction",
            database: writeDatabase,
            eventSeq: 2,
            sessionId: scope.sessionId,
            sourceEventSeqs: [0, 1],
          }),
        ).toBe(true);
      },
      { agentId: scope.agentId, env: scope.env },
    );
    const manifest = readTranscriptMemoryPolicyExportManifest(scope);
    const subject = readCurrentSessionMemorySubject(scope);
    const events = await loadTranscriptEvents(scope);
    if (!manifest || !subject) {
      throw new Error("expected a current-policy manifest and source subject");
    }
    database.db.prepare("DELETE FROM session_windows WHERE session_id = ?").run(scope.sessionId);
    await importSqliteSessionRows({
      agentId: scope.agentId,
      confirmedMemorySubjectLineage: prepareSessionMemorySubjectLineageSeed(subject),
      confirmedTranscriptPolicyManifest: manifest,
      entry: { sessionId: scope.sessionId, updatedAt: 2 },
      env: scope.env,
      readTranscriptEvents(append) {
        append(events[0] as object);
        append({
          type: "message",
          id: "confirmed-message",
          parentId: null,
          message: { role: "user", content: "tampered bytes" },
        });
        append(events[2] as object);
      },
      sessionKey: scope.sessionKey,
    });

    expect(await loadTranscriptEvents(scope)).toEqual([events[0]]);
    expect(
      database.db
        .prepare(
          `SELECT authorization_status
             FROM transcript_event_memory_policies
            WHERE session_id = ? AND event_seq = 1`,
        )
        .get(scope.sessionId),
    ).toEqual({ authorization_status: "pending" });
    expect(
      database.db
        .prepare(
          `SELECT 1
             FROM memory_compaction_policy_bindings
            WHERE session_id = ? AND compaction_id = ?`,
        )
        .get(scope.sessionId, "mismatched-import-compaction"),
    ).toBeUndefined();
    expect(
      database.db
        .prepare(
          `SELECT authorization_status
             FROM transcript_event_memory_policies
            WHERE session_id = ? AND event_seq = 2`,
        )
        .get(scope.sessionId),
    ).toEqual({ authorization_status: "pending" });
  });

  it("rejects a manifest whose companion is bound to another source event", async () => {
    const scope = await createScope("mismatched-manifest-sequence");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "confirmed-message",
      message: { role: "user", content: "original bytes" },
    });
    const database = insertCutover(scope);
    insertPolicyFixture({ scope, eventSeq: 0 });
    insertPolicyFixture({ scope, eventSeq: 1 });
    const manifest = readTranscriptMemoryPolicyExportManifest(scope);
    const subject = readCurrentSessionMemorySubject(scope);
    const events = await loadTranscriptEvents(scope);
    if (!manifest || !subject) {
      throw new Error("expected a current-policy manifest and source subject");
    }
    const mismatchedManifest = {
      ...manifest,
      events: manifest.events.map((event) =>
        event.eventSeq === 1 ? { ...event, eventSeq: 2 } : event,
      ),
    };
    database.db.prepare("DELETE FROM session_windows WHERE session_id = ?").run(scope.sessionId);
    await importSqliteSessionRows({
      agentId: scope.agentId,
      confirmedMemorySubjectLineage: prepareSessionMemorySubjectLineageSeed(subject),
      confirmedTranscriptPolicyManifest: mismatchedManifest,
      entry: { sessionId: scope.sessionId, updatedAt: 2 },
      env: scope.env,
      readTranscriptEvents(append) {
        for (const event of events) {
          append(event);
        }
      },
      sessionKey: scope.sessionKey,
    });

    expect(
      database.db
        .prepare(
          `SELECT authorization_status
             FROM transcript_event_memory_policies
            WHERE session_id = ? AND event_seq = 1`,
        )
        .get(scope.sessionId),
    ).toEqual({ authorization_status: "pending" });
  });

  it("keeps cross-database parent forks pending", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-memory-cross-fork-"));
    tempDirs.push(root);
    const sourceStorePath = path.join(root, "source", "sessions.json");
    const targetStorePath = path.join(root, "target", "sessions.json");
    const sourceSessionId = "shared-source-id";
    const sourceSessionKey = "agent:source:parent";
    const targetSessionKey = "agent:target:child";
    await replaceTranscriptEvents(
      {
        agentId: "source",
        sessionId: sourceSessionId,
        sessionKey: sourceSessionKey,
        storePath: sourceStorePath,
      },
      [
        { type: "session", version: 3, id: sourceSessionId },
        {
          type: "message",
          id: "source-message",
          parentId: null,
          message: { role: "user", content: "source content" },
        },
      ],
    );
    await replaceSessionEntry(
      { agentId: "source", sessionKey: sourceSessionKey, storePath: sourceStorePath },
      { sessionId: sourceSessionId, updatedAt: 1 },
    );
    const targetResolved = resolveSqliteScope({
      agentId: "target",
      sessionKey: targetSessionKey,
      storePath: targetStorePath,
    });
    const targetDatabase = openOpenClawAgentDatabase(toDatabaseOptions(targetResolved));
    targetDatabase.db
      .prepare(
        `INSERT INTO memory_migrations
          (migration_id, source_kind, source_hash, phase, classification_json, plan_hash,
           verified_at, cutover_at, updated_at)
         VALUES (?, 'test', ?, 'cutover', '{}', ?, 1, 1, 1)`,
      )
      .run("target-cutover", "target-source", "target-plan");
    transcriptMemoryPolicyTesting.resetDatabase(targetDatabase.db);

    const forked = await forkSessionFromParentTranscript({
      agentId: "source",
      parentEntry: { sessionId: sourceSessionId, updatedAt: 1 },
      parentSessionKey: sourceSessionKey,
      sessionKey: targetSessionKey,
      storePath: sourceStorePath,
      targetStorePath,
    });
    if (forked.status !== "created") {
      throw new Error("expected cross-database parent fork");
    }

    expect(
      targetDatabase.db
        .prepare(
          `SELECT authorization_status
             FROM transcript_event_memory_policies
            WHERE session_id = ?
            ORDER BY event_seq ASC`,
        )
        .all(forked.transcript.sessionId),
    ).toEqual([{ authorization_status: "pending" }]);
  });

  it("clears a destination compaction binding when canonical repair replaces its transcript", async () => {
    const source = await createScope("canonical-repair-source");
    const targetBase = await createScope("canonical-repair-target");
    const target = { ...targetBase, sessionId: source.sessionId };
    await upsertSessionEntry(source, {
      sessionFile: "sqlite",
      sessionId: source.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(source, {
      eventId: "canonical-source-message",
      message: { role: "user", content: "source replacement" },
    });
    await upsertSessionEntry(target, {
      sessionFile: "sqlite",
      sessionId: target.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(target, {
      eventId: "canonical-target-message",
      message: { role: "user", content: "target replacement" },
    });
    await replaceTranscriptEvents(target, [
      ...(await loadTranscriptEvents(target)),
      {
        firstKeptEntryId: target.sessionId,
        id: "canonical-repair-compaction",
        parentId: "canonical-target-message",
        sourceEntryIds: [target.sessionId, "canonical-target-message"],
        summary: "stale destination summary",
        tokensBefore: 10,
        type: "compaction",
      },
    ]);
    const targetDatabase = insertCutover(target);
    for (const eventSeq of [0, 1, 2]) {
      insertPolicyFixture({ scope: target, eventSeq });
    }
    runOpenClawAgentWriteTransaction(
      (writeDatabase) => {
        expect(
          recordTranscriptCompactionPolicyInTransaction({
            compactionId: "canonical-repair-compaction",
            database: writeDatabase,
            eventSeq: 2,
            sessionId: target.sessionId,
            sourceEventSeqs: [0, 1],
          }),
        ).toBe(true);
      },
      { agentId: target.agentId, env: target.env },
    );
    const sourceDatabase = openOpenClawAgentDatabase({ agentId: source.agentId, env: source.env });

    copySqliteSessionOwnedStateForCanonicalRepair({
      canonicalKey: target.sessionKey,
      destinationDatabase: targetDatabase,
      source: { agentId: source.agentId, storePath: sourceDatabase.path },
      sourceEntries: [{ sessionId: source.sessionId, updatedAt: 1 }],
      sourceKeys: [source.sessionKey],
    });

    expect(
      targetDatabase.db
        .prepare(
          `SELECT 1
             FROM memory_compaction_policy_bindings
            WHERE session_id = ? AND compaction_id = ?`,
        )
        .get(target.sessionId, "canonical-repair-compaction"),
    ).toBeUndefined();
  });

  it("rebuilds a compaction binding only through exact header-repair mappings", async () => {
    const scope = await createScope("compaction-header-repair");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "repair-source-user",
      message: { role: "user", content: "repair source user" },
    });
    await appendTranscriptMessage(scope, {
      eventId: "repair-source-assistant",
      message: { role: "assistant", content: "repair source assistant" },
    });
    const withoutHeader = (await loadTranscriptEvents(scope)).filter(
      (event) => (event as { type?: unknown }).type !== "session",
    );
    await replaceTranscriptEvents(scope, [
      ...withoutHeader,
      {
        firstKeptEntryId: "repair-source-user",
        id: "repair-compaction",
        parentId: "repair-source-assistant",
        sourceEntryIds: ["repair-source-user", "repair-source-assistant"],
        summary: "repair summary",
        tokensBefore: 10,
        type: "compaction",
      },
    ]);
    const database = insertCutover(scope);
    for (const eventSeq of [0, 1, 2]) {
      insertPolicyFixture({ scope, eventSeq });
    }
    runOpenClawAgentWriteTransaction(
      (writeDatabase) => {
        expect(
          recordTranscriptCompactionPolicyInTransaction({
            compactionId: "repair-compaction",
            database: writeDatabase,
            eventSeq: 2,
            sessionId: scope.sessionId,
            sourceEventSeqs: [0, 1],
          }),
        ).toBe(true);
      },
      { agentId: scope.agentId, env: scope.env },
    );
    const sourceRows = database.db
      .prepare(
        `SELECT event_json, seq
           FROM transcript_events
          WHERE session_id = ?
          ORDER BY seq ASC`,
      )
      .all(scope.sessionId) as Array<{ event_json: string; seq: number }>;
    const repairedHeader = {
      id: scope.sessionId,
      timestamp: "2026-08-06T00:00:00.000Z",
      type: "session",
      version: 3,
    };
    const resolved = resolveSqliteScope(scope);
    runOpenClawAgentWriteTransaction((writeDatabase) => {
      replaceSqliteTranscriptEventsInTransaction(
        writeDatabase,
        { ...resolved, sessionId: scope.sessionId },
        [
          repairedHeader,
          ...withoutHeader,
          {
            firstKeptEntryId: "repair-source-user",
            id: "repair-compaction",
            parentId: "repair-source-assistant",
            sourceEntryIds: ["repair-source-user", "repair-source-assistant"],
            summary: "repair summary",
            tokensBefore: 10,
            type: "compaction",
          },
        ],
        {
          preservedMemoryPolicyBindings: sourceRows.map((sourceRow, index) =>
            createTranscriptMemoryPolicyRewriteBinding({
              sourceEventJson: sourceRow.event_json,
              sourceEventSeq: sourceRow.seq,
              targetEventIndex: index + 1,
            }),
          ),
        },
      );
    }, toDatabaseOptions(resolved));

    expect(
      database.db
        .prepare(
          `SELECT source_event_seqs_json
             FROM memory_compaction_policy_bindings
            WHERE session_id = ? AND compaction_id = ?`,
        )
        .get(scope.sessionId, "repair-compaction"),
    ).toEqual({ source_event_seqs_json: '["1","2"]' });
    await expect(
      loadTranscriptEvents(scope).then((events) =>
        events.map((event) => (event as { id?: string }).id),
      ),
    ).resolves.toContain("repair-compaction");
  });

  it("preserves explicitly bound rows but leaves reordered duplicate raw replacements pending", async () => {
    const scope = await createScope("replacement-pending");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "first-duplicate",
      message: { content: "same bytes", role: "user" },
    });
    await appendTranscriptMessage(scope, {
      eventId: "second-duplicate",
      message: { content: "same bytes", role: "user" },
    });
    const database = insertCutover(scope);
    insertPolicyFixture({ scope, eventSeq: 0 });
    insertPolicyFixture({ scope, eventSeq: 1 });
    insertPolicyFixture({ scope, eventSeq: 2 });
    const sourceEvents = await loadTranscriptEvents(scope);
    expect(sourceEvents).toHaveLength(3);
    const sourceRows = database.db
      .prepare(
        `SELECT event_json, seq
           FROM transcript_events
          WHERE session_id = ?
          ORDER BY seq ASC`,
      )
      .all(scope.sessionId) as Array<{ event_json: string; seq: number }>;
    const reorderedEvents = [sourceEvents[0], sourceEvents[2], sourceEvents[1]];
    const reorderedSourceRows = [sourceRows[0], sourceRows[2], sourceRows[1]];
    const resolved = resolveSqliteScope(scope);
    runOpenClawAgentWriteTransaction((writeDatabase) => {
      replaceSqliteTranscriptEventsInTransaction(
        writeDatabase,
        { ...resolved, sessionId: scope.sessionId },
        reorderedEvents,
        {
          preservedMemoryPolicyBindings: reorderedSourceRows.map((sourceRow, targetEventIndex) => {
            if (!sourceRow) {
              throw new Error("missing source row for rewrite binding");
            }
            return createTranscriptMemoryPolicyRewriteBinding({
              sourceEventJson: sourceRow.event_json,
              sourceEventSeq: sourceRow.seq,
              targetEventIndex,
            });
          }),
        },
      );
    }, toDatabaseOptions(resolved));

    expect(
      database.db
        .prepare(
          `SELECT event_seq, authorization_status, run_id
             FROM transcript_event_memory_policies
            WHERE session_id = ?
            ORDER BY event_seq ASC`,
        )
        .all(scope.sessionId),
    ).toEqual([
      { authorization_status: "authorized", event_seq: 0, run_id: "run-1" },
      { authorization_status: "authorized", event_seq: 1, run_id: "run-1" },
      { authorization_status: "authorized", event_seq: 2, run_id: "run-1" },
    ]);

    await replaceSqliteTranscriptEvents(scope, reorderedEvents);

    expect(
      database.db
        .prepare(
          `SELECT event_seq, authorization_status
             FROM transcript_event_memory_policies
            WHERE session_id = ?
            ORDER BY event_seq ASC`,
        )
        .all(scope.sessionId),
    ).toEqual([
      { authorization_status: "pending", event_seq: 0 },
      { authorization_status: "pending", event_seq: 1 },
      { authorization_status: "pending", event_seq: 2 },
    ]);
    await expect(loadTranscriptEvents(scope)).resolves.toEqual([]);
  });

  it("invalidates a compaction when an exact rewrite changes one captured source", async () => {
    const scope = await createScope("compaction-rewrite-pending");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "rewrite-source-user",
      message: { role: "user", content: "original source" },
    });
    await appendTranscriptMessage(scope, {
      eventId: "rewrite-source-assistant",
      message: { role: "assistant", content: "original answer" },
    });
    await replaceTranscriptEvents(scope, [
      ...(await loadTranscriptEvents(scope)),
      {
        firstKeptEntryId: "rewrite-source-user",
        id: "rewrite-compaction",
        parentId: "rewrite-source-assistant",
        sourceEntryIds: ["rewrite-source-user", "rewrite-source-assistant"],
        summary: "must become unavailable",
        tokensBefore: 10,
        type: "compaction",
      },
    ]);
    const database = insertCutover(scope);
    for (const eventSeq of [0, 1, 2, 3]) {
      insertPolicyFixture({ scope, eventSeq });
    }
    runOpenClawAgentWriteTransaction(
      (writeDatabase) => {
        expect(
          recordTranscriptCompactionPolicyInTransaction({
            compactionId: "rewrite-compaction",
            database: writeDatabase,
            eventSeq: 3,
            sessionId: scope.sessionId,
            sourceEventSeqs: [1, 2],
          }),
        ).toBe(true);
      },
      { agentId: scope.agentId, env: scope.env },
    );
    const source = database.db
      .prepare(
        `SELECT event_json, seq
           FROM transcript_events
          WHERE session_id = ? AND seq = 1`,
      )
      .get(scope.sessionId) as { event_json: string; seq: number };
    const resolved = resolveSqliteScope(scope);
    runOpenClawAgentWriteTransaction((writeDatabase) => {
      rewriteSqliteTranscriptEventRowsInTransaction(
        writeDatabase,
        { ...resolved, sessionId: scope.sessionId },
        [
          {
            event: {
              id: "rewrite-source-user",
              message: { content: "changed source", role: "user" },
              parentId: null,
              type: "message",
            },
            expectedEventJson: source.event_json,
            seq: source.seq,
          },
        ],
      );
    }, toDatabaseOptions(resolved));

    expect(
      database.db
        .prepare(
          `SELECT 1
             FROM memory_compaction_policy_bindings
            WHERE session_id = ? AND compaction_id = ?`,
        )
        .get(scope.sessionId, "rewrite-compaction"),
    ).toBeUndefined();
    expect(
      database.db
        .prepare(
          `SELECT authorization_status
             FROM transcript_event_memory_policies
            WHERE session_id = ? AND event_seq = 3`,
        )
        .get(scope.sessionId),
    ).toEqual({ authorization_status: "pending" });
    await expect(
      loadTranscriptEvents(scope).then((events) =>
        events.map((event) => (event as { id?: string }).id),
      ),
    ).resolves.not.toContain("rewrite-compaction");
  });

  it("makes a changed in-place transcript row pending until it receives new policy evidence", async () => {
    const scope = await createScope("exact-rewrite-pending");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "rewrite-message",
      message: { content: "original bytes", role: "user" },
    });
    const database = insertCutover(scope);
    insertPolicyFixture({ scope, eventSeq: 0 });
    insertPolicyFixture({ scope, eventSeq: 1 });
    const source = database.db
      .prepare(
        `SELECT event_json, seq
           FROM transcript_events
          WHERE session_id = ? AND seq = 1`,
      )
      .get(scope.sessionId) as { event_json: string; seq: number };
    const resolved = resolveSqliteScope(scope);

    runOpenClawAgentWriteTransaction((writeDatabase) => {
      rewriteSqliteTranscriptEventRowsInTransaction(
        writeDatabase,
        { ...resolved, sessionId: scope.sessionId },
        [
          {
            event: {
              id: "rewrite-message",
              message: { content: "rewritten bytes", role: "user" },
              parentId: null,
              type: "message",
            },
            expectedEventJson: source.event_json,
            seq: source.seq,
          },
        ],
      );
    }, toDatabaseOptions(resolved));

    expect(
      database.db
        .prepare(
          `SELECT authorization_status, source_policy_set_id
             FROM transcript_event_memory_policies
            WHERE session_id = ? AND event_seq = 1`,
        )
        .get(scope.sessionId),
    ).toEqual({ authorization_status: "pending", source_policy_set_id: null });
    expect(
      database.db
        .prepare(
          `SELECT COUNT(*) AS count
             FROM transcript_event_memory_policy_details
            WHERE session_id = ? AND event_seq = 1`,
        )
        .get(scope.sessionId),
    ).toEqual({ count: 0 });
    await expect(loadTranscriptEvents(scope)).resolves.toHaveLength(1);
  });

  it("does not expose an unlabeled row through the transcript write lock or derive from it", async () => {
    const scope = await createScope("write-lock");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "unlabeled-message",
      message: { role: "user", content: "must stay hidden" },
    });
    insertCutover(scope);

    await expect(
      withTranscriptWriteLock(scope, async (transcript) => await transcript.readEvents()),
    ).resolves.toEqual([]);
    await expect(
      withTranscriptWriteLock(scope, async (transcript) => {
        const events = await transcript.readEvents();
        await transcript.replaceEvents(events);
      }),
    ).rejects.toThrow("transcript rewrite unavailable while memory policy enforcement is active");
  });
});
