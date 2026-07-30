import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createEffectiveMemoryPolicySetId } from "../../plugins/memory-invocation-serialization.js";
import {
  closeOpenClawAgentDatabasesForTest,
  openOpenClawAgentDatabase,
  runOpenClawAgentWriteTransaction,
} from "../../state/openclaw-agent-db.js";
import {
  appendTranscriptMessage,
  loadTranscriptEvents,
  readTranscriptRawDelta,
  readTranscriptStatsSync,
  upsertSessionEntry,
  withTranscriptWriteLock,
} from "./session-accessor.js";
import { copyTranscriptMemoryPolicyInTransaction } from "./session-transcript-memory-policy.js";
import { replaceSqliteTranscriptEvents } from "./session-accessor.sqlite-transcript-write.js";
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
  const memberPolicySetIds = ["source-policy-1"];
  const policySetId = createEffectiveMemoryPolicySetId({
    memoryPolicyRevision: "policy-revision-1",
    memberPolicySetIds,
  });
  const stablePolicyId = "stable-policy-1";
  const policyRevisionId = "stable-policy-revision-1";
  const exposureSetId = "exposure-set-1";
  const audiencesJson = JSON.stringify([{ kind: "user", id: "principal-1" }]);
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
      "policy-revision-1",
      JSON.stringify(memberPolicySetIds),
    );
  database.db
    .prepare(
      `INSERT OR IGNORE INTO memory_policy_set_metadata
        (policy_set_id, policy_set_revision, source_policy_set_ids_json,
         normalized_audience_intersection_json, retention_state, created_at)
       VALUES (?, 'policy-set-revision-1', ?, ?, 'active', 1)`,
    )
    .run(policySetId, JSON.stringify(memberPolicySetIds), audiencesJson);
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
       VALUES (?, ?, 'run-1', 'context-1', 'plan-1', 1, NULL, ?, ?, '[]', '[]', '[]', ?,
               'delivery-1', 'registry-1', 1)`,
    )
    .run(
      exposureSetId,
      params.scope.agentId,
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
      params.labelRunId ?? "run-1",
    );
  database.db
    .prepare(
      `INSERT INTO transcript_event_memory_policy_details
        (session_id, event_seq, policy_set_revision, actor_evidence_json, delegation_json,
         finalized_egress_audiences_json, exposed_resource_revisions_json,
         origin_session_id, origin_event_seq, created_at)
       VALUES (?, ?, 'policy-set-revision-1', '{}', 'null', ?, '[]', ?, ?, 1)`,
    )
    .run(
      params.scope.sessionId,
      params.eventSeq,
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

describe("transcript memory policy", () => {
  afterEach(async () => {
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

  it("preserves exact companions across replacement and leaves new rows pending", async () => {
    const scope = await createScope("replacement");
    await upsertSessionEntry(scope, {
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    await appendTranscriptMessage(scope, {
      eventId: "preserved-message",
      message: { role: "user", content: "historic content" },
    });
    const database = insertCutover(scope);
    insertPolicyFixture({ scope, eventSeq: 0 });
    insertPolicyFixture({ scope, eventSeq: 1 });
    const original = await loadTranscriptEvents(scope);

    await replaceSqliteTranscriptEvents(scope, original);

    expect(
      (await loadTranscriptEvents(scope)).map((event) => (event as { id?: string }).id),
    ).toEqual([scope.sessionId, "preserved-message"]);

    await replaceSqliteTranscriptEvents(scope, [
      original[0] as object,
      {
        type: "message",
        id: "replacement-message",
        parentId: null,
        message: { role: "user", content: "new content without a prepared policy" },
      },
    ]);

    expect(
      (await loadTranscriptEvents(scope)).map((event) => (event as { id?: string }).id),
    ).toEqual([scope.sessionId]);
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
