import { afterEach, describe, expect, it } from "vitest";
import { createEffectiveMemoryPolicySetId } from "../../plugins/memory-invocation-serialization.js";
import {
  openOpenClawAgentDatabase,
  runOpenClawAgentWriteTransaction,
} from "../../state/openclaw-agent-db.js";
import {
  appendTranscriptMessage,
  loadTranscriptEvents,
  readTranscriptRawDelta,
  readTranscriptStatsSync,
  upsertSessionEntry,
} from "./session-accessor.js";
import { replaceSqliteTranscriptEvents } from "./session-accessor.sqlite-transcript-write.js";
import {
  authorizeTranscriptCompactionSources,
  recordTranscriptCompactionPolicyInTransaction,
} from "./session-transcript-memory-policy.js";
import {
  createTranscriptMemoryPolicyTestHarness,
  insertCutover,
  insertPolicyFixture,
  setCurrentCompactionPolicyLabel,
} from "./session-transcript-memory-policy.test-support.js";

const harness = createTranscriptMemoryPolicyTestHarness();

describe("transcript memory policy", () => {
  afterEach(() => harness.cleanup());

  it("hides missing, mismatched, and pending labels behind a dense v2 cursor", async () => {
    const scope = await harness.createScope("visibility");
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
    const scope = await harness.createScope("atomicity");
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
    const scope = await harness.createScope("revoked");
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
    const scope = await harness.createScope("revised");
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
    const scope = await harness.createScope("compaction-policy");
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
    const scope = await harness.createScope("compaction-preflight");
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
    const scope = await harness.createScope("compaction-derived-policy");
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
    const scope = await harness.createScope("compaction-mixed-audience");
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
    const scope = await harness.createScope("compaction-session-binding");
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
});
