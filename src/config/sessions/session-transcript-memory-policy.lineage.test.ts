import { afterEach, describe, expect, it } from "vitest";
import { createEffectiveMemoryPolicySetId } from "../../plugins/memory-invocation-serialization.js";
import {
  openOpenClawAgentDatabase,
  runOpenClawAgentWriteTransaction,
} from "../../state/openclaw-agent-db.js";
import {
  appendTranscriptMessage,
  forkSessionAtMessage,
  forkSessionFromParentTranscript,
  loadTranscriptEvents,
  replaceTranscriptEvents,
  upsertSessionEntry,
} from "./session-accessor.js";
import { replaceSqliteTranscriptEvents } from "./session-accessor.sqlite-transcript-write.js";
import {
  copyTranscriptMemoryPolicyInTransaction,
  recordTranscriptCompactionPolicyInTransaction,
} from "./session-transcript-memory-policy.js";
import {
  createTranscriptMemoryPolicyTestHarness,
  insertCutover,
  insertPolicyFixture,
} from "./session-transcript-memory-policy.test-support.js";

const harness = createTranscriptMemoryPolicyTestHarness();

describe("transcript memory policy lineage", () => {
  afterEach(() => harness.cleanup());

  it("carries a prior summary's derived policy into the next compaction", async () => {
    const scope = await harness.createScope("nested-compaction-policy");
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
    const scope = await harness.createScope("copy");
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
    const scope = await harness.createScope("same-database-fork");
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
    const scope = await harness.createScope("message-cut-fork");
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
});
