import { afterEach, describe, expect, it } from "vitest";
import {
  openOpenClawAgentDatabase,
  runOpenClawAgentWriteTransaction,
} from "../../state/openclaw-agent-db.js";
import {
  appendTranscriptMessage,
  loadTranscriptEvents,
  replaceTranscriptEvents,
  upsertSessionEntry,
  withTranscriptWriteLock,
} from "./session-accessor.js";
import { copySqliteSessionOwnedStateForCanonicalRepair } from "./session-accessor.sqlite-canonical-repair.js";
import { resolveSqliteScope, toDatabaseOptions } from "./session-accessor.sqlite-scope.js";
import {
  createTranscriptMemoryPolicyRewriteBinding,
  replaceSqliteTranscriptEventsInTransaction,
  rewriteSqliteTranscriptEventRowsInTransaction,
} from "./session-accessor.sqlite-transcript-store.js";
import { replaceSqliteTranscriptEvents } from "./session-accessor.sqlite-transcript-write.js";
import { recordTranscriptCompactionPolicyInTransaction } from "./session-transcript-memory-policy.js";
import {
  createTranscriptMemoryPolicyTestHarness,
  insertCutover,
  insertPolicyFixture,
} from "./session-transcript-memory-policy.test-support.js";

const harness = createTranscriptMemoryPolicyTestHarness();

describe("transcript memory policy rewrite", () => {
  afterEach(() => harness.cleanup());

  it("clears a destination compaction binding when canonical repair replaces its transcript", async () => {
    const source = await harness.createScope("canonical-repair-source");
    const targetBase = await harness.createScope("canonical-repair-target");
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
    const scope = await harness.createScope("compaction-header-repair");
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
    const scope = await harness.createScope("replacement-pending");
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
    const scope = await harness.createScope("compaction-rewrite-pending");
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
    const scope = await harness.createScope("exact-rewrite-pending");
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
    const scope = await harness.createScope("write-lock");
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
