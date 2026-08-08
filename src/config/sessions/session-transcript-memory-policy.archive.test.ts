import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  openOpenClawAgentDatabase,
  runOpenClawAgentWriteTransaction,
} from "../../state/openclaw-agent-db.js";
import { readSessionArchiveContentSync } from "./archive-compression.js";
import {
  appendTranscriptMessage,
  forkSessionFromParentTranscript,
  loadTranscriptEvents,
  readCurrentSessionMemorySubject,
  readTranscriptMemoryPolicyExportManifest,
  replaceSessionEntry,
  replaceTranscriptEvents,
  upsertSessionEntry,
} from "./session-accessor.js";
import { materializeSqliteSessionStateDeletePlans } from "./session-accessor.sqlite-archive.js";
import { importSqliteSessionRows } from "./session-accessor.sqlite-import.js";
import {
  deleteMaterializedSqliteSessionStatePlans,
  planSqliteSessionStateDeleteIfUnreferenced,
} from "./session-accessor.sqlite-lifecycle-state.js";
import { resolveSqliteScope, toDatabaseOptions } from "./session-accessor.sqlite-scope.js";
import { prepareSessionMemorySubjectLineageSeed } from "./session-memory-subject.js";
import { recordTranscriptCompactionPolicyInTransaction } from "./session-transcript-memory-policy.js";
import {
  createTranscriptMemoryPolicyTestHarness,
  insertCutover,
  insertPolicyFixture,
  transcriptMemoryPolicyTesting,
} from "./session-transcript-memory-policy.test-support.js";

const harness = createTranscriptMemoryPolicyTestHarness();

describe("transcript memory policy archive and import", () => {
  afterEach(() => harness.cleanup());

  it("persists immutable policy lineage with an archive before reclaiming source rows", async () => {
    const scope = await harness.createScope("archive-lineage");
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
    const scope = await harness.createScope("archive-compaction-cleanup");
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
    const scope = await harness.createScope("archive-revocation");
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
    const scope = await harness.createScope("archive-pending");
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
    const scope = await harness.createScope("confirmed-import");
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
      loadTranscriptEvents(scope).then((loadedEvents) =>
        loadedEvents.map((event) => (event as { id?: string }).id),
      ),
    ).resolves.toContain("confirmed-import-compaction");
  });

  it("requires manifest bindings and round-trips multi-digit compaction source sequences", async () => {
    const scope = await harness.createScope("multi-digit-compaction-import");
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
      loadTranscriptEvents(scope).then((loadedEvents) =>
        loadedEvents.map((event) => (event as { id?: string }).id),
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
      loadTranscriptEvents(scope).then((loadedEvents) =>
        loadedEvents.map((event) => (event as { id?: string }).id),
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
      loadTranscriptEvents(scope).then((loadedEvents) =>
        loadedEvents.map((event) => (event as { id?: string }).id),
      ),
    ).resolves.toContain("numeric-compaction");
  });

  it("leaves a manifest-mismatched import pending", async () => {
    const scope = await harness.createScope("mismatched-import");
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
    const scope = await harness.createScope("mismatched-manifest-sequence");
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
    const mismatchedEventIndex = manifest.events.findIndex((event) => event.eventSeq === 1);
    const mismatchedEvent = manifest.events[mismatchedEventIndex];
    if (mismatchedEventIndex < 0 || !mismatchedEvent) {
      throw new Error("expected manifest event to mismatch");
    }
    const mismatchedManifest = {
      ...manifest,
      events: manifest.events.toSpliced(mismatchedEventIndex, 1, {
        ...mismatchedEvent,
        eventSeq: 2,
      }),
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
    harness.trackTempDir(root);
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
});
