import { afterEach, describe, expect, it } from "vitest";
import {
  appendTranscriptEvent,
  appendTranscriptMessage,
  loadTranscriptEvents,
  upsertSessionEntry,
} from "./session-accessor.js";
import {
  branchSqliteCompactionCheckpointSession,
  restoreSqliteCompactionCheckpointSession,
} from "./session-accessor.sqlite.js";
import {
  createTranscriptMemoryPolicyTestHarness,
  insertCutover,
  insertPolicyFixture,
} from "./session-transcript-memory-policy.test-support.js";
import { SESSION_TOTAL_TOKENS_VERSION, type SessionCompactionCheckpoint } from "./types.js";

const harness = createTranscriptMemoryPolicyTestHarness();

type PolicyScope = Awaited<
  ReturnType<ReturnType<typeof createTranscriptMemoryPolicyTestHarness>["createScope"]>
>;

function checkpointForSource(params: {
  checkpointId: string;
  sessionId: string;
  sessionKey: string;
  sourceLeafId: string;
}): SessionCompactionCheckpoint {
  return {
    checkpointId: params.checkpointId,
    sessionKey: params.sessionKey,
    sessionId: params.sessionId,
    createdAt: 1,
    reason: "manual",
    tokensBefore: 123,
    tokensAfter: 45,
    tokensVersion: SESSION_TOTAL_TOKENS_VERSION,
    preCompaction: {
      sessionId: params.sessionId,
      leafId: params.sourceLeafId,
    },
    postCompaction: {
      sessionId: params.sessionId,
      entryId: params.sourceLeafId,
    },
  };
}

async function seedFilteredCheckpointSource(params: {
  authorizeEverySourceRow?: boolean;
  checkpointId: string;
  includeIdlessRawEvent?: boolean;
  label: string;
}): Promise<{ checkpoint: SessionCompactionCheckpoint; scope: PolicyScope }> {
  const scope = await harness.createScope(params.label);
  await upsertSessionEntry(scope, {
    sessionFile: "sqlite",
    sessionId: scope.sessionId,
    updatedAt: 1,
  });
  await appendTranscriptMessage(scope, {
    eventId: "checkpoint-readable",
    message: { role: "user", content: "readable checkpoint source" },
  });
  if (params.includeIdlessRawEvent) {
    await appendTranscriptEvent(scope, {
      payload: { note: "authorized checkpoint source without an event id" },
      type: "custom",
    });
  }
  await appendTranscriptMessage(scope, {
    eventId: "checkpoint-filtered",
    message: { role: "assistant", content: "filtered checkpoint source" },
  });

  insertCutover(scope);
  // The header and first message are authorized; the checkpoint boundary also
  // contains an unbound message that must not bless the token total.
  insertPolicyFixture({ scope, eventSeq: 0 });
  insertPolicyFixture({ scope, eventSeq: 1 });
  if (params.authorizeEverySourceRow) {
    insertPolicyFixture({ scope, eventSeq: 2 });
    if (params.includeIdlessRawEvent) {
      insertPolicyFixture({ scope, eventSeq: 3 });
    }
  }
  const checkpoint = checkpointForSource({
    checkpointId: params.checkpointId,
    sessionId: scope.sessionId,
    sessionKey: scope.sessionKey,
    sourceLeafId: "checkpoint-filtered",
  });
  await upsertSessionEntry(scope, { compactionCheckpoints: [checkpoint] });
  return { checkpoint, scope };
}

function expectNoFreshCheckpointTotal(entry: {
  totalTokens?: number;
  totalTokensFresh?: boolean;
  totalTokensVersion?: number;
}): void {
  expect(entry.totalTokens).toBeUndefined();
  expect(entry.totalTokensFresh).toBeUndefined();
  expect(entry.totalTokensVersion).toBeUndefined();
}

describe("SQLite checkpoint memory policy", () => {
  afterEach(() => harness.cleanup());

  it("clears fresh totals when an enforced branch filters a checkpoint source row", async () => {
    const { checkpoint, scope } = await seedFilteredCheckpointSource({
      checkpointId: "filtered-branch",
      label: "checkpoint-filtered-branch",
    });
    const branchKey = `${scope.sessionKey}-branch`;

    const result = await branchSqliteCompactionCheckpointSession({
      agentId: scope.agentId,
      env: scope.env,
      sourceKey: scope.sessionKey,
      nextKey: branchKey,
      checkpointId: checkpoint.checkpointId,
    });

    if (result.status !== "created") {
      throw new Error(`expected checkpoint branch, got ${result.status}`);
    }
    expectNoFreshCheckpointTotal(result.entry);
    await expect(
      loadTranscriptEvents({ ...scope, sessionId: result.entry.sessionId, sessionKey: branchKey }),
    ).resolves.toEqual([expect.objectContaining({ id: "checkpoint-readable" })]);
  });

  it("clears fresh totals when an enforced restore filters a checkpoint source row", async () => {
    const { checkpoint, scope } = await seedFilteredCheckpointSource({
      checkpointId: "filtered-restore",
      label: "checkpoint-filtered-restore",
    });

    const result = await restoreSqliteCompactionCheckpointSession({
      agentId: scope.agentId,
      env: scope.env,
      sessionKey: scope.sessionKey,
      checkpointId: checkpoint.checkpointId,
    });

    if (result.status !== "created") {
      throw new Error(`expected checkpoint restore, got ${result.status}`);
    }
    expectNoFreshCheckpointTotal(result.entry);
    await expect(
      loadTranscriptEvents({ ...scope, sessionId: result.entry.sessionId }),
    ).resolves.toEqual([expect.objectContaining({ id: "checkpoint-readable" })]);
  });

  it("keeps a fresh total only when an enforced branch copies every source row", async () => {
    const { checkpoint, scope } = await seedFilteredCheckpointSource({
      authorizeEverySourceRow: true,
      checkpointId: "complete-branch",
      label: "checkpoint-complete-branch",
    });

    const result = await branchSqliteCompactionCheckpointSession({
      agentId: scope.agentId,
      env: scope.env,
      sourceKey: scope.sessionKey,
      nextKey: `${scope.sessionKey}-complete-branch`,
      checkpointId: checkpoint.checkpointId,
    });

    if (result.status !== "created") {
      throw new Error(`expected complete checkpoint branch, got ${result.status}`);
    }
    expect(result.entry).toMatchObject({
      totalTokens: 123,
      totalTokensFresh: true,
      totalTokensVersion: SESSION_TOTAL_TOKENS_VERSION,
    });
  });

  it("clears fresh totals when an otherwise authorized branch replays an idless raw event", async () => {
    const { checkpoint, scope } = await seedFilteredCheckpointSource({
      authorizeEverySourceRow: true,
      checkpointId: "idless-branch",
      includeIdlessRawEvent: true,
      label: "checkpoint-idless-branch",
    });
    await expect(loadTranscriptEvents(scope)).resolves.toContainEqual({
      payload: { note: "authorized checkpoint source without an event id" },
      type: "custom",
    });

    const result = await branchSqliteCompactionCheckpointSession({
      agentId: scope.agentId,
      env: scope.env,
      sourceKey: scope.sessionKey,
      nextKey: `${scope.sessionKey}-idless-branch`,
      checkpointId: checkpoint.checkpointId,
    });

    if (result.status !== "created") {
      throw new Error(`expected idless checkpoint branch, got ${result.status}`);
    }
    expectNoFreshCheckpointTotal(result.entry);
  });

  it("keeps legacy checkpoint bytes pending and clears their token total", async () => {
    const scope = await harness.createScope("checkpoint-legacy");
    const checkpointFile = "/legacy/checkpoint.jsonl";
    const checkpoint = {
      ...checkpointForSource({
        checkpointId: "legacy-pending",
        sessionId: "legacy-checkpoint-source",
        sessionKey: scope.sessionKey,
        sourceLeafId: "legacy-checkpoint-message",
      }),
      preCompaction: {
        sessionId: "legacy-checkpoint-source",
        sessionFile: checkpointFile,
        leafId: "legacy-checkpoint-message",
      },
    } satisfies SessionCompactionCheckpoint;
    await upsertSessionEntry(scope, {
      compactionCheckpoints: [checkpoint],
      sessionFile: "sqlite",
      sessionId: scope.sessionId,
      updatedAt: 1,
    });
    const database = insertCutover(scope);
    const branchKey = `${scope.sessionKey}-legacy-branch`;

    const result = await branchSqliteCompactionCheckpointSession({
      agentId: scope.agentId,
      env: scope.env,
      sourceKey: scope.sessionKey,
      nextKey: branchKey,
      checkpointId: checkpoint.checkpointId,
      legacySource: {
        checkpointId: checkpoint.checkpointId,
        events: [
          { id: "legacy-header", type: "session" },
          {
            id: "legacy-checkpoint-message",
            message: { content: "unbound legacy checkpoint", role: "user" },
            parentId: null,
            type: "message",
          },
        ],
        sessionFile: checkpointFile,
        sourceLeafId: "legacy-checkpoint-message",
      },
    });

    if (result.status !== "created") {
      throw new Error(`expected legacy checkpoint branch, got ${result.status}`);
    }
    expectNoFreshCheckpointTotal(result.entry);
    await expect(
      loadTranscriptEvents({ ...scope, sessionId: result.entry.sessionId, sessionKey: branchKey }),
    ).resolves.toEqual([]);
    expect(
      database.db
        .prepare(
          `SELECT authorization_status
             FROM transcript_event_memory_policies
            WHERE session_id = ?
            ORDER BY event_seq ASC`,
        )
        .all(result.entry.sessionId),
    ).toEqual([{ authorization_status: "pending" }, { authorization_status: "pending" }]);
  });
});
