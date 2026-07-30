import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  closeOpenClawAgentDatabasesForTest,
  openOpenClawAgentDatabase,
} from "../../state/openclaw-agent-db.js";
import compactionMemoryPolicyExtension from "./compaction-memory-policy.js";
import { consumeCompactionSafeguardCancelReason } from "./compaction-safeguard-runtime.js";

const stateDirs: string[] = [];

describe("compaction memory policy hook", () => {
  afterEach(async () => {
    closeOpenClawAgentDatabasesForTest();
    await Promise.all(stateDirs.splice(0).map((stateDir) => fs.rm(stateDir, { recursive: true })));
  });

  it("cancels the before-compact hook when planner sources lack authorization", async () => {
    const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-compaction-policy-"));
    stateDirs.push(stateDir);
    const agentId = "compaction-policy-agent";
    const sessionId = "compaction-policy-session";
    const database = openOpenClawAgentDatabase({
      agentId,
      env: { OPENCLAW_STATE_DIR: stateDir },
    });
    database.db
      .prepare(
        `INSERT INTO memory_migrations
          (migration_id, source_kind, source_hash, phase, classification_json, plan_hash,
           verified_at, cutover_at, updated_at)
         VALUES (?, ?, ?, 'cutover', '{}', ?, 1, 1, 1)`,
      )
      .run("compaction-policy-cutover", "test", "source", "plan");

    let handler:
      | ((event: unknown, ctx: { sessionManager: unknown }) => Promise<unknown> | unknown)
      | undefined;
    compactionMemoryPolicyExtension({
      on: (_event: string, registered: typeof handler) => {
        handler = registered;
      },
    } as never);
    if (!handler) {
      throw new Error("expected compaction memory policy handler");
    }
    const sessionManager = {
      getSessionTarget: () => ({
        agentId,
        sessionId,
        sessionKey: `agent:${agentId}:test`,
        storePath: database.path,
      }),
    };

    expect(
      await handler(
        { preparation: { sourceEntryIds: ["missing-source-entry"] } },
        { sessionManager },
      ),
    ).toEqual({ cancel: true });
    expect(consumeCompactionSafeguardCancelReason(sessionManager)).toContain(
      "transcript sources are not authorized",
    );
  });
});
