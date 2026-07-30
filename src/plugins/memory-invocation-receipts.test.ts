import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  closeOpenClawAgentDatabasesForTest,
  openOpenClawAgentDatabase,
} from "../state/openclaw-agent-db.js";
import { ensureOpenClawAgentScopedMemorySchema } from "../state/openclaw-agent-scoped-memory-schema.js";
import {
  hasCurrentMemoryEgressReceipts,
  type MemoryInvocationState,
} from "./memory-invocation-receipts.js";

const stateDirs: string[] = [];

afterEach(async () => {
  closeOpenClawAgentDatabasesForTest();
  await Promise.all(
    stateDirs.splice(0).map(async (dir) => await fs.rm(dir, { recursive: true, force: true })),
  );
});

function createState(params?: {
  deliveryRevision?: string;
  egressRegistryRevision?: string;
  receiptIds?: string[];
}) {
  return {
    agentId: "memory-egress-test",
    runId: "run-1",
    context: {
      contextFingerprint: "context-1",
      runId: "run-1",
      delivery: {
        deliveryRevision: params?.deliveryRevision ?? "delivery-1",
        egressRegistryRevision: params?.egressRegistryRevision ?? "registry-1",
      },
    },
    plan: {
      planId: "plan-1",
      allowedEgressAudiences: [{ kind: "user", id: "principal-1" }],
    },
    runExposure: {
      sourcePolicySetIdsJson: JSON.stringify(["policy-1", "policy-2"]),
      exposedResourceRevisionsJson: JSON.stringify(["revision-1", "revision-2"]),
      egressReceiptIdsJson: JSON.stringify(params?.receiptIds ?? ["egress-1", "egress-2"]),
    },
  } as unknown as MemoryInvocationState;
}

function insertReceiptPair(params: {
  db: ReturnType<typeof openOpenClawAgentDatabase>["db"];
  suffix: "1" | "2";
}): void {
  const now = Date.now();
  params.db
    .prepare(
      `INSERT INTO memory_exposure_receipts
        (receipt_id, context_fingerprint, plan_id, run_id, run_exposure_revision,
         source_policy_set_id, exposed_revision_handles_json, recorded_at)
       VALUES (?, 'context-1', 'plan-1', 'run-1', ?, ?, ?, ?)`,
    )
    .run(
      `exposure-${params.suffix}`,
      `revision-${params.suffix}`,
      `policy-${params.suffix}`,
      JSON.stringify([`revision-${params.suffix}`]),
      now,
    );
  params.db
    .prepare(
      `INSERT INTO memory_egress_receipts
        (receipt_id, exposure_receipt_id, context_fingerprint, plan_id, run_id,
         run_exposure_revision, source_policy_set_id, allowed_audiences_json,
         delivery_revision, egress_registry_revision, expires_at, recorded_at)
       VALUES (?, ?, 'context-1', 'plan-1', 'run-1', ?, ?, ?,
               'delivery-1', 'registry-1', ?, ?)`,
    )
    .run(
      `egress-${params.suffix}`,
      `exposure-${params.suffix}`,
      `revision-${params.suffix}`,
      `policy-${params.suffix}`,
      JSON.stringify([{ kind: "user", id: "principal-1" }]),
      now + 60_000,
      now,
    );
}

describe("hasCurrentMemoryEgressReceipts", () => {
  it("requires receipts covering every later scoped exposure and rejects rebound revisions", async () => {
    const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-memory-egress-"));
    stateDirs.push(stateDir);
    const previousStateDir = process.env.OPENCLAW_STATE_DIR;
    process.env.OPENCLAW_STATE_DIR = stateDir;
    try {
      const database = openOpenClawAgentDatabase({
        agentId: "memory-egress-test",
        env: { OPENCLAW_STATE_DIR: stateDir },
      });
      ensureOpenClawAgentScopedMemorySchema(database.db);
      insertReceiptPair({ db: database.db, suffix: "1" });
      insertReceiptPair({ db: database.db, suffix: "2" });

      expect(hasCurrentMemoryEgressReceipts(createState())).toBe(true);
      // An earlier egress receipt cannot authorize the larger, later exposure set.
      expect(hasCurrentMemoryEgressReceipts(createState({ receiptIds: ["egress-1"] }))).toBe(false);
      expect(hasCurrentMemoryEgressReceipts(createState({ receiptIds: ["missing"] }))).toBe(false);
      expect(hasCurrentMemoryEgressReceipts(createState({ deliveryRevision: "delivery-2" }))).toBe(
        false,
      );
      expect(
        hasCurrentMemoryEgressReceipts(createState({ egressRegistryRevision: "registry-2" })),
      ).toBe(false);
    } finally {
      if (previousStateDir === undefined) {
        delete process.env.OPENCLAW_STATE_DIR;
      } else {
        process.env.OPENCLAW_STATE_DIR = previousStateDir;
      }
    }
  });
});
