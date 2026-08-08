import { openOpenClawAgentDatabase } from "openclaw/plugin-sdk/sqlite-runtime";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  createBuiltinScopedMemoryResource,
  createBuiltinScopedMemoryStore,
} from "../../test-api.js";
import { createBuiltinScopedMemoryRuntime } from "./scoped-memory-runtime.js";
import {
  SCOPED_MEMORY_RUNTIME_NOW_MS as NOW_MS,
  createScopedMemoryRuntimeContext as createContext,
  createScopedMemoryRuntimeStore as createStore,
  createScopedMemoryRuntimeTestFixture,
} from "./scoped-memory-runtime.test-support.js";

describe("builtin authorized scoped memory runtime", () => {
  let fixture: ReturnType<typeof createScopedMemoryRuntimeTestFixture>;

  beforeEach(() => {
    fixture = createScopedMemoryRuntimeTestFixture();
    fixture.setup();
  });

  afterEach(() => {
    fixture.teardown();
  });

  it("searches and exactly reads through opaque handles with persisted receipts", async () => {
    const store = createStore();
    const resource = createBuiltinScopedMemoryResource({
      agentId: "main",
      store,
      logicalLocator: "MEMORY.md",
      content: "authorized saffron memory\nsecond line",
      actor: { kind: "human", id: "principal-owner" },
      nowMs: 2_000,
    });
    const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const context = createContext();
    const plan = await runtime.authorize(context);

    const search = await runtime.searchAuthorized({
      context,
      plan,
      query: "saffron",
      limit: 5,
    });

    expect(search.value).toHaveLength(1);
    expect(search.value[0]).toMatchObject({
      path: "MEMORY.md",
      snippet: "authorized saffron memory\nsecond line",
      resourceHandle: {
        planId: plan.planId,
        contextFingerprint: context.contextFingerprint,
        resourceRevision: resource.revisionId,
      },
    });
    expect(search.value[0]?.resourceHandle.handleId).toMatch(/^mrh1_/u);
    const read = await runtime.readAuthorized({
      context,
      plan,
      handle: search.value[0]!.resourceHandle,
      from: 2,
      lines: 1,
    });
    expect(read.value).toEqual({
      text: "second line",
      path: "MEMORY.md",
      truncated: false,
      from: 2,
      lines: 1,
    });
    const database = openOpenClawAgentDatabase({ agentId: "main" }).db;
    expect(
      database.prepare("SELECT COUNT(*) AS count FROM memory_exposure_receipts").get(),
    ).toEqual({ count: 2 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM memory_egress_receipts").get()).toEqual({
      count: 2,
    });
    expect(search.exposureReceipt.runExposureRevision).toBe(
      search.egressReceipt.runExposureRevision,
    );
  });

  it("maps a shown projection descendant to only its current approved root", async () => {
    const sourceStore = createStore();
    const source = createBuiltinScopedMemoryResource({
      agentId: "main",
      store: sourceStore,
      logicalLocator: "projection-source.md",
      content: "projection source record",
      actor: { kind: "human", id: "principal-owner" },
      nowMs: 2_000,
    });
    const targetStore = createBuiltinScopedMemoryStore({
      agentId: "main",
      scopeKind: "agent-shared",
      audienceKind: "agent-shared",
      audienceId: "main",
      authorityKind: "agent",
      authorityOwnerId: "main",
      defaultCapabilities: ["retrieve", "read"],
      actor: { kind: "human", id: "principal-owner" },
      reason: "projection exposure target",
      nowMs: 1_000,
    });
    const database = openOpenClawAgentDatabase({ agentId: "main" }).db;
    const roots = [
      {
        label: "approved",
        projectionId: "projection-approved",
        reviewState: "approved" as const,
        expiresAt: NOW_MS + 1_000,
      },
      {
        label: "pending",
        projectionId: "projection-pending",
        reviewState: "pending" as const,
        expiresAt: NOW_MS + 1_000,
      },
      {
        label: "expired",
        projectionId: "projection-expired",
        reviewState: "approved" as const,
        expiresAt: NOW_MS - 1,
      },
      {
        label: "inactive",
        projectionId: "projection-inactive",
        reviewState: "approved" as const,
        expiresAt: NOW_MS + 1_000,
      },
    ].map(({ label, projectionId, reviewState, expiresAt }) => {
      const root = createBuiltinScopedMemoryResource({
        agentId: "main",
        store: targetStore,
        logicalLocator: `projection-root-${label}.md`,
        content: `projection ${label} root`,
        lifecycleState: "pending",
        actor: { kind: "human", id: "principal-owner" },
        nowMs: 2_000,
      });
      const descendant = createBuiltinScopedMemoryResource({
        agentId: "main",
        store: targetStore,
        logicalLocator: `projection-descendant-${label}.md`,
        content: `projection descendant exposure marker ${label}`,
        actor: { kind: "human", id: "principal-owner" },
        nowMs: 3_000,
      });
      database
        .prepare(
          `INSERT INTO memory_lineage_edges
             (child_revision_id, parent_revision_id, edge_kind, created_at)
           VALUES (?, ?, ?, ?), (?, ?, ?, ?)`,
        )
        .run(
          root.revisionId,
          source.revisionId,
          "project",
          2_000,
          descendant.revisionId,
          root.revisionId,
          "derive",
          3_000,
        );
      database
        .prepare(
          `INSERT INTO memory_projections (
             projection_id, agent_id, source_revision_id, target_agent_id, target_store_id,
             target_resource_id, target_revision_id, target_kind, target_audience_id,
             purpose, preview, publisher_kind, publisher_id, review_state,
             reviewer_kind, reviewer_id, review_reason, expires_at, revocation_behavior,
             supersedes_projection_id, created_at, reviewed_at, revoked_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          projectionId,
          "main",
          source.revisionId,
          "main",
          targetStore.storeId,
          root.resourceId,
          root.revisionId,
          "agent-shared",
          "main",
          "projection exposure test",
          "approved target copy",
          "local-agent-owner",
          "principal-owner",
          "pending",
          null,
          null,
          null,
          expiresAt,
          "tombstone",
          null,
          2_000,
          null,
          null,
        );
      if (reviewState === "approved") {
        database
          .prepare(
            `UPDATE memory_resource_revisions
                SET lifecycle_state = ?, activated_at = ?
              WHERE revision_id = ?`,
          )
          .run("active", 2_000, root.revisionId);
        database
          .prepare(
            `UPDATE memory_projections
                SET review_state = ?, reviewer_kind = ?, reviewer_id = ?, reviewed_at = ?
              WHERE projection_id = ?`,
          )
          .run("approved", "local-agent-owner", "principal-owner", 2_000, projectionId);
      }
      if (label === "inactive") {
        database
          .prepare(
            `UPDATE memory_resource_revisions
                SET lifecycle_state = ?, retired_at = ?
              WHERE revision_id = ?`,
          )
          .run("tombstoned", NOW_MS, root.revisionId);
      }
      return { label, projectionId, reviewState, expiresAt, root, descendant };
    });

    const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const context = createContext({ operation: "read" });
    const plan = await runtime.authorize(context);
    const result = await runtime.searchAuthorized({
      context,
      plan,
      query: "projection descendant exposure marker",
      limit: 10,
    });

    expect(result.value.map((entry) => entry.resourceHandle.resourceRevision).toSorted()).toEqual(
      roots.map((entry) => entry.descendant.revisionId).toSorted(),
    );
    expect(
      database
        .prepare(
          `SELECT projection_id, exposure_receipt_id, recorded_at
             FROM memory_projection_exposures
            WHERE exposure_receipt_id = ?
            ORDER BY projection_id`,
        )
        .all(result.exposureReceipt.receiptId),
    ).toEqual([
      {
        projection_id: "projection-approved",
        exposure_receipt_id: result.exposureReceipt.receiptId,
        recorded_at: NOW_MS,
      },
    ]);
  });

  it("prepares stable transcript policy requirements before core commits an event", async () => {
    const store = createStore({ defaultCapabilities: ["retrieve", "read", "status"] });
    const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const context = createContext({ operation: "status" });
    const plan = await runtime.authorize(context);
    const status = await runtime.statusAuthorized({ context, plan });

    const prepared = await runtime.prepareTranscriptPolicy({
      context,
      plan,
      policySetId: status.exposureReceipt.sourcePolicySetId,
      sourcePolicySetIds: [status.exposureReceipt.sourcePolicySetId],
    });

    expect(prepared).toMatchObject({
      version: 1,
      policySetId: status.exposureReceipt.sourcePolicySetId,
      retentionState: "active",
      requirements: [
        {
          stablePolicyId: store.policyId,
          capturedRevisionId: store.policyRevisionId,
          expectedActiveRevisionId: store.policyRevisionId,
          expectedRevocationEpoch: store.policyRevocationEpoch,
        },
      ],
    });
    expect(prepared.policySetRevision).toMatch(/^mpsr1_/u);
  });
});
