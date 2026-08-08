import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import type {
  AuthorizedMemoryMutation,
  MemoryAccessContext,
} from "openclaw/plugin-sdk/memory-authorization";
import { openOpenClawAgentDatabase } from "openclaw/plugin-sdk/sqlite-runtime";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  createBuiltinScopedMemoryResource,
  createBuiltinScopedMemoryStore,
} from "../../test-api.js";
import { resolveBuiltinScopedMemoryArtifactPath } from "./scoped-memory-resource-artifacts.js";
import { createBuiltinScopedMemoryRuntime } from "./scoped-memory-runtime.js";
import {
  SCOPED_MEMORY_RUNTIME_NOW_MS as NOW_MS,
  createScopedMemoryRuntimeContext as createContext,
  createScopedMemoryRuntimeStore as createStore,
  createScopedMemoryRuntimeTestFixture,
} from "./scoped-memory-runtime.test-support.js";

describe("builtin authorized scoped memory runtime", () => {
  let fixture: ReturnType<typeof createScopedMemoryRuntimeTestFixture>;
  let stateDir = "";

  beforeEach(() => {
    fixture = createScopedMemoryRuntimeTestFixture();
    fixture.setup();
    stateDir = fixture.stateDir;
  });

  afterEach(() => {
    fixture.teardown();
  });

  it("keeps a reviewed conversation projection immutable through ordinary mutations", async () => {
    const sourceStore = createStore();
    const source = createBuiltinScopedMemoryResource({
      agentId: "main",
      store: sourceStore,
      logicalLocator: "projection-source.md",
      content: "private projection source",
      actor: { kind: "human", id: "principal-owner" },
      nowMs: 2_000,
    });
    const conversationStore = createBuiltinScopedMemoryStore({
      agentId: "main",
      scopeKind: "conversation",
      audienceKind: "conversation",
      audienceId: "conversation-1",
      authorityKind: "conversation",
      authorityOwnerId: "conversation-1",
      defaultCapabilities: ["retrieve", "read", "append", "replace", "delete"],
      actor: { kind: "human", id: "principal-owner" },
      reason: "conversation projection mutation regression",
      nowMs: 1_000,
    });
    const projectionCopy = createBuiltinScopedMemoryResource({
      agentId: "main",
      store: conversationStore,
      logicalLocator: "projections/reviewed-conversation-copy.md",
      content: "reviewed conversation cobalt copy",
      lifecycleState: "pending",
      actor: { kind: "human", id: "principal-owner" },
      expiresAt: NOW_MS + 1_000,
      nowMs: 3_000,
    });
    createBuiltinScopedMemoryResource({
      agentId: "main",
      store: conversationStore,
      logicalLocator: "conversation-note.md",
      content: "ordinary conversation mutable note",
      actor: { kind: "human", id: "principal-owner" },
      nowMs: 3_000,
    });
    const database = openOpenClawAgentDatabase({ agentId: "main" }).db;
    database
      .prepare(
        `INSERT INTO memory_projections (
          projection_id, agent_id, source_revision_id, target_agent_id, target_store_id,
          target_resource_id, target_revision_id, target_kind, target_audience_id,
          purpose, preview, publisher_kind, publisher_id, review_state, reviewer_kind,
          reviewer_id, review_reason, expires_at, revocation_behavior, supersedes_projection_id,
          created_at, reviewed_at, revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        "projection-conversation-immutable",
        "main",
        source.revisionId,
        "main",
        conversationStore.storeId,
        projectionCopy.resourceId,
        projectionCopy.revisionId,
        "conversation",
        "conversation-1",
        "reviewed conversation projection",
        "reviewed conversation copy",
        "local-agent-owner",
        "principal-owner",
        "pending",
        null,
        null,
        null,
        NOW_MS + 1_000,
        "tombstone",
        null,
        3_000,
        null,
        null,
      );
    database
      .prepare(
        `UPDATE memory_resource_revisions
            SET lifecycle_state = ?, activated_at = ?
          WHERE revision_id = ?`,
      )
      .run("active", 3_000, projectionCopy.revisionId);
    database
      .prepare(
        `UPDATE memory_projections
            SET review_state = ?, reviewer_kind = ?, reviewer_id = ?, reviewed_at = ?
          WHERE projection_id = ?`,
      )
      .run(
        "approved",
        "local-agent-owner",
        "principal-owner",
        3_000,
        "projection-conversation-immutable",
      );

    const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const readContext = createContext({
      subject: {
        version: 1,
        kind: "conversation",
        conversationPrincipalId: "conversation-1",
        channel: "test",
        accountId: "default",
      },
      actor: {
        kind: "unattributed",
        transportAuditRef: "conversation-projection-transport-audit",
        evidenceRevision: "conversation-projection-evidence",
      },
      verifiedPrincipals: [],
      conversation: {
        conversationPrincipalId: "conversation-1",
        channel: "test",
        accountId: "default",
        evidenceRevision: "conversation-projection-evidence",
      },
      delivery: {
        sinkKind: "channel",
        audiences: [{ kind: "conversation", id: "conversation-1" }],
        egressCapabilityIds: ["reply.final"],
        egressRegistryRevision: "conversation-projection-egress",
        deliveryRevision: "conversation-projection-delivery",
      },
    });
    const readPlan = await runtime.authorize(readContext);
    const projectionSearch = await runtime.searchAuthorized({
      context: readContext,
      plan: readPlan,
      query: "reviewed conversation cobalt",
      limit: 1,
    });
    const projectionTarget = projectionSearch.value[0]?.resourceHandle;
    if (!projectionTarget) {
      throw new Error("expected a conversation projection handle");
    }

    const expectProjectionMutationRejected = async (params: {
      operation: "append" | "replace" | "delete";
      mutation: AuthorizedMemoryMutation;
    }) => {
      const context: MemoryAccessContext = { ...readContext, operation: params.operation };
      const plan = await runtime.authorize(context);
      await expect(
        runtime.writeAuthorized({ context, plan, mutation: params.mutation }),
      ).rejects.toThrow("mutation placement is unavailable");
    };

    await expectProjectionMutationRejected({
      operation: "append",
      mutation: {
        version: 1,
        kind: "append",
        mutationId: "projection-append",
        idempotencyKey: "projection-append-key",
        content: "unreviewed append",
        contentType: "markdown",
        target: projectionTarget,
      },
    });
    await expectProjectionMutationRejected({
      operation: "replace",
      mutation: {
        version: 1,
        kind: "replace",
        mutationId: "projection-replace",
        idempotencyKey: "projection-replace-key",
        content: "unreviewed replacement",
        contentType: "markdown",
        target: projectionTarget,
      },
    });
    await expectProjectionMutationRejected({
      operation: "delete",
      mutation: {
        version: 1,
        kind: "delete",
        mutationId: "projection-delete",
        idempotencyKey: "projection-delete-key",
        target: projectionTarget,
      },
    });
    await expectProjectionMutationRejected({
      operation: "delete",
      mutation: {
        version: 1,
        kind: "tombstone",
        mutationId: "projection-tombstone",
        idempotencyKey: "projection-tombstone-key",
        target: projectionTarget,
      },
    });

    const ordinarySearch = await runtime.searchAuthorized({
      context: readContext,
      plan: readPlan,
      query: "ordinary conversation mutable",
      limit: 1,
    });
    const ordinaryTarget = ordinarySearch.value[0]?.resourceHandle;
    if (!ordinaryTarget) {
      throw new Error("expected an ordinary conversation handle");
    }
    const appendContext: MemoryAccessContext = { ...readContext, operation: "append" };
    const appendPlan = await runtime.authorize(appendContext);
    await expect(
      runtime.writeAuthorized({
        context: appendContext,
        plan: appendPlan,
        mutation: {
          version: 1,
          kind: "append",
          mutationId: "ordinary-conversation-append",
          idempotencyKey: "ordinary-conversation-append-key",
          content: "ordinary append",
          contentType: "markdown",
          target: ordinaryTarget,
        },
      }),
    ).resolves.toMatchObject({ status: "committed" });

    expect(
      database
        .prepare("SELECT lifecycle_state FROM memory_resource_revisions WHERE revision_id = ?")
        .get(projectionCopy.revisionId),
    ).toEqual({ lifecycle_state: "active" });
    expect(
      database
        .prepare("SELECT COUNT(*) AS count FROM memory_write_intents WHERE resource_id = ?")
        .get(projectionCopy.resourceId),
    ).toEqual({ count: 0 });
  });

  it("retries a failed audit delivery once and records the event idempotently", async () => {
    createStore({ defaultCapabilities: ["retrieve", "read", "append"] });
    const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const context = createContext({ operation: "append" });
    const plan = await runtime.authorize(context);
    await runtime.writeAuthorized({
      context,
      plan,
      mutation: {
        version: 1,
        kind: "remember",
        mutationId: "mutation-audit-primer",
        idempotencyKey: "audit-primer-key",
        content: "audit primer cobalt artifact",
        contentType: "markdown",
      },
    });
    const stateDatabase = new DatabaseSync(path.join(stateDir, "state", "openclaw.sqlite"));
    stateDatabase.exec(`
      CREATE TRIGGER fail_memory_access_audit
      BEFORE INSERT ON memory_access_audit
      BEGIN
        SELECT RAISE(ABORT, 'audit delivery failed');
      END;
    `);
    try {
      await runtime.writeAuthorized({
        context,
        plan,
        mutation: {
          version: 1,
          kind: "remember",
          mutationId: "mutation-audit-retry",
          idempotencyKey: "audit-retry-key",
          content: "audit retry cobalt artifact",
          contentType: "markdown",
        },
      });
      const agentDatabase = openOpenClawAgentDatabase({ agentId: "main" }).db;
      expect(
        agentDatabase
          .prepare(
            "SELECT state, attempts FROM memory_audit_outbox WHERE intent_id = (SELECT intent_id FROM memory_write_intents WHERE mutation_id = ?)",
          )
          .get("mutation-audit-retry"),
      ).toEqual({ state: "pending", attempts: 1 });

      stateDatabase.exec("DROP TRIGGER fail_memory_access_audit");
      await runtime.authorize({ ...context, requestId: "request-audit-retry" });

      const event = agentDatabase
        .prepare(
          "SELECT event_id, state, attempts FROM memory_audit_outbox WHERE intent_id = (SELECT intent_id FROM memory_write_intents WHERE mutation_id = ?)",
        )
        .get("mutation-audit-retry") as { event_id: string; state: string; attempts: number };
      expect(event).toMatchObject({ state: "delivered", attempts: 2 });
      expect(
        stateDatabase
          .prepare("SELECT COUNT(*) AS count FROM memory_access_audit WHERE event_id = ?")
          .get(event.event_id),
      ).toEqual({ count: 1 });
    } finally {
      stateDatabase.close();
    }
  });

  it("tombstones the catalog before removing every indexed and file artifact", async () => {
    createStore({ defaultCapabilities: ["retrieve", "read", "append", "delete"] });
    const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const appendContext = createContext({ operation: "append" });
    const appendPlan = await runtime.authorize(appendContext);
    const remembered = await runtime.writeAuthorized({
      context: appendContext,
      plan: appendPlan,
      mutation: {
        version: 1,
        kind: "remember",
        mutationId: "mutation-delete-source",
        idempotencyKey: "delete-source-key",
        content: "delete cobalt artifact",
        contentType: "markdown",
      },
    });
    const handle = remembered.resourceHandle;
    if (!handle) {
      throw new Error("expected remembered resource handle");
    }
    const database = openOpenClawAgentDatabase({ agentId: "main" });
    const artifact = database.db
      .prepare(
        `SELECT root.path_key, revision.artifact_locator
           FROM memory_resource_revisions AS revision
           JOIN memory_resources AS resource ON resource.resource_id = revision.resource_id
           JOIN memory_stores AS store ON store.store_id = resource.store_id
           JOIN memory_storage_roots AS root ON root.storage_root_id = store.storage_root_id
          WHERE revision.revision_id = ?`,
      )
      .get(handle.resourceRevision) as { path_key: string; artifact_locator: string };
    const artifactPath = resolveBuiltinScopedMemoryArtifactPath({
      databasePath: database.path,
      pathKey: artifact.path_key,
      artifactLocator: artifact.artifact_locator,
    });
    const deleteContext = { ...appendContext, operation: "delete" as const };
    const deletePlan = await runtime.authorize(deleteContext);

    await runtime.writeAuthorized({
      context: deleteContext,
      plan: deletePlan,
      mutation: {
        version: 1,
        kind: "tombstone",
        mutationId: "mutation-delete-1",
        idempotencyKey: "delete-key-1",
        target: handle,
      },
    });

    expect(
      database.db
        .prepare("SELECT lifecycle_state FROM memory_resource_revisions WHERE revision_id = ?")
        .get(handle.resourceRevision),
    ).toEqual({ lifecycle_state: "tombstoned" });
    expect(
      database.db
        .prepare("SELECT COUNT(*) AS count FROM memory_scoped_chunks WHERE revision_id = ?")
        .get(handle.resourceRevision),
    ).toEqual({ count: 0 });
    expect(fs.existsSync(artifactPath)).toBe(false);
    const readContext = { ...appendContext, operation: "read" as const };
    const readPlan = await runtime.authorize(readContext);
    await expect(
      runtime.readAuthorized({ context: readContext, plan: readPlan, handle }),
    ).rejects.toThrow("revision is unavailable");
  });

  it("preserves source policy requirements and tombstones every derived descendant", async () => {
    const store = createStore({
      defaultCapabilities: ["retrieve", "read", "append", "derive", "delete"],
    });
    const source = createBuiltinScopedMemoryResource({
      agentId: "main",
      store,
      logicalLocator: "source.md",
      content: "source cobalt lineage",
      actor: { kind: "human", id: "principal-owner" },
      nowMs: 2_000,
    });
    const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const readContext = createContext({ operation: "read" });
    const readPlan = await runtime.authorize(readContext);
    const sourceSearch = await runtime.searchAuthorized({
      context: readContext,
      plan: readPlan,
      query: "cobalt",
      limit: 1,
    });
    const sourceHandle = sourceSearch.value[0]?.resourceHandle;
    if (!sourceHandle) {
      throw new Error("expected source handle");
    }
    const deriveContext = createContext({ operation: "derive" });
    const derivePlan = await runtime.authorize(deriveContext);
    const derived = await runtime.writeAuthorized({
      context: deriveContext,
      plan: derivePlan,
      mutation: {
        version: 1,
        kind: "derive",
        mutationId: "mutation-derived-lineage",
        idempotencyKey: "derived-lineage-key",
        content: "derived cobalt lineage",
        contentType: "markdown",
        sourceHandles: [sourceHandle],
        sourcePolicySetId: sourceSearch.exposureReceipt.sourcePolicySetId,
      },
    });
    const derivedHandle = derived.resourceHandle;
    if (!derivedHandle) {
      throw new Error("expected derived handle");
    }
    const database = openOpenClawAgentDatabase({ agentId: "main" }).db;
    expect(
      database
        .prepare(
          "SELECT parent_revision_id, edge_kind FROM memory_lineage_edges WHERE child_revision_id = ?",
        )
        .all(derivedHandle.resourceRevision),
    ).toEqual([{ parent_revision_id: source.revisionId, edge_kind: "derive" }]);
    expect(
      database
        .prepare(
          `SELECT stable_policy_id, captured_revision_id, expected_active_revision_id,
                  expected_revocation_epoch
             FROM memory_revision_policy_requirements
            WHERE revision_id = ?`,
        )
        .all(derivedHandle.resourceRevision),
    ).toEqual([
      {
        stable_policy_id: store.policyId,
        captured_revision_id: store.policyRevisionId,
        expected_active_revision_id: store.policyRevisionId,
        expected_revocation_epoch: store.policyRevocationEpoch,
      },
    ]);

    const deleteContext = createContext({ operation: "delete" });
    const deletePlan = await runtime.authorize(deleteContext);
    await runtime.writeAuthorized({
      context: deleteContext,
      plan: deletePlan,
      mutation: {
        version: 1,
        kind: "tombstone",
        mutationId: "mutation-tombstone-lineage",
        idempotencyKey: "tombstone-lineage-key",
        target: sourceHandle,
      },
    });

    expect(
      database
        .prepare("SELECT lifecycle_state FROM memory_resource_revisions WHERE revision_id = ?")
        .get(derivedHandle.resourceRevision),
    ).toEqual({ lifecycle_state: "tombstoned" });
    expect(
      database
        .prepare("SELECT COUNT(*) AS count FROM memory_scoped_chunks WHERE revision_id = ?")
        .get(derivedHandle.resourceRevision),
    ).toEqual({ count: 0 });
    await expect(
      runtime.readAuthorized({ context: readContext, plan: readPlan, handle: derivedHandle }),
    ).rejects.toThrow("revision is unavailable");
  });

  it("carries a finite source expiry into derived copies", async () => {
    let nowMs = NOW_MS;
    const store = createStore({ defaultCapabilities: ["retrieve", "read", "derive"] });
    createBuiltinScopedMemoryResource({
      agentId: "main",
      store,
      logicalLocator: "expiring-source.md",
      content: "temporary cobalt source",
      actor: { kind: "human", id: "principal-owner" },
      expiresAt: NOW_MS + 100,
      nowMs: 2_000,
    });
    const runtime = createBuiltinScopedMemoryRuntime({ now: () => nowMs });
    const readContext = createContext({ operation: "read" });
    const readPlan = await runtime.authorize(readContext);
    const sourceSearch = await runtime.searchAuthorized({
      context: readContext,
      plan: readPlan,
      query: "temporary cobalt",
      limit: 1,
    });
    const sourceHandle = sourceSearch.value[0]?.resourceHandle;
    if (!sourceHandle) {
      throw new Error("expected expiring source handle");
    }
    const deriveContext = createContext({ operation: "derive" });
    const derivePlan = await runtime.authorize(deriveContext);
    const derived = await runtime.writeAuthorized({
      context: deriveContext,
      plan: derivePlan,
      mutation: {
        version: 1,
        kind: "derive",
        mutationId: "mutation-expiring-derived",
        idempotencyKey: "expiring-derived-key",
        content: "temporary cobalt derivative",
        contentType: "markdown",
        sourceHandles: [sourceHandle],
        sourcePolicySetId: sourceSearch.exposureReceipt.sourcePolicySetId,
      },
    });
    const derivedHandle = derived.resourceHandle;
    if (!derivedHandle) {
      throw new Error("expected derived handle");
    }
    const database = openOpenClawAgentDatabase({ agentId: "main" }).db;
    expect(
      database
        .prepare("SELECT expires_at FROM memory_resource_revisions WHERE revision_id = ?")
        .get(derivedHandle.resourceRevision),
    ).toEqual({ expires_at: NOW_MS + 100 });

    nowMs = NOW_MS + 100;
    const expiredPlan = await runtime.authorize(readContext);
    const expiredSearch = await runtime.searchAuthorized({
      context: readContext,
      plan: expiredPlan,
      query: "temporary cobalt derivative",
      limit: 1,
    });
    expect(expiredSearch.value).toEqual([]);
  });
});
