import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import type {
  AuthorizedMemoryPlan,
  AuthorizedResourceHandle,
} from "openclaw/plugin-sdk/memory-authorization";
import { loadSqliteVecExtension } from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import {
  AGENT_SCOPED_MEMORY_SCHEMA_SQL,
  openOpenClawAgentDatabase,
} from "openclaw/plugin-sdk/sqlite-runtime";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  createBuiltinScopedMemoryResource,
  readScopedMemorySqliteVecCandidatePage,
  readScopedMemoryVectorCandidatePage,
  reviseBuiltinScopedMemoryPolicy,
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

  beforeEach(() => {
    fixture = createScopedMemoryRuntimeTestFixture();
    fixture.setup();
  });

  afterEach(() => {
    fixture.teardown();
  });

  it("authorizes import, export, sync, and status without caller-selected stores", async () => {
    createStore({
      defaultCapabilities: ["retrieve", "read", "append", "import", "export", "sync", "status"],
    });
    const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const appendContext = createContext({ operation: "append" });
    const appendPlan = await runtime.authorize(appendContext);
    const remembered = await runtime.writeAuthorized({
      context: appendContext,
      plan: appendPlan,
      mutation: {
        version: 1,
        kind: "remember",
        mutationId: "mutation-export-source",
        idempotencyKey: "export-source-key",
        content: "export amber artifact",
        contentType: "markdown",
      },
    });
    const handle = remembered.resourceHandle;
    if (!handle) {
      throw new Error("expected remembered resource handle");
    }
    const importContext = { ...appendContext, operation: "import" as const };
    const importPlan = await runtime.authorize(importContext);
    const imported = await runtime.importAuthorized({
      context: importContext,
      plan: importPlan,
      mutation: {
        version: 1,
        kind: "import",
        mutationId: "mutation-import-1",
        idempotencyKey: "import-key-1",
        content: "imported amber artifact",
        contentType: "markdown",
      },
    });
    expect(imported.status).toBe("committed");
    const exportContext = { ...appendContext, operation: "export" as const };
    const exportPlan = await runtime.authorize(exportContext);
    const exported = await runtime.exportAuthorized({
      context: exportContext,
      plan: exportPlan,
      handles: [handle],
    });
    expect(JSON.parse(exported.value.payload)).toEqual([
      { revisionId: handle.resourceRevision, content: "export amber artifact" },
    ]);
    expect(exported.exposureReceipt.exposedRevisionHandles).toEqual([handle.resourceRevision]);
    const syncContext = { ...appendContext, operation: "sync" as const };
    const syncPlan = await runtime.authorize(syncContext);
    await expect(
      runtime.syncAuthorized({ context: syncContext, plan: syncPlan }),
    ).resolves.toMatchObject({
      value: { status: "completed" },
    });
    const statusContext = { ...appendContext, operation: "status" as const };
    const statusPlan = await runtime.authorize(statusContext);
    await expect(
      runtime.statusAuthorized({ context: statusContext, plan: statusPlan }),
    ).resolves.toMatchObject({
      value: { backend: "builtin", files: 2 },
    });
  });

  it("does not expose an inaccessible store through status counts", async () => {
    const allowedStore = createStore({ defaultCapabilities: ["retrieve", "read", "status"] });
    const hiddenStore = createStore({
      audienceId: "principal-other",
      authorityOwnerId: "principal-other",
      defaultCapabilities: ["retrieve", "read", "status"],
    });
    createBuiltinScopedMemoryResource({
      agentId: "main",
      store: allowedStore,
      logicalLocator: "visible-status.md",
      content: "visible cobalt status",
      actor: { kind: "human", id: "principal-owner" },
      nowMs: 2_000,
    });
    createBuiltinScopedMemoryResource({
      agentId: "main",
      store: hiddenStore,
      logicalLocator: "hidden-status.md",
      content: "hidden cobalt status",
      actor: { kind: "human", id: "principal-other" },
      nowMs: 2_001,
    });
    const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const context = createContext({ operation: "status" });
    const plan = await runtime.authorize(context);

    await expect(runtime.statusAuthorized({ context, plan })).resolves.toMatchObject({
      value: { files: 1, custom: { mounts: 1, resources: 1 } },
    });
  });

  it("quarantines an unmapped watcher artifact before it can become searchable", async () => {
    const store = createStore();
    const database = openOpenClawAgentDatabase({ agentId: "main" });
    const root = database.db
      .prepare(
        `SELECT root.path_key
           FROM memory_stores AS store
           JOIN memory_storage_roots AS root ON root.storage_root_id = store.storage_root_id
          WHERE store.store_id = ?`,
      )
      .get(store.storeId) as { path_key: string };
    const probe = resolveBuiltinScopedMemoryArtifactPath({
      databasePath: database.path,
      pathKey: root.path_key,
      artifactLocator: "r1_aaaaaaaaaaaaaaaaaaaaaaaa.md",
    });
    const orphanPath = path.join(path.dirname(probe), "watcher-unmapped.md");
    fs.writeFileSync(orphanPath, "unmapped watcher cobalt", "utf8");

    const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const context = createContext();
    const plan = await runtime.authorize(context);
    const result = await runtime.searchAuthorized({
      context,
      plan,
      query: "watcher cobalt",
      limit: 1,
    });

    expect(result.value).toEqual([]);
    expect(fs.existsSync(orphanPath)).toBe(false);
    expect(
      fs.readdirSync(path.join(path.dirname(path.dirname(orphanPath)), ".quarantine")),
    ).toHaveLength(1);
  });

  it("quarantines a corrupted active artifact and removes its search eligibility", async () => {
    createStore({ defaultCapabilities: ["retrieve", "read", "append"] });
    const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const appendContext = createContext({ operation: "append" });
    const appendPlan = await runtime.authorize(appendContext);
    const remembered = await runtime.writeAuthorized({
      context: appendContext,
      plan: appendPlan,
      mutation: {
        version: 1,
        kind: "remember",
        mutationId: "mutation-corrupt-active",
        idempotencyKey: "corrupt-active-key",
        content: "corrupt cobalt artifact",
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
    fs.writeFileSync(artifactPath, "corrupted active artifact", "utf8");

    const recoveryRuntime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const readContext = { ...appendContext, operation: "read" as const };
    const readPlan = await recoveryRuntime.authorize(readContext);
    await expect(
      recoveryRuntime.searchAuthorized({
        context: readContext,
        plan: readPlan,
        query: "corrupt cobalt",
        limit: 1,
      }),
    ).resolves.toMatchObject({ value: [] });
    expect(
      database.db
        .prepare("SELECT state FROM memory_write_intents WHERE mutation_id = ?")
        .get("mutation-corrupt-active"),
    ).toEqual({ state: "quarantined" });
    expect(
      database.db
        .prepare("SELECT COUNT(*) AS count FROM memory_scoped_chunks WHERE revision_id = ?")
        .get(handle.resourceRevision),
    ).toEqual({ count: 0 });
    expect(fs.existsSync(artifactPath)).toBe(false);
  });

  it("applies deny precedence and policy-entry expiry", async () => {
    const deniedStore = createStore({
      policyEntries: [
        {
          effect: "deny",
          principalId: "principal-owner",
          operation: "read",
          grantorPrincipalId: "principal-owner",
          reason: "deny test",
        },
      ],
    });
    createBuiltinScopedMemoryResource({
      agentId: "main",
      store: deniedStore,
      logicalLocator: "denied.md",
      content: "private cobalt sentinel",
      actor: { kind: "human", id: "principal-owner" },
      nowMs: 2_000,
    });
    const expiredStore = createStore({
      defaultCapabilities: [],
      policyEntries: [
        {
          effect: "allow",
          principalId: "principal-owner",
          operation: "retrieve",
          grantorPrincipalId: "principal-owner",
          reason: "expired test",
          expiresAt: NOW_MS,
        },
        {
          effect: "allow",
          principalId: "principal-owner",
          operation: "read",
          grantorPrincipalId: "principal-owner",
          reason: "expired test",
          expiresAt: NOW_MS,
        },
      ],
    });
    createBuiltinScopedMemoryResource({
      agentId: "main",
      store: expiredStore,
      logicalLocator: "expired.md",
      content: "private cobalt expired",
      actor: { kind: "human", id: "principal-owner" },
      nowMs: 2_000,
    });
    const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const context = createContext();
    const plan = await runtime.authorize(context);

    const result = await runtime.searchAuthorized({
      context,
      plan,
      query: "cobalt",
      limit: 10,
    });

    expect(plan.mounts).toEqual([]);
    expect(result.value).toEqual([]);
    expect(JSON.stringify(result)).not.toContain("cobalt");
  });

  it("excludes pending, quarantined, tombstoned, expired, and stale-hash revisions", async () => {
    const store = createStore();
    const cases = [
      ["pending.md", "pending", undefined],
      ["quarantined.md", "quarantined", undefined],
      ["tombstoned.md", "tombstoned", undefined],
      ["expired.md", "active", NOW_MS],
      ["stale.md", "active", undefined],
      ["allowed.md", "active", undefined],
    ] as const;
    const resources = cases.map(([logicalLocator, lifecycleState, expiresAt], index) =>
      createBuiltinScopedMemoryResource({
        agentId: "main",
        store,
        logicalLocator,
        content: `sharedtoken ${logicalLocator}`,
        lifecycleState,
        actor: { kind: "human", id: "principal-owner" },
        ...(expiresAt !== undefined ? { expiresAt } : {}),
        nowMs: 2_000 + index,
      }),
    );
    const database = openOpenClawAgentDatabase({ agentId: "main" });
    const stale = database.db
      .prepare(
        `SELECT root.path_key, revision.artifact_locator
           FROM memory_resource_revisions AS revision
           JOIN memory_resources AS resource ON resource.resource_id = revision.resource_id
           JOIN memory_stores AS store ON store.store_id = resource.store_id
           JOIN memory_storage_roots AS root ON root.storage_root_id = store.storage_root_id
          WHERE revision.revision_id = ?`,
      )
      .get(resources[4]!.revisionId) as { path_key: string; artifact_locator: string };
    fs.writeFileSync(
      resolveBuiltinScopedMemoryArtifactPath({
        databasePath: database.path,
        pathKey: stale.path_key,
        artifactLocator: stale.artifact_locator,
      }),
      "tampered sharedtoken",
      "utf8",
    );
    const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const context = createContext();
    const plan = await runtime.authorize(context);

    const result = await runtime.searchAuthorized({
      context,
      plan,
      query: "sharedtoken",
      limit: 10,
    });

    expect(result.value.map((entry) => entry.path)).toEqual(["allowed.md"]);
  });

  it("pages past a full denied candidate page to preserve the authorized superset", async () => {
    const store = createStore();
    const resource = createBuiltinScopedMemoryResource({
      agentId: "main",
      store,
      logicalLocator: "authorized.md",
      content: "authorized paging sentinel",
      actor: { kind: "human", id: "principal-owner" },
      nowMs: 2_000,
    });
    const database = openOpenClawAgentDatabase({ agentId: "main" }).db;
    const allowedChunk = database
      .prepare("SELECT chunk_id FROM memory_scoped_chunks WHERE revision_id = ?")
      .get(resource.revisionId) as { chunk_id: string };
    const candidates = [
      ...Array.from({ length: 20 }, (_, index) => ({
        chunkId: `denied-chunk-${index}`,
        revisionId: `denied-revision-${index}`,
        score: 1 - index / 100,
      })),
      {
        chunkId: allowedChunk.chunk_id,
        revisionId: resource.revisionId,
        score: 0.5,
      },
    ];
    const offsets: number[] = [];
    const runtime = createBuiltinScopedMemoryRuntime({
      now: () => NOW_MS,
      candidatePageReader: (params) => {
        offsets.push(params.offset);
        return candidates.slice(params.offset, params.offset + params.limit);
      },
    });
    const context = createContext();
    const plan = await runtime.authorize(context);

    const result = await runtime.searchAuthorized({
      context,
      plan,
      query: "paging",
      limit: 1,
    });

    expect(offsets).toEqual([0, 20]);
    expect(result.value.map((entry) => entry.path)).toEqual(["authorized.md"]);
  });

  it("rejects plan and handle tampering and keeps receipts immutable", async () => {
    const store = createStore();
    createBuiltinScopedMemoryResource({
      agentId: "main",
      store,
      logicalLocator: "bound.md",
      content: "bound amber sentinel",
      actor: { kind: "human", id: "principal-owner" },
      nowMs: 2_000,
    });
    const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const context = createContext();
    const plan = await runtime.authorize(context);
    const search = await runtime.searchAuthorized({
      context,
      plan,
      query: "amber",
      limit: 1,
    });
    const handle = search.value[0]!.resourceHandle;

    const tamperedPlans: AuthorizedMemoryPlan[] = [
      { ...plan, memoryPolicyRevision: "mpr1_forged" },
      {
        ...plan,
        mounts: [{ ...plan.mounts[0]!, mountHandle: `mm1_${"x".repeat(32)}` }],
      },
      { ...plan, bootstrapResourceHandles: [handle] },
      {
        ...plan,
        allowedEgressAudiences: [{ kind: "user", id: "principal-attacker" }],
      },
      { ...plan, expiresAt: "not-a-timestamp" },
    ];
    for (const tamperedPlan of tamperedPlans) {
      await expect(
        runtime.searchAuthorized({
          context,
          plan: tamperedPlan,
          query: "amber",
          limit: 1,
        }),
      ).rejects.toThrow("plan is unavailable");
    }

    const tamperedHandles: AuthorizedResourceHandle[] = [
      { ...handle, version: 2 as 1 },
      { ...handle, handleId: `mrh1_${"x".repeat(32)}` },
      { ...handle, planId: `mp1_${"x".repeat(32)}` },
      { ...handle, contextFingerprint: "sha256:forged" },
      { ...handle, resourceRevision: "resource-revision-forged" },
      { ...handle, policyRevision: "policy-revision-forged" },
      { ...handle, expiresAt: "2099-01-01T00:00:00.000Z" },
    ];
    for (const tamperedHandle of tamperedHandles) {
      await expect(
        runtime.readAuthorized({ context, plan, handle: tamperedHandle }),
      ).rejects.toThrow("revision is unavailable");
    }

    const read = await runtime.readAuthorized({
      context,
      plan: structuredClone(plan),
      handle: structuredClone(handle),
    });
    expect(read.egressReceipt).toMatchObject({
      planId: plan.planId,
      allowedAudiences: plan.allowedEgressAudiences,
      expiresAt: plan.expiresAt,
    });
    expect(Object.isFrozen(read.exposureReceipt)).toBe(true);
    expect(Object.isFrozen(read.egressReceipt)).toBe(true);

    const database = openOpenClawAgentDatabase({ agentId: "main" }).db;
    const persisted = database
      .prepare(
        `SELECT receipt_id, plan_id, allowed_audiences_json, expires_at
           FROM memory_egress_receipts
          WHERE receipt_id = ?`,
      )
      .get(read.egressReceipt.receiptId) as {
      receipt_id: string;
      plan_id: string;
      allowed_audiences_json: string;
      expires_at: number;
    };
    expect(persisted).toEqual({
      receipt_id: read.egressReceipt.receiptId,
      plan_id: plan.planId,
      allowed_audiences_json: JSON.stringify(plan.allowedEgressAudiences),
      expires_at: Date.parse(plan.expiresAt),
    });
    expect(() =>
      database
        .prepare("UPDATE memory_egress_receipts SET plan_id = ? WHERE receipt_id = ?")
        .run("forged", read.egressReceipt.receiptId),
    ).toThrow("immutable");
    expect(() =>
      database
        .prepare("DELETE FROM memory_exposure_receipts WHERE receipt_id = ?")
        .run(read.exposureReceipt.receiptId),
    ).toThrow("cannot be deleted");

    reviseBuiltinScopedMemoryPolicy({
      agentId: "main",
      policyId: store.policyId,
      entries: [],
      actor: { kind: "human", id: "principal-owner" },
      reason: "revoke old handles",
      nowMs: 9_000,
    });
    await expect(runtime.readAuthorized({ context, plan, handle })).rejects.toThrow(
      "plan is unavailable",
    );
  });

  it("fails before returning content when receipt persistence fails", async () => {
    const store = createStore();
    createBuiltinScopedMemoryResource({
      agentId: "main",
      store,
      logicalLocator: "receipt.md",
      content: "receipt violet sentinel",
      actor: { kind: "human", id: "principal-owner" },
      nowMs: 2_000,
    });
    const database = openOpenClawAgentDatabase({ agentId: "main" }).db;
    database.exec(`
      CREATE TRIGGER fail_memory_egress_receipt
      BEFORE INSERT ON memory_egress_receipts
      BEGIN
        SELECT RAISE(ABORT, 'receipt persistence failed');
      END;
    `);
    const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const context = createContext();
    const plan = await runtime.authorize(context);

    await expect(
      runtime.searchAuthorized({ context, plan, query: "violet", limit: 1 }),
    ).rejects.toThrow("receipt persistence failed");
    expect(
      database.prepare("SELECT COUNT(*) AS count FROM memory_exposure_receipts").get(),
    ).toEqual({ count: 0 });
  });

  it("retries opaque resource-handle collisions", async () => {
    const store = createStore();
    for (const logicalLocator of ["one.md", "two.md"]) {
      createBuiltinScopedMemoryResource({
        agentId: "main",
        store,
        logicalLocator,
        content: `collision silver ${logicalLocator}`,
        actor: { kind: "human", id: "principal-owner" },
        nowMs: 2_000,
      });
    }
    const firstHandle = `mrh1_${"a".repeat(32)}`;
    const secondHandle = `mrh1_${"b".repeat(32)}`;
    let resourceCalls = 0;
    const runtime = createBuiltinScopedMemoryRuntime({
      now: () => NOW_MS,
      generateOpaqueId(kind) {
        if (kind === "plan") {
          return `mp1_${"p".repeat(32)}`;
        }
        if (kind === "mount") {
          return `mm1_${"m".repeat(32)}`;
        }
        resourceCalls += 1;
        return resourceCalls <= 2 ? firstHandle : secondHandle;
      },
    });
    const context = createContext();
    const plan = await runtime.authorize(context);
    const result = await runtime.searchAuthorized({
      context,
      plan,
      query: "silver",
      limit: 2,
    });

    expect(result.value.map((entry) => entry.resourceHandle.handleId).toSorted()).toEqual(
      [firstHandle, secondHandle].toSorted(),
    );
    expect(resourceCalls).toBe(3);
  });

  it("preserves the authorized candidate superset in vector-scan mode", async () => {
    const store = createStore();
    createBuiltinScopedMemoryResource({
      agentId: "main",
      store,
      logicalLocator: "vector.md",
      content: "vector emerald sentinel",
      vectors: [[1, 0]],
      actor: { kind: "human", id: "principal-owner" },
      nowMs: 2_000,
    });
    const runtime = createBuiltinScopedMemoryRuntime({
      now: () => NOW_MS,
      candidatePageReader: readScopedMemoryVectorCandidatePage,
      embedQuery: () => [1, 0],
    });
    const context = createContext();
    const plan = await runtime.authorize(context);

    const result = await runtime.searchAuthorized({ context, plan, query: "ignored", limit: 1 });

    expect(result.value).toHaveLength(1);
    expect(result.value[0]?.path).toBe("vector.md");
    expect(result.value[0]?.vectorScore).toBeCloseTo(1);
  });

  it("prevents unauthorized sqlite-vec rows from crowding out authorized candidates", async () => {
    const database = new DatabaseSync(":memory:", { allowExtension: true });
    const loaded = await loadSqliteVecExtension({ db: database });
    expect(loaded.ok, loaded.error).toBe(true);
    database.exec(AGENT_SCOPED_MEMORY_SCHEMA_SQL);
    database.exec("PRAGMA foreign_keys = OFF");
    database
      .prepare(
        "INSERT INTO memory_resources (resource_id, agent_id, store_id, logical_locator, source, created_at) VALUES ('resource-1', 'main', 'store-1', 'sqlite-vec.md', 'memory', 1)",
      )
      .run();
    database
      .prepare(
        "INSERT INTO memory_resources (resource_id, agent_id, store_id, logical_locator, source, created_at) VALUES ('resource-denied', 'main', 'store-denied', 'denied.md', 'memory', 1)",
      )
      .run();
    database
      .prepare(
        `INSERT INTO memory_resource_revisions
          (revision_id, resource_id, revision_number, artifact_locator, content_hash, content_bytes,
           policy_revision_id, policy_revocation_epoch, source_policy_set_id, lifecycle_state,
           actor_kind, created_at, activated_at)
         VALUES ('revision-1', 'resource-1', 1, 'r1_aaaaaaaaaaaaaaaaaa.md', 'hash', 1,
                 'policy-revision-1', 0, 'policy-set-1', 'active', 'system', 1, 1)`,
      )
      .run();
    database
      .prepare(
        `INSERT INTO memory_resource_revisions
          (revision_id, resource_id, revision_number, artifact_locator, content_hash, content_bytes,
           policy_revision_id, policy_revocation_epoch, source_policy_set_id, lifecycle_state,
           actor_kind, created_at, activated_at)
         VALUES ('revision-denied', 'resource-denied', 1, 'r1_bbbbbbbbbbbbbbbbbb.md', 'hash', 1,
                 'policy-revision-denied', 0, 'policy-set-denied', 'active', 'system', 1, 1)`,
      )
      .run();
    database
      .prepare(
        `INSERT INTO memory_scoped_chunks
          (chunk_id, revision_id, chunk_ordinal, start_line, end_line, text, content_hash, model, updated_at)
         VALUES ('chunk-1', 'revision-1', 0, 1, 1, 'sqlite vec', 'hash', 'fixture-vector-v1', 1)`,
      )
      .run();
    database
      .prepare(
        `INSERT INTO memory_scoped_chunks
          (chunk_id, revision_id, chunk_ordinal, start_line, end_line, text, content_hash, model, updated_at)
         VALUES ('chunk-denied', 'revision-denied', 0, 1, 1, 'denied sqlite vec', 'hash', 'fixture-vector-v1', 1)`,
      )
      .run();
    database.exec(
      "CREATE VIRTUAL TABLE memory_scoped_chunks_vec USING vec0(chunk_id TEXT PRIMARY KEY, embedding FLOAT[2])",
    );
    database
      .prepare("INSERT INTO memory_scoped_chunks_vec (chunk_id, embedding) VALUES (?, ?)")
      .run("chunk-1", Buffer.from(new Float32Array([0.8, 0.2]).buffer));
    database
      .prepare("INSERT INTO memory_scoped_chunks_vec (chunk_id, embedding) VALUES (?, ?)")
      .run("chunk-denied", Buffer.from(new Float32Array([1, 0]).buffer));

    const candidates = await readScopedMemorySqliteVecCandidatePage({
      database,
      query: "ignored",
      queryVector: [1, 0],
      storeIds: ["store-1"],
      sources: ["memory"],
      limit: 1,
      offset: 0,
    });

    expect(candidates).toEqual([
      expect.objectContaining({ chunkId: "chunk-1", revisionId: "revision-1" }),
    ]);
    database.close();
  });
});
