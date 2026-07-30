import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import type {
  AuthorizedMemoryMutation,
  AuthorizedMemoryPlan,
  AuthorizedResourceHandle,
  MemoryAccessContext,
} from "openclaw/plugin-sdk/memory-authorization";
import { loadSqliteVecExtension } from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import { openOpenClawAgentDatabase } from "openclaw/plugin-sdk/sqlite-runtime";
import { AGENT_SCOPED_MEMORY_SCHEMA_SQL } from "openclaw/plugin-sdk/sqlite-runtime";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createBuiltinScopedMemoryResource,
  createBuiltinScopedMemoryStore,
  readScopedMemorySqliteVecCandidatePage,
  readScopedMemoryVectorCandidatePage,
  reviseBuiltinScopedMemoryPolicy,
} from "../../test-api.js";
import { resolveBuiltinScopedMemoryArtifactPath } from "./scoped-memory-resources.js";
import { createBuiltinScopedMemoryRuntime } from "./scoped-memory-runtime.js";

const NOW_MS = 10_000;

function createContext(overrides: Partial<MemoryAccessContext> = {}): MemoryAccessContext {
  return {
    version: 1,
    contextId: "context-1",
    contextFingerprint: "sha256:context-1",
    requestId: "request-1",
    runId: "run-1",
    agentId: "main",
    sessionKey: "agent:main:main",
    sessionId: "session-1",
    sessionIdentityRevision: "session-revision-1",
    subjectRevision: "subject-revision-1",
    subject: {
      version: 1,
      kind: "user",
      principalId: "principal-owner",
      creationEvidence: { kind: "gateway-profile", revision: "creation-revision-1" },
    },
    actor: {
      kind: "principal",
      actorKind: "human",
      principalId: "principal-owner",
      assurance: "gateway-profile",
      evidenceRevision: "actor-revision-1",
    },
    verifiedPrincipals: [
      {
        principalId: "principal-owner",
        assurance: "gateway-profile",
        evidenceRevision: "principal-revision-1",
      },
    ],
    delivery: {
      sinkKind: "private",
      audiences: [{ kind: "user", id: "principal-owner" }],
      egressCapabilityIds: ["reply.final"],
      egressRegistryRevision: "egress-revision-1",
      deliveryRevision: "delivery-revision-1",
    },
    collaboration: { kind: "not-applicable" },
    verifiedMemberships: [],
    operation: "read",
    hostFactsRevision: "host-facts-revision-1",
    ...overrides,
  };
}

describe("builtin authorized scoped memory runtime", () => {
  let stateDir = "";

  beforeEach(() => {
    stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-scoped-memory-runtime-"));
    vi.stubEnv("OPENCLAW_STATE_DIR", stateDir);
  });

  afterEach(() => {
    try {
      openOpenClawAgentDatabase({ agentId: "main" }).db.close();
    } catch {}
    vi.unstubAllEnvs();
    fs.rmSync(stateDir, { recursive: true, force: true });
  });

  function createStore(
    params: {
      agentId?: string;
      audienceId?: string;
      authorityOwnerId?: string;
      defaultCapabilities?: Parameters<
        typeof createBuiltinScopedMemoryStore
      >[0]["defaultCapabilities"];
      policyEntries?: Parameters<typeof createBuiltinScopedMemoryStore>[0]["policyEntries"];
    } = {},
  ) {
    return createBuiltinScopedMemoryStore({
      agentId: params.agentId ?? "main",
      scopeKind: "user",
      audienceKind: "user",
      audienceId: params.audienceId ?? "principal-owner",
      authorityKind: "user",
      authorityOwnerId: params.authorityOwnerId ?? "principal-owner",
      defaultCapabilities: params.defaultCapabilities ?? ["retrieve", "read"],
      ...(params.policyEntries ? { policyEntries: params.policyEntries } : {}),
      actor: { kind: "human", id: "principal-owner" },
      reason: "runtime test placement",
      nowMs: 1_000,
    });
  }

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

  it("commits a subject-selected remember through the pending-to-active lifecycle", async () => {
    createStore({ defaultCapabilities: ["retrieve", "read", "append"] });
    const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const context = createContext({ operation: "append" });
    const plan = await runtime.authorize(context);

    const result = await runtime.writeAuthorized({
      context,
      plan,
      mutation: {
        version: 1,
        kind: "remember",
        mutationId: "mutation-remember-1",
        idempotencyKey: "remember-key-1",
        content: "authorized crimson memory",
        contentType: "markdown",
      },
    });

    expect(result).toMatchObject({
      mutationId: "mutation-remember-1",
      status: "committed",
      policyRevision: plan.memoryPolicyRevision,
      resourceHandle: {
        planId: plan.planId,
        contextFingerprint: context.contextFingerprint,
      },
    });
    const database = openOpenClawAgentDatabase({ agentId: "main" }).db;
    expect(
      database
        .prepare("SELECT state, indexed_at FROM memory_write_intents WHERE mutation_id = ?")
        .get("mutation-remember-1"),
    ).toEqual({ state: "active", indexed_at: NOW_MS });
    expect(
      database
        .prepare("SELECT decision, state FROM memory_audit_outbox WHERE operation = ?")
        .get("append"),
    ).toEqual({ decision: "committed", state: "delivered" });
  });

  it.each(["pending", "renamed", "activated", "indexed"] as const)(
    "recovers a valid interrupted write after the %s boundary",
    async (interruptionPoint) => {
      const agentId = `recovery-${interruptionPoint}`;
      createStore({
        agentId,
        defaultCapabilities: ["retrieve", "read", "append"],
      });
      const context = createContext({
        agentId,
        operation: "append",
        sessionKey: `agent:${agentId}:main`,
        sessionId: `session-${interruptionPoint}`,
      });
      const failingRuntime = createBuiltinScopedMemoryRuntime({
        now: () => NOW_MS,
        onMutationPhase: (phase) => {
          if (phase === interruptionPoint) {
            throw new Error(`interrupt-${phase}`);
          }
        },
      });
      const failingPlan = await failingRuntime.authorize(context);
      await expect(
        failingRuntime.writeAuthorized({
          context,
          plan: failingPlan,
          mutation: {
            version: 1,
            kind: "remember",
            mutationId: `mutation-${interruptionPoint}`,
            idempotencyKey: `key-${interruptionPoint}`,
            content: `recovery ${interruptionPoint} cobalt`,
            contentType: "markdown",
          },
        }),
      ).rejects.toThrow(`interrupt-${interruptionPoint}`);

      const recoveryRuntime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
      const readContext = { ...context, operation: "read" as const };
      const readPlan = await recoveryRuntime.authorize(readContext);
      const recovered = await recoveryRuntime.searchAuthorized({
        context: readContext,
        plan: readPlan,
        query: `recovery ${interruptionPoint}`,
        limit: 1,
      });

      expect(recovered.value).toHaveLength(1);
      const database = openOpenClawAgentDatabase({ agentId }).db;
      expect(
        database
          .prepare("SELECT state, indexed_at FROM memory_write_intents WHERE mutation_id = ?")
          .get(`mutation-${interruptionPoint}`),
      ).toEqual({ state: "active", indexed_at: NOW_MS });
      expect(
        database
          .prepare(
            "SELECT decision, state FROM memory_audit_outbox WHERE intent_id = (SELECT intent_id FROM memory_write_intents WHERE mutation_id = ?)",
          )
          .get(`mutation-${interruptionPoint}`),
      ).toEqual({ decision: "committed", state: "delivered" });
    },
  );

  it("discards an interrupted staged artifact before it gains a durable catalog mapping", async () => {
    createStore({ defaultCapabilities: ["retrieve", "read", "append"] });
    const context = createContext({ operation: "append" });
    const failingRuntime = createBuiltinScopedMemoryRuntime({
      now: () => NOW_MS,
      onMutationPhase: (phase) => {
        if (phase === "staged") {
          throw new Error("interrupt-staged");
        }
      },
    });
    const plan = await failingRuntime.authorize(context);

    await expect(
      failingRuntime.writeAuthorized({
        context,
        plan,
        mutation: {
          version: 1,
          kind: "remember",
          mutationId: "mutation-staged",
          idempotencyKey: "key-staged",
          content: "staged cobalt artifact",
          contentType: "markdown",
        },
      }),
    ).rejects.toThrow("interrupt-staged");

    const database = openOpenClawAgentDatabase({ agentId: "main" }).db;
    expect(database.prepare("SELECT COUNT(*) AS count FROM memory_write_intents").get()).toEqual({
      count: 0,
    });
    const recoveryRuntime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const readContext = { ...context, operation: "read" as const };
    const readPlan = await recoveryRuntime.authorize(readContext);
    await expect(
      recoveryRuntime.searchAuthorized({
        context: readContext,
        plan: readPlan,
        query: "staged cobalt",
        limit: 1,
      }),
    ).resolves.toMatchObject({ value: [] });
  });

  it("treats an exact retry as one durable mutation", async () => {
    createStore({ defaultCapabilities: ["retrieve", "read", "append"] });
    const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const context = createContext({ operation: "append" });
    const plan = await runtime.authorize(context);
    const mutation = {
      version: 1 as const,
      kind: "remember" as const,
      mutationId: "mutation-idempotent",
      idempotencyKey: "idempotency-key",
      content: "idempotent cobalt artifact",
      contentType: "markdown" as const,
    };

    await expect(runtime.writeAuthorized({ context, plan, mutation })).resolves.toMatchObject({
      status: "committed",
    });
    await expect(runtime.writeAuthorized({ context, plan, mutation })).resolves.toMatchObject({
      status: "unchanged",
    });

    const database = openOpenClawAgentDatabase({ agentId: "main" }).db;
    expect(
      database
        .prepare("SELECT COUNT(*) AS count FROM memory_write_intents WHERE mutation_id = ?")
        .get(mutation.mutationId),
    ).toEqual({ count: 1 });
    expect(
      database
        .prepare(
          "SELECT COUNT(*) AS count FROM memory_resource_revisions WHERE lifecycle_state = ?",
        )
        .get("active"),
    ).toEqual({ count: 1 });
  });

  it.each(["storeId", "ownerId", "audience", "placementHandle", "destinationHandle"] as const)(
    "rejects a caller-selected %s destination field",
    async (field) => {
      createStore({ defaultCapabilities: ["retrieve", "read", "append"] });
      const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
      const context = createContext({ operation: "append" });
      const plan = await runtime.authorize(context);
      const mutation = {
        version: 1,
        kind: "remember",
        mutationId: `mutation-forged-${field}`,
        idempotencyKey: `key-forged-${field}`,
        content: "forged destination cobalt artifact",
        contentType: "markdown",
        [field]: "forged-destination",
      } as unknown as AuthorizedMemoryMutation;

      await expect(runtime.writeAuthorized({ context, plan, mutation })).rejects.toThrow(
        "mutation placement is unavailable",
      );
    },
  );

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
