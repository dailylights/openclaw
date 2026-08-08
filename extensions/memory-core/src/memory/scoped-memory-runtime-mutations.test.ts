import type { AuthorizedMemoryMutation } from "openclaw/plugin-sdk/memory-authorization";
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

  it.each([
    {
      label: "user",
      store: {
        scopeKind: "user" as const,
        audienceKind: "user" as const,
        audienceId: "principal-owner",
        authorityKind: "user" as const,
        authorityOwnerId: "principal-owner",
      },
      context: {},
    },
    {
      label: "conversation",
      store: {
        scopeKind: "conversation" as const,
        audienceKind: "conversation" as const,
        audienceId: "conversation-1",
        authorityKind: "conversation" as const,
        authorityOwnerId: "conversation-1",
      },
      context: {
        subject: {
          version: 1 as const,
          kind: "conversation" as const,
          conversationPrincipalId: "conversation-1",
          channel: "telegram",
          accountId: "default",
        },
        actor: {
          kind: "unattributed" as const,
          transportAuditRef: "transport-audit-1",
          evidenceRevision: "conversation-evidence-1",
        },
        verifiedPrincipals: [],
        conversation: {
          conversationPrincipalId: "conversation-1",
          channel: "telegram",
          accountId: "default",
          evidenceRevision: "conversation-evidence-1",
        },
        delivery: {
          sinkKind: "channel" as const,
          audiences: [{ kind: "conversation" as const, id: "conversation-1" }],
          egressCapabilityIds: ["reply.final"],
          egressRegistryRevision: "conversation-egress-1",
          deliveryRevision: "conversation-delivery-1",
        },
      },
    },
    ...(["agent", "service"] as const).map((kind) => ({
      label: kind,
      store: {
        scopeKind: "agent" as const,
        audienceKind: "agent" as const,
        audienceId: "main",
        authorityKind: "agent" as const,
        authorityOwnerId: "main",
      },
      context: {
        subject: { version: 1 as const, kind, principalId: "main" },
        actor: {
          kind: "principal" as const,
          actorKind: kind,
          principalId: "main",
          assurance: "service" as const,
          evidenceRevision: `${kind}-evidence-1`,
        },
        verifiedPrincipals: [
          {
            principalId: "main",
            assurance: "service" as const,
            evidenceRevision: `${kind}-evidence-1`,
          },
        ],
        delivery: {
          sinkKind: "internal" as const,
          audiences: [{ kind: "agent" as const, id: "main" }],
          egressCapabilityIds: ["reply.final"],
          egressRegistryRevision: `${kind}-egress-1`,
          deliveryRevision: `${kind}-delivery-1`,
        },
      },
    })),
  ])(
    "writes a $label maintenance note only to its subject-selected store",
    async ({ store, context }) => {
      const selectedStore = createBuiltinScopedMemoryStore({
        agentId: "main",
        ...store,
        defaultCapabilities: ["append"],
        actor: { kind: "human", id: "principal-owner" },
        reason: "maintenance target matrix",
        nowMs: 1_000,
      });
      const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
      const writeContext = createContext({ ...context, operation: "append" });
      const plan = await runtime.authorize(writeContext);
      const result = await runtime.writeAuthorized({
        context: writeContext,
        plan,
        mutation: {
          version: 1,
          kind: "remember",
          mutationId: `maintenance-${store.audienceKind}`,
          idempotencyKey: `maintenance-${store.audienceKind}`,
          content: "authorized maintenance note",
          contentType: "markdown",
        },
      });
      const revisionId = result.resourceHandle?.resourceRevision;
      if (!revisionId) {
        throw new Error("expected remembered resource revision");
      }
      const database = openOpenClawAgentDatabase({ agentId: "main" }).db;
      expect(
        database
          .prepare(
            "SELECT resource.store_id AS store_id FROM memory_resources AS resource INNER JOIN memory_resource_revisions AS revision ON revision.resource_id = resource.resource_id WHERE revision.revision_id = ?",
          )
          .get(revisionId),
      ).toEqual({ store_id: selectedStore.storeId });
    },
  );

  it("rejects a maintenance write for an ambiguous subject", async () => {
    createBuiltinScopedMemoryStore({
      agentId: "main",
      scopeKind: "agent",
      audienceKind: "agent",
      audienceId: "main",
      authorityKind: "agent",
      authorityOwnerId: "main",
      defaultCapabilities: ["append"],
      actor: { kind: "human", id: "principal-owner" },
      reason: "ambiguous maintenance denial",
      nowMs: 1_000,
    });
    const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const context = createContext({
      operation: "append",
      subject: { version: 1, kind: "ambiguous", reason: "unbound" },
      actor: {
        kind: "unattributed",
        transportAuditRef: "ambiguous-audit-1",
        evidenceRevision: "ambiguous-evidence-1",
      },
      verifiedPrincipals: [],
      delivery: {
        sinkKind: "internal",
        audiences: [{ kind: "agent", id: "main" }],
        egressCapabilityIds: ["reply.final"],
        egressRegistryRevision: "ambiguous-egress-1",
        deliveryRevision: "ambiguous-delivery-1",
      },
    });
    const plan = await runtime.authorize(context);

    await expect(
      runtime.writeAuthorized({
        context,
        plan,
        mutation: {
          version: 1,
          kind: "remember",
          mutationId: "ambiguous-maintenance",
          idempotencyKey: "ambiguous-maintenance",
          content: "must not persist",
          contentType: "markdown",
        },
      }),
    ).rejects.toThrow("authorized memory mutation is unavailable");
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

  it("does not let a cross-operation handle select an agent-shared mutation target", async () => {
    createStore({ defaultCapabilities: ["retrieve", "read", "append", "delete"] });
    const sharedStore = createBuiltinScopedMemoryStore({
      agentId: "main",
      scopeKind: "agent-shared",
      audienceKind: "agent-shared",
      audienceId: "main",
      authorityKind: "agent",
      authorityOwnerId: "main",
      // The explicit mutation capabilities model a permissive target policy;
      // ordinary runtime capture must still not select this shared audience.
      defaultCapabilities: ["retrieve", "read", "append", "delete"],
      actor: { kind: "human", id: "principal-owner" },
      reason: "cross-operation target regression",
      nowMs: 1_000,
    });
    const sharedResource = createBuiltinScopedMemoryResource({
      agentId: "main",
      store: sharedStore,
      logicalLocator: "reviewed-shared-copy.md",
      content: "reviewed shared cobalt copy",
      actor: { kind: "human", id: "principal-owner" },
      nowMs: 2_000,
    });
    const runtime = createBuiltinScopedMemoryRuntime({ now: () => NOW_MS });
    const readContext = createContext({ operation: "read" });
    const readPlan = await runtime.authorize(readContext);
    const search = await runtime.searchAuthorized({
      context: readContext,
      plan: readPlan,
      query: "reviewed shared cobalt",
      limit: 1,
    });
    const target = search.value[0]?.resourceHandle;
    if (!target) {
      throw new Error("expected a shared resource handle");
    }

    const appendContext = { ...readContext, operation: "append" as const };
    const appendPlan = await runtime.authorize(appendContext);
    await expect(
      runtime.writeAuthorized({
        context: appendContext,
        plan: appendPlan,
        mutation: {
          version: 1,
          kind: "append",
          mutationId: "shared-target-append",
          idempotencyKey: "shared-target-append-key",
          content: "unreviewed mutation",
          contentType: "markdown",
          target,
        },
      }),
    ).rejects.toThrow("mutation placement is unavailable");

    const deleteContext = { ...readContext, operation: "delete" as const };
    const deletePlan = await runtime.authorize(deleteContext);
    await expect(
      runtime.writeAuthorized({
        context: deleteContext,
        plan: deletePlan,
        mutation: {
          version: 1,
          kind: "tombstone",
          mutationId: "shared-target-tombstone",
          idempotencyKey: "shared-target-tombstone-key",
          target,
        },
      }),
    ).rejects.toThrow("mutation placement is unavailable");

    const database = openOpenClawAgentDatabase({ agentId: "main" }).db;
    expect(
      database
        .prepare("SELECT lifecycle_state FROM memory_resource_revisions WHERE revision_id = ?")
        .get(sharedResource.revisionId),
    ).toEqual({ lifecycle_state: "active" });
  });
});
