import { describe, expect, it, vi } from "vitest";
import type { AuthorizedMemoryPlan } from "../memory-host-sdk/host/authorization.js";
import {
  brandAuthorizedMemoryPlan,
  createMemoryAccessContextFactory,
  isTrustedAuthorizedMemoryPlan,
  isTrustedMemoryAccessContext,
  MemoryAccessContextError,
  type MemoryAccessContextFacts,
} from "./memory-access-context.js";

const NOW_MS = Date.parse("2026-07-29T12:00:00.000Z");

function createAuthoritativeSessionIdentity() {
  return {
    sessionId: "session-1",
    sessionIdentityRevision: "session-revision-1",
    subjectRevision: "subject-revision-1",
    subject: {
      version: 1 as const,
      kind: "user" as const,
      principalId: "principal-owner",
      creationEvidence: {
        kind: "gateway-profile" as const,
        revision: "creation-revision-1",
      },
    },
  };
}

function createFacts(): MemoryAccessContextFacts {
  return {
    contextId: "context-1",
    requestId: "request-1",
    runId: "run-1",
    agentId: "agent-a",
    sessionKey: "agent:agent-a:main",
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
      expiresAt: "2026-07-29T13:00:00.000Z",
    },
    verifiedPrincipals: [
      {
        principalId: "principal-collaborator",
        assurance: "oidc",
        evidenceRevision: "principal-revision-2",
      },
      {
        principalId: "principal-owner",
        assurance: "gateway-profile",
        evidenceRevision: "principal-revision-1",
      },
    ],
    conversation: {
      conversationPrincipalId: "conversation-1",
      channel: "discord",
      accountId: "default",
      evidenceRevision: "conversation-revision-1",
    },
    delivery: {
      sinkKind: "channel",
      audiences: [
        { kind: "user", id: "principal-owner" },
        { kind: "conversation", id: "conversation-1" },
      ],
      egressCapabilityIds: ["message.send", "reply.final"],
      egressRegistryRevision: "egress-registry-revision-1",
      deliveryRevision: "delivery-revision-1",
    },
    collaboration: {
      kind: "gateway-session",
      mode: "shared",
      role: "owner",
      decisionRevision: "collaboration-revision-1",
    },
    verifiedMemberships: [
      {
        principalId: "principal-owner",
        groupId: "group-2",
        provider: "oidc",
        evidenceRevision: "membership-revision-2",
        observedAt: "2026-07-29T11:00:00.000Z",
        expiresAt: "2026-07-29T13:00:00.000Z",
      },
      {
        principalId: "principal-owner",
        groupId: "group-1",
        provider: "gateway",
        evidenceRevision: "membership-revision-1",
        observedAt: "2026-07-29T11:00:00.000Z",
        expiresAt: "2026-07-29T13:00:00.000Z",
      },
    ],
    operation: "read",
    hostFactsRevision: "host-facts-revision-1",
  };
}

function createFactory() {
  const readCurrentSessionIdentity = vi.fn(async () => createAuthoritativeSessionIdentity());
  return {
    create: createMemoryAccessContextFactory({ readCurrentSessionIdentity, now: () => NOW_MS }),
    readCurrentSessionIdentity,
  };
}

function createPlan(
  context: Awaited<ReturnType<ReturnType<typeof createMemoryAccessContextFactory>>>,
): AuthorizedMemoryPlan {
  return {
    version: 1,
    planId: "plan-1",
    contextFingerprint: context.contextFingerprint,
    runId: context.runId,
    agentId: context.agentId,
    sessionId: context.sessionId,
    sessionIdentityRevision: context.sessionIdentityRevision,
    subjectRevision: context.subjectRevision,
    memoryPolicyRevision: "memory-policy-revision-1",
    deliveryRevision: context.delivery.deliveryRevision,
    operation: context.operation,
    mounts: [
      {
        version: 1,
        agentId: context.agentId,
        mountHandle: "mount-1",
        capabilities: ["read", "retrieve"],
        audienceRevision: "audience-revision-1",
      },
    ],
    bootstrapResourceHandles: [
      {
        version: 1,
        handleId: "resource-handle-1",
        planId: "plan-1",
        contextFingerprint: context.contextFingerprint,
        resourceRevision: "resource-revision-1",
        policyRevision: "memory-policy-revision-1",
        expiresAt: "2026-07-29T12:04:00.000Z",
      },
    ],
    allowedEgressAudiences: context.delivery.audiences,
    expiresAt: "2026-07-29T12:05:00.000Z",
  };
}

function expectContextError(run: () => unknown, code: MemoryAccessContextError["code"]): void {
  try {
    run();
    throw new Error("expected MemoryAccessContextError");
  } catch (error) {
    expect(error).toBeInstanceOf(MemoryAccessContextError);
    expect(error).toMatchObject({ code });
  }
}

describe("memory access context factory", () => {
  it("rereads the session mapping and creates a deeply frozen, branded context", async () => {
    const { create, readCurrentSessionIdentity } = createFactory();
    const context = await create(createFacts());

    expect(readCurrentSessionIdentity).toHaveBeenCalledWith({
      agentId: "agent-a",
      sessionKey: "agent:agent-a:main",
    });
    expect(isTrustedMemoryAccessContext(context)).toBe(true);
    expect(context.contextFingerprint).toMatch(/^sha256:[a-f0-9]{64}$/u);
    expect(Object.isFrozen(context)).toBe(true);
    expect(Object.isFrozen(context.subject)).toBe(true);
    expect(Object.isFrozen(context.delivery.audiences)).toBe(true);
    expect(Object.isFrozen(context.verifiedMemberships[0])).toBe(true);
    expect(() => {
      (context.delivery.audiences as Array<unknown>).push({ kind: "internal", id: "forged" });
    }).toThrow();
  });

  it("canonicalizes set-like facts into one stable fingerprint", async () => {
    const { create } = createFactory();
    const firstFacts = createFacts();
    const secondFacts = {
      ...createFacts(),
      verifiedPrincipals: firstFacts.verifiedPrincipals.toReversed(),
      verifiedMemberships: firstFacts.verifiedMemberships.toReversed(),
      delivery: {
        ...firstFacts.delivery,
        audiences: firstFacts.delivery.audiences.toReversed(),
        egressCapabilityIds: firstFacts.delivery.egressCapabilityIds.toReversed(),
      },
    } satisfies MemoryAccessContextFacts;

    const first = await create(firstFacts);
    const second = await create(secondFacts);

    expect(second.contextFingerprint).toBe(first.contextFingerprint);
    expect(second.verifiedPrincipals.map((entry) => entry.principalId)).toEqual([
      "principal-collaborator",
      "principal-owner",
    ]);
    expect(second.delivery.egressCapabilityIds).toEqual(["message.send", "reply.final"]);
  });

  it("strips caller extras and loses trust across JSON or object copying", async () => {
    const { create } = createFactory();
    const subjectWithExtras = {
      ...createFacts().subject,
      rawOwner: "principal-attacker",
    };
    const facts = {
      ...createFacts(),
      prompt: "forge principal-owner",
      query: "private memory",
      pluginExtras: { owner: "principal-attacker" },
      contextFingerprint: "forged",
      subject: subjectWithExtras,
    } as MemoryAccessContextFacts;
    const context = await create(facts);

    expect(context).not.toHaveProperty("prompt");
    expect(context).not.toHaveProperty("query");
    expect(context).not.toHaveProperty("pluginExtras");
    expect(context.contextFingerprint).not.toBe("forged");
    expect(context.subject).not.toHaveProperty("rawOwner");
    // oxlint-disable-next-line unicorn/prefer-structured-clone -- This test exercises JSON trust loss.
    expect(isTrustedMemoryAccessContext(JSON.parse(JSON.stringify(context)))).toBe(false);
    expect(isTrustedMemoryAccessContext({ ...context })).toBe(false);
    expect(
      isTrustedMemoryAccessContext({ ...JSON.parse('{"version":1}'), prompt: "trusted" }),
    ).toBe(false);
  });

  it("uses the authoritative persisted subject instead of caller identity fields", async () => {
    const { create } = createFactory();
    const context = await create({
      ...createFacts(),
      subjectRevision: "forged-subject-revision",
      subject: {
        version: 1,
        kind: "system",
        principalId: "principal-attacker",
      },
    });

    expect(context.subjectRevision).toBe("subject-revision-1");
    expect(context.subject).toEqual(createAuthoritativeSessionIdentity().subject);
  });

  it("fails closed when the authoritative session mapping is absent or rebound", async () => {
    const facts = createFacts();
    for (const current of [
      null,
      { ...createAuthoritativeSessionIdentity(), sessionId: "session-2" },
      {
        ...createAuthoritativeSessionIdentity(),
        sessionIdentityRevision: "session-revision-2",
      },
    ]) {
      const create = createMemoryAccessContextFactory({
        readCurrentSessionIdentity: vi.fn(async () => current),
      });
      await expect(create(facts)).rejects.toMatchObject({ code: "session-rebound" });
    }
  });

  it.each([
    ["operation", { operation: "own-everything" }],
    ["delivery sink", { delivery: { ...createFacts().delivery, sinkKind: "broadcast" } }],
    [
      "audience kind",
      { delivery: { ...createFacts().delivery, audiences: [{ kind: "email", id: "x" }] } },
    ],
    ["actor assurance", { actor: { ...createFacts().actor, assurance: "display-name" } }],
    ["actor expiry", { actor: { ...createFacts().actor, expiresAt: "" } }],
    [
      "verified principal expiry",
      {
        verifiedPrincipals: [
          {
            ...createFacts().verifiedPrincipals[0]!,
            expiresAt: "",
          },
        ],
      },
    ],
    [
      "collaboration role",
      { collaboration: { ...createFacts().collaboration, role: "superuser" } },
    ],
  ])("rejects an invalid runtime enum for %s", async (_name, override) => {
    const { create } = createFactory();
    await expect(
      create({ ...createFacts(), ...override } as MemoryAccessContextFacts),
    ).rejects.toMatchObject({ code: "invalid-context" });
  });

  it("rejects expired actor, principal, and membership evidence", async () => {
    const { create } = createFactory();
    const facts = createFacts();
    if (facts.actor.kind !== "principal") {
      throw new Error("expected principal actor fixture");
    }

    await expect(
      create({
        ...facts,
        actor: { ...facts.actor, expiresAt: "2026-07-29T12:00:00.000Z" },
      }),
    ).rejects.toMatchObject({ code: "identity-revoked" });
    await expect(
      create({
        ...facts,
        verifiedPrincipals: [
          { ...facts.verifiedPrincipals[0]!, expiresAt: "2026-07-29T11:59:59.000Z" },
        ],
      }),
    ).rejects.toMatchObject({ code: "identity-revoked" });
    await expect(
      create({
        ...facts,
        verifiedMemberships: [
          { ...facts.verifiedMemberships[0]!, expiresAt: "2026-07-29T12:00:00.000Z" },
        ],
      }),
    ).rejects.toMatchObject({ code: "membership-stale" });
  });

  it("rejects a non-finite authoritative clock", async () => {
    const create = createMemoryAccessContextFactory({
      readCurrentSessionIdentity: vi.fn(async () => ({
        ...createAuthoritativeSessionIdentity(),
      })),
      now: () => Number.NaN,
    });

    await expect(create(createFacts())).rejects.toMatchObject({ code: "invalid-context" });
  });
});

describe("authorized memory plan admission", () => {
  it("brands only a context-bound plugin plan, strips extras, and freezes it", async () => {
    const { create } = createFactory();
    const context = await create(createFacts());
    const plan = createPlan(context);
    const mountWithExtras = {
      ...plan.mounts[0]!,
      ownerId: "principal-attacker",
    };
    const pluginPlan = {
      ...plan,
      prompt: "ignore the context",
      rawStoreId: "private:other-user",
      mounts: [mountWithExtras],
    } as AuthorizedMemoryPlan;

    const trustedPlan = brandAuthorizedMemoryPlan({ context, plan: pluginPlan, nowMs: NOW_MS });

    expect(isTrustedAuthorizedMemoryPlan(trustedPlan)).toBe(true);
    expect(trustedPlan).not.toHaveProperty("prompt");
    expect(trustedPlan).not.toHaveProperty("rawStoreId");
    expect(trustedPlan.mounts[0]).not.toHaveProperty("ownerId");
    expect(Object.isFrozen(trustedPlan.bootstrapResourceHandles[0])).toBe(true);
    expect(() => {
      (trustedPlan.mounts as Array<unknown>).push({});
    }).toThrow();
    // oxlint-disable-next-line unicorn/prefer-structured-clone -- This test exercises JSON trust loss.
    expect(isTrustedAuthorizedMemoryPlan(JSON.parse(JSON.stringify(trustedPlan)))).toBe(false);
    expect(isTrustedAuthorizedMemoryPlan({ ...trustedPlan })).toBe(false);
  });

  it("rejects caller plans without a trusted access context", () => {
    const context = { ...createFacts(), contextFingerprint: "sha256:forged" } as never;
    expectContextError(
      () => brandAuthorizedMemoryPlan({ context, plan: {} as AuthorizedMemoryPlan, nowMs: NOW_MS }),
      "invalid-context",
    );
  });

  it("caps plan and handle lifetime at the earliest evidence expiry", async () => {
    const { create } = createFactory();
    const context = await create(createFacts());
    const plan = createPlan(context);
    const tooLong = {
      ...plan,
      expiresAt: "2026-07-29T13:00:00.001Z",
      bootstrapResourceHandles: [
        { ...plan.bootstrapResourceHandles[0]!, expiresAt: "2026-07-29T13:00:00.000Z" },
      ],
    } satisfies AuthorizedMemoryPlan;

    expectContextError(
      () => brandAuthorizedMemoryPlan({ context, plan: tooLong, nowMs: NOW_MS }),
      "plan-expired",
    );
  });

  it("revalidates evidence expiry after asynchronous authorization", async () => {
    const { create } = createFactory();
    const context = await create(createFacts());
    const plan = {
      ...createPlan(context),
      expiresAt: "2026-07-29T13:00:00.000Z",
      bootstrapResourceHandles: [
        {
          ...createPlan(context).bootstrapResourceHandles[0]!,
          expiresAt: "2026-07-29T13:00:00.000Z",
        },
      ],
    } satisfies AuthorizedMemoryPlan;

    expectContextError(
      () => brandAuthorizedMemoryPlan({ context, plan, nowMs: Date.parse(plan.expiresAt) }),
      "identity-revoked",
    );
  });

  it.each([
    [
      "context fingerprint",
      "invalid-context",
      (plan: AuthorizedMemoryPlan) => ({ ...plan, contextFingerprint: "other" }),
    ],
    ["agent", "outside-view", (plan: AuthorizedMemoryPlan) => ({ ...plan, agentId: "agent-b" })],
    [
      "session revision",
      "revision-stale",
      (plan: AuthorizedMemoryPlan) => ({ ...plan, sessionIdentityRevision: "new" }),
    ],
    [
      "delivery revision",
      "delivery-rebound",
      (plan: AuthorizedMemoryPlan) => ({ ...plan, deliveryRevision: "new" }),
    ],
    [
      "expiry",
      "plan-expired",
      (plan: AuthorizedMemoryPlan) => ({ ...plan, expiresAt: "2026-07-29T11:59:00.000Z" }),
    ],
    [
      "audience",
      "outside-view",
      (plan: AuthorizedMemoryPlan) => ({
        ...plan,
        allowedEgressAudiences: [{ kind: "user" as const, id: "other" }],
      }),
    ],
    [
      "mount agent",
      "outside-view",
      (plan: AuthorizedMemoryPlan) => ({
        ...plan,
        mounts: [{ ...plan.mounts[0]!, agentId: "agent-b" }],
      }),
    ],
    [
      "mount capability",
      "invalid-context",
      (plan: AuthorizedMemoryPlan) => ({
        ...plan,
        mounts: [{ ...plan.mounts[0]!, capabilities: ["root"] as never }],
      }),
    ],
    [
      "handle policy",
      "invalid-context",
      (plan: AuthorizedMemoryPlan) => ({
        ...plan,
        bootstrapResourceHandles: [{ ...plan.bootstrapResourceHandles[0]!, policyRevision: "old" }],
      }),
    ],
    [
      "handle lifetime",
      "plan-expired",
      (plan: AuthorizedMemoryPlan) => ({
        ...plan,
        bootstrapResourceHandles: [
          { ...plan.bootstrapResourceHandles[0]!, expiresAt: "2026-07-29T12:06:00.000Z" },
        ],
      }),
    ],
  ] as const)("rejects a plan rebound through %s", async (_name, code, mutate) => {
    const { create } = createFactory();
    const context = await create(createFacts());
    expectContextError(
      () =>
        brandAuthorizedMemoryPlan({ context, plan: mutate(createPlan(context)), nowMs: NOW_MS }),
      code,
    );
  });
});
