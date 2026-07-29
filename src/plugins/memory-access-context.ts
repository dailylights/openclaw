import { stableStringify } from "../agents/stable-stringify.js";
import { sha256Hex } from "../infra/crypto-digest.js";
import type {
  AudienceRef,
  AuthorizedMemoryPlan,
  AuthorizedResourceHandle,
  MemoryAccessContext,
  MemoryActorEvidence,
  MemoryOperation,
  MemoryVerifiedMembership,
  SessionMemorySubject,
  VerifiedPrincipalRef,
} from "../memory-host-sdk/host/authorization.js";
import { MEMORY_OPERATIONS } from "../memory-host-sdk/host/authorization.js";

const memoryAccessContextBrand: unique symbol = Symbol("openclaw.memory-access-context");
const authorizedMemoryPlanBrand: unique symbol = Symbol("openclaw.authorized-memory-plan");
const trustedMemoryAccessContexts = new WeakSet<object>();
const trustedAuthorizedMemoryPlans = new WeakSet<object>();

type MemoryAccessContextFailureCode =
  | "invalid-context"
  | "session-rebound"
  | "delivery-rebound"
  | "plan-expired"
  | "identity-revoked"
  | "membership-stale"
  | "revision-stale"
  | "outside-view";

export class MemoryAccessContextError extends Error {
  readonly code: MemoryAccessContextFailureCode;

  constructor(code: MemoryAccessContextFailureCode) {
    super(code);
    this.name = "MemoryAccessContextError";
    this.code = code;
  }
}

type MemorySessionIdentitySnapshot = Readonly<{
  sessionId: string;
  sessionIdentityRevision: string;
  subjectRevision: string;
  subject: SessionMemorySubject;
}>;

export type MemoryAccessContextFacts = Readonly<{
  contextId: string;
  requestId: string;
  runId: string;
  agentId: string;
  sessionKey: string;
  sessionId: string;
  sessionIdentityRevision: string;
  subjectRevision: string;
  subject: SessionMemorySubject;
  actor: MemoryActorEvidence;
  verifiedPrincipals: readonly VerifiedPrincipalRef[];
  conversation?: MemoryAccessContext["conversation"];
  delivery: MemoryAccessContext["delivery"];
  collaboration: MemoryAccessContext["collaboration"];
  verifiedMemberships: readonly MemoryVerifiedMembership[];
  delegation?: MemoryAccessContext["delegation"];
  operation: MemoryOperation;
  hostFactsRevision: string;
}>;

type MemoryAccessContextFactoryDependencies = Readonly<{
  readCurrentSessionIdentity(params: {
    agentId: string;
    sessionKey: string;
  }): Promise<MemorySessionIdentitySnapshot | null>;
  now?: () => number;
}>;

function assertNonEmpty(value: string): void {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new MemoryAccessContextError("invalid-context");
  }
}

function assertOneOf<T extends string>(value: string, allowed: readonly T[]): asserts value is T {
  if (!(allowed as readonly string[]).includes(value)) {
    throw new MemoryAccessContextError("invalid-context");
  }
}

function assertTimestamp(value: string): void {
  assertNonEmpty(value);
  if (!Number.isFinite(Date.parse(value))) {
    throw new MemoryAccessContextError("invalid-context");
  }
}

function assertCurrentTime(nowMs: number): void {
  if (!Number.isFinite(nowMs)) {
    throw new MemoryAccessContextError("invalid-context");
  }
}

function assertUnexpiredTimestamp(
  value: string,
  nowMs: number,
  code: "identity-revoked" | "membership-stale",
): void {
  assertTimestamp(value);
  if (Date.parse(value) <= nowMs) {
    throw new MemoryAccessContextError(code);
  }
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function audienceKey(value: AudienceRef): string {
  return `${value.kind}\0${value.id}`;
}

function cloneAudience(value: AudienceRef): AudienceRef {
  assertOneOf(value.kind, ["user", "conversation", "role", "agent-shared", "agent", "internal"]);
  assertNonEmpty(value.id);
  return { kind: value.kind, id: value.id };
}

function cloneAudiences(values: readonly AudienceRef[]): AudienceRef[] {
  return values
    .map(cloneAudience)
    .toSorted((left, right) => compareText(audienceKey(left), audienceKey(right)));
}

function cloneSubject(subject: SessionMemorySubject): SessionMemorySubject {
  if (subject.version !== 1) {
    throw new MemoryAccessContextError("invalid-context");
  }
  switch (subject.kind) {
    case "user":
      assertNonEmpty(subject.principalId);
      assertOneOf(subject.creationEvidence.kind, [
        "gateway-profile",
        "channel-binding",
        "adapter-attested",
        "explicit-service",
      ]);
      assertNonEmpty(subject.creationEvidence.revision);
      return {
        version: 1,
        kind: "user",
        principalId: subject.principalId,
        creationEvidence: {
          kind: subject.creationEvidence.kind,
          revision: subject.creationEvidence.revision,
        },
      };
    case "conversation":
      assertNonEmpty(subject.conversationPrincipalId);
      assertNonEmpty(subject.channel);
      assertNonEmpty(subject.accountId);
      return {
        version: 1,
        kind: "conversation",
        conversationPrincipalId: subject.conversationPrincipalId,
        channel: subject.channel,
        accountId: subject.accountId,
      };
    case "service":
    case "agent":
    case "system":
      assertNonEmpty(subject.principalId);
      return { version: 1, kind: subject.kind, principalId: subject.principalId };
    case "ambiguous":
      assertOneOf(subject.reason, ["shared-main", "unbound", "conflicting-bindings"]);
      return { version: 1, kind: "ambiguous", reason: subject.reason };
    default:
      throw new MemoryAccessContextError("invalid-context");
  }
}

function cloneActor(actor: MemoryActorEvidence, nowMs: number): MemoryActorEvidence {
  assertNonEmpty(actor.evidenceRevision);
  if (actor.kind === "unattributed") {
    assertNonEmpty(actor.transportAuditRef);
    return {
      kind: "unattributed",
      transportAuditRef: actor.transportAuditRef,
      evidenceRevision: actor.evidenceRevision,
    };
  }
  if (actor.kind !== "principal") {
    throw new MemoryAccessContextError("invalid-context");
  }
  assertNonEmpty(actor.principalId);
  assertOneOf(actor.actorKind, ["human", "agent", "service", "system"]);
  assertOneOf(actor.assurance, ["gateway-profile", "adapter-attested", "oidc", "service"]);
  if (actor.expiresAt !== undefined) {
    assertUnexpiredTimestamp(actor.expiresAt, nowMs, "identity-revoked");
  }
  return {
    kind: "principal",
    actorKind: actor.actorKind,
    principalId: actor.principalId,
    assurance: actor.assurance,
    evidenceRevision: actor.evidenceRevision,
    ...(actor.expiresAt !== undefined ? { expiresAt: actor.expiresAt } : {}),
  };
}

function cloneVerifiedPrincipals(
  values: readonly VerifiedPrincipalRef[],
  nowMs: number,
): VerifiedPrincipalRef[] {
  return values
    .map((value) => {
      assertNonEmpty(value.principalId);
      assertNonEmpty(value.evidenceRevision);
      assertOneOf(value.assurance, ["gateway-profile", "adapter-attested", "oidc", "service"]);
      if (value.expiresAt !== undefined) {
        assertUnexpiredTimestamp(value.expiresAt, nowMs, "identity-revoked");
      }
      return {
        principalId: value.principalId,
        assurance: value.assurance,
        evidenceRevision: value.evidenceRevision,
        ...(value.expiresAt !== undefined ? { expiresAt: value.expiresAt } : {}),
      } satisfies VerifiedPrincipalRef;
    })
    .toSorted((left, right) =>
      compareText(
        [left.principalId, left.assurance, left.evidenceRevision, left.expiresAt ?? ""].join("\0"),
        [right.principalId, right.assurance, right.evidenceRevision, right.expiresAt ?? ""].join(
          "\0",
        ),
      ),
    );
}

function cloneMemberships(
  values: readonly MemoryVerifiedMembership[],
  nowMs: number,
): MemoryVerifiedMembership[] {
  return values
    .map((value) => {
      for (const field of [
        value.principalId,
        value.groupId,
        value.provider,
        value.evidenceRevision,
        value.observedAt,
        value.expiresAt,
      ]) {
        assertNonEmpty(field);
      }
      assertTimestamp(value.observedAt);
      assertUnexpiredTimestamp(value.expiresAt, nowMs, "membership-stale");
      return {
        principalId: value.principalId,
        groupId: value.groupId,
        provider: value.provider,
        evidenceRevision: value.evidenceRevision,
        observedAt: value.observedAt,
        expiresAt: value.expiresAt,
      };
    })
    .toSorted((left, right) =>
      compareText(
        [left.principalId, left.groupId, left.provider, left.evidenceRevision].join("\0"),
        [right.principalId, right.groupId, right.provider, right.evidenceRevision].join("\0"),
      ),
    );
}

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (!value || typeof value !== "object" || seen.has(value)) {
    return value;
  }
  seen.add(value);
  for (const nested of Object.values(value)) {
    deepFreeze(nested, seen);
  }
  return Object.freeze(value);
}

function brandAndFreeze<T extends object>(
  value: T,
  brand: symbol,
  trustedValues: WeakSet<object>,
): T {
  Object.defineProperty(value, brand, {
    value: true,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  trustedValues.add(value);
  return deepFreeze(value);
}

function buildSerializableContext(
  facts: MemoryAccessContextFacts,
  identity: MemorySessionIdentitySnapshot,
  nowMs: number,
) {
  for (const value of [
    facts.contextId,
    facts.requestId,
    facts.runId,
    facts.agentId,
    facts.sessionKey,
    facts.sessionId,
    identity.sessionIdentityRevision,
    identity.subjectRevision,
    facts.delivery.egressRegistryRevision,
    facts.delivery.deliveryRevision,
    facts.hostFactsRevision,
  ]) {
    assertNonEmpty(value);
  }
  assertOneOf(facts.operation, MEMORY_OPERATIONS);
  assertOneOf(facts.delivery.sinkKind, ["private", "channel", "session", "internal"]);
  for (const capabilityId of facts.delivery.egressCapabilityIds) {
    assertNonEmpty(capabilityId);
  }
  if (
    facts.collaboration.kind !== "gateway-session" &&
    facts.collaboration.kind !== "not-applicable"
  ) {
    throw new MemoryAccessContextError("invalid-context");
  }
  const collaboration =
    facts.collaboration.kind === "gateway-session"
      ? {
          kind: "gateway-session" as const,
          mode: facts.collaboration.mode,
          role: facts.collaboration.role,
          decisionRevision: facts.collaboration.decisionRevision,
        }
      : ({ kind: "not-applicable" } as const);
  if (collaboration.kind === "gateway-session") {
    assertNonEmpty(collaboration.decisionRevision);
    assertOneOf(collaboration.mode, ["shared", "read-only", "suggest", "draft"]);
    assertOneOf(collaboration.role, ["admin", "owner", "member", "viewer"]);
  }
  const conversation = facts.conversation
    ? {
        conversationPrincipalId: facts.conversation.conversationPrincipalId,
        channel: facts.conversation.channel,
        accountId: facts.conversation.accountId,
        evidenceRevision: facts.conversation.evidenceRevision,
      }
    : undefined;
  if (conversation) {
    for (const value of Object.values(conversation)) {
      assertNonEmpty(value);
    }
  }
  const delegation = facts.delegation
    ? {
        rootPrincipalId: facts.delegation.rootPrincipalId,
        rootContextId: facts.delegation.rootContextId,
        parentContextId: facts.delegation.parentContextId,
        parentMemoryPlanId: facts.delegation.parentMemoryPlanId,
        capabilitySnapshotId: facts.delegation.capabilitySnapshotId,
        allowedOperations: [...new Set(facts.delegation.allowedOperations)].toSorted(),
        maximumAudiences: cloneAudiences(facts.delegation.maximumAudiences),
        storeCapToken: facts.delegation.storeCapToken,
        depth: facts.delegation.depth,
      }
    : undefined;
  if (delegation) {
    for (const value of [
      delegation.rootPrincipalId,
      delegation.rootContextId,
      delegation.parentContextId,
      delegation.parentMemoryPlanId,
      delegation.capabilitySnapshotId,
      delegation.storeCapToken,
    ]) {
      assertNonEmpty(value);
    }
    if (!Number.isInteger(delegation.depth) || delegation.depth < 1) {
      throw new MemoryAccessContextError("invalid-context");
    }
    for (const operation of delegation.allowedOperations) {
      assertOneOf(operation, MEMORY_OPERATIONS);
    }
  }
  return {
    version: 1 as const,
    contextId: facts.contextId,
    requestId: facts.requestId,
    runId: facts.runId,
    agentId: facts.agentId,
    sessionKey: facts.sessionKey,
    sessionId: identity.sessionId,
    sessionIdentityRevision: identity.sessionIdentityRevision,
    subjectRevision: identity.subjectRevision,
    subject: cloneSubject(identity.subject),
    actor: cloneActor(facts.actor, nowMs),
    verifiedPrincipals: cloneVerifiedPrincipals(facts.verifiedPrincipals, nowMs),
    ...(conversation ? { conversation } : {}),
    delivery: {
      sinkKind: facts.delivery.sinkKind,
      audiences: cloneAudiences(facts.delivery.audiences),
      egressCapabilityIds: [...new Set(facts.delivery.egressCapabilityIds)].toSorted(compareText),
      egressRegistryRevision: facts.delivery.egressRegistryRevision,
      deliveryRevision: facts.delivery.deliveryRevision,
    },
    collaboration,
    verifiedMemberships: cloneMemberships(facts.verifiedMemberships, nowMs),
    ...(delegation ? { delegation } : {}),
    operation: facts.operation,
    hostFactsRevision: facts.hostFactsRevision,
  };
}

/**
 * Installs the authoritative session lookup once, then creates branded contexts from explicit
 * host facts. Unknown caller fields are deliberately not copied into the trusted value.
 */
export function createMemoryAccessContextFactory(
  dependencies: MemoryAccessContextFactoryDependencies,
): (facts: MemoryAccessContextFacts) => Promise<MemoryAccessContext> {
  return async (facts) => {
    const currentIdentity = await dependencies.readCurrentSessionIdentity({
      agentId: facts.agentId,
      sessionKey: facts.sessionKey,
    });
    if (
      !currentIdentity ||
      currentIdentity.sessionId !== facts.sessionId ||
      currentIdentity.sessionIdentityRevision !== facts.sessionIdentityRevision
    ) {
      throw new MemoryAccessContextError("session-rebound");
    }
    const nowMs = dependencies.now?.() ?? Date.now();
    assertCurrentTime(nowMs);
    // The caller supplies the expected session identity only for rebound detection.
    // Subject provenance always comes from the authoritative persisted snapshot.
    const serializable = buildSerializableContext(facts, currentIdentity, nowMs);
    const contextFingerprint = `sha256:${sha256Hex(stableStringify(serializable))}`;
    const context = {
      ...serializable,
      contextFingerprint,
    } satisfies MemoryAccessContext;
    return brandAndFreeze(context, memoryAccessContextBrand, trustedMemoryAccessContexts);
  };
}

export function isTrustedMemoryAccessContext(value: unknown): value is MemoryAccessContext {
  return (
    typeof value === "object" &&
    value !== null &&
    trustedMemoryAccessContexts.has(value) &&
    (value as Record<symbol, unknown>)[memoryAccessContextBrand] === true &&
    Object.isFrozen(value)
  );
}

function currentEvidenceExpiryMs(context: MemoryAccessContext, nowMs: number): number | undefined {
  let earliestExpiryMs: number | undefined;
  const include = (
    expiresAt: string | undefined,
    code: "identity-revoked" | "membership-stale",
  ): void => {
    if (expiresAt === undefined) {
      return;
    }
    const expiresAtMs = Date.parse(expiresAt);
    if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) {
      throw new MemoryAccessContextError(code);
    }
    earliestExpiryMs =
      earliestExpiryMs === undefined ? expiresAtMs : Math.min(earliestExpiryMs, expiresAtMs);
  };
  if (context.actor.kind === "principal") {
    include(context.actor.expiresAt, "identity-revoked");
  }
  for (const principal of context.verifiedPrincipals) {
    include(principal.expiresAt, "identity-revoked");
  }
  for (const membership of context.verifiedMemberships) {
    include(membership.expiresAt, "membership-stale");
  }
  return earliestExpiryMs;
}

function cloneResourceHandle(
  handle: AuthorizedResourceHandle,
  planId: string,
  contextFingerprint: string,
  policyRevision: string,
  planExpiresAtMs: number,
  nowMs: number,
): AuthorizedResourceHandle {
  for (const value of [
    handle.handleId,
    handle.planId,
    handle.contextFingerprint,
    handle.resourceRevision,
    handle.policyRevision,
    handle.expiresAt,
  ]) {
    assertNonEmpty(value);
  }
  if (
    handle.version !== 1 ||
    handle.planId !== planId ||
    handle.contextFingerprint !== contextFingerprint ||
    handle.policyRevision !== policyRevision
  ) {
    throw new MemoryAccessContextError("invalid-context");
  }
  const handleExpiresAtMs = Date.parse(handle.expiresAt);
  if (
    !Number.isFinite(handleExpiresAtMs) ||
    handleExpiresAtMs <= nowMs ||
    handleExpiresAtMs > planExpiresAtMs
  ) {
    throw new MemoryAccessContextError("plan-expired");
  }
  return {
    version: 1,
    handleId: handle.handleId,
    planId: handle.planId,
    contextFingerprint: handle.contextFingerprint,
    resourceRevision: handle.resourceRevision,
    policyRevision: handle.policyRevision,
    expiresAt: handle.expiresAt,
  };
}

/** Validates, strips unknown fields from, brands, and freezes one plugin-issued plan. */
export function brandAuthorizedMemoryPlan(params: {
  context: MemoryAccessContext;
  plan: AuthorizedMemoryPlan;
  nowMs?: number;
}): AuthorizedMemoryPlan {
  if (!isTrustedMemoryAccessContext(params.context) || params.plan.version !== 1) {
    throw new MemoryAccessContextError("invalid-context");
  }
  const { context, plan } = params;
  if (plan.contextFingerprint !== context.contextFingerprint || plan.runId !== context.runId) {
    throw new MemoryAccessContextError("invalid-context");
  }
  if (
    plan.agentId !== context.agentId ||
    plan.sessionId !== context.sessionId ||
    plan.operation !== context.operation
  ) {
    throw new MemoryAccessContextError("outside-view");
  }
  if (
    plan.sessionIdentityRevision !== context.sessionIdentityRevision ||
    plan.subjectRevision !== context.subjectRevision
  ) {
    throw new MemoryAccessContextError("revision-stale");
  }
  if (plan.deliveryRevision !== context.delivery.deliveryRevision) {
    throw new MemoryAccessContextError("delivery-rebound");
  }
  const nowMs = params.nowMs ?? Date.now();
  assertCurrentTime(nowMs);
  const evidenceExpiresAtMs = currentEvidenceExpiryMs(context, nowMs);
  const expiresAtMs = Date.parse(plan.expiresAt);
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) {
    throw new MemoryAccessContextError("plan-expired");
  }
  if (evidenceExpiresAtMs !== undefined && expiresAtMs > evidenceExpiresAtMs) {
    throw new MemoryAccessContextError("plan-expired");
  }
  for (const value of [plan.planId, plan.memoryPolicyRevision, plan.expiresAt]) {
    assertNonEmpty(value);
  }
  const deliveryAudienceKeys = new Set(context.delivery.audiences.map(audienceKey));
  const allowedEgressAudiences = cloneAudiences(plan.allowedEgressAudiences);
  if (allowedEgressAudiences.some((audience) => !deliveryAudienceKeys.has(audienceKey(audience)))) {
    throw new MemoryAccessContextError("outside-view");
  }
  const brandedPlan = {
    version: 1 as const,
    planId: plan.planId,
    contextFingerprint: plan.contextFingerprint,
    runId: plan.runId,
    agentId: plan.agentId,
    sessionId: plan.sessionId,
    sessionIdentityRevision: plan.sessionIdentityRevision,
    subjectRevision: plan.subjectRevision,
    memoryPolicyRevision: plan.memoryPolicyRevision,
    deliveryRevision: plan.deliveryRevision,
    operation: plan.operation,
    mounts: plan.mounts.map((mount) => {
      if (mount.version !== 1 || mount.agentId !== context.agentId) {
        throw new MemoryAccessContextError("outside-view");
      }
      assertNonEmpty(mount.mountHandle);
      assertNonEmpty(mount.audienceRevision);
      for (const capability of mount.capabilities) {
        assertOneOf(capability, MEMORY_OPERATIONS);
      }
      return {
        version: 1 as const,
        agentId: mount.agentId,
        mountHandle: mount.mountHandle,
        capabilities: [...new Set(mount.capabilities)].toSorted(compareText),
        audienceRevision: mount.audienceRevision,
      };
    }),
    bootstrapResourceHandles: plan.bootstrapResourceHandles.map((handle) =>
      cloneResourceHandle(
        handle,
        plan.planId,
        plan.contextFingerprint,
        plan.memoryPolicyRevision,
        expiresAtMs,
        nowMs,
      ),
    ),
    allowedEgressAudiences,
    expiresAt: plan.expiresAt,
  } satisfies AuthorizedMemoryPlan;
  return brandAndFreeze(brandedPlan, authorizedMemoryPlanBrand, trustedAuthorizedMemoryPlans);
}

export function isTrustedAuthorizedMemoryPlan(value: unknown): value is AuthorizedMemoryPlan {
  return (
    typeof value === "object" &&
    value !== null &&
    trustedAuthorizedMemoryPlans.has(value) &&
    (value as Record<symbol, unknown>)[authorizedMemoryPlanBrand] === true &&
    Object.isFrozen(value)
  );
}
