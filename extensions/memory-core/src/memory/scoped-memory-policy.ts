import type {
  AudienceRef,
  MemoryAuthorizationConformanceAdapter,
  MemoryAuthorizationConformanceDecision,
  MemoryAuthorizationConformancePolicyEntry,
  MemoryAuthorizationConformanceResource,
  MemoryAuthorizationConformanceScenario,
  MemoryAuthorizationReasonCode,
  MemoryAccessContext,
  MemoryOperation,
} from "openclaw/plugin-sdk/memory-authorization";
import { MEMORY_OPERATIONS } from "openclaw/plugin-sdk/memory-authorization";
import type { MemoryPolicyEntryRow, MemoryStoreRow } from "./scoped-memory-db.js";

export const SCOPED_MEMORY_OPERATION_REQUIREMENTS: Readonly<
  Record<MemoryOperation, readonly MemoryOperation[]>
> = {
  retrieve: ["retrieve"],
  read: ["retrieve", "read"],
  append: ["append"],
  replace: ["append", "replace"],
  derive: ["retrieve", "read", "derive"],
  deposit: ["deposit"],
  project: ["project"],
  publish: ["publish"],
  import: ["import"],
  export: ["export"],
  delete: ["delete"],
  sync: ["sync"],
  status: ["status"],
  "policy-admin": ["policy-admin"],
};

function audienceKey(audience: AudienceRef): string {
  return `${audience.kind}\0${audience.id}`;
}

function isExpired(expiresAt: string | undefined, now: string): boolean {
  if (expiresAt === undefined) {
    return false;
  }
  const expiry = Date.parse(expiresAt);
  const current = Date.parse(now);
  return !Number.isFinite(expiry) || !Number.isFinite(current) || expiry <= current;
}

function policyEntryMatches(params: {
  entry: MemoryAuthorizationConformancePolicyEntry;
  scenario: MemoryAuthorizationConformanceScenario;
  resource: MemoryAuthorizationConformanceResource;
  operation: MemoryOperation;
}): boolean {
  return (
    params.entry.operation === params.operation &&
    (params.entry.resourceId === "*" || params.entry.resourceId === params.resource.resourceId) &&
    (params.entry.principalId === "*" ||
      params.scenario.context.principalIds.includes(params.entry.principalId)) &&
    !isExpired(params.entry.expiresAt, params.scenario.now)
  );
}

function planBindingFailure(
  scenario: MemoryAuthorizationConformanceScenario,
): MemoryAuthorizationReasonCode | null {
  if (isExpired(scenario.plan.expiresAt, scenario.now)) {
    return "plan-expired";
  }
  if (scenario.plan.contextFingerprint !== scenario.context.contextFingerprint) {
    return "invalid-context";
  }
  if (
    scenario.plan.agentId !== scenario.context.agentId ||
    scenario.plan.operation !== scenario.context.operation
  ) {
    return "outside-view";
  }
  if (
    scenario.plan.sessionIdentityRevision !== scenario.context.sessionIdentityRevision ||
    scenario.plan.subjectRevision !== scenario.context.subjectRevision ||
    scenario.plan.policyRevision !== scenario.context.policyRevision
  ) {
    return "revision-stale";
  }
  if (scenario.plan.deliveryRevision !== scenario.context.deliveryRevision) {
    return "delivery-rebound";
  }
  return null;
}

/** Memory Core policy evaluator used by both live rows and host-run conformance admission. */
function evaluateScopedMemoryConformanceScenario(params: {
  scenario: MemoryAuthorizationConformanceScenario;
  resource: MemoryAuthorizationConformanceResource;
}): MemoryAuthorizationConformanceDecision {
  const { resource, scenario } = params;
  const bindingFailure = planBindingFailure(scenario);
  if (bindingFailure) {
    return { allowed: false, reasonCode: bindingFailure };
  }
  const store = scenario.stores.find((entry) => entry.storeId === resource.storeId);
  if (
    !store ||
    store.agentId !== scenario.context.agentId ||
    resource.agentId !== scenario.context.agentId ||
    !scenario.viewStoreIds.includes(resource.storeId)
  ) {
    return { allowed: false, reasonCode: "outside-view" };
  }
  if (isExpired(resource.expiresAt, scenario.now)) {
    return { allowed: false, reasonCode: "revision-stale" };
  }
  const resourceAudiences = new Set(resource.audiences.map(audienceKey));
  if (
    scenario.context.deliveryAudiences.some(
      (audience) => !resourceAudiences.has(audienceKey(audience)),
    )
  ) {
    return { allowed: false, reasonCode: "outside-view" };
  }
  const delegation = scenario.context.delegation;
  if (delegation) {
    const maximumAudiences = new Set(delegation.maximumAudiences.map(audienceKey));
    if (
      !delegation.allowedOperations.includes(scenario.context.operation) ||
      scenario.context.deliveryAudiences.some(
        (audience) => !maximumAudiences.has(audienceKey(audience)),
      )
    ) {
      return { allowed: false, reasonCode: "default-deny" };
    }
  }
  const inheritedPolicies = new Set(scenario.context.lineagePolicySetIds);
  if (
    resource.requiredLineagePolicySetIds?.some((policySetId) => !inheritedPolicies.has(policySetId))
  ) {
    return { allowed: false, reasonCode: "lineage-deny" };
  }
  const requiredOperations = SCOPED_MEMORY_OPERATION_REQUIREMENTS[scenario.context.operation];
  for (const operation of requiredOperations) {
    if (
      scenario.policyEntries.some(
        (entry) =>
          entry.effect === "deny" && policyEntryMatches({ entry, scenario, resource, operation }),
      )
    ) {
      return { allowed: false, reasonCode: "explicit-deny" };
    }
  }
  for (const operation of requiredOperations) {
    const placed = store.placementCapabilities.includes(operation);
    const explicitlyAllowed = scenario.policyEntries.some(
      (entry) =>
        entry.effect === "allow" && policyEntryMatches({ entry, scenario, resource, operation }),
    );
    if (!placed && !explicitlyAllowed) {
      return { allowed: false, reasonCode: "default-deny" };
    }
  }
  return {
    allowed: true,
    reasonCode: "allowed",
    handle: `authorized:${resource.resourceId}:${resource.revision}`,
  };
}

/** Adapter is deliberately plugin-owned; host admission runs the independent suite against it. */
export const builtinScopedMemoryConformanceAdapter: MemoryAuthorizationConformanceAdapter =
  Object.freeze({
    evaluate: evaluateScopedMemoryConformanceScenario,
    prefilter: (scenario) => [
      ...new Set(scenario.resources.map((resource) => resource.resourceId)),
    ],
  });

function livePolicyEntryMatches(params: {
  entry: MemoryPolicyEntryRow;
  store: MemoryStoreRow;
  principalIds: ReadonlySet<string>;
  operation: MemoryOperation;
  nowMs: number;
}): boolean {
  const { entry, store } = params;
  return (
    entry.operation === params.operation &&
    (entry.principal_id === "*" || params.principalIds.has(entry.principal_id)) &&
    (entry.audience_kind === "*" || entry.audience_kind === store.audience_kind) &&
    (entry.audience_id === "*" || entry.audience_id === store.audience_id) &&
    (entry.expires_at === null || entry.expires_at > params.nowMs)
  );
}

function liveAudienceKey(audience: AudienceRef): string {
  return `${audience.kind}\0${audience.id}`;
}

/** Principals used by the live policy evaluator come only from host-verified context facts. */
function listScopedMemoryContextPrincipalIds(context: MemoryAccessContext): Set<string> {
  const ids = new Set(context.verifiedPrincipals.map((entry) => entry.principalId));
  if (context.actor.kind === "principal") {
    ids.add(context.actor.principalId);
  }
  switch (context.subject.kind) {
    case "user":
      ids.add(context.subject.principalId);
      break;
    case "conversation":
      ids.add(context.subject.conversationPrincipalId);
      break;
    case "service":
    case "agent":
    case "system":
      ids.add(context.subject.principalId);
      break;
    case "ambiguous":
      break;
  }
  for (const membership of context.verifiedMemberships) {
    ids.add(membership.principalId);
    ids.add(membership.groupId);
  }
  return ids;
}

/** Broad agent stores cover delivery inside the same agent cell; other stores require exact audience. */
function scopedMemoryStoreCoversDelivery(params: {
  context: MemoryAccessContext;
  store: Pick<MemoryStoreRow, "audience_kind" | "audience_id">;
}): boolean {
  if (
    (params.store.audience_kind === "agent-shared" || params.store.audience_kind === "agent") &&
    params.store.audience_id === params.context.agentId
  ) {
    return true;
  }
  const storeKey = `${params.store.audience_kind}\0${params.store.audience_id}`;
  return params.context.delivery.audiences.every(
    (audience) => liveAudienceKey(audience) === storeKey,
  );
}

/** Authoritative store-level allow/deny evaluation for one requested operation. */
export function evaluateScopedMemoryStorePolicy(params: {
  context: MemoryAccessContext;
  store: MemoryStoreRow;
  defaultCapabilities: readonly MemoryOperation[];
  entries: readonly MemoryPolicyEntryRow[];
  nowMs: number;
}): MemoryAuthorizationConformanceDecision {
  if (params.context.delegation) {
    const maximumAudiences = new Set(
      params.context.delegation.maximumAudiences.map(liveAudienceKey),
    );
    if (
      !params.context.delegation.allowedOperations.includes(params.context.operation) ||
      params.context.delivery.audiences.some(
        (audience) => !maximumAudiences.has(liveAudienceKey(audience)),
      )
    ) {
      return { allowed: false, reasonCode: "default-deny" };
    }
  }
  if (!scopedMemoryStoreCoversDelivery({ context: params.context, store: params.store })) {
    return { allowed: false, reasonCode: "outside-view" };
  }
  const principalIds = listScopedMemoryContextPrincipalIds(params.context);
  const requiredOperations = SCOPED_MEMORY_OPERATION_REQUIREMENTS[params.context.operation];
  for (const operation of requiredOperations) {
    if (
      params.entries.some(
        (entry) =>
          entry.effect === "deny" &&
          livePolicyEntryMatches({
            entry,
            store: params.store,
            principalIds,
            operation,
            nowMs: params.nowMs,
          }),
      )
    ) {
      return { allowed: false, reasonCode: "explicit-deny" };
    }
  }
  const defaults = new Set(
    params.defaultCapabilities.filter((operation): operation is MemoryOperation =>
      (MEMORY_OPERATIONS as readonly string[]).includes(operation),
    ),
  );
  for (const operation of requiredOperations) {
    const explicitlyAllowed = params.entries.some(
      (entry) =>
        entry.effect === "allow" &&
        livePolicyEntryMatches({
          entry,
          store: params.store,
          principalIds,
          operation,
          nowMs: params.nowMs,
        }),
    );
    if (!defaults.has(operation) && !explicitlyAllowed) {
      return { allowed: false, reasonCode: "default-deny" };
    }
  }
  return {
    allowed: true,
    reasonCode: "allowed",
    handle: `authorized:${params.store.store_id}:${params.context.hostFactsRevision}`,
  };
}
