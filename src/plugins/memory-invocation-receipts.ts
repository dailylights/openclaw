import { executeSqliteQueryTakeFirstSync, getNodeSqliteKysely } from "../infra/kysely-sync.js";
import type {
  AuthorizedMemoryPlan,
  AuthorizedMemoryResultEnvelope,
  AuthorizedResourceHandle,
  MemoryAccessContext,
  MemoryEgressAuthorizationReceipt,
  MemoryExposureReceipt,
} from "../memory-host-sdk/host/authorization.js";
import type { DB as OpenClawAgentDatabaseSchema } from "../state/openclaw-agent-db.generated.js";
import { openOpenClawAgentDatabase } from "../state/openclaw-agent-db.js";
import { ensureOpenClawAgentScopedMemorySchema } from "../state/openclaw-agent-scoped-memory-schema.js";
import type { AdmittedAuthorizedMemoryReadRuntime } from "./memory-authorization-runtime.js";
import {
  canonicalMemoryAudiencesJson,
  canonicalMemoryStringArrayJson,
  createEffectiveMemoryPolicySetId,
  createMemoryOpaqueId,
  equalMemoryAudiences,
  equalMemoryStringArrays,
  parseCanonicalMemoryAudiences,
  parseCanonicalMemoryStringArray,
  sortedUniqueMemoryStrings,
} from "./memory-invocation-serialization.js";

type MemoryInvocationDatabase = Pick<
  OpenClawAgentDatabaseSchema,
  | "memory_egress_receipts"
  | "memory_exposure_receipts"
  | "memory_policy_sets"
  | "memory_run_exposures"
>;

export type TranscriptMemoryRunExposureSnapshot = Readonly<{
  exposureSetId: string;
  revisionNumber: number;
  previous?: TranscriptMemoryRunExposureSnapshot;
  agentId: string;
  runId: string;
  contextFingerprint: string;
  planId: string;
  memoryPolicyRevision: string;
  sourcePolicySetIdsJson: string;
  effectiveSourcePolicySetId: string;
  exposedResourceRevisionsJson: string;
  exposureReceiptIdsJson: string;
  egressReceiptIdsJson: string;
  deliveryAudiencesJson: string;
  deliveryRevision: string;
  egressRegistryRevision: string;
  createdAt: number;
}>;

export type MemoryInvocationState = {
  agentId: string;
  sessionId: string;
  sessionKey: string;
  runId: string;
  context?: MemoryAccessContext;
  plan?: AuthorizedMemoryPlan;
  runtime?: AdmittedAuthorizedMemoryReadRuntime;
  runExposure?: TranscriptMemoryRunExposureSnapshot;
  initialization: "created" | "initializing" | "ready" | "unavailable";
  displayHandles: MemoryDisplayHandleRegistry;
  mergeTail: Promise<void>;
};

type MemoryDisplayHandleRegistry = Map<string, Map<string, AuthorizedResourceHandle>>;

export function createMemoryDisplayHandleRegistry(): MemoryDisplayHandleRegistry {
  return new Map();
}

export function rememberMemoryDisplayHandle(
  registry: MemoryDisplayHandleRegistry,
  path: string,
  handle: AuthorizedResourceHandle,
): void {
  const byHandle = registry.get(path) ?? new Map();
  byHandle.set(handle.handleId, handle);
  registry.set(path, byHandle);
}

export function resolveUniqueMemoryDisplayHandle(
  registry: MemoryDisplayHandleRegistry,
  path: string,
): AuthorizedResourceHandle | undefined {
  const handles = registry.get(path);
  return handles?.size === 1 ? handles.values().next().value : undefined;
}

export function advanceMemoryRunExposure(params: {
  state: MemoryInvocationState;
  sourcePolicySetIds: readonly string[];
  exposedResourceRevisions: readonly string[];
  exposureReceiptIds: readonly string[];
  egressReceiptIds: readonly string[];
}): TranscriptMemoryRunExposureSnapshot {
  const { state } = params;
  const context = state.context;
  const plan = state.plan;
  if (!context || !plan) {
    throw new Error("memory invocation is unavailable");
  }
  if (
    [
      ...params.sourcePolicySetIds,
      ...params.exposedResourceRevisions,
      ...params.exposureReceiptIds,
      ...params.egressReceiptIds,
    ].some((value) => typeof value !== "string" || value.trim().length === 0)
  ) {
    throw new Error("memory run exposure is unavailable");
  }
  const previous = state.runExposure;
  const previousPolicySets = previous
    ? parseCanonicalMemoryStringArray(previous.sourcePolicySetIdsJson)
    : [];
  const previousResourceRevisions = previous
    ? parseCanonicalMemoryStringArray(previous.exposedResourceRevisionsJson)
    : [];
  const previousExposureReceipts = previous
    ? parseCanonicalMemoryStringArray(previous.exposureReceiptIdsJson)
    : [];
  const previousEgressReceipts = previous
    ? parseCanonicalMemoryStringArray(previous.egressReceiptIdsJson)
    : [];
  if (
    !previousPolicySets ||
    !previousResourceRevisions ||
    !previousExposureReceipts ||
    !previousEgressReceipts ||
    (previous !== undefined &&
      (previous.agentId !== state.agentId ||
        previous.runId !== state.runId ||
        previous.contextFingerprint !== context.contextFingerprint ||
        previous.planId !== plan.planId ||
        previous.memoryPolicyRevision !== plan.memoryPolicyRevision ||
        previous.deliveryRevision !== context.delivery.deliveryRevision ||
        previous.egressRegistryRevision !== context.delivery.egressRegistryRevision))
  ) {
    throw new Error("memory run exposure is unavailable");
  }
  const sourcePolicySetIds = sortedUniqueMemoryStrings([
    ...previousPolicySets,
    ...params.sourcePolicySetIds,
  ]);
  const effectiveSourcePolicySetId = createEffectiveMemoryPolicySetId({
    memoryPolicyRevision: plan.memoryPolicyRevision,
    memberPolicySetIds: sourcePolicySetIds,
  });
  const snapshot = Object.freeze({
    exposureSetId: createMemoryOpaqueId("mre1"),
    revisionNumber: (previous?.revisionNumber ?? 0) + 1,
    ...(previous ? { previous } : {}),
    agentId: state.agentId,
    runId: state.runId,
    contextFingerprint: context.contextFingerprint,
    planId: plan.planId,
    memoryPolicyRevision: plan.memoryPolicyRevision,
    sourcePolicySetIdsJson: canonicalMemoryStringArrayJson(sourcePolicySetIds),
    effectiveSourcePolicySetId,
    exposedResourceRevisionsJson: canonicalMemoryStringArrayJson(
      sortedUniqueMemoryStrings([...previousResourceRevisions, ...params.exposedResourceRevisions]),
    ),
    exposureReceiptIdsJson: canonicalMemoryStringArrayJson(
      sortedUniqueMemoryStrings([...previousExposureReceipts, ...params.exposureReceiptIds]),
    ),
    egressReceiptIdsJson: canonicalMemoryStringArrayJson(
      sortedUniqueMemoryStrings([...previousEgressReceipts, ...params.egressReceiptIds]),
    ),
    deliveryAudiencesJson: canonicalMemoryAudiencesJson(context.delivery.audiences),
    deliveryRevision: context.delivery.deliveryRevision,
    egressRegistryRevision: context.delivery.egressRegistryRevision,
    createdAt: Date.now(),
  }) satisfies TranscriptMemoryRunExposureSnapshot;
  state.runExposure = snapshot;
  return snapshot;
}

function validateMemoryReceiptRows(params: {
  state: MemoryInvocationState;
  exposure: MemoryExposureReceipt;
  egress: MemoryEgressAuthorizationReceipt;
  expectedResourceRevisions: readonly string[];
}): void {
  const { state, exposure, egress } = params;
  const context = state.context;
  const plan = state.plan;
  if (!context || !plan) {
    throw new Error("memory invocation is unavailable");
  }
  const expectedResourceRevisions = sortedUniqueMemoryStrings(params.expectedResourceRevisions);
  const receiptResourceRevisions = sortedUniqueMemoryStrings(exposure.exposedRevisionHandles);
  const nowMs = Date.now();
  const exposureRecordedAt = Date.parse(exposure.recordedAt);
  const egressExpiresAt = Date.parse(egress.expiresAt);
  const planExpiresAt = Date.parse(plan.expiresAt);
  if (
    exposure.version !== 1 ||
    egress.version !== 1 ||
    !equalMemoryStringArrays(expectedResourceRevisions, receiptResourceRevisions) ||
    exposure.contextFingerprint !== context.contextFingerprint ||
    egress.contextFingerprint !== context.contextFingerprint ||
    exposure.planId !== plan.planId ||
    egress.planId !== plan.planId ||
    exposure.runId !== context.runId ||
    egress.runId !== context.runId ||
    exposure.runExposureRevision !== egress.runExposureRevision ||
    exposure.sourcePolicySetId !== egress.sourcePolicySetId ||
    egress.deliveryRevision !== context.delivery.deliveryRevision ||
    egress.egressRegistryRevision !== context.delivery.egressRegistryRevision ||
    !Number.isFinite(exposureRecordedAt) ||
    exposureRecordedAt > nowMs ||
    !Number.isFinite(egressExpiresAt) ||
    egressExpiresAt <= nowMs ||
    egressExpiresAt > planExpiresAt ||
    !equalMemoryAudiences(egress.allowedAudiences, plan.allowedEgressAudiences)
  ) {
    throw new Error("memory receipt binding is unavailable");
  }
  const database = openOpenClawAgentDatabase({ agentId: state.agentId });
  ensureOpenClawAgentScopedMemorySchema(database.db);
  const kysely = getNodeSqliteKysely<MemoryInvocationDatabase>(database.db);
  const exposureRow = executeSqliteQueryTakeFirstSync(
    database.db,
    kysely
      .selectFrom("memory_exposure_receipts")
      .selectAll()
      .where("receipt_id", "=", exposure.receiptId),
  );
  const egressRow = executeSqliteQueryTakeFirstSync(
    database.db,
    kysely
      .selectFrom("memory_egress_receipts")
      .selectAll()
      .where("receipt_id", "=", egress.receiptId),
  );
  const storedHandles = exposureRow
    ? parseCanonicalMemoryStringArray(exposureRow.exposed_revision_handles_json)
    : undefined;
  const storedAudiences = egressRow
    ? parseCanonicalMemoryAudiences(egressRow.allowed_audiences_json)
    : undefined;
  if (
    !exposureRow ||
    !egressRow ||
    !storedHandles ||
    !storedAudiences ||
    !equalMemoryStringArrays(sortedUniqueMemoryStrings(storedHandles), expectedResourceRevisions) ||
    !equalMemoryAudiences(storedAudiences, plan.allowedEgressAudiences) ||
    exposureRow.context_fingerprint !== exposure.contextFingerprint ||
    exposureRow.plan_id !== exposure.planId ||
    exposureRow.run_id !== exposure.runId ||
    exposureRow.run_exposure_revision !== exposure.runExposureRevision ||
    exposureRow.source_policy_set_id !== exposure.sourcePolicySetId ||
    egressRow.exposure_receipt_id !== exposure.receiptId ||
    egressRow.context_fingerprint !== egress.contextFingerprint ||
    egressRow.plan_id !== egress.planId ||
    egressRow.run_id !== egress.runId ||
    egressRow.run_exposure_revision !== egress.runExposureRevision ||
    egressRow.source_policy_set_id !== egress.sourcePolicySetId ||
    egressRow.delivery_revision !== egress.deliveryRevision ||
    egressRow.egress_registry_revision !== egress.egressRegistryRevision ||
    exposureRow.recorded_at !== exposureRecordedAt ||
    egressRow.expires_at !== egressExpiresAt ||
    egressRow.recorded_at < exposureRecordedAt ||
    egressRow.recorded_at > nowMs
  ) {
    throw new Error("memory receipt persistence is unavailable");
  }
}

export async function mergeMemoryInvocationEnvelope<T>(params: {
  state: MemoryInvocationState;
  envelope: AuthorizedMemoryResultEnvelope<T>;
  expectedResourceRevisions: readonly string[];
  isInvocationValid: () => boolean;
}): Promise<void> {
  const previous = params.state.mergeTail;
  let release!: () => void;
  params.state.mergeTail = new Promise<void>((resolve) => {
    release = resolve;
  });
  await previous;
  try {
    if (!params.isInvocationValid()) {
      throw new Error("memory invocation is unavailable");
    }
    validateMemoryReceiptRows({
      state: params.state,
      exposure: params.envelope.exposureReceipt,
      egress: params.envelope.egressReceipt,
      expectedResourceRevisions: params.expectedResourceRevisions,
    });
    advanceMemoryRunExposure({
      state: params.state,
      sourcePolicySetIds: [params.envelope.exposureReceipt.sourcePolicySetId],
      exposedResourceRevisions: params.expectedResourceRevisions,
      exposureReceiptIds: [params.envelope.exposureReceipt.receiptId],
      egressReceiptIds: [params.envelope.egressReceipt.receiptId],
    });
  } finally {
    release();
  }
}
