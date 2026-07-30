import { executeSqliteQueryTakeFirstSync, getNodeSqliteKysely } from "../infra/kysely-sync.js";
import type {
  AuthorizedMemoryPlan,
  AuthorizedMemoryResultEnvelope,
  AuthorizedResourceHandle,
  MemoryAccessContext,
  MemoryEgressAuthorizationReceipt,
  MemoryExposureReceipt,
  PreparedMemoryTranscriptPolicy,
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

export type MemoryVirtualFilesystemRoot = Readonly<{
  virtualRoot: "private" | "channel" | "shared" | "projections" | "postbox-review";
  mountHandle: string;
  sourcePath: string;
}>;

/** Ephemeral, model-visible view. The source path is never a controlled artifact root. */
export type MemoryVirtualFilesystemView = Readonly<{
  viewId: string;
  rootDir: string;
  roots: readonly MemoryVirtualFilesystemRoot[];
}>;

export type MemoryInvocationState = {
  agentId: string;
  sessionId: string;
  sessionKey: string;
  runId: string;
  deliveryInput?: Readonly<{
    messageChannel?: string;
    agentAccountId?: string;
    messageTo?: string;
    messageThreadId?: string | number;
  }>;
  context?: MemoryAccessContext;
  plan?: AuthorizedMemoryPlan;
  runtime?: AdmittedAuthorizedMemoryReadRuntime;
  runExposure?: TranscriptMemoryRunExposureSnapshot;
  transcriptPolicy?: PreparedMemoryTranscriptPolicy;
  virtualFilesystem?: MemoryVirtualFilesystemView;
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

/**
 * The plugin resolves stable policy requirements before a transcript write.
 * The later SQLite transaction receives only this immutable payload, never a
 * plugin callback or an implicit policy lookup.
 */
export async function refreshMemoryInvocationTranscriptPolicy(
  state: MemoryInvocationState,
): Promise<void> {
  const { context, plan, runtime, runExposure } = state;
  if (!context || !plan || !runtime || !runExposure) {
    throw new Error("memory transcript policy is unavailable");
  }
  const sourcePolicySetIds = parseCanonicalMemoryStringArray(runExposure.sourcePolicySetIdsJson);
  if (!sourcePolicySetIds) {
    throw new Error("memory transcript policy is unavailable");
  }
  const policy = await runtime.prepareTranscriptPolicy({
    context,
    plan,
    sourcePolicySetIds,
    policySetId: runExposure.effectiveSourcePolicySetId,
  });
  if (
    policy.version !== 1 ||
    policy.policySetId !== runExposure.effectiveSourcePolicySetId ||
    policy.sourcePolicySetIds.some((value) => !sourcePolicySetIds.includes(value)) ||
    policy.sourcePolicySetIds.length !== sourcePolicySetIds.length ||
    policy.requirements.length === 0 ||
    policy.requirements.some(
      (requirement) =>
        !requirement.stablePolicyId.trim() ||
        !requirement.capturedRevisionId.trim() ||
        !requirement.expectedActiveRevisionId.trim() ||
        !Number.isSafeInteger(requirement.expectedRevocationEpoch) ||
        requirement.expectedRevocationEpoch < 0,
    )
  ) {
    throw new Error("memory transcript policy is unavailable");
  }
  state.transcriptPolicy = Object.freeze({
    ...policy,
    sourcePolicySetIds: Object.freeze([...policy.sourcePolicySetIds]),
    normalizedAudienceIntersection: Object.freeze([...policy.normalizedAudienceIntersection]),
    requirements: Object.freeze([...policy.requirements]),
  });
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
    await refreshMemoryInvocationTranscriptPolicy(params.state);
  } finally {
    release();
  }
}

/** Re-check persisted egress receipts immediately before an outbound delivery. */
export function hasCurrentMemoryEgressReceipts(state: MemoryInvocationState): boolean {
  const context = state.context;
  const plan = state.plan;
  const exposure = state.runExposure;
  if (!context || !plan || !exposure) {
    return false;
  }
  const resourceRevisions = parseCanonicalMemoryStringArray(exposure.exposedResourceRevisionsJson);
  const receiptIds = parseCanonicalMemoryStringArray(exposure.egressReceiptIdsJson);
  const sourcePolicySetIds = parseCanonicalMemoryStringArray(exposure.sourcePolicySetIdsJson);
  if (!resourceRevisions || !receiptIds || !sourcePolicySetIds) {
    return false;
  }
  if (resourceRevisions.length === 0) {
    return true;
  }
  if (receiptIds.length === 0) {
    return false;
  }
  const database = openOpenClawAgentDatabase({ agentId: state.agentId });
  ensureOpenClawAgentScopedMemorySchema(database.db);
  const kysely = getNodeSqliteKysely<MemoryInvocationDatabase>(database.db);
  const nowMs = Date.now();
  const coveredResourceRevisions: string[] = [];
  const coveredPolicySetIds: string[] = [];
  const receiptsAreCurrent = receiptIds.every((receiptId) => {
    const row = executeSqliteQueryTakeFirstSync(
      database.db,
      kysely.selectFrom("memory_egress_receipts").selectAll().where("receipt_id", "=", receiptId),
    );
    const exposureRow = row
      ? executeSqliteQueryTakeFirstSync(
          database.db,
          kysely
            .selectFrom("memory_exposure_receipts")
            .selectAll()
            .where("receipt_id", "=", row.exposure_receipt_id),
        )
      : undefined;
    const allowedAudiences = row
      ? parseCanonicalMemoryAudiences(row.allowed_audiences_json)
      : undefined;
    const exposedRevisions = exposureRow
      ? parseCanonicalMemoryStringArray(exposureRow.exposed_revision_handles_json)
      : undefined;
    if (exposedRevisions) {
      coveredResourceRevisions.push(...exposedRevisions);
    }
    if (exposureRow) {
      coveredPolicySetIds.push(exposureRow.source_policy_set_id);
    }
    return Boolean(
      row &&
      exposureRow &&
      allowedAudiences &&
      exposedRevisions &&
      row.context_fingerprint === context.contextFingerprint &&
      row.plan_id === plan.planId &&
      row.run_id === context.runId &&
      row.exposure_receipt_id === exposureRow.receipt_id &&
      row.run_exposure_revision === exposureRow.run_exposure_revision &&
      row.source_policy_set_id === exposureRow.source_policy_set_id &&
      exposureRow.context_fingerprint === context.contextFingerprint &&
      exposureRow.plan_id === plan.planId &&
      exposureRow.run_id === context.runId &&
      row.delivery_revision === context.delivery.deliveryRevision &&
      row.egress_registry_revision === context.delivery.egressRegistryRevision &&
      row.expires_at > nowMs &&
      exposureRow.recorded_at <= row.recorded_at &&
      equalMemoryAudiences(allowedAudiences, plan.allowedEgressAudiences),
    );
  });
  return (
    receiptsAreCurrent &&
    equalMemoryStringArrays(
      sortedUniqueMemoryStrings(coveredResourceRevisions),
      sortedUniqueMemoryStrings(resourceRevisions),
    ) &&
    equalMemoryStringArrays(
      sortedUniqueMemoryStrings(coveredPolicySetIds),
      sortedUniqueMemoryStrings(sourcePolicySetIds),
    )
  );
}
