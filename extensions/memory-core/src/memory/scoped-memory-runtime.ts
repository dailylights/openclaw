import { randomBytes, randomUUID } from "node:crypto";
import fs from "node:fs";
import type { DatabaseSync } from "node:sqlite";
import type {
  AudienceRef,
  AuthorizedMemoryPlan,
  AuthorizedMemoryResultEnvelope,
  AuthorizedMemorySearchResult,
  AuthorizedResourceHandle,
  DeepReadonly,
  MemoryAccessContext,
  MemoryEgressAuthorizationReceipt,
  MemoryExposureReceipt,
} from "openclaw/plugin-sdk/memory-authorization";
import type {
  MemoryReadResult,
  MemorySource,
} from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import { normalizeAgentId } from "openclaw/plugin-sdk/routing";
import {
  executeSqliteQuerySync,
  getNodeSqliteKysely,
  runSqliteImmediateTransactionSync,
} from "openclaw/plugin-sdk/sqlite-runtime";
import {
  assertScopedMemoryPlanBinding,
  createScopedMemoryAggregateRevision,
  createScopedMemoryPolicyRevision,
  equalScopedMemoryAuthorizedPlan,
  equalScopedMemoryResourceHandle,
  readScopedMemoryAuthorizedRevisionSnapshot,
  readScopedMemoryRevisionAuthorization,
  resolveScopedMemoryAuthorizedStores,
  type ScopedMemoryAuthorizedRevisionSnapshot,
  type ScopedMemoryMountRecord,
  type ScopedMemoryPlanRecord,
  type ScopedMemoryRevisionAuthorization,
} from "./scoped-memory-authorization.js";
import {
  readScopedMemoryFtsCandidatePage,
  type ScopedMemoryCandidatePageReader,
} from "./scoped-memory-candidates.js";
import { type ScopedMemoryDatabase, withScopedMemoryDatabase } from "./scoped-memory-db.js";

const PLAN_TTL_MS = 5 * 60_000;
const DEFAULT_MAX_PLANS = 1_024;
const DEFAULT_MAX_HANDLES = 8_192;
const OPAQUE_ID_ATTEMPTS = 8;
const MAX_SEARCH_RESULTS = 100;
const MAX_CANDIDATES_SCANNED = 10_000;

type OpaqueIdKind = "plan" | "mount" | "resource";

type HandleRecord = Readonly<{
  handle: AuthorizedResourceHandle;
  planId: string;
  storeId: string;
  resourceId: string;
  revisionId: string;
  expiresAtMs: number;
}>;

type BuiltinScopedMemoryRuntimeDependencies = Readonly<{
  now?: () => number;
  generateOpaqueId?: (kind: OpaqueIdKind) => string;
  readFile?: typeof fs.readFileSync;
  candidatePageReader?: ScopedMemoryCandidatePageReader;
  embedQuery?: (query: string) => readonly number[] | Promise<readonly number[]>;
  maxPlans?: number;
  maxHandles?: number;
}>;

function createOpaqueId(kind: OpaqueIdKind): string {
  const prefix = kind === "plan" ? "mp1" : kind === "mount" ? "mm1" : "mrh1";
  return `${prefix}_${randomBytes(24).toString("base64url")}`;
}

function assertOpaqueId(value: string): void {
  if (!/^[a-z0-9]+_[A-Za-z0-9_-]{24,}$/u.test(value)) {
    throw new Error("scoped-memory opaque identifier is invalid");
  }
}

function allocateOpaqueId(params: {
  kind: OpaqueIdKind;
  occupied: (candidate: string) => boolean;
  generate?: (kind: OpaqueIdKind) => string;
}): string {
  for (let attempt = 0; attempt < OPAQUE_ID_ATTEMPTS; attempt += 1) {
    const candidate = params.generate?.(params.kind) ?? createOpaqueId(params.kind);
    assertOpaqueId(candidate);
    if (!params.occupied(candidate)) {
      return candidate;
    }
  }
  throw new Error("could not allocate a scoped-memory opaque identifier");
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function audienceKey(audience: AudienceRef): string {
  return `${audience.kind}\0${audience.id}`;
}

function earliestContextExpiry(context: MemoryAccessContext): number | undefined {
  const expiries: number[] = [];
  if (context.actor.kind === "principal" && context.actor.expiresAt) {
    expiries.push(Date.parse(context.actor.expiresAt));
  }
  for (const principal of context.verifiedPrincipals) {
    if (principal.expiresAt) {
      expiries.push(Date.parse(principal.expiresAt));
    }
  }
  for (const membership of context.verifiedMemberships) {
    expiries.push(Date.parse(membership.expiresAt));
  }
  const valid = expiries.filter(Number.isFinite);
  return valid.length > 0 ? Math.min(...valid) : undefined;
}

function normalizeSources(sources: readonly MemorySource[] | undefined): MemorySource[] {
  const normalized = [...new Set<MemorySource>(sources ?? ["memory", "sessions"])];
  if (normalized.some((source) => source !== "memory" && source !== "sessions")) {
    throw new Error("authorized memory source is invalid");
  }
  return normalized.toSorted(compareText);
}

function freezeEnvelope<T>(params: {
  value: DeepReadonly<T>;
  exposureReceipt: MemoryExposureReceipt;
  egressReceipt: MemoryEgressAuthorizationReceipt;
}): AuthorizedMemoryResultEnvelope<T> {
  return Object.freeze({
    version: 1,
    value: params.value,
    exposureReceipt: params.exposureReceipt,
    egressReceipt: params.egressReceipt,
  });
}

/** Creates one isolated runtime instance; caches are bounded, expiring, and process-local. */
export function createBuiltinScopedMemoryRuntime(
  dependencies: BuiltinScopedMemoryRuntimeDependencies = {},
) {
  const plans = new Map<string, ScopedMemoryPlanRecord>();
  const handles = new Map<string, HandleRecord>();
  const now = dependencies.now ?? Date.now;
  const readFile = dependencies.readFile ?? fs.readFileSync;
  const candidatePageReader = dependencies.candidatePageReader ?? readScopedMemoryFtsCandidatePage;
  const maxPlans = Math.max(1, dependencies.maxPlans ?? DEFAULT_MAX_PLANS);
  const maxHandles = Math.max(1, dependencies.maxHandles ?? DEFAULT_MAX_HANDLES);

  const purgeExpired = (nowMs: number): void => {
    for (const [planId, record] of plans) {
      if (record.expiresAtMs <= nowMs) {
        plans.delete(planId);
      }
    }
    for (const [handleId, record] of handles) {
      if (record.expiresAtMs <= nowMs || !plans.has(record.planId)) {
        handles.delete(handleId);
      }
    }
    while (plans.size > maxPlans) {
      const oldest = plans.keys().next().value as string | undefined;
      if (!oldest) {
        break;
      }
      plans.delete(oldest);
    }
    while (handles.size > maxHandles) {
      const oldest = handles.keys().next().value as string | undefined;
      if (!oldest) {
        break;
      }
      handles.delete(oldest);
    }
  };

  const validatePlan = (params: {
    database: DatabaseSync;
    context: MemoryAccessContext;
    plan: AuthorizedMemoryPlan;
    nowMs: number;
  }): ScopedMemoryPlanRecord => {
    assertScopedMemoryPlanBinding(params);
    purgeExpired(params.nowMs);
    const record = plans.get(params.plan.planId);
    if (!record || !equalScopedMemoryAuthorizedPlan(params.plan, record.plan)) {
      throw new Error("authorized memory plan is unavailable");
    }
    const currentStores = resolveScopedMemoryAuthorizedStores({
      database: params.database,
      context: params.context,
      nowMs: params.nowMs,
    });
    if (createScopedMemoryPolicyRevision(currentStores) !== params.plan.memoryPolicyRevision) {
      throw new Error("authorized memory plan is unavailable");
    }
    const currentByStore = new Map(currentStores.map((entry) => [entry.store.store_id, entry]));
    for (const mount of record.mounts) {
      const current = currentByStore.get(mount.store.store_id);
      if (
        !current ||
        current.policyRevisionId !== mount.policyRevisionId ||
        current.policyRevocationEpoch !== mount.policyRevocationEpoch ||
        current.audienceRevision !== mount.audienceRevision
      ) {
        throw new Error("authorized memory plan is unavailable");
      }
    }
    if (currentStores.length !== record.mounts.length) {
      throw new Error("authorized memory plan is unavailable");
    }
    return record;
  };

  const issueHandle = (params: {
    context: MemoryAccessContext;
    plan: AuthorizedMemoryPlan;
    snapshot: ScopedMemoryRevisionAuthorization;
  }): AuthorizedResourceHandle => {
    const existing = [...handles.values()].find(
      (entry) =>
        entry.planId === params.plan.planId && entry.revisionId === params.snapshot.revisionId,
    );
    if (existing) {
      return existing.handle;
    }
    const handleId = allocateOpaqueId({
      kind: "resource",
      occupied: (candidate) => handles.has(candidate),
      generate: dependencies.generateOpaqueId,
    });
    const planExpiry = Date.parse(params.plan.expiresAt);
    const expiresAtMs = Math.min(planExpiry, params.snapshot.expiresAt ?? Number.POSITIVE_INFINITY);
    const handle = Object.freeze({
      version: 1 as const,
      handleId,
      planId: params.plan.planId,
      contextFingerprint: params.context.contextFingerprint,
      resourceRevision: params.snapshot.revisionId,
      policyRevision: params.plan.memoryPolicyRevision,
      expiresAt: new Date(expiresAtMs).toISOString(),
    });
    handles.set(handleId, {
      handle,
      planId: params.plan.planId,
      storeId: params.snapshot.storeId,
      resourceId: params.snapshot.resourceId,
      revisionId: params.snapshot.revisionId,
      expiresAtMs,
    });
    purgeExpired(now());
    return handle;
  };

  const persistReceipts = (params: {
    database: DatabaseSync;
    context: MemoryAccessContext;
    plan: AuthorizedMemoryPlan;
    snapshots: readonly ScopedMemoryAuthorizedRevisionSnapshot[];
    resourceHandles: readonly AuthorizedResourceHandle[];
    nowMs: number;
  }): {
    exposureReceipt: MemoryExposureReceipt;
    egressReceipt: MemoryEgressAuthorizationReceipt;
  } => {
    const exposureReceiptId = randomUUID();
    const egressReceiptId = randomUUID();
    const runExposureRevision = `mer1_${randomBytes(18).toString("base64url")}`;
    const sourcePolicySetId = createScopedMemoryAggregateRevision("mpset1", [
      ...new Set(params.snapshots.map((snapshot) => snapshot.sourcePolicySetId)),
    ]);
    const recordedAt = new Date(params.nowMs).toISOString();
    const exposedResourceRevisions = [
      ...new Set(params.resourceHandles.map((handle) => handle.resourceRevision)),
    ].toSorted(compareText);
    let allowedAudiences: AudienceRef[] = [];
    let canonicalPlan: AuthorizedMemoryPlan | undefined;

    runSqliteImmediateTransactionSync(params.database, () => {
      const planRecord = validatePlan({
        database: params.database,
        context: params.context,
        plan: params.plan,
        nowMs: params.nowMs,
      });
      canonicalPlan = planRecord.plan;
      allowedAudiences = [...canonicalPlan.allowedEgressAudiences].toSorted((left, right) =>
        compareText(audienceKey(left), audienceKey(right)),
      );
      for (const snapshot of params.snapshots) {
        const current = readScopedMemoryRevisionAuthorization({
          database: params.database,
          context: params.context,
          planRecord,
          revisionId: snapshot.revisionId,
          nowMs: params.nowMs,
        });
        if (
          !current ||
          current.contentHash !== snapshot.contentHash ||
          current.artifactLocator !== snapshot.artifactLocator ||
          current.sourcePolicySetId !== snapshot.sourcePolicySetId
        ) {
          throw new Error("authorized memory revision is unavailable");
        }
      }
      const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
      executeSqliteQuerySync(
        params.database,
        db.insertInto("memory_exposure_receipts").values({
          receipt_id: exposureReceiptId,
          context_fingerprint: params.context.contextFingerprint,
          plan_id: canonicalPlan.planId,
          run_id: params.context.runId,
          run_exposure_revision: runExposureRevision,
          source_policy_set_id: sourcePolicySetId,
          exposed_revision_handles_json: JSON.stringify(exposedResourceRevisions),
          recorded_at: params.nowMs,
        }),
      );
      executeSqliteQuerySync(
        params.database,
        db.insertInto("memory_egress_receipts").values({
          receipt_id: egressReceiptId,
          exposure_receipt_id: exposureReceiptId,
          context_fingerprint: params.context.contextFingerprint,
          plan_id: canonicalPlan.planId,
          run_id: params.context.runId,
          run_exposure_revision: runExposureRevision,
          source_policy_set_id: sourcePolicySetId,
          allowed_audiences_json: JSON.stringify(allowedAudiences),
          delivery_revision: params.context.delivery.deliveryRevision,
          egress_registry_revision: params.context.delivery.egressRegistryRevision,
          expires_at: Date.parse(canonicalPlan.expiresAt),
          recorded_at: params.nowMs,
        }),
      );
    });

    if (!canonicalPlan) {
      throw new Error("authorized memory plan is unavailable");
    }

    return {
      exposureReceipt: Object.freeze({
        version: 1,
        receiptId: exposureReceiptId,
        contextFingerprint: params.context.contextFingerprint,
        planId: canonicalPlan.planId,
        runId: params.context.runId,
        runExposureRevision,
        sourcePolicySetId,
        exposedRevisionHandles: Object.freeze(exposedResourceRevisions),
        recordedAt,
      }),
      egressReceipt: Object.freeze({
        version: 1,
        receiptId: egressReceiptId,
        contextFingerprint: params.context.contextFingerprint,
        planId: canonicalPlan.planId,
        runId: params.context.runId,
        runExposureRevision,
        sourcePolicySetId,
        allowedAudiences: Object.freeze(allowedAudiences),
        deliveryRevision: params.context.delivery.deliveryRevision,
        egressRegistryRevision: params.context.delivery.egressRegistryRevision,
        expiresAt: canonicalPlan.expiresAt,
      }),
    };
  };

  const authorize = async (context: MemoryAccessContext): Promise<AuthorizedMemoryPlan> => {
    const agentId = normalizeAgentId(context.agentId);
    if (
      context.version !== 1 ||
      agentId !== context.agentId ||
      (context.operation !== "read" && context.operation !== "retrieve")
    ) {
      throw new Error("authorized memory context is unavailable");
    }
    const nowMs = now();
    purgeExpired(nowMs);
    const planId = allocateOpaqueId({
      kind: "plan",
      occupied: (candidate) => plans.has(candidate),
      generate: dependencies.generateOpaqueId,
    });
    return withScopedMemoryDatabase(agentId, (database) => {
      const stores = resolveScopedMemoryAuthorizedStores({ database, context, nowMs });
      const occupiedMounts = new Set<string>();
      const mounts: ScopedMemoryMountRecord[] = stores.map((store) => {
        const mountHandle = allocateOpaqueId({
          kind: "mount",
          occupied: (candidate) => occupiedMounts.has(candidate),
          generate: dependencies.generateOpaqueId,
        });
        occupiedMounts.add(mountHandle);
        return { ...store, mountHandle };
      });
      const evidenceExpiry = earliestContextExpiry(context);
      const expiresAtMs = Math.min(nowMs + PLAN_TTL_MS, evidenceExpiry ?? Number.POSITIVE_INFINITY);
      if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) {
        throw new Error("authorized memory context is unavailable");
      }
      const policyRevision = createScopedMemoryPolicyRevision(stores);
      const plan = Object.freeze({
        version: 1 as const,
        planId,
        contextFingerprint: context.contextFingerprint,
        runId: context.runId,
        agentId,
        sessionId: context.sessionId,
        sessionIdentityRevision: context.sessionIdentityRevision,
        subjectRevision: context.subjectRevision,
        memoryPolicyRevision: policyRevision,
        deliveryRevision: context.delivery.deliveryRevision,
        operation: context.operation,
        mounts: Object.freeze(
          mounts.map((mount) =>
            Object.freeze({
              version: 1 as const,
              agentId,
              mountHandle: mount.mountHandle,
              capabilities: Object.freeze([...mount.capabilities]),
              audienceRevision: mount.audienceRevision,
            }),
          ),
        ),
        bootstrapResourceHandles: Object.freeze([]),
        allowedEgressAudiences: Object.freeze(
          [...context.delivery.audiences].toSorted((left, right) =>
            compareText(audienceKey(left), audienceKey(right)),
          ),
        ),
        expiresAt: new Date(expiresAtMs).toISOString(),
      }) satisfies AuthorizedMemoryPlan;
      plans.set(planId, { plan, mounts: Object.freeze(mounts), expiresAtMs });
      purgeExpired(nowMs);
      return plan;
    });
  };

  const searchAuthorized = async (params: {
    context: MemoryAccessContext;
    plan: AuthorizedMemoryPlan;
    query: string;
    subjectHandles?: readonly string[];
    sources?: readonly MemorySource[];
    limit: number;
    signal?: AbortSignal;
  }): Promise<AuthorizedMemoryResultEnvelope<readonly AuthorizedMemorySearchResult[]>> => {
    if (params.context.operation !== "read" || params.subjectHandles?.length) {
      throw new Error("authorized memory search is unavailable");
    }
    const limit = Math.min(MAX_SEARCH_RESULTS, Math.max(1, Math.trunc(params.limit)));
    if (!Number.isFinite(params.limit) || !params.query.trim()) {
      throw new Error("authorized memory search is unavailable");
    }
    const sources = normalizeSources(params.sources);
    const queryVector = dependencies.embedQuery
      ? [...(await dependencies.embedQuery(params.query))]
      : undefined;
    const nowMs = now();
    return withScopedMemoryDatabase(params.context.agentId, async (database, databasePath) => {
      const planRecord = validatePlan({
        database,
        context: params.context,
        plan: params.plan,
        nowMs,
      });
      const storeIds = planRecord.mounts.map((mount) => mount.store.store_id);
      const results: AuthorizedMemorySearchResult[] = [];
      const snapshots: ScopedMemoryAuthorizedRevisionSnapshot[] = [];
      const resultHandles: AuthorizedResourceHandle[] = [];
      const seenChunks = new Set<string>();
      let offset = 0;
      const pageSize = Math.min(200, Math.max(20, limit * 4));
      while (results.length < limit && offset < MAX_CANDIDATES_SCANNED) {
        if (params.signal?.aborted) {
          throw params.signal.reason ?? new Error("authorized memory search aborted");
        }
        const page = await candidatePageReader({
          database,
          query: params.query,
          ...(queryVector ? { queryVector } : {}),
          storeIds,
          sources,
          limit: pageSize,
          offset,
        });
        if (page.length === 0) {
          break;
        }
        offset += page.length;
        for (const candidate of page) {
          if (seenChunks.has(candidate.chunkId)) {
            continue;
          }
          seenChunks.add(candidate.chunkId);
          const snapshot = readScopedMemoryAuthorizedRevisionSnapshot({
            database,
            databasePath,
            context: params.context,
            planRecord,
            revisionId: candidate.revisionId,
            chunkId: candidate.chunkId,
            nowMs,
            readFile,
          });
          if (!snapshot?.chunk || !sources.includes(snapshot.source)) {
            continue;
          }
          const resourceHandle = issueHandle({
            context: params.context,
            plan: params.plan,
            snapshot,
          });
          snapshots.push(snapshot);
          resultHandles.push(resourceHandle);
          results.push(
            Object.freeze({
              path: snapshot.logicalLocator,
              startLine: snapshot.chunk.startLine,
              endLine: snapshot.chunk.endLine,
              score: candidate.score,
              ...(candidate.vectorScore !== undefined
                ? { vectorScore: candidate.vectorScore }
                : {}),
              ...(candidate.textScore !== undefined ? { textScore: candidate.textScore } : {}),
              snippet: snapshot.chunk.text,
              source: snapshot.source,
              citation: `${snapshot.logicalLocator}#L${snapshot.chunk.startLine}-L${snapshot.chunk.endLine}`,
              resourceHandle,
            }),
          );
          if (results.length >= limit) {
            break;
          }
        }
        if (page.length < pageSize) {
          break;
        }
      }
      const receipts = persistReceipts({
        database,
        context: params.context,
        plan: params.plan,
        snapshots,
        resourceHandles: resultHandles,
        nowMs,
      });
      return freezeEnvelope({
        value: Object.freeze(results),
        ...receipts,
      });
    });
  };

  const readAuthorized = async (params: {
    context: MemoryAccessContext;
    plan: AuthorizedMemoryPlan;
    handle: AuthorizedResourceHandle;
    from?: number;
    lines?: number;
  }): Promise<AuthorizedMemoryResultEnvelope<MemoryReadResult>> => {
    if (params.context.operation !== "read") {
      throw new Error("authorized memory read is unavailable");
    }
    const nowMs = now();
    return withScopedMemoryDatabase(params.context.agentId, (database, databasePath) => {
      const planRecord = validatePlan({
        database,
        context: params.context,
        plan: params.plan,
        nowMs,
      });
      const handleRecord = handles.get(params.handle.handleId);
      if (
        !handleRecord ||
        handleRecord.expiresAtMs <= nowMs ||
        handleRecord.planId !== params.plan.planId ||
        !equalScopedMemoryResourceHandle(params.handle, handleRecord.handle) ||
        handleRecord.revisionId !== params.handle.resourceRevision ||
        handleRecord.handle.contextFingerprint !== params.context.contextFingerprint ||
        handleRecord.handle.policyRevision !== params.plan.memoryPolicyRevision
      ) {
        throw new Error("authorized memory revision is unavailable");
      }
      const snapshot = readScopedMemoryAuthorizedRevisionSnapshot({
        database,
        databasePath,
        context: params.context,
        planRecord,
        revisionId: handleRecord.revisionId,
        nowMs,
        readFile,
      });
      if (!snapshot) {
        throw new Error("authorized memory revision is unavailable");
      }
      const from = Math.max(1, Math.trunc(params.from ?? 1));
      const lines = Math.max(1, Math.min(1_000, Math.trunc(params.lines ?? 50)));
      if (!Number.isFinite(from) || !Number.isFinite(lines)) {
        throw new Error("authorized memory read is unavailable");
      }
      const contentLines = snapshot.content.split(/\r?\n/u);
      const startIndex = from - 1;
      const selected = contentLines.slice(startIndex, startIndex + lines);
      const nextFrom =
        startIndex + selected.length < contentLines.length ? from + selected.length : undefined;
      const value = Object.freeze({
        text: selected.join("\n"),
        path: snapshot.logicalLocator,
        truncated: nextFrom !== undefined,
        from,
        lines: selected.length,
        ...(nextFrom !== undefined ? { nextFrom } : {}),
      });
      const receipts = persistReceipts({
        database,
        context: params.context,
        plan: params.plan,
        snapshots: [snapshot],
        resourceHandles: [params.handle],
        nowMs,
      });
      return freezeEnvelope({ value, ...receipts });
    });
  };

  return Object.freeze({ authorize, searchAuthorized, readAuthorized });
}
