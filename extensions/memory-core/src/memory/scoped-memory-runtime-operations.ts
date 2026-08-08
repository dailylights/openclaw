import { randomUUID } from "node:crypto";
import fs from "node:fs";
import type { DatabaseSync } from "node:sqlite";
import type {
  AuthorizedMemoryPlan,
  AuthorizedMemoryResultEnvelope,
  AuthorizedMemorySearchResult,
  AuthorizedResourceHandle,
  MemoryAccessContext,
  MemoryEgressAuthorizationReceipt,
  MemoryExportResult,
  MemoryExposureReceipt,
  MemorySyncResult,
  PreparedMemoryTranscriptPolicy,
} from "openclaw/plugin-sdk/memory-authorization";
import type {
  MemoryProviderStatus,
  MemoryReadResult,
  MemorySource,
} from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import { normalizeAgentId } from "openclaw/plugin-sdk/routing";
import {
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
} from "openclaw/plugin-sdk/sqlite-runtime";
import {
  createScopedMemoryAggregateRevision,
  createScopedMemoryPolicyRevision,
  equalScopedMemoryResourceHandle,
  readScopedMemoryAuthorizedRevisionSnapshot,
  resolveScopedMemoryAuthorizedStores,
  type ScopedMemoryAuthorizedRevisionSnapshot,
  type ScopedMemoryMountRecord,
  type ScopedMemoryPlanRecord,
  type ScopedMemoryRevisionAuthorization,
} from "./scoped-memory-authorization.js";
import type { ScopedMemoryCandidatePageReader } from "./scoped-memory-candidates.js";
import type { ScopedMemoryDatabase } from "./scoped-memory-db.js";
import { withScopedMemoryDatabase } from "./scoped-memory-db.js";
import { resolveBuiltinScopedMemoryArtifactPath } from "./scoped-memory-resource-artifacts.js";
import {
  allocateOpaqueId,
  audienceKey,
  compareText,
  earliestContextExpiry,
  freezeEnvelope,
  MAX_CANDIDATES_SCANNED,
  MAX_SEARCH_RESULTS,
  normalizeSources,
  PLAN_TTL_MS,
  readVerifiedArtifact,
  type BuiltinScopedMemoryRuntimeDependencies,
  type HandleRecord,
} from "./scoped-memory-runtime-primitives.js";

type ScopedMemoryRuntimeOperationDependencies = Readonly<{
  dependencies: Pick<BuiltinScopedMemoryRuntimeDependencies, "embedQuery" | "generateOpaqueId">;
  plans: Map<string, ScopedMemoryPlanRecord>;
  handles: Map<string, HandleRecord>;
  now: () => number;
  readFile: typeof fs.readFileSync;
  candidatePageReader: ScopedMemoryCandidatePageReader;
  purgeExpired: (nowMs: number) => void;
  validatePlan: (params: {
    database: DatabaseSync;
    context: MemoryAccessContext;
    plan: AuthorizedMemoryPlan;
    nowMs: number;
  }) => ScopedMemoryPlanRecord;
  issueHandle: (params: {
    context: MemoryAccessContext;
    plan: AuthorizedMemoryPlan;
    snapshot: ScopedMemoryAuthorizedRevisionSnapshot;
  }) => AuthorizedResourceHandle;
  persistReceipts: (params: {
    database: DatabaseSync;
    context: MemoryAccessContext;
    plan: AuthorizedMemoryPlan;
    snapshots: readonly ScopedMemoryAuthorizedRevisionSnapshot[];
    resourceHandles: readonly AuthorizedResourceHandle[];
    nowMs: number;
  }) => Readonly<{
    exposureReceipt: MemoryExposureReceipt;
    egressReceipt: MemoryEgressAuthorizationReceipt;
  }>;
  recoverPendingWrites: (agentId: string) => void;
  assertMutationHandle: (params: {
    database: DatabaseSync;
    context: MemoryAccessContext;
    plan: AuthorizedMemoryPlan;
    planRecord: ScopedMemoryPlanRecord;
    handle: AuthorizedResourceHandle;
    nowMs: number;
  }) => ScopedMemoryRevisionAuthorization;
}>;

export function createScopedMemoryRuntimeOperations(
  dependencies: ScopedMemoryRuntimeOperationDependencies,
) {
  const {
    dependencies: runtimeDependencies,
    plans,
    handles,
    now,
    readFile,
    candidatePageReader,
    purgeExpired,
    validatePlan,
    issueHandle,
    persistReceipts,
    recoverPendingWrites,
    assertMutationHandle,
  } = dependencies;
  const syncAuthorized = async (params: {
    context: MemoryAccessContext;
    plan: AuthorizedMemoryPlan;
  }): Promise<AuthorizedMemoryResultEnvelope<MemorySyncResult>> => {
    if (params.context.operation !== "sync") {
      throw new Error("authorized memory sync is unavailable");
    }
    const agentId = normalizeAgentId(params.context.agentId);
    recoverPendingWrites(agentId);
    const nowMs = now();
    return withScopedMemoryDatabase(agentId, (database) => {
      validatePlan({ database, context: params.context, plan: params.plan, nowMs });
      const receipts = persistReceipts({
        database,
        context: params.context,
        plan: params.plan,
        snapshots: [],
        resourceHandles: [],
        nowMs,
      });
      return freezeEnvelope({
        value: Object.freeze({
          version: 1,
          status: "completed",
          synchronizedHandles: Object.freeze([]),
        }),
        ...receipts,
      });
    });
  };

  const exportAuthorized = async (params: {
    context: MemoryAccessContext;
    plan: AuthorizedMemoryPlan;
    handles: readonly AuthorizedResourceHandle[];
  }): Promise<AuthorizedMemoryResultEnvelope<MemoryExportResult>> => {
    if (params.context.operation !== "export") {
      throw new Error("authorized memory export is unavailable");
    }
    const nowMs = now();
    return withScopedMemoryDatabase(params.context.agentId, (database, databasePath) => {
      const planRecord = validatePlan({
        database,
        context: params.context,
        plan: params.plan,
        nowMs,
      });
      const snapshots = params.handles.map((handle) => {
        const authorization = assertMutationHandle({
          database,
          context: params.context,
          plan: params.plan,
          planRecord,
          handle,
          nowMs,
        });
        const content = readVerifiedArtifact({
          pathname: resolveBuiltinScopedMemoryArtifactPath({
            databasePath,
            pathKey: authorization.pathKey,
            artifactLocator: authorization.artifactLocator,
          }),
          expectedHash: authorization.contentHash,
          expectedBytes: authorization.contentBytes,
        });
        if (content === undefined) {
          throw new Error("authorized memory revision is unavailable");
        }
        return { ...authorization, content };
      });
      const receipts = persistReceipts({
        database,
        context: params.context,
        plan: params.plan,
        snapshots,
        resourceHandles: params.handles,
        nowMs,
      });
      return freezeEnvelope({
        value: Object.freeze({
          version: 1,
          exportId: randomUUID(),
          contentType: "application/json",
          encoding: "utf8",
          payload: JSON.stringify(
            snapshots.map((snapshot) => ({
              revisionId: snapshot.revisionId,
              content: snapshot.content,
            })),
          ),
          exportedHandles: Object.freeze([...params.handles]),
        }),
        ...receipts,
      });
    });
  };

  const statusAuthorized = async (params: {
    context: MemoryAccessContext;
    plan: AuthorizedMemoryPlan;
  }): Promise<AuthorizedMemoryResultEnvelope<MemoryProviderStatus>> => {
    if (params.context.operation !== "status") {
      throw new Error("authorized memory status is unavailable");
    }
    const nowMs = now();
    return withScopedMemoryDatabase(params.context.agentId, (database) => {
      const planRecord = validatePlan({
        database,
        context: params.context,
        plan: params.plan,
        nowMs,
      });
      const db = getNodeSqliteKysely<ScopedMemoryDatabase>(database);
      const authorizedStoreIds = planRecord.mounts.map((mount) => mount.store.store_id);
      // Status is still a memory exposure: do not let aggregate counts reveal a
      // private store that this operation did not mount for the caller.
      const counts =
        authorizedStoreIds.length === 0
          ? undefined
          : executeSqliteQueryTakeFirstSync(
              database,
              db
                .selectFrom("memory_resource_revisions as revision")
                .innerJoin(
                  "memory_resources as resource",
                  "resource.resource_id",
                  "revision.resource_id",
                )
                .select(({ fn }) => [
                  fn.count<string>("revision.revision_id").as("files"),
                  fn.count<string>("resource.resource_id").as("resources"),
                ])
                .where("resource.agent_id", "=", params.context.agentId)
                .where("resource.store_id", "in", authorizedStoreIds)
                .where("revision.lifecycle_state", "=", "active"),
            );
      const receipts = persistReceipts({
        database,
        context: params.context,
        plan: params.plan,
        snapshots: [],
        resourceHandles: [],
        nowMs,
      });
      return freezeEnvelope({
        value: Object.freeze({
          backend: "builtin" as const,
          provider: "scoped-memory",
          files: Number(counts?.files ?? 0),
          chunks: 0,
          custom: { mounts: planRecord.mounts.length, resources: Number(counts?.resources ?? 0) },
        }),
        ...receipts,
      });
    });
  };

  /**
   * Materialize the stable policy facts before core starts its transcript
   * transaction. The payload contains no store paths or ACL entries, only the
   * immutable identifiers core needs to fail closed on later revocation.
   */
  const prepareTranscriptPolicy = async (params: {
    context: MemoryAccessContext;
    plan: AuthorizedMemoryPlan;
    sourcePolicySetIds: readonly string[];
    policySetId: string;
  }): Promise<PreparedMemoryTranscriptPolicy> => {
    const nowMs = now();
    const sourcePolicySetIds = [...new Set(params.sourcePolicySetIds)].toSorted(compareText);
    if (
      !params.policySetId.trim() ||
      sourcePolicySetIds.some((policySetId) => !policySetId.trim())
    ) {
      throw new Error("authorized transcript policy is unavailable");
    }
    return withScopedMemoryDatabase(params.context.agentId, (database) => {
      const planRecord = validatePlan({
        database,
        context: params.context,
        plan: params.plan,
        nowMs,
      });
      const requirements = planRecord.mounts
        .map((mount) =>
          Object.freeze({
            stablePolicyId: mount.policyId,
            capturedRevisionId: mount.policyRevisionId,
            expectedActiveRevisionId: mount.policyRevisionId,
            expectedRevocationEpoch: mount.policyRevocationEpoch,
          }),
        )
        .toSorted((left, right) => compareText(left.stablePolicyId, right.stablePolicyId));
      if (
        requirements.some(
          (requirement, index) =>
            index > 0 && requirement.stablePolicyId === requirements[index - 1]?.stablePolicyId,
        )
      ) {
        throw new Error("authorized transcript policy is unavailable");
      }
      const audiences = [...params.plan.allowedEgressAudiences].toSorted((left, right) =>
        compareText(audienceKey(left), audienceKey(right)),
      );
      const policySetRevision = createScopedMemoryAggregateRevision("mpsr1", [
        params.policySetId,
        ...sourcePolicySetIds,
        ...requirements.map(
          (requirement) =>
            `${requirement.stablePolicyId}\0${requirement.capturedRevisionId}\0${requirement.expectedActiveRevisionId}\0${requirement.expectedRevocationEpoch}`,
        ),
        ...audiences.map((audience) => audienceKey(audience)),
      ]);
      return Object.freeze({
        version: 1 as const,
        policySetId: params.policySetId,
        policySetRevision,
        sourcePolicySetIds: Object.freeze(sourcePolicySetIds),
        normalizedAudienceIntersection: Object.freeze(audiences),
        requirements: Object.freeze(requirements),
        retentionState: "active" as const,
      });
    });
  };

  const authorize = async (context: MemoryAccessContext): Promise<AuthorizedMemoryPlan> => {
    const agentId = normalizeAgentId(context.agentId);
    if (context.version !== 1 || agentId !== context.agentId) {
      throw new Error("authorized memory context is unavailable");
    }
    recoverPendingWrites(agentId);
    const nowMs = now();
    purgeExpired(nowMs);
    const planId = allocateOpaqueId({
      kind: "plan",
      occupied: (candidate) => plans.has(candidate),
      generate: runtimeDependencies.generateOpaqueId,
    });
    return withScopedMemoryDatabase(agentId, (database) => {
      const stores = resolveScopedMemoryAuthorizedStores({ database, context, nowMs });
      const occupiedMounts = new Set<string>();
      const mounts: ScopedMemoryMountRecord[] = stores.map((store) => {
        const mountHandle = allocateOpaqueId({
          kind: "mount",
          occupied: (candidate) => occupiedMounts.has(candidate),
          generate: runtimeDependencies.generateOpaqueId,
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
              virtualRoot: mount.virtualRoot,
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
    const queryVector = runtimeDependencies.embedQuery
      ? [...(await runtimeDependencies.embedQuery(params.query))]
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
          const mount = planRecord.mounts.find(
            (entry) => entry.store.store_id === snapshot.storeId,
          );
          if (!mount) {
            throw new Error("authorized memory mount is unavailable");
          }
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
              mountHandle: mount.mountHandle,
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
  return Object.freeze({
    syncAuthorized,
    exportAuthorized,
    statusAuthorized,
    prepareTranscriptPolicy,
    authorize,
    searchAuthorized,
    readAuthorized,
  });
}
