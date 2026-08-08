import { randomBytes, randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type {
  AudienceRef,
  AuthorizedMemoryPlan,
  AuthorizedResourceHandle,
  MemoryAccessContext,
  MemoryEgressAuthorizationReceipt,
  MemoryExposureReceipt,
} from "openclaw/plugin-sdk/memory-authorization";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
  runSqliteImmediateTransactionSync,
} from "openclaw/plugin-sdk/sqlite-runtime";
import {
  assertScopedMemoryPlanBinding,
  createScopedMemoryAggregateRevision,
  createScopedMemoryPolicyRevision,
  equalScopedMemoryAuthorizedPlan,
  readScopedMemoryRevisionAuthorization,
  resolveScopedMemoryAuthorizedStores,
  type ScopedMemoryAuthorizedRevisionSnapshot,
  type ScopedMemoryMountRecord,
  type ScopedMemoryPlanRecord,
  type ScopedMemoryRevisionAuthorization,
} from "./scoped-memory-authorization.js";
import type { MemoryStoreRow, ScopedMemoryDatabase } from "./scoped-memory-db.js";
import {
  allocateOpaqueId,
  audienceKey,
  collectProjectionExposureAncestorRevisionIds,
  compareText,
  type HandleRecord,
  type OpaqueIdKind,
} from "./scoped-memory-runtime-primitives.js";

export function createScopedMemoryRuntimePlanOperations(dependencies: {
  plans: Map<string, ScopedMemoryPlanRecord>;
  handles: Map<string, HandleRecord>;
  now: () => number;
  maxPlans: number;
  maxHandles: number;
  generateOpaqueId?: (kind: OpaqueIdKind) => string;
}) {
  const { plans, handles, now, maxPlans, maxHandles } = dependencies;
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
      const ancestryRevisionIds = collectProjectionExposureAncestorRevisionIds({
        database: params.database,
        revisionIds: exposedResourceRevisions,
      });
      if (ancestryRevisionIds.length > 0) {
        const projections = executeSqliteQuerySync(
          params.database,
          db
            .selectFrom("memory_projections as projection")
            .innerJoin(
              "memory_resource_revisions as target_revision",
              "target_revision.revision_id",
              "projection.target_revision_id",
            )
            .innerJoin(
              "memory_resources as target_resource",
              "target_resource.resource_id",
              "target_revision.resource_id",
            )
            .select("projection.projection_id")
            .where("projection.target_revision_id", "in", ancestryRevisionIds)
            .where("projection.agent_id", "=", params.context.agentId)
            .where("projection.target_agent_id", "=", params.context.agentId)
            .where("projection.review_state", "=", "approved")
            .where("projection.expires_at", ">", params.nowMs)
            .where("target_revision.lifecycle_state", "=", "active")
            .where("target_resource.agent_id", "=", params.context.agentId)
            .whereRef("target_resource.resource_id", "=", "projection.target_resource_id")
            .whereRef("target_resource.store_id", "=", "projection.target_store_id")
            .orderBy("projection.projection_id"),
        ).rows;
        if (projections.length > 0) {
          executeSqliteQuerySync(
            params.database,
            db.insertInto("memory_projection_exposures").values(
              projections.map((projection) => ({
                projection_id: projection.projection_id,
                exposure_receipt_id: exposureReceiptId,
                recorded_at: params.nowMs,
              })),
            ),
          );
        }
      }
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

  const selectDefaultMutationMount = (params: {
    context: MemoryAccessContext;
    planRecord: ScopedMemoryPlanRecord;
  }): ScopedMemoryMountRecord => {
    const subjectAudience =
      params.context.subject.kind === "user"
        ? { kind: "user" as const, id: params.context.subject.principalId }
        : params.context.subject.kind === "conversation"
          ? {
              kind: "conversation" as const,
              id: params.context.subject.conversationPrincipalId,
            }
          : params.context.subject.kind === "service" ||
              params.context.subject.kind === "agent" ||
              params.context.subject.kind === "system"
            ? { kind: "agent" as const, id: params.context.subject.principalId }
            : undefined;
    if (!subjectAudience) {
      throw new Error("authorized memory mutation is unavailable");
    }
    const mount = params.planRecord.mounts.find(
      (entry) =>
        entry.store.audience_kind === subjectAudience.kind &&
        entry.store.audience_id === subjectAudience.id,
    );
    if (!mount) {
      throw new Error("authorized memory mutation is unavailable");
    }
    return mount;
  };

  const assertSubjectDefaultMutationTarget = (params: {
    mount: ScopedMemoryMountRecord;
    target: ScopedMemoryRevisionAuthorization;
  }): void => {
    // A handle proves a revision is readable; it must not select a different
    // write audience. Ordinary mutations stay in the session-subject store.
    if (params.target.storeId !== params.mount.store.store_id) {
      throw new Error("authorized memory mutation placement is unavailable");
    }
  };

  const assertMutationTargetIsNotProjectionCopy = (params: {
    database: DatabaseSync;
    agentId: string;
    resourceId: string;
  }): void => {
    const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
    const projection = executeSqliteQueryTakeFirstSync(
      params.database,
      db
        .selectFrom("memory_projections")
        .select("projection_id")
        .where("agent_id", "=", params.agentId)
        .where("target_resource_id", "=", params.resourceId)
        .limit(1),
    );
    // A projection copy must remain bound to its review lifecycle. Revising or
    // tombstoning its resource would create an unreviewed successor or evade it.
    if (projection) {
      throw new Error("authorized memory mutation placement is unavailable");
    }
  };

  const readMutationStoreRoot = (params: {
    database: DatabaseSync;
    agentId: string;
    mount: ScopedMemoryMountRecord;
  }): { pathKey: string; store: MemoryStoreRow } => {
    const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
    const row = executeSqliteQueryTakeFirstSync(
      params.database,
      db
        .selectFrom("memory_stores as store")
        .innerJoin("memory_storage_roots as root", "root.storage_root_id", "store.storage_root_id")
        .innerJoin("memory_policies as policy", "policy.policy_id", "store.policy_id")
        .selectAll("store")
        .select(["root.path_key", "policy.current_revision_id", "policy.revocation_epoch"])
        .where("store.store_id", "=", params.mount.store.store_id)
        .where("store.agent_id", "=", params.agentId)
        .where("store.lifecycle_state", "=", "active")
        .where("root.agent_id", "=", params.agentId)
        .where("root.backend_kind", "=", "builtin")
        .where("root.lifecycle_state", "=", "active")
        .where("policy.agent_id", "=", params.agentId)
        .where("policy.lifecycle_state", "=", "active"),
    );
    if (
      !row?.path_key ||
      row.current_revision_id !== params.mount.policyRevisionId ||
      row.revocation_epoch !== params.mount.policyRevocationEpoch
    ) {
      throw new Error("authorized memory store is unavailable");
    }
    return {
      pathKey: row.path_key,
      store: {
        store_id: row.store_id,
        agent_id: row.agent_id,
        storage_root_id: row.storage_root_id,
        policy_id: row.policy_id,
        scope_kind: row.scope_kind,
        audience_kind: row.audience_kind,
        audience_id: row.audience_id,
        lifecycle_state: row.lifecycle_state,
        created_at: row.created_at,
        updated_at: row.updated_at,
      },
    };
  };

  const findCommittedIdempotency = (params: {
    database: DatabaseSync;
    agentId: string;
    idempotencyKey: string;
  }) => {
    const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
    return executeSqliteQueryTakeFirstSync(
      params.database,
      db
        .selectFrom("memory_write_intents")
        .select(["mutation_id", "state", "pending_revision_id", "updated_at"])
        .where("agent_id", "=", params.agentId)
        .where("idempotency_key", "=", params.idempotencyKey),
    );
  };
  return Object.freeze({
    purgeExpired,
    validatePlan,
    issueHandle,
    persistReceipts,
    selectDefaultMutationMount,
    assertSubjectDefaultMutationTarget,
    assertMutationTargetIsNotProjectionCopy,
    readMutationStoreRoot,
    findCommittedIdempotency,
  });
}
