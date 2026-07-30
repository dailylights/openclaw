import { createHash, randomBytes, randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import type {
  AudienceRef,
  AuthorizedMemoryPlan,
  AuthorizedMemoryMutation,
  AuthorizedMemoryResultEnvelope,
  AuthorizedMemorySearchResult,
  AuthorizedResourceHandle,
  DeepReadonly,
  MemoryAccessContext,
  MemoryEgressAuthorizationReceipt,
  MemoryExposureReceipt,
  MemoryExportResult,
  MemorySyncResult,
  PreparedMemoryTranscriptPolicy,
  MemoryWriteResult,
} from "openclaw/plugin-sdk/memory-authorization";
import type {
  MemoryProviderStatus,
  MemoryReadResult,
  MemorySource,
} from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import { normalizeAgentId } from "openclaw/plugin-sdk/routing";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
  runSqliteImmediateTransactionSync,
  writeMemoryAccessAudit,
} from "openclaw/plugin-sdk/sqlite-runtime";
import {
  assertScopedMemoryPlanBinding,
  createScopedMemoryAggregateRevision,
  createScopedMemoryPolicyRevision,
  equalScopedMemoryAuthorizedPlan,
  equalScopedMemoryResourceHandle,
  readScopedMemoryAuthorizedRevisionSnapshot,
  readScopedMemoryRevisionPolicyRequirements,
  readScopedMemoryRevisionAuthorization,
  resolveScopedMemoryAuthorizedStores,
  type ScopedMemoryAuthorizedRevisionSnapshot,
  type ScopedMemoryMountRecord,
  type ScopedMemoryPlanRecord,
  type ScopedMemoryRevisionPolicyRequirement,
  type ScopedMemoryRevisionAuthorization,
} from "./scoped-memory-authorization.js";
import {
  readScopedMemoryFtsCandidatePage,
  type ScopedMemoryCandidatePageReader,
} from "./scoped-memory-candidates.js";
import {
  type MemoryStoreRow,
  type ScopedMemoryDatabase,
  withScopedMemoryDatabase,
} from "./scoped-memory-db.js";
import { resolveBuiltinScopedMemoryArtifactPath } from "./scoped-memory-resources.js";
import { createScopedMemorySourcePolicySetId } from "./scoped-memory-store.js";

const PLAN_TTL_MS = 5 * 60_000;
const DEFAULT_MAX_PLANS = 1_024;
const DEFAULT_MAX_HANDLES = 8_192;
const OPAQUE_ID_ATTEMPTS = 8;
const MAX_SEARCH_RESULTS = 100;
const MAX_CANDIDATES_SCANNED = 10_000;
const SCOPED_CHUNK_MAX_LINES = 40;
const SCOPED_CHUNK_MAX_CHARS = 4_000;
const STAGED_ARTIFACT_PATTERN = /^mwst1_[A-Za-z0-9_-]{18,}\.tmp$/u;
const CALLER_SELECTED_MUTATION_DESTINATION_FIELDS = [
  "artifactLocator",
  "audience",
  "audienceId",
  "destinationAudience",
  "destinationHandle",
  "destinationOwnerId",
  "destinationStoreId",
  "logicalLocator",
  "owner",
  "ownerId",
  "path",
  "placementHandle",
  "root",
  "rootId",
  "store",
  "storeId",
] as const;

type OpaqueIdKind = "plan" | "mount" | "resource" | "intent" | "stage";

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
  /** Test-only interruption hook. It is called only between lifecycle transactions. */
  onMutationPhase?: (phase: "staged" | "pending" | "renamed" | "activated" | "indexed") => void;
}>;

function createOpaqueId(kind: OpaqueIdKind): string {
  const prefix =
    kind === "plan"
      ? "mp1"
      : kind === "mount"
        ? "mm1"
        : kind === "resource"
          ? "mrh1"
          : kind === "intent"
            ? "mwi1"
            : "mwst1";
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

type MemoryLineageEdgeKind = "revision" | "derive" | "project" | "publish";

function mergeRevisionPolicyRequirements(
  requirements: readonly ScopedMemoryRevisionPolicyRequirement[],
): ScopedMemoryRevisionPolicyRequirement[] {
  const byPolicyId = new Map<string, ScopedMemoryRevisionPolicyRequirement>();
  for (const requirement of requirements) {
    const existing = byPolicyId.get(requirement.stablePolicyId);
    if (
      existing &&
      (existing.capturedRevisionId !== requirement.capturedRevisionId ||
        existing.expectedActiveRevisionId !== requirement.expectedActiveRevisionId ||
        existing.expectedRevocationEpoch !== requirement.expectedRevocationEpoch)
    ) {
      throw new Error("authorized memory mutation source policy is unavailable");
    }
    byPolicyId.set(requirement.stablePolicyId, requirement);
  }
  return [...byPolicyId.values()].toSorted((left, right) =>
    compareText(left.stablePolicyId, right.stablePolicyId),
  );
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

function hashText(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function createFinalArtifactLocator(): string {
  return `r1_${randomBytes(18).toString("base64url")}.md`;
}

function createStagedArtifactLocator(): string {
  return `mwst1_${randomBytes(18).toString("base64url")}.tmp`;
}

function resolveScopedArtifactChild(base: string, locator: string, pattern: RegExp): string {
  if (!pattern.test(locator)) {
    throw new Error("scoped-memory artifact locator is invalid");
  }
  const resolvedBase = path.resolve(base);
  const resolved = path.resolve(resolvedBase, locator);
  if (path.dirname(resolved) !== resolvedBase || path.basename(resolved) !== locator) {
    throw new Error("scoped-memory artifact locator escaped its storage root");
  }
  return resolved;
}

function syncDirectory(directory: string): void {
  try {
    const descriptor = fs.openSync(directory, "r");
    try {
      fs.fsyncSync(descriptor);
    } finally {
      fs.closeSync(descriptor);
    }
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    // Windows cannot fsync directories. The staged file itself is always fsynced
    // before rename, so this is the narrow platform capability exception.
    if (code !== "EINVAL" && code !== "EPERM" && code !== "EISDIR") {
      throw error;
    }
  }
}

function writeStagedArtifact(params: {
  directory: string;
  locator: string;
  content: string;
}): string {
  const pathname = resolveScopedArtifactChild(
    params.directory,
    params.locator,
    STAGED_ARTIFACT_PATTERN,
  );
  const descriptor = fs.openSync(pathname, "wx", 0o600);
  try {
    fs.writeFileSync(descriptor, params.content, "utf8");
    fs.fchmodSync(descriptor, 0o600);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  syncDirectory(params.directory);
  return pathname;
}

function readVerifiedArtifact(params: {
  pathname: string;
  expectedHash: string;
  expectedBytes: number;
}): string | undefined {
  try {
    const content = fs.readFileSync(params.pathname, "utf8");
    return Buffer.byteLength(content) === params.expectedBytes &&
      hashText(content) === params.expectedHash
      ? content
      : undefined;
  } catch {
    return undefined;
  }
}

function quarantineArtifact(pathname: string): void {
  try {
    const storeDirectory = path.dirname(pathname);
    const quarantineDirectory = path.join(path.dirname(storeDirectory), ".quarantine");
    fs.mkdirSync(quarantineDirectory, { recursive: true, mode: 0o700 });
    fs.chmodSync(quarantineDirectory, 0o700);
    fs.renameSync(pathname, path.join(quarantineDirectory, `orphan_${randomUUID()}`));
    syncDirectory(quarantineDirectory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
  }
}

function chunkContent(content: string): Array<{
  ordinal: number;
  startLine: number;
  endLine: number;
  text: string;
}> {
  const lines = content.split(/\r?\n/u);
  const chunks: Array<{ ordinal: number; startLine: number; endLine: number; text: string }> = [];
  let start = 0;
  while (start < lines.length) {
    let end = start;
    let chars = 0;
    while (end < lines.length && end - start < SCOPED_CHUNK_MAX_LINES) {
      const nextChars = chars + (lines[end]?.length ?? 0) + (end === start ? 0 : 1);
      if (end > start && nextChars > SCOPED_CHUNK_MAX_CHARS) {
        break;
      }
      chars = nextChars;
      end += 1;
    }
    chunks.push({
      ordinal: chunks.length,
      startLine: start + 1,
      endLine: Math.max(start + 1, end),
      text: lines.slice(start, end).join("\n"),
    });
    start = end;
  }
  return chunks;
}

function mutationOperation(mutation: AuthorizedMemoryMutation): MemoryAccessContext["operation"] {
  switch (mutation.kind) {
    case "remember":
    case "append":
      return "append";
    case "replace":
      return "replace";
    case "derive":
      return "derive";
    case "deposit":
      return "deposit";
    case "project":
      return "project";
    case "publish":
      return "publish";
    case "import":
      return "import";
    case "delete":
    case "tombstone":
      return "delete";
    case "admin-reclassify":
      return "policy-admin";
  }
}

function actorRef(context: MemoryAccessContext): string {
  const value =
    context.actor.kind === "principal"
      ? `${context.actor.actorKind}\0${context.actor.principalId}\0${context.actor.evidenceRevision}`
      : `unattributed\0${context.actor.transportAuditRef}\0${context.actor.evidenceRevision}`;
  return `sha256:${hashText(value)}`;
}

function subjectRef(context: MemoryAccessContext): string {
  return `sha256:${hashText(JSON.stringify(context.subject))}`;
}

function actorRecord(context: MemoryAccessContext): {
  kind: "human" | "agent" | "service" | "system" | "unattributed";
  id: string | null;
} {
  if (context.actor.kind === "unattributed") {
    return { kind: "unattributed", id: null };
  }
  return { kind: context.actor.actorKind, id: context.actor.principalId };
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

  const finalizeAuditOutbox = (params: {
    database: DatabaseSync;
    intentId: string;
    decision: "committed" | "quarantined" | "tombstoned";
    reasonCode: string;
    nowMs: number;
  }): void => {
    const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
    executeSqliteQuerySync(
      params.database,
      db
        .updateTable("memory_audit_outbox")
        .set({
          decision: params.decision,
          reason_code: params.reasonCode,
          updated_at: params.nowMs,
        })
        .where("intent_id", "=", params.intentId)
        .where("state", "=", "pending"),
    );
  };

  const drainAuditOutbox = (agentId: string): void => {
    try {
      withScopedMemoryDatabase(agentId, (database) => {
        const local = getNodeSqliteKysely<ScopedMemoryDatabase>(database);
        const pending = executeSqliteQuerySync(
          database,
          local
            .selectFrom("memory_audit_outbox")
            .selectAll()
            .where("agent_id", "=", agentId)
            .where("state", "=", "pending")
            .orderBy("created_at")
            .orderBy("event_id")
            .limit(100),
        ).rows;
        for (const event of pending) {
          try {
            writeMemoryAccessAudit({
              eventId: event.event_id,
              agentId: event.agent_id,
              requestId: event.request_id,
              runId: event.run_id,
              actorRef: event.actor_ref,
              subjectRef: event.subject_ref,
              operation: event.operation,
              decision: event.decision === "pending" ? "quarantined" : event.decision,
              reasonCode: event.reason_code,
              resourceRevisionId: event.resource_revision_id,
              contentHash: event.content_hash,
              occurredAt: event.created_at,
              receivedAt: now(),
            });
            runSqliteImmediateTransactionSync(database, () => {
              executeSqliteQuerySync(
                database,
                local
                  .updateTable("memory_audit_outbox")
                  .set({
                    state: "delivered",
                    delivered_at: now(),
                    attempts: event.attempts + 1,
                    updated_at: now(),
                  })
                  .where("event_id", "=", event.event_id)
                  .where("state", "=", "pending"),
              );
            });
          } catch {
            runSqliteImmediateTransactionSync(database, () => {
              executeSqliteQuerySync(
                database,
                local
                  .updateTable("memory_audit_outbox")
                  .set({ attempts: event.attempts + 1, updated_at: now() })
                  .where("event_id", "=", event.event_id)
                  .where("state", "=", "pending"),
              );
            });
          }
        }
      });
    } catch {
      // Audit delivery is deliberately not an authorization dependency.
    }
  };

  const activatePendingIntent = (params: {
    database: DatabaseSync;
    agentId: string;
    intentId: string;
    revisionId: string;
    nowMs: number;
    revalidate?: () => void;
  }): boolean => {
    const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
    let activated = false;
    runSqliteImmediateTransactionSync(params.database, () => {
      params.revalidate?.();
      const pending = executeSqliteQueryTakeFirstSync(
        params.database,
        db
          .selectFrom("memory_write_intents as intent")
          .innerJoin(
            "memory_resource_revisions as revision",
            "revision.revision_id",
            "intent.pending_revision_id",
          )
          .innerJoin("memory_resources as resource", "resource.resource_id", "revision.resource_id")
          .innerJoin("memory_stores as store", "store.store_id", "resource.store_id")
          .innerJoin("memory_policies as policy", "policy.policy_id", "store.policy_id")
          .select([
            "intent.state as intent_state",
            "revision.lifecycle_state as revision_state",
            "revision.resource_id",
            "revision.policy_revision_id",
            "revision.policy_revocation_epoch",
            "policy.current_revision_id",
            "policy.revocation_epoch",
            "policy.lifecycle_state as policy_state",
            "store.lifecycle_state as store_state",
          ])
          .where("intent.intent_id", "=", params.intentId)
          .where("intent.agent_id", "=", params.agentId)
          .where("revision.revision_id", "=", params.revisionId)
          .where("resource.agent_id", "=", params.agentId)
          .where("store.agent_id", "=", params.agentId)
          .where("policy.agent_id", "=", params.agentId),
      );
      if (!pending) {
        throw new Error("authorized memory write intent is unavailable");
      }
      if (pending.intent_state === "active" && pending.revision_state === "active") {
        activated = true;
        return;
      }
      if (pending.intent_state !== "pending" && pending.intent_state !== "renamed") {
        return;
      }
      if (
        pending.revision_state !== "pending" ||
        pending.store_state !== "active" ||
        pending.policy_state !== "active" ||
        pending.current_revision_id !== pending.policy_revision_id ||
        pending.revocation_epoch !== pending.policy_revocation_epoch
      ) {
        executeSqliteQuerySync(
          params.database,
          db
            .updateTable("memory_resource_revisions")
            .set({ lifecycle_state: "quarantined" })
            .where("revision_id", "=", params.revisionId)
            .where("lifecycle_state", "=", "pending"),
        );
        executeSqliteQuerySync(
          params.database,
          db
            .updateTable("memory_write_intents")
            .set({ state: "quarantined", updated_at: params.nowMs })
            .where("intent_id", "=", params.intentId),
        );
        finalizeAuditOutbox({
          database: params.database,
          intentId: params.intentId,
          decision: "quarantined",
          reasonCode: "policy-revalidated-failed",
          nowMs: params.nowMs,
        });
        return;
      }
      const activeRows = executeSqliteQuerySync(
        params.database,
        db
          .selectFrom("memory_resource_revisions")
          .select("revision_id")
          .where("resource_id", "=", pending.resource_id)
          .where("lifecycle_state", "=", "active")
          .where("revision_id", "!=", params.revisionId),
      ).rows;
      for (const active of activeRows) {
        executeSqliteQuerySync(
          params.database,
          db.deleteFrom("memory_scoped_chunks").where("revision_id", "=", active.revision_id),
        );
      }
      executeSqliteQuerySync(
        params.database,
        db
          .updateTable("memory_resource_revisions")
          .set({ lifecycle_state: "tombstoned", retired_at: params.nowMs })
          .where("resource_id", "=", pending.resource_id)
          .where("lifecycle_state", "=", "active")
          .where("revision_id", "!=", params.revisionId),
      );
      const updated = executeSqliteQuerySync(
        params.database,
        db
          .updateTable("memory_resource_revisions")
          .set({ lifecycle_state: "active", activated_at: params.nowMs })
          .where("revision_id", "=", params.revisionId)
          .where("lifecycle_state", "=", "pending"),
      );
      if (updated.numAffectedRows !== 1n) {
        throw new Error("authorized memory revision is unavailable");
      }
      executeSqliteQuerySync(
        params.database,
        db
          .updateTable("memory_write_intents")
          .set({ state: "active", activated_at: params.nowMs, updated_at: params.nowMs })
          .where("intent_id", "=", params.intentId),
      );
      finalizeAuditOutbox({
        database: params.database,
        intentId: params.intentId,
        decision: "committed",
        reasonCode: "authorized-write-activated",
        nowMs: params.nowMs,
      });
      activated = true;
    });
    return activated;
  };

  const indexActiveIntent = (params: {
    database: DatabaseSync;
    agentId: string;
    intentId: string;
    revisionId: string;
    content: string;
    nowMs: number;
    revalidate?: () => void;
  }): boolean => {
    const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
    let indexed = false;
    const chunks = chunkContent(params.content);
    runSqliteImmediateTransactionSync(params.database, () => {
      params.revalidate?.();
      const current = executeSqliteQueryTakeFirstSync(
        params.database,
        db
          .selectFrom("memory_write_intents as intent")
          .innerJoin(
            "memory_resource_revisions as revision",
            "revision.revision_id",
            "intent.pending_revision_id",
          )
          .innerJoin("memory_resources as resource", "resource.resource_id", "revision.resource_id")
          .select(["intent.state", "intent.indexed_at", "revision.lifecycle_state"])
          .where("intent.intent_id", "=", params.intentId)
          .where("intent.agent_id", "=", params.agentId)
          .where("revision.revision_id", "=", params.revisionId)
          .where("resource.agent_id", "=", params.agentId),
      );
      if (!current || current.state !== "active" || current.lifecycle_state !== "active") {
        return;
      }
      if (current.indexed_at !== null) {
        indexed = true;
        return;
      }
      const existing = executeSqliteQueryTakeFirstSync(
        params.database,
        db
          .selectFrom("memory_scoped_chunks")
          .select("chunk_id")
          .where("revision_id", "=", params.revisionId)
          .limit(1),
      );
      if (existing) {
        throw new Error("active scoped-memory revision has an untracked index");
      }
      executeSqliteQuerySync(
        params.database,
        db.insertInto("memory_scoped_chunks").values(
          chunks.map((chunk) => ({
            chunk_id: randomUUID(),
            revision_id: params.revisionId,
            chunk_ordinal: chunk.ordinal,
            start_line: chunk.startLine,
            end_line: chunk.endLine,
            text: chunk.text,
            content_hash: hashText(chunk.text),
            model: "builtin-markdown-v1",
            updated_at: params.nowMs,
          })),
        ),
      );
      executeSqliteQuerySync(
        params.database,
        db
          .updateTable("memory_write_intents")
          .set({ indexed_at: params.nowMs, updated_at: params.nowMs })
          .where("intent_id", "=", params.intentId)
          .where("indexed_at", "is", null),
      );
      indexed = true;
    });
    return indexed;
  };

  const assertMutationHandle = (params: {
    database: DatabaseSync;
    context: MemoryAccessContext;
    plan: AuthorizedMemoryPlan;
    planRecord: ScopedMemoryPlanRecord;
    handle: AuthorizedResourceHandle;
    nowMs: number;
  }): ScopedMemoryRevisionAuthorization => {
    const record = handles.get(params.handle.handleId);
    const issuedPlan = record ? plans.get(record.planId) : undefined;
    if (
      !record ||
      !issuedPlan ||
      record.expiresAtMs <= params.nowMs ||
      !equalScopedMemoryResourceHandle(params.handle, record.handle) ||
      issuedPlan.plan.agentId !== params.context.agentId ||
      issuedPlan.plan.runId !== params.context.runId ||
      issuedPlan.plan.sessionId !== params.context.sessionId ||
      issuedPlan.plan.sessionIdentityRevision !== params.context.sessionIdentityRevision ||
      issuedPlan.plan.subjectRevision !== params.context.subjectRevision ||
      params.handle.policyRevision !== params.plan.memoryPolicyRevision
    ) {
      throw new Error("authorized memory revision is unavailable");
    }
    const snapshot = readScopedMemoryRevisionAuthorization({
      database: params.database,
      context: params.context,
      planRecord: params.planRecord,
      revisionId: record.revisionId,
      nowMs: params.nowMs,
    });
    if (!snapshot) {
      throw new Error("authorized memory revision is unavailable");
    }
    return snapshot;
  };

  const validateMutation = (params: {
    context: MemoryAccessContext;
    plan: AuthorizedMemoryPlan;
    mutation: AuthorizedMemoryMutation;
  }): void => {
    const { mutation } = params;
    const mutationRecord = mutation as Readonly<Record<string, unknown>>;
    // The host chooses placement from the verified session subject. Reject stale
    // or model-supplied destination selectors instead of silently honoring a hint.
    if (
      CALLER_SELECTED_MUTATION_DESTINATION_FIELDS.some((field) =>
        Object.hasOwn(mutationRecord, field),
      )
    ) {
      throw new Error("authorized memory mutation placement is unavailable");
    }
    if (
      mutation.version !== 1 ||
      mutationOperation(mutation) !== params.context.operation ||
      params.plan.operation !== params.context.operation ||
      !mutation.mutationId.trim() ||
      !mutation.idempotencyKey.trim()
    ) {
      throw new Error("authorized memory mutation is unavailable");
    }
    if ("content" in mutation && !mutation.content.trim()) {
      throw new Error("authorized memory mutation content is unavailable");
    }
    if (
      (mutation.kind === "derive" || mutation.kind === "project" || mutation.kind === "publish") &&
      mutation.sourceHandles.length === 0
    ) {
      throw new Error("authorized memory mutation sources are unavailable");
    }
  };

  const quarantineIntent = (params: {
    database: DatabaseSync;
    intentId: string;
    revisionId: string | null;
    nowMs: number;
    reasonCode: string;
  }): void => {
    const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
    runSqliteImmediateTransactionSync(params.database, () => {
      if (params.revisionId) {
        executeSqliteQuerySync(
          params.database,
          db.deleteFrom("memory_scoped_chunks").where("revision_id", "=", params.revisionId),
        );
        executeSqliteQuerySync(
          params.database,
          db
            .updateTable("memory_resource_revisions")
            .set({ lifecycle_state: "quarantined" })
            .where("revision_id", "=", params.revisionId)
            .where("lifecycle_state", "=", "pending"),
        );
        executeSqliteQuerySync(
          params.database,
          db
            .updateTable("memory_resource_revisions")
            .set({ lifecycle_state: "tombstoned", retired_at: params.nowMs })
            .where("revision_id", "=", params.revisionId)
            .where("lifecycle_state", "=", "active"),
        );
      }
      executeSqliteQuerySync(
        params.database,
        db
          .updateTable("memory_write_intents")
          .set({ state: "quarantined", updated_at: params.nowMs })
          .where("intent_id", "=", params.intentId)
          .where("state", "in", ["pending", "renamed", "active"]),
      );
      finalizeAuditOutbox({
        database: params.database,
        intentId: params.intentId,
        decision: "quarantined",
        reasonCode: params.reasonCode,
        nowMs: params.nowMs,
      });
    });
  };

  const recoverPendingWrites = (agentId: string): void => {
    withScopedMemoryDatabase(agentId, (database, databasePath) => {
      const db = getNodeSqliteKysely<ScopedMemoryDatabase>(database);
      const knownArtifacts = new Map<string, Set<string>>();
      const known = executeSqliteQuerySync(
        database,
        db
          .selectFrom("memory_stores as store")
          .innerJoin(
            "memory_storage_roots as root",
            "root.storage_root_id",
            "store.storage_root_id",
          )
          .leftJoin("memory_resources as resource", "resource.store_id", "store.store_id")
          .leftJoin(
            "memory_resource_revisions as revision",
            "revision.resource_id",
            "resource.resource_id",
          )
          .leftJoin("memory_write_intents as intent", "intent.store_id", "store.store_id")
          .select(["root.path_key", "revision.artifact_locator", "intent.staged_locator"])
          .where("store.agent_id", "=", agentId)
          .where("root.agent_id", "=", agentId)
          .where("store.lifecycle_state", "=", "active")
          .where("root.backend_kind", "=", "builtin")
          .where("root.lifecycle_state", "=", "active"),
      ).rows;
      for (const row of known) {
        if (!row.path_key) {
          continue;
        }
        const files = knownArtifacts.get(row.path_key) ?? new Set<string>();
        if (row.artifact_locator) {
          files.add(row.artifact_locator);
        }
        if (row.staged_locator) {
          files.add(row.staged_locator);
        }
        knownArtifacts.set(row.path_key, files);
      }
      for (const [pathKey, files] of knownArtifacts) {
        const sentinelPath = resolveBuiltinScopedMemoryArtifactPath({
          databasePath,
          pathKey,
          artifactLocator: createFinalArtifactLocator(),
        });
        const storeDirectory = path.dirname(sentinelPath);
        let entries: fs.Dirent[];
        try {
          entries = fs.readdirSync(storeDirectory, { withFileTypes: true });
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === "ENOENT") {
            continue;
          }
          throw error;
        }
        for (const entry of entries) {
          if (!entry.isFile() || files.has(entry.name)) {
            continue;
          }
          quarantineArtifact(path.join(storeDirectory, entry.name));
        }
      }
      const intents = executeSqliteQuerySync(
        database,
        db
          .selectFrom("memory_write_intents as intent")
          .innerJoin("memory_stores as store", "store.store_id", "intent.store_id")
          .innerJoin(
            "memory_storage_roots as root",
            "root.storage_root_id",
            "store.storage_root_id",
          )
          .select([
            "intent.intent_id",
            "intent.pending_revision_id",
            "intent.staged_locator",
            "intent.final_locator",
            "intent.content_hash",
            "intent.content_bytes",
            "intent.state",
            "root.path_key",
          ])
          .where("intent.agent_id", "=", agentId)
          .where("intent.state", "in", ["pending", "renamed", "active", "tombstoned"])
          .orderBy("intent.created_at")
          .orderBy("intent.intent_id"),
      ).rows;
      for (const intent of intents) {
        if (!intent.path_key || !intent.final_locator) {
          if (intent.state !== "tombstoned") {
            quarantineIntent({
              database,
              intentId: intent.intent_id,
              revisionId: intent.pending_revision_id,
              nowMs: now(),
              reasonCode: "missing-artifact-locator",
            });
          }
          continue;
        }
        const finalPath = resolveBuiltinScopedMemoryArtifactPath({
          databasePath,
          pathKey: intent.path_key,
          artifactLocator: intent.final_locator,
        });
        if (intent.state === "tombstoned") {
          try {
            fs.unlinkSync(finalPath);
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
              continue;
            }
          }
          continue;
        }
        if (!intent.pending_revision_id || !intent.content_hash || intent.content_bytes === null) {
          quarantineIntent({
            database,
            intentId: intent.intent_id,
            revisionId: intent.pending_revision_id,
            nowMs: now(),
            reasonCode: "missing-write-facts",
          });
          continue;
        }
        let content = readVerifiedArtifact({
          pathname: finalPath,
          expectedHash: intent.content_hash,
          expectedBytes: intent.content_bytes,
        });
        if (!content && intent.state === "pending" && intent.staged_locator) {
          const storeDirectory = path.dirname(finalPath);
          const stagedPath = resolveScopedArtifactChild(
            storeDirectory,
            intent.staged_locator,
            STAGED_ARTIFACT_PATTERN,
          );
          const stagedContent = readVerifiedArtifact({
            pathname: stagedPath,
            expectedHash: intent.content_hash,
            expectedBytes: intent.content_bytes,
          });
          if (stagedContent) {
            fs.renameSync(stagedPath, finalPath);
            syncDirectory(storeDirectory);
            content = readVerifiedArtifact({
              pathname: finalPath,
              expectedHash: intent.content_hash,
              expectedBytes: intent.content_bytes,
            });
          }
        }
        if (!content) {
          quarantineIntent({
            database,
            intentId: intent.intent_id,
            revisionId: intent.pending_revision_id,
            nowMs: now(),
            reasonCode: "artifact-recovery-failed",
          });
          quarantineArtifact(finalPath);
          continue;
        }
        if (intent.state === "pending") {
          runSqliteImmediateTransactionSync(database, () => {
            executeSqliteQuerySync(
              database,
              db
                .updateTable("memory_write_intents")
                .set({ state: "renamed", updated_at: now() })
                .where("intent_id", "=", intent.intent_id)
                .where("state", "=", "pending"),
            );
          });
        }
        activatePendingIntent({
          database,
          agentId,
          intentId: intent.intent_id,
          revisionId: intent.pending_revision_id,
          nowMs: now(),
        });
        indexActiveIntent({
          database,
          agentId,
          intentId: intent.intent_id,
          revisionId: intent.pending_revision_id,
          content,
          nowMs: now(),
        });
      }
    });
    drainAuditOutbox(agentId);
  };

  /** Tombstone every catalog descendant before a source artifact can disappear. */
  const tombstoneRevisionLineage = (params: {
    database: DatabaseSync;
    revisionId: string;
    nowMs: number;
  }): readonly string[] => {
    const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
    const descendantIds = new Set([params.revisionId]);
    let frontier = [params.revisionId];
    while (frontier.length > 0) {
      const children = executeSqliteQuerySync(
        params.database,
        db
          .selectFrom("memory_lineage_edges")
          .select("child_revision_id")
          .where("parent_revision_id", "in", frontier)
          .orderBy("child_revision_id"),
      ).rows;
      frontier = children.flatMap((child) => {
        if (descendantIds.has(child.child_revision_id)) {
          return [];
        }
        descendantIds.add(child.child_revision_id);
        return [child.child_revision_id];
      });
    }
    const invalidatedIds = [...descendantIds];
    executeSqliteQuerySync(
      params.database,
      db.deleteFrom("memory_scoped_chunks").where("revision_id", "in", invalidatedIds),
    );
    executeSqliteQuerySync(
      params.database,
      db
        .updateTable("memory_resource_revisions")
        .set({ lifecycle_state: "tombstoned", retired_at: params.nowMs })
        .where("revision_id", "in", invalidatedIds)
        .where("lifecycle_state", "in", ["pending", "active", "quarantined"]),
    );
    executeSqliteQuerySync(
      params.database,
      db
        .updateTable("memory_write_intents")
        .set({ state: "quarantined", updated_at: params.nowMs })
        .where("pending_revision_id", "in", invalidatedIds)
        .where("state", "in", ["pending", "renamed"]),
    );
    return Object.freeze(invalidatedIds);
  };

  const writeAuthorized = async (params: {
    context: MemoryAccessContext;
    plan: AuthorizedMemoryPlan;
    mutation: AuthorizedMemoryMutation;
  }): Promise<MemoryWriteResult> => {
    validateMutation(params);
    const agentId = normalizeAgentId(params.context.agentId);
    if (agentId !== params.context.agentId) {
      throw new Error("authorized memory mutation is unavailable");
    }
    recoverPendingWrites(agentId);
    const nowMs = now();
    let stagePath: string | undefined;
    let durableIntent = false;
    try {
      return withScopedMemoryDatabase(agentId, (database, databasePath) => {
        const planRecord = validatePlan({
          database,
          context: params.context,
          plan: params.plan,
          nowMs,
        });
        const existing = findCommittedIdempotency({
          database,
          agentId,
          idempotencyKey: params.mutation.idempotencyKey,
        });
        if (existing) {
          if (existing.mutation_id !== params.mutation.mutationId) {
            throw new Error("authorized memory idempotency key is already in use");
          }
          if (existing.state === "active" || existing.state === "tombstoned") {
            return Object.freeze({
              version: 1,
              mutationId: params.mutation.mutationId,
              status: "unchanged",
              policyRevision: params.plan.memoryPolicyRevision,
              committedAt: new Date(existing.updated_at).toISOString(),
            });
          }
          throw new Error("authorized memory mutation recovery is incomplete");
        }

        if (params.mutation.kind === "delete" || params.mutation.kind === "tombstone") {
          const target = assertMutationHandle({
            database,
            context: params.context,
            plan: params.plan,
            planRecord,
            handle: params.mutation.target,
            nowMs,
          });
          const intentId = allocateOpaqueId({
            kind: "intent",
            occupied: () => false,
            generate: dependencies.generateOpaqueId,
          });
          const finalPath = resolveBuiltinScopedMemoryArtifactPath({
            databasePath,
            pathKey: target.pathKey,
            artifactLocator: target.artifactLocator,
          });
          runSqliteImmediateTransactionSync(database, () => {
            const current = readScopedMemoryRevisionAuthorization({
              database,
              context: params.context,
              planRecord: validatePlan({
                database,
                context: params.context,
                plan: params.plan,
                nowMs,
              }),
              revisionId: target.revisionId,
              nowMs,
            });
            if (!current || current.resourceId !== target.resourceId) {
              throw new Error("authorized memory revision is unavailable");
            }
            const db = getNodeSqliteKysely<ScopedMemoryDatabase>(database);
            tombstoneRevisionLineage({
              database,
              revisionId: target.revisionId,
              nowMs,
            });
            executeSqliteQuerySync(
              database,
              db.insertInto("memory_write_intents").values({
                intent_id: intentId,
                idempotency_key: params.mutation.idempotencyKey,
                mutation_id: params.mutation.mutationId,
                agent_id: agentId,
                request_id: params.context.requestId,
                run_id: params.context.runId,
                context_fingerprint: params.context.contextFingerprint,
                plan_id: params.plan.planId,
                mutation_kind: "tombstone",
                store_id: target.storeId,
                resource_id: target.resourceId,
                pending_revision_id: target.revisionId,
                staged_locator: null,
                final_locator: target.artifactLocator,
                content_hash: target.contentHash,
                content_bytes: target.contentBytes,
                state: "tombstoned",
                created_at: nowMs,
                updated_at: nowMs,
                activated_at: nowMs,
                indexed_at: nowMs,
              }),
            );
            executeSqliteQuerySync(
              database,
              db.insertInto("memory_audit_outbox").values({
                event_id: randomUUID(),
                intent_id: intentId,
                agent_id: agentId,
                request_id: params.context.requestId,
                run_id: params.context.runId,
                actor_ref: actorRef(params.context),
                subject_ref: subjectRef(params.context),
                operation: "delete",
                resource_revision_id: target.revisionId,
                content_hash: target.contentHash,
                decision: "tombstoned",
                reason_code: "authorized-tombstone",
                state: "pending",
                attempts: 0,
                created_at: nowMs,
                updated_at: nowMs,
                delivered_at: null,
              }),
            );
          });
          try {
            fs.unlinkSync(finalPath);
            syncDirectory(path.dirname(finalPath));
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
              throw error;
            }
          }
          dependencies.onMutationPhase?.("activated");
          drainAuditOutbox(agentId);
          return Object.freeze({
            version: 1,
            mutationId: params.mutation.mutationId,
            status: "committed",
            policyRevision: params.plan.memoryPolicyRevision,
            committedAt: new Date(nowMs).toISOString(),
          });
        }

        if (params.mutation.kind === "admin-reclassify") {
          throw new Error("authorized memory reclassification requires a policy revision");
        }

        let mount = selectDefaultMutationMount({ context: params.context, planRecord });
        if (!("content" in params.mutation)) {
          throw new Error("authorized memory mutation content is unavailable");
        }
        let resourceId = randomUUID() as `${string}-${string}-${string}-${string}-${string}`;
        let revisionNumber = 1;
        let logicalLocator = `memory/${resourceId}.md`;
        let content = params.mutation.content;
        let retiredArtifactPath: string | undefined;
        let sourceSnapshots: ScopedMemoryRevisionAuthorization[] = [];
        let lineageEdgeKind: MemoryLineageEdgeKind | undefined;
        let policyRequirements: ScopedMemoryRevisionPolicyRequirement[] = [
          {
            stablePolicyId: mount.policyId,
            capturedRevisionId: mount.policyRevisionId,
            expectedActiveRevisionId: mount.policyRevisionId,
            expectedRevocationEpoch: mount.policyRevocationEpoch,
          },
        ];
        if (params.mutation.kind === "append" || params.mutation.kind === "replace") {
          const target = assertMutationHandle({
            database,
            context: params.context,
            plan: params.plan,
            planRecord,
            handle: params.mutation.target,
            nowMs,
          });
          const targetMount = planRecord.mounts.find(
            (entry) => entry.store.store_id === target.storeId,
          );
          if (!targetMount) {
            throw new Error("authorized memory mutation is unavailable");
          }
          const existingContent = readVerifiedArtifact({
            pathname: resolveBuiltinScopedMemoryArtifactPath({
              databasePath,
              pathKey: target.pathKey,
              artifactLocator: target.artifactLocator,
            }),
            expectedHash: target.contentHash,
            expectedBytes: target.contentBytes,
          });
          if (existingContent === undefined) {
            throw new Error("authorized memory revision is unavailable");
          }
          mount = targetMount;
          resourceId = target.resourceId as `${string}-${string}-${string}-${string}-${string}`;
          logicalLocator = target.logicalLocator;
          revisionNumber =
            executeSqliteQueryTakeFirstSync(
              database,
              getNodeSqliteKysely<ScopedMemoryDatabase>(database)
                .selectFrom("memory_resource_revisions")
                .select("revision_number")
                .where("resource_id", "=", resourceId)
                .orderBy("revision_number", "desc")
                .limit(1),
            )!.revision_number + 1;
          content =
            params.mutation.kind === "append"
              ? `${existingContent}${existingContent.endsWith("\n") ? "" : "\n"}${params.mutation.content}`
              : params.mutation.content;
          retiredArtifactPath = resolveBuiltinScopedMemoryArtifactPath({
            databasePath,
            pathKey: target.pathKey,
            artifactLocator: target.artifactLocator,
          });
          sourceSnapshots = [target];
          lineageEdgeKind = "revision";
        }
        if (
          params.mutation.kind === "derive" ||
          params.mutation.kind === "project" ||
          params.mutation.kind === "publish"
        ) {
          sourceSnapshots = params.mutation.sourceHandles.map((handle) =>
            assertMutationHandle({
              database,
              context: params.context,
              plan: params.plan,
              planRecord,
              handle,
              nowMs,
            }),
          );
          if (sourceSnapshots.some((source) => source.storeId !== mount.store.store_id)) {
            throw new Error("authorized memory mutation crosses an audience boundary");
          }
          if (
            params.mutation.kind === "derive" &&
            params.mutation.sourcePolicySetId !==
              createScopedMemoryAggregateRevision(
                "mpset1",
                sourceSnapshots.map((source) => source.sourcePolicySetId),
              )
          ) {
            throw new Error("authorized memory mutation source policy is unavailable");
          }
          lineageEdgeKind = params.mutation.kind;
        }
        if (sourceSnapshots.length > 0) {
          policyRequirements = mergeRevisionPolicyRequirements(
            sourceSnapshots.flatMap((source) =>
              readScopedMemoryRevisionPolicyRequirements({
                database,
                revisionId: source.revisionId,
              }),
            ),
          );
          if (policyRequirements.length === 0) {
            throw new Error("authorized memory mutation source policy is unavailable");
          }
        }

        const root = readMutationStoreRoot({ database, agentId, mount });
        const finalLocator = createFinalArtifactLocator();
        const stagedLocator = createStagedArtifactLocator();
        const finalPath = resolveBuiltinScopedMemoryArtifactPath({
          databasePath,
          pathKey: root.pathKey,
          artifactLocator: finalLocator,
        });
        const storeDirectory = path.dirname(finalPath);
        fs.mkdirSync(storeDirectory, { recursive: true, mode: 0o700 });
        fs.chmodSync(storeDirectory, 0o700);
        stagePath = writeStagedArtifact({
          directory: storeDirectory,
          locator: stagedLocator,
          content,
        });
        dependencies.onMutationPhase?.("staged");

        const intentId = allocateOpaqueId({
          kind: "intent",
          occupied: () => false,
          generate: dependencies.generateOpaqueId,
        });
        const revisionId = randomUUID();
        const contentHash = hashText(content);
        const contentBytes = Buffer.byteLength(content);
        const actor = actorRecord(params.context);
        runSqliteImmediateTransactionSync(database, () => {
          const currentPlan = validatePlan({
            database,
            context: params.context,
            plan: params.plan,
            nowMs,
          });
          const currentRoot = readMutationStoreRoot({
            database,
            agentId,
            mount:
              currentPlan.mounts.find((entry) => entry.store.store_id === mount.store.store_id) ??
              mount,
          });
          if (currentRoot.pathKey !== root.pathKey) {
            throw new Error("authorized memory storage root changed during write");
          }
          const currentSourceSnapshots = sourceSnapshots.map((source) => {
            const current = readScopedMemoryRevisionAuthorization({
              database,
              context: params.context,
              planRecord: currentPlan,
              revisionId: source.revisionId,
              nowMs,
            });
            if (
              !current ||
              current.contentHash !== source.contentHash ||
              current.artifactLocator !== source.artifactLocator ||
              current.sourcePolicySetId !== source.sourcePolicySetId
            ) {
              throw new Error("authorized memory revision is unavailable");
            }
            return current;
          });
          const currentSourcePolicySetId =
            currentSourceSnapshots.length === 0
              ? createScopedMemorySourcePolicySetId(mount.policyRevisionId)
              : createScopedMemoryAggregateRevision(
                  "mpset1",
                  currentSourceSnapshots.map((source) => source.sourcePolicySetId),
                );
          if (
            params.mutation.kind === "derive" &&
            params.mutation.sourcePolicySetId !== currentSourcePolicySetId
          ) {
            throw new Error("authorized memory mutation source policy is unavailable");
          }
          const currentPolicyRequirements =
            currentSourceSnapshots.length === 0
              ? policyRequirements
              : mergeRevisionPolicyRequirements(
                  currentSourceSnapshots.flatMap((source) =>
                    readScopedMemoryRevisionPolicyRequirements({
                      database,
                      revisionId: source.revisionId,
                    }),
                  ),
                );
          if (currentPolicyRequirements.length === 0) {
            throw new Error("authorized memory mutation source policy is unavailable");
          }
          const db = getNodeSqliteKysely<ScopedMemoryDatabase>(database);
          if (revisionNumber === 1) {
            executeSqliteQuerySync(
              database,
              db.insertInto("memory_resources").values({
                resource_id: resourceId,
                agent_id: agentId,
                store_id: root.store.store_id,
                logical_locator: logicalLocator,
                source: "memory",
                created_at: nowMs,
              }),
            );
          }
          executeSqliteQuerySync(
            database,
            db.insertInto("memory_resource_revisions").values({
              revision_id: revisionId,
              resource_id: resourceId,
              revision_number: revisionNumber,
              artifact_locator: finalLocator,
              content_hash: contentHash,
              content_bytes: contentBytes,
              policy_revision_id: mount.policyRevisionId,
              policy_revocation_epoch: mount.policyRevocationEpoch,
              source_policy_set_id: currentSourcePolicySetId,
              lifecycle_state: "pending",
              actor_kind: actor.kind,
              actor_id: actor.id,
              expires_at: null,
              created_at: nowMs,
              activated_at: null,
              retired_at: null,
            }),
          );
          executeSqliteQuerySync(
            database,
            db.insertInto("memory_revision_policy_requirements").values(
              currentPolicyRequirements.map((requirement) => ({
                revision_id: revisionId,
                stable_policy_id: requirement.stablePolicyId,
                captured_revision_id: requirement.capturedRevisionId,
                expected_active_revision_id: requirement.expectedActiveRevisionId,
                expected_revocation_epoch: requirement.expectedRevocationEpoch,
                created_at: nowMs,
              })),
            ),
          );
          if (lineageEdgeKind) {
            executeSqliteQuerySync(
              database,
              db.insertInto("memory_lineage_edges").values(
                [...new Set(currentSourceSnapshots.map((source) => source.revisionId))]
                  .toSorted(compareText)
                  .map((parentRevisionId) => ({
                    child_revision_id: revisionId,
                    parent_revision_id: parentRevisionId,
                    edge_kind: lineageEdgeKind,
                    created_at: nowMs,
                  })),
              ),
            );
          }
          executeSqliteQuerySync(
            database,
            db.insertInto("memory_write_intents").values({
              intent_id: intentId,
              idempotency_key: params.mutation.idempotencyKey,
              mutation_id: params.mutation.mutationId,
              agent_id: agentId,
              request_id: params.context.requestId,
              run_id: params.context.runId,
              context_fingerprint: params.context.contextFingerprint,
              plan_id: params.plan.planId,
              mutation_kind: params.mutation.kind,
              store_id: root.store.store_id,
              resource_id: resourceId,
              pending_revision_id: revisionId,
              staged_locator: stagedLocator,
              final_locator: finalLocator,
              content_hash: contentHash,
              content_bytes: contentBytes,
              state: "pending",
              created_at: nowMs,
              updated_at: nowMs,
              activated_at: null,
              indexed_at: null,
            }),
          );
          executeSqliteQuerySync(
            database,
            db.insertInto("memory_audit_outbox").values({
              event_id: randomUUID(),
              intent_id: intentId,
              agent_id: agentId,
              request_id: params.context.requestId,
              run_id: params.context.runId,
              actor_ref: actorRef(params.context),
              subject_ref: subjectRef(params.context),
              operation: params.context.operation,
              resource_revision_id: revisionId,
              content_hash: contentHash,
              decision: "pending",
              reason_code: "authorized-write-pending",
              state: "pending",
              attempts: 0,
              created_at: nowMs,
              updated_at: nowMs,
              delivered_at: null,
            }),
          );
        });
        durableIntent = true;
        dependencies.onMutationPhase?.("pending");
        fs.renameSync(stagePath, finalPath);
        stagePath = undefined;
        syncDirectory(storeDirectory);
        const verifiedContent = readVerifiedArtifact({
          pathname: finalPath,
          expectedHash: contentHash,
          expectedBytes: contentBytes,
        });
        if (verifiedContent === undefined) {
          quarantineIntent({
            database,
            intentId,
            revisionId,
            nowMs: now(),
            reasonCode: "finalized-artifact-hash-mismatch",
          });
          throw new Error("authorized memory finalized artifact is unavailable");
        }
        runSqliteImmediateTransactionSync(database, () => {
          const db = getNodeSqliteKysely<ScopedMemoryDatabase>(database);
          executeSqliteQuerySync(
            database,
            db
              .updateTable("memory_write_intents")
              .set({ state: "renamed", updated_at: now() })
              .where("intent_id", "=", intentId)
              .where("state", "=", "pending"),
          );
        });
        dependencies.onMutationPhase?.("renamed");
        const activated = activatePendingIntent({
          database,
          agentId,
          intentId,
          revisionId,
          nowMs: now(),
          revalidate: () => {
            validatePlan({ database, context: params.context, plan: params.plan, nowMs: now() });
          },
        });
        if (!activated) {
          throw new Error("authorized memory mutation was quarantined");
        }
        dependencies.onMutationPhase?.("activated");
        indexActiveIntent({
          database,
          agentId,
          intentId,
          revisionId,
          content: verifiedContent,
          nowMs: now(),
          revalidate: () => {
            validatePlan({ database, context: params.context, plan: params.plan, nowMs: now() });
          },
        });
        dependencies.onMutationPhase?.("indexed");
        if (retiredArtifactPath) {
          try {
            fs.unlinkSync(retiredArtifactPath);
            syncDirectory(path.dirname(retiredArtifactPath));
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
              throw error;
            }
          }
        }
        const snapshot = readScopedMemoryRevisionAuthorization({
          database,
          context: params.context,
          planRecord: validatePlan({
            database,
            context: params.context,
            plan: params.plan,
            nowMs: now(),
          }),
          revisionId,
          nowMs: now(),
        });
        if (!snapshot) {
          throw new Error("authorized memory revision is unavailable");
        }
        const resourceHandle = issueHandle({
          context: params.context,
          plan: params.plan,
          snapshot,
        });
        drainAuditOutbox(agentId);
        return Object.freeze({
          version: 1,
          mutationId: params.mutation.mutationId,
          status: "committed",
          resourceHandle,
          policyRevision: params.plan.memoryPolicyRevision,
          committedAt: new Date(now()).toISOString(),
        });
      });
    } catch (error) {
      if (stagePath && !durableIntent) {
        try {
          fs.unlinkSync(stagePath);
        } catch {}
      }
      throw error;
    }
  };

  const importAuthorized = async (params: {
    context: MemoryAccessContext;
    plan: AuthorizedMemoryPlan;
    mutation: Extract<AuthorizedMemoryMutation, { kind: "import" }>;
  }): Promise<MemoryWriteResult> => await writeAuthorized(params);

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
    authorize,
    searchAuthorized,
    readAuthorized,
    writeAuthorized,
    importAuthorized,
    syncAuthorized,
    exportAuthorized,
    statusAuthorized,
    prepareTranscriptPolicy,
  });
}
