import { createHash } from "node:crypto";
import type fs from "node:fs";
import type { DatabaseSync } from "node:sqlite";
import {
  MEMORY_OPERATIONS,
  type AudienceRef,
  type AuthorizedMemoryPlan,
  type AuthorizedResourceHandle,
  type MemoryAccessContext,
  type MemoryOperation,
} from "openclaw/plugin-sdk/memory-authorization";
import type { MemorySource } from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
} from "openclaw/plugin-sdk/sqlite-runtime";
import type {
  MemoryPolicyEntryRow,
  MemoryStoreRow,
  ScopedMemoryDatabase,
} from "./scoped-memory-db.js";
import {
  evaluateScopedMemoryStorePolicy,
  SCOPED_MEMORY_OPERATION_REQUIREMENTS,
} from "./scoped-memory-policy.js";
import { resolveBuiltinScopedMemoryArtifactPath } from "./scoped-memory-resources.js";
import { createScopedMemorySourcePolicySetId } from "./scoped-memory-store.js";

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function audienceKey(audience: AudienceRef): string {
  return `${audience.kind}\0${audience.id}`;
}

type AuthorizedStoreDescriptor = Readonly<{
  store: MemoryStoreRow;
  policyId: string;
  policyRevisionId: string;
  policyRevocationEpoch: number;
  defaultCapabilities: readonly MemoryOperation[];
  capabilities: readonly MemoryOperation[];
  audienceRevision: string;
}>;

export type ScopedMemoryMountRecord = AuthorizedStoreDescriptor &
  Readonly<{
    mountHandle: string;
  }>;

export type ScopedMemoryPlanRecord = Readonly<{
  plan: AuthorizedMemoryPlan;
  mounts: readonly ScopedMemoryMountRecord[];
  expiresAtMs: number;
}>;

export type ScopedMemoryRevisionAuthorization = Readonly<{
  resourceId: string;
  revisionId: string;
  storeId: string;
  logicalLocator: string;
  source: MemorySource;
  artifactLocator: string;
  contentHash: string;
  contentBytes: number;
  policyRevisionId: string;
  policyRevocationEpoch: number;
  sourcePolicySetId: string;
  expiresAt: number | null;
  pathKey: string;
}>;

export type ScopedMemoryAuthorizedRevisionSnapshot = ScopedMemoryRevisionAuthorization &
  Readonly<{
    content: string;
    chunk?: Readonly<{
      chunkId: string;
      startLine: number;
      endLine: number;
      text: string;
      contentHash: string;
    }>;
  }>;

function hashText(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function createScopedMemoryAggregateRevision(
  prefix: string,
  values: readonly string[],
): string {
  return `${prefix}_${hashText(values.toSorted().join("\0"))}`;
}

function deriveViewAudienceKeys(context: MemoryAccessContext): Set<string> {
  const keys = new Set(context.delivery.audiences.map(audienceKey));
  switch (context.subject.kind) {
    case "user":
      keys.add(`user\0${context.subject.principalId}`);
      break;
    case "conversation":
      keys.add(`conversation\0${context.subject.conversationPrincipalId}`);
      break;
    case "service":
    case "agent":
    case "system":
      keys.add(`agent\0${context.subject.principalId}`);
      break;
    case "ambiguous":
      break;
  }
  for (const principal of context.verifiedPrincipals) {
    keys.add(`user\0${principal.principalId}`);
  }
  for (const membership of context.verifiedMemberships) {
    keys.add(`role\0${membership.groupId}`);
  }
  if (context.conversation) {
    keys.add(`conversation\0${context.conversation.conversationPrincipalId}`);
  }
  keys.add(`agent-shared\0${context.agentId}`);
  keys.add(`agent\0${context.agentId}`);
  if (context.delivery.sinkKind === "internal") {
    keys.add(`internal\0${context.agentId}`);
  }
  return keys;
}

function parseCapabilities(value: string): MemoryOperation[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) {
    return [];
  }
  return [
    ...new Set(
      parsed.filter(
        (entry): entry is MemoryOperation =>
          typeof entry === "string" && (MEMORY_OPERATIONS as readonly string[]).includes(entry),
      ),
    ),
  ].toSorted(compareText);
}

function listPolicyEntries(
  database: DatabaseSync,
  policyRevisionId: string,
): MemoryPolicyEntryRow[] {
  const db = getNodeSqliteKysely<ScopedMemoryDatabase>(database);
  return executeSqliteQuerySync(
    database,
    db
      .selectFrom("memory_policy_entries")
      .selectAll()
      .where("policy_revision_id", "=", policyRevisionId)
      .orderBy("entry_id"),
  ).rows;
}

export function resolveScopedMemoryAuthorizedStores(params: {
  database: DatabaseSync;
  context: MemoryAccessContext;
  nowMs: number;
}): AuthorizedStoreDescriptor[] {
  const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
  const viewAudienceKeys = deriveViewAudienceKeys(params.context);
  const rows = executeSqliteQuerySync(
    params.database,
    db
      .selectFrom("memory_stores as store")
      .innerJoin("memory_storage_roots as root", "root.storage_root_id", "store.storage_root_id")
      .innerJoin("memory_policies as policy", "policy.policy_id", "store.policy_id")
      .innerJoin(
        "memory_policy_revisions as policy_revision",
        "policy_revision.revision_id",
        "policy.current_revision_id",
      )
      .selectAll("store")
      .select([
        "root.default_capabilities_json",
        "root.backend_kind",
        "root.lifecycle_state as root_lifecycle_state",
        "policy.current_revision_id",
        "policy.revocation_epoch",
        "policy.lifecycle_state as policy_lifecycle_state",
        "policy_revision.lifecycle_state as policy_revision_lifecycle_state",
        "policy_revision.revocation_epoch as policy_revision_revocation_epoch",
      ])
      .where("store.agent_id", "=", params.context.agentId)
      .where("root.agent_id", "=", params.context.agentId)
      .where("policy.agent_id", "=", params.context.agentId)
      .orderBy("store.store_id"),
  ).rows;

  return rows.flatMap((row) => {
    const key = `${row.audience_kind}\0${row.audience_id}`;
    if (
      !viewAudienceKeys.has(key) ||
      row.lifecycle_state !== "active" ||
      row.root_lifecycle_state !== "active" ||
      row.backend_kind !== "builtin" ||
      row.policy_lifecycle_state !== "active" ||
      row.policy_revision_lifecycle_state !== "active" ||
      row.revocation_epoch !== row.policy_revision_revocation_epoch
    ) {
      return [];
    }
    const store: MemoryStoreRow = {
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
    };
    const entries = listPolicyEntries(params.database, row.current_revision_id);
    const defaultCapabilities = parseCapabilities(row.default_capabilities_json);
    const decision = evaluateScopedMemoryStorePolicy({
      context: params.context,
      store,
      defaultCapabilities,
      entries,
      nowMs: params.nowMs,
    });
    if (!decision.allowed) {
      return [];
    }
    const capabilities = [
      ...new Set([
        ...defaultCapabilities,
        ...SCOPED_MEMORY_OPERATION_REQUIREMENTS[params.context.operation],
      ]),
    ].toSorted(compareText);
    return [
      {
        store,
        policyId: row.policy_id,
        policyRevisionId: row.current_revision_id,
        policyRevocationEpoch: row.revocation_epoch,
        defaultCapabilities,
        capabilities,
        audienceRevision: createScopedMemoryAggregateRevision("mar1", [
          row.store_id,
          row.audience_kind,
          row.audience_id,
          row.current_revision_id,
          String(row.revocation_epoch),
        ]),
      },
    ];
  });
}

export function createScopedMemoryPolicyRevision(
  stores: readonly AuthorizedStoreDescriptor[],
): string {
  return createScopedMemoryAggregateRevision(
    "mpr1",
    stores.map(
      (store) =>
        `${store.store.store_id}\0${store.policyId}\0${store.policyRevisionId}\0${store.policyRevocationEpoch}`,
    ),
  );
}

export function assertScopedMemoryPlanBinding(params: {
  context: MemoryAccessContext;
  plan: AuthorizedMemoryPlan;
  nowMs: number;
}): void {
  const { context, plan } = params;
  const expiresAtMs = Date.parse(plan.expiresAt);
  if (
    context.version !== 1 ||
    plan.version !== 1 ||
    plan.contextFingerprint !== context.contextFingerprint ||
    plan.runId !== context.runId ||
    plan.agentId !== context.agentId ||
    plan.sessionId !== context.sessionId ||
    plan.sessionIdentityRevision !== context.sessionIdentityRevision ||
    plan.subjectRevision !== context.subjectRevision ||
    plan.deliveryRevision !== context.delivery.deliveryRevision ||
    plan.operation !== context.operation ||
    !Number.isFinite(expiresAtMs) ||
    expiresAtMs <= params.nowMs
  ) {
    throw new Error("authorized memory plan is unavailable");
  }
}

function equalOrderedValues<T>(
  left: readonly T[],
  right: readonly T[],
  equal: (leftValue: T, rightValue: T) => boolean,
): boolean {
  return (
    left.length === right.length &&
    left.every((leftValue, index) => {
      const rightValue = right[index];
      return rightValue !== undefined && equal(leftValue, rightValue);
    })
  );
}

function equalAudience(left: AudienceRef, right: AudienceRef): boolean {
  return left.kind === right.kind && left.id === right.id;
}

export function equalScopedMemoryResourceHandle(
  left: AuthorizedResourceHandle,
  right: AuthorizedResourceHandle,
): boolean {
  return (
    left.version === right.version &&
    left.handleId === right.handleId &&
    left.planId === right.planId &&
    left.contextFingerprint === right.contextFingerprint &&
    left.resourceRevision === right.resourceRevision &&
    left.policyRevision === right.policyRevision &&
    left.expiresAt === right.expiresAt
  );
}

export function equalScopedMemoryAuthorizedPlan(
  left: AuthorizedMemoryPlan,
  right: AuthorizedMemoryPlan,
): boolean {
  return (
    left.version === right.version &&
    left.planId === right.planId &&
    left.contextFingerprint === right.contextFingerprint &&
    left.runId === right.runId &&
    left.agentId === right.agentId &&
    left.sessionId === right.sessionId &&
    left.sessionIdentityRevision === right.sessionIdentityRevision &&
    left.subjectRevision === right.subjectRevision &&
    left.memoryPolicyRevision === right.memoryPolicyRevision &&
    left.deliveryRevision === right.deliveryRevision &&
    left.operation === right.operation &&
    left.expiresAt === right.expiresAt &&
    equalOrderedValues(
      left.mounts,
      right.mounts,
      (leftMount, rightMount) =>
        leftMount.version === rightMount.version &&
        leftMount.agentId === rightMount.agentId &&
        leftMount.mountHandle === rightMount.mountHandle &&
        leftMount.audienceRevision === rightMount.audienceRevision &&
        equalOrderedValues(
          leftMount.capabilities,
          rightMount.capabilities,
          (leftCapability, rightCapability) => leftCapability === rightCapability,
        ),
    ) &&
    equalOrderedValues(
      left.bootstrapResourceHandles,
      right.bootstrapResourceHandles,
      equalScopedMemoryResourceHandle,
    ) &&
    equalOrderedValues(left.allowedEgressAudiences, right.allowedEgressAudiences, equalAudience)
  );
}

export function readScopedMemoryRevisionAuthorization(params: {
  database: DatabaseSync;
  context: MemoryAccessContext;
  planRecord: ScopedMemoryPlanRecord;
  revisionId: string;
  nowMs: number;
}): ScopedMemoryRevisionAuthorization | undefined {
  const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
  const row = executeSqliteQueryTakeFirstSync(
    params.database,
    db
      .selectFrom("memory_resource_revisions as revision")
      .innerJoin("memory_resources as resource", "resource.resource_id", "revision.resource_id")
      .innerJoin("memory_stores as store", "store.store_id", "resource.store_id")
      .innerJoin("memory_storage_roots as root", "root.storage_root_id", "store.storage_root_id")
      .innerJoin("memory_policies as policy", "policy.policy_id", "store.policy_id")
      .innerJoin(
        "memory_policy_revisions as policy_revision",
        "policy_revision.revision_id",
        "policy.current_revision_id",
      )
      .select([
        "resource.resource_id",
        "resource.agent_id",
        "resource.store_id",
        "resource.logical_locator",
        "resource.source",
        "revision.revision_id",
        "revision.artifact_locator",
        "revision.content_hash",
        "revision.content_bytes",
        "revision.policy_revision_id",
        "revision.policy_revocation_epoch",
        "revision.source_policy_set_id",
        "revision.lifecycle_state as revision_lifecycle_state",
        "revision.expires_at",
        "store.storage_root_id",
        "store.policy_id",
        "store.scope_kind",
        "store.audience_kind",
        "store.audience_id",
        "store.lifecycle_state as store_lifecycle_state",
        "store.created_at as store_created_at",
        "store.updated_at as store_updated_at",
        "root.path_key",
        "root.backend_kind",
        "root.lifecycle_state as root_lifecycle_state",
        "root.default_capabilities_json",
        "policy.current_revision_id",
        "policy.revocation_epoch",
        "policy.lifecycle_state as policy_lifecycle_state",
        "policy_revision.lifecycle_state as policy_revision_lifecycle_state",
        "policy_revision.revocation_epoch as current_policy_revocation_epoch",
      ])
      .where("revision.revision_id", "=", params.revisionId),
  );
  if (!row?.path_key || row.agent_id !== params.context.agentId) {
    return undefined;
  }
  const mount = params.planRecord.mounts.find((entry) => entry.store.store_id === row.store_id);
  if (
    !mount ||
    row.revision_lifecycle_state !== "active" ||
    row.store_lifecycle_state !== "active" ||
    row.root_lifecycle_state !== "active" ||
    row.backend_kind !== "builtin" ||
    row.policy_lifecycle_state !== "active" ||
    row.policy_revision_lifecycle_state !== "active" ||
    row.current_revision_id !== mount.policyRevisionId ||
    row.revocation_epoch !== mount.policyRevocationEpoch ||
    row.current_policy_revocation_epoch !== mount.policyRevocationEpoch ||
    row.policy_revision_id !== mount.policyRevisionId ||
    row.policy_revocation_epoch !== mount.policyRevocationEpoch ||
    row.source_policy_set_id !== createScopedMemorySourcePolicySetId(mount.policyRevisionId) ||
    (row.expires_at !== null && row.expires_at <= params.nowMs)
  ) {
    return undefined;
  }
  const store: MemoryStoreRow = {
    store_id: row.store_id,
    agent_id: row.agent_id,
    storage_root_id: row.storage_root_id,
    policy_id: row.policy_id,
    scope_kind: row.scope_kind,
    audience_kind: row.audience_kind,
    audience_id: row.audience_id,
    lifecycle_state: row.store_lifecycle_state,
    created_at: row.store_created_at,
    updated_at: row.store_updated_at,
  };
  const decision = evaluateScopedMemoryStorePolicy({
    context: params.context,
    store,
    defaultCapabilities: parseCapabilities(row.default_capabilities_json),
    entries: listPolicyEntries(params.database, mount.policyRevisionId),
    nowMs: params.nowMs,
  });
  if (!decision.allowed) {
    return undefined;
  }
  return {
    resourceId: row.resource_id,
    revisionId: row.revision_id,
    storeId: row.store_id,
    logicalLocator: row.logical_locator,
    source: row.source,
    artifactLocator: row.artifact_locator,
    contentHash: row.content_hash,
    contentBytes: row.content_bytes,
    policyRevisionId: row.policy_revision_id,
    policyRevocationEpoch: row.policy_revocation_epoch,
    sourcePolicySetId: row.source_policy_set_id,
    expiresAt: row.expires_at,
    pathKey: row.path_key,
  };
}

export function readScopedMemoryAuthorizedRevisionSnapshot(params: {
  database: DatabaseSync;
  databasePath: string;
  context: MemoryAccessContext;
  planRecord: ScopedMemoryPlanRecord;
  revisionId: string;
  chunkId?: string;
  nowMs: number;
  readFile: typeof fs.readFileSync;
}): ScopedMemoryAuthorizedRevisionSnapshot | undefined {
  const authorization = readScopedMemoryRevisionAuthorization(params);
  if (!authorization) {
    return undefined;
  }
  const artifactPath = resolveBuiltinScopedMemoryArtifactPath({
    databasePath: params.databasePath,
    pathKey: authorization.pathKey,
    artifactLocator: authorization.artifactLocator,
  });
  let content: string;
  try {
    content = params.readFile(artifactPath, "utf8") as string;
  } catch {
    return undefined;
  }
  if (
    Buffer.byteLength(content) !== authorization.contentBytes ||
    hashText(content) !== authorization.contentHash
  ) {
    return undefined;
  }
  if (!params.chunkId) {
    return { ...authorization, content };
  }
  const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
  const chunk = executeSqliteQueryTakeFirstSync(
    params.database,
    db
      .selectFrom("memory_scoped_chunks")
      .select(["chunk_id", "revision_id", "start_line", "end_line", "text", "content_hash"])
      .where("chunk_id", "=", params.chunkId)
      .where("revision_id", "=", authorization.revisionId),
  );
  if (!chunk || hashText(chunk.text) !== chunk.content_hash) {
    return undefined;
  }
  return {
    ...authorization,
    content,
    chunk: {
      chunkId: chunk.chunk_id,
      startLine: chunk.start_line,
      endLine: chunk.end_line,
      text: chunk.text,
      contentHash: chunk.content_hash,
    },
  };
}
