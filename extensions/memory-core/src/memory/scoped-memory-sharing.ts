// Explicit sharing stays outside the generic memory mutation path: every copy is
// bound to a reviewed operator preview, a single target, and an expiry.
import { createHash, randomBytes, randomUUID } from "node:crypto";
import fs from "node:fs";
import type { DatabaseSync } from "node:sqlite";
import type { MemoryOperation } from "openclaw/plugin-sdk/memory-authorization";
import { normalizeAgentId } from "openclaw/plugin-sdk/routing";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
  runSqliteImmediateTransactionSync,
} from "openclaw/plugin-sdk/sqlite-runtime";
import {
  type MemoryPolicyEntryRow,
  type MemoryPostboxItemRow,
  type MemoryProjectionRow,
  type MemoryRevisionPolicyRequirementRow,
  type MemoryStoreRow,
  type ScopedMemoryDatabase,
  type ScopedMemoryProjectionTargetKind,
  type ScopedMemoryPublisherKind,
  withScopedMemoryDatabase,
} from "./scoped-memory-db.js";
import {
  createBuiltinScopedMemoryResource,
  removeTombstonedBuiltinScopedMemoryArtifacts,
  resolveBuiltinScopedMemoryArtifactPath,
  type ScopedMemoryRevisionPolicyRequirementInput,
} from "./scoped-memory-resources.js";
import {
  createScopedMemorySourcePolicySetId,
  normalizeScopedMemoryRequiredText,
  type BuiltinScopedMemoryStore,
} from "./scoped-memory-store.js";

const PREVIEW_TTL_MS = 5 * 60_000;
const POSTBOX_HANDLE_TTL_MS = 5 * 60_000;
const DEFAULT_POSTBOX_RATE_LIMIT_WINDOW_MS = 60 * 60_000;
const DEFAULT_POSTBOX_RATE_LIMIT_MAX_ITEMS = 10;
// Purge keeps immutable review/audit metadata while removing both content bodies.
const PURGED_POSTBOX_CONTENT = "[purged]";

type SharingAuthority = Readonly<{
  kind: ScopedMemoryPublisherKind;
  id: string;
}>;

type ProjectionPreviewInput = Readonly<{
  agentId: string;
  authority: SharingAuthority;
  sourceRevisionId: string;
  targetKind: ScopedMemoryProjectionTargetKind;
  targetId: string;
  purpose: string;
  expiresAtMs: number;
  supersedesProjectionId?: string;
}>;

type ProjectionPreviewRecord = Readonly<{
  previewId: string;
  agentId: string;
  authority: SharingAuthority;
  sourceRevisionId: string;
  targetKind: ScopedMemoryProjectionTargetKind;
  targetId: string;
  targetStoreId: string;
  purpose: string;
  expiresAtMs: number;
  supersedesProjectionId?: string;
  expiresAtPreviewMs: number;
}>;

type PostboxSourceMessage = Readonly<{
  agentId: string;
  sessionId: string;
  sourceConversationId: string;
  sourceEventId?: string;
  sourceActor: Readonly<{
    kind: "human" | "agent" | "service";
    id: string;
    evidenceRevision: string;
  }>;
  targetUserId: string;
  targetUserEvidenceRevision: string;
  content: string;
  expiresAtMs: number;
}>;

type PostboxSourceMessageRecord = Readonly<{
  handle: string;
  message: PostboxSourceMessage;
  expiresAtMs: number;
}>;

type ScopedStoreDetails = Readonly<{
  store: MemoryStoreRow;
  policyRevisionId: string;
  policyRevocationEpoch: number;
  authorityOwnerId: string;
  defaultCapabilities: readonly MemoryOperation[];
  policyEntries: readonly MemoryPolicyEntryRow[];
}>;

type SourceRevision = ScopedStoreDetails &
  Readonly<{
    revisionId: string;
    resourceId: string;
    artifactLocator: string;
    contentHash: string;
    contentBytes: number;
    sourcePolicySetId: string;
    expiresAt: number | null;
    pathKey: string;
  }>;

/** Immutable ownership facts remain available after source policy revocation. */
type HistoricalRevisionOwner = Readonly<{
  authorityOwnerId: string;
  resourceId: string;
}>;

export type ScopedMemorySharingProjection = Readonly<{
  projectionId: string;
  sourceRevisionId: string;
  targetKind: ScopedMemoryProjectionTargetKind;
  targetAudienceId: string;
  purpose: string;
  preview: string;
  reviewState: MemoryProjectionRow["review_state"];
  expiresAt: string;
  createdAt: string;
  reviewedAt?: string;
  revokedAt?: string;
  supersedesProjectionId?: string;
}>;

export type ScopedMemorySharingPostboxItem = Readonly<{
  postboxItemId: string;
  sourceConversationId: string;
  provenanceLabel: string;
  contentPreview: string;
  reviewState: MemoryPostboxItemRow["review_state"];
  expiresAt: string;
  createdAt: string;
  reviewedAt?: string;
}>;

/** The pending review body, visible only through the target-owner inspection action. */
export type ScopedMemorySharingPostboxInspection = Readonly<{
  postboxItemId: string;
  reviewContent: string;
  expiresAt: string;
}>;

export type ScopedMemorySharingStatus = Readonly<{
  postboxMode: "off" | "review-required";
  projections: readonly ScopedMemorySharingProjection[];
  postboxItems: readonly ScopedMemorySharingPostboxItem[];
}>;

function hashText(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function createOpaqueId(prefix: "mppv1" | "mph1"): string {
  return `${prefix}_${randomBytes(24).toString("base64url")}`;
}

function iso(value: number): string {
  return new Date(value).toISOString();
}

function requireFutureExpiry(value: number, nowMs: number, label: string): number {
  if (!Number.isFinite(value) || value <= nowMs) {
    throw new Error(`${label} must be a future time`);
  }
  return Math.trunc(value);
}

function capProjectionExpiryToSource(params: {
  requestedExpiresAtMs: number;
  sourceExpiresAtMs: number | null;
}): number {
  return params.sourceExpiresAtMs !== null && Number.isFinite(params.sourceExpiresAtMs)
    ? Math.min(params.requestedExpiresAtMs, params.sourceExpiresAtMs)
    : params.requestedExpiresAtMs;
}

function assertPostboxMode(value: unknown): "off" | "review-required" {
  if (value !== "off" && value !== "review-required") {
    throw new Error("postbox mode is unavailable");
  }
  return value;
}

function parseCapabilities(value: string): MemoryOperation[] {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed)) {
      return [];
    }
    const allowed = new Set<MemoryOperation>([
      "retrieve",
      "read",
      "append",
      "replace",
      "derive",
      "deposit",
      "project",
      "publish",
      "import",
      "export",
      "delete",
      "sync",
      "status",
      "policy-admin",
    ]);
    return [...new Set(parsed.filter((entry): entry is MemoryOperation => allowed.has(entry)))];
  } catch {
    return [];
  }
}

function assertAuthority(authority: SharingAuthority): SharingAuthority {
  const id = normalizeScopedMemoryRequiredText(authority.id, "sharing authority id");
  if (authority.kind !== "gateway-admin" && authority.kind !== "local-agent-owner") {
    throw new Error("sharing authority is unavailable");
  }
  return { kind: authority.kind, id };
}

function policyEntryMatches(params: {
  entry: MemoryPolicyEntryRow;
  authority: SharingAuthority;
  store: MemoryStoreRow;
  operation: MemoryOperation;
  nowMs: number;
}): boolean {
  const { entry, authority, store, operation, nowMs } = params;
  return (
    entry.operation === operation &&
    (entry.principal_id === "*" || entry.principal_id === authority.id) &&
    (entry.audience_kind === "*" || entry.audience_kind === store.audience_kind) &&
    (entry.audience_id === "*" || entry.audience_id === store.audience_id) &&
    (entry.expires_at === null || entry.expires_at > nowMs)
  );
}

function assertPolicyOperation(params: {
  details: ScopedStoreDetails;
  authority: SharingAuthority;
  operation: "project" | "publish";
  nowMs: number;
  explicitPublishEntry?: boolean;
}): void {
  const matching = params.details.policyEntries.filter((entry) =>
    policyEntryMatches({
      entry,
      authority: params.authority,
      store: params.details.store,
      operation: params.operation,
      nowMs: params.nowMs,
    }),
  );
  if (matching.some((entry) => entry.effect === "deny")) {
    throw new Error("sharing operation is denied by policy");
  }
  const allow = matching.some(
    (entry) =>
      entry.effect === "allow" && (!params.explicitPublishEntry || entry.entry_kind === "publish"),
  );
  if (
    params.explicitPublishEntry
      ? !allow
      : !allow && !params.details.defaultCapabilities.includes(params.operation)
  ) {
    throw new Error("sharing operation is not authorized by policy");
  }
}

function assertLocalOwnerOrAdmin(params: {
  authority: SharingAuthority;
  authorityOwnerId: string;
}): void {
  if (
    params.authority.kind !== "gateway-admin" &&
    params.authority.id !== params.authorityOwnerId
  ) {
    throw new Error("sharing authority is unavailable");
  }
}

function toBuiltinStore(details: ScopedStoreDetails): BuiltinScopedMemoryStore {
  return {
    storageRootId: details.store.storage_root_id,
    storeId: details.store.store_id,
    policyId: details.store.policy_id,
    policyRevisionId: details.policyRevisionId,
    policyRevocationEpoch: details.policyRevocationEpoch,
    sourcePolicySetId: createScopedMemorySourcePolicySetId(details.policyRevisionId),
  };
}

function expectedAudienceAuthorityKind(
  audienceKind: MemoryStoreRow["audience_kind"],
): MemoryStoreRow["scope_kind"] {
  // Agent-shared audiences remain owned by the agent control root; their
  // audience is shared, but granting publish never changes that ownership.
  return audienceKind === "agent-shared" ? "agent" : audienceKind;
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

function readStoreByAudience(params: {
  database: DatabaseSync;
  agentId: string;
  audienceKind: MemoryStoreRow["audience_kind"];
  audienceId: string;
}): ScopedStoreDetails {
  const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
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
        "root.authority_owner_id",
        "root.authority_kind",
        "root.default_capabilities_json",
        "root.backend_kind",
        "root.lifecycle_state as root_lifecycle_state",
        "policy.current_revision_id",
        "policy.revocation_epoch",
        "policy.lifecycle_state as policy_lifecycle_state",
        "policy_revision.lifecycle_state as policy_revision_lifecycle_state",
        "policy_revision.revocation_epoch as policy_revision_epoch",
      ])
      .where("store.agent_id", "=", params.agentId)
      .where("store.audience_kind", "=", params.audienceKind)
      .where("store.audience_id", "=", params.audienceId)
      .where("store.lifecycle_state", "=", "active")
      .where("root.agent_id", "=", params.agentId)
      .where("root.backend_kind", "=", "builtin")
      .where("root.lifecycle_state", "=", "active")
      .where("policy.agent_id", "=", params.agentId)
      .where("policy.lifecycle_state", "=", "active")
      .where("policy_revision.lifecycle_state", "=", "active")
      .orderBy("store.store_id"),
  ).rows;
  if (rows.length !== 1) {
    throw new Error("sharing target is unavailable");
  }
  const row = rows[0]!;
  if (
    row.revocation_epoch !== row.policy_revision_epoch ||
    row.scope_kind !== params.audienceKind ||
    row.authority_kind !== expectedAudienceAuthorityKind(params.audienceKind)
  ) {
    throw new Error("sharing target policy is unavailable");
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
  return {
    store,
    policyRevisionId: row.current_revision_id,
    policyRevocationEpoch: row.revocation_epoch,
    authorityOwnerId: row.authority_owner_id,
    defaultCapabilities: parseCapabilities(row.default_capabilities_json),
    policyEntries: listPolicyEntries(params.database, row.current_revision_id),
  };
}

function readRevisionPolicyRequirements(params: {
  database: DatabaseSync;
  revisionId: string;
}): ScopedMemoryRevisionPolicyRequirementInput[] {
  const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
  return executeSqliteQuerySync(
    params.database,
    db
      .selectFrom("memory_revision_policy_requirements")
      .selectAll()
      .where("revision_id", "=", params.revisionId)
      .orderBy("stable_policy_id"),
  ).rows.map((requirement: MemoryRevisionPolicyRequirementRow) => ({
    stablePolicyId: requirement.stable_policy_id,
    capturedRevisionId: requirement.captured_revision_id,
    expectedActiveRevisionId: requirement.expected_active_revision_id,
    expectedRevocationEpoch: requirement.expected_revocation_epoch,
  }));
}

function createAggregateSourcePolicySetId(sourcePolicySetIds: readonly string[]): string {
  return `mpset1_${hashText([...new Set(sourcePolicySetIds)].toSorted().join("\0"))}`;
}

function revisionRequirementsAreCurrent(params: {
  database: DatabaseSync;
  revisionId: string;
}): boolean {
  const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
  const rows = executeSqliteQuerySync(
    params.database,
    db
      .selectFrom("memory_revision_policy_requirements as requirement")
      .innerJoin("memory_policies as policy", "policy.policy_id", "requirement.stable_policy_id")
      .innerJoin(
        "memory_policy_revisions as expected_revision",
        "expected_revision.revision_id",
        "requirement.expected_active_revision_id",
      )
      .select([
        "policy.current_revision_id",
        "policy.revocation_epoch",
        "policy.lifecycle_state as policy_state",
        "expected_revision.lifecycle_state as expected_state",
        "requirement.expected_active_revision_id",
        "requirement.expected_revocation_epoch",
      ])
      .where("requirement.revision_id", "=", params.revisionId),
  ).rows;
  return (
    rows.length > 0 &&
    rows.every(
      (row) =>
        row.policy_state === "active" &&
        row.expected_state === "active" &&
        row.current_revision_id === row.expected_active_revision_id &&
        row.revocation_epoch === row.expected_revocation_epoch,
    )
  );
}

function readActiveSourceRevision(params: {
  database: DatabaseSync;
  agentId: string;
  sourceRevisionId: string;
  nowMs: number;
}): SourceRevision {
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
      .selectAll("store")
      .select([
        "revision.revision_id",
        "revision.resource_id",
        "revision.artifact_locator",
        "revision.content_hash",
        "revision.content_bytes",
        "revision.source_policy_set_id",
        "revision.expires_at",
        "revision.lifecycle_state as revision_lifecycle_state",
        "revision.policy_revision_id",
        "revision.policy_revocation_epoch",
        "root.path_key",
        "root.authority_owner_id",
        "root.default_capabilities_json",
        "root.backend_kind",
        "root.lifecycle_state as root_lifecycle_state",
        "policy.current_revision_id",
        "policy.revocation_epoch",
        "policy.lifecycle_state as policy_lifecycle_state",
        "policy_revision.lifecycle_state as policy_revision_lifecycle_state",
        "policy_revision.revocation_epoch as policy_revision_epoch",
      ])
      .where("revision.revision_id", "=", params.sourceRevisionId)
      .where("resource.agent_id", "=", params.agentId)
      .where("store.agent_id", "=", params.agentId)
      .where("root.agent_id", "=", params.agentId)
      .where("policy.agent_id", "=", params.agentId),
  );
  if (
    !row?.path_key ||
    row.revision_lifecycle_state !== "active" ||
    row.lifecycle_state !== "active" ||
    row.root_lifecycle_state !== "active" ||
    row.backend_kind !== "builtin" ||
    row.policy_lifecycle_state !== "active" ||
    row.policy_revision_lifecycle_state !== "active" ||
    row.revocation_epoch !== row.policy_revision_epoch ||
    row.policy_revision_id !== row.current_revision_id ||
    row.policy_revocation_epoch !== row.revocation_epoch ||
    !row.source_policy_set_id.trim() ||
    (row.expires_at !== null && row.expires_at <= params.nowMs) ||
    !revisionRequirementsAreCurrent({
      database: params.database,
      revisionId: params.sourceRevisionId,
    })
  ) {
    throw new Error("sharing source revision is unavailable");
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
  return {
    store,
    policyRevisionId: row.current_revision_id,
    policyRevocationEpoch: row.revocation_epoch,
    authorityOwnerId: row.authority_owner_id,
    defaultCapabilities: parseCapabilities(row.default_capabilities_json),
    policyEntries: listPolicyEntries(params.database, row.current_revision_id),
    revisionId: row.revision_id,
    resourceId: row.resource_id,
    artifactLocator: row.artifact_locator,
    contentHash: row.content_hash,
    contentBytes: row.content_bytes,
    sourcePolicySetId: row.source_policy_set_id,
    expiresAt: row.expires_at,
    pathKey: row.path_key,
  };
}

function readHistoricalRevisionOwner(params: {
  database: DatabaseSync;
  agentId: string;
  revisionId: string;
  unavailableMessage: string;
}): HistoricalRevisionOwner {
  const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
  const row = executeSqliteQueryTakeFirstSync(
    params.database,
    db
      .selectFrom("memory_resource_revisions as revision")
      .innerJoin("memory_resources as resource", "resource.resource_id", "revision.resource_id")
      .innerJoin("memory_stores as store", "store.store_id", "resource.store_id")
      .innerJoin("memory_storage_roots as root", "root.storage_root_id", "store.storage_root_id")
      .select(["resource.resource_id", "root.authority_owner_id"])
      .where("revision.revision_id", "=", params.revisionId)
      .where("resource.agent_id", "=", params.agentId)
      .where("store.agent_id", "=", params.agentId)
      .where("root.agent_id", "=", params.agentId),
  );
  if (!row) {
    throw new Error(params.unavailableMessage);
  }
  return {
    resourceId: row.resource_id,
    authorityOwnerId: row.authority_owner_id,
  };
}

function assertHistoricalProjectionAuthority(params: {
  database: DatabaseSync;
  projection: MemoryProjectionRow;
  authority: SharingAuthority;
}): HistoricalRevisionOwner {
  const source = readHistoricalRevisionOwner({
    database: params.database,
    agentId: params.projection.agent_id,
    revisionId: params.projection.source_revision_id,
    unavailableMessage: "projection source is unavailable",
  });
  assertAgentOwnerOrAdmin({
    database: params.database,
    agentId: params.projection.agent_id,
    authority: params.authority,
  });
  return source;
}

function assertHistoricalPostboxAuthority(params: {
  database: DatabaseSync;
  item: MemoryPostboxItemRow;
  authority: SharingAuthority;
}): void {
  const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
  const row = executeSqliteQueryTakeFirstSync(
    params.database,
    db
      .selectFrom("memory_stores as store")
      .innerJoin("memory_storage_roots as root", "root.storage_root_id", "store.storage_root_id")
      .select("root.authority_owner_id")
      .where("store.store_id", "=", params.item.target_store_id)
      .where("store.agent_id", "=", params.item.agent_id)
      .where("root.agent_id", "=", params.item.agent_id),
  );
  if (!row) {
    throw new Error("postbox item is unavailable");
  }
  assertLocalOwnerOrAdmin({
    authority: params.authority,
    authorityOwnerId: row.authority_owner_id,
  });
}

function readVerifiedSourceContent(params: {
  databasePath: string;
  source: SourceRevision;
}): string {
  const artifactPath = resolveBuiltinScopedMemoryArtifactPath({
    databasePath: params.databasePath,
    pathKey: params.source.pathKey,
    artifactLocator: params.source.artifactLocator,
  });
  let content: string;
  try {
    content = fs.readFileSync(artifactPath, "utf8");
  } catch {
    throw new Error("sharing source revision is unavailable");
  }
  if (
    Buffer.byteLength(content) !== params.source.contentBytes ||
    hashText(content) !== params.source.contentHash
  ) {
    throw new Error("sharing source revision is unavailable");
  }
  return content;
}

function assertProjectionTarget(params: {
  agentId: string;
  targetKind: ScopedMemoryProjectionTargetKind;
  targetId: string;
}): string {
  const targetId = normalizeScopedMemoryRequiredText(params.targetId, "projection target id");
  if (
    !(["conversation", "role", "agent-shared"] as const).includes(params.targetKind) ||
    targetId === "*"
  ) {
    throw new Error("projection target is unavailable");
  }
  if (params.targetKind === "agent-shared" && targetId !== params.agentId) {
    throw new Error("projection target is unavailable");
  }
  return targetId;
}

function assertProjectionAuthority(params: {
  database: DatabaseSync;
  source: SourceRevision;
  target: ScopedStoreDetails;
  authority: SharingAuthority;
  nowMs: number;
}): void {
  assertAgentOwnerOrAdmin({
    database: params.database,
    agentId: params.source.store.agent_id,
    authority: params.authority,
  });
  assertPolicyOperation({
    details: params.source,
    authority: params.authority,
    operation: "project",
    nowMs: params.nowMs,
  });
  assertPolicyOperation({
    details: params.target,
    authority: params.authority,
    operation: "publish",
    nowMs: params.nowMs,
    explicitPublishEntry: true,
  });
}

function projectRow(row: MemoryProjectionRow): ScopedMemorySharingProjection {
  return Object.freeze({
    projectionId: row.projection_id,
    sourceRevisionId: row.source_revision_id,
    targetKind: row.target_kind,
    targetAudienceId: row.target_audience_id,
    purpose: row.purpose,
    preview: row.preview,
    reviewState: row.review_state,
    expiresAt: iso(row.expires_at),
    createdAt: iso(row.created_at),
    ...(row.reviewed_at === null ? {} : { reviewedAt: iso(row.reviewed_at) }),
    ...(row.revoked_at === null ? {} : { revokedAt: iso(row.revoked_at) }),
    ...(row.supersedes_projection_id === null
      ? {}
      : { supersedesProjectionId: row.supersedes_projection_id }),
  });
}

function postboxRow(row: MemoryPostboxItemRow): ScopedMemorySharingPostboxItem {
  return Object.freeze({
    postboxItemId: row.postbox_item_id,
    sourceConversationId: row.source_conversation_id,
    provenanceLabel: row.provenance_label,
    // The review body stays private to the owner review action; list/status never emits it.
    contentPreview: `Quarantined item from ${row.provenance_label}`,
    reviewState: row.review_state,
    expiresAt: iso(row.expires_at),
    createdAt: iso(row.created_at),
    ...(row.reviewed_at === null ? {} : { reviewedAt: iso(row.reviewed_at) }),
  });
}

function tombstoneRevisionLineage(params: {
  database: DatabaseSync;
  revisionId: string;
  nowMs: number;
}): string[] {
  const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
  const revisionIds = new Set([params.revisionId]);
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
      if (revisionIds.has(child.child_revision_id)) {
        return [];
      }
      revisionIds.add(child.child_revision_id);
      return [child.child_revision_id];
    });
  }
  const ids = [...revisionIds];
  executeSqliteQuerySync(
    params.database,
    db.deleteFrom("memory_scoped_chunks").where("revision_id", "in", ids),
  );
  executeSqliteQuerySync(
    params.database,
    db
      .updateTable("memory_resource_revisions")
      .set({ lifecycle_state: "tombstoned", retired_at: params.nowMs })
      .where("revision_id", "in", ids)
      .where("lifecycle_state", "in", ["pending", "active", "quarantined"]),
  );
  return ids;
}

function readProjection(params: {
  database: DatabaseSync;
  agentId: string;
  projectionId: string;
}): MemoryProjectionRow {
  const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
  const row = executeSqliteQueryTakeFirstSync(
    params.database,
    db
      .selectFrom("memory_projections")
      .selectAll()
      .where("projection_id", "=", params.projectionId)
      .where("agent_id", "=", params.agentId),
  );
  if (!row) {
    throw new Error("projection is unavailable");
  }
  return row;
}

function assertProjectionRefreshLineage(params: {
  database: DatabaseSync;
  agentId: string;
  source: SourceRevision;
  target: ScopedStoreDetails;
  supersededProjectionId: string;
}): void {
  const superseded = readProjection({
    database: params.database,
    agentId: params.agentId,
    projectionId: params.supersededProjectionId,
  });
  if (
    superseded.review_state !== "approved" ||
    superseded.target_store_id !== params.target.store.store_id ||
    superseded.target_kind !== params.target.store.audience_kind ||
    superseded.target_audience_id !== params.target.store.audience_id
  ) {
    throw new Error("projection refresh source is unavailable");
  }
  const historicSource = readHistoricalRevisionOwner({
    database: params.database,
    agentId: params.agentId,
    revisionId: superseded.source_revision_id,
    unavailableMessage: "projection refresh source is unavailable",
  });
  if (historicSource.resourceId !== params.source.resourceId) {
    throw new Error("projection refresh source is unavailable");
  }
}

function assertCurrentProjectionReviewAuthority(params: {
  database: DatabaseSync;
  projection: MemoryProjectionRow;
  authority: SharingAuthority;
  nowMs: number;
}): { source: SourceRevision; target: ScopedStoreDetails } {
  const source = readActiveSourceRevision({
    database: params.database,
    agentId: params.projection.agent_id,
    sourceRevisionId: params.projection.source_revision_id,
    nowMs: params.nowMs,
  });
  const target = readStoreByAudience({
    database: params.database,
    agentId: params.projection.agent_id,
    audienceKind: params.projection.target_kind,
    audienceId: params.projection.target_audience_id,
  });
  if (target.store.store_id !== params.projection.target_store_id) {
    throw new Error("projection target is unavailable");
  }
  assertProjectionAuthority({
    database: params.database,
    source,
    target,
    authority: params.authority,
    nowMs: params.nowMs,
  });
  return { source, target };
}

function assertAgentOwnerOrAdmin(params: {
  database: DatabaseSync;
  agentId: string;
  authority: SharingAuthority;
}): void {
  if (params.authority.kind === "gateway-admin") {
    return;
  }
  const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
  const owner = executeSqliteQueryTakeFirstSync(
    params.database,
    db
      .selectFrom("memory_stores as store")
      .innerJoin("memory_storage_roots as root", "root.storage_root_id", "store.storage_root_id")
      .select("root.storage_root_id")
      .where("store.agent_id", "=", params.agentId)
      .where("store.scope_kind", "=", "agent")
      .where("store.audience_kind", "=", "agent")
      .where("store.audience_id", "=", params.agentId)
      .where("store.lifecycle_state", "=", "active")
      .where("root.agent_id", "=", params.agentId)
      .where("root.authority_kind", "=", "agent")
      .where("root.authority_owner_id", "=", params.authority.id)
      .where("root.lifecycle_state", "=", "active")
      .limit(1),
  );
  if (!owner) {
    throw new Error("sharing authority is unavailable");
  }
}

export type ScopedMemorySharingService = Readonly<{
  previewProjection(
    input: ProjectionPreviewInput,
  ): ScopedMemorySharingProjection & { previewId: string };
  createProjection(input: {
    agentId: string;
    authority: SharingAuthority;
    previewId: string;
  }): ScopedMemorySharingProjection;
  reviewProjection(input: {
    agentId: string;
    authority: SharingAuthority;
    projectionId: string;
    decision: "approve" | "reject";
    reason?: string;
  }): ScopedMemorySharingProjection;
  revokeProjection(input: {
    agentId: string;
    authority: SharingAuthority;
    projectionId: string;
  }): ScopedMemorySharingProjection;
  projectionImpact(input: {
    agentId: string;
    authority: SharingAuthority;
    projectionId: string;
  }): Readonly<{
    projectionId: string;
    priorExposures: readonly Readonly<{ receiptId: string; runRef: string; recordedAt: string }>[];
  }>;
  configurePostbox(input: {
    agentId: string;
    authority: SharingAuthority;
    mode: "off" | "review-required";
  }): Readonly<{ postboxMode: "off" | "review-required" }>;
  issuePostboxSourceMessageHandle(input: PostboxSourceMessage): string;
  depositPostbox(input: {
    sourceMessageHandle: string;
    sessionId: string;
    sourceConversationId: string;
  }): Readonly<{ accepted: boolean }>;
  inspectPostbox(input: {
    agentId: string;
    authority: SharingAuthority;
    postboxItemId: string;
  }): ScopedMemorySharingPostboxInspection;
  reviewPostbox(input: {
    agentId: string;
    authority: SharingAuthority;
    postboxItemId: string;
    decision: "approve" | "reject";
    reason?: string;
    editedContent?: string;
  }): ScopedMemorySharingPostboxItem;
  purgePostbox(input: {
    agentId: string;
    authority: SharingAuthority;
    postboxItemId: string;
  }): ScopedMemorySharingPostboxItem;
  status(input: { agentId: string; authority: SharingAuthority }): ScopedMemorySharingStatus;
}>;

/**
 * Plugin-owned explicit sharing control plane. It accepts only trusted operator
 * identities; model-facing runtime mutations never receive these entry points.
 */
export function createScopedMemorySharingService(
  dependencies: { now?: () => number } = {},
): ScopedMemorySharingService {
  const now = dependencies.now ?? Date.now;
  const previews = new Map<string, ProjectionPreviewRecord>();
  const postboxHandles = new Map<string, PostboxSourceMessageRecord>();

  const purgeEphemeralRecords = (nowMs: number) => {
    for (const [id, preview] of previews) {
      if (preview.expiresAtPreviewMs <= nowMs) {
        previews.delete(id);
      }
    }
    for (const [handle, record] of postboxHandles) {
      if (record.expiresAtMs <= nowMs) {
        postboxHandles.delete(handle);
      }
    }
  };

  const previewProjection = (input: ProjectionPreviewInput) => {
    const nowMs = now();
    const agentId = normalizeAgentId(input.agentId);
    const authority = assertAuthority(input.authority);
    const sourceRevisionId = normalizeScopedMemoryRequiredText(
      input.sourceRevisionId,
      "source revision id",
    );
    const targetId = assertProjectionTarget({
      agentId,
      targetKind: input.targetKind,
      targetId: input.targetId,
    });
    const purpose = normalizeScopedMemoryRequiredText(input.purpose, "projection purpose");
    const requestedExpiresAtMs = requireFutureExpiry(input.expiresAtMs, nowMs, "projection expiry");
    const supersedesProjectionId = input.supersedesProjectionId
      ? normalizeScopedMemoryRequiredText(input.supersedesProjectionId, "superseded projection id")
      : undefined;
    const { target, expiresAtMs } = withScopedMemoryDatabase(agentId, (database) => {
      const source = readActiveSourceRevision({ database, agentId, sourceRevisionId, nowMs });
      const target = readStoreByAudience({
        database,
        agentId,
        audienceKind: input.targetKind,
        audienceId: targetId,
      });
      assertProjectionAuthority({ database, source, target, authority, nowMs });
      if (supersedesProjectionId) {
        assertProjectionRefreshLineage({
          database,
          agentId,
          source,
          target,
          supersededProjectionId: supersedesProjectionId,
        });
      }
      return {
        target,
        expiresAtMs: capProjectionExpiryToSource({
          requestedExpiresAtMs,
          sourceExpiresAtMs: source.expiresAt,
        }),
      };
    });
    const previewId = createOpaqueId("mppv1");
    const preview = `Reviewed copy of revision ${sourceRevisionId.slice(0, 12)} to ${input.targetKind} ${targetId.slice(0, 24)} until ${iso(expiresAtMs)}`;
    previews.set(
      previewId,
      Object.freeze({
        previewId,
        agentId,
        authority,
        sourceRevisionId,
        targetKind: input.targetKind,
        targetId,
        targetStoreId: target.store.store_id,
        purpose,
        expiresAtMs,
        ...(supersedesProjectionId ? { supersedesProjectionId } : {}),
        expiresAtPreviewMs: nowMs + PREVIEW_TTL_MS,
      }),
    );
    purgeEphemeralRecords(nowMs);
    return Object.freeze({
      previewId,
      projectionId: previewId,
      sourceRevisionId,
      targetKind: input.targetKind,
      targetAudienceId: targetId,
      purpose,
      preview,
      reviewState: "pending" as const,
      expiresAt: iso(expiresAtMs),
      createdAt: iso(nowMs),
      ...(supersedesProjectionId ? { supersedesProjectionId } : {}),
    });
  };

  const createProjection = (input: {
    agentId: string;
    authority: SharingAuthority;
    previewId: string;
  }) => {
    const nowMs = now();
    const agentId = normalizeAgentId(input.agentId);
    const authority = assertAuthority(input.authority);
    const preview = previews.get(input.previewId);
    if (
      !preview ||
      preview.expiresAtPreviewMs <= nowMs ||
      preview.agentId !== agentId ||
      preview.authority.kind !== authority.kind ||
      preview.authority.id !== authority.id
    ) {
      throw new Error("projection preview is unavailable");
    }
    previews.delete(input.previewId);
    const projectionId = randomUUID();
    const created = withScopedMemoryDatabase(agentId, (database, databasePath) => {
      const source = readActiveSourceRevision({
        database,
        agentId,
        sourceRevisionId: preview.sourceRevisionId,
        nowMs,
      });
      const target = readStoreByAudience({
        database,
        agentId,
        audienceKind: preview.targetKind,
        audienceId: preview.targetId,
      });
      if (target.store.store_id !== preview.targetStoreId) {
        throw new Error("projection target is unavailable");
      }
      assertProjectionAuthority({ database, source, target, authority, nowMs });
      if (preview.supersedesProjectionId) {
        assertProjectionRefreshLineage({
          database,
          agentId,
          source,
          target,
          supersededProjectionId: preview.supersedesProjectionId,
        });
      }
      const content = readVerifiedSourceContent({ databasePath, source });
      const sourcePolicyRequirements = readRevisionPolicyRequirements({
        database,
        revisionId: source.revisionId,
      });
      if (sourcePolicyRequirements.length === 0) {
        throw new Error("sharing source revision is unavailable");
      }
      const expiresAtMs = capProjectionExpiryToSource({
        requestedExpiresAtMs: preview.expiresAtMs,
        sourceExpiresAtMs: source.expiresAt,
      });
      const targetStore = toBuiltinStore(target);
      const copy = createBuiltinScopedMemoryResource({
        agentId,
        store: targetStore,
        logicalLocator: `projections/${projectionId}.md`,
        content,
        lifecycleState: "pending",
        actor: { kind: "human", id: authority.id },
        expiresAt: expiresAtMs,
        inheritedPolicyRequirements: sourcePolicyRequirements,
        sourcePolicySetId: createAggregateSourcePolicySetId([
          source.sourcePolicySetId,
          targetStore.sourcePolicySetId,
        ]),
        nowMs,
      });
      const row: MemoryProjectionRow = {
        projection_id: projectionId,
        agent_id: agentId,
        source_revision_id: source.revisionId,
        target_agent_id: agentId,
        target_store_id: target.store.store_id,
        target_resource_id: copy.resourceId,
        target_revision_id: copy.revisionId,
        target_kind: preview.targetKind,
        target_audience_id: preview.targetId,
        purpose: preview.purpose,
        preview: `Reviewed copy of revision ${source.revisionId.slice(0, 12)} to ${preview.targetKind} ${preview.targetId.slice(0, 24)} until ${iso(expiresAtMs)}`,
        publisher_kind: authority.kind,
        publisher_id: authority.id,
        review_state: "pending",
        reviewer_kind: null,
        reviewer_id: null,
        review_reason: null,
        expires_at: expiresAtMs,
        revocation_behavior: "tombstone",
        supersedes_projection_id: preview.supersedesProjectionId ?? null,
        created_at: nowMs,
        reviewed_at: null,
        revoked_at: null,
      };
      try {
        runSqliteImmediateTransactionSync(database, () => {
          const db = getNodeSqliteKysely<ScopedMemoryDatabase>(database);
          const currentSource = readActiveSourceRevision({
            database,
            agentId,
            sourceRevisionId: preview.sourceRevisionId,
            nowMs,
          });
          if (currentSource.contentHash !== source.contentHash) {
            throw new Error("sharing source revision is unavailable");
          }
          // The copy expiry is immutable; never attach it if the current source cap changed.
          if (
            capProjectionExpiryToSource({
              requestedExpiresAtMs: preview.expiresAtMs,
              sourceExpiresAtMs: currentSource.expiresAt,
            }) !== expiresAtMs
          ) {
            throw new Error("sharing source revision is unavailable");
          }
          const currentTarget = readStoreByAudience({
            database,
            agentId,
            audienceKind: preview.targetKind,
            audienceId: preview.targetId,
          });
          if (currentTarget.store.store_id !== target.store.store_id) {
            throw new Error("projection target is unavailable");
          }
          assertProjectionAuthority({
            database,
            source: currentSource,
            target: currentTarget,
            authority,
            nowMs,
          });
          if (preview.supersedesProjectionId) {
            // A preview is only a proposal. Recheck its lineage in the commit
            // section so a concurrently revoked predecessor cannot be refreshed.
            assertProjectionRefreshLineage({
              database,
              agentId,
              source: currentSource,
              target: currentTarget,
              supersededProjectionId: preview.supersedesProjectionId,
            });
          }
          executeSqliteQuerySync(
            database,
            db.insertInto("memory_lineage_edges").values({
              child_revision_id: copy.revisionId,
              parent_revision_id: source.revisionId,
              edge_kind: "project",
              created_at: nowMs,
            }),
          );
          executeSqliteQuerySync(database, db.insertInto("memory_projections").values(row));
        });
      } catch (error) {
        let tombstonedRevisionIds: string[] = [];
        runSqliteImmediateTransactionSync(database, () => {
          tombstonedRevisionIds = tombstoneRevisionLineage({
            database,
            revisionId: copy.revisionId,
            nowMs,
          });
        });
        removeTombstonedBuiltinScopedMemoryArtifacts({
          database,
          databasePath,
          agentId,
          revisionIds: tombstonedRevisionIds,
        });
        throw error;
      }
      return row;
    });
    return projectRow(created);
  };

  const reviewProjection = (input: {
    agentId: string;
    authority: SharingAuthority;
    projectionId: string;
    decision: "approve" | "reject";
    reason?: string;
  }) => {
    const nowMs = now();
    const agentId = normalizeAgentId(input.agentId);
    const authority = assertAuthority(input.authority);
    const projectionId = normalizeScopedMemoryRequiredText(input.projectionId, "projection id");
    const reason = input.reason
      ? normalizeScopedMemoryRequiredText(input.reason, "review reason")
      : undefined;
    return withScopedMemoryDatabase(agentId, (database, databasePath) => {
      let tombstonedRevisionIds: string[] = [];
      if (input.decision === "reject" && !reason) {
        throw new Error("projection rejection reason is required");
      }
      runSqliteImmediateTransactionSync(database, () => {
        const db = getNodeSqliteKysely<ScopedMemoryDatabase>(database);
        const projection = readProjection({ database, agentId, projectionId });
        if (projection.review_state !== "pending" || projection.expires_at <= nowMs) {
          throw new Error("projection review is unavailable");
        }
        if (input.decision === "approve") {
          assertCurrentProjectionReviewAuthority({ database, projection, authority, nowMs });
          const activated = executeSqliteQuerySync(
            database,
            db
              .updateTable("memory_resource_revisions")
              .set({ lifecycle_state: "active", activated_at: nowMs })
              .where("revision_id", "=", projection.target_revision_id)
              .where("lifecycle_state", "=", "pending"),
          );
          if (activated.numAffectedRows !== 1n) {
            throw new Error("projection review is unavailable");
          }
          const reviewed = executeSqliteQuerySync(
            database,
            db
              .updateTable("memory_projections")
              .set({
                review_state: "approved",
                reviewer_kind: authority.kind,
                reviewer_id: authority.id,
                reviewed_at: nowMs,
              })
              .where("projection_id", "=", projection.projection_id)
              .where("review_state", "=", "pending"),
          );
          if (reviewed.numAffectedRows !== 1n) {
            throw new Error("projection review is unavailable");
          }
        } else {
          assertHistoricalProjectionAuthority({ database, projection, authority });
          const rejected = executeSqliteQuerySync(
            database,
            db
              .updateTable("memory_projections")
              .set({
                review_state: "rejected",
                reviewer_kind: authority.kind,
                reviewer_id: authority.id,
                review_reason: reason!,
                reviewed_at: nowMs,
              })
              .where("projection_id", "=", projection.projection_id)
              .where("review_state", "=", "pending"),
          );
          if (rejected.numAffectedRows !== 1n) {
            throw new Error("projection review is unavailable");
          }
          tombstonedRevisionIds = tombstoneRevisionLineage({
            database,
            revisionId: projection.target_revision_id,
            nowMs,
          });
        }
      });
      if (tombstonedRevisionIds.length > 0) {
        removeTombstonedBuiltinScopedMemoryArtifacts({
          database,
          databasePath,
          agentId,
          revisionIds: tombstonedRevisionIds,
        });
      }
      return projectRow(readProjection({ database, agentId, projectionId }));
    });
  };

  const revokeProjection = (input: {
    agentId: string;
    authority: SharingAuthority;
    projectionId: string;
  }) => {
    const nowMs = now();
    const agentId = normalizeAgentId(input.agentId);
    const authority = assertAuthority(input.authority);
    const projectionId = normalizeScopedMemoryRequiredText(input.projectionId, "projection id");
    return withScopedMemoryDatabase(agentId, (database, databasePath) => {
      let tombstonedRevisionIds: string[] = [];
      runSqliteImmediateTransactionSync(database, () => {
        const projection = readProjection({ database, agentId, projectionId });
        if (projection.review_state !== "approved") {
          throw new Error("projection revocation is unavailable");
        }
        assertHistoricalProjectionAuthority({ database, projection, authority });
        const db = getNodeSqliteKysely<ScopedMemoryDatabase>(database);
        const revoked = executeSqliteQuerySync(
          database,
          db
            .updateTable("memory_projections")
            .set({ review_state: "revoked", revoked_at: nowMs })
            .where("projection_id", "=", projection.projection_id)
            .where("review_state", "=", "approved"),
        );
        if (revoked.numAffectedRows !== 1n) {
          throw new Error("projection revocation is unavailable");
        }
        tombstonedRevisionIds = tombstoneRevisionLineage({
          database,
          revisionId: projection.target_revision_id,
          nowMs,
        });
      });
      removeTombstonedBuiltinScopedMemoryArtifacts({
        database,
        databasePath,
        agentId,
        revisionIds: tombstonedRevisionIds,
      });
      return projectRow(readProjection({ database, agentId, projectionId }));
    });
  };

  const projectionImpact = (input: {
    agentId: string;
    authority: SharingAuthority;
    projectionId: string;
  }) => {
    const agentId = normalizeAgentId(input.agentId);
    const authority = assertAuthority(input.authority);
    const projectionId = normalizeScopedMemoryRequiredText(input.projectionId, "projection id");
    return withScopedMemoryDatabase(agentId, (database) => {
      const projection = readProjection({ database, agentId, projectionId });
      assertHistoricalProjectionAuthority({ database, projection, authority });
      const db = getNodeSqliteKysely<ScopedMemoryDatabase>(database);
      const rows = executeSqliteQuerySync(
        database,
        db
          .selectFrom("memory_projection_exposures as exposure")
          .innerJoin(
            "memory_exposure_receipts as receipt",
            "receipt.receipt_id",
            "exposure.exposure_receipt_id",
          )
          .select(["receipt.receipt_id", "receipt.run_id", "exposure.recorded_at"])
          .where("exposure.projection_id", "=", projectionId)
          .orderBy("exposure.recorded_at")
          .orderBy("receipt.receipt_id"),
      ).rows;
      return Object.freeze({
        projectionId,
        priorExposures: Object.freeze(
          rows.map((row) =>
            Object.freeze({
              receiptId: row.receipt_id,
              runRef: `sha256:${hashText(row.run_id).slice(0, 16)}`,
              recordedAt: iso(row.recorded_at),
            }),
          ),
        ),
      });
    });
  };

  const configurePostbox = (input: {
    agentId: string;
    authority: SharingAuthority;
    mode: "off" | "review-required";
  }) => {
    const nowMs = now();
    const agentId = normalizeAgentId(input.agentId);
    const authority = assertAuthority(input.authority);
    const mode = assertPostboxMode(input.mode);
    return withScopedMemoryDatabase(agentId, (database) => {
      assertAgentOwnerOrAdmin({ database, agentId, authority });
      const db = getNodeSqliteKysely<ScopedMemoryDatabase>(database);
      runSqliteImmediateTransactionSync(database, () => {
        const existing = executeSqliteQueryTakeFirstSync(
          database,
          db
            .selectFrom("memory_sharing_settings")
            .select(["agent_id", "rate_limit_window_ms", "rate_limit_max_items"])
            .where("agent_id", "=", agentId),
        );
        if (existing) {
          executeSqliteQuerySync(
            database,
            db
              .updateTable("memory_sharing_settings")
              .set({ postbox_mode: mode, updated_at: nowMs })
              .where("agent_id", "=", agentId),
          );
        } else {
          executeSqliteQuerySync(
            database,
            db.insertInto("memory_sharing_settings").values({
              agent_id: agentId,
              postbox_mode: mode,
              rate_limit_window_ms: DEFAULT_POSTBOX_RATE_LIMIT_WINDOW_MS,
              rate_limit_max_items: DEFAULT_POSTBOX_RATE_LIMIT_MAX_ITEMS,
              created_at: nowMs,
              updated_at: nowMs,
            }),
          );
        }
      });
      return Object.freeze({ postboxMode: mode });
    });
  };

  const issuePostboxSourceMessageHandle = (input: PostboxSourceMessage): string => {
    const nowMs = now();
    const agentId = normalizeAgentId(input.agentId);
    const content = normalizeScopedMemoryRequiredText(input.content, "postbox source content");
    const expiresAtMs = requireFutureExpiry(
      input.expiresAtMs,
      nowMs,
      "postbox source handle expiry",
    );
    if (expiresAtMs - nowMs > POSTBOX_HANDLE_TTL_MS) {
      throw new Error("postbox source handle expiry is unavailable");
    }
    const message: PostboxSourceMessage = {
      ...input,
      agentId,
      sessionId: normalizeScopedMemoryRequiredText(input.sessionId, "postbox session id"),
      sourceConversationId: normalizeScopedMemoryRequiredText(
        input.sourceConversationId,
        "postbox source conversation id",
      ),
      sourceActor: {
        ...input.sourceActor,
        id: normalizeScopedMemoryRequiredText(input.sourceActor.id, "postbox source actor id"),
        evidenceRevision: normalizeScopedMemoryRequiredText(
          input.sourceActor.evidenceRevision,
          "postbox source evidence revision",
        ),
      },
      targetUserId: normalizeScopedMemoryRequiredText(input.targetUserId, "postbox target user id"),
      targetUserEvidenceRevision: normalizeScopedMemoryRequiredText(
        input.targetUserEvidenceRevision,
        "postbox target user evidence revision",
      ),
      content,
      expiresAtMs,
    };
    const handle = createOpaqueId("mph1");
    postboxHandles.set(handle, Object.freeze({ handle, message, expiresAtMs }));
    purgeEphemeralRecords(nowMs);
    return handle;
  };

  const depositPostbox = (input: {
    sourceMessageHandle: string;
    sessionId: string;
    sourceConversationId: string;
  }) => {
    const nowMs = now();
    const sourceMessageHandle = normalizeScopedMemoryRequiredText(
      input.sourceMessageHandle,
      "postbox source message handle",
    );
    const sessionId = normalizeScopedMemoryRequiredText(input.sessionId, "postbox session id");
    const sourceConversationId = normalizeScopedMemoryRequiredText(
      input.sourceConversationId,
      "postbox source conversation id",
    );
    const record = postboxHandles.get(sourceMessageHandle);
    // A handle is a one-shot server capability. Consume it before any database
    // work so a failed or cross-channel attempt cannot be replayed later.
    postboxHandles.delete(sourceMessageHandle);
    if (
      !record ||
      record.expiresAtMs <= nowMs ||
      record.message.sessionId !== sessionId ||
      record.message.sourceConversationId !== sourceConversationId
    ) {
      throw new Error("postbox deposit is unavailable");
    }
    const { message } = record;
    return withScopedMemoryDatabase(message.agentId, (database) => {
      const db = getNodeSqliteKysely<ScopedMemoryDatabase>(database);
      const handleHash = hashText(record.handle);
      let accepted = false;
      runSqliteImmediateTransactionSync(database, () => {
        // Re-read every mutable decision row in the commit section. A setting
        // or target revocation between handle issuance and deposit must win.
        const target = readStoreByAudience({
          database,
          agentId: message.agentId,
          audienceKind: "user",
          audienceId: message.targetUserId,
        });
        const settings = executeSqliteQueryTakeFirstSync(
          database,
          db
            .selectFrom("memory_sharing_settings")
            .selectAll()
            .where("agent_id", "=", message.agentId),
        );
        if (!settings || settings.postbox_mode !== "review-required") {
          return;
        }
        const duplicate = executeSqliteQueryTakeFirstSync(
          database,
          db
            .selectFrom("memory_postbox_items")
            .select("postbox_item_id")
            .where("agent_id", "=", message.agentId)
            .where("source_message_handle_hash", "=", handleHash),
        );
        if (duplicate) {
          throw new Error("postbox deposit is unavailable");
        }
        const rate = executeSqliteQueryTakeFirstSync(
          database,
          db
            .selectFrom("memory_postbox_rate_limits")
            .selectAll()
            .where("agent_id", "=", message.agentId)
            .where("source_conversation_id", "=", message.sourceConversationId)
            .where("target_store_id", "=", target.store.store_id),
        );
        const inWindow =
          rate !== undefined && nowMs - rate.window_started_at < settings.rate_limit_window_ms;
        const count = inWindow && rate ? rate.accepted_count : 0;
        if (count >= settings.rate_limit_max_items) {
          if (rate) {
            executeSqliteQuerySync(
              database,
              db
                .updateTable("memory_postbox_rate_limits")
                .set({
                  dropped_count: rate.dropped_count + 1,
                  last_dropped_at: nowMs,
                  updated_at: nowMs,
                })
                .where("agent_id", "=", message.agentId)
                .where("source_conversation_id", "=", message.sourceConversationId)
                .where("target_store_id", "=", target.store.store_id),
            );
          }
          return;
        }
        if (rate && inWindow) {
          executeSqliteQuerySync(
            database,
            db
              .updateTable("memory_postbox_rate_limits")
              .set({ accepted_count: count + 1, last_accepted_at: nowMs, updated_at: nowMs })
              .where("agent_id", "=", message.agentId)
              .where("source_conversation_id", "=", message.sourceConversationId)
              .where("target_store_id", "=", target.store.store_id),
          );
        } else if (rate) {
          executeSqliteQuerySync(
            database,
            db
              .updateTable("memory_postbox_rate_limits")
              .set({
                window_started_at: nowMs,
                accepted_count: 1,
                dropped_count: 0,
                last_accepted_at: nowMs,
                last_dropped_at: null,
                updated_at: nowMs,
              })
              .where("agent_id", "=", message.agentId)
              .where("source_conversation_id", "=", message.sourceConversationId)
              .where("target_store_id", "=", target.store.store_id),
          );
        } else {
          executeSqliteQuerySync(
            database,
            db.insertInto("memory_postbox_rate_limits").values({
              agent_id: message.agentId,
              source_conversation_id: message.sourceConversationId,
              target_store_id: target.store.store_id,
              window_started_at: nowMs,
              accepted_count: 1,
              dropped_count: 0,
              last_accepted_at: nowMs,
              last_dropped_at: null,
              updated_at: nowMs,
            }),
          );
        }
        const itemId = randomUUID();
        executeSqliteQuerySync(
          database,
          db.insertInto("memory_postbox_items").values({
            postbox_item_id: itemId,
            agent_id: message.agentId,
            target_agent_id: message.agentId,
            target_store_id: target.store.store_id,
            target_kind: "user",
            target_audience_id: message.targetUserId,
            target_user_id: message.targetUserId,
            target_user_evidence_revision: message.targetUserEvidenceRevision,
            target_resource_id: null,
            target_revision_id: null,
            source_conversation_id: message.sourceConversationId,
            source_message_handle_hash: handleHash,
            source_event_id: message.sourceEventId ?? null,
            source_actor_kind: message.sourceActor.kind,
            source_actor_id: message.sourceActor.id,
            source_evidence_revision: message.sourceActor.evidenceRevision,
            provenance_label: `conversation:${message.sourceConversationId.slice(0, 32)}`,
            content: message.content,
            content_hash: hashText(message.content),
            review_content: message.content,
            review_content_hash: hashText(message.content),
            review_state: "pending",
            reviewer_kind: null,
            reviewer_id: null,
            review_reason: null,
            expires_at: message.expiresAtMs,
            created_at: nowMs,
            updated_at: nowMs,
            reviewed_at: null,
            purged_at: null,
          }),
        );
        accepted = true;
      });
      return Object.freeze({ accepted });
    });
  };

  const readPostboxItem = (params: {
    database: DatabaseSync;
    agentId: string;
    postboxItemId: string;
  }): MemoryPostboxItemRow => {
    const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
    const row = executeSqliteQueryTakeFirstSync(
      params.database,
      db
        .selectFrom("memory_postbox_items")
        .selectAll()
        .where("agent_id", "=", params.agentId)
        .where("postbox_item_id", "=", params.postboxItemId),
    );
    if (!row) {
      throw new Error("postbox item is unavailable");
    }
    return row;
  };

  const assertPostboxReviewAuthority = (params: {
    database: DatabaseSync;
    item: MemoryPostboxItemRow;
    authority: SharingAuthority;
  }): ScopedStoreDetails => {
    const target = readStoreByAudience({
      database: params.database,
      agentId: params.item.agent_id,
      audienceKind: "user",
      audienceId: params.item.target_user_id,
    });
    if (target.store.store_id !== params.item.target_store_id) {
      throw new Error("postbox item is unavailable");
    }
    assertLocalOwnerOrAdmin({
      authority: params.authority,
      authorityOwnerId: target.authorityOwnerId,
    });
    return target;
  };

  const inspectPostbox = (input: {
    agentId: string;
    authority: SharingAuthority;
    postboxItemId: string;
  }) => {
    const nowMs = now();
    const agentId = normalizeAgentId(input.agentId);
    const authority = assertAuthority(input.authority);
    const postboxItemId = normalizeScopedMemoryRequiredText(input.postboxItemId, "postbox item id");
    return withScopedMemoryDatabase(agentId, (database) => {
      const item = readPostboxItem({ database, agentId, postboxItemId });
      // This is the sole body-bearing owner action; status/list remains redacted.
      assertHistoricalPostboxAuthority({ database, item, authority });
      if (item.review_state !== "pending" || item.expires_at <= nowMs) {
        throw new Error("postbox inspection is unavailable");
      }
      return Object.freeze({
        postboxItemId: item.postbox_item_id,
        reviewContent: item.review_content,
        expiresAt: iso(item.expires_at),
      });
    });
  };

  const reviewPostbox = (input: {
    agentId: string;
    authority: SharingAuthority;
    postboxItemId: string;
    decision: "approve" | "reject";
    reason?: string;
    editedContent?: string;
  }) => {
    const nowMs = now();
    const agentId = normalizeAgentId(input.agentId);
    const authority = assertAuthority(input.authority);
    const postboxItemId = normalizeScopedMemoryRequiredText(input.postboxItemId, "postbox item id");
    const reason = input.reason
      ? normalizeScopedMemoryRequiredText(input.reason, "postbox review reason")
      : undefined;
    return withScopedMemoryDatabase(agentId, (database, databasePath) => {
      if (input.decision === "reject" && !reason) {
        throw new Error("postbox rejection reason is required");
      }
      if (input.decision === "reject") {
        const db = getNodeSqliteKysely<ScopedMemoryDatabase>(database);
        runSqliteImmediateTransactionSync(database, () => {
          const item = readPostboxItem({ database, agentId, postboxItemId });
          if (item.review_state !== "pending" || item.expires_at <= nowMs) {
            throw new Error("postbox review is unavailable");
          }
          // Rejecting a stranded item must remain possible after a target policy
          // revocation; use immutable target ownership instead of current policy.
          assertHistoricalPostboxAuthority({ database, item, authority });
          const rejected = executeSqliteQuerySync(
            database,
            db
              .updateTable("memory_postbox_items")
              .set({
                review_state: "rejected",
                reviewer_kind: authority.kind,
                reviewer_id: authority.id,
                review_reason: reason!,
                reviewed_at: nowMs,
                updated_at: nowMs,
              })
              .where("postbox_item_id", "=", item.postbox_item_id)
              .where("review_state", "=", "pending"),
          );
          if (rejected.numAffectedRows !== 1n) {
            throw new Error("postbox review is unavailable");
          }
        });
        return postboxRow(readPostboxItem({ database, agentId, postboxItemId }));
      }

      const item = readPostboxItem({ database, agentId, postboxItemId });
      if (item.review_state !== "pending" || item.expires_at <= nowMs) {
        throw new Error("postbox review is unavailable");
      }
      const target = assertPostboxReviewAuthority({ database, item, authority });
      const editedContent =
        input.editedContent === undefined
          ? item.review_content
          : normalizeScopedMemoryRequiredText(input.editedContent, "postbox reviewed content");
      // Prepare the copy outside the immediate transaction. It stays pending and
      // therefore unreadable until the final review transition attaches it.
      const copy = createBuiltinScopedMemoryResource({
        agentId,
        store: toBuiltinStore(target),
        logicalLocator: `postbox/${item.postbox_item_id}.md`,
        content: editedContent,
        lifecycleState: "pending",
        actor: { kind: "human", id: authority.id },
        expiresAt: item.expires_at,
        nowMs,
      });
      try {
        runSqliteImmediateTransactionSync(database, () => {
          const db = getNodeSqliteKysely<ScopedMemoryDatabase>(database);
          const current = readPostboxItem({ database, agentId, postboxItemId });
          if (current.review_state !== "pending" || current.expires_at <= nowMs) {
            throw new Error("postbox review is unavailable");
          }
          const currentTarget = assertPostboxReviewAuthority({
            database,
            item: current,
            authority,
          });
          if (currentTarget.store.store_id !== target.store.store_id) {
            throw new Error("postbox review is unavailable");
          }
          const activated = executeSqliteQuerySync(
            database,
            db
              .updateTable("memory_resource_revisions")
              .set({ lifecycle_state: "active", activated_at: nowMs })
              .where("revision_id", "=", copy.revisionId)
              .where("lifecycle_state", "=", "pending"),
          );
          if (activated.numAffectedRows !== 1n) {
            throw new Error("postbox review is unavailable");
          }
          const approved = executeSqliteQuerySync(
            database,
            db
              .updateTable("memory_postbox_items")
              .set({
                target_resource_id: copy.resourceId,
                target_revision_id: copy.revisionId,
                review_content: editedContent,
                review_content_hash: hashText(editedContent),
                review_state: "approved",
                reviewer_kind: authority.kind,
                reviewer_id: authority.id,
                reviewed_at: nowMs,
                updated_at: nowMs,
              })
              .where("postbox_item_id", "=", current.postbox_item_id)
              .where("review_state", "=", "pending"),
          );
          if (approved.numAffectedRows !== 1n) {
            throw new Error("postbox review is unavailable");
          }
        });
      } catch (error) {
        let tombstonedRevisionIds: string[] = [];
        runSqliteImmediateTransactionSync(database, () => {
          tombstonedRevisionIds = tombstoneRevisionLineage({
            database,
            revisionId: copy.revisionId,
            nowMs,
          });
        });
        removeTombstonedBuiltinScopedMemoryArtifacts({
          database,
          databasePath,
          agentId,
          revisionIds: tombstonedRevisionIds,
        });
        throw error;
      }
      return postboxRow(readPostboxItem({ database, agentId, postboxItemId }));
    });
  };

  const purgePostbox = (input: {
    agentId: string;
    authority: SharingAuthority;
    postboxItemId: string;
  }) => {
    const nowMs = now();
    const agentId = normalizeAgentId(input.agentId);
    const authority = assertAuthority(input.authority);
    const postboxItemId = normalizeScopedMemoryRequiredText(input.postboxItemId, "postbox item id");
    return withScopedMemoryDatabase(agentId, (database, databasePath) => {
      let tombstonedRevisionIds: string[] = [];
      runSqliteImmediateTransactionSync(database, () => {
        const item = readPostboxItem({ database, agentId, postboxItemId });
        // A revoked target policy must not strand sensitive quarantine material.
        assertHistoricalPostboxAuthority({ database, item, authority });
        if (item.review_state === "purged") {
          if (item.target_revision_id) {
            tombstonedRevisionIds = tombstoneRevisionLineage({
              database,
              revisionId: item.target_revision_id,
              nowMs,
            });
          }
          return;
        }
        if (!(["pending", "approved", "rejected"] as const).includes(item.review_state)) {
          throw new Error("postbox item is unavailable");
        }
        if (item.target_revision_id) {
          tombstonedRevisionIds = tombstoneRevisionLineage({
            database,
            revisionId: item.target_revision_id,
            nowMs,
          });
        }
        const db = getNodeSqliteKysely<ScopedMemoryDatabase>(database);
        const purged = executeSqliteQuerySync(
          database,
          db
            .updateTable("memory_postbox_items")
            .set({
              content: PURGED_POSTBOX_CONTENT,
              content_hash: hashText(PURGED_POSTBOX_CONTENT),
              review_content: PURGED_POSTBOX_CONTENT,
              review_content_hash: hashText(PURGED_POSTBOX_CONTENT),
              review_state: "purged",
              purged_at: nowMs,
              updated_at: nowMs,
            })
            .where("postbox_item_id", "=", item.postbox_item_id)
            .where("review_state", "in", ["pending", "approved", "rejected"]),
        );
        if (purged.numAffectedRows !== 1n) {
          throw new Error("postbox item is unavailable");
        }
      });
      // The durable tombstone/redaction commits first. A failed unlink leaves the
      // item purged, and a retry repeats cleanup from the immutable lineage rows.
      removeTombstonedBuiltinScopedMemoryArtifacts({
        database,
        databasePath,
        agentId,
        revisionIds: tombstonedRevisionIds,
      });
      return postboxRow(readPostboxItem({ database, agentId, postboxItemId }));
    });
  };

  const status = (input: { agentId: string; authority: SharingAuthority }) => {
    const agentId = normalizeAgentId(input.agentId);
    const authority = assertAuthority(input.authority);
    return withScopedMemoryDatabase(agentId, (database) => {
      assertAgentOwnerOrAdmin({ database, agentId, authority });
      const db = getNodeSqliteKysely<ScopedMemoryDatabase>(database);
      const settings = executeSqliteQueryTakeFirstSync(
        database,
        db
          .selectFrom("memory_sharing_settings")
          .select("postbox_mode")
          .where("agent_id", "=", agentId),
      );
      const projections = executeSqliteQuerySync(
        database,
        db
          .selectFrom("memory_projections")
          .selectAll()
          .where("agent_id", "=", agentId)
          .orderBy("created_at", "desc")
          .orderBy("projection_id", "desc"),
      ).rows;
      const postboxItems = executeSqliteQuerySync(
        database,
        db
          .selectFrom("memory_postbox_items")
          .selectAll()
          .where("agent_id", "=", agentId)
          .orderBy("created_at", "desc")
          .orderBy("postbox_item_id", "desc"),
      ).rows;
      // The caller has already proven control-root ownership for this agent.
      // It may project an explicitly projectable private source it does not own,
      // so hiding that redacted lifecycle record would strand its review/revocation path.
      const visibleProjectionRows = projections;
      const visiblePostboxRows =
        authority.kind === "gateway-admin"
          ? postboxItems
          : postboxItems.filter((item) => {
              try {
                assertHistoricalPostboxAuthority({ database, item, authority });
                return true;
              } catch {
                return false;
              }
            });
      return Object.freeze({
        postboxMode: settings?.postbox_mode ?? "off",
        projections: Object.freeze(visibleProjectionRows.map(projectRow)),
        postboxItems: Object.freeze(visiblePostboxRows.map(postboxRow)),
      });
    });
  };

  return Object.freeze({
    previewProjection,
    createProjection,
    reviewProjection,
    revokeProjection,
    projectionImpact,
    configurePostbox,
    issuePostboxSourceMessageHandle,
    depositPostbox,
    inspectPostbox,
    reviewPostbox,
    purgePostbox,
    status,
  });
}
