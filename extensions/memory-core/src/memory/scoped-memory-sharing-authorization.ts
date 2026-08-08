import fs from "node:fs";
import type { DatabaseSync } from "node:sqlite";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
} from "openclaw/plugin-sdk/sqlite-runtime";
import type {
  MemoryPolicyEntryRow,
  MemoryPostboxItemRow,
  MemoryProjectionRow,
  MemoryRevisionPolicyRequirementRow,
  MemoryStoreRow,
  ScopedMemoryDatabase,
  ScopedMemoryProjectionTargetKind,
} from "./scoped-memory-db.js";
import { resolveBuiltinScopedMemoryArtifactPath } from "./scoped-memory-resource-artifacts.js";
import type { ScopedMemoryRevisionPolicyRequirementInput } from "./scoped-memory-resources.js";
import {
  assertLocalOwnerOrAdmin,
  assertPolicyOperation,
  hashText,
  iso,
  parseCapabilities,
  type HistoricalRevisionOwner,
  type ScopedMemorySharingPostboxItem,
  type ScopedMemorySharingProjection,
  type ScopedStoreDetails,
  type SharingAuthority,
  type SourceRevision,
} from "./scoped-memory-sharing-contracts.js";
import { normalizeScopedMemoryRequiredText } from "./scoped-memory-store.js";

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

export function readStoreByAudience(params: {
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

export function readRevisionPolicyRequirements(params: {
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

export function createAggregateSourcePolicySetId(sourcePolicySetIds: readonly string[]): string {
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

export function readActiveSourceRevision(params: {
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

export function assertHistoricalProjectionAuthority(params: {
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

export function assertHistoricalPostboxAuthority(params: {
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

export function readVerifiedSourceContent(params: {
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

export function assertProjectionTarget(params: {
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

export function assertProjectionAuthority(params: {
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

export function projectRow(row: MemoryProjectionRow): ScopedMemorySharingProjection {
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

export function postboxRow(row: MemoryPostboxItemRow): ScopedMemorySharingPostboxItem {
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

export function tombstoneRevisionLineage(params: {
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

export function readProjection(params: {
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

export function assertProjectionRefreshLineage(params: {
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

export function assertCurrentProjectionReviewAuthority(params: {
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

export function assertAgentOwnerOrAdmin(params: {
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
