import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import {
  ensureOpenClawAgentScopedMemorySchema,
  openOpenClawAgentDatabase,
} from "openclaw/plugin-sdk/sqlite-runtime";

export type ScopedMemoryLifecycleState = "pending" | "active" | "quarantined" | "tombstoned";
export type ScopedMemoryScopeKind =
  | "user"
  | "conversation"
  | "role"
  | "agent-shared"
  | "agent"
  | "internal";
export type ScopedMemoryActorKind = "human" | "agent" | "service" | "system" | "unattributed";

type MemoryStorageRootRow = {
  storage_root_id: string;
  agent_id: string;
  backend_kind: "builtin" | "qmd" | "alternate";
  opaque_locator: string;
  path_key_version: number;
  path_key: string | null;
  authority_kind: ScopedMemoryScopeKind;
  authority_owner_id: string;
  default_capabilities_json: string;
  lifecycle_state: ScopedMemoryLifecycleState;
  created_at: number;
  updated_at: number;
};

export type MemoryStoreRow = {
  store_id: string;
  agent_id: string;
  storage_root_id: string;
  policy_id: string;
  scope_kind: ScopedMemoryScopeKind;
  audience_kind: ScopedMemoryScopeKind;
  audience_id: string;
  lifecycle_state: ScopedMemoryLifecycleState;
  created_at: number;
  updated_at: number;
};

type MemoryPolicyRow = {
  policy_id: string;
  agent_id: string;
  current_revision_id: string;
  revocation_epoch: number;
  lifecycle_state: "active" | "revoked";
  created_at: number;
  updated_at: number;
};

type MemoryPolicyRevisionRow = {
  revision_id: string;
  policy_id: string;
  revision_number: number;
  revocation_epoch: number;
  lifecycle_state: "active" | "superseded" | "revoked";
  actor_kind: ScopedMemoryActorKind;
  actor_id: string | null;
  reason: string;
  created_at: number;
};

export type MemoryPolicyEntryRow = {
  entry_id: string;
  policy_revision_id: string;
  entry_kind: "placement" | "exception" | "publish";
  effect: "allow" | "deny";
  principal_id: string;
  audience_kind: ScopedMemoryScopeKind | "*";
  audience_id: string;
  operation:
    | "retrieve"
    | "read"
    | "append"
    | "replace"
    | "derive"
    | "deposit"
    | "project"
    | "publish"
    | "import"
    | "export"
    | "delete"
    | "sync"
    | "status"
    | "policy-admin";
  grantor_principal_id: string;
  reason: string;
  expires_at: number | null;
  created_at: number;
};

type MemoryResourceRow = {
  resource_id: string;
  agent_id: string;
  store_id: string;
  logical_locator: string;
  source: "memory" | "sessions";
  created_at: number;
};

type MemoryResourceRevisionRow = {
  revision_id: string;
  resource_id: string;
  revision_number: number;
  artifact_locator: string;
  content_hash: string;
  content_bytes: number;
  policy_revision_id: string;
  policy_revocation_epoch: number;
  source_policy_set_id: string;
  lifecycle_state: ScopedMemoryLifecycleState;
  actor_kind: ScopedMemoryActorKind;
  actor_id: string | null;
  expires_at: number | null;
  created_at: number;
  activated_at: number | null;
  retired_at: number | null;
};

export type MemoryRevisionPolicyRequirementRow = {
  revision_id: string;
  stable_policy_id: string;
  captured_revision_id: string;
  expected_active_revision_id: string;
  expected_revocation_epoch: number;
  created_at: number;
};

export type MemoryLineageEdgeRow = {
  child_revision_id: string;
  parent_revision_id: string;
  edge_kind: "revision" | "derive" | "project" | "publish";
  created_at: number;
};

type MemoryResourceSubjectRow = {
  revision_id: string;
  subject_kind: "person" | "project" | "conversation" | "topic";
  subject_id: string;
  evidence_revision: string;
  lifecycle_state: "current" | "superseded";
  created_at: number;
};

type MemoryScopedChunkRow = {
  chunk_id: string;
  revision_id: string;
  chunk_ordinal: number;
  start_line: number;
  end_line: number;
  text: string;
  content_hash: string;
  model: string;
  updated_at: number;
};

type MemoryScopedChunkVectorRow = {
  chunk_id: string;
  model: string;
  dims: number;
  embedding: string;
  updated_at: number;
};

type MemoryExposureReceiptRow = {
  receipt_id: string;
  context_fingerprint: string;
  plan_id: string;
  run_id: string;
  run_exposure_revision: string;
  source_policy_set_id: string;
  exposed_revision_handles_json: string;
  recorded_at: number;
};

type MemoryEgressReceiptRow = {
  receipt_id: string;
  exposure_receipt_id: string;
  context_fingerprint: string;
  plan_id: string;
  run_id: string;
  run_exposure_revision: string;
  source_policy_set_id: string;
  allowed_audiences_json: string;
  delivery_revision: string;
  egress_registry_revision: string;
  expires_at: number;
  recorded_at: number;
};

type MemoryWriteIntentRow = {
  intent_id: string;
  idempotency_key: string;
  mutation_id: string;
  agent_id: string;
  request_id: string;
  run_id: string;
  context_fingerprint: string;
  plan_id: string;
  mutation_kind:
    | "remember"
    | "append"
    | "replace"
    | "delete"
    | "tombstone"
    | "derive"
    | "deposit"
    | "project"
    | "publish"
    | "import"
    | "sync"
    | "admin-reclassify";
  store_id: string;
  resource_id: string | null;
  pending_revision_id: string | null;
  staged_locator: string | null;
  final_locator: string | null;
  content_hash: string | null;
  content_bytes: number | null;
  state: "pending" | "renamed" | "active" | "quarantined" | "tombstoned";
  created_at: number;
  updated_at: number;
  activated_at: number | null;
  indexed_at: number | null;
};

type MemoryAuditOutboxRow = {
  event_id: string;
  intent_id: string;
  agent_id: string;
  request_id: string;
  run_id: string;
  actor_ref: string;
  subject_ref: string;
  operation: string;
  resource_revision_id: string | null;
  content_hash: string | null;
  decision: "pending" | "committed" | "quarantined" | "tombstoned";
  reason_code: string;
  state: "pending" | "delivered";
  attempts: number;
  created_at: number;
  updated_at: number;
  delivered_at: number | null;
};

export type ScopedMemoryDatabase = {
  memory_storage_roots: MemoryStorageRootRow;
  memory_stores: MemoryStoreRow;
  memory_policies: MemoryPolicyRow;
  memory_policy_revisions: MemoryPolicyRevisionRow;
  memory_policy_entries: MemoryPolicyEntryRow;
  memory_resources: MemoryResourceRow;
  memory_resource_revisions: MemoryResourceRevisionRow;
  memory_revision_policy_requirements: MemoryRevisionPolicyRequirementRow;
  memory_lineage_edges: MemoryLineageEdgeRow;
  memory_resource_subjects: MemoryResourceSubjectRow;
  memory_scoped_chunks: MemoryScopedChunkRow;
  memory_scoped_chunk_vectors: MemoryScopedChunkVectorRow;
  memory_exposure_receipts: MemoryExposureReceiptRow;
  memory_egress_receipts: MemoryEgressReceiptRow;
  memory_write_intents: MemoryWriteIntentRow;
  memory_audit_outbox: MemoryAuditOutboxRow;
};

export function withScopedMemoryDatabase<T>(
  agentId: string,
  callback: (db: DatabaseSync, databasePath: string) => T,
): T {
  const database = openOpenClawAgentDatabase({ agentId });
  ensureOpenClawAgentScopedMemorySchema(database.db);
  return callback(database.db, database.path);
}

/** Filesystem owner for opaque builtin memory-store directories. */
export function resolveScopedMemoryArtifactBase(databasePath: string): string {
  return path.join(path.dirname(databasePath), "memory-scopes", "v1");
}
