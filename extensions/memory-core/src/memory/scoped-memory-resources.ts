import { createHash, randomBytes, randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { normalizeAgentId } from "openclaw/plugin-sdk/routing";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
  runSqliteImmediateTransactionSync,
} from "openclaw/plugin-sdk/sqlite-runtime";
import {
  resolveScopedMemoryArtifactBase,
  type ScopedMemoryDatabase,
  type ScopedMemoryLifecycleState,
  withScopedMemoryDatabase,
} from "./scoped-memory-db.js";
import {
  createScopedMemorySourcePolicySetId,
  normalizeScopedMemoryRequiredText,
  type BuiltinScopedMemoryStore,
  type ScopedMemoryActor,
} from "./scoped-memory-store.js";

const OPAQUE_ARTIFACT_ATTEMPTS = 8;
const OPAQUE_PATH_KEY_PATTERN = /^s1_[A-Za-z0-9_-]{24,}$/u;
const OPAQUE_ARTIFACT_PATTERN = /^r1_[A-Za-z0-9_-]{18,}\.md$/u;
const SCOPED_CHUNK_MAX_LINES = 40;
const SCOPED_CHUNK_MAX_CHARS = 4_000;

type BuiltinScopedMemoryResource = Readonly<{
  resourceId: string;
  revisionId: string;
  policyRevisionId: string;
  sourcePolicySetId: string;
}>;

function hashText(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function createOpaqueArtifactLocator(): string {
  return `r1_${randomBytes(18).toString("base64url")}.md`;
}

function assertOpaquePathKey(pathKey: string): void {
  if (!OPAQUE_PATH_KEY_PATTERN.test(pathKey)) {
    throw new Error("generated scoped-memory path key is invalid");
  }
}

function assertOpaqueArtifactLocator(locator: string): void {
  if (!OPAQUE_ARTIFACT_PATTERN.test(locator)) {
    throw new Error("scoped-memory artifact locator is invalid");
  }
}

function resolveChildPath(base: string, child: string): string {
  const resolvedBase = path.resolve(base);
  const resolved = path.resolve(resolvedBase, child);
  if (path.dirname(resolved) !== resolvedBase || path.basename(resolved) !== child) {
    throw new Error("scoped-memory locator escaped its storage root");
  }
  return resolved;
}

export function resolveBuiltinScopedMemoryArtifactPath(params: {
  databasePath: string;
  pathKey: string;
  artifactLocator: string;
}): string {
  assertOpaquePathKey(params.pathKey);
  assertOpaqueArtifactLocator(params.artifactLocator);
  const storeDir = resolveChildPath(
    resolveScopedMemoryArtifactBase(params.databasePath),
    params.pathKey,
  );
  return resolveChildPath(storeDir, params.artifactLocator);
}

function writeOpaqueArtifact(params: { databasePath: string; pathKey: string; content: string }): {
  artifactLocator: string;
  artifactPath: string;
} {
  for (let attempt = 0; attempt < OPAQUE_ARTIFACT_ATTEMPTS; attempt += 1) {
    const artifactLocator = createOpaqueArtifactLocator();
    const artifactPath = resolveBuiltinScopedMemoryArtifactPath({
      databasePath: params.databasePath,
      pathKey: params.pathKey,
      artifactLocator,
    });
    try {
      fs.writeFileSync(artifactPath, params.content, {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
      });
      return { artifactLocator, artifactPath };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
        throw error;
      }
    }
  }
  throw new Error("could not allocate an opaque scoped-memory artifact");
}

function removeArtifact(artifactPath: string): void {
  try {
    fs.unlinkSync(artifactPath);
  } catch {}
}

function chunkMarkdown(content: string): Array<{
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
    const text = lines.slice(start, end).join("\n");
    chunks.push({
      ordinal: chunks.length,
      startLine: start + 1,
      endLine: Math.max(start + 1, end),
      text,
    });
    start = end;
  }
  return chunks;
}

function readActiveStoreRoot(params: {
  database: DatabaseSync;
  agentId: string;
  storeId: string;
}): { pathKey: string; defaultCapabilitiesJson: string } {
  const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
  const row = executeSqliteQueryTakeFirstSync(
    params.database,
    db
      .selectFrom("memory_stores as store")
      .innerJoin("memory_storage_roots as root", "root.storage_root_id", "store.storage_root_id")
      .select(["root.path_key", "root.default_capabilities_json"])
      .where("store.store_id", "=", params.storeId)
      .where("store.agent_id", "=", params.agentId)
      .where("store.lifecycle_state", "=", "active")
      .where("root.agent_id", "=", params.agentId)
      .where("root.backend_kind", "=", "builtin")
      .where("root.lifecycle_state", "=", "active"),
  );
  if (!row?.path_key) {
    throw new Error("active builtin scoped-memory store is unavailable");
  }
  return {
    pathKey: row.path_key,
    defaultCapabilitiesJson: row.default_capabilities_json,
  };
}

function readActivePolicy(params: {
  database: DatabaseSync;
  agentId: string;
  policyId: string;
  policyRevisionId: string;
  policyRevocationEpoch: number;
}): void {
  const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
  const row = executeSqliteQueryTakeFirstSync(
    params.database,
    db
      .selectFrom("memory_policies as policy")
      .innerJoin(
        "memory_policy_revisions as revision",
        "revision.revision_id",
        "policy.current_revision_id",
      )
      .select(["policy.policy_id"])
      .where("policy.policy_id", "=", params.policyId)
      .where("policy.agent_id", "=", params.agentId)
      .where("policy.current_revision_id", "=", params.policyRevisionId)
      .where("policy.revocation_epoch", "=", params.policyRevocationEpoch)
      .where("policy.lifecycle_state", "=", "active")
      .where("revision.lifecycle_state", "=", "active"),
  );
  if (!row) {
    throw new Error("active scoped-memory policy is unavailable");
  }
}

/** Seed one immutable Markdown revision for the authorized builtin backend. */
export function createBuiltinScopedMemoryResource(params: {
  agentId: string;
  store: BuiltinScopedMemoryStore;
  logicalLocator: string;
  content: string;
  source?: "memory" | "sessions";
  lifecycleState?: ScopedMemoryLifecycleState;
  actor: ScopedMemoryActor;
  expiresAt?: number;
  subjects?: readonly Readonly<{
    kind: "person" | "project" | "conversation" | "topic";
    id: string;
    evidenceRevision: string;
  }>[];
  vectors?: readonly number[][];
  nowMs?: number;
}): BuiltinScopedMemoryResource {
  const agentId = normalizeAgentId(params.agentId);
  const logicalLocator = normalizeScopedMemoryRequiredText(params.logicalLocator, "logicalLocator");
  if (!params.content.trim()) {
    throw new Error("scoped-memory content is required");
  }
  const lifecycleState = params.lifecycleState ?? "active";
  const nowMs = params.nowMs ?? Date.now();
  const resourceId = randomUUID();
  const revisionId = randomUUID();
  const contentHash = hashText(params.content);
  const chunks = chunkMarkdown(params.content);

  return withScopedMemoryDatabase(agentId, (database, databasePath) => {
    const root = readActiveStoreRoot({ database, agentId, storeId: params.store.storeId });
    readActivePolicy({
      database,
      agentId,
      policyId: params.store.policyId,
      policyRevisionId: params.store.policyRevisionId,
      policyRevocationEpoch: params.store.policyRevocationEpoch,
    });
    const artifact = writeOpaqueArtifact({
      databasePath,
      pathKey: root.pathKey,
      content: params.content,
    });
    const db = getNodeSqliteKysely<ScopedMemoryDatabase>(database);
    try {
      runSqliteImmediateTransactionSync(database, () => {
        // Filesystem work is complete; now recheck the authoritative store and policy rows.
        readActiveStoreRoot({ database, agentId, storeId: params.store.storeId });
        readActivePolicy({
          database,
          agentId,
          policyId: params.store.policyId,
          policyRevisionId: params.store.policyRevisionId,
          policyRevocationEpoch: params.store.policyRevocationEpoch,
        });
        executeSqliteQuerySync(
          database,
          db.insertInto("memory_resources").values({
            resource_id: resourceId,
            agent_id: agentId,
            store_id: params.store.storeId,
            logical_locator: logicalLocator,
            source: params.source ?? "memory",
            created_at: nowMs,
          }),
        );
        executeSqliteQuerySync(
          database,
          db.insertInto("memory_resource_revisions").values({
            revision_id: revisionId,
            resource_id: resourceId,
            revision_number: 1,
            artifact_locator: artifact.artifactLocator,
            content_hash: contentHash,
            content_bytes: Buffer.byteLength(params.content),
            policy_revision_id: params.store.policyRevisionId,
            policy_revocation_epoch: params.store.policyRevocationEpoch,
            source_policy_set_id: params.store.sourcePolicySetId,
            lifecycle_state: lifecycleState,
            actor_kind: params.actor.kind,
            actor_id: params.actor.id ?? null,
            expires_at: params.expiresAt ?? null,
            created_at: nowMs,
            activated_at: lifecycleState === "active" ? nowMs : null,
            retired_at: lifecycleState === "tombstoned" ? nowMs : null,
          }),
        );
        executeSqliteQuerySync(
          database,
          db.insertInto("memory_revision_policy_requirements").values({
            revision_id: revisionId,
            stable_policy_id: params.store.policyId,
            captured_revision_id: params.store.policyRevisionId,
            expected_active_revision_id: params.store.policyRevisionId,
            expected_revocation_epoch: params.store.policyRevocationEpoch,
            created_at: nowMs,
          }),
        );
        const subjects = (params.subjects ?? []).map((subject) => ({
          revision_id: revisionId,
          subject_kind: subject.kind,
          subject_id: normalizeScopedMemoryRequiredText(subject.id, "resource subject id"),
          evidence_revision: normalizeScopedMemoryRequiredText(
            subject.evidenceRevision,
            "resource subject evidenceRevision",
          ),
          lifecycle_state: "current" as const,
          created_at: nowMs,
        }));
        if (subjects.length > 0) {
          executeSqliteQuerySync(
            database,
            db.insertInto("memory_resource_subjects").values(subjects),
          );
        }
        executeSqliteQuerySync(
          database,
          db.insertInto("memory_scoped_chunks").values(
            chunks.map((chunk) => ({
              chunk_id: randomUUID(),
              revision_id: revisionId,
              chunk_ordinal: chunk.ordinal,
              start_line: chunk.startLine,
              end_line: chunk.endLine,
              text: chunk.text,
              content_hash: hashText(chunk.text),
              model: "builtin-markdown-v1",
              updated_at: nowMs,
            })),
          ),
        );
        if (params.vectors && params.vectors.length > 0) {
          const storedChunks = executeSqliteQuerySync(
            database,
            db
              .selectFrom("memory_scoped_chunks")
              .select(["chunk_id", "chunk_ordinal"])
              .where("revision_id", "=", revisionId)
              .orderBy("chunk_ordinal"),
          ).rows;
          const vectors = storedChunks.flatMap((chunk) => {
            const vector = params.vectors?.[chunk.chunk_ordinal];
            return vector && vector.length > 0
              ? [
                  {
                    chunk_id: chunk.chunk_id,
                    model: "fixture-vector-v1",
                    dims: vector.length,
                    embedding: JSON.stringify(vector),
                    updated_at: nowMs,
                  },
                ]
              : [];
          });
          if (vectors.length > 0) {
            executeSqliteQuerySync(
              database,
              db.insertInto("memory_scoped_chunk_vectors").values(vectors),
            );
          }
        }
      });
    } catch (error) {
      removeArtifact(artifact.artifactPath);
      throw error;
    }
    return Object.freeze({
      resourceId,
      revisionId,
      policyRevisionId: params.store.policyRevisionId,
      sourcePolicySetId: params.store.sourcePolicySetId,
    });
  });
}

function readActiveResourceStore(params: {
  database: DatabaseSync;
  agentId: string;
  resourceId: string;
}): {
  pathKey: string;
  policyId: string;
  policyRevisionId: string;
  policyRevocationEpoch: number;
} {
  const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
  const row = executeSqliteQueryTakeFirstSync(
    params.database,
    db
      .selectFrom("memory_resources as resource")
      .innerJoin("memory_stores as store", "store.store_id", "resource.store_id")
      .innerJoin("memory_storage_roots as root", "root.storage_root_id", "store.storage_root_id")
      .innerJoin("memory_policies as policy", "policy.policy_id", "store.policy_id")
      .select([
        "root.path_key",
        "policy.policy_id",
        "policy.current_revision_id",
        "policy.revocation_epoch",
      ])
      .where("resource.resource_id", "=", params.resourceId)
      .where("resource.agent_id", "=", params.agentId)
      .where("store.agent_id", "=", params.agentId)
      .where("store.lifecycle_state", "=", "active")
      .where("root.agent_id", "=", params.agentId)
      .where("root.backend_kind", "=", "builtin")
      .where("root.lifecycle_state", "=", "active")
      .where("policy.agent_id", "=", params.agentId)
      .where("policy.lifecycle_state", "=", "active"),
  );
  if (!row?.path_key) {
    throw new Error("active builtin scoped-memory resource is unavailable");
  }
  return {
    pathKey: row.path_key,
    policyId: row.policy_id,
    policyRevisionId: row.current_revision_id,
    policyRevocationEpoch: row.revocation_epoch,
  };
}

/** Add one immutable revision to an existing logical resource. */
export function createBuiltinScopedMemoryResourceRevision(params: {
  agentId: string;
  resourceId: string;
  content: string;
  lifecycleState?: ScopedMemoryLifecycleState;
  actor: ScopedMemoryActor;
  expiresAt?: number;
  subjects?: readonly Readonly<{
    kind: "person" | "project" | "conversation" | "topic";
    id: string;
    evidenceRevision: string;
  }>[];
  vectors?: readonly number[][];
  nowMs?: number;
}): BuiltinScopedMemoryResource {
  const agentId = normalizeAgentId(params.agentId);
  const resourceId = normalizeScopedMemoryRequiredText(params.resourceId, "resourceId");
  if (!params.content.trim()) {
    throw new Error("scoped-memory content is required");
  }
  const lifecycleState = params.lifecycleState ?? "pending";
  const nowMs = params.nowMs ?? Date.now();
  const revisionId = randomUUID();
  const contentHash = hashText(params.content);
  const chunks = chunkMarkdown(params.content);

  return withScopedMemoryDatabase(agentId, (database, databasePath) => {
    const initial = readActiveResourceStore({ database, agentId, resourceId });
    readActivePolicy({
      database,
      agentId,
      policyId: initial.policyId,
      policyRevisionId: initial.policyRevisionId,
      policyRevocationEpoch: initial.policyRevocationEpoch,
    });
    const artifact = writeOpaqueArtifact({
      databasePath,
      pathKey: initial.pathKey,
      content: params.content,
    });
    const db = getNodeSqliteKysely<ScopedMemoryDatabase>(database);
    let committedPolicyRevisionId = initial.policyRevisionId;
    let committedSourcePolicySetId = createScopedMemorySourcePolicySetId(initial.policyRevisionId);
    try {
      runSqliteImmediateTransactionSync(database, () => {
        const current = readActiveResourceStore({ database, agentId, resourceId });
        if (current.pathKey !== initial.pathKey) {
          throw new Error("scoped-memory storage root changed during revision");
        }
        readActivePolicy({
          database,
          agentId,
          policyId: current.policyId,
          policyRevisionId: current.policyRevisionId,
          policyRevocationEpoch: current.policyRevocationEpoch,
        });
        committedPolicyRevisionId = current.policyRevisionId;
        committedSourcePolicySetId = createScopedMemorySourcePolicySetId(current.policyRevisionId);
        const previous = executeSqliteQueryTakeFirstSync(
          database,
          db
            .selectFrom("memory_resource_revisions")
            .select(["revision_id", "revision_number", "source_policy_set_id"])
            .where("resource_id", "=", resourceId)
            .orderBy("revision_number", "desc")
            .limit(1),
        );
        if (!previous) {
          throw new Error("scoped-memory resource has no revision history");
        }
        const inheritedRequirements = executeSqliteQuerySync(
          database,
          db
            .selectFrom("memory_revision_policy_requirements")
            .selectAll()
            .where("revision_id", "=", previous.revision_id)
            .orderBy("stable_policy_id"),
        ).rows;
        if (inheritedRequirements.length === 0) {
          throw new Error("scoped-memory resource lineage is unavailable");
        }
        committedSourcePolicySetId = `mpset1_${hashText(previous.source_policy_set_id)}`;
        if (lifecycleState === "active") {
          executeSqliteQuerySync(
            database,
            db
              .updateTable("memory_resource_revisions")
              .set({ lifecycle_state: "tombstoned", retired_at: nowMs })
              .where("resource_id", "=", resourceId)
              .where("lifecycle_state", "=", "active"),
          );
        }
        executeSqliteQuerySync(
          database,
          db.insertInto("memory_resource_revisions").values({
            revision_id: revisionId,
            resource_id: resourceId,
            revision_number: previous.revision_number + 1,
            artifact_locator: artifact.artifactLocator,
            content_hash: contentHash,
            content_bytes: Buffer.byteLength(params.content),
            policy_revision_id: committedPolicyRevisionId,
            policy_revocation_epoch: current.policyRevocationEpoch,
            source_policy_set_id: committedSourcePolicySetId,
            lifecycle_state: lifecycleState,
            actor_kind: params.actor.kind,
            actor_id: params.actor.id ?? null,
            expires_at: params.expiresAt ?? null,
            created_at: nowMs,
            activated_at: lifecycleState === "active" ? nowMs : null,
            retired_at: lifecycleState === "tombstoned" ? nowMs : null,
          }),
        );
        executeSqliteQuerySync(
          database,
          db.insertInto("memory_revision_policy_requirements").values(
            inheritedRequirements.map((requirement) => ({
              revision_id: revisionId,
              stable_policy_id: requirement.stable_policy_id,
              captured_revision_id: requirement.captured_revision_id,
              expected_active_revision_id: requirement.expected_active_revision_id,
              expected_revocation_epoch: requirement.expected_revocation_epoch,
              created_at: nowMs,
            })),
          ),
        );
        executeSqliteQuerySync(
          database,
          db.insertInto("memory_lineage_edges").values({
            child_revision_id: revisionId,
            parent_revision_id: previous.revision_id,
            edge_kind: "revision",
            created_at: nowMs,
          }),
        );
        const subjects = (params.subjects ?? []).map((subject) => ({
          revision_id: revisionId,
          subject_kind: subject.kind,
          subject_id: normalizeScopedMemoryRequiredText(subject.id, "resource subject id"),
          evidence_revision: normalizeScopedMemoryRequiredText(
            subject.evidenceRevision,
            "resource subject evidenceRevision",
          ),
          lifecycle_state: "current" as const,
          created_at: nowMs,
        }));
        if (subjects.length > 0) {
          executeSqliteQuerySync(
            database,
            db.insertInto("memory_resource_subjects").values(subjects),
          );
        }
        executeSqliteQuerySync(
          database,
          db.insertInto("memory_scoped_chunks").values(
            chunks.map((chunk) => ({
              chunk_id: randomUUID(),
              revision_id: revisionId,
              chunk_ordinal: chunk.ordinal,
              start_line: chunk.startLine,
              end_line: chunk.endLine,
              text: chunk.text,
              content_hash: hashText(chunk.text),
              model: "builtin-markdown-v1",
              updated_at: nowMs,
            })),
          ),
        );
        if (params.vectors && params.vectors.length > 0) {
          const storedChunks = executeSqliteQuerySync(
            database,
            db
              .selectFrom("memory_scoped_chunks")
              .select(["chunk_id", "chunk_ordinal"])
              .where("revision_id", "=", revisionId)
              .orderBy("chunk_ordinal"),
          ).rows;
          const vectors = storedChunks.flatMap((chunk) => {
            const vector = params.vectors?.[chunk.chunk_ordinal];
            return vector && vector.length > 0
              ? [
                  {
                    chunk_id: chunk.chunk_id,
                    model: "fixture-vector-v1",
                    dims: vector.length,
                    embedding: JSON.stringify(vector),
                    updated_at: nowMs,
                  },
                ]
              : [];
          });
          if (vectors.length > 0) {
            executeSqliteQuerySync(
              database,
              db.insertInto("memory_scoped_chunk_vectors").values(vectors),
            );
          }
        }
      });
    } catch (error) {
      removeArtifact(artifact.artifactPath);
      throw error;
    }
    return Object.freeze({
      resourceId,
      revisionId,
      policyRevisionId: committedPolicyRevisionId,
      sourcePolicySetId: committedSourcePolicySetId,
    });
  });
}

/** Lifecycle-only transition; immutable revision identity and content fields remain protected. */
export function setBuiltinScopedMemoryRevisionLifecycle(params: {
  agentId: string;
  revisionId: string;
  lifecycleState: ScopedMemoryLifecycleState;
  nowMs?: number;
}): void {
  const agentId = normalizeAgentId(params.agentId);
  const nowMs = params.nowMs ?? Date.now();
  withScopedMemoryDatabase(agentId, (database) => {
    const db = getNodeSqliteKysely<ScopedMemoryDatabase>(database);
    runSqliteImmediateTransactionSync(database, () => {
      const current = executeSqliteQueryTakeFirstSync(
        database,
        db
          .selectFrom("memory_resource_revisions as revision")
          .innerJoin("memory_resources as resource", "resource.resource_id", "revision.resource_id")
          .select(["revision.resource_id", "revision.lifecycle_state", "revision.activated_at"])
          .where("revision.revision_id", "=", params.revisionId)
          .where("resource.agent_id", "=", agentId),
      );
      if (!current) {
        throw new Error("scoped-memory revision is unavailable");
      }
      const allowedTransitions: Readonly<
        Record<ScopedMemoryLifecycleState, readonly ScopedMemoryLifecycleState[]>
      > = {
        pending: ["pending", "active", "quarantined", "tombstoned"],
        active: ["active", "quarantined", "tombstoned"],
        quarantined: ["quarantined", "active", "tombstoned"],
        tombstoned: ["tombstoned"],
      };
      if (!allowedTransitions[current.lifecycle_state].includes(params.lifecycleState)) {
        throw new Error("invalid scoped-memory revision lifecycle transition");
      }
      if (current.lifecycle_state === params.lifecycleState) {
        return;
      }
      if (params.lifecycleState === "active") {
        // Activation is the one place that replaces an existing active revision.
        // Retiring it in the same commit preserves the one-active-revision invariant.
        executeSqliteQuerySync(
          database,
          db
            .updateTable("memory_resource_revisions")
            .set({ lifecycle_state: "tombstoned", retired_at: nowMs })
            .where("resource_id", "=", current.resource_id)
            .where("lifecycle_state", "=", "active")
            .where("revision_id", "!=", params.revisionId),
        );
      }
      const result = executeSqliteQuerySync(
        database,
        db
          .updateTable("memory_resource_revisions")
          .set({
            lifecycle_state: params.lifecycleState,
            activated_at:
              params.lifecycleState === "active"
                ? (current.activated_at ?? nowMs)
                : current.activated_at,
            retired_at: params.lifecycleState === "tombstoned" ? nowMs : null,
          })
          .where("revision_id", "=", params.revisionId),
      );
      if (result.numAffectedRows !== 1n) {
        throw new Error("scoped-memory revision is unavailable");
      }
    });
  });
}
