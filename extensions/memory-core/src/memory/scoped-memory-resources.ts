import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { normalizeAgentId } from "openclaw/plugin-sdk/routing";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
  runSqliteImmediateTransactionSync,
} from "openclaw/plugin-sdk/sqlite-runtime";
import {
  type ScopedMemoryDatabase,
  type ScopedMemoryLifecycleState,
  withScopedMemoryDatabase,
} from "./scoped-memory-db.js";
import {
  chunkBuiltinScopedMemoryContent,
  hashScopedMemoryText,
  removeBuiltinScopedMemoryArtifact,
  writeBuiltinScopedMemoryArtifact,
} from "./scoped-memory-resource-artifacts.js";
import {
  createScopedMemorySourcePolicySetId,
  normalizeScopedMemoryRequiredText,
  type BuiltinScopedMemoryStore,
  type ScopedMemoryActor,
} from "./scoped-memory-store.js";

type BuiltinScopedMemoryResource = Readonly<{
  resourceId: string;
  revisionId: string;
  policyRevisionId: string;
  sourcePolicySetId: string;
}>;

/** Immutable policy requirements inherited by a derived or projected revision. */
export type ScopedMemoryRevisionPolicyRequirementInput = Readonly<{
  stablePolicyId: string;
  capturedRevisionId: string;
  expectedActiveRevisionId: string;
  expectedRevocationEpoch: number;
}>;

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

function normalizeRevisionPolicyRequirements(params: {
  store: Pick<BuiltinScopedMemoryStore, "policyId" | "policyRevisionId" | "policyRevocationEpoch">;
  inherited: readonly ScopedMemoryRevisionPolicyRequirementInput[];
}): ScopedMemoryRevisionPolicyRequirementInput[] {
  const requirements = new Map<string, ScopedMemoryRevisionPolicyRequirementInput>();
  const add = (requirement: ScopedMemoryRevisionPolicyRequirementInput) => {
    const normalized: ScopedMemoryRevisionPolicyRequirementInput = {
      stablePolicyId: normalizeScopedMemoryRequiredText(
        requirement.stablePolicyId,
        "policy requirement stablePolicyId",
      ),
      capturedRevisionId: normalizeScopedMemoryRequiredText(
        requirement.capturedRevisionId,
        "policy requirement capturedRevisionId",
      ),
      expectedActiveRevisionId: normalizeScopedMemoryRequiredText(
        requirement.expectedActiveRevisionId,
        "policy requirement expectedActiveRevisionId",
      ),
      expectedRevocationEpoch: requirement.expectedRevocationEpoch,
    };
    if (
      !Number.isSafeInteger(normalized.expectedRevocationEpoch) ||
      normalized.expectedRevocationEpoch < 0
    ) {
      throw new Error("policy requirement expectedRevocationEpoch is invalid");
    }
    const existing = requirements.get(normalized.stablePolicyId);
    if (
      existing &&
      (existing.capturedRevisionId !== normalized.capturedRevisionId ||
        existing.expectedActiveRevisionId !== normalized.expectedActiveRevisionId ||
        existing.expectedRevocationEpoch !== normalized.expectedRevocationEpoch)
    ) {
      throw new Error("scoped-memory resource policy requirements conflict");
    }
    requirements.set(normalized.stablePolicyId, normalized);
  };
  add({
    stablePolicyId: params.store.policyId,
    capturedRevisionId: params.store.policyRevisionId,
    expectedActiveRevisionId: params.store.policyRevisionId,
    expectedRevocationEpoch: params.store.policyRevocationEpoch,
  });
  for (const requirement of params.inherited) {
    add(requirement);
  }
  return [...requirements.values()].toSorted((left, right) =>
    left.stablePolicyId.localeCompare(right.stablePolicyId),
  );
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
  /** Additional stable-policy requirements carried from an authorized source revision. */
  inheritedPolicyRequirements?: readonly ScopedMemoryRevisionPolicyRequirementInput[];
  /** Aggregate policy-set identifier for an authorized derived or projected copy. */
  sourcePolicySetId?: string;
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
  const contentHash = hashScopedMemoryText(params.content);
  const chunks = chunkBuiltinScopedMemoryContent(params.content);
  const sourcePolicySetId = params.sourcePolicySetId
    ? normalizeScopedMemoryRequiredText(params.sourcePolicySetId, "sourcePolicySetId")
    : params.store.sourcePolicySetId;
  const policyRequirements = normalizeRevisionPolicyRequirements({
    store: params.store,
    inherited: params.inheritedPolicyRequirements ?? [],
  });

  return withScopedMemoryDatabase(agentId, (database, databasePath) => {
    const root = readActiveStoreRoot({ database, agentId, storeId: params.store.storeId });
    readActivePolicy({
      database,
      agentId,
      policyId: params.store.policyId,
      policyRevisionId: params.store.policyRevisionId,
      policyRevocationEpoch: params.store.policyRevocationEpoch,
    });
    const artifact = writeBuiltinScopedMemoryArtifact({
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
            source_policy_set_id: sourcePolicySetId,
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
            policyRequirements.map((requirement) => ({
              revision_id: revisionId,
              stable_policy_id: requirement.stablePolicyId,
              captured_revision_id: requirement.capturedRevisionId,
              expected_active_revision_id: requirement.expectedActiveRevisionId,
              expected_revocation_epoch: requirement.expectedRevocationEpoch,
              created_at: nowMs,
            })),
          ),
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
              content_hash: hashScopedMemoryText(chunk.text),
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
      removeBuiltinScopedMemoryArtifact(artifact.artifactPath);
      throw error;
    }
    return Object.freeze({
      resourceId,
      revisionId,
      policyRevisionId: params.store.policyRevisionId,
      sourcePolicySetId,
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
  const contentHash = hashScopedMemoryText(params.content);
  const chunks = chunkBuiltinScopedMemoryContent(params.content);

  return withScopedMemoryDatabase(agentId, (database, databasePath) => {
    const initial = readActiveResourceStore({ database, agentId, resourceId });
    readActivePolicy({
      database,
      agentId,
      policyId: initial.policyId,
      policyRevisionId: initial.policyRevisionId,
      policyRevocationEpoch: initial.policyRevocationEpoch,
    });
    const artifact = writeBuiltinScopedMemoryArtifact({
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
        const inheritedSourceRequirements = inheritedRequirements
          .filter((requirement) => requirement.stable_policy_id !== current.policyId)
          .map((requirement) => ({
            stablePolicyId: requirement.stable_policy_id,
            capturedRevisionId: requirement.captured_revision_id,
            expectedActiveRevisionId: requirement.expected_active_revision_id,
            expectedRevocationEpoch: requirement.expected_revocation_epoch,
          }));
        for (const requirement of inheritedSourceRequirements) {
          readActivePolicy({
            database,
            agentId,
            policyId: requirement.stablePolicyId,
            policyRevisionId: requirement.expectedActiveRevisionId,
            policyRevocationEpoch: requirement.expectedRevocationEpoch,
          });
        }
        const policyRequirements = normalizeRevisionPolicyRequirements({
          store: current,
          inherited: inheritedSourceRequirements,
        });
        const sourcePolicySetIds = policyRequirements
          .map((requirement) =>
            createScopedMemorySourcePolicySetId(requirement.expectedActiveRevisionId),
          )
          .toSorted();
        committedSourcePolicySetId =
          sourcePolicySetIds.length === 1
            ? sourcePolicySetIds[0]!
            : `mpset1_${hashScopedMemoryText(sourcePolicySetIds.join("\0"))}`;
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
            policyRequirements.map((requirement) => ({
              revision_id: revisionId,
              stable_policy_id: requirement.stablePolicyId,
              captured_revision_id: requirement.capturedRevisionId,
              expected_active_revision_id: requirement.expectedActiveRevisionId,
              expected_revocation_epoch: requirement.expectedRevocationEpoch,
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
              content_hash: hashScopedMemoryText(chunk.text),
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
      removeBuiltinScopedMemoryArtifact(artifact.artifactPath);
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
