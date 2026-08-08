import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import type {
  AuthorizedMemoryMutation,
  AuthorizedMemoryPlan,
  AuthorizedResourceHandle,
  MemoryAccessContext,
} from "openclaw/plugin-sdk/memory-authorization";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
  runSqliteImmediateTransactionSync,
  writeMemoryAccessAudit,
} from "openclaw/plugin-sdk/sqlite-runtime";
import {
  equalScopedMemoryResourceHandle,
  readScopedMemoryRevisionAuthorization,
  type ScopedMemoryPlanRecord,
  type ScopedMemoryRevisionAuthorization,
} from "./scoped-memory-authorization.js";
import type { ScopedMemoryDatabase } from "./scoped-memory-db.js";
import { withScopedMemoryDatabase } from "./scoped-memory-db.js";
import { resolveBuiltinScopedMemoryArtifactPath } from "./scoped-memory-resource-artifacts.js";
import {
  CALLER_SELECTED_MUTATION_DESTINATION_FIELDS,
  chunkContent,
  createFinalArtifactLocator,
  hashText,
  mutationOperation,
  quarantineArtifact,
  readVerifiedArtifact,
  resolveScopedArtifactChild,
  STAGED_ARTIFACT_PATTERN,
  syncDirectory,
  type HandleRecord,
} from "./scoped-memory-runtime-primitives.js";

export function createScopedMemoryRuntimeRecoveryOperations(dependencies: {
  plans: Map<string, ScopedMemoryPlanRecord>;
  handles: Map<string, HandleRecord>;
  now: () => number;
}) {
  const { plans, handles, now } = dependencies;
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
  return Object.freeze({
    drainAuditOutbox,
    activatePendingIntent,
    indexActiveIntent,
    assertMutationHandle,
    validateMutation,
    quarantineIntent,
    recoverPendingWrites,
  });
}
