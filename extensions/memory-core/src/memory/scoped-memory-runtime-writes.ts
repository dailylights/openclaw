import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type {
  AuthorizedMemoryMutation,
  AuthorizedMemoryPlan,
  MemoryAccessContext,
  MemoryWriteResult,
} from "openclaw/plugin-sdk/memory-authorization";
import { normalizeAgentId } from "openclaw/plugin-sdk/routing";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
  runSqliteImmediateTransactionSync,
} from "openclaw/plugin-sdk/sqlite-runtime";
import {
  createScopedMemoryAggregateRevision,
  readScopedMemoryRevisionPolicyRequirements,
  readScopedMemoryRevisionAuthorization,
  type ScopedMemoryRevisionAuthorization,
  type ScopedMemoryRevisionPolicyRequirement,
} from "./scoped-memory-authorization.js";
import type { ScopedMemoryDatabase } from "./scoped-memory-db.js";
import { withScopedMemoryDatabase } from "./scoped-memory-db.js";
import { resolveBuiltinScopedMemoryArtifactPath } from "./scoped-memory-resource-artifacts.js";
import { tombstoneRevisionLineage } from "./scoped-memory-runtime-lineage.js";
import { createScopedMemoryRuntimePlanOperations } from "./scoped-memory-runtime-plans.js";
import {
  allocateOpaqueId,
  actorRecord,
  actorRef,
  compareText,
  createFinalArtifactLocator,
  createStagedArtifactLocator,
  hashText,
  mergeRevisionPolicyRequirements,
  readVerifiedArtifact,
  syncDirectory,
  subjectRef,
  writeStagedArtifact,
  type BuiltinScopedMemoryRuntimeDependencies,
  type MemoryLineageEdgeKind,
} from "./scoped-memory-runtime-primitives.js";
import { createScopedMemoryRuntimeRecoveryOperations } from "./scoped-memory-runtime-recovery.js";
import { createScopedMemorySourcePolicySetId } from "./scoped-memory-store.js";

type ScopedMemoryRuntimeWriteDependencies = Readonly<{
  dependencies: Pick<
    BuiltinScopedMemoryRuntimeDependencies,
    "generateOpaqueId" | "onMutationPhase"
  >;
  now: () => number;
  planOperations: ReturnType<typeof createScopedMemoryRuntimePlanOperations>;
  recoveryOperations: ReturnType<typeof createScopedMemoryRuntimeRecoveryOperations>;
}>;

export function createScopedMemoryRuntimeWriteOperations(
  options: ScopedMemoryRuntimeWriteDependencies,
) {
  const { dependencies, now, planOperations, recoveryOperations } = options;
  const {
    validatePlan,
    issueHandle,
    selectDefaultMutationMount,
    assertSubjectDefaultMutationTarget,
    assertMutationTargetIsNotProjectionCopy,
    readMutationStoreRoot,
    findCommittedIdempotency,
  } = planOperations;
  const {
    drainAuditOutbox,
    activatePendingIntent,
    indexActiveIntent,
    assertMutationHandle,
    validateMutation,
    quarantineIntent,
    recoverPendingWrites,
  } = recoveryOperations;
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
          const mount = selectDefaultMutationMount({ context: params.context, planRecord });
          const target = assertMutationHandle({
            database,
            context: params.context,
            plan: params.plan,
            planRecord,
            handle: params.mutation.target,
            nowMs,
          });
          assertSubjectDefaultMutationTarget({ mount, target });
          assertMutationTargetIsNotProjectionCopy({
            database,
            agentId,
            resourceId: target.resourceId,
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
            assertMutationTargetIsNotProjectionCopy({
              database,
              agentId,
              resourceId: current.resourceId,
            });
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

        const mount = selectDefaultMutationMount({ context: params.context, planRecord });
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
          assertSubjectDefaultMutationTarget({ mount, target });
          assertMutationTargetIsNotProjectionCopy({
            database,
            agentId,
            resourceId: target.resourceId,
          });
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
          if (params.mutation.kind === "append" || params.mutation.kind === "replace") {
            assertMutationTargetIsNotProjectionCopy({ database, agentId, resourceId });
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
          // A derived or revised copy must not outlive any readable source. In
          // particular, this keeps expiry-only projections from becoming durable
          // through an otherwise-authorized follow-on mutation.
          const inheritedExpiry = currentSourceSnapshots.reduce<number | null>(
            (earliest, source) =>
              source.expiresAt === null
                ? earliest
                : earliest === null
                  ? source.expiresAt
                  : Math.min(earliest, source.expiresAt),
            null,
          );
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
              expires_at: inheritedExpiry,
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
  return Object.freeze({ writeAuthorized });
}
