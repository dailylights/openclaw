import { randomUUID } from "node:crypto";
import { normalizeAgentId } from "openclaw/plugin-sdk/routing";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
  runSqliteImmediateTransactionSync,
} from "openclaw/plugin-sdk/sqlite-runtime";
import {
  type MemoryProjectionRow,
  type ScopedMemoryDatabase,
  withScopedMemoryDatabase,
} from "./scoped-memory-db.js";
import { removeTombstonedBuiltinScopedMemoryArtifacts } from "./scoped-memory-resource-artifacts.js";
import { createBuiltinScopedMemoryResource } from "./scoped-memory-resources.js";
import {
  assertAgentOwnerOrAdmin,
  assertCurrentProjectionReviewAuthority,
  assertHistoricalPostboxAuthority,
  assertHistoricalProjectionAuthority,
  assertProjectionAuthority,
  assertProjectionRefreshLineage,
  assertProjectionTarget,
  createAggregateSourcePolicySetId,
  postboxRow,
  projectRow,
  readActiveSourceRevision,
  readProjection,
  readRevisionPolicyRequirements,
  readStoreByAudience,
  readVerifiedSourceContent,
  tombstoneRevisionLineage,
} from "./scoped-memory-sharing-authorization.js";
import {
  assertAuthority,
  capProjectionExpiryToSource,
  createOpaqueId,
  hashText,
  iso,
  PREVIEW_TTL_MS,
  requireFutureExpiry,
  type PostboxSourceMessageRecord,
  type PostboxSourceMessage,
  type ProjectionPreviewInput,
  type ProjectionPreviewRecord,
  type ScopedMemorySharingPostboxItem,
  type ScopedMemorySharingPostboxInspection,
  type ScopedMemorySharingProjection,
  type ScopedMemorySharingStatus,
  type SharingAuthority,
  toBuiltinStore,
} from "./scoped-memory-sharing-contracts.js";
import { createScopedMemoryPostboxOperations } from "./scoped-memory-sharing-postbox.js";
import { normalizeScopedMemoryRequiredText } from "./scoped-memory-store.js";

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
      const targetStore = readStoreByAudience({
        database,
        agentId,
        audienceKind: input.targetKind,
        audienceId: targetId,
      });
      assertProjectionAuthority({ database, source, target: targetStore, authority, nowMs });
      if (supersedesProjectionId) {
        assertProjectionRefreshLineage({
          database,
          agentId,
          source,
          target: targetStore,
          supersededProjectionId: supersedesProjectionId,
        });
      }
      return {
        target: targetStore,
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

  const {
    configurePostbox,
    issuePostboxSourceMessageHandle,
    depositPostbox,
    inspectPostbox,
    reviewPostbox,
    purgePostbox,
  } = createScopedMemoryPostboxOperations({ now, postboxHandles, purgeEphemeralRecords });
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
