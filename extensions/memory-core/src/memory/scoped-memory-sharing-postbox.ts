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
  type MemoryPostboxItemRow,
  type ScopedMemoryDatabase,
  withScopedMemoryDatabase,
} from "./scoped-memory-db.js";
import { removeTombstonedBuiltinScopedMemoryArtifacts } from "./scoped-memory-resource-artifacts.js";
import { createBuiltinScopedMemoryResource } from "./scoped-memory-resources.js";
import {
  assertAgentOwnerOrAdmin,
  assertHistoricalPostboxAuthority,
  postboxRow,
  readStoreByAudience,
  tombstoneRevisionLineage,
} from "./scoped-memory-sharing-authorization.js";
import {
  assertAuthority,
  assertLocalOwnerOrAdmin,
  assertPostboxMode,
  createOpaqueId,
  DEFAULT_POSTBOX_RATE_LIMIT_WINDOW_MS,
  DEFAULT_POSTBOX_RATE_LIMIT_MAX_ITEMS,
  hashText,
  iso,
  POSTBOX_HANDLE_TTL_MS,
  PURGED_POSTBOX_CONTENT,
  requireFutureExpiry,
  toBuiltinStore,
} from "./scoped-memory-sharing-contracts.js";
import type {
  PostboxSourceMessage,
  PostboxSourceMessageRecord,
  ScopedStoreDetails,
  SharingAuthority,
} from "./scoped-memory-sharing-contracts.js";
import { normalizeScopedMemoryRequiredText } from "./scoped-memory-store.js";

export function createScopedMemoryPostboxOperations(options: {
  now: () => number;
  postboxHandles: Map<string, PostboxSourceMessageRecord>;
  purgeEphemeralRecords: (nowMs: number) => void;
}) {
  const { now, postboxHandles, purgeEphemeralRecords } = options;
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

  return {
    configurePostbox,
    issuePostboxSourceMessageHandle,
    depositPostbox,
    inspectPostbox,
    reviewPostbox,
    purgePostbox,
  };
}
