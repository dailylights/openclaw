import { uniqueStrings } from "@openclaw/normalization-core/string-normalization";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
} from "../../infra/kysely-sync.js";
import type { OpenClawAgentDatabase } from "../../state/openclaw-agent-db.js";
import {
  linkSessionConversation,
  prepareSessionConversation,
  upsertConversationIdentity,
} from "./session-accessor.sqlite-conversation.js";
import { publishSqliteSessionEntryCacheInvalidation } from "./session-accessor.sqlite-entry-cache.js";
import { readExactSessionEntryRow } from "./session-accessor.sqlite-entry-read.js";
import {
  clearSessionCollaborationForKey,
  deleteSessionDeliveryArtifacts,
  deleteSessionNodeArtifacts,
  rehomeLegacySessionNodeArtifacts,
} from "./session-accessor.sqlite-node-artifacts.js";
import { resolveSessionEntryProvenanceRow } from "./session-accessor.sqlite-provenance.js";
import { collectSqliteSessionStateIdsForEntry } from "./session-accessor.sqlite-references.js";
import { getSessionKysely } from "./session-accessor.sqlite-scope.js";
import {
  bindSqliteSessionNode,
  bindSqliteSessionRoot,
  normalizeSqliteSessionEntryTimestamp,
} from "./session-accessor.sqlite-session-row.js";
import {
  hasValidSqliteSessionEntryIdentity,
  parseSqliteSessionEntryJson as parseSessionEntryRow,
} from "./session-accessor.sqlite-status.js";
import { readTranscriptMutationStateInTransaction } from "./session-accessor.sqlite-transcript-state.js";
import {
  assertCanonicalSessionEntryLineageWrite,
  assertCanonicalSessionKeyWriteMatchesDatabase,
  canonicalSessionKeyMigrationRequiredError,
} from "./session-canonical-key.js";
import {
  persistSessionMemorySubjectInTransaction,
  rehomeSessionMemorySubjectAliases,
  tryRehomeSessionMemorySubjectSnapshot,
  type TrustedSessionMemorySubjectSeed,
} from "./session-memory-subject.js";
import { resolveDeliveryProvenCanonicalSessionKey } from "./store-entry.js";
export { collectSessionEntryLookupKeys } from "./store-entry.js";
import type { SessionEntry } from "./types.js";

export {
  assertSqliteLifecycleTargetSnapshotUnchanged,
  assertSqliteLifecycleTargetUnchanged,
  assertSqliteSessionEntrySelectionUnchanged,
  createSqliteSessionIdentitySnapshot,
  normalizeSqliteLifecycleTarget,
  readExactSessionEntryJsonForCanonicalRepair,
  readExactSessionEntryRow,
  readExactSessionEntryRowValidated,
  readSessionEntryRow,
  readSqliteLifecycleTargetSnapshot,
  readSqliteSessionEntryCount,
  readSqliteSessionEntryKeys,
  readSqliteSessionEntrySelectionSnapshot,
  readSqliteSessionEntryStore,
  readSqliteSessionIdentitySnapshot,
  resolveSqliteLifecyclePrimaryEntry,
  sqliteSessionEntriesEqual,
} from "./session-accessor.sqlite-entry-read.js";
export type { ResolvedSessionEntryRow } from "./session-accessor.sqlite-entry-read.js";

export function deleteSqliteSessionEntryRows(
  database: OpenClawAgentDatabase,
  sessionKey: string,
  options: { deleteOwnedWindows?: boolean; deliveryCleanupKeys?: readonly string[] } = {},
): void {
  const db = getSessionKysely(database.db);
  const windows = executeSqliteQuerySync(
    database.db,
    db.selectFrom("session_windows").select("session_id").where("session_key", "=", sessionKey),
  ).rows;
  const survivingNodes = executeSqliteQuerySync(
    database.db,
    db
      .selectFrom("session_nodes")
      .select(["current_session_id", "entry_json", "session_key"])
      .where("session_key", "!=", sessionKey)
      .orderBy("session_key", "asc"),
  ).rows;
  for (const window of windows) {
    const survivingNode = survivingNodes.find((node) => {
      if (node.current_session_id === window.session_id) {
        return true;
      }
      const entry = parseSessionEntryRow(node);
      return entry
        ? collectSqliteSessionStateIdsForEntry(entry).includes(window.session_id)
        : false;
    });
    if (
      survivingNode &&
      tryRehomeSessionMemorySubjectSnapshot({
        database,
        sessionId: window.session_id,
        sourceSessionKey: sessionKey,
        targetSessionKey: survivingNode.session_key,
      })
    ) {
      executeSqliteQuerySync(
        database.db,
        db
          .updateTable("session_windows")
          .set({ session_key: survivingNode.session_key })
          .where("session_id", "=", window.session_id),
      );
    }
  }
  if (options.deleteOwnedWindows) {
    deleteSessionDeliveryArtifacts(database, sessionKey, options.deliveryCleanupKeys);
    deleteSessionNodeArtifacts(database, sessionKey);
    executeSqliteQuerySync(
      database.db,
      db.deleteFrom("session_nodes").where("session_key", "=", sessionKey),
    );
    publishSqliteSessionEntryCacheInvalidation(database);
    return;
  }
  const remainingWindow = executeSqliteQueryTakeFirstSync(
    database.db,
    db
      .selectFrom("session_windows")
      .select(["session_id", "updated_at"])
      .where("session_key", "=", sessionKey)
      .orderBy("updated_at", "desc")
      .orderBy("session_id", "asc")
      .limit(1),
  );
  if (remainingWindow) {
    deleteSessionNodeArtifacts(database, sessionKey);
    clearSqliteSessionEntryPreservingWindows(database, {
      sessionId: remainingWindow.session_id,
      sessionKey,
      updatedAt: remainingWindow.updated_at,
    });
    publishSqliteSessionEntryCacheInvalidation(database);
    return;
  }
  executeSqliteQuerySync(
    database.db,
    db.deleteFrom("session_nodes").where("session_key", "=", sessionKey),
  );
  publishSqliteSessionEntryCacheInvalidation(database);
}

/** Remove the logical entry while retaining its node-owned transcript windows. */
function clearSqliteSessionEntryPreservingWindows(
  database: OpenClawAgentDatabase,
  params: { sessionId: string; sessionKey: string; updatedAt: number },
): void {
  const db = getSessionKysely(database.db);
  const cleared = {
    current_session_id: params.sessionId,
    entry_json: "{}",
    entry_valid: -1,
    updated_at: params.updatedAt,
    status: null,
    created_at: null,
    created_via: null,
    created_actor_type: null,
    created_actor_id: null,
    parent_session_key: null,
    spawned_by: null,
    fork_source_session_key: null,
    fork_source_session_id: null,
    fork_source_entry_id: null,
    label: null,
    display_name: null,
    category: null,
    icon: null,
    pinned_at: null,
    archived_at: null,
    last_read_at: null,
    last_interaction_at: null,
    last_activity_at: null,
  } as const;
  executeSqliteQuerySync(
    database.db,
    db
      .insertInto("session_nodes")
      .values({ session_key: params.sessionKey, ...cleared })
      .onConflict((conflict) => conflict.column("session_key").doUpdateSet(cleared)),
  );
  executeSqliteQuerySync(
    database.db,
    db
      .updateTable("session_nodes")
      .set({ entry_valid: -1 })
      .where("session_key", "=", params.sessionKey),
  );
}

export function deleteSqliteLifecycleTargetRows(
  database: OpenClawAgentDatabase,
  target: { canonicalKey: string; storeKeys: string[] },
): void {
  for (const sessionKey of uniqueStrings([target.canonicalKey, ...target.storeKeys])) {
    const trimmed = sessionKey.trim();
    if (trimmed) {
      deleteSqliteSessionEntryRows(database, trimmed);
    }
  }
}

export function deleteLegacySessionEntryRows(
  database: OpenClawAgentDatabase,
  legacyKeys: string[],
  sessionKey: string,
  options: { rehomeMembers?: boolean } = {},
): void {
  if (legacyKeys.length === 0) {
    return;
  }
  // Subject snapshots reference the logical key independently from session windows.
  // Rehome them before alias-node deletion can cascade immutable provenance away.
  rehomeSessionMemorySubjectAliases(database, sessionKey, legacyKeys);
  const db = getSessionKysely(database.db);
  for (const legacyKey of legacyKeys) {
    if (legacyKey === sessionKey) {
      continue;
    }
    rehomeSqliteSessionWindows(database, sessionKey, [legacyKey]);
    rehomeLegacySessionNodeArtifacts(database, legacyKey, sessionKey, options);
    executeSqliteQuerySync(
      database.db,
      db.deleteFrom("session_nodes").where("session_key", "=", legacyKey),
    );
    publishSqliteSessionEntryCacheInvalidation(database);
  }
}

/** Move retained generations to the canonical node before removing key aliases. */
export function rehomeSqliteSessionWindows(
  database: OpenClawAgentDatabase,
  canonicalKey: string,
  previousKeys: Iterable<string>,
): void {
  const legacyKeys = uniqueStrings([...previousKeys].map((key) => key.trim())).filter(
    (key) => key && key !== canonicalKey,
  );
  if (legacyKeys.length === 0) {
    return;
  }
  const db = getSessionKysely(database.db);
  executeSqliteQuerySync(
    database.db,
    db
      .updateTable("session_windows")
      .set({ session_key: canonicalKey })
      .where("session_key", "in", legacyKeys),
  );
}

export function writeSessionEntry(
  database: OpenClawAgentDatabase,
  sessionKey: string,
  entry: SessionEntry,
  options: {
    allowStoredAliases?: boolean;
    preserveNodeSuggestions?: boolean;
    previousEntry?: SessionEntry | null;
    memorySubjectSeed?: TrustedSessionMemorySubjectSeed;
    memorySubjectAliasSourceKeys?: Iterable<string>;
  } = {},
): void {
  const db = getSessionKysely(database.db);
  if (!options.allowStoredAliases) {
    assertCanonicalSessionKeyWriteMatchesDatabase(database, sessionKey);
    assertCanonicalSessionEntryLineageWrite(database, entry);
    if (resolveDeliveryProvenCanonicalSessionKey(sessionKey, entry) !== sessionKey) {
      throw canonicalSessionKeyMigrationRequiredError(
        `refusing non-canonical session key write ${sessionKey}`,
      );
    }
  }
  const normalizedEntry = normalizeSqliteSessionEntryTimestamp(entry);
  if (!hasValidSqliteSessionEntryIdentity(normalizedEntry)) {
    throw new Error("Refusing invalid SQLite session entry identity");
  }
  const updatedAt = normalizedEntry.updatedAt;
  // Doctor validated the raw rejected row before entering the transaction and passes its
  // hydrated snapshot explicitly; re-reading it through the runtime parser must stay fail-closed.
  const canonicalPreviousRow =
    options.allowStoredAliases && options.previousEntry !== undefined
      ? undefined
      : readExactSessionEntryRow(database, sessionKey);
  const canonicalPreviousEntry =
    canonicalPreviousRow?.entry ??
    (options.allowStoredAliases && options.previousEntry !== undefined
      ? (options.previousEntry ?? undefined)
      : undefined);
  const previousEntry =
    options.previousEntry === undefined
      ? canonicalPreviousEntry
      : (options.previousEntry ?? undefined);
  // The lifecycle-selected entry owns visibility copy-forward semantics.
  if (previousEntry && previousEntry.sessionId !== normalizedEntry.sessionId) {
    delete normalizedEntry.visibility;
  }
  // Collaboration rows belong to the exact canonical node being overwritten,
  // which can differ from the selected alias during canonicalization.
  if (canonicalPreviousEntry && canonicalPreviousEntry.sessionId !== normalizedEntry.sessionId) {
    // Doctor merges duplicate logical nodes; suggestions are owned by session_key,
    // not by the transcript generation being replaced. Membership remains winner-only.
    clearSessionCollaborationForKey(database, sessionKey, {
      clearSuggestions: options.preserveNodeSuggestions !== true,
    });
  }
  // Registry writes snapshot the current transcript watermark so recovery can
  // distinguish same-millisecond transcript writes before and after this row.
  const transcriptObservedAt =
    readTranscriptMutationStateInTransaction(database, normalizedEntry.sessionId).updatedAt ??
    updatedAt;
  const boundSessionRoot = bindSqliteSessionRoot({
    entry: normalizedEntry,
    sessionKey,
    updatedAt,
  });
  const conversation = prepareSessionConversation({
    entry: normalizedEntry,
    sessionScope: boundSessionRoot.session_scope,
  });
  if (conversation) {
    upsertConversationIdentity(database, conversation.identity, updatedAt);
  }
  const boundSessionRow = {
    ...boundSessionRoot,
    primary_conversation_id:
      conversation?.role === "primary" ? conversation.identity.conversationRef : null,
    transcript_observed_at: transcriptObservedAt,
  };
  const sessionRow = resolveSessionEntryProvenanceRow({
    boundSessionRow,
    database,
    entry: normalizedEntry,
    previousEntry,
  });
  const sessionNode = bindSqliteSessionNode({
    entry: normalizedEntry,
    sessionKey,
    updatedAt,
  });
  executeSqliteQuerySync(
    database.db,
    db
      .insertInto("session_nodes")
      .values(sessionNode)
      .onConflict((conflict) =>
        conflict.column("session_key").doUpdateSet({
          current_session_id: sessionNode.current_session_id,
          entry_json: sessionNode.entry_json,
          entry_valid: sessionNode.entry_valid,
          updated_at: sessionNode.updated_at,
          status: sessionNode.status,
          created_at: sessionNode.created_at,
          created_via: sessionNode.created_via,
          created_actor_type: sessionNode.created_actor_type,
          created_actor_id: sessionNode.created_actor_id,
          parent_session_key: sessionNode.parent_session_key,
          spawned_by: sessionNode.spawned_by,
          fork_source_session_key: sessionNode.fork_source_session_key,
          fork_source_session_id: sessionNode.fork_source_session_id,
          fork_source_entry_id: sessionNode.fork_source_entry_id,
          label: sessionNode.label,
          display_name: sessionNode.display_name,
          category: sessionNode.category,
          icon: sessionNode.icon,
          pinned_at: sessionNode.pinned_at,
          archived_at: sessionNode.archived_at,
          last_read_at: sessionNode.last_read_at,
          last_interaction_at: sessionNode.last_interaction_at,
          last_activity_at: sessionNode.last_activity_at,
        }),
      ),
  );
  executeSqliteQuerySync(
    database.db,
    db.updateTable("session_nodes").set({ entry_valid: 1 }).where("session_key", "=", sessionKey),
  );
  executeSqliteQuerySync(
    database.db,
    db
      .insertInto("session_windows")
      .values(sessionRow)
      .onConflict((conflict) =>
        conflict.column("session_id").doUpdateSet({
          session_key: sessionKey,
          previous_session_id: sessionRow.previous_session_id,
          reason: sessionRow.reason,
          session_scope: sessionRow.session_scope,
          transcript_observed_at: transcriptObservedAt,
          session_entry_provenance: sessionRow.session_entry_provenance,
          acp_owned: sessionRow.acp_owned,
          plugin_owner_id: sessionRow.plugin_owner_id,
          hook_external_content_source: sessionRow.hook_external_content_source,
          updated_at: updatedAt,
          started_at: sessionRow.started_at,
          ended_at: sessionRow.ended_at,
          status: sessionRow.status,
          chat_type: sessionRow.chat_type,
          channel: sessionRow.channel,
          account_id: sessionRow.account_id,
          primary_conversation_id: sessionRow.primary_conversation_id,
          model_provider: sessionRow.model_provider,
          model: sessionRow.model,
          agent_harness_id: sessionRow.agent_harness_id,
          parent_session_key: sessionRow.parent_session_key,
          spawned_by: sessionRow.spawned_by,
          display_name: sessionRow.display_name,
        }),
      ),
  );
  if (conversation) {
    linkSessionConversation({
      database,
      sessionId: sessionRow.session_id,
      conversation,
      updatedAt,
    });
  }
  persistSessionMemorySubjectInTransaction({
    database,
    sessionKey,
    sessionId: sessionRow.session_id,
    sessionScope: boundSessionRoot.session_scope,
    ...(options.memorySubjectSeed ? { seed: options.memorySubjectSeed } : {}),
    ...(options.memorySubjectAliasSourceKeys
      ? { aliasSourceSessionKeys: options.memorySubjectAliasSourceKeys }
      : {}),
    now: updatedAt,
  });
  publishSqliteSessionEntryCacheInvalidation(database, sessionNode);
}

/** Resolves the parent fork decision using SQLite transcript rows when totals are stale. */
