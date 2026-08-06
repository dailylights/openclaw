import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { assertOpenClawAgentSchemaContains } from "./openclaw-agent-db-schema-helpers.js";
import { OPENCLAW_AGENT_SCHEMA_SQL } from "./openclaw-agent-schema.js";
import {
  AGENT_SCOPED_MEMORY_FTS_SHADOW_TABLES,
  AGENT_SCOPED_MEMORY_FTS_TABLE,
  AGENT_SCOPED_MEMORY_SCHEMA_SQL,
  AGENT_SCOPED_MEMORY_TABLES,
  ensureOpenClawAgentScopedMemorySchema,
} from "./openclaw-agent-scoped-memory-schema.js";

describe("scoped memory additive agent schema", () => {
  const databases: DatabaseSync[] = [];

  afterEach(() => {
    for (const database of databases.splice(0)) {
      database.close();
    }
  });

  function createDatabase(): DatabaseSync {
    const database = new DatabaseSync(":memory:");
    databases.push(database);
    return database;
  }

  function tableNames(database: DatabaseSync): string[] {
    return (
      database
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")
        .all() as Array<{ name: string }>
    ).map((row) => row.name);
  }

  type ProjectionInsert = {
    projectionId: string;
    agentId: string;
    sourceRevisionId: string;
    targetAgentId: string;
    targetStoreId: string;
    targetResourceId: string;
    targetRevisionId: string;
    targetKind: "conversation" | "role" | "agent-shared" | "user";
    targetAudienceId: string;
    purpose: string;
    preview: string;
    publisherKind: "local-agent-owner" | "gateway-admin";
    publisherId: string;
    reviewState: "pending" | "approved" | "rejected" | "revoked";
    reviewerKind: "local-agent-owner" | "gateway-admin" | null;
    reviewerId: string | null;
    reviewReason: string | null;
    expiresAt: number | null;
    revocationBehavior: "tombstone";
    supersedesProjectionId: string | null;
    createdAt: number;
    reviewedAt: number | null;
    revokedAt: number | null;
  };

  type PostboxItemInsert = {
    postboxItemId: string;
    agentId: string;
    targetAgentId: string;
    targetStoreId: string;
    targetKind: "user" | "conversation";
    targetAudienceId: string;
    targetUserId: string;
    targetUserEvidenceRevision: string;
    targetResourceId: string | null;
    targetRevisionId: string | null;
    sourceConversationId: string;
    sourceMessageHandleHash: string;
    sourceEventId: string | null;
    sourceActorKind: "human" | "agent" | "service";
    sourceActorId: string;
    sourceEvidenceRevision: string;
    provenanceLabel: string;
    content: string;
    contentHash: string;
    reviewContent: string;
    reviewContentHash: string;
    reviewState: "pending" | "approved" | "rejected" | "purged";
    reviewerKind: "local-agent-owner" | "gateway-admin" | null;
    reviewerId: string | null;
    reviewReason: string | null;
    expiresAt: number | null;
    createdAt: number;
    updatedAt: number;
    reviewedAt: number | null;
    purgedAt: number | null;
  };

  function hash(character: string): string {
    return character.repeat(64);
  }

  function seedScopedMemoryGraph(database: DatabaseSync): void {
    database.exec(`
      PRAGMA foreign_keys = ON;

      INSERT INTO memory_policies
        (policy_id, agent_id, current_revision_id, revocation_epoch, lifecycle_state, created_at, updated_at)
      VALUES
        ('policy-a', 'agent-a', 'policy-revision-a', 0, 'active', 1, 1),
        ('policy-b', 'agent-b', 'policy-revision-b', 0, 'active', 1, 1);

      INSERT INTO memory_policy_revisions
        (revision_id, policy_id, revision_number, revocation_epoch, lifecycle_state, actor_kind, actor_id, reason, created_at)
      VALUES
        ('policy-revision-a', 'policy-a', 1, 0, 'active', 'human', 'owner-a', 'seed', 1),
        ('policy-revision-b', 'policy-b', 1, 0, 'active', 'human', 'owner-b', 'seed', 1);

      INSERT INTO memory_storage_roots
        (storage_root_id, agent_id, backend_kind, opaque_locator, path_key_version, path_key, authority_kind, authority_owner_id, default_capabilities_json, lifecycle_state, created_at, updated_at)
      VALUES
        ('root-a', 'agent-a', 'builtin', 'locator-a', 1, 'root-key-a', 'user', 'owner-a', '[]', 'active', 1, 1),
        ('root-b', 'agent-b', 'builtin', 'locator-b', 1, 'root-key-b', 'user', 'owner-b', '[]', 'active', 1, 1);

      INSERT INTO memory_stores
        (store_id, agent_id, storage_root_id, policy_id, scope_kind, audience_kind, audience_id, lifecycle_state, created_at, updated_at)
      VALUES
        ('source-store', 'agent-a', 'root-a', 'policy-a', 'user', 'user', 'user-a', 'active', 1, 1),
        ('projection-store', 'agent-a', 'root-a', 'policy-a', 'role', 'conversation', 'conversation-a', 'active', 1, 1),
        ('postbox-store', 'agent-a', 'root-a', 'policy-a', 'internal', 'user', 'user-a', 'active', 1, 1),
        ('foreign-store', 'agent-b', 'root-b', 'policy-b', 'role', 'conversation', 'conversation-b', 'active', 1, 1);

      INSERT INTO memory_resources (resource_id, agent_id, store_id, logical_locator, created_at)
      VALUES
        ('source-resource', 'agent-a', 'source-store', 'source.md', 1),
        ('projection-resource', 'agent-a', 'projection-store', 'projection.md', 1),
        ('postbox-resource', 'agent-a', 'postbox-store', 'postbox.md', 1),
        ('foreign-resource', 'agent-b', 'foreign-store', 'foreign.md', 1);

      INSERT INTO memory_resource_revisions
        (revision_id, resource_id, revision_number, artifact_locator, content_hash, content_bytes, policy_revision_id, policy_revocation_epoch, source_policy_set_id, lifecycle_state, actor_kind, actor_id, expires_at, created_at, activated_at, retired_at)
      VALUES
        ('source-revision', 'source-resource', 1, 'source-artifact', 'source-hash', 1, 'policy-revision-a', 0, 'source-policy-set', 'active', 'human', 'owner-a', NULL, 1, 1, NULL),
        ('projection-revision', 'projection-resource', 1, 'projection-artifact', 'projection-hash', 1, 'policy-revision-a', 0, 'projection-policy-set', 'pending', 'human', 'owner-a', NULL, 1, NULL, NULL),
        ('postbox-revision', 'postbox-resource', 1, 'postbox-artifact', 'postbox-hash', 1, 'policy-revision-a', 0, 'postbox-policy-set', 'quarantined', 'human', 'owner-a', NULL, 1, NULL, NULL),
        ('foreign-revision', 'foreign-resource', 1, 'foreign-artifact', 'foreign-hash', 1, 'policy-revision-b', 0, 'foreign-policy-set', 'active', 'human', 'owner-b', NULL, 1, 1, NULL);

      INSERT INTO memory_exposure_receipts
        (receipt_id, context_fingerprint, plan_id, run_id, run_exposure_revision, source_policy_set_id, exposed_revision_handles_json, recorded_at)
      VALUES ('exposure-a', 'context-a', 'plan-a', 'run-a', '1', 'source-policy-set', '[]', 1);
    `);
  }

  function insertProjection(
    database: DatabaseSync,
    overrides: Partial<ProjectionInsert> = {},
  ): void {
    const row: ProjectionInsert = {
      projectionId: "projection-a",
      agentId: "agent-a",
      sourceRevisionId: "source-revision",
      targetAgentId: "agent-a",
      targetStoreId: "projection-store",
      targetResourceId: "projection-resource",
      targetRevisionId: "projection-revision",
      targetKind: "conversation",
      targetAudienceId: "conversation-a",
      purpose: "Share the reviewed incident summary",
      preview: "Incident summary for conversation-a",
      publisherKind: "local-agent-owner",
      publisherId: "owner-a",
      reviewState: "pending",
      reviewerKind: null,
      reviewerId: null,
      reviewReason: null,
      expiresAt: 100,
      revocationBehavior: "tombstone",
      supersedesProjectionId: null,
      createdAt: 10,
      reviewedAt: null,
      revokedAt: null,
      ...overrides,
    };
    database
      .prepare(
        `INSERT INTO memory_projections (
          projection_id, agent_id, source_revision_id, target_agent_id, target_store_id,
          target_resource_id, target_revision_id, target_kind, target_audience_id, purpose,
          preview, publisher_kind, publisher_id, review_state, reviewer_kind, reviewer_id,
          review_reason, expires_at, revocation_behavior, supersedes_projection_id, created_at,
          reviewed_at, revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        row.projectionId,
        row.agentId,
        row.sourceRevisionId,
        row.targetAgentId,
        row.targetStoreId,
        row.targetResourceId,
        row.targetRevisionId,
        row.targetKind,
        row.targetAudienceId,
        row.purpose,
        row.preview,
        row.publisherKind,
        row.publisherId,
        row.reviewState,
        row.reviewerKind,
        row.reviewerId,
        row.reviewReason,
        row.expiresAt,
        row.revocationBehavior,
        row.supersedesProjectionId,
        row.createdAt,
        row.reviewedAt,
        row.revokedAt,
      );
  }

  function insertPostboxItem(
    database: DatabaseSync,
    overrides: Partial<PostboxItemInsert> = {},
  ): void {
    const row: PostboxItemInsert = {
      postboxItemId: "postbox-item-a",
      agentId: "agent-a",
      targetAgentId: "agent-a",
      targetStoreId: "postbox-store",
      targetKind: "user",
      targetAudienceId: "user-a",
      targetUserId: "user-a",
      targetUserEvidenceRevision: "target-evidence-a",
      targetResourceId: null,
      targetRevisionId: null,
      sourceConversationId: "conversation-a",
      sourceMessageHandleHash: hash("a"),
      sourceEventId: "event-a",
      sourceActorKind: "human",
      sourceActorId: "sender-a",
      sourceEvidenceRevision: "source-evidence-a",
      provenanceLabel: "From conversation-a",
      content: "Original deposited text",
      contentHash: hash("b"),
      reviewContent: "Original deposited text",
      reviewContentHash: hash("b"),
      reviewState: "pending",
      reviewerKind: null,
      reviewerId: null,
      reviewReason: null,
      expiresAt: 100,
      createdAt: 10,
      updatedAt: 10,
      reviewedAt: null,
      purgedAt: null,
      ...overrides,
    };
    database
      .prepare(
        `INSERT INTO memory_postbox_items (
          postbox_item_id, agent_id, target_agent_id, target_store_id, target_kind,
          target_audience_id, target_user_id, target_user_evidence_revision,
          target_resource_id, target_revision_id, source_conversation_id,
          source_message_handle_hash, source_event_id, source_actor_kind, source_actor_id,
          source_evidence_revision, provenance_label, content, content_hash, review_content,
          review_content_hash, review_state, reviewer_kind, reviewer_id, review_reason,
          expires_at, created_at, updated_at, reviewed_at, purged_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        row.postboxItemId,
        row.agentId,
        row.targetAgentId,
        row.targetStoreId,
        row.targetKind,
        row.targetAudienceId,
        row.targetUserId,
        row.targetUserEvidenceRevision,
        row.targetResourceId,
        row.targetRevisionId,
        row.sourceConversationId,
        row.sourceMessageHandleHash,
        row.sourceEventId,
        row.sourceActorKind,
        row.sourceActorId,
        row.sourceEvidenceRevision,
        row.provenanceLabel,
        row.content,
        row.contentHash,
        row.reviewContent,
        row.reviewContentHash,
        row.reviewState,
        row.reviewerKind,
        row.reviewerId,
        row.reviewReason,
        row.expiresAt,
        row.createdAt,
        row.updatedAt,
        row.reviewedAt,
        row.purgedAt,
      );
  }

  it("lazily installs every canonical table from an absent schema", () => {
    const database = createDatabase();

    ensureOpenClawAgentScopedMemorySchema(database);

    expect(tableNames(database)).toEqual(
      expect.arrayContaining([
        ...AGENT_SCOPED_MEMORY_TABLES,
        AGENT_SCOPED_MEMORY_FTS_TABLE,
        ...AGENT_SCOPED_MEMORY_FTS_SHADOW_TABLES,
      ]),
    );
  });

  it("finishes an interrupted schema that created only the first table", () => {
    const database = createDatabase();
    const firstTableOnly = AGENT_SCOPED_MEMORY_SCHEMA_SQL.slice(
      0,
      AGENT_SCOPED_MEMORY_SCHEMA_SQL.indexOf("CREATE TABLE IF NOT EXISTS memory_stores"),
    );
    database.exec(firstTableOnly);
    expect(tableNames(database)).toContain("memory_storage_roots");
    expect(tableNames(database)).not.toContain("memory_stores");

    ensureOpenClawAgentScopedMemorySchema(database);

    expect(tableNames(database)).toEqual(
      expect.arrayContaining([
        ...AGENT_SCOPED_MEMORY_TABLES,
        AGENT_SCOPED_MEMORY_FTS_TABLE,
        ...AGENT_SCOPED_MEMORY_FTS_SHADOW_TABLES,
      ]),
    );
  });

  it("keeps the current-version schema compatible before feature-local ensure", () => {
    const database = createDatabase();
    database.exec(OPENCLAW_AGENT_SCHEMA_SQL.replace(AGENT_SCOPED_MEMORY_SCHEMA_SQL, ""));

    expect(() =>
      assertOpenClawAgentSchemaContains(database, ":memory:", OPENCLAW_AGENT_SCHEMA_SQL),
    ).not.toThrow();
  });

  it("keeps scoped FTS rows synchronized across insert, update, and delete", () => {
    const database = createDatabase();
    ensureOpenClawAgentScopedMemorySchema(database);
    database.exec("PRAGMA foreign_keys = OFF");
    database
      .prepare(
        `INSERT INTO memory_scoped_chunks
          (chunk_id, revision_id, chunk_ordinal, start_line, end_line, text, content_hash, model, updated_at)
         VALUES (?, ?, 0, 1, 1, ?, ?, 'test', 1)`,
      )
      .run("chunk-1", "revision-1", "alpha token", "hash-1");
    expect(
      database
        .prepare(
          "SELECT chunk_id FROM memory_scoped_chunks_fts WHERE memory_scoped_chunks_fts MATCH ?",
        )
        .all('"alpha"'),
    ).toEqual([{ chunk_id: "chunk-1" }]);

    database
      .prepare("UPDATE memory_scoped_chunks SET text = ?, content_hash = ? WHERE chunk_id = ?")
      .run("beta token", "hash-2", "chunk-1");
    expect(
      database
        .prepare(
          "SELECT chunk_id FROM memory_scoped_chunks_fts WHERE memory_scoped_chunks_fts MATCH ?",
        )
        .all('"beta"'),
    ).toEqual([{ chunk_id: "chunk-1" }]);

    database.prepare("DELETE FROM memory_scoped_chunks WHERE chunk_id = ?").run("chunk-1");
    expect(database.prepare("SELECT chunk_id FROM memory_scoped_chunks_fts").all()).toEqual([]);
  });

  it("requires a pending, finite, same-agent projection copy for one named non-private audience", () => {
    const database = createDatabase();
    ensureOpenClawAgentScopedMemorySchema(database);
    seedScopedMemoryGraph(database);

    insertProjection(database);

    // Make the private-store copy otherwise valid so the target-kind CHECK is
    // the rejection under test, rather than the pending-copy lifecycle guard.
    database
      .prepare("UPDATE memory_resource_revisions SET lifecycle_state = ? WHERE revision_id = ?")
      .run("pending", "postbox-revision");
    expect(() =>
      insertProjection(database, {
        projectionId: "private-target",
        targetKind: "user",
        targetStoreId: "postbox-store",
        targetResourceId: "postbox-resource",
        targetRevisionId: "postbox-revision",
        targetAudienceId: "user-a",
      }),
    ).toThrow(/CHECK constraint failed/u);
    expect(() =>
      insertProjection(database, {
        projectionId: "empty-target",
        targetAudienceId: "",
      }),
    ).toThrow(/memory projection target must be a same-agent named store/u);
    // As above, make the foreign copy otherwise valid so this reaches the
    // same-agent constraint instead of failing on its active lifecycle state.
    database
      .prepare("UPDATE memory_resource_revisions SET lifecycle_state = ? WHERE revision_id = ?")
      .run("pending", "foreign-revision");
    expect(() =>
      insertProjection(database, {
        projectionId: "cross-agent-target",
        targetAgentId: "agent-b",
        targetStoreId: "foreign-store",
        targetResourceId: "foreign-resource",
        targetRevisionId: "foreign-revision",
        targetAudienceId: "conversation-b",
      }),
    ).toThrow(/CHECK constraint failed/u);
    expect(() =>
      insertProjection(database, {
        projectionId: "encoded-user-target",
        targetStoreId: "postbox-store",
        targetResourceId: "postbox-resource",
        targetRevisionId: "postbox-revision",
        targetAudienceId: "user-a",
      }),
    ).toThrow(/memory projection target must be a same-agent named store/u);
    expect(() =>
      insertProjection(database, {
        projectionId: "expired-projection",
        expiresAt: 10,
      }),
    ).toThrow(/CHECK constraint failed/u);
    expect(() =>
      insertProjection(database, {
        projectionId: "preapproved-projection",
        reviewState: "approved",
        reviewerKind: "gateway-admin",
        reviewerId: "admin-a",
        reviewedAt: 20,
      }),
    ).toThrow(/memory projections must begin pending/u);

    expect(() =>
      database
        .prepare(
          "UPDATE memory_projections SET review_state = ?, reviewer_kind = ?, reviewer_id = ?, reviewed_at = ? WHERE projection_id = ?",
        )
        .run("approved", "gateway-admin", "admin-a", 20, "projection-a"),
    ).toThrow(/memory projection approval requires an active copy/u);
    database
      .prepare(
        "UPDATE memory_resource_revisions SET lifecycle_state = ?, activated_at = ? WHERE revision_id = ?",
      )
      .run("active", 20, "projection-revision");
    database
      .prepare(
        "UPDATE memory_projections SET review_state = ?, reviewer_kind = ?, reviewer_id = ?, reviewed_at = ? WHERE projection_id = ?",
      )
      .run("approved", "gateway-admin", "admin-a", 20, "projection-a");
  });

  it("preserves reviewer audit metadata when an approved projection is revoked", () => {
    const database = createDatabase();
    ensureOpenClawAgentScopedMemorySchema(database);
    seedScopedMemoryGraph(database);
    insertProjection(database);
    database
      .prepare(
        "UPDATE memory_resource_revisions SET lifecycle_state = ?, activated_at = ? WHERE revision_id = ?",
      )
      .run("active", 20, "projection-revision");
    database
      .prepare(
        "UPDATE memory_projections SET review_state = ?, reviewer_kind = ?, reviewer_id = ?, reviewed_at = ? WHERE projection_id = ?",
      )
      .run("approved", "gateway-admin", "admin-a", 20, "projection-a");

    expect(() =>
      database
        .prepare(
          "UPDATE memory_projections SET review_state = ?, reviewer_id = ?, reviewed_at = ?, revoked_at = ? WHERE projection_id = ?",
        )
        .run("revoked", "forged-reviewer", 50, 51, "projection-a"),
    ).toThrow(/memory projection review metadata is immutable after review/u);

    database
      .prepare(
        "UPDATE memory_projections SET review_state = ?, revoked_at = ? WHERE projection_id = ?",
      )
      .run("revoked", 51, "projection-a");
    expect(
      database
        .prepare(
          "SELECT review_state, reviewer_id, reviewed_at, revoked_at FROM memory_projections WHERE projection_id = ?",
        )
        .get("projection-a"),
    ).toEqual({
      review_state: "revoked",
      reviewer_id: "admin-a",
      reviewed_at: 20,
      revoked_at: 51,
    });
    expect(() =>
      database
        .prepare("UPDATE memory_projections SET revoked_at = ? WHERE projection_id = ?")
        .run(52, "projection-a"),
    ).toThrow(/memory projection revocation timestamp can only be set on revocation/u);
  });

  it("keeps projection exposure evidence append-only for revocation impact", () => {
    const database = createDatabase();
    ensureOpenClawAgentScopedMemorySchema(database);
    seedScopedMemoryGraph(database);
    insertProjection(database);

    database
      .prepare(
        "INSERT INTO memory_projection_exposures (projection_id, exposure_receipt_id, recorded_at) VALUES (?, ?, ?)",
      )
      .run("projection-a", "exposure-a", 30);

    expect(() =>
      database
        .prepare("UPDATE memory_projection_exposures SET recorded_at = ? WHERE projection_id = ?")
        .run(31, "projection-a"),
    ).toThrow(/memory projection exposures are immutable/u);
    expect(() =>
      database
        .prepare("DELETE FROM memory_projection_exposures WHERE projection_id = ?")
        .run("projection-a"),
    ).toThrow(/memory projection exposures cannot be deleted/u);
  });

  it("keeps postbox off by default and preserves a review-only quarantine record", () => {
    const database = createDatabase();
    ensureOpenClawAgentScopedMemorySchema(database);
    seedScopedMemoryGraph(database);

    database
      .prepare(
        "INSERT INTO memory_sharing_settings (agent_id, created_at, updated_at) VALUES (?, ?, ?)",
      )
      .run("agent-a", 10, 10);
    expect(
      database
        .prepare(
          "SELECT postbox_mode, rate_limit_window_ms, rate_limit_max_items FROM memory_sharing_settings WHERE agent_id = ?",
        )
        .get("agent-a"),
    ).toEqual({ postbox_mode: "off", rate_limit_window_ms: 3_600_000, rate_limit_max_items: 10 });
    expect(() =>
      database
        .prepare("UPDATE memory_sharing_settings SET postbox_mode = ? WHERE agent_id = ?")
        .run("labeled-without-review", "agent-a"),
    ).toThrow(/CHECK constraint failed/u);

    insertPostboxItem(database);
    database
      .prepare(
        "UPDATE memory_postbox_items SET review_content = ?, review_content_hash = ?, updated_at = ? WHERE postbox_item_id = ?",
      )
      .run("Owner-edited review text", hash("c"), 11, "postbox-item-a");
    expect(() =>
      database
        .prepare(
          "UPDATE memory_postbox_items SET target_resource_id = ?, target_revision_id = ?, updated_at = ? WHERE postbox_item_id = ?",
        )
        .run("postbox-resource", "postbox-revision", 20, "postbox-item-a"),
    ).toThrow(/memory postbox target can only attach during pending approval/u);
    expect(() =>
      database
        .prepare(
          "UPDATE memory_postbox_items SET review_state = ?, reviewer_kind = ?, reviewer_id = ?, reviewed_at = ?, updated_at = ? WHERE postbox_item_id = ?",
        )
        .run("approved", "local-agent-owner", "owner-a", 20, 20, "postbox-item-a"),
    ).toThrow(/memory postbox review state cannot be reopened/u);
    database
      .prepare(
        `UPDATE memory_postbox_items
         SET target_resource_id = ?, target_revision_id = ?, review_state = ?, reviewer_kind = ?, reviewer_id = ?, reviewed_at = ?, updated_at = ?
         WHERE postbox_item_id = ?`,
      )
      .run(
        "postbox-resource",
        "postbox-revision",
        "approved",
        "local-agent-owner",
        "owner-a",
        20,
        20,
        "postbox-item-a",
      );

    expect(
      database
        .prepare(
          "SELECT content, review_content, review_state FROM memory_postbox_items WHERE postbox_item_id = ?",
        )
        .get("postbox-item-a"),
    ).toEqual({
      content: "Original deposited text",
      review_content: "Owner-edited review text",
      review_state: "approved",
    });
    expect(() =>
      database
        .prepare("UPDATE memory_postbox_items SET content = ? WHERE postbox_item_id = ?")
        .run("mutated source", "postbox-item-a"),
    ).toThrow(/memory postbox content can only be redacted during purge/u);
    expect(() =>
      database
        .prepare("UPDATE memory_postbox_items SET review_content = ? WHERE postbox_item_id = ?")
        .run("late review edit", "postbox-item-a"),
    ).toThrow(/memory postbox review copy can only change while pending/u);
    expect(() =>
      insertPostboxItem(database, {
        postboxItemId: "replayed-postbox-item",
      }),
    ).toThrow(/UNIQUE constraint failed/u);
    expect(() =>
      insertPostboxItem(database, {
        postboxItemId: "expired-postbox-item",
        sourceMessageHandleHash: hash("d"),
        expiresAt: 10,
      }),
    ).toThrow(/CHECK constraint failed/u);
  });

  it("preserves reviewer audit metadata when a reviewed postbox item is purged", () => {
    const database = createDatabase();
    ensureOpenClawAgentScopedMemorySchema(database);
    seedScopedMemoryGraph(database);
    insertPostboxItem(database);
    database
      .prepare(
        `UPDATE memory_postbox_items
         SET target_resource_id = ?, target_revision_id = ?, review_state = ?, reviewer_kind = ?, reviewer_id = ?, reviewed_at = ?, updated_at = ?
         WHERE postbox_item_id = ?`,
      )
      .run(
        "postbox-resource",
        "postbox-revision",
        "approved",
        "local-agent-owner",
        "owner-a",
        20,
        20,
        "postbox-item-a",
      );

    const purgedHash = "eccd0ed57eaab896fae1c5934381ca8d1a9ec62a1d61695e3950e8b1436bb1ca";
    expect(() =>
      database
        .prepare(
          `UPDATE memory_postbox_items
           SET content = ?, content_hash = ?, review_content = ?, review_content_hash = ?,
               review_state = ?, reviewer_id = ?, reviewed_at = ?, purged_at = ?, updated_at = ?
           WHERE postbox_item_id = ?`,
        )
        .run(
          "[purged]",
          purgedHash,
          "[purged]",
          purgedHash,
          "purged",
          "forged-reviewer",
          50,
          51,
          51,
          "postbox-item-a",
        ),
    ).toThrow(/memory postbox review metadata/u);

    expect(() =>
      database
        .prepare(
          `UPDATE memory_postbox_items
           SET content = ?, content_hash = ?, review_content = ?, review_content_hash = ?,
               review_state = ?, purged_at = ?, updated_at = ?
           WHERE postbox_item_id = ?`,
        )
        .run("[purged]", purgedHash, "[purged]", purgedHash, "purged", 19, 20, "postbox-item-a"),
    ).toThrow(/memory postbox purge timestamp can only be set on purge/u);

    database
      .prepare(
        `UPDATE memory_postbox_items
         SET content = ?, content_hash = ?, review_content = ?, review_content_hash = ?,
             review_state = ?, purged_at = ?, updated_at = ?
         WHERE postbox_item_id = ?`,
      )
      .run("[purged]", purgedHash, "[purged]", purgedHash, "purged", 51, 51, "postbox-item-a");
    expect(
      database
        .prepare(
          "SELECT review_state, reviewer_id, reviewed_at, purged_at FROM memory_postbox_items WHERE postbox_item_id = ?",
        )
        .get("postbox-item-a"),
    ).toEqual({
      review_state: "purged",
      reviewer_id: "owner-a",
      reviewed_at: 20,
      purged_at: 51,
    });
    expect(() =>
      database
        .prepare("UPDATE memory_postbox_items SET purged_at = ? WHERE postbox_item_id = ?")
        .run(52, "postbox-item-a"),
    ).toThrow(/memory postbox purge timestamp can only be set on purge/u);

    insertPostboxItem(database, {
      postboxItemId: "pending-purge-item",
      sourceMessageHandleHash: hash("e"),
    });
    expect(() =>
      database
        .prepare(
          "UPDATE memory_postbox_items SET review_state = ?, purged_at = ?, updated_at = ? WHERE postbox_item_id = ?",
        )
        .run("purged", 51, 51, "pending-purge-item"),
    ).toThrow(/memory postbox purge requires canonical content redaction/u);
    expect(() =>
      database
        .prepare(
          `UPDATE memory_postbox_items
           SET content = ?, content_hash = ?, review_content = ?, review_content_hash = ?,
               review_state = ?, reviewer_kind = ?, reviewer_id = ?, reviewed_at = ?, purged_at = ?, updated_at = ?
           WHERE postbox_item_id = ?`,
        )
        .run(
          "[purged]",
          purgedHash,
          "[purged]",
          purgedHash,
          "purged",
          "gateway-admin",
          "forged-reviewer",
          50,
          51,
          51,
          "pending-purge-item",
        ),
    ).toThrow(/memory postbox review metadata can only be set by approval or rejection/u);

    database
      .prepare(
        `UPDATE memory_postbox_items
         SET content = ?, content_hash = ?, review_content = ?, review_content_hash = ?,
             review_state = ?, purged_at = ?, updated_at = ?
         WHERE postbox_item_id = ?`,
      )
      .run("[purged]", purgedHash, "[purged]", purgedHash, "purged", 51, 51, "pending-purge-item");
    expect(
      database
        .prepare(
          "SELECT review_state, reviewer_kind, reviewer_id, reviewed_at, purged_at FROM memory_postbox_items WHERE postbox_item_id = ?",
        )
        .get("pending-purge-item"),
    ).toEqual({
      review_state: "purged",
      reviewer_kind: null,
      reviewer_id: null,
      reviewed_at: null,
      purged_at: 51,
    });
  });

  it("persists per-source-channel postbox rate limits and aggregates dropped deposits without their content", () => {
    const database = createDatabase();
    ensureOpenClawAgentScopedMemorySchema(database);
    seedScopedMemoryGraph(database);

    database
      .prepare(
        `INSERT INTO memory_postbox_rate_limits
          (agent_id, source_conversation_id, target_store_id, window_started_at, accepted_count, last_accepted_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run("agent-a", "conversation-a", "postbox-store", 10, 1, 10, 10);
    expect(
      database
        .prepare(
          "SELECT accepted_count, dropped_count, last_dropped_at FROM memory_postbox_rate_limits WHERE agent_id = ? AND source_conversation_id = ? AND target_store_id = ?",
        )
        .get("agent-a", "conversation-a", "postbox-store"),
    ).toEqual({ accepted_count: 1, dropped_count: 0, last_dropped_at: null });
    expect(() =>
      database
        .prepare(
          `INSERT INTO memory_postbox_rate_limits
            (agent_id, source_conversation_id, target_store_id, window_started_at, accepted_count, last_accepted_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run("agent-a", "conversation-a", "projection-store", 10, 1, 10, 10),
    ).toThrow(/memory postbox rate limit target must be a same-agent user store/u);
    database
      .prepare(
        `UPDATE memory_postbox_rate_limits
         SET dropped_count = dropped_count + 1, last_dropped_at = ?, updated_at = ?
         WHERE agent_id = ? AND source_conversation_id = ? AND target_store_id = ?`,
      )
      .run(12, 12, "agent-a", "conversation-a", "postbox-store");
    expect(
      database
        .prepare(
          "SELECT dropped_count, last_dropped_at FROM memory_postbox_rate_limits WHERE agent_id = ? AND source_conversation_id = ? AND target_store_id = ?",
        )
        .get("agent-a", "conversation-a", "postbox-store"),
    ).toEqual({ dropped_count: 1, last_dropped_at: 12 });
    expect(() =>
      database
        .prepare(
          "UPDATE memory_postbox_rate_limits SET dropped_count = ?, last_dropped_at = ?, updated_at = ? WHERE agent_id = ? AND source_conversation_id = ? AND target_store_id = ?",
        )
        .run(0, 13, 13, "agent-a", "conversation-a", "postbox-store"),
    ).toThrow(/CHECK constraint failed/u);
    expect(() =>
      database
        .prepare(
          "UPDATE memory_postbox_rate_limits SET dropped_count = ?, last_dropped_at = ?, updated_at = ? WHERE agent_id = ? AND source_conversation_id = ? AND target_store_id = ?",
        )
        .run(2, 9, 13, "agent-a", "conversation-a", "postbox-store"),
    ).toThrow(/CHECK constraint failed/u);
    expect(() =>
      database
        .prepare(
          "UPDATE memory_postbox_rate_limits SET target_store_id = ? WHERE agent_id = ? AND source_conversation_id = ? AND target_store_id = ?",
        )
        .run("foreign-store", "agent-a", "conversation-a", "postbox-store"),
    ).toThrow(/memory postbox rate limit target must be a same-agent user store/u);
  });
});
