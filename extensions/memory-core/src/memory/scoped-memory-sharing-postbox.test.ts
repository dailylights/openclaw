import fs from "node:fs";
import { openOpenClawAgentDatabase } from "openclaw/plugin-sdk/sqlite-runtime";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  createBuiltinScopedMemoryResourceRevision,
  reviseBuiltinScopedMemoryPolicy,
} from "../../test-api.js";
import { createScopedMemorySharingService } from "./scoped-memory-sharing.js";
import {
  createScopedMemorySharingTestFixture,
  SCOPED_MEMORY_SHARING_AGENT_ID as AGENT_ID,
  SCOPED_MEMORY_SHARING_OWNER_ID as OWNER_ID,
  scopedMemorySharingOwnerAuthority as ownerAuthority,
} from "./scoped-memory-sharing.test-support.js";

describe("scoped memory sharing postbox", () => {
  let fixture: ReturnType<typeof createScopedMemorySharingTestFixture>;
  let nowMs = 10_000;

  beforeEach(() => {
    nowMs = 10_000;
    fixture = createScopedMemorySharingTestFixture({ now: () => nowMs });
    fixture.setup();
  });

  afterEach(() => {
    fixture.teardown();
  });

  function createUserPostboxStore() {
    return fixture.createUserPostboxStore();
  }

  function issuePostboxHandle(...params: Parameters<(typeof fixture)["issuePostboxHandle"]>) {
    return fixture.issuePostboxHandle(...params);
  }

  function depositPostbox(...params: Parameters<(typeof fixture)["depositPostbox"]>) {
    return fixture.depositPostbox(...params);
  }

  it("accepts a current postbox handle once and does not expose its content in status", () => {
    createUserPostboxStore();
    const service = createScopedMemorySharingService({ now: () => nowMs });
    expect(service.status({ agentId: AGENT_ID, authority: ownerAuthority() }).postboxMode).toBe(
      "off",
    );
    service.configurePostbox({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      mode: "review-required",
    });
    const wrongSessionHandle = issuePostboxHandle(service);
    expect(() =>
      depositPostbox(service, wrongSessionHandle, { sessionId: "another-session" }),
    ).toThrow("postbox deposit is unavailable");
    expect(() => depositPostbox(service, wrongSessionHandle)).toThrow(
      "postbox deposit is unavailable",
    );
    const wrongConversationHandle = issuePostboxHandle(service);
    expect(() =>
      depositPostbox(service, wrongConversationHandle, {
        sourceConversationId: "another-conversation",
      }),
    ).toThrow("postbox deposit is unavailable");
    const handle = issuePostboxHandle(service, {
      sessionId: "source-session-a",
      sourceConversationId: "source-conversation-a",
      content: "quarantined message must stay private",
    });

    expect(
      depositPostbox(service, handle, {
        sessionId: "source-session-a",
        sourceConversationId: "source-conversation-a",
      }),
    ).toEqual({ accepted: true });
    expect(() =>
      depositPostbox(service, handle, {
        sessionId: "source-session-a",
        sourceConversationId: "source-conversation-a",
      }),
    ).toThrow("postbox deposit is unavailable");
    const status = service.status({ agentId: AGENT_ID, authority: ownerAuthority() });
    expect(status.postboxItems).toHaveLength(1);
    const pending = status.postboxItems[0];
    if (!pending) {
      throw new Error("expected a pending postbox item");
    }
    expect(pending).toMatchObject({
      sourceConversationId: "source-conversation-a",
      reviewState: "pending",
    });
    expect(pending.contentPreview).not.toContain("quarantined message");
    expect(
      openOpenClawAgentDatabase({ agentId: AGENT_ID })
        .db.prepare(
          "SELECT target_resource_id, target_revision_id FROM memory_postbox_items WHERE postbox_item_id = ?",
        )
        .get(pending.postboxItemId),
    ).toEqual({ target_resource_id: null, target_revision_id: null });
  });

  it("allows only the target owner or gateway admin to inspect a pending postbox body", () => {
    createUserPostboxStore();
    const service = createScopedMemorySharingService({ now: () => nowMs });
    service.configurePostbox({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      mode: "review-required",
    });
    const reviewContent = "quarantined review body must remain owner-only";
    expect(
      depositPostbox(service, issuePostboxHandle(service, { content: reviewContent })),
    ).toEqual({ accepted: true });
    const pending = service.status({ agentId: AGENT_ID, authority: ownerAuthority() })
      .postboxItems[0];
    if (!pending) {
      throw new Error("expected a pending postbox item");
    }

    expect(
      service.inspectPostbox({
        agentId: AGENT_ID,
        authority: ownerAuthority(),
        postboxItemId: pending.postboxItemId,
      }),
    ).toEqual({
      postboxItemId: pending.postboxItemId,
      reviewContent,
      expiresAt: new Date(nowMs + 1_000).toISOString(),
    });
    expect(pending.contentPreview).not.toContain(reviewContent);
    expect(() =>
      service.inspectPostbox({
        agentId: AGENT_ID,
        authority: { kind: "local-agent-owner", id: "another-owner" },
        postboxItemId: pending.postboxItemId,
      }),
    ).toThrow("sharing authority is unavailable");
    expect(
      service.inspectPostbox({
        agentId: AGENT_ID,
        authority: { kind: "gateway-admin", id: "gateway-admin-1" },
        postboxItemId: pending.postboxItemId,
      }).reviewContent,
    ).toBe(reviewContent);

    service.reviewPostbox({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      postboxItemId: pending.postboxItemId,
      decision: "approve",
      editedContent: "owner-reviewed body",
    });
    expect(() =>
      service.inspectPostbox({
        agentId: AGENT_ID,
        authority: ownerAuthority(),
        postboxItemId: pending.postboxItemId,
      }),
    ).toThrow("postbox inspection is unavailable");
  });

  it("expires a source-message handle before it can deposit", () => {
    createUserPostboxStore();
    const service = createScopedMemorySharingService({ now: () => nowMs });
    service.configurePostbox({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      mode: "review-required",
    });
    const handle = issuePostboxHandle(service, { expiresAtMs: nowMs + 1 });

    nowMs += 1;
    expect(() => depositPostbox(service, handle)).toThrow("postbox deposit is unavailable");
  });

  it("does not leave an active postbox copy if final approval cannot attach it", () => {
    createUserPostboxStore();
    const service = createScopedMemorySharingService({ now: () => nowMs });
    service.configurePostbox({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      mode: "review-required",
    });
    expect(depositPostbox(service, issuePostboxHandle(service))).toEqual({ accepted: true });
    const pending = service.status({ agentId: AGENT_ID, authority: ownerAuthority() })
      .postboxItems[0];
    if (!pending) {
      throw new Error("expected pending postbox item");
    }
    const database = openOpenClawAgentDatabase({ agentId: AGENT_ID }).db;
    database.exec(`
      CREATE TRIGGER fail_postbox_approval
      BEFORE UPDATE OF review_state ON memory_postbox_items
      WHEN NEW.review_state = 'approved'
      BEGIN
        SELECT RAISE(ABORT, 'forced postbox approval failure');
      END;
    `);

    expect(() =>
      service.reviewPostbox({
        agentId: AGENT_ID,
        authority: ownerAuthority(),
        postboxItemId: pending.postboxItemId,
        decision: "approve",
      }),
    ).toThrow("forced postbox approval failure");
    expect(
      database
        .prepare(
          "SELECT review_state, target_resource_id, target_revision_id FROM memory_postbox_items WHERE postbox_item_id = ?",
        )
        .get(pending.postboxItemId),
    ).toEqual({ review_state: "pending", target_resource_id: null, target_revision_id: null });
    const failedCopy = database
      .prepare(
        `SELECT revision.revision_id, revision.lifecycle_state
           FROM memory_resources AS resource
           INNER JOIN memory_resource_revisions AS revision ON revision.resource_id = resource.resource_id
          WHERE resource.logical_locator = ?`,
      )
      .get(`postbox/${pending.postboxItemId}.md`) as
      | { revision_id: string; lifecycle_state: string }
      | undefined;
    if (!failedCopy) {
      throw new Error("expected tombstoned postbox copy");
    }
    expect(failedCopy.lifecycle_state).toBe("tombstoned");
    expect(fs.existsSync(fixture.artifactPathForRevision(failedCopy.revision_id))).toBe(false);
  });

  it("allows historical rejection and purge after the target policy has been revoked", () => {
    const targetStore = createUserPostboxStore();
    const service = createScopedMemorySharingService({ now: () => nowMs });
    service.configurePostbox({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      mode: "review-required",
    });
    const rejectHandle = issuePostboxHandle(service, {
      sessionId: "reject-session",
      sourceConversationId: "reject-conversation",
    });
    const purgeHandle = issuePostboxHandle(service, {
      sessionId: "purge-session",
      sourceConversationId: "purge-conversation",
    });
    expect(
      depositPostbox(service, rejectHandle, {
        sessionId: "reject-session",
        sourceConversationId: "reject-conversation",
      }),
    ).toEqual({ accepted: true });
    expect(
      depositPostbox(service, purgeHandle, {
        sessionId: "purge-session",
        sourceConversationId: "purge-conversation",
      }),
    ).toEqual({ accepted: true });
    const items = service.status({ agentId: AGENT_ID, authority: ownerAuthority() }).postboxItems;
    const rejectItem = items.find((item) => item.sourceConversationId === "reject-conversation");
    const purgeItem = items.find((item) => item.sourceConversationId === "purge-conversation");
    if (!rejectItem || !purgeItem) {
      throw new Error("expected both postbox fixtures");
    }
    service.reviewPostbox({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      postboxItemId: purgeItem.postboxItemId,
      decision: "approve",
    });
    const database = openOpenClawAgentDatabase({ agentId: AGENT_ID }).db;
    const target = database
      .prepare("SELECT target_revision_id FROM memory_postbox_items WHERE postbox_item_id = ?")
      .get(purgeItem.postboxItemId) as { target_revision_id: string };

    nowMs += 1;
    reviseBuiltinScopedMemoryPolicy({
      agentId: AGENT_ID,
      policyId: targetStore.policyId,
      entries: [],
      actor: { kind: "human", id: OWNER_ID },
      reason: "revoke target policy while items await cleanup",
      nowMs,
    });

    expect(
      service.reviewPostbox({
        agentId: AGENT_ID,
        authority: ownerAuthority(),
        postboxItemId: rejectItem.postboxItemId,
        decision: "reject",
        reason: "target policy is no longer active",
      }).reviewState,
    ).toBe("rejected");
    expect(
      service.purgePostbox({
        agentId: AGENT_ID,
        authority: ownerAuthority(),
        postboxItemId: purgeItem.postboxItemId,
      }).reviewState,
    ).toBe("purged");
    expect(
      database
        .prepare("SELECT lifecycle_state FROM memory_resource_revisions WHERE revision_id = ?")
        .get(target.target_revision_id),
    ).toEqual({ lifecycle_state: "tombstoned" });
  });

  it("resets the entire rate-limit window, including prior dropped-item metadata", () => {
    createUserPostboxStore();
    const service = createScopedMemorySharingService({ now: () => nowMs });
    service.configurePostbox({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      mode: "review-required",
    });
    const database = openOpenClawAgentDatabase({ agentId: AGENT_ID }).db;
    database
      .prepare(
        "UPDATE memory_sharing_settings SET rate_limit_window_ms = ?, rate_limit_max_items = ? WHERE agent_id = ?",
      )
      .run(100, 1, AGENT_ID);

    expect(depositPostbox(service, issuePostboxHandle(service))).toEqual({ accepted: true });
    nowMs += 1;
    expect(
      depositPostbox(service, issuePostboxHandle(service, { sessionId: "source-session-2" }), {
        sessionId: "source-session-2",
      }),
    ).toEqual({ accepted: false });
    expect(
      database
        .prepare(
          "SELECT accepted_count, dropped_count, last_dropped_at FROM memory_postbox_rate_limits",
        )
        .get(),
    ).toEqual({ accepted_count: 1, dropped_count: 1, last_dropped_at: nowMs });

    nowMs += 100;
    expect(
      depositPostbox(service, issuePostboxHandle(service, { sessionId: "source-session-3" }), {
        sessionId: "source-session-3",
      }),
    ).toEqual({ accepted: true });
    expect(
      database
        .prepare(
          "SELECT window_started_at, accepted_count, dropped_count, last_dropped_at FROM memory_postbox_rate_limits",
        )
        .get(),
    ).toEqual({
      window_started_at: nowMs,
      accepted_count: 1,
      dropped_count: 0,
      last_dropped_at: null,
    });
  });

  it("purges an approved postbox promotion and tombstones the promoted copy", () => {
    createUserPostboxStore();
    const service = createScopedMemorySharingService({ now: () => nowMs });
    service.configurePostbox({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      mode: "review-required",
    });
    expect(depositPostbox(service, issuePostboxHandle(service))).toEqual({ accepted: true });
    const pending = service.status({ agentId: AGENT_ID, authority: ownerAuthority() })
      .postboxItems[0];
    if (!pending) {
      throw new Error("expected pending postbox item");
    }
    const approved = service.reviewPostbox({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      postboxItemId: pending.postboxItemId,
      decision: "approve",
      editedContent: "reviewed postbox content",
    });
    expect(approved.reviewState).toBe("approved");
    const database = openOpenClawAgentDatabase({ agentId: AGENT_ID }).db;
    const target = database
      .prepare("SELECT target_revision_id FROM memory_postbox_items WHERE postbox_item_id = ?")
      .get(pending.postboxItemId) as { target_revision_id: string };
    expect(target.target_revision_id).toEqual(expect.any(String));
    const artifact = database
      .prepare(
        `SELECT resource.resource_id
           FROM memory_resource_revisions AS revision
           INNER JOIN memory_resources AS resource ON resource.resource_id = revision.resource_id
          WHERE revision.revision_id = ?`,
      )
      .get(target.target_revision_id) as { resource_id: string };
    const artifactPath = fixture.artifactPathForRevision(target.target_revision_id);
    expect(fs.readFileSync(artifactPath, "utf8")).toBe("reviewed postbox content");
    const descendant = createBuiltinScopedMemoryResourceRevision({
      agentId: AGENT_ID,
      resourceId: artifact.resource_id,
      content: "postbox descendant content",
      actor: { kind: "human", id: OWNER_ID },
      nowMs,
    });
    const descendantArtifactPath = fixture.artifactPathForRevision(descendant.revisionId);
    expect(fs.readFileSync(descendantArtifactPath, "utf8")).toBe("postbox descendant content");
    expect(
      database
        .prepare("SELECT lifecycle_state FROM memory_resource_revisions WHERE revision_id = ?")
        .get(target.target_revision_id),
    ).toEqual({ lifecycle_state: "active" });

    const purged = service.purgePostbox({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      postboxItemId: pending.postboxItemId,
    });
    expect(purged.reviewState).toBe("purged");
    expect(
      database
        .prepare("SELECT lifecycle_state FROM memory_resource_revisions WHERE revision_id = ?")
        .get(target.target_revision_id),
    ).toEqual({ lifecycle_state: "tombstoned" });
    expect(
      database
        .prepare("SELECT lifecycle_state FROM memory_resource_revisions WHERE revision_id = ?")
        .get(descendant.revisionId),
    ).toEqual({ lifecycle_state: "tombstoned" });
    expect(
      database
        .prepare(
          "SELECT review_state, content, review_content FROM memory_postbox_items WHERE postbox_item_id = ?",
        )
        .get(pending.postboxItemId),
    ).toEqual({ review_state: "purged", content: "[purged]", review_content: "[purged]" });
    expect(fs.existsSync(artifactPath)).toBe(false);
    expect(fs.existsSync(descendantArtifactPath)).toBe(false);
  });
});
