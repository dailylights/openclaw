import fs from "node:fs";
import { openOpenClawAgentDatabase } from "openclaw/plugin-sdk/sqlite-runtime";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  createBuiltinScopedMemoryResource,
  createBuiltinScopedMemoryResourceRevision,
  createBuiltinScopedMemoryStore,
  reviseBuiltinScopedMemoryPolicy,
} from "../../test-api.js";
import { createScopedMemorySharingService } from "./scoped-memory-sharing.js";
import {
  createScopedMemorySharingTestFixture,
  SCOPED_MEMORY_SHARING_AGENT_ID as AGENT_ID,
  SCOPED_MEMORY_SHARING_OWNER_ID as OWNER_ID,
  scopedMemorySharingOwnerAuthority as ownerAuthority,
} from "./scoped-memory-sharing.test-support.js";

describe("scoped memory sharing service", () => {
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

  function createSourceStore() {
    return fixture.createSourceStore();
  }

  function createProjectionTarget(
    targetKind: "conversation" | "role" | "agent-shared" = "conversation",
    targetId = "conversation-1",
  ) {
    return fixture.createProjectionTarget(targetKind, targetId);
  }

  function createProjectionFixture(params: { sourceExpiresAtMs?: number } = {}) {
    return fixture.createProjectionFixture(params);
  }

  function createPendingProjection(
    params: Parameters<(typeof fixture)["createPendingProjection"]>[0],
  ) {
    return fixture.createPendingProjection(params);
  }

  async function searchConversationProjection(query = "saffron") {
    return fixture.searchConversationProjection(query);
  }

  function artifactPathForRevision(revisionId: string): string {
    return fixture.artifactPathForRevision(revisionId);
  }

  it("keeps a pending copy invisible until its required review approves it", async () => {
    const { source, service } = createProjectionFixture();
    const pending = createPendingProjection({ service, sourceRevisionId: source.revisionId });
    const database = openOpenClawAgentDatabase({ agentId: AGENT_ID }).db;

    expect(
      database
        .prepare("SELECT lifecycle_state FROM memory_resource_revisions WHERE revision_id = ?")
        .get(pending.projectionId),
    ).toBeUndefined();
    expect(
      database
        .prepare(
          "SELECT lifecycle_state FROM memory_resource_revisions WHERE revision_id = (SELECT target_revision_id FROM memory_projections WHERE projection_id = ?)",
        )
        .get(pending.projectionId),
    ).toEqual({ lifecycle_state: "pending" });
    await expect(searchConversationProjection()).resolves.toMatchObject({ value: [] });

    const approved = service.reviewProjection({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      projectionId: pending.projectionId,
      decision: "approve",
    });
    expect(approved.reviewState).toBe("approved");
    const exposed = await searchConversationProjection();
    expect(exposed.value).toHaveLength(1);
    expect(exposed.value[0]?.snippet).toContain("private saffron projection source");
  });

  it("caps projection preview and stored expiry at a finite source expiry", () => {
    const sourceExpiresAtMs = nowMs + 500;
    const requestedExpiresAtMs = nowMs + 5_000;
    const { source, service } = createProjectionFixture({ sourceExpiresAtMs });
    const preview = service.previewProjection({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      sourceRevisionId: source.revisionId,
      targetKind: "conversation",
      targetId: "conversation-1",
      purpose: "must not outlive its source",
      expiresAtMs: requestedExpiresAtMs,
    });
    expect(preview.expiresAt).toBe(new Date(sourceExpiresAtMs).toISOString());

    const projection = service.createProjection({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      previewId: preview.previewId,
    });
    expect(projection.expiresAt).toBe(new Date(sourceExpiresAtMs).toISOString());
    expect(
      openOpenClawAgentDatabase({ agentId: AGENT_ID })
        .db.prepare(
          `SELECT projection.expires_at AS projection_expires_at, revision.expires_at AS target_expires_at
             FROM memory_projections AS projection
             INNER JOIN memory_resource_revisions AS revision ON revision.revision_id = projection.target_revision_id
            WHERE projection.projection_id = ?`,
        )
        .get(projection.projectionId),
    ).toEqual({
      projection_expires_at: sourceExpiresAtMs,
      target_expires_at: sourceExpiresAtMs,
    });
  });

  it.each([
    { targetKind: "conversation" as const, targetId: "conversation-1" },
    { targetKind: "role" as const, targetId: "role-1" },
    { targetKind: "agent-shared" as const, targetId: AGENT_ID },
  ])("creates a pending projection for the canonical $targetKind target root", (target) => {
    const sourceStore = createSourceStore();
    createProjectionTarget(target.targetKind, target.targetId);
    const source = createBuiltinScopedMemoryResource({
      agentId: AGENT_ID,
      store: sourceStore,
      logicalLocator: `source-${target.targetKind}.md`,
      content: `reviewed ${target.targetKind} source`,
      actor: { kind: "human", id: OWNER_ID },
      nowMs: 2_000,
    });
    const service = createScopedMemorySharingService({ now: () => nowMs });

    const preview = service.previewProjection({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      sourceRevisionId: source.revisionId,
      targetKind: target.targetKind,
      targetId: target.targetId,
      purpose: `share with ${target.targetKind}`,
      expiresAtMs: nowMs + 10_000,
    });
    expect(
      service.createProjection({
        agentId: AGENT_ID,
        authority: ownerAuthority(),
        previewId: preview.previewId,
      }),
    ).toMatchObject({ targetKind: target.targetKind, reviewState: "pending" });
  });

  it("requires the agent control owner rather than ownership of an unrelated private root", () => {
    const unrelatedOwnerId = "principal-unrelated";
    createBuiltinScopedMemoryStore({
      agentId: AGENT_ID,
      scopeKind: "user",
      audienceKind: "user",
      audienceId: unrelatedOwnerId,
      authorityKind: "user",
      authorityOwnerId: unrelatedOwnerId,
      defaultCapabilities: ["retrieve", "read"],
      actor: { kind: "human", id: unrelatedOwnerId },
      reason: "unrelated private root fixture",
      nowMs: 1_000,
    });
    const service = createScopedMemorySharingService({ now: () => nowMs });
    const unrelatedAuthority = { kind: "local-agent-owner" as const, id: unrelatedOwnerId };

    expect(() =>
      service.configurePostbox({
        agentId: AGENT_ID,
        authority: unrelatedAuthority,
        mode: "review-required",
      }),
    ).toThrow("sharing authority is unavailable");
    expect(() => service.status({ agentId: AGENT_ID, authority: unrelatedAuthority })).toThrow(
      "sharing authority is unavailable",
    );
  });

  it("requires the canonical agent control root rather than another agent-authority root", () => {
    const alternateOwnerId = "principal-agent-shared-root";
    createBuiltinScopedMemoryStore({
      agentId: AGENT_ID,
      scopeKind: "agent-shared",
      audienceKind: "agent-shared",
      audienceId: AGENT_ID,
      authorityKind: "agent",
      authorityOwnerId: alternateOwnerId,
      defaultCapabilities: ["retrieve", "read"],
      actor: { kind: "human", id: alternateOwnerId },
      reason: "alternate agent-authority root fixture",
      nowMs: 1_000,
    });
    const service = createScopedMemorySharingService({ now: () => nowMs });
    const alternateAuthority = { kind: "local-agent-owner" as const, id: alternateOwnerId };

    expect(() =>
      service.configurePostbox({
        agentId: AGENT_ID,
        authority: alternateAuthority,
        mode: "review-required",
      }),
    ).toThrow("sharing authority is unavailable");
    expect(() => service.status({ agentId: AGENT_ID, authority: alternateAuthority })).toThrow(
      "sharing authority is unavailable",
    );
  });

  it("requires the agent control owner for projection lifecycle even with private policy grants", () => {
    const privateOwnerId = "principal-private-owner";
    const privateAuthority = { kind: "local-agent-owner" as const, id: privateOwnerId };
    const sourceStore = createBuiltinScopedMemoryStore({
      agentId: AGENT_ID,
      scopeKind: "user",
      audienceKind: "user",
      audienceId: privateOwnerId,
      authorityKind: "user",
      authorityOwnerId: privateOwnerId,
      defaultCapabilities: ["retrieve", "read"],
      policyEntries: [
        {
          effect: "allow",
          principalId: OWNER_ID,
          operation: "project",
          grantorPrincipalId: privateOwnerId,
          reason: "agent control owner may project this source",
        },
        {
          effect: "allow",
          principalId: privateOwnerId,
          operation: "project",
          grantorPrincipalId: privateOwnerId,
          reason: "private owner project grant cannot bypass agent control",
        },
      ],
      actor: { kind: "human", id: privateOwnerId },
      reason: "private source with explicit project grants",
      nowMs: 1_000,
    });
    createBuiltinScopedMemoryStore({
      agentId: AGENT_ID,
      scopeKind: "conversation",
      audienceKind: "conversation",
      audienceId: "conversation-private-source",
      authorityKind: "conversation",
      authorityOwnerId: OWNER_ID,
      defaultCapabilities: ["retrieve", "read"],
      policyEntries: [
        {
          kind: "publish",
          effect: "allow",
          principalId: OWNER_ID,
          audienceKind: "conversation",
          audienceId: "conversation-private-source",
          operation: "publish",
          grantorPrincipalId: OWNER_ID,
          reason: "agent control owner may publish",
        },
        {
          kind: "publish",
          effect: "allow",
          principalId: privateOwnerId,
          audienceKind: "conversation",
          audienceId: "conversation-private-source",
          operation: "publish",
          grantorPrincipalId: OWNER_ID,
          reason: "private publish grant cannot bypass agent control",
        },
      ],
      actor: { kind: "human", id: OWNER_ID },
      reason: "target with explicit publish grants",
      nowMs: 1_000,
    });
    const source = createBuiltinScopedMemoryResource({
      agentId: AGENT_ID,
      store: sourceStore,
      logicalLocator: "private-owner-source.md",
      content: "agent controlled reviewed copy",
      actor: { kind: "human", id: privateOwnerId },
      nowMs: 2_000,
    });
    const service = createScopedMemorySharingService({ now: () => nowMs });
    const input = {
      agentId: AGENT_ID,
      sourceRevisionId: source.revisionId,
      targetKind: "conversation" as const,
      targetId: "conversation-private-source",
      purpose: "share a policy-authorized private source",
      expiresAtMs: nowMs + 10_000,
    };

    expect(() => service.previewProjection({ ...input, authority: privateAuthority })).toThrow(
      "sharing authority is unavailable",
    );

    const preview = service.previewProjection({ ...input, authority: ownerAuthority() });
    expect(() =>
      service.createProjection({
        agentId: AGENT_ID,
        authority: privateAuthority,
        previewId: preview.previewId,
      }),
    ).toThrow("projection preview is unavailable");
    const pending = service.createProjection({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      previewId: preview.previewId,
    });
    expect(service.status({ agentId: AGENT_ID, authority: ownerAuthority() }).projections).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          projectionId: pending.projectionId,
          sourceRevisionId: source.revisionId,
          reviewState: "pending",
        }),
      ]),
    );
    expect(() =>
      service.reviewProjection({
        agentId: AGENT_ID,
        authority: privateAuthority,
        projectionId: pending.projectionId,
        decision: "approve",
      }),
    ).toThrow("sharing authority is unavailable");
    expect(
      service.reviewProjection({
        agentId: AGENT_ID,
        authority: ownerAuthority(),
        projectionId: pending.projectionId,
        decision: "approve",
      }).reviewState,
    ).toBe("approved");
  });

  it("removes a prepared projection artifact when final creation cannot attach it", () => {
    const { source, service } = createProjectionFixture();
    const preview = service.previewProjection({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      sourceRevisionId: source.revisionId,
      targetKind: "conversation",
      targetId: "conversation-1",
      purpose: "force a projection attach failure",
      expiresAtMs: nowMs + 1_000,
    });
    const database = openOpenClawAgentDatabase({ agentId: AGENT_ID }).db;
    database.exec(`
      CREATE TRIGGER fail_projection_creation
      BEFORE INSERT ON memory_projections
      BEGIN
        SELECT RAISE(ABORT, 'forced projection creation failure');
      END;
    `);

    expect(() =>
      service.createProjection({
        agentId: AGENT_ID,
        authority: ownerAuthority(),
        previewId: preview.previewId,
      }),
    ).toThrow("forced projection creation failure");
    const failedCopy = database
      .prepare(
        `SELECT revision.revision_id, revision.lifecycle_state
           FROM memory_resources AS resource
           INNER JOIN memory_resource_revisions AS revision ON revision.resource_id = resource.resource_id
          WHERE resource.logical_locator LIKE 'projections/%'`,
      )
      .get() as { revision_id: string; lifecycle_state: string } | undefined;
    if (!failedCopy) {
      throw new Error("expected tombstoned projection copy");
    }
    expect(failedCopy.lifecycle_state).toBe("tombstoned");
    expect(fs.existsSync(artifactPathForRevision(failedCopy.revision_id))).toBe(false);
  });

  it("removes a rejected pending projection artifact", () => {
    const { source, service } = createProjectionFixture();
    const projection = createPendingProjection({ service, sourceRevisionId: source.revisionId });
    const database = openOpenClawAgentDatabase({ agentId: AGENT_ID }).db;
    const target = database
      .prepare("SELECT target_revision_id FROM memory_projections WHERE projection_id = ?")
      .get(projection.projectionId) as { target_revision_id: string };
    const artifactPath = artifactPathForRevision(target.target_revision_id);
    expect(fs.existsSync(artifactPath)).toBe(true);

    expect(
      service.reviewProjection({
        agentId: AGENT_ID,
        authority: ownerAuthority(),
        projectionId: projection.projectionId,
        decision: "reject",
        reason: "not appropriate for this audience",
      }).reviewState,
    ).toBe("rejected");
    expect(
      database
        .prepare("SELECT lifecycle_state FROM memory_resource_revisions WHERE revision_id = ?")
        .get(target.target_revision_id),
    ).toEqual({ lifecycle_state: "tombstoned" });
    expect(fs.existsSync(artifactPath)).toBe(false);
  });

  it("carries source policy requirements into a reviewed copy and revokes future reads", async () => {
    const { sourceStore, targetStore, source, service } = createProjectionFixture();
    const pending = createPendingProjection({ service, sourceRevisionId: source.revisionId });
    service.reviewProjection({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      projectionId: pending.projectionId,
      decision: "approve",
    });
    const database = openOpenClawAgentDatabase({ agentId: AGENT_ID }).db;
    const requirementRows = database
      .prepare(
        `SELECT stable_policy_id, expected_active_revision_id, expected_revocation_epoch
           FROM memory_revision_policy_requirements
          WHERE revision_id = (SELECT target_revision_id FROM memory_projections WHERE projection_id = ?)
          ORDER BY stable_policy_id`,
      )
      .all(pending.projectionId) as Array<{
      stable_policy_id: string;
      expected_active_revision_id: string;
      expected_revocation_epoch: number;
    }>;
    expect(requirementRows).toEqual(
      [
        {
          stable_policy_id: sourceStore.policyId,
          expected_active_revision_id: sourceStore.policyRevisionId,
          expected_revocation_epoch: sourceStore.policyRevocationEpoch,
        },
        {
          stable_policy_id: targetStore.policyId,
          expected_active_revision_id: targetStore.policyRevisionId,
          expected_revocation_epoch: targetStore.policyRevocationEpoch,
        },
      ].toSorted((left, right) => left.stable_policy_id.localeCompare(right.stable_policy_id)),
    );
    expect((await searchConversationProjection()).value).toHaveLength(1);

    nowMs += 1;
    reviseBuiltinScopedMemoryPolicy({
      agentId: AGENT_ID,
      policyId: sourceStore.policyId,
      entries: [],
      actor: { kind: "human", id: OWNER_ID },
      reason: "revoke projected source policy",
      nowMs,
    });

    expect((await searchConversationProjection()).value).toEqual([]);
  });

  it("rejects wildcard, cross-agent, non-projection, and unknown target selections", () => {
    const { source, service } = createProjectionFixture();
    const input = {
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      sourceRevisionId: source.revisionId,
      purpose: "must remain one named target",
      expiresAtMs: nowMs + 1_000,
    };

    expect(() =>
      service.previewProjection({
        ...input,
        targetKind: "conversation",
        targetId: "*",
      }),
    ).toThrow("projection target is unavailable");
    expect(() =>
      service.previewProjection({
        ...input,
        targetKind: "agent-shared",
        targetId: "other-agent",
      }),
    ).toThrow("projection target is unavailable");
    expect(() =>
      service.previewProjection({
        ...input,
        targetKind: "user" as never,
        targetId: OWNER_ID,
      }),
    ).toThrow("projection target is unavailable");
    expect(() =>
      service.previewProjection({
        ...input,
        targetKind: "role",
        targetId: "missing-role",
      }),
    ).toThrow("sharing target is unavailable");
  });

  it("treats a refresh as a distinct pending projection with explicit lineage", () => {
    const { source, service } = createProjectionFixture();
    const first = createPendingProjection({ service, sourceRevisionId: source.revisionId });
    service.reviewProjection({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      projectionId: first.projectionId,
      decision: "approve",
    });
    nowMs += 1;
    const refreshedSource = createBuiltinScopedMemoryResourceRevision({
      agentId: AGENT_ID,
      resourceId: source.resourceId,
      content: "private saffron projection source, refreshed",
      lifecycleState: "active",
      actor: { kind: "human", id: OWNER_ID },
      nowMs,
    });
    const refresh = createPendingProjection({
      service,
      sourceRevisionId: refreshedSource.revisionId,
      supersedesProjectionId: first.projectionId,
    });

    expect(refresh).toMatchObject({
      reviewState: "pending",
      sourceRevisionId: refreshedSource.revisionId,
      supersedesProjectionId: first.projectionId,
    });
    const database = openOpenClawAgentDatabase({ agentId: AGENT_ID }).db;
    expect(
      database
        .prepare(
          "SELECT supersedes_projection_id, review_state FROM memory_projections WHERE projection_id = ?",
        )
        .get(refresh.projectionId),
    ).toEqual({ supersedes_projection_id: first.projectionId, review_state: "pending" });
  });

  it("rejects a refresh preview after its approved predecessor is revoked", () => {
    const { source, service } = createProjectionFixture();
    const first = createPendingProjection({ service, sourceRevisionId: source.revisionId });
    service.reviewProjection({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      projectionId: first.projectionId,
      decision: "approve",
    });
    const preview = service.previewProjection({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      sourceRevisionId: source.revisionId,
      targetKind: "conversation",
      targetId: "conversation-1",
      purpose: "refresh only while the predecessor remains approved",
      expiresAtMs: nowMs + 10_000,
      supersedesProjectionId: first.projectionId,
    });
    service.revokeProjection({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      projectionId: first.projectionId,
    });

    expect(() =>
      service.createProjection({
        agentId: AGENT_ID,
        authority: ownerAuthority(),
        previewId: preview.previewId,
      }),
    ).toThrow("projection refresh source is unavailable");
    expect(
      openOpenClawAgentDatabase({ agentId: AGENT_ID })
        .db.prepare(
          "SELECT COUNT(*) AS count FROM memory_projections WHERE supersedes_projection_id = ?",
        )
        .get(first.projectionId),
    ).toEqual({ count: 0 });
  });

  it("continues to list impact and permits historical revocation after source policy revocation", async () => {
    const { sourceStore, source, service } = createProjectionFixture();
    const projection = createPendingProjection({ service, sourceRevisionId: source.revisionId });
    service.reviewProjection({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      projectionId: projection.projectionId,
      decision: "approve",
    });
    const database = openOpenClawAgentDatabase({ agentId: AGENT_ID }).db;
    const target = database
      .prepare("SELECT target_revision_id FROM memory_projections WHERE projection_id = ?")
      .get(projection.projectionId) as { target_revision_id: string };
    const artifactPath = artifactPathForRevision(target.target_revision_id);
    expect(fs.existsSync(artifactPath)).toBe(true);
    const exposure = await searchConversationProjection();
    expect(exposure.value).toHaveLength(1);

    nowMs += 1;
    reviseBuiltinScopedMemoryPolicy({
      agentId: AGENT_ID,
      policyId: sourceStore.policyId,
      entries: [],
      actor: { kind: "human", id: OWNER_ID },
      reason: "invalidate source after a prior exposure",
      nowMs,
    });

    expect(
      service.projectionImpact({
        agentId: AGENT_ID,
        authority: ownerAuthority(),
        projectionId: projection.projectionId,
      }).priorExposures,
    ).toEqual([expect.objectContaining({ receiptId: exposure.exposureReceipt.receiptId })]);
    expect(service.status({ agentId: AGENT_ID, authority: ownerAuthority() }).projections).toEqual(
      expect.arrayContaining([expect.objectContaining({ projectionId: projection.projectionId })]),
    );
    const revoked = service.revokeProjection({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      projectionId: projection.projectionId,
    });
    expect(revoked.reviewState).toBe("revoked");
    expect(
      database
        .prepare(
          "SELECT lifecycle_state FROM memory_resource_revisions WHERE revision_id = (SELECT target_revision_id FROM memory_projections WHERE projection_id = ?)",
        )
        .get(projection.projectionId),
    ).toEqual({ lifecycle_state: "tombstoned" });
    expect(fs.existsSync(artifactPath)).toBe(false);
  });

  it("does not expose an approved copy after its mandatory expiry", async () => {
    const { source, service } = createProjectionFixture();
    const projection = createPendingProjection({
      service,
      sourceRevisionId: source.revisionId,
      expiresAtMs: nowMs + 50,
    });
    service.reviewProjection({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      projectionId: projection.projectionId,
      decision: "approve",
    });
    expect((await searchConversationProjection()).value).toHaveLength(1);

    nowMs += 50;
    expect((await searchConversationProjection()).value).toEqual([]);
  });
});
