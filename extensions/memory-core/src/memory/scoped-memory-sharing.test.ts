import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { MemoryAccessContext } from "openclaw/plugin-sdk/memory-authorization";
import { openOpenClawAgentDatabase } from "openclaw/plugin-sdk/sqlite-runtime";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createBuiltinScopedMemoryResource,
  createBuiltinScopedMemoryResourceRevision,
  createBuiltinScopedMemoryStore,
  reviseBuiltinScopedMemoryPolicy,
} from "../../test-api.js";
import { resolveBuiltinScopedMemoryArtifactPath } from "./scoped-memory-resources.js";
import { createBuiltinScopedMemoryRuntime } from "./scoped-memory-runtime.js";
import { createScopedMemorySharingService } from "./scoped-memory-sharing.js";

const AGENT_ID = "main";
const OWNER_ID = "principal-owner";

function ownerAuthority() {
  return { kind: "local-agent-owner" as const, id: OWNER_ID };
}

function createConversationContext(): MemoryAccessContext {
  return {
    version: 1,
    contextId: "sharing-context-1",
    contextFingerprint: "sha256:sharing-context-1",
    requestId: "sharing-request-1",
    runId: "sharing-run-1",
    agentId: AGENT_ID,
    sessionKey: "agent:main:conversation-1",
    sessionId: "sharing-session-1",
    sessionIdentityRevision: "sharing-session-revision-1",
    subjectRevision: "sharing-subject-revision-1",
    subject: {
      version: 1,
      kind: "conversation",
      conversationPrincipalId: "conversation-1",
      channel: "test",
      accountId: "default",
    },
    actor: {
      kind: "unattributed",
      transportAuditRef: "sharing-transport-audit-1",
      evidenceRevision: "sharing-conversation-evidence-1",
    },
    verifiedPrincipals: [],
    delivery: {
      sinkKind: "channel",
      audiences: [{ kind: "conversation", id: "conversation-1" }],
      egressCapabilityIds: ["reply.final"],
      egressRegistryRevision: "sharing-egress-revision-1",
      deliveryRevision: "sharing-delivery-revision-1",
    },
    conversation: {
      conversationPrincipalId: "conversation-1",
      channel: "test",
      accountId: "default",
      evidenceRevision: "sharing-conversation-evidence-1",
    },
    collaboration: { kind: "not-applicable" },
    verifiedMemberships: [],
    operation: "read",
    hostFactsRevision: "sharing-host-facts-revision-1",
  };
}

describe("scoped memory sharing service", () => {
  let stateDir = "";
  let nowMs = 10_000;

  beforeEach(() => {
    stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-scoped-memory-sharing-"));
    nowMs = 10_000;
    vi.stubEnv("OPENCLAW_STATE_DIR", stateDir);
    createAgentControlStore();
  });

  afterEach(() => {
    try {
      openOpenClawAgentDatabase({ agentId: AGENT_ID }).db.close();
    } catch {}
    vi.unstubAllEnvs();
    fs.rmSync(stateDir, { recursive: true, force: true });
  });

  function createSourceStore() {
    return createBuiltinScopedMemoryStore({
      agentId: AGENT_ID,
      scopeKind: "user",
      audienceKind: "user",
      audienceId: OWNER_ID,
      authorityKind: "user",
      authorityOwnerId: OWNER_ID,
      defaultCapabilities: ["retrieve", "read", "project"],
      actor: { kind: "human", id: OWNER_ID },
      reason: "sharing source fixture",
      nowMs: 1_000,
    });
  }

  function createAgentControlStore() {
    return createBuiltinScopedMemoryStore({
      agentId: AGENT_ID,
      scopeKind: "agent",
      audienceKind: "agent",
      audienceId: AGENT_ID,
      authorityKind: "agent",
      authorityOwnerId: OWNER_ID,
      defaultCapabilities: ["retrieve", "read"],
      actor: { kind: "human", id: OWNER_ID },
      reason: "agent control owner fixture",
      nowMs: 1_000,
    });
  }

  function createProjectionTarget(
    targetKind: "conversation" | "role" | "agent-shared" = "conversation",
    targetId = "conversation-1",
  ) {
    return createBuiltinScopedMemoryStore({
      agentId: AGENT_ID,
      scopeKind: targetKind,
      audienceKind: targetKind,
      audienceId: targetId,
      authorityKind: targetKind === "agent-shared" ? "agent" : targetKind,
      authorityOwnerId: OWNER_ID,
      defaultCapabilities: ["retrieve", "read"],
      policyEntries: [
        {
          kind: "publish",
          effect: "allow",
          principalId: OWNER_ID,
          audienceKind: targetKind,
          audienceId: targetId,
          operation: "publish",
          grantorPrincipalId: OWNER_ID,
          reason: "owner can publish reviewed projections",
        },
      ],
      actor: { kind: "human", id: OWNER_ID },
      reason: "sharing target fixture",
      nowMs: 1_000,
    });
  }

  function createUserPostboxStore() {
    return createBuiltinScopedMemoryStore({
      agentId: AGENT_ID,
      scopeKind: "user",
      audienceKind: "user",
      audienceId: OWNER_ID,
      authorityKind: "user",
      authorityOwnerId: OWNER_ID,
      defaultCapabilities: ["retrieve", "read"],
      actor: { kind: "human", id: OWNER_ID },
      reason: "postbox target fixture",
      nowMs: 1_000,
    });
  }

  function createProjectionFixture(params: { sourceExpiresAtMs?: number } = {}) {
    const sourceStore = createSourceStore();
    const targetStore = createProjectionTarget();
    const source = createBuiltinScopedMemoryResource({
      agentId: AGENT_ID,
      store: sourceStore,
      logicalLocator: "private-source.md",
      content: "private saffron projection source",
      actor: { kind: "human", id: OWNER_ID },
      expiresAt: params.sourceExpiresAtMs,
      nowMs: 2_000,
    });
    const service = createScopedMemorySharingService({ now: () => nowMs });
    return { sourceStore, targetStore, source, service };
  }

  function createPendingProjection(params: {
    service: ReturnType<typeof createScopedMemorySharingService>;
    sourceRevisionId: string;
    expiresAtMs?: number;
    supersedesProjectionId?: string;
  }) {
    const preview = params.service.previewProjection({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      sourceRevisionId: params.sourceRevisionId,
      targetKind: "conversation",
      targetId: "conversation-1",
      purpose: "share the reviewed saffron fact",
      expiresAtMs: params.expiresAtMs ?? nowMs + 10_000,
      ...(params.supersedesProjectionId
        ? { supersedesProjectionId: params.supersedesProjectionId }
        : {}),
    });
    return params.service.createProjection({
      agentId: AGENT_ID,
      authority: ownerAuthority(),
      previewId: preview.previewId,
    });
  }

  async function searchConversationProjection(query = "saffron") {
    const runtime = createBuiltinScopedMemoryRuntime({ now: () => nowMs });
    const context = createConversationContext();
    const plan = await runtime.authorize(context);
    return runtime.searchAuthorized({ context, plan, query, limit: 10 });
  }

  function issuePostboxHandle(
    service: ReturnType<typeof createScopedMemorySharingService>,
    overrides: Partial<{
      sessionId: string;
      sourceConversationId: string;
      content: string;
      expiresAtMs: number;
    }> = {},
  ) {
    return service.issuePostboxSourceMessageHandle({
      agentId: AGENT_ID,
      sessionId: overrides.sessionId ?? "source-session-1",
      sourceConversationId: overrides.sourceConversationId ?? "source-conversation-1",
      sourceEventId: "source-event-1",
      sourceActor: {
        kind: "human",
        id: "source-human-1",
        evidenceRevision: "source-evidence-1",
      },
      targetUserId: OWNER_ID,
      targetUserEvidenceRevision: "target-user-evidence-1",
      content: overrides.content ?? "quarantined crimson observation",
      expiresAtMs: overrides.expiresAtMs ?? nowMs + 1_000,
    });
  }

  function depositPostbox(
    service: ReturnType<typeof createScopedMemorySharingService>,
    sourceMessageHandle: string,
    overrides: Partial<{ sessionId: string; sourceConversationId: string }> = {},
  ) {
    return service.depositPostbox({
      sourceMessageHandle,
      sessionId: overrides.sessionId ?? "source-session-1",
      sourceConversationId: overrides.sourceConversationId ?? "source-conversation-1",
    });
  }

  function artifactPathForRevision(revisionId: string): string {
    const openedDatabase = openOpenClawAgentDatabase({ agentId: AGENT_ID });
    const artifact = openedDatabase.db
      .prepare(
        `SELECT root.path_key, revision.artifact_locator
           FROM memory_resource_revisions AS revision
           INNER JOIN memory_resources AS resource ON resource.resource_id = revision.resource_id
           INNER JOIN memory_stores AS store ON store.store_id = resource.store_id
           INNER JOIN memory_storage_roots AS root ON root.storage_root_id = store.storage_root_id
          WHERE revision.revision_id = ?`,
      )
      .get(revisionId) as { path_key: string; artifact_locator: string } | undefined;
    if (!artifact) {
      throw new Error("expected scoped-memory artifact");
    }
    return resolveBuiltinScopedMemoryArtifactPath({
      databasePath: openedDatabase.path,
      pathKey: artifact.path_key,
      artifactLocator: artifact.artifact_locator,
    });
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
    expect(fs.existsSync(artifactPathForRevision(failedCopy.revision_id))).toBe(false);
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

    expect(depositPostbox(service, issuePostboxHandle(service))).toEqual({
      accepted: true,
    });
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
    expect(depositPostbox(service, issuePostboxHandle(service))).toEqual({
      accepted: true,
    });
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
    const openedDatabase = openOpenClawAgentDatabase({ agentId: AGENT_ID });
    const database = openedDatabase.db;
    const target = database
      .prepare("SELECT target_revision_id FROM memory_postbox_items WHERE postbox_item_id = ?")
      .get(pending.postboxItemId) as { target_revision_id: string };
    expect(target.target_revision_id).toEqual(expect.any(String));
    const artifact = database
      .prepare(
        `SELECT revision.resource_id, root.path_key, revision.artifact_locator
           FROM memory_resource_revisions AS revision
           INNER JOIN memory_resources AS resource ON resource.resource_id = revision.resource_id
           INNER JOIN memory_stores AS store ON store.store_id = resource.store_id
           INNER JOIN memory_storage_roots AS root ON root.storage_root_id = store.storage_root_id
          WHERE revision.revision_id = ?`,
      )
      .get(target.target_revision_id) as {
      resource_id: string;
      path_key: string;
      artifact_locator: string;
    };
    const artifactPath = resolveBuiltinScopedMemoryArtifactPath({
      databasePath: openedDatabase.path,
      pathKey: artifact.path_key,
      artifactLocator: artifact.artifact_locator,
    });
    expect(fs.readFileSync(artifactPath, "utf8")).toBe("reviewed postbox content");
    const descendant = createBuiltinScopedMemoryResourceRevision({
      agentId: AGENT_ID,
      resourceId: artifact.resource_id,
      content: "postbox descendant content",
      actor: { kind: "human", id: OWNER_ID },
      nowMs,
    });
    const descendantArtifact = database
      .prepare(
        `SELECT root.path_key, revision.artifact_locator
           FROM memory_resource_revisions AS revision
           INNER JOIN memory_resources AS resource ON resource.resource_id = revision.resource_id
           INNER JOIN memory_stores AS store ON store.store_id = resource.store_id
           INNER JOIN memory_storage_roots AS root ON root.storage_root_id = store.storage_root_id
          WHERE revision.revision_id = ?`,
      )
      .get(descendant.revisionId) as { path_key: string; artifact_locator: string };
    const descendantArtifactPath = resolveBuiltinScopedMemoryArtifactPath({
      databasePath: openedDatabase.path,
      pathKey: descendantArtifact.path_key,
      artifactLocator: descendantArtifact.artifact_locator,
    });
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
