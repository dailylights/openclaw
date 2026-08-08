import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { MemoryAccessContext } from "openclaw/plugin-sdk/memory-authorization";
import { openOpenClawAgentDatabase } from "openclaw/plugin-sdk/sqlite-runtime";
import { vi } from "vitest";
import {
  createBuiltinScopedMemoryResource,
  createBuiltinScopedMemoryStore,
} from "../../test-api.js";
import { resolveBuiltinScopedMemoryArtifactPath } from "./scoped-memory-resource-artifacts.js";
import { createBuiltinScopedMemoryRuntime } from "./scoped-memory-runtime.js";
import { createScopedMemorySharingService } from "./scoped-memory-sharing.js";

export const SCOPED_MEMORY_SHARING_AGENT_ID = "main";
export const SCOPED_MEMORY_SHARING_OWNER_ID = "principal-owner";

export function scopedMemorySharingOwnerAuthority() {
  return { kind: "local-agent-owner" as const, id: SCOPED_MEMORY_SHARING_OWNER_ID };
}

function createConversationContext(): MemoryAccessContext {
  return {
    version: 1,
    contextId: "sharing-context-1",
    contextFingerprint: "sha256:sharing-context-1",
    requestId: "sharing-request-1",
    runId: "sharing-run-1",
    agentId: SCOPED_MEMORY_SHARING_AGENT_ID,
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

export function createScopedMemorySharingTestFixture(dependencies: { now: () => number }) {
  let stateDir = "";

  const createAgentControlStore = () =>
    createBuiltinScopedMemoryStore({
      agentId: SCOPED_MEMORY_SHARING_AGENT_ID,
      scopeKind: "agent",
      audienceKind: "agent",
      audienceId: SCOPED_MEMORY_SHARING_AGENT_ID,
      authorityKind: "agent",
      authorityOwnerId: SCOPED_MEMORY_SHARING_OWNER_ID,
      defaultCapabilities: ["retrieve", "read"],
      actor: { kind: "human", id: SCOPED_MEMORY_SHARING_OWNER_ID },
      reason: "agent control owner fixture",
      nowMs: 1_000,
    });

  return {
    setup() {
      stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-scoped-memory-sharing-"));
      vi.stubEnv("OPENCLAW_STATE_DIR", stateDir);
      createAgentControlStore();
    },
    teardown() {
      try {
        openOpenClawAgentDatabase({ agentId: SCOPED_MEMORY_SHARING_AGENT_ID }).db.close();
      } catch {}
      vi.unstubAllEnvs();
      fs.rmSync(stateDir, { recursive: true, force: true });
    },
    createSourceStore() {
      return createBuiltinScopedMemoryStore({
        agentId: SCOPED_MEMORY_SHARING_AGENT_ID,
        scopeKind: "user",
        audienceKind: "user",
        audienceId: SCOPED_MEMORY_SHARING_OWNER_ID,
        authorityKind: "user",
        authorityOwnerId: SCOPED_MEMORY_SHARING_OWNER_ID,
        defaultCapabilities: ["retrieve", "read", "project"],
        actor: { kind: "human", id: SCOPED_MEMORY_SHARING_OWNER_ID },
        reason: "sharing source fixture",
        nowMs: 1_000,
      });
    },
    createProjectionTarget(
      targetKind: "conversation" | "role" | "agent-shared" = "conversation",
      targetId = "conversation-1",
    ) {
      return createBuiltinScopedMemoryStore({
        agentId: SCOPED_MEMORY_SHARING_AGENT_ID,
        scopeKind: targetKind,
        audienceKind: targetKind,
        audienceId: targetId,
        authorityKind: targetKind === "agent-shared" ? "agent" : targetKind,
        authorityOwnerId: SCOPED_MEMORY_SHARING_OWNER_ID,
        defaultCapabilities: ["retrieve", "read"],
        policyEntries: [
          {
            kind: "publish",
            effect: "allow",
            principalId: SCOPED_MEMORY_SHARING_OWNER_ID,
            audienceKind: targetKind,
            audienceId: targetId,
            operation: "publish",
            grantorPrincipalId: SCOPED_MEMORY_SHARING_OWNER_ID,
            reason: "owner can publish reviewed projections",
          },
        ],
        actor: { kind: "human", id: SCOPED_MEMORY_SHARING_OWNER_ID },
        reason: "sharing target fixture",
        nowMs: 1_000,
      });
    },
    createUserPostboxStore() {
      return createBuiltinScopedMemoryStore({
        agentId: SCOPED_MEMORY_SHARING_AGENT_ID,
        scopeKind: "user",
        audienceKind: "user",
        audienceId: SCOPED_MEMORY_SHARING_OWNER_ID,
        authorityKind: "user",
        authorityOwnerId: SCOPED_MEMORY_SHARING_OWNER_ID,
        defaultCapabilities: ["retrieve", "read"],
        actor: { kind: "human", id: SCOPED_MEMORY_SHARING_OWNER_ID },
        reason: "postbox target fixture",
        nowMs: 1_000,
      });
    },
    createProjectionFixture(params: { sourceExpiresAtMs?: number } = {}) {
      const sourceStore = this.createSourceStore();
      const targetStore = this.createProjectionTarget();
      const source = createBuiltinScopedMemoryResource({
        agentId: SCOPED_MEMORY_SHARING_AGENT_ID,
        store: sourceStore,
        logicalLocator: "private-source.md",
        content: "private saffron projection source",
        actor: { kind: "human", id: SCOPED_MEMORY_SHARING_OWNER_ID },
        expiresAt: params.sourceExpiresAtMs,
        nowMs: 2_000,
      });
      const service = createScopedMemorySharingService({ now: dependencies.now });
      return { sourceStore, targetStore, source, service };
    },
    createPendingProjection(params: {
      service: ReturnType<typeof createScopedMemorySharingService>;
      sourceRevisionId: string;
      expiresAtMs?: number;
      supersedesProjectionId?: string;
    }) {
      const preview = params.service.previewProjection({
        agentId: SCOPED_MEMORY_SHARING_AGENT_ID,
        authority: scopedMemorySharingOwnerAuthority(),
        sourceRevisionId: params.sourceRevisionId,
        targetKind: "conversation",
        targetId: "conversation-1",
        purpose: "share the reviewed saffron fact",
        expiresAtMs: params.expiresAtMs ?? dependencies.now() + 10_000,
        ...(params.supersedesProjectionId
          ? { supersedesProjectionId: params.supersedesProjectionId }
          : {}),
      });
      return params.service.createProjection({
        agentId: SCOPED_MEMORY_SHARING_AGENT_ID,
        authority: scopedMemorySharingOwnerAuthority(),
        previewId: preview.previewId,
      });
    },
    async searchConversationProjection(query = "saffron") {
      const runtime = createBuiltinScopedMemoryRuntime({ now: dependencies.now });
      const context = createConversationContext();
      const plan = await runtime.authorize(context);
      return runtime.searchAuthorized({ context, plan, query, limit: 10 });
    },
    issuePostboxHandle(
      service: ReturnType<typeof createScopedMemorySharingService>,
      overrides: Partial<{
        sessionId: string;
        sourceConversationId: string;
        content: string;
        expiresAtMs: number;
      }> = {},
    ) {
      return service.issuePostboxSourceMessageHandle({
        agentId: SCOPED_MEMORY_SHARING_AGENT_ID,
        sessionId: overrides.sessionId ?? "source-session-1",
        sourceConversationId: overrides.sourceConversationId ?? "source-conversation-1",
        sourceEventId: "source-event-1",
        sourceActor: {
          kind: "human",
          id: "source-human-1",
          evidenceRevision: "source-evidence-1",
        },
        targetUserId: SCOPED_MEMORY_SHARING_OWNER_ID,
        targetUserEvidenceRevision: "target-user-evidence-1",
        content: overrides.content ?? "quarantined crimson observation",
        expiresAtMs: overrides.expiresAtMs ?? dependencies.now() + 1_000,
      });
    },
    depositPostbox(
      service: ReturnType<typeof createScopedMemorySharingService>,
      sourceMessageHandle: string,
      overrides: Partial<{ sessionId: string; sourceConversationId: string }> = {},
    ) {
      return service.depositPostbox({
        sourceMessageHandle,
        sessionId: overrides.sessionId ?? "source-session-1",
        sourceConversationId: overrides.sourceConversationId ?? "source-conversation-1",
      });
    },
    artifactPathForRevision(revisionId: string): string {
      const openedDatabase = openOpenClawAgentDatabase({ agentId: SCOPED_MEMORY_SHARING_AGENT_ID });
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
    },
  };
}
