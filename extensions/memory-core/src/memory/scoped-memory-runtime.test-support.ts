import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { MemoryAccessContext } from "openclaw/plugin-sdk/memory-authorization";
import { openOpenClawAgentDatabase } from "openclaw/plugin-sdk/sqlite-runtime";
import { vi } from "vitest";
import { createBuiltinScopedMemoryStore } from "../../test-api.js";

export const SCOPED_MEMORY_RUNTIME_NOW_MS = 10_000;

export function createScopedMemoryRuntimeContext(
  overrides: Partial<MemoryAccessContext> = {},
): MemoryAccessContext {
  return {
    version: 1,
    contextId: "context-1",
    contextFingerprint: "sha256:context-1",
    requestId: "request-1",
    runId: "run-1",
    agentId: "main",
    sessionKey: "agent:main:main",
    sessionId: "session-1",
    sessionIdentityRevision: "session-revision-1",
    subjectRevision: "subject-revision-1",
    subject: {
      version: 1,
      kind: "user",
      principalId: "principal-owner",
      creationEvidence: { kind: "gateway-profile", revision: "creation-revision-1" },
    },
    actor: {
      kind: "principal",
      actorKind: "human",
      principalId: "principal-owner",
      assurance: "gateway-profile",
      evidenceRevision: "actor-revision-1",
    },
    verifiedPrincipals: [
      {
        principalId: "principal-owner",
        assurance: "gateway-profile",
        evidenceRevision: "principal-revision-1",
      },
    ],
    delivery: {
      sinkKind: "private",
      audiences: [{ kind: "user", id: "principal-owner" }],
      egressCapabilityIds: ["reply.final"],
      egressRegistryRevision: "egress-revision-1",
      deliveryRevision: "delivery-revision-1",
    },
    collaboration: { kind: "not-applicable" },
    verifiedMemberships: [],
    operation: "read",
    hostFactsRevision: "host-facts-revision-1",
    ...overrides,
  };
}

export function createScopedMemoryRuntimeStore(
  params: {
    agentId?: string;
    audienceId?: string;
    authorityOwnerId?: string;
    defaultCapabilities?: Parameters<
      typeof createBuiltinScopedMemoryStore
    >[0]["defaultCapabilities"];
    policyEntries?: Parameters<typeof createBuiltinScopedMemoryStore>[0]["policyEntries"];
  } = {},
) {
  return createBuiltinScopedMemoryStore({
    agentId: params.agentId ?? "main",
    scopeKind: "user",
    audienceKind: "user",
    audienceId: params.audienceId ?? "principal-owner",
    authorityKind: "user",
    authorityOwnerId: params.authorityOwnerId ?? "principal-owner",
    defaultCapabilities: params.defaultCapabilities ?? ["retrieve", "read"],
    ...(params.policyEntries ? { policyEntries: params.policyEntries } : {}),
    actor: { kind: "human", id: "principal-owner" },
    reason: "runtime test placement",
    nowMs: 1_000,
  });
}

export function createScopedMemoryRuntimeTestFixture() {
  let stateDir = "";
  return {
    setup() {
      stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-scoped-memory-runtime-"));
      vi.stubEnv("OPENCLAW_STATE_DIR", stateDir);
    },
    teardown() {
      try {
        openOpenClawAgentDatabase({ agentId: "main" }).db.close();
      } catch {}
      vi.unstubAllEnvs();
      fs.rmSync(stateDir, { recursive: true, force: true });
    },
    get stateDir() {
      return stateDir;
    },
  };
}
