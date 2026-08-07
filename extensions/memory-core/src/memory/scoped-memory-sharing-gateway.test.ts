import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { GatewayRequestHandlerOptions } from "openclaw/plugin-sdk/gateway-runtime";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { memoryIdentityLifecycle } from "../../../../src/state/memory-identity.js";
import { closeOpenClawStateDatabaseForTest } from "../../../../src/state/openclaw-state-db.js";
import { ensureProfileForEmail } from "../../../../src/state/user-profiles.js";
import { registerScopedMemorySharingGatewayMethods } from "./scoped-memory-sharing-gateway.js";

const METHODS = [
  "memory.sharing.status",
  "memory.sharing.projection.preview",
  "memory.sharing.projection.create",
  "memory.sharing.projection.refresh",
  "memory.sharing.projection.review",
  "memory.sharing.projection.revoke",
  "memory.sharing.projection.impact",
  "memory.sharing.postbox.list",
  "memory.sharing.postbox.inspect",
  "memory.sharing.postbox.review",
  "memory.sharing.postbox.purge",
] as const;

type RegisteredMethod = {
  handler: (options: GatewayRequestHandlerOptions) => Promise<void>;
  scope: string | undefined;
};

type SharingGatewayClient = NonNullable<GatewayRequestHandlerOptions["client"]>;

const projection = {
  projectionId: "projection-1",
  sourceRevisionId: "revision-1",
  targetKind: "conversation" as const,
  targetAudienceId: "conversation-1",
  purpose: "Share a reviewed decision",
  preview: "Reviewed projection",
  reviewState: "pending" as const,
  expiresAt: "2030-01-02T03:04:05.000Z",
  createdAt: "2030-01-01T03:04:05.000Z",
};

const postboxItem = {
  postboxItemId: "postbox-1",
  sourceConversationId: "conversation-1",
  provenanceLabel: "conversation:conversation-1",
  contentPreview: "Quarantined item from conversation:conversation-1",
  reviewState: "pending" as const,
  expiresAt: "2030-01-02T03:04:05.000Z",
  createdAt: "2030-01-01T03:04:05.000Z",
};

const postboxInspection = {
  postboxItemId: "postbox-1",
  reviewContent: "owner-only quarantined content",
  expiresAt: "2030-01-02T03:04:05.000Z",
};

function createService() {
  return {
    status: vi.fn(() => ({
      postboxMode: "review-required" as const,
      projections: [projection],
      postboxItems: [postboxItem],
      sourceContent: "never expose",
    })),
    previewProjection: vi.fn(() => ({
      ...projection,
      previewId: "preview-1",
      sourceContent: "never expose",
    })),
    createProjection: vi.fn(() => ({ ...projection, sourceContent: "never expose" })),
    reviewProjection: vi.fn(() => ({ ...projection, sourceContent: "never expose" })),
    revokeProjection: vi.fn(() => ({ ...projection, sourceContent: "never expose" })),
    projectionImpact: vi.fn(() => ({
      projectionId: "projection-1",
      priorExposures: [
        { receiptId: "receipt-1", runRef: "sha256:abc", recordedAt: "2030-01-01T03:04:05.000Z" },
      ],
    })),
    inspectPostbox: vi.fn(() => ({ ...postboxInspection, sourceContent: "never expose" })),
    reviewPostbox: vi.fn(() => ({ ...postboxItem, content: "never expose" })),
    purgePostbox: vi.fn(() => ({ ...postboxItem, content: "never expose" })),
  };
}

function createHarness() {
  const methods = new Map<string, RegisteredMethod>();
  const service = createService();
  const api = {
    runtime: {
      config: {
        current: () => ({ agents: { list: [{ id: "main" }] } }),
      },
    },
    registerGatewayMethod(
      method: string,
      handler: RegisteredMethod["handler"],
      options?: { scope?: string },
    ) {
      methods.set(method, { handler, scope: options?.scope });
    },
  } as unknown as OpenClawPluginApi;
  registerScopedMemorySharingGatewayMethods(api, service as never);
  return { methods, service };
}

let stateDir = "";
let ownerProfileId = "";
let ownerPrincipalId = "";

function clientWithScopes(scopes: string[]): SharingGatewayClient {
  return {
    connect: {
      minProtocol: 1,
      maxProtocol: 1,
      client: {
        id: "openclaw-control-ui",
        version: "test",
        platform: "test",
        mode: "webchat",
      },
      scopes,
    },
  };
}

function ownerClient(profileId = ownerProfileId): SharingGatewayClient {
  return {
    ...clientWithScopes(["operator.write"]),
    authenticatedUserProfile: { profileId, displayName: null, hasAvatar: false, updatedAt: 1 },
  };
}

async function invoke(
  method: RegisteredMethod,
  params: unknown,
  client: GatewayRequestHandlerOptions["client"] = ownerClient(),
) {
  const respond = vi.fn();
  await method.handler({ params, client, respond } as unknown as GatewayRequestHandlerOptions);
  return respond;
}

describe("scoped memory sharing Gateway methods", () => {
  beforeEach(() => {
    stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-scoped-memory-sharing-gateway-"));
    vi.stubEnv("OPENCLAW_STATE_DIR", stateDir);
    const profile = ensureProfileForEmail("owner@example.test");
    const principal = memoryIdentityLifecycle.ensureGatewayProfileMemoryPrincipal(profile.id);
    if (!principal) {
      throw new Error("expected a canonical Gateway profile principal");
    }
    ownerProfileId = profile.id;
    ownerPrincipalId = principal.principalId;
    vi.clearAllMocks();
  });

  afterEach(() => {
    closeOpenClawStateDatabaseForTest();
    vi.unstubAllEnvs();
    fs.rmSync(stateDir, { recursive: true, force: true });
  });

  it("registers the complete sharing surface with operator.write", () => {
    const { methods } = createHarness();
    expect([...methods.entries()].map(([name, entry]) => [name, entry.scope])).toEqual(
      METHODS.map((method) => [method, "operator.write"]),
    );
  });

  it("rejects unknown fields, invalid targets, and non-future expiry at the Gateway boundary", async () => {
    const { methods, service } = createHarness();
    const preview = methods.get("memory.sharing.projection.preview")!;
    const unexpected = await invoke(preview, { agentId: "main", extra: true });
    const userTarget = await invoke(preview, {
      agentId: "main",
      sourceRevisionId: "revision-1",
      targetKind: "user",
      targetId: "user-1",
      purpose: "Share a reviewed decision",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const wrongAgentSharedTarget = await invoke(preview, {
      agentId: "main",
      sourceRevisionId: "revision-1",
      targetKind: "agent-shared",
      targetId: "other-agent",
      purpose: "Share a reviewed decision",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const expired = await invoke(preview, {
      agentId: "main",
      sourceRevisionId: "revision-1",
      targetKind: "conversation",
      targetId: "conversation-1",
      purpose: "Share a reviewed decision",
      expiresAt: "2020-01-01T00:00:00.000Z",
    });

    expect(service.previewProjection).not.toHaveBeenCalled();
    for (const respond of [unexpected, userTarget, wrongAgentSharedTarget, expired]) {
      expect(respond.mock.calls[0]?.[2]).toMatchObject({ code: "INVALID_REQUEST" });
    }
  });

  it("resolves authenticated profiles, rejects profile-less writers, and permits admins", async () => {
    const { methods, service } = createHarness();
    const status = methods.get("memory.sharing.status")!;

    expect(ownerPrincipalId).not.toBe(ownerProfileId);
    await invoke(status, { agentId: "main" }, ownerClient());
    expect(service.status).toHaveBeenLastCalledWith({
      agentId: "main",
      authority: { kind: "local-agent-owner", id: ownerPrincipalId },
    });

    const profilelessWriter = await invoke(
      status,
      { agentId: "main" },
      {
        ...clientWithScopes(["operator.write"]),
        authenticatedUserId: "not-a-profile@example.com",
      },
    );
    expect(service.status).toHaveBeenCalledTimes(1);
    expect(profilelessWriter.mock.calls[0]?.[2]).toMatchObject({ code: "FORBIDDEN" });

    const admin = await invoke(status, { agentId: "main" }, clientWithScopes(["operator.admin"]));
    expect(service.status).toHaveBeenLastCalledWith({
      agentId: "main",
      authority: { kind: "gateway-admin", id: "gateway-admin" },
    });
    expect(admin.mock.calls[0]?.[0]).toBe(true);
  });

  it("keeps list responses redacted and permits one owner/admin inspection shape", async () => {
    const { methods, service } = createHarness();
    const status = await invoke(methods.get("memory.sharing.status")!, { agentId: "main" });
    const preview = await invoke(methods.get("memory.sharing.projection.preview")!, {
      agentId: "main",
      sourceRevisionId: "revision-1",
      targetKind: "conversation",
      targetId: "conversation-1",
      purpose: "Share a reviewed decision",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const postboxList = await invoke(methods.get("memory.sharing.postbox.list")!, {
      agentId: "main",
    });
    const postboxInspect = await invoke(methods.get("memory.sharing.postbox.inspect")!, {
      agentId: "main",
      postboxItemId: "postbox-1",
    });
    const impact = await invoke(methods.get("memory.sharing.projection.impact")!, {
      agentId: "main",
      projectionId: "projection-1",
    });

    expect(status.mock.calls[0]?.[1]).toEqual({
      postboxMode: "review-required",
      projections: [projection],
      postboxItems: [postboxItem],
    });
    expect(preview.mock.calls[0]?.[1]).toEqual({ ...projection, previewId: "preview-1" });
    expect(postboxList.mock.calls[0]?.[1]).toEqual({ postboxItems: [postboxItem] });
    expect(postboxInspect.mock.calls[0]?.[1]).toEqual(postboxInspection);
    expect(impact.mock.calls[0]?.[1]).toEqual({
      projectionId: "projection-1",
      priorExposureCount: 1,
    });
    expect(service.inspectPostbox).toHaveBeenCalledWith({
      agentId: "main",
      authority: { kind: "local-agent-owner", id: ownerPrincipalId },
      postboxItemId: "postbox-1",
    });
  });

  it("requires rejection reasons and routes create and refresh through the reviewed preview", async () => {
    const { methods, service } = createHarness();
    const projectionReview = methods.get("memory.sharing.projection.review")!;
    const postboxReview = methods.get("memory.sharing.postbox.review")!;
    const missingProjectionReason = await invoke(projectionReview, {
      agentId: "main",
      projectionId: "projection-1",
      decision: "reject",
    });
    const missingPostboxReason = await invoke(postboxReview, {
      agentId: "main",
      postboxItemId: "postbox-1",
      decision: "reject",
    });
    await invoke(methods.get("memory.sharing.projection.create")!, {
      agentId: "main",
      previewId: "preview-1",
    });
    await invoke(methods.get("memory.sharing.projection.refresh")!, {
      agentId: "main",
      previewId: "preview-2",
    });

    expect(missingProjectionReason.mock.calls[0]?.[2]).toMatchObject({ code: "INVALID_REQUEST" });
    expect(missingPostboxReason.mock.calls[0]?.[2]).toMatchObject({ code: "INVALID_REQUEST" });
    expect(service.createProjection).toHaveBeenNthCalledWith(1, {
      agentId: "main",
      previewId: "preview-1",
      authority: { kind: "local-agent-owner", id: ownerPrincipalId },
    });
    expect(service.createProjection).toHaveBeenNthCalledWith(2, {
      agentId: "main",
      previewId: "preview-2",
      authority: { kind: "local-agent-owner", id: ownerPrincipalId },
    });
  });
});
