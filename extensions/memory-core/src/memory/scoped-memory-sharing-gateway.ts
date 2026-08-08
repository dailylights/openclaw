// Gateway sharing controls validate untrusted RPC input before it reaches the
// plugin-owned service. The service remains the sole owner of sharing state.
import type { OpenClawConfig } from "openclaw/plugin-sdk/config-contracts";
import {
  ErrorCodes,
  errorShape,
  type GatewayRequestHandlerOptions,
} from "openclaw/plugin-sdk/gateway-runtime";
import {
  resolveGatewayProfileMemoryPrincipalId,
  resolveSessionAgentIds,
} from "openclaw/plugin-sdk/memory-core-host-runtime-core";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";
import { normalizeAgentId } from "openclaw/plugin-sdk/routing";
import type {
  ScopedMemorySharingPostboxInspection,
  ScopedMemorySharingPostboxItem,
  ScopedMemorySharingProjection,
  ScopedMemorySharingStatus,
} from "./scoped-memory-sharing-contracts.js";
import { createScopedMemorySharingService } from "./scoped-memory-sharing.js";
import type { ScopedMemorySharingService } from "./scoped-memory-sharing.js";

const MEMORY_SHARING_GATEWAY_METHODS = {
  status: "memory.sharing.status",
  preview: "memory.sharing.projection.preview",
  create: "memory.sharing.projection.create",
  review: "memory.sharing.projection.review",
  refresh: "memory.sharing.projection.refresh",
  revoke: "memory.sharing.projection.revoke",
  impact: "memory.sharing.projection.impact",
  postboxList: "memory.sharing.postbox.list",
  postboxInspect: "memory.sharing.postbox.inspect",
  postboxReview: "memory.sharing.postbox.review",
  postboxPurge: "memory.sharing.postbox.purge",
} as const;

const SHARING_GATEWAY_SCOPE = "operator.write" as const;
const GATEWAY_ADMIN_AUDIT_ID = "gateway-admin";
const ISO_TIMESTAMP_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2})$/u;

type SharingAuthority = Parameters<ScopedMemorySharingService["status"]>[0]["authority"];
type ProjectionTargetKind = "conversation" | "role" | "agent-shared";
type ReviewDecision = "approve" | "reject";
type SharingGatewayService = Pick<
  ScopedMemorySharingService,
  | "createProjection"
  | "inspectPostbox"
  | "previewProjection"
  | "projectionImpact"
  | "purgePostbox"
  | "reviewPostbox"
  | "reviewProjection"
  | "revokeProjection"
  | "status"
>;

class InvalidSharingRequestError extends Error {}

class SharingAuthorizationError extends Error {}

function paramsRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new InvalidSharingRequestError("params must be an object.");
  }
  return value as Record<string, unknown>;
}

function assertOnlyKeys(params: Record<string, unknown>, allowed: readonly string[]): void {
  const allowedKeys = new Set(allowed);
  const unexpected = Object.keys(params).find((key) => !allowedKeys.has(key));
  if (unexpected) {
    throw new InvalidSharingRequestError(`unexpected parameter: ${unexpected}`);
  }
}

function readRequiredString(params: Record<string, unknown>, key: string): string {
  const value = params[key];
  if (typeof value !== "string" || !value.trim()) {
    throw new InvalidSharingRequestError(`${key} must be a non-empty string.`);
  }
  return value.trim();
}

function readOptionalString(params: Record<string, unknown>, key: string): string | undefined {
  const value = params[key];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string" || !value.trim()) {
    throw new InvalidSharingRequestError(`${key} must be a non-empty string when provided.`);
  }
  return value.trim();
}

function readAgentId(params: Record<string, unknown>): string {
  try {
    return normalizeAgentId(readRequiredString(params, "agentId"));
  } catch (error) {
    const message = error instanceof Error ? error.message : "agentId is invalid.";
    throw new InvalidSharingRequestError(message);
  }
}

function readProjectionTargetKind(params: Record<string, unknown>): ProjectionTargetKind {
  const targetKind = readRequiredString(params, "targetKind");
  if (targetKind !== "conversation" && targetKind !== "role" && targetKind !== "agent-shared") {
    throw new InvalidSharingRequestError("targetKind must be conversation, role, or agent-shared.");
  }
  return targetKind;
}

function readFutureExpiry(params: Record<string, unknown>): number {
  const expiresAt = readRequiredString(params, "expiresAt");
  if (!ISO_TIMESTAMP_PATTERN.test(expiresAt)) {
    throw new InvalidSharingRequestError("expiresAt must be an ISO timestamp with a timezone.");
  }
  const expiresAtMs = Date.parse(expiresAt);
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) {
    throw new InvalidSharingRequestError("expiresAt must be a future timestamp.");
  }
  return expiresAtMs;
}

function readReviewDecision(params: Record<string, unknown>): ReviewDecision {
  const decision = readRequiredString(params, "decision");
  if (decision !== "approve" && decision !== "reject") {
    throw new InvalidSharingRequestError("decision must be approve or reject.");
  }
  return decision;
}

function readStatusRequest(value: unknown): { agentId: string } {
  const params = paramsRecord(value);
  assertOnlyKeys(params, ["agentId"]);
  return { agentId: readAgentId(params) };
}

function readPreviewRequest(value: unknown): {
  agentId: string;
  sourceRevisionId: string;
  targetKind: ProjectionTargetKind;
  targetId: string;
  purpose: string;
  expiresAtMs: number;
  supersedesProjectionId?: string;
} {
  const params = paramsRecord(value);
  assertOnlyKeys(params, [
    "agentId",
    "sourceRevisionId",
    "targetKind",
    "targetId",
    "purpose",
    "expiresAt",
    "supersedesProjectionId",
  ]);
  const agentId = readAgentId(params);
  const targetKind = readProjectionTargetKind(params);
  const targetId = readRequiredString(params, "targetId");
  const supersedesProjectionId = readOptionalString(params, "supersedesProjectionId");
  if (targetId === "*" || (targetKind === "agent-shared" && targetId !== agentId)) {
    throw new InvalidSharingRequestError("projection target is unavailable.");
  }
  return {
    agentId,
    sourceRevisionId: readRequiredString(params, "sourceRevisionId"),
    targetKind,
    targetId,
    purpose: readRequiredString(params, "purpose"),
    expiresAtMs: readFutureExpiry(params),
    ...(supersedesProjectionId ? { supersedesProjectionId } : {}),
  };
}

function readPreviewActionRequest(value: unknown): { agentId: string; previewId: string } {
  const params = paramsRecord(value);
  assertOnlyKeys(params, ["agentId", "previewId"]);
  return {
    agentId: readAgentId(params),
    previewId: readRequiredString(params, "previewId"),
  };
}

function readProjectionIdRequest(value: unknown): { agentId: string; projectionId: string } {
  const params = paramsRecord(value);
  assertOnlyKeys(params, ["agentId", "projectionId"]);
  return {
    agentId: readAgentId(params),
    projectionId: readRequiredString(params, "projectionId"),
  };
}

function readProjectionReviewRequest(value: unknown): {
  agentId: string;
  projectionId: string;
  decision: ReviewDecision;
  reason?: string;
} {
  const params = paramsRecord(value);
  assertOnlyKeys(params, ["agentId", "projectionId", "decision", "reason"]);
  const decision = readReviewDecision(params);
  const reason = readOptionalString(params, "reason");
  if (decision === "reject" && !reason) {
    throw new InvalidSharingRequestError("reason is required when rejecting a projection.");
  }
  return {
    agentId: readAgentId(params),
    projectionId: readRequiredString(params, "projectionId"),
    decision,
    ...(reason ? { reason } : {}),
  };
}

function readPostboxIdRequest(value: unknown): { agentId: string; postboxItemId: string } {
  const params = paramsRecord(value);
  assertOnlyKeys(params, ["agentId", "postboxItemId"]);
  return {
    agentId: readAgentId(params),
    postboxItemId: readRequiredString(params, "postboxItemId"),
  };
}

function readPostboxReviewRequest(value: unknown): {
  agentId: string;
  postboxItemId: string;
  decision: ReviewDecision;
  reason?: string;
  editedContent?: string;
} {
  const params = paramsRecord(value);
  assertOnlyKeys(params, ["agentId", "postboxItemId", "decision", "reason", "editedContent"]);
  const decision = readReviewDecision(params);
  const reason = readOptionalString(params, "reason");
  if (decision === "reject" && !reason) {
    throw new InvalidSharingRequestError("reason is required when rejecting a postbox item.");
  }
  const editedContent = readOptionalString(params, "editedContent");
  return {
    agentId: readAgentId(params),
    postboxItemId: readRequiredString(params, "postboxItemId"),
    decision,
    ...(reason ? { reason } : {}),
    ...(editedContent ? { editedContent } : {}),
  };
}

function assertKnownAgent(api: OpenClawPluginApi, agentId: string): void {
  const config = api.runtime.config.current() as OpenClawConfig;
  const agentIds = (config.agents?.list ?? []).map((entry) => normalizeAgentId(entry.id));
  if (agentIds.length === 0) {
    agentIds.push(resolveSessionAgentIds({ config }).sessionAgentId);
  }
  if (!agentIds.includes(agentId)) {
    throw new InvalidSharingRequestError(`Unknown agent id "${agentId}".`);
  }
}

function resolveSharingAuthority(client: GatewayRequestHandlerOptions["client"]): SharingAuthority {
  const scopes = Array.isArray(client?.connect?.scopes) ? client.connect.scopes : [];
  if (scopes.includes("operator.admin")) {
    // Admin may not have a user profile, so preserve a stable non-user audit actor.
    return { kind: "gateway-admin", id: GATEWAY_ADMIN_AUDIT_ID };
  }
  const profileId = client?.authenticatedUserProfile?.profileId;
  if (typeof profileId === "string" && profileId.trim()) {
    const principalId = resolveGatewayProfileMemoryPrincipalId(profileId);
    if (principalId) {
      return { kind: "local-agent-owner", id: principalId };
    }
  }
  throw new SharingAuthorizationError(
    "memory sharing requires an authenticated user profile or operator.admin.",
  );
}

function redactProjection(value: ScopedMemorySharingProjection) {
  return {
    projectionId: value.projectionId,
    sourceRevisionId: value.sourceRevisionId,
    targetKind: value.targetKind,
    targetAudienceId: value.targetAudienceId,
    purpose: value.purpose,
    preview: value.preview,
    reviewState: value.reviewState,
    expiresAt: value.expiresAt,
    createdAt: value.createdAt,
    ...(value.reviewedAt ? { reviewedAt: value.reviewedAt } : {}),
    ...(value.revokedAt ? { revokedAt: value.revokedAt } : {}),
    ...(value.supersedesProjectionId
      ? { supersedesProjectionId: value.supersedesProjectionId }
      : {}),
  };
}

function redactPostboxItem(value: ScopedMemorySharingPostboxItem) {
  return {
    postboxItemId: value.postboxItemId,
    sourceConversationId: value.sourceConversationId,
    provenanceLabel: value.provenanceLabel,
    contentPreview: value.contentPreview,
    reviewState: value.reviewState,
    expiresAt: value.expiresAt,
    createdAt: value.createdAt,
    ...(value.reviewedAt ? { reviewedAt: value.reviewedAt } : {}),
  };
}

function selectPostboxInspection(value: ScopedMemorySharingPostboxInspection) {
  // This is the sole Gateway response that contains a postbox body. The
  // service already restricts it to the pending target owner or an admin.
  return {
    postboxItemId: value.postboxItemId,
    reviewContent: value.reviewContent,
    expiresAt: value.expiresAt,
  };
}

function redactStatus(value: ScopedMemorySharingStatus) {
  return {
    postboxMode: value.postboxMode,
    projections: value.projections.map(redactProjection),
    postboxItems: value.postboxItems.map(redactPostboxItem),
  };
}

function respondInvalid(respond: GatewayRequestHandlerOptions["respond"], error: unknown): void {
  const message = error instanceof Error ? error.message : "invalid memory sharing request";
  respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, message));
}

function respondForbidden(respond: GatewayRequestHandlerOptions["respond"], error: unknown): void {
  const message = error instanceof Error ? error.message : "memory sharing is not authorized";
  respond(false, undefined, errorShape(ErrorCodes.FORBIDDEN, message));
}

function respondUnavailable(respond: GatewayRequestHandlerOptions["respond"]): void {
  // Do not reflect service failures: they can encode private store topology.
  respond(false, undefined, errorShape(ErrorCodes.UNAVAILABLE, "memory sharing is unavailable"));
}

function registerSharingMethod<TRequest extends { agentId: string }>(params: {
  api: OpenClawPluginApi;
  method: string;
  service: SharingGatewayService;
  readRequest: (value: unknown) => TRequest;
  run: (request: TRequest, authority: SharingAuthority, service: SharingGatewayService) => unknown;
}): void {
  params.api.registerGatewayMethod(
    params.method,
    async ({ params: rawParams, client, respond }: GatewayRequestHandlerOptions) => {
      let request: TRequest;
      try {
        request = params.readRequest(rawParams);
        assertKnownAgent(params.api, request.agentId);
      } catch (error) {
        respondInvalid(respond, error);
        return;
      }
      let authority: SharingAuthority;
      try {
        authority = resolveSharingAuthority(client);
      } catch (error) {
        respondForbidden(respond, error);
        return;
      }
      try {
        respond(true, params.run(request, authority, params.service));
      } catch {
        respondUnavailable(respond);
      }
    },
    { scope: SHARING_GATEWAY_SCOPE },
  );
}

export function registerScopedMemorySharingGatewayMethods(
  api: OpenClawPluginApi,
  service: SharingGatewayService = createScopedMemorySharingService(),
): void {
  registerSharingMethod({
    api,
    service,
    method: MEMORY_SHARING_GATEWAY_METHODS.status,
    readRequest: readStatusRequest,
    run: (request, authority, sharing) => redactStatus(sharing.status({ ...request, authority })),
  });
  registerSharingMethod({
    api,
    service,
    method: MEMORY_SHARING_GATEWAY_METHODS.preview,
    readRequest: readPreviewRequest,
    run: (request, authority, sharing) => {
      const preview = sharing.previewProjection({ ...request, authority });
      return { ...redactProjection(preview), previewId: preview.previewId };
    },
  });
  registerSharingMethod({
    api,
    service,
    method: MEMORY_SHARING_GATEWAY_METHODS.create,
    readRequest: readPreviewActionRequest,
    run: (request, authority, sharing) =>
      redactProjection(sharing.createProjection({ ...request, authority })),
  });
  registerSharingMethod({
    api,
    service,
    method: MEMORY_SHARING_GATEWAY_METHODS.refresh,
    readRequest: readPreviewActionRequest,
    run: (request, authority, sharing) =>
      redactProjection(sharing.createProjection({ ...request, authority })),
  });
  registerSharingMethod({
    api,
    service,
    method: MEMORY_SHARING_GATEWAY_METHODS.review,
    readRequest: readProjectionReviewRequest,
    run: (request, authority, sharing) =>
      redactProjection(sharing.reviewProjection({ ...request, authority })),
  });
  registerSharingMethod({
    api,
    service,
    method: MEMORY_SHARING_GATEWAY_METHODS.revoke,
    readRequest: readProjectionIdRequest,
    run: (request, authority, sharing) =>
      redactProjection(sharing.revokeProjection({ ...request, authority })),
  });
  registerSharingMethod({
    api,
    service,
    method: MEMORY_SHARING_GATEWAY_METHODS.impact,
    readRequest: readProjectionIdRequest,
    run: (request, authority, sharing) => {
      const impact = sharing.projectionImpact({ ...request, authority });
      return {
        projectionId: impact.projectionId,
        priorExposureCount: impact.priorExposures.length,
      };
    },
  });
  registerSharingMethod({
    api,
    service,
    method: MEMORY_SHARING_GATEWAY_METHODS.postboxList,
    readRequest: readStatusRequest,
    run: (request, authority, sharing) => ({
      postboxItems: sharing.status({ ...request, authority }).postboxItems.map(redactPostboxItem),
    }),
  });
  registerSharingMethod({
    api,
    service,
    method: MEMORY_SHARING_GATEWAY_METHODS.postboxInspect,
    readRequest: readPostboxIdRequest,
    run: (request, authority, sharing) =>
      selectPostboxInspection(sharing.inspectPostbox({ ...request, authority })),
  });
  registerSharingMethod({
    api,
    service,
    method: MEMORY_SHARING_GATEWAY_METHODS.postboxReview,
    readRequest: readPostboxReviewRequest,
    run: (request, authority, sharing) =>
      redactPostboxItem(sharing.reviewPostbox({ ...request, authority })),
  });
  registerSharingMethod({
    api,
    service,
    method: MEMORY_SHARING_GATEWAY_METHODS.postboxPurge,
    readRequest: readPostboxIdRequest,
    run: (request, authority, sharing) =>
      redactPostboxItem(sharing.purgePostbox({ ...request, authority })),
  });
}
