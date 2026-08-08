import { createHash, randomBytes } from "node:crypto";
import type { MemoryOperation } from "openclaw/plugin-sdk/memory-authorization";
import type {
  MemoryPolicyEntryRow,
  MemoryPostboxItemRow,
  MemoryProjectionRow,
  MemoryStoreRow,
  ScopedMemoryProjectionTargetKind,
  ScopedMemoryPublisherKind,
} from "./scoped-memory-db.js";
import {
  createScopedMemorySourcePolicySetId,
  normalizeScopedMemoryRequiredText,
} from "./scoped-memory-store.js";
import type { BuiltinScopedMemoryStore } from "./scoped-memory-store.js";

export const PREVIEW_TTL_MS = 5 * 60_000;
export const POSTBOX_HANDLE_TTL_MS = 5 * 60_000;
export const DEFAULT_POSTBOX_RATE_LIMIT_WINDOW_MS = 60 * 60_000;
export const DEFAULT_POSTBOX_RATE_LIMIT_MAX_ITEMS = 10;
// Purge keeps immutable review/audit metadata while removing both content bodies.
export const PURGED_POSTBOX_CONTENT = "[purged]";

export type SharingAuthority = Readonly<{
  kind: ScopedMemoryPublisherKind;
  id: string;
}>;

export type ProjectionPreviewInput = Readonly<{
  agentId: string;
  authority: SharingAuthority;
  sourceRevisionId: string;
  targetKind: ScopedMemoryProjectionTargetKind;
  targetId: string;
  purpose: string;
  expiresAtMs: number;
  supersedesProjectionId?: string;
}>;

export type ProjectionPreviewRecord = Readonly<{
  previewId: string;
  agentId: string;
  authority: SharingAuthority;
  sourceRevisionId: string;
  targetKind: ScopedMemoryProjectionTargetKind;
  targetId: string;
  targetStoreId: string;
  purpose: string;
  expiresAtMs: number;
  supersedesProjectionId?: string;
  expiresAtPreviewMs: number;
}>;

export type PostboxSourceMessage = Readonly<{
  agentId: string;
  sessionId: string;
  sourceConversationId: string;
  sourceEventId?: string;
  sourceActor: Readonly<{
    kind: "human" | "agent" | "service";
    id: string;
    evidenceRevision: string;
  }>;
  targetUserId: string;
  targetUserEvidenceRevision: string;
  content: string;
  expiresAtMs: number;
}>;

export type PostboxSourceMessageRecord = Readonly<{
  handle: string;
  message: PostboxSourceMessage;
  expiresAtMs: number;
}>;

export type ScopedStoreDetails = Readonly<{
  store: MemoryStoreRow;
  policyRevisionId: string;
  policyRevocationEpoch: number;
  authorityOwnerId: string;
  defaultCapabilities: readonly MemoryOperation[];
  policyEntries: readonly MemoryPolicyEntryRow[];
}>;

export type SourceRevision = ScopedStoreDetails &
  Readonly<{
    revisionId: string;
    resourceId: string;
    artifactLocator: string;
    contentHash: string;
    contentBytes: number;
    sourcePolicySetId: string;
    expiresAt: number | null;
    pathKey: string;
  }>;

/** Immutable ownership facts remain available after source policy revocation. */
export type HistoricalRevisionOwner = Readonly<{
  authorityOwnerId: string;
  resourceId: string;
}>;

export type ScopedMemorySharingProjection = Readonly<{
  projectionId: string;
  sourceRevisionId: string;
  targetKind: ScopedMemoryProjectionTargetKind;
  targetAudienceId: string;
  purpose: string;
  preview: string;
  reviewState: MemoryProjectionRow["review_state"];
  expiresAt: string;
  createdAt: string;
  reviewedAt?: string;
  revokedAt?: string;
  supersedesProjectionId?: string;
}>;

export type ScopedMemorySharingPostboxItem = Readonly<{
  postboxItemId: string;
  sourceConversationId: string;
  provenanceLabel: string;
  contentPreview: string;
  reviewState: MemoryPostboxItemRow["review_state"];
  expiresAt: string;
  createdAt: string;
  reviewedAt?: string;
}>;

/** The pending review body, visible only through the target-owner inspection action. */
export type ScopedMemorySharingPostboxInspection = Readonly<{
  postboxItemId: string;
  reviewContent: string;
  expiresAt: string;
}>;

export type ScopedMemorySharingStatus = Readonly<{
  postboxMode: "off" | "review-required";
  projections: readonly ScopedMemorySharingProjection[];
  postboxItems: readonly ScopedMemorySharingPostboxItem[];
}>;

export function hashText(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function createOpaqueId(prefix: "mppv1" | "mph1"): string {
  return `${prefix}_${randomBytes(24).toString("base64url")}`;
}

export function iso(value: number): string {
  return new Date(value).toISOString();
}

export function requireFutureExpiry(value: number, nowMs: number, label: string): number {
  if (!Number.isFinite(value) || value <= nowMs) {
    throw new Error(`${label} must be a future time`);
  }
  return Math.trunc(value);
}

export function capProjectionExpiryToSource(params: {
  requestedExpiresAtMs: number;
  sourceExpiresAtMs: number | null;
}): number {
  return params.sourceExpiresAtMs !== null && Number.isFinite(params.sourceExpiresAtMs)
    ? Math.min(params.requestedExpiresAtMs, params.sourceExpiresAtMs)
    : params.requestedExpiresAtMs;
}

export function assertPostboxMode(value: unknown): "off" | "review-required" {
  if (value !== "off" && value !== "review-required") {
    throw new Error("postbox mode is unavailable");
  }
  return value;
}

export function parseCapabilities(value: string): MemoryOperation[] {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed)) {
      return [];
    }
    const allowed = new Set<MemoryOperation>([
      "retrieve",
      "read",
      "append",
      "replace",
      "derive",
      "deposit",
      "project",
      "publish",
      "import",
      "export",
      "delete",
      "sync",
      "status",
      "policy-admin",
    ]);
    return [...new Set(parsed.filter((entry): entry is MemoryOperation => allowed.has(entry)))];
  } catch {
    return [];
  }
}

export function assertAuthority(authority: SharingAuthority): SharingAuthority {
  const id = normalizeScopedMemoryRequiredText(authority.id, "sharing authority id");
  if (authority.kind !== "gateway-admin" && authority.kind !== "local-agent-owner") {
    throw new Error("sharing authority is unavailable");
  }
  return { kind: authority.kind, id };
}

function policyEntryMatches(params: {
  entry: MemoryPolicyEntryRow;
  authority: SharingAuthority;
  store: MemoryStoreRow;
  operation: MemoryOperation;
  nowMs: number;
}): boolean {
  const { entry, authority, store, operation, nowMs } = params;
  return (
    entry.operation === operation &&
    (entry.principal_id === "*" || entry.principal_id === authority.id) &&
    (entry.audience_kind === "*" || entry.audience_kind === store.audience_kind) &&
    (entry.audience_id === "*" || entry.audience_id === store.audience_id) &&
    (entry.expires_at === null || entry.expires_at > nowMs)
  );
}

export function assertPolicyOperation(params: {
  details: ScopedStoreDetails;
  authority: SharingAuthority;
  operation: "project" | "publish";
  nowMs: number;
  explicitPublishEntry?: boolean;
}): void {
  const matching = params.details.policyEntries.filter((entry) =>
    policyEntryMatches({
      entry,
      authority: params.authority,
      store: params.details.store,
      operation: params.operation,
      nowMs: params.nowMs,
    }),
  );
  if (matching.some((entry) => entry.effect === "deny")) {
    throw new Error("sharing operation is denied by policy");
  }
  const allow = matching.some(
    (entry) =>
      entry.effect === "allow" && (!params.explicitPublishEntry || entry.entry_kind === "publish"),
  );
  if (
    params.explicitPublishEntry
      ? !allow
      : !allow && !params.details.defaultCapabilities.includes(params.operation)
  ) {
    throw new Error("sharing operation is not authorized by policy");
  }
}

export function assertLocalOwnerOrAdmin(params: {
  authority: SharingAuthority;
  authorityOwnerId: string;
}): void {
  if (
    params.authority.kind !== "gateway-admin" &&
    params.authority.id !== params.authorityOwnerId
  ) {
    throw new Error("sharing authority is unavailable");
  }
}

export function toBuiltinStore(details: ScopedStoreDetails): BuiltinScopedMemoryStore {
  return {
    storageRootId: details.store.storage_root_id,
    storeId: details.store.store_id,
    policyId: details.store.policy_id,
    policyRevisionId: details.policyRevisionId,
    policyRevocationEpoch: details.policyRevocationEpoch,
    sourcePolicySetId: createScopedMemorySourcePolicySetId(details.policyRevisionId),
  };
}
