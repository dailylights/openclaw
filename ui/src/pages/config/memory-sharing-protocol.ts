import { isRecord } from "@openclaw/normalization-core/record-coerce";
import { i18n, t } from "../../i18n/index.ts";
import { isGatewayMethodAdvertised } from "../../lib/gateway-methods.ts";

const MEMORY_SHARING_GATEWAY_METHODS = [
  "memory.sharing.status",
  "memory.sharing.projection.preview",
  "memory.sharing.projection.create",
  "memory.sharing.projection.review",
  "memory.sharing.projection.refresh",
  "memory.sharing.projection.revoke",
  "memory.sharing.projection.impact",
  "memory.sharing.postbox.list",
  "memory.sharing.postbox.inspect",
  "memory.sharing.postbox.review",
  "memory.sharing.postbox.purge",
] as const;

type ProjectionTargetKind = "conversation" | "role" | "agent-shared";
export type ProjectionReviewDecision = "approve" | "reject";
export type PostboxReviewDecision = "approve" | "reject";

type ProjectionDetails = {
  sourceRevisionId: string;
  targetKind: ProjectionTargetKind;
  targetAudienceId: string;
  purpose: string;
  preview: string;
  reviewState: string;
  expiresAt: string;
  createdAt: string;
  reviewedAt: string | null;
  revokedAt: string | null;
  supersedesProjectionId: string | null;
};

export type Projection = ProjectionDetails & {
  projectionId: string;
};

export type ProjectionPreview = ProjectionDetails & {
  previewId: string;
};

export type PostboxItem = {
  postboxItemId: string;
  sourceConversationId: string;
  provenanceLabel: string;
  contentPreview: string;
  reviewState: string;
  expiresAt: string;
  createdAt: string;
  reviewedAt: string | null;
};

export type PostboxInspection = {
  postboxItemId: string;
  reviewContent: string;
  expiresAt: string;
};

type SharingStatus = {
  postboxMode: "off" | "review-required" | "unknown";
  projections: Projection[];
  postboxItems: PostboxItem[];
};

export type SharingLoadState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ready"; status: SharingStatus }
  | { kind: "error" };

export type ProjectionForm = {
  sourceRevisionId: string;
  targetKind: ProjectionTargetKind;
  targetId: string;
  purpose: string;
  expiresAt: string;
  supersedesProjectionId: string | null;
};

export type ProjectionImpact = {
  priorExposureCount: number;
};

type GatewayMethodHost = {
  hello?: {
    features?: { methods?: string[] } | null;
  } | null;
};

export const TARGET_KINDS: ReadonlyArray<{ value: ProjectionTargetKind; labelKey: string }> = [
  { value: "conversation", labelKey: "memoryPage.sharing.targets.conversation" },
  { value: "role", labelKey: "memoryPage.sharing.targets.role" },
  { value: "agent-shared", labelKey: "memoryPage.sharing.targets.agentShared" },
];

const MAX_REDACTED_PREVIEW_LENGTH = 1_000;

export function emptyProjectionForm(): ProjectionForm {
  return {
    sourceRevisionId: "",
    targetKind: "conversation",
    targetId: "",
    purpose: "",
    expiresAt: "",
    supersedesProjectionId: null,
  };
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

/** Server-supplied previews are redacted, but cap their rendering independently. */
function asRedactedText(value: unknown): string {
  return typeof value === "string" ? value.slice(0, MAX_REDACTED_PREVIEW_LENGTH) : "";
}

function asOptionalString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

export function asTargetKind(value: unknown): ProjectionTargetKind | null {
  return value === "conversation" || value === "role" || value === "agent-shared" ? value : null;
}

function parseProjectionDetails(value: unknown): ProjectionDetails | null {
  if (!isRecord(value)) {
    return null;
  }
  const sourceRevisionId = asString(value.sourceRevisionId);
  const targetKind = asTargetKind(value.targetKind);
  const targetAudienceId = asString(value.targetAudienceId);
  const purpose = asRedactedText(value.purpose);
  const reviewState = asString(value.reviewState);
  const expiresAt = asString(value.expiresAt);
  const createdAt = asString(value.createdAt);
  if (
    !sourceRevisionId ||
    !targetKind ||
    !targetAudienceId ||
    !reviewState ||
    !expiresAt ||
    !createdAt
  ) {
    return null;
  }
  return {
    sourceRevisionId,
    targetKind,
    targetAudienceId,
    purpose,
    preview: asRedactedText(value.preview),
    reviewState,
    expiresAt,
    createdAt,
    reviewedAt: asOptionalString(value.reviewedAt),
    revokedAt: asOptionalString(value.revokedAt),
    supersedesProjectionId: asOptionalString(value.supersedesProjectionId),
  };
}

function parseProjection(value: unknown): Projection | null {
  const details = parseProjectionDetails(value);
  const projectionId = isRecord(value) ? asString(value.projectionId) : null;
  return details && projectionId ? { ...details, projectionId } : null;
}

export function parseProjectionPreview(value: unknown): ProjectionPreview | null {
  const details = parseProjectionDetails(value);
  const previewId = isRecord(value) ? asString(value.previewId) : null;
  return details && previewId ? { ...details, previewId } : null;
}

function parsePostboxItem(value: unknown): PostboxItem | null {
  if (!isRecord(value)) {
    return null;
  }
  const postboxItemId = asString(value.postboxItemId);
  const sourceConversationId = asString(value.sourceConversationId);
  const provenanceLabel = asRedactedText(value.provenanceLabel);
  const reviewState = asString(value.reviewState);
  const expiresAt = asString(value.expiresAt);
  const createdAt = asString(value.createdAt);
  if (!postboxItemId || !sourceConversationId || !reviewState || !expiresAt || !createdAt) {
    return null;
  }
  return {
    postboxItemId,
    sourceConversationId,
    provenanceLabel,
    contentPreview: asRedactedText(value.contentPreview),
    reviewState,
    expiresAt,
    createdAt,
    reviewedAt: asOptionalString(value.reviewedAt),
  };
}

export function parsePostboxInspection(value: unknown): PostboxInspection | null {
  if (!isRecord(value)) {
    return null;
  }
  const postboxItemId = asString(value.postboxItemId);
  const expiresAt = asString(value.expiresAt);
  const reviewContent = typeof value.reviewContent === "string" ? value.reviewContent : null;
  if (!postboxItemId || !expiresAt || reviewContent === null) {
    return null;
  }
  return { postboxItemId, reviewContent, expiresAt };
}

export function parsePostboxItems(value: unknown): PostboxItem[] | null {
  if (Array.isArray(value)) {
    return value.map(parsePostboxItem).filter((item): item is PostboxItem => item !== null);
  }
  if (!isRecord(value)) {
    return null;
  }
  const items = value.postboxItems ?? value.items;
  if (!Array.isArray(items)) {
    return null;
  }
  return items.map(parsePostboxItem).filter((item): item is PostboxItem => item !== null);
}

export function parseSharingStatus(value: unknown): SharingStatus | null {
  if (!isRecord(value)) {
    return null;
  }
  const projections = Array.isArray(value.projections)
    ? value.projections.map(parseProjection).filter((item): item is Projection => item !== null)
    : [];
  const postboxItems = parsePostboxItems(value) ?? [];
  return {
    postboxMode:
      value.postboxMode === "off" || value.postboxMode === "review-required"
        ? value.postboxMode
        : "unknown",
    projections,
    postboxItems,
  };
}

export function parseImpact(value: unknown): ProjectionImpact {
  if (!isRecord(value)) {
    return { priorExposureCount: 0 };
  }
  const directCount = value.priorExposureCount ?? value.exposureCount ?? value.count;
  if (typeof directCount === "number" && Number.isSafeInteger(directCount) && directCount >= 0) {
    return { priorExposureCount: directCount };
  }
  if (Array.isArray(value.exposures)) {
    return { priorExposureCount: value.exposures.length };
  }
  return { priorExposureCount: 0 };
}

export function localDateTimeValue(iso: string): string {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) {
    return "";
  }
  const date = new Date(ms);
  const offsetMs = date.getTimezoneOffset() * 60_000;
  return new Date(ms - offsetMs).toISOString().slice(0, 16);
}

export function futureIso(localDateTime: string): string | null {
  const ms = Date.parse(localDateTime);
  if (!Number.isFinite(ms) || ms <= Date.now()) {
    return null;
  }
  return new Date(ms).toISOString();
}

export function formatTimestamp(value: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    return t("memoryPage.sharing.unknownTimestamp");
  }
  return new Intl.DateTimeFormat(i18n.getLocale(), {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(timestamp));
}

export function targetLabel(kind: ProjectionTargetKind): string {
  return t(TARGET_KINDS.find((target) => target.value === kind)?.labelKey ?? "common.unknown");
}

export function reviewStateLabel(value: string): string {
  switch (value) {
    case "pending":
      return t("memoryPage.sharing.reviewState.pending");
    case "approved":
      return t("memoryPage.sharing.reviewState.approved");
    case "rejected":
      return t("memoryPage.sharing.reviewState.rejected");
    case "revoked":
      return t("memoryPage.sharing.reviewState.revoked");
    default:
      return t("memoryPage.sharing.reviewState.unknown");
  }
}

export function postboxModeLabel(mode: SharingStatus["postboxMode"]): string {
  switch (mode) {
    case "off":
      return t("memoryPage.sharing.postboxMode.off");
    case "review-required":
      return t("memoryPage.sharing.postboxMode.reviewRequired");
    default:
      return t("memoryPage.sharing.postboxMode.unknown");
  }
}

export function statusKind(reviewState: string): "ok" | "warn" | "muted" {
  if (reviewState === "approved") {
    return "ok";
  }
  if (reviewState === "pending") {
    return "warn";
  }
  return "muted";
}

/** The sharing UI stays hidden until the Gateway explicitly advertises every review operation. */
export function hasMemorySharingGatewayMethods(host: GatewayMethodHost): boolean {
  return MEMORY_SHARING_GATEWAY_METHODS.every(
    (method) => isGatewayMethodAdvertised(host, method) === true,
  );
}
