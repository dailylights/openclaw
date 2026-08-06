import { isRecord } from "@openclaw/normalization-core/record-coerce";
import { html, nothing, type PropertyValues, type TemplateResult } from "lit";
import { property, state } from "lit/decorators.js";
import type { GatewayBrowserClient } from "../../api/gateway.ts";
import {
  renderSettingsRow,
  renderSettingsSection,
  renderSettingsStatus,
  renderSettingsValue,
} from "../../components/settings-ui.ts";
import { i18n, t } from "../../i18n/index.ts";
import { isGatewayMethodAdvertised } from "../../lib/gateway-methods.ts";
import { OpenClawLightDomElement } from "../../lit/openclaw-element.ts";
import "../../styles/memory-sharing.css";

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
type ProjectionReviewDecision = "approve" | "reject";
type PostboxReviewDecision = "approve" | "reject";

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

type Projection = ProjectionDetails & {
  projectionId: string;
};

type ProjectionPreview = ProjectionDetails & {
  previewId: string;
};

type PostboxItem = {
  postboxItemId: string;
  sourceConversationId: string;
  provenanceLabel: string;
  contentPreview: string;
  reviewState: string;
  expiresAt: string;
  createdAt: string;
  reviewedAt: string | null;
};

type PostboxInspection = {
  postboxItemId: string;
  reviewContent: string;
  expiresAt: string;
};

type SharingStatus = {
  postboxMode: "off" | "review-required" | "unknown";
  projections: Projection[];
  postboxItems: PostboxItem[];
};

type SharingLoadState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ready"; status: SharingStatus }
  | { kind: "error" };

type ProjectionForm = {
  sourceRevisionId: string;
  targetKind: ProjectionTargetKind;
  targetId: string;
  purpose: string;
  expiresAt: string;
  supersedesProjectionId: string | null;
};

type ProjectionImpact = {
  priorExposureCount: number;
};

type GatewayMethodHost = {
  hello?: {
    features?: { methods?: string[] } | null;
  } | null;
};

const TARGET_KINDS: ReadonlyArray<{ value: ProjectionTargetKind; labelKey: string }> = [
  { value: "conversation", labelKey: "memoryPage.sharing.targets.conversation" },
  { value: "role", labelKey: "memoryPage.sharing.targets.role" },
  { value: "agent-shared", labelKey: "memoryPage.sharing.targets.agentShared" },
];

const MAX_REDACTED_PREVIEW_LENGTH = 1_000;

function emptyProjectionForm(): ProjectionForm {
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

function asTargetKind(value: unknown): ProjectionTargetKind | null {
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

function parseProjectionPreview(value: unknown): ProjectionPreview | null {
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

function parsePostboxInspection(value: unknown): PostboxInspection | null {
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

function parsePostboxItems(value: unknown): PostboxItem[] | null {
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

function parseSharingStatus(value: unknown): SharingStatus | null {
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

function parseImpact(value: unknown): ProjectionImpact {
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

function localDateTimeValue(iso: string): string {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) {
    return "";
  }
  const date = new Date(ms);
  const offsetMs = date.getTimezoneOffset() * 60_000;
  return new Date(ms - offsetMs).toISOString().slice(0, 16);
}

function futureIso(localDateTime: string): string | null {
  const ms = Date.parse(localDateTime);
  if (!Number.isFinite(ms) || ms <= Date.now()) {
    return null;
  }
  return new Date(ms).toISOString();
}

function formatTimestamp(value: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    return t("memoryPage.sharing.unknownTimestamp");
  }
  return new Intl.DateTimeFormat(i18n.getLocale(), {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(timestamp));
}

function targetLabel(kind: ProjectionTargetKind): string {
  return t(TARGET_KINDS.find((target) => target.value === kind)?.labelKey ?? "common.unknown");
}

function reviewStateLabel(value: string): string {
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

function postboxModeLabel(mode: SharingStatus["postboxMode"]): string {
  switch (mode) {
    case "off":
      return t("memoryPage.sharing.postboxMode.off");
    case "review-required":
      return t("memoryPage.sharing.postboxMode.reviewRequired");
    default:
      return t("memoryPage.sharing.postboxMode.unknown");
  }
}

function statusKind(state: string): "ok" | "warn" | "muted" {
  if (state === "approved") {
    return "ok";
  }
  if (state === "pending") {
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

class MemorySharingElement extends OpenClawLightDomElement {
  @property({ attribute: false }) client: GatewayBrowserClient | null = null;
  @property({ type: Boolean }) connected = false;
  @property({ type: Boolean }) canWrite = false;
  @property({ type: Boolean }) methodsAvailable = false;
  @property() agentId: string | null = null;

  @state() private loadState: SharingLoadState = { kind: "idle" };
  @state() private form: ProjectionForm = emptyProjectionForm();
  @state() private preview: ProjectionPreview | null = null;
  @state() private busyOperation: string | null = null;
  @state() private operationError: string | null = null;
  @state() private impacts = new Map<string, ProjectionImpact>();
  @state() private postboxEdits = new Map<string, string>();
  @state() private postboxInspections = new Map<string, PostboxInspection>();
  @state() private projectionRejectReasons = new Map<string, string>();
  @state() private postboxRejectReasons = new Map<string, string>();
  @state() private revokeCandidateId: string | null = null;
  @state() private purgeCandidateId: string | null = null;

  private loadRequest: { client: GatewayBrowserClient; agentId: string } | null = null;

  protected override updated(changed: PropertyValues<this>) {
    if (
      !changed.has("client") &&
      !changed.has("connected") &&
      !changed.has("canWrite") &&
      !changed.has("methodsAvailable") &&
      !changed.has("agentId")
    ) {
      return;
    }
    this.loadRequest = null;
    this.preview = null;
    this.impacts = new Map();
    this.postboxInspections = new Map();
    this.operationError = null;
    this.revokeCandidateId = null;
    this.purgeCandidateId = null;
    this.projectionRejectReasons = new Map();
    this.postboxRejectReasons = new Map();
    if (changed.has("agentId")) {
      this.form = emptyProjectionForm();
      this.postboxEdits = new Map();
    }
    if (!this.canUse()) {
      this.loadState = { kind: "idle" };
      return;
    }
    void this.load();
  }

  private canUse(): this is this & { client: GatewayBrowserClient; agentId: string } {
    return Boolean(
      this.connected && this.canWrite && this.methodsAvailable && this.client && this.agentId,
    );
  }

  private isCurrentRequest(request: { client: GatewayBrowserClient; agentId: string }): boolean {
    return (
      this.isConnected &&
      this.canUse() &&
      this.client === request.client &&
      this.agentId === request.agentId
    );
  }

  private async load() {
    if (!this.canUse()) {
      return;
    }
    const request = { client: this.client, agentId: this.agentId };
    this.loadRequest = request;
    this.loadState = { kind: "loading" };
    try {
      const [statusResponse, postboxResponse] = await Promise.all([
        request.client.request<unknown>("memory.sharing.status", { agentId: request.agentId }),
        request.client.request<unknown>("memory.sharing.postbox.list", {
          agentId: request.agentId,
        }),
      ]);
      if (this.loadRequest !== request || !this.isCurrentRequest(request)) {
        return;
      }
      const status = parseSharingStatus(statusResponse);
      if (!status) {
        throw new Error("invalid sharing status response");
      }
      this.loadState = {
        kind: "ready",
        status: {
          ...status,
          postboxItems: parsePostboxItems(postboxResponse) ?? status.postboxItems,
        },
      };
    } catch {
      if (this.loadRequest === request && this.isCurrentRequest(request)) {
        // The service never exposes source content through this surface, so do
        // not echo opaque Gateway errors that may include rejected arguments.
        this.loadState = { kind: "error" };
      }
    }
  }

  private async request(method: string, payload: Record<string, unknown>): Promise<unknown | null> {
    if (!this.canUse() || this.busyOperation) {
      return null;
    }
    const request = { client: this.client, agentId: this.agentId };
    this.busyOperation = method;
    this.operationError = null;
    try {
      const response = await request.client.request<unknown>(method, payload);
      return this.isCurrentRequest(request) ? response : null;
    } catch {
      if (this.isCurrentRequest(request)) {
        this.operationError = t("memoryPage.sharing.requestFailed");
      }
      return null;
    } finally {
      if (this.isCurrentRequest(request) && this.busyOperation === method) {
        this.busyOperation = null;
      }
    }
  }

  private updateForm<K extends keyof ProjectionForm>(key: K, value: ProjectionForm[K]) {
    this.form = { ...this.form, [key]: value };
    this.preview = null;
  }

  private updateTargetKind(value: string) {
    const targetKind = asTargetKind(value);
    if (!targetKind) {
      return;
    }
    this.form = {
      ...this.form,
      targetKind,
      // An agent-shared audience is the selected agent's one shared store;
      // do not let the UI turn it into a cross-agent or arbitrary target.
      targetId: targetKind === "agent-shared" ? (this.agentId ?? "") : this.form.targetId,
    };
    this.preview = null;
  }

  private previewPayload(): {
    agentId: string;
    sourceRevisionId: string;
    targetKind: ProjectionTargetKind;
    targetId: string;
    purpose: string;
    expiresAt: string;
    supersedesProjectionId?: string;
  } | null {
    const sourceRevisionId = this.form.sourceRevisionId.trim();
    const targetId = this.form.targetId.trim();
    const purpose = this.form.purpose.trim();
    const expiresAt = futureIso(this.form.expiresAt);
    const targetKind = asTargetKind(this.form.targetKind);
    if (
      !this.agentId ||
      !sourceRevisionId ||
      !targetKind ||
      !targetId ||
      !purpose ||
      !expiresAt ||
      (targetKind === "agent-shared" && targetId !== this.agentId)
    ) {
      this.operationError = t("memoryPage.sharing.completeRequiredFields");
      return null;
    }
    return {
      agentId: this.agentId,
      sourceRevisionId,
      targetKind,
      targetId,
      purpose,
      expiresAt,
      ...(this.form.supersedesProjectionId
        ? { supersedesProjectionId: this.form.supersedesProjectionId }
        : {}),
    };
  }

  private async requestPreview() {
    const payload = this.previewPayload();
    if (!payload) {
      return;
    }
    const response = await this.request("memory.sharing.projection.preview", payload);
    if (response === null) {
      return;
    }
    const preview = parseProjectionPreview(response);
    if (!preview) {
      this.operationError = t("memoryPage.sharing.requestFailed");
      return;
    }
    this.preview = preview;
  }

  private async finalizePreview() {
    const preview = this.preview;
    if (!preview || !this.agentId) {
      return;
    }
    const refresh = this.form.supersedesProjectionId !== null;
    const response = await this.request(
      refresh ? "memory.sharing.projection.refresh" : "memory.sharing.projection.create",
      { agentId: this.agentId, previewId: preview.previewId },
    );
    if (response === null) {
      return;
    }
    this.preview = null;
    this.form = emptyProjectionForm();
    await this.load();
  }

  private updateProjectionRejectReason(projectionId: string, reason: string) {
    const reasons = new Map(this.projectionRejectReasons);
    if (reason) {
      reasons.set(projectionId, reason);
    } else {
      reasons.delete(projectionId);
    }
    this.projectionRejectReasons = reasons;
  }

  private async reviewProjection(projectionId: string, decision: ProjectionReviewDecision) {
    if (!this.agentId) {
      return;
    }
    const reason =
      decision === "reject" ? this.projectionRejectReasons.get(projectionId)?.trim() : undefined;
    if (decision === "reject" && !reason) {
      this.operationError = t("memoryPage.sharing.review.reasonRequired");
      return;
    }
    const response = await this.request("memory.sharing.projection.review", {
      agentId: this.agentId,
      projectionId,
      decision,
      ...(reason ? { reason } : {}),
    });
    if (response !== null) {
      this.updateProjectionRejectReason(projectionId, "");
      await this.load();
    }
  }

  private prepareRefresh(projection: Projection) {
    this.form = {
      sourceRevisionId: projection.sourceRevisionId,
      targetKind: projection.targetKind,
      targetId: projection.targetAudienceId,
      purpose: projection.purpose,
      expiresAt: localDateTimeValue(projection.expiresAt),
      supersedesProjectionId: projection.projectionId,
    };
    this.preview = null;
    this.operationError = null;
  }

  private cancelRefresh() {
    this.form = emptyProjectionForm();
    this.preview = null;
    this.operationError = null;
  }

  private async revokeProjection(projectionId: string) {
    if (!this.agentId) {
      return;
    }
    const response = await this.request("memory.sharing.projection.revoke", {
      agentId: this.agentId,
      projectionId,
    });
    if (response !== null) {
      this.revokeCandidateId = null;
      await this.load();
    }
  }

  private async loadImpact(projectionId: string) {
    if (!this.agentId) {
      return;
    }
    const response = await this.request("memory.sharing.projection.impact", {
      agentId: this.agentId,
      projectionId,
    });
    if (response !== null) {
      this.impacts = new Map(this.impacts).set(projectionId, parseImpact(response));
    }
  }

  private updatePostboxEdit(postboxItemId: string, editedContent: string) {
    const edits = new Map(this.postboxEdits);
    if (editedContent) {
      edits.set(postboxItemId, editedContent);
    } else {
      edits.delete(postboxItemId);
    }
    this.postboxEdits = edits;
  }

  private updatePostboxRejectReason(postboxItemId: string, reason: string) {
    const reasons = new Map(this.postboxRejectReasons);
    if (reason) {
      reasons.set(postboxItemId, reason);
    } else {
      reasons.delete(postboxItemId);
    }
    this.postboxRejectReasons = reasons;
  }

  private clearPostboxInspection(postboxItemId: string) {
    const inspections = new Map(this.postboxInspections);
    inspections.delete(postboxItemId);
    this.postboxInspections = inspections;
  }

  private async inspectPostbox(postboxItemId: string) {
    if (!this.agentId) {
      return;
    }
    const response = await this.request("memory.sharing.postbox.inspect", {
      agentId: this.agentId,
      postboxItemId,
    });
    if (response === null) {
      return;
    }
    const inspection = parsePostboxInspection(response);
    if (!inspection || inspection.postboxItemId !== postboxItemId) {
      this.operationError = t("memoryPage.sharing.requestFailed");
      return;
    }
    this.postboxInspections = new Map(this.postboxInspections).set(postboxItemId, inspection);
  }

  private async reviewPostbox(postboxItemId: string, decision: PostboxReviewDecision) {
    if (!this.agentId) {
      return;
    }
    const editedContent = this.postboxEdits.get(postboxItemId)?.trim();
    const reason =
      decision === "reject" ? this.postboxRejectReasons.get(postboxItemId)?.trim() : undefined;
    if (decision === "reject" && !reason) {
      this.operationError = t("memoryPage.sharing.review.reasonRequired");
      return;
    }
    const response = await this.request("memory.sharing.postbox.review", {
      agentId: this.agentId,
      postboxItemId,
      decision,
      ...(editedContent ? { editedContent } : {}),
      ...(reason ? { reason } : {}),
    });
    if (response !== null) {
      this.postboxEdits = new Map(this.postboxEdits);
      this.postboxEdits.delete(postboxItemId);
      this.clearPostboxInspection(postboxItemId);
      this.updatePostboxRejectReason(postboxItemId, "");
      await this.load();
    }
  }

  private async purgePostbox(postboxItemId: string) {
    if (!this.agentId) {
      return;
    }
    const response = await this.request("memory.sharing.postbox.purge", {
      agentId: this.agentId,
      postboxItemId,
    });
    if (response !== null) {
      this.purgeCandidateId = null;
      this.clearPostboxInspection(postboxItemId);
      await this.load();
    }
  }

  private renderStatus() {
    const state = this.loadState;
    const ready = state.kind === "ready" ? state.status : null;
    return renderSettingsSection(
      {
        title: t("memoryPage.sharing.status.title"),
        description: t("memoryPage.sharing.status.description"),
        actions: html`<button
          type="button"
          class="btn btn--sm"
          ?disabled=${this.busyOperation !== null || state.kind === "loading"}
          @click=${() => void this.load()}
        >
          ${t("memoryPage.sharing.refresh")}
        </button>`,
      },
      state.kind === "loading"
        ? renderSettingsRow({
            title: t("memoryPage.sharing.status.loading"),
            control: renderSettingsStatus({ kind: "muted", label: t("common.loading") }),
          })
        : state.kind === "error"
          ? renderSettingsRow({
              title: t("memoryPage.sharing.status.unavailable"),
              description: t("memoryPage.sharing.status.unavailableDescription"),
              control: renderSettingsStatus({ kind: "danger", label: t("common.failed") }),
            })
          : html`
              ${renderSettingsRow({
                title: t("memoryPage.sharing.status.agent"),
                control: renderSettingsValue(this.agentId ?? t("common.unknown"), { mono: true }),
              })}
              ${ready
                ? html`
                    ${renderSettingsRow({
                      title: t("memoryPage.sharing.status.postboxMode"),
                      control: renderSettingsStatus({
                        kind: ready.postboxMode === "review-required" ? "warn" : "muted",
                        label: postboxModeLabel(ready.postboxMode),
                      }),
                    })}
                    ${renderSettingsRow({
                      title: t("memoryPage.sharing.status.projectionCount"),
                      control: renderSettingsValue(String(ready.projections.length)),
                    })}
                    ${renderSettingsRow({
                      title: t("memoryPage.sharing.status.postboxCount"),
                      control: renderSettingsValue(String(ready.postboxItems.length)),
                    })}
                  `
                : nothing}
            `,
    );
  }

  private renderProjectionForm() {
    const refreshing = this.form.supersedesProjectionId !== null;
    const form = this.form;
    return renderSettingsSection(
      {
        title: refreshing
          ? t("memoryPage.sharing.projection.refreshTitle")
          : t("memoryPage.sharing.projection.createTitle"),
        description: refreshing
          ? t("memoryPage.sharing.projection.refreshDescription")
          : t("memoryPage.sharing.projection.createDescription"),
        actions: refreshing
          ? html`<button type="button" class="btn btn--sm" @click=${() => this.cancelRefresh()}>
              ${t("memoryPage.sharing.projection.cancelRefresh")}
            </button>`
          : undefined,
      },
      html`
        <form
          class="memory-sharing__form"
          @submit=${(event: SubmitEvent) => {
            event.preventDefault();
            void this.requestPreview();
          }}
        >
          ${renderSettingsRow({
            title: t("memoryPage.sharing.projection.sourceRevision"),
            description: t("memoryPage.sharing.projection.sourceRevisionDescription"),
            stacked: true,
            control: html`<input
              id="memory-sharing-source-revision"
              class="settings-input"
              aria-label=${t("memoryPage.sharing.projection.sourceRevision")}
              autocomplete="off"
              required
              .value=${form.sourceRevisionId}
              @input=${(event: Event) =>
                this.updateForm("sourceRevisionId", (event.target as HTMLInputElement).value)}
            />`,
          })}
          ${renderSettingsRow({
            title: t("memoryPage.sharing.projection.targetKind"),
            description: t("memoryPage.sharing.projection.targetKindDescription"),
            stacked: true,
            control: html`<select
              id="memory-sharing-target-kind"
              class="settings-select"
              aria-label=${t("memoryPage.sharing.projection.targetKind")}
              .value=${form.targetKind}
              @change=${(event: Event) =>
                this.updateTargetKind((event.target as HTMLSelectElement).value)}
            >
              ${TARGET_KINDS.map(
                (target) => html`<option value=${target.value}>${t(target.labelKey)}</option>`,
              )}
            </select>`,
          })}
          ${renderSettingsRow({
            title: t("memoryPage.sharing.projection.targetId"),
            description:
              form.targetKind === "agent-shared"
                ? t("memoryPage.sharing.projection.agentSharedTargetDescription")
                : t("memoryPage.sharing.projection.targetIdDescription"),
            stacked: true,
            control: html`<input
              id="memory-sharing-target-id"
              class="settings-input"
              aria-label=${t("memoryPage.sharing.projection.targetId")}
              autocomplete="off"
              required
              ?disabled=${form.targetKind === "agent-shared"}
              .value=${form.targetId}
              @input=${(event: Event) =>
                this.updateForm("targetId", (event.target as HTMLInputElement).value)}
            />`,
          })}
          ${renderSettingsRow({
            title: t("memoryPage.sharing.projection.purpose"),
            stacked: true,
            control: html`<textarea
              id="memory-sharing-purpose"
              class="settings-input"
              aria-label=${t("memoryPage.sharing.projection.purpose")}
              required
              .value=${form.purpose}
              @input=${(event: Event) =>
                this.updateForm("purpose", (event.target as HTMLTextAreaElement).value)}
            ></textarea>`,
          })}
          ${renderSettingsRow({
            title: t("memoryPage.sharing.projection.expiry"),
            description: t("memoryPage.sharing.projection.expiryDescription"),
            stacked: true,
            control: html`<input
              id="memory-sharing-expiry"
              class="settings-input"
              type="datetime-local"
              aria-label=${t("memoryPage.sharing.projection.expiry")}
              required
              .value=${form.expiresAt}
              @input=${(event: Event) =>
                this.updateForm("expiresAt", (event.target as HTMLInputElement).value)}
            />`,
          })}
          <div class="settings-row settings-row--actions">
            <div class="settings-row__control">
              <button type="submit" class="btn btn--sm" ?disabled=${this.busyOperation !== null}>
                ${t("memoryPage.sharing.projection.preview")}
              </button>
            </div>
          </div>
        </form>
      `,
    );
  }

  private renderPreview() {
    const preview = this.preview;
    if (!preview) {
      return nothing;
    }
    const refreshing = this.form.supersedesProjectionId !== null;
    return renderSettingsSection(
      {
        title: t("memoryPage.sharing.preview.title"),
        description: t("memoryPage.sharing.preview.description"),
      },
      html`
        ${renderSettingsRow({
          title: t("memoryPage.sharing.preview.target"),
          description: `${targetLabel(preview.targetKind)} · ${preview.targetAudienceId}`,
        })}
        ${renderSettingsRow({
          title: t("memoryPage.sharing.preview.expiry"),
          control: renderSettingsValue(formatTimestamp(preview.expiresAt)),
        })}
        ${renderSettingsRow({
          title: t("memoryPage.sharing.preview.redactedPreview"),
          stacked: true,
          control: html`<p class="memory-sharing__redacted-preview">${preview.preview}</p>`,
        })}
        <div class="settings-row settings-row--actions">
          <div class="settings-row__control">
            <button
              type="button"
              class="btn btn--sm"
              ?disabled=${this.busyOperation !== null}
              @click=${() => void this.finalizePreview()}
            >
              ${refreshing
                ? t("memoryPage.sharing.preview.refreshForReview")
                : t("memoryPage.sharing.preview.createForReview")}
            </button>
          </div>
        </div>
      `,
    );
  }

  private renderProjectionActions(projection: Projection): TemplateResult {
    const pendingRevoke = this.revokeCandidateId === projection.projectionId;
    const impact = this.impacts.get(projection.projectionId);
    const rejectReason = this.projectionRejectReasons.get(projection.projectionId) ?? "";
    return html`
      <div class="memory-sharing__actions">
        ${projection.reviewState === "pending"
          ? html`
              <button
                type="button"
                class="btn btn--sm"
                ?disabled=${this.busyOperation !== null}
                @click=${() => void this.reviewProjection(projection.projectionId, "approve")}
              >
                ${t("memoryPage.sharing.review.approve")}
              </button>
              <label
                class="memory-sharing__reason"
                for="memory-sharing-projection-reason-${projection.projectionId}"
              >
                <span>${t("memoryPage.sharing.review.reason")}</span>
                <textarea
                  id="memory-sharing-projection-reason-${projection.projectionId}"
                  class="settings-input"
                  aria-label=${t("memoryPage.sharing.review.reason")}
                  .value=${rejectReason}
                  @input=${(event: Event) =>
                    this.updateProjectionRejectReason(
                      projection.projectionId,
                      (event.target as HTMLTextAreaElement).value,
                    )}
                ></textarea>
              </label>
              <button
                type="button"
                class="btn btn--sm"
                ?disabled=${this.busyOperation !== null || !rejectReason.trim()}
                @click=${() => void this.reviewProjection(projection.projectionId, "reject")}
              >
                ${t("memoryPage.sharing.review.reject")}
              </button>
            `
          : nothing}
        ${projection.reviewState === "approved"
          ? html`<button
              type="button"
              class="btn btn--sm"
              ?disabled=${this.busyOperation !== null}
              @click=${() => this.prepareRefresh(projection)}
            >
              ${t("memoryPage.sharing.projection.refresh")}
            </button>`
          : nothing}
        <button
          type="button"
          class="btn btn--sm"
          ?disabled=${this.busyOperation !== null}
          @click=${() => void this.loadImpact(projection.projectionId)}
        >
          ${t("memoryPage.sharing.projection.impact")}
        </button>
        ${projection.reviewState === "approved"
          ? pendingRevoke
            ? html`
                <button
                  type="button"
                  class="btn btn--sm btn--danger"
                  ?disabled=${this.busyOperation !== null}
                  @click=${() => void this.revokeProjection(projection.projectionId)}
                >
                  ${t("memoryPage.sharing.projection.confirmRevoke")}
                </button>
                <button
                  type="button"
                  class="btn btn--sm"
                  ?disabled=${this.busyOperation !== null}
                  @click=${() => (this.revokeCandidateId = null)}
                >
                  ${t("common.cancel")}
                </button>
              `
            : html`<button
                type="button"
                class="btn btn--sm btn--danger"
                ?disabled=${this.busyOperation !== null}
                @click=${() => (this.revokeCandidateId = projection.projectionId)}
              >
                ${t("memoryPage.sharing.projection.revoke")}
              </button>`
          : nothing}
      </div>
      ${impact
        ? html`<p class="memory-sharing__impact" role="status">
            ${t("memoryPage.sharing.projection.priorExposures", {
              count: String(impact.priorExposureCount),
            })}
          </p>`
        : nothing}
    `;
  }

  private renderProjections() {
    const projections = this.loadState.kind === "ready" ? this.loadState.status.projections : [];
    return renderSettingsSection(
      {
        title: t("memoryPage.sharing.projections.title"),
        description: t("memoryPage.sharing.projections.description"),
        count: projections.length,
      },
      projections.length === 0
        ? renderSettingsRow({ title: t("memoryPage.sharing.projections.empty") })
        : projections.map(
            (projection) => html`
              <article class="memory-sharing__item">
                ${renderSettingsRow({
                  title: projection.purpose || t("memoryPage.sharing.projection.untitled"),
                  description: `${targetLabel(projection.targetKind)} · ${projection.targetAudienceId}`,
                  control: renderSettingsStatus({
                    kind: statusKind(projection.reviewState),
                    label: reviewStateLabel(projection.reviewState),
                  }),
                })}
                ${renderSettingsRow({
                  title: t("memoryPage.sharing.preview.redactedPreview"),
                  description: html`<span class="memory-sharing__redacted-preview"
                    >${projection.preview}</span
                  >`,
                })}
                ${renderSettingsRow({
                  title: t("memoryPage.sharing.projection.expires"),
                  control: renderSettingsValue(formatTimestamp(projection.expiresAt)),
                })}
                <div class="settings-row settings-row--actions">
                  <div class="settings-row__control">
                    ${this.renderProjectionActions(projection)}
                  </div>
                </div>
              </article>
            `,
          ),
    );
  }

  private renderPostboxActions(item: PostboxItem): TemplateResult {
    const pendingPurge = this.purgeCandidateId === item.postboxItemId;
    const editedContent = this.postboxEdits.get(item.postboxItemId) ?? "";
    const inspection = this.postboxInspections.get(item.postboxItemId);
    const rejectReason = this.postboxRejectReasons.get(item.postboxItemId) ?? "";
    return html`
      ${item.reviewState === "pending"
        ? html`
            ${inspection
              ? renderSettingsRow({
                  title: t("memoryPage.sharing.postbox.inspection"),
                  description: t("memoryPage.sharing.postbox.inspectionDescription"),
                  stacked: true,
                  control: html`<textarea
                    id="memory-sharing-postbox-inspection-${item.postboxItemId}"
                    class="settings-input"
                    aria-label=${t("memoryPage.sharing.postbox.inspection")}
                    readonly
                    .value=${inspection.reviewContent}
                  ></textarea>`,
                })
              : nothing}
            <div class="settings-row settings-row--actions">
              <div class="settings-row__control memory-sharing__actions">
                <button
                  type="button"
                  class="btn btn--sm"
                  ?disabled=${this.busyOperation !== null}
                  @click=${() =>
                    inspection
                      ? this.clearPostboxInspection(item.postboxItemId)
                      : void this.inspectPostbox(item.postboxItemId)}
                >
                  ${inspection
                    ? t("memoryPage.sharing.postbox.hideInspection")
                    : t("memoryPage.sharing.postbox.inspect")}
                </button>
              </div>
            </div>
            ${renderSettingsRow({
              title: t("memoryPage.sharing.postbox.replacement"),
              description: t("memoryPage.sharing.postbox.replacementDescription"),
              stacked: true,
              control: html`<textarea
                class="settings-input"
                .value=${editedContent}
                @input=${(event: Event) =>
                  this.updatePostboxEdit(
                    item.postboxItemId,
                    (event.target as HTMLTextAreaElement).value,
                  )}
              ></textarea>`,
            })}
            <div class="settings-row settings-row--actions">
              <div class="settings-row__control memory-sharing__actions">
                <button
                  type="button"
                  class="btn btn--sm"
                  ?disabled=${this.busyOperation !== null}
                  @click=${() => void this.reviewPostbox(item.postboxItemId, "approve")}
                >
                  ${t("memoryPage.sharing.review.approve")}
                </button>
                <label
                  class="memory-sharing__reason"
                  for="memory-sharing-postbox-reason-${item.postboxItemId}"
                >
                  <span>${t("memoryPage.sharing.review.reason")}</span>
                  <textarea
                    id="memory-sharing-postbox-reason-${item.postboxItemId}"
                    class="settings-input"
                    aria-label=${t("memoryPage.sharing.review.reason")}
                    .value=${rejectReason}
                    @input=${(event: Event) =>
                      this.updatePostboxRejectReason(
                        item.postboxItemId,
                        (event.target as HTMLTextAreaElement).value,
                      )}
                  ></textarea>
                </label>
                <button
                  type="button"
                  class="btn btn--sm"
                  ?disabled=${this.busyOperation !== null || !rejectReason.trim()}
                  @click=${() => void this.reviewPostbox(item.postboxItemId, "reject")}
                >
                  ${t("memoryPage.sharing.review.reject")}
                </button>
              </div>
            </div>
          `
        : nothing}
      <div class="settings-row settings-row--actions">
        <div class="settings-row__control memory-sharing__actions">
          ${pendingPurge
            ? html`
                <button
                  type="button"
                  class="btn btn--sm btn--danger"
                  ?disabled=${this.busyOperation !== null}
                  @click=${() => void this.purgePostbox(item.postboxItemId)}
                >
                  ${t("memoryPage.sharing.postbox.confirmPurge")}
                </button>
                <button
                  type="button"
                  class="btn btn--sm"
                  ?disabled=${this.busyOperation !== null}
                  @click=${() => (this.purgeCandidateId = null)}
                >
                  ${t("common.cancel")}
                </button>
              `
            : html`<button
                type="button"
                class="btn btn--sm btn--danger"
                ?disabled=${this.busyOperation !== null}
                @click=${() => (this.purgeCandidateId = item.postboxItemId)}
              >
                ${t("memoryPage.sharing.postbox.purge")}
              </button>`}
        </div>
      </div>
    `;
  }

  private renderPostbox() {
    const items = this.loadState.kind === "ready" ? this.loadState.status.postboxItems : [];
    return renderSettingsSection(
      {
        title: t("memoryPage.sharing.postbox.title"),
        description: t("memoryPage.sharing.postbox.description"),
        count: items.length,
      },
      items.length === 0
        ? renderSettingsRow({ title: t("memoryPage.sharing.postbox.empty") })
        : items.map(
            (item) => html`
              <article class="memory-sharing__item">
                ${renderSettingsRow({
                  title: item.provenanceLabel || t("memoryPage.sharing.postbox.unknownProvenance"),
                  description: t("memoryPage.sharing.postbox.provenanceOnly"),
                  control: renderSettingsStatus({
                    kind: statusKind(item.reviewState),
                    label: reviewStateLabel(item.reviewState),
                  }),
                })}
                ${renderSettingsRow({
                  title: t("memoryPage.sharing.postbox.redactedPreview"),
                  description: html`<span class="memory-sharing__redacted-preview"
                    >${item.contentPreview}</span
                  >`,
                })}
                ${renderSettingsRow({
                  title: t("memoryPage.sharing.postbox.expires"),
                  control: renderSettingsValue(formatTimestamp(item.expiresAt)),
                })}
                ${this.renderPostboxActions(item)}
              </article>
            `,
          ),
    );
  }

  override render() {
    // Loss of sharing write access redacts the whole surface immediately,
    // including rows fetched before the Gateway sent the new authorization.
    if (!this.canUse()) {
      return nothing;
    }
    return html`
      <section class="settings-page memory-sharing" aria-label=${t("memoryPage.sharing.title")}>
        <h2 class="memory-sharing__title">${t("memoryPage.sharing.title")}</h2>
        <p class="settings-page__intro">${t("memoryPage.sharing.intro")}</p>
        ${this.renderStatus()} ${this.renderProjectionForm()} ${this.renderPreview()}
        ${this.operationError
          ? html`<p class="memory-sharing__error" role="alert">${this.operationError}</p>`
          : nothing}
        ${this.renderProjections()} ${this.renderPostbox()}
      </section>
    `;
  }
}

if (!customElements.get("openclaw-memory-sharing")) {
  customElements.define("openclaw-memory-sharing", MemorySharingElement);
}
