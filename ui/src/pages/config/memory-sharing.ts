import { nothing, type PropertyValues } from "lit";
import { property, state } from "lit/decorators.js";
import type { GatewayBrowserClient } from "../../api/gateway.ts";
import { t } from "../../i18n/index.ts";
import { OpenClawLightDomElement } from "../../lit/openclaw-element.ts";
import "../../styles/memory-sharing.css";
import {
  asTargetKind,
  emptyProjectionForm,
  futureIso,
  localDateTimeValue,
  parseImpact,
  parsePostboxInspection,
  parsePostboxItems,
  parseProjectionPreview,
  parseSharingStatus,
  type PostboxInspection,
  type PostboxReviewDecision,
  type Projection,
  type ProjectionForm,
  type ProjectionImpact,
  type ProjectionPreview,
  type ProjectionReviewDecision,
  type SharingLoadState,
} from "./memory-sharing-protocol.ts";
import { renderMemorySharing } from "./memory-sharing-view.ts";

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
        request.client.request("memory.sharing.status", { agentId: request.agentId }),
        request.client.request("memory.sharing.postbox.list", {
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

  private async request(method: string, payload: Record<string, unknown>): Promise<unknown> {
    if (!this.canUse() || this.busyOperation) {
      return null;
    }
    const request = { client: this.client, agentId: this.agentId };
    this.busyOperation = method;
    this.operationError = null;
    try {
      const response = await request.client.request(method, payload);
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
    targetKind: ProjectionForm["targetKind"];
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

  override render() {
    // Loss of sharing write access redacts the whole surface immediately,
    // including rows fetched before the Gateway sent the new authorization.
    if (!this.canUse()) {
      return nothing;
    }
    return renderMemorySharing({
      agentId: this.agentId,
      loadState: this.loadState,
      form: this.form,
      preview: this.preview,
      busyOperation: this.busyOperation,
      operationError: this.operationError,
      impacts: this.impacts,
      postboxEdits: this.postboxEdits,
      postboxInspections: this.postboxInspections,
      projectionRejectReasons: this.projectionRejectReasons,
      postboxRejectReasons: this.postboxRejectReasons,
      revokeCandidateId: this.revokeCandidateId,
      purgeCandidateId: this.purgeCandidateId,
      load: () => this.load(),
      updateForm: <K extends keyof ProjectionForm>(key: K, value: ProjectionForm[K]) =>
        this.updateForm(key, value),
      updateTargetKind: (value) => this.updateTargetKind(value),
      requestPreview: () => this.requestPreview(),
      finalizePreview: () => this.finalizePreview(),
      updateProjectionRejectReason: (projectionId, reason) =>
        this.updateProjectionRejectReason(projectionId, reason),
      reviewProjection: (projectionId, decision) => this.reviewProjection(projectionId, decision),
      prepareRefresh: (projection) => this.prepareRefresh(projection),
      cancelRefresh: () => this.cancelRefresh(),
      revokeProjection: (projectionId) => this.revokeProjection(projectionId),
      loadImpact: (projectionId) => this.loadImpact(projectionId),
      setRevokeCandidate: (projectionId) => {
        this.revokeCandidateId = projectionId;
      },
      updatePostboxEdit: (postboxItemId, editedContent) =>
        this.updatePostboxEdit(postboxItemId, editedContent),
      updatePostboxRejectReason: (postboxItemId, reason) =>
        this.updatePostboxRejectReason(postboxItemId, reason),
      clearPostboxInspection: (postboxItemId) => this.clearPostboxInspection(postboxItemId),
      inspectPostbox: (postboxItemId) => this.inspectPostbox(postboxItemId),
      reviewPostbox: (postboxItemId, decision) => this.reviewPostbox(postboxItemId, decision),
      purgePostbox: (postboxItemId) => this.purgePostbox(postboxItemId),
      setPurgeCandidate: (postboxItemId) => {
        this.purgeCandidateId = postboxItemId;
      },
    });
  }
}

if (!customElements.get("openclaw-memory-sharing")) {
  customElements.define("openclaw-memory-sharing", MemorySharingElement);
}
