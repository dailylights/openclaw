import { html, nothing, type TemplateResult } from "lit";
import {
  renderSettingsRow,
  renderSettingsSection,
  renderSettingsStatus,
  renderSettingsValue,
} from "../../components/settings-ui.ts";
import { t } from "../../i18n/index.ts";
import {
  formatTimestamp,
  postboxModeLabel,
  reviewStateLabel,
  statusKind,
  TARGET_KINDS,
  targetLabel,
  type PostboxInspection,
  type PostboxItem,
  type PostboxReviewDecision,
  type Projection,
  type ProjectionForm,
  type ProjectionImpact,
  type ProjectionPreview,
  type ProjectionReviewDecision,
  type SharingLoadState,
} from "./memory-sharing-protocol.ts";

type MemorySharingView = {
  agentId: string | null;
  loadState: SharingLoadState;
  form: ProjectionForm;
  preview: ProjectionPreview | null;
  busyOperation: string | null;
  operationError: string | null;
  impacts: ReadonlyMap<string, ProjectionImpact>;
  postboxEdits: ReadonlyMap<string, string>;
  postboxInspections: ReadonlyMap<string, PostboxInspection>;
  projectionRejectReasons: ReadonlyMap<string, string>;
  postboxRejectReasons: ReadonlyMap<string, string>;
  revokeCandidateId: string | null;
  purgeCandidateId: string | null;
  load(): Promise<void>;
  updateForm(key: keyof ProjectionForm, value: string | null): void;
  updateTargetKind(value: string): void;
  requestPreview(): Promise<void>;
  finalizePreview(): Promise<void>;
  updateProjectionRejectReason(projectionId: string, reason: string): void;
  reviewProjection(projectionId: string, decision: ProjectionReviewDecision): Promise<void>;
  prepareRefresh(projection: Projection): void;
  cancelRefresh(): void;
  revokeProjection(projectionId: string): Promise<void>;
  loadImpact(projectionId: string): Promise<void>;
  setRevokeCandidate(projectionId: string | null): void;
  updatePostboxEdit(postboxItemId: string, editedContent: string): void;
  updatePostboxRejectReason(postboxItemId: string, reason: string): void;
  clearPostboxInspection(postboxItemId: string): void;
  inspectPostbox(postboxItemId: string): Promise<void>;
  reviewPostbox(postboxItemId: string, decision: PostboxReviewDecision): Promise<void>;
  purgePostbox(postboxItemId: string): Promise<void>;
  setPurgeCandidate(postboxItemId: string | null): void;
};

function renderStatus(view: MemorySharingView): TemplateResult {
  const loadState = view.loadState;
  const ready = loadState.kind === "ready" ? loadState.status : null;
  return renderSettingsSection(
    {
      title: t("memoryPage.sharing.status.title"),
      description: t("memoryPage.sharing.status.description"),
      actions: html`<button
        type="button"
        class="btn btn--sm"
        ?disabled=${view.busyOperation !== null || loadState.kind === "loading"}
        @click=${() => void view.load()}
      >
        ${t("memoryPage.sharing.refresh")}
      </button>`,
    },
    loadState.kind === "loading"
      ? renderSettingsRow({
          title: t("memoryPage.sharing.status.loading"),
          control: renderSettingsStatus({ kind: "muted", label: t("common.loading") }),
        })
      : loadState.kind === "error"
        ? renderSettingsRow({
            title: t("memoryPage.sharing.status.unavailable"),
            description: t("memoryPage.sharing.status.unavailableDescription"),
            control: renderSettingsStatus({ kind: "danger", label: t("common.failed") }),
          })
        : html`
            ${renderSettingsRow({
              title: t("memoryPage.sharing.status.agent"),
              control: renderSettingsValue(view.agentId ?? t("common.unknown"), { mono: true }),
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

function renderProjectionForm(view: MemorySharingView): TemplateResult {
  const refreshing = view.form.supersedesProjectionId !== null;
  const form = view.form;
  return renderSettingsSection(
    {
      title: refreshing
        ? t("memoryPage.sharing.projection.refreshTitle")
        : t("memoryPage.sharing.projection.createTitle"),
      description: refreshing
        ? t("memoryPage.sharing.projection.refreshDescription")
        : t("memoryPage.sharing.projection.createDescription"),
      actions: refreshing
        ? html`<button type="button" class="btn btn--sm" @click=${() => view.cancelRefresh()}>
            ${t("memoryPage.sharing.projection.cancelRefresh")}
          </button>`
        : undefined,
    },
    html`
      <form
        class="memory-sharing__form"
        @submit=${(event: SubmitEvent) => {
          event.preventDefault();
          void view.requestPreview();
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
              view.updateForm("sourceRevisionId", (event.target as HTMLInputElement).value)}
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
              view.updateTargetKind((event.target as HTMLSelectElement).value)}
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
              view.updateForm("targetId", (event.target as HTMLInputElement).value)}
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
              view.updateForm("purpose", (event.target as HTMLTextAreaElement).value)}
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
              view.updateForm("expiresAt", (event.target as HTMLInputElement).value)}
          />`,
        })}
        <div class="settings-row settings-row--actions">
          <div class="settings-row__control">
            <button type="submit" class="btn btn--sm" ?disabled=${view.busyOperation !== null}>
              ${t("memoryPage.sharing.projection.preview")}
            </button>
          </div>
        </div>
      </form>
    `,
  );
}

function renderPreview(view: MemorySharingView): TemplateResult | typeof nothing {
  const preview = view.preview;
  if (!preview) {
    return nothing;
  }
  const refreshing = view.form.supersedesProjectionId !== null;
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
            ?disabled=${view.busyOperation !== null}
            @click=${() => void view.finalizePreview()}
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

function renderProjectionActions(view: MemorySharingView, projection: Projection): TemplateResult {
  const pendingRevoke = view.revokeCandidateId === projection.projectionId;
  const impact = view.impacts.get(projection.projectionId);
  const rejectReason = view.projectionRejectReasons.get(projection.projectionId) ?? "";
  return html`
    <div class="memory-sharing__actions">
      ${projection.reviewState === "pending"
        ? html`
            <button
              type="button"
              class="btn btn--sm"
              ?disabled=${view.busyOperation !== null}
              @click=${() => void view.reviewProjection(projection.projectionId, "approve")}
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
                  view.updateProjectionRejectReason(
                    projection.projectionId,
                    (event.target as HTMLTextAreaElement).value,
                  )}
              ></textarea>
            </label>
            <button
              type="button"
              class="btn btn--sm"
              ?disabled=${view.busyOperation !== null || !rejectReason.trim()}
              @click=${() => void view.reviewProjection(projection.projectionId, "reject")}
            >
              ${t("memoryPage.sharing.review.reject")}
            </button>
          `
        : nothing}
      ${projection.reviewState === "approved"
        ? html`<button
            type="button"
            class="btn btn--sm"
            ?disabled=${view.busyOperation !== null}
            @click=${() => view.prepareRefresh(projection)}
          >
            ${t("memoryPage.sharing.projection.refresh")}
          </button>`
        : nothing}
      <button
        type="button"
        class="btn btn--sm"
        ?disabled=${view.busyOperation !== null}
        @click=${() => void view.loadImpact(projection.projectionId)}
      >
        ${t("memoryPage.sharing.projection.impact")}
      </button>
      ${projection.reviewState === "approved"
        ? pendingRevoke
          ? html`
              <button
                type="button"
                class="btn btn--sm btn--danger"
                ?disabled=${view.busyOperation !== null}
                @click=${() => void view.revokeProjection(projection.projectionId)}
              >
                ${t("memoryPage.sharing.projection.confirmRevoke")}
              </button>
              <button
                type="button"
                class="btn btn--sm"
                ?disabled=${view.busyOperation !== null}
                @click=${() => view.setRevokeCandidate(null)}
              >
                ${t("common.cancel")}
              </button>
            `
          : html`<button
              type="button"
              class="btn btn--sm btn--danger"
              ?disabled=${view.busyOperation !== null}
              @click=${() => view.setRevokeCandidate(projection.projectionId)}
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

function renderProjections(view: MemorySharingView): TemplateResult {
  const projections = view.loadState.kind === "ready" ? view.loadState.status.projections : [];
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
                  ${renderProjectionActions(view, projection)}
                </div>
              </div>
            </article>
          `,
        ),
  );
}

function renderPostboxActions(view: MemorySharingView, item: PostboxItem): TemplateResult {
  const pendingPurge = view.purgeCandidateId === item.postboxItemId;
  const editedContent = view.postboxEdits.get(item.postboxItemId) ?? "";
  const inspection = view.postboxInspections.get(item.postboxItemId);
  const rejectReason = view.postboxRejectReasons.get(item.postboxItemId) ?? "";
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
                ?disabled=${view.busyOperation !== null}
                @click=${() =>
                  inspection
                    ? view.clearPostboxInspection(item.postboxItemId)
                    : void view.inspectPostbox(item.postboxItemId)}
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
                view.updatePostboxEdit(
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
                ?disabled=${view.busyOperation !== null}
                @click=${() => void view.reviewPostbox(item.postboxItemId, "approve")}
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
                    view.updatePostboxRejectReason(
                      item.postboxItemId,
                      (event.target as HTMLTextAreaElement).value,
                    )}
                ></textarea>
              </label>
              <button
                type="button"
                class="btn btn--sm"
                ?disabled=${view.busyOperation !== null || !rejectReason.trim()}
                @click=${() => void view.reviewPostbox(item.postboxItemId, "reject")}
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
                ?disabled=${view.busyOperation !== null}
                @click=${() => void view.purgePostbox(item.postboxItemId)}
              >
                ${t("memoryPage.sharing.postbox.confirmPurge")}
              </button>
              <button
                type="button"
                class="btn btn--sm"
                ?disabled=${view.busyOperation !== null}
                @click=${() => view.setPurgeCandidate(null)}
              >
                ${t("common.cancel")}
              </button>
            `
          : html`<button
              type="button"
              class="btn btn--sm btn--danger"
              ?disabled=${view.busyOperation !== null}
              @click=${() => view.setPurgeCandidate(item.postboxItemId)}
            >
              ${t("memoryPage.sharing.postbox.purge")}
            </button>`}
      </div>
    </div>
  `;
}

function renderPostbox(view: MemorySharingView): TemplateResult {
  const items = view.loadState.kind === "ready" ? view.loadState.status.postboxItems : [];
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
              ${renderPostboxActions(view, item)}
            </article>
          `,
        ),
  );
}

export function renderMemorySharing(view: MemorySharingView): TemplateResult {
  return html`
    <section class="settings-page memory-sharing" aria-label=${t("memoryPage.sharing.title")}>
      <h2 class="memory-sharing__title">${t("memoryPage.sharing.title")}</h2>
      <p class="settings-page__intro">${t("memoryPage.sharing.intro")}</p>
      ${renderStatus(view)} ${renderProjectionForm(view)} ${renderPreview(view)}
      ${view.operationError
        ? html`<p class="memory-sharing__error" role="alert">${view.operationError}</p>`
        : nothing}
      ${renderProjections(view)} ${renderPostbox(view)}
    </section>
  `;
}
