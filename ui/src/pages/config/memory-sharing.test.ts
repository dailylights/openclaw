/* @vitest-environment jsdom */

import { describe, expect, it, vi } from "vitest";
import type { GatewayBrowserClient } from "../../api/gateway.ts";
import { waitForFast } from "../../test-helpers/wait-for.ts";
import { hasMemorySharingGatewayMethods } from "./memory-sharing-protocol.ts";
import "./memory-sharing.ts";

type Request = (method: string, params: Record<string, unknown>) => Promise<unknown>;

type MemorySharingElement = HTMLElement & {
  client: GatewayBrowserClient | null;
  connected: boolean;
  canWrite: boolean;
  methodsAvailable: boolean;
  agentId: string | null;
  updateComplete: Promise<unknown>;
};

const allMethods = [
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
];

function projection(overrides: Record<string, unknown> = {}) {
  return {
    projectionId: "projection-1",
    sourceRevisionId: "revision-source-1",
    targetKind: "conversation",
    targetAudienceId: "conversation-1",
    purpose: "Keep the rollout decision available in this conversation.",
    preview: "[redacted preview] rollout decision",
    reviewState: "pending",
    expiresAt: "2030-01-02T03:04:00.000Z",
    createdAt: "2030-01-01T03:04:00.000Z",
    sourceContent: "never render source content",
    ...overrides,
  };
}

function postboxItem(overrides: Record<string, unknown> = {}) {
  return {
    postboxItemId: "postbox-1",
    sourceConversationId: "conversation-source-1",
    provenanceLabel: "Verified channel deposit",
    contentPreview: "[redacted preview] proposed follow-up",
    reviewState: "pending",
    expiresAt: "2030-01-02T03:04:00.000Z",
    createdAt: "2030-01-01T03:04:00.000Z",
    content: "never render deposited source content",
    ...overrides,
  };
}

function sharingStatus() {
  return {
    postboxMode: "review-required",
    projections: [projection()],
    postboxItems: [postboxItem()],
  };
}

function createElement(request: Request, overrides: Partial<MemorySharingElement> = {}) {
  const element = document.createElement("openclaw-memory-sharing") as MemorySharingElement;
  element.client = { request } as unknown as GatewayBrowserClient;
  element.connected = true;
  element.canWrite = true;
  element.methodsAvailable = true;
  element.agentId = "main";
  Object.assign(element, overrides);
  document.body.append(element);
  return element;
}

function button(container: ParentNode, label: string): HTMLButtonElement {
  const match = [...container.querySelectorAll<HTMLButtonElement>("button")].find(
    (candidate) => candidate.textContent?.replace(/\s+/g, " ").trim() === label,
  );
  if (!match) {
    throw new Error(`Missing button: ${label}`);
  }
  return match;
}

function input(element: HTMLElement, id: string): HTMLInputElement {
  const field = element.querySelector<HTMLInputElement>(`#${id}`);
  if (!field) {
    throw new Error(`Missing input: ${id}`);
  }
  return field;
}

function setInput(element: HTMLElement, id: string, value: string) {
  const field = input(element, id);
  field.value = value;
  field.dispatchEvent(new InputEvent("input", { bubbles: true }));
}

function reviewRows(element: HTMLElement): [HTMLElement, HTMLElement] {
  const [projectionRow, postboxRow] =
    element.querySelectorAll<HTMLElement>(".memory-sharing__item");
  if (!projectionRow || !postboxRow) {
    throw new Error("Missing redacted review rows");
  }
  return [projectionRow, postboxRow];
}

describe("MemorySharingElement", () => {
  it("requires every advertised review method and Gateway write access before it renders", async () => {
    expect(hasMemorySharingGatewayMethods({ hello: { features: { methods: allMethods } } })).toBe(
      true,
    );
    expect(
      hasMemorySharingGatewayMethods({ hello: { features: { methods: allMethods.slice(1) } } }),
    ).toBe(false);

    const request = vi.fn<Request>(() => Promise.resolve(sharingStatus()));
    const element = createElement(request, { canWrite: false });
    try {
      await element.updateComplete;
      expect(element.textContent).toBe("");
      expect(request).not.toHaveBeenCalled();

      element.canWrite = true;
      element.methodsAvailable = false;
      await element.updateComplete;
      expect(element.textContent).toBe("");
      expect(request).not.toHaveBeenCalled();
    } finally {
      element.remove();
    }
  });

  it("uses one approved target shape, a future expiry, and separate pending-review creation", async () => {
    const request = vi.fn<Request>((method) => {
      if (method === "memory.sharing.status") {
        return Promise.resolve(sharingStatus());
      }
      if (method === "memory.sharing.postbox.list") {
        return Promise.resolve({ postboxItems: [postboxItem()] });
      }
      if (method === "memory.sharing.projection.preview") {
        return Promise.resolve({ ...projection(), previewId: "preview-1" });
      }
      return Promise.resolve({});
    });
    const element = createElement(request);
    try {
      await waitForFast(() => expect(element.textContent).toContain("Reviewed projections"));
      expect(element.textContent).toContain("[redacted preview] rollout decision");
      expect(element.textContent).toContain("[redacted preview] proposed follow-up");
      expect(element.textContent).not.toContain("never render source content");
      expect(element.textContent).not.toContain("never render deposited source content");

      const targets = [
        ...element.querySelectorAll<HTMLSelectElement>("#memory-sharing-target-kind option"),
      ]
        .map((option) => option.value)
        .toSorted();
      expect(targets).toEqual(["agent-shared", "conversation", "role"]);
      const targetKind = element.querySelector<HTMLSelectElement>("#memory-sharing-target-kind");
      if (!targetKind) {
        throw new Error("Missing target kind field");
      }
      targetKind.value = "agent-shared";
      targetKind.dispatchEvent(new Event("change", { bubbles: true }));
      await element.updateComplete;
      expect(input(element, "memory-sharing-target-id").value).toBe("main");
      expect(input(element, "memory-sharing-target-id").disabled).toBe(true);
      targetKind.value = "conversation";
      targetKind.dispatchEvent(new Event("change", { bubbles: true }));
      await element.updateComplete;

      setInput(element, "memory-sharing-source-revision", "revision-source-2");
      setInput(element, "memory-sharing-target-id", "conversation-2");
      const purpose = element.querySelector<HTMLTextAreaElement>("#memory-sharing-purpose");
      if (!purpose) {
        throw new Error("Missing purpose field");
      }
      purpose.value = "Share a reviewed rollout decision";
      purpose.dispatchEvent(new InputEvent("input", { bubbles: true }));
      setInput(element, "memory-sharing-expiry", "2020-01-02T03:04");
      await element.updateComplete;

      button(element, "Preview for review").click();
      await element.updateComplete;
      expect(
        request.mock.calls.filter(([method]) => method === "memory.sharing.projection.preview"),
      ).toHaveLength(0);
      expect(element.textContent).toContain("future expiry");

      setInput(element, "memory-sharing-expiry", "2030-01-02T03:04");
      button(element, "Preview for review").click();
      await waitForFast(() => expect(element.textContent).toContain("Create pending review"));
      expect(request).toHaveBeenCalledWith("memory.sharing.projection.preview", {
        agentId: "main",
        sourceRevisionId: "revision-source-2",
        targetKind: "conversation",
        targetId: "conversation-2",
        purpose: "Share a reviewed rollout decision",
        expiresAt: new Date("2030-01-02T03:04").toISOString(),
      });

      button(element, "Create pending review").click();
      await waitForFast(() =>
        expect(request).toHaveBeenCalledWith("memory.sharing.projection.create", {
          agentId: "main",
          previewId: "preview-1",
        }),
      );
      expect(element.textContent).toContain("Pending review");
    } finally {
      element.remove();
    }
  });

  it("sends review, refresh, impact, postbox review, and purge through the redacted RPC surface", async () => {
    let projectionReviewState = "pending";
    let postboxReviewState = "pending";
    const request = vi.fn<Request>((method, params) => {
      if (method === "memory.sharing.status") {
        return Promise.resolve({
          postboxMode: "review-required",
          projections: [projection({ reviewState: projectionReviewState })],
          postboxItems: [postboxItem({ reviewState: postboxReviewState })],
        });
      }
      if (method === "memory.sharing.postbox.list") {
        return Promise.resolve({
          postboxItems: [postboxItem({ reviewState: postboxReviewState })],
        });
      }
      if (method === "memory.sharing.projection.preview") {
        return Promise.resolve({ ...projection(), previewId: "refresh-preview-1" });
      }
      if (method === "memory.sharing.projection.impact") {
        return Promise.resolve({
          priorExposureCount: 2,
          rawReceipt: "never render receipt details",
        });
      }
      if (method === "memory.sharing.projection.review" && params?.decision === "approve") {
        projectionReviewState = "approved";
      }
      if (method === "memory.sharing.postbox.review" && params?.decision === "approve") {
        postboxReviewState = "approved";
      }
      if (method === "memory.sharing.postbox.purge") {
        postboxReviewState = "purged";
      }
      if (method === "memory.sharing.projection.revoke") {
        projectionReviewState = "revoked";
      }
      return Promise.resolve({});
    });
    const element = createElement(request);
    try {
      await waitForFast(() =>
        expect(element.querySelectorAll(".memory-sharing__item")).toHaveLength(2),
      );
      let [projectionRow] = reviewRows(element);

      button(projectionRow, "Approve").click();
      await waitForFast(() =>
        expect(request).toHaveBeenCalledWith("memory.sharing.projection.review", {
          agentId: "main",
          projectionId: "projection-1",
          decision: "approve",
        }),
      );
      await waitForFast(() =>
        expect(
          request.mock.calls.filter(([method]) => method === "memory.sharing.postbox.list").length,
        ).toBeGreaterThanOrEqual(2),
      );
      [projectionRow] = reviewRows(element);

      button(projectionRow, "Prior exposure impact").click();
      await waitForFast(() =>
        expect(element.textContent).toContain("Prior redacted exposure receipts: 2"),
      );
      expect(element.textContent).not.toContain("never render receipt details");

      [projectionRow] = reviewRows(element);
      button(projectionRow, "Refresh").click();
      await element.updateComplete;
      button(element, "Preview for review").click();
      await waitForFast(() =>
        expect(request).toHaveBeenCalledWith("memory.sharing.projection.preview", {
          agentId: "main",
          sourceRevisionId: "revision-source-1",
          targetKind: "conversation",
          targetId: "conversation-1",
          purpose: "Keep the rollout decision available in this conversation.",
          expiresAt: "2030-01-02T03:04:00.000Z",
          supersedesProjectionId: "projection-1",
        }),
      );
      await waitForFast(() => expect(element.textContent).toContain("Refresh for review"));
      button(element, "Refresh for review").click();
      await waitForFast(() =>
        expect(request).toHaveBeenCalledWith("memory.sharing.projection.refresh", {
          agentId: "main",
          previewId: "refresh-preview-1",
        }),
      );
      await waitForFast(() =>
        expect(
          request.mock.calls.filter(([method]) => method === "memory.sharing.postbox.list").length,
        ).toBeGreaterThanOrEqual(3),
      );

      let [, postboxRow] = reviewRows(element);
      button(postboxRow, "Approve").click();
      await waitForFast(() =>
        expect(request).toHaveBeenCalledWith("memory.sharing.postbox.review", {
          agentId: "main",
          postboxItemId: "postbox-1",
          decision: "approve",
        }),
      );
      await waitForFast(() =>
        expect(
          request.mock.calls.filter(([method]) => method === "memory.sharing.postbox.list").length,
        ).toBeGreaterThanOrEqual(4),
      );

      [, postboxRow] = reviewRows(element);
      button(postboxRow, "Purge").click();
      await element.updateComplete;
      button(postboxRow, "Confirm purge").click();
      await waitForFast(() =>
        expect(request).toHaveBeenCalledWith("memory.sharing.postbox.purge", {
          agentId: "main",
          postboxItemId: "postbox-1",
        }),
      );
      await waitForFast(() =>
        expect(
          request.mock.calls.filter(([method]) => method === "memory.sharing.postbox.list").length,
        ).toBeGreaterThanOrEqual(5),
      );

      [projectionRow] = reviewRows(element);
      button(projectionRow, "Revoke").click();
      await element.updateComplete;
      button(reviewRows(element)[0], "Confirm revoke").click();
      await waitForFast(() =>
        expect(request).toHaveBeenCalledWith("memory.sharing.projection.revoke", {
          agentId: "main",
          projectionId: "projection-1",
        }),
      );
    } finally {
      element.remove();
    }
  });

  it("offers refresh and revoke only for approved projections", async () => {
    for (const reviewState of ["pending", "rejected", "revoked"] as const) {
      const request = vi.fn<Request>((method) => {
        if (method === "memory.sharing.status") {
          return Promise.resolve({
            postboxMode: "off",
            projections: [projection({ reviewState })],
            postboxItems: [],
          });
        }
        if (method === "memory.sharing.postbox.list") {
          return Promise.resolve({ postboxItems: [] });
        }
        return Promise.resolve({});
      });
      const element = createElement(request);
      try {
        await waitForFast(() =>
          expect(element.querySelectorAll(".memory-sharing__item")).toHaveLength(1),
        );
        const projectionRow = element.querySelector<HTMLElement>(".memory-sharing__item");
        if (!projectionRow) {
          throw new Error("Missing projection row");
        }
        const labels = [...projectionRow.querySelectorAll<HTMLButtonElement>("button")].map(
          (candidate) => candidate.textContent?.replace(/\s+/g, " ").trim(),
        );
        expect(labels).not.toContain("Refresh");
        expect(labels).not.toContain("Revoke");
      } finally {
        element.remove();
      }
    }
  });

  it("inspects postbox content only after an explicit owner review action and removes it on hide", async () => {
    const reviewContent = "owner-only postbox content";
    const request = vi.fn<Request>((method) => {
      if (method === "memory.sharing.status") {
        return Promise.resolve(sharingStatus());
      }
      if (method === "memory.sharing.postbox.list") {
        return Promise.resolve({ postboxItems: [postboxItem()] });
      }
      if (method === "memory.sharing.postbox.inspect") {
        return Promise.resolve({
          postboxItemId: "postbox-1",
          reviewContent,
          expiresAt: "2030-01-02T03:04:00.000Z",
          unexpectedSourceMetadata: "do not render",
        });
      }
      return Promise.resolve({});
    });
    const element = createElement(request);
    try {
      await waitForFast(() =>
        expect(element.querySelectorAll(".memory-sharing__item")).toHaveLength(2),
      );
      expect(request).not.toHaveBeenCalledWith("memory.sharing.postbox.inspect", expect.anything());
      expect(element.querySelector("#memory-sharing-postbox-inspection-postbox-1")).toBeNull();

      button(reviewRows(element)[1], "Inspect pending content").click();
      await waitForFast(() =>
        expect(request).toHaveBeenCalledWith("memory.sharing.postbox.inspect", {
          agentId: "main",
          postboxItemId: "postbox-1",
        }),
      );
      await waitForFast(() => {
        const inspection = element.querySelector<HTMLTextAreaElement>(
          "#memory-sharing-postbox-inspection-postbox-1",
        );
        expect(inspection?.value).toBe(reviewContent);
      });
      expect(element.textContent).not.toContain("do not render");
      expect(JSON.stringify(request.mock.calls)).not.toContain(reviewContent);

      button(reviewRows(element)[1], "Hide content").click();
      await element.updateComplete;
      expect(element.querySelector("#memory-sharing-postbox-inspection-postbox-1")).toBeNull();
    } finally {
      element.remove();
    }
  });

  it("requires owner-entered rejection reasons and does not request postbox content without inspection", async () => {
    const request = vi.fn<Request>((method) => {
      if (method === "memory.sharing.status") {
        return Promise.resolve(sharingStatus());
      }
      if (method === "memory.sharing.postbox.list") {
        return Promise.resolve({ postboxItems: [postboxItem()] });
      }
      return Promise.resolve({});
    });
    const element = createElement(request);
    try {
      await waitForFast(() =>
        expect(element.querySelectorAll(".memory-sharing__item")).toHaveLength(2),
      );
      let [projectionRow, postboxRow] = reviewRows(element);
      const projectionReject = button(projectionRow, "Reject");
      const postboxReject = button(postboxRow, "Reject");
      expect(projectionReject.disabled).toBe(true);
      expect(postboxReject.disabled).toBe(true);

      setInput(
        element,
        "memory-sharing-projection-reason-projection-1",
        "Audience is no longer eligible.",
      );
      await element.updateComplete;
      expect(button(reviewRows(element)[0], "Reject").disabled).toBe(false);
      button(reviewRows(element)[0], "Reject").click();
      await waitForFast(() =>
        expect(request).toHaveBeenCalledWith("memory.sharing.projection.review", {
          agentId: "main",
          projectionId: "projection-1",
          decision: "reject",
          reason: "Audience is no longer eligible.",
        }),
      );

      [projectionRow, postboxRow] = reviewRows(element);
      expect(projectionRow.textContent).not.toContain("never render source content");
      setInput(
        element,
        "memory-sharing-postbox-reason-postbox-1",
        "The quarantined item is not relevant.",
      );
      await element.updateComplete;
      expect(button(reviewRows(element)[1], "Reject").disabled).toBe(false);
      button(reviewRows(element)[1], "Reject").click();
      await waitForFast(() =>
        expect(request).toHaveBeenCalledWith("memory.sharing.postbox.review", {
          agentId: "main",
          postboxItemId: "postbox-1",
          decision: "reject",
          reason: "The quarantined item is not relevant.",
        }),
      );
      expect(postboxRow.textContent).not.toContain("never render deposited source content");
      expect(JSON.stringify(request.mock.calls)).not.toContain(
        "never render deposited source content",
      );
    } finally {
      element.remove();
    }
  });
});
