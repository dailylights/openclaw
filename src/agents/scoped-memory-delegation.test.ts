import { beforeEach, describe, expect, it, vi } from "vitest";

const hoisted = vi.hoisted(() => ({
  isMemoryIsolationCutoverAgent: vi.fn(),
}));

vi.mock("../plugins/memory-cutover.js", () => ({
  isMemoryIsolationCutoverAgent: hoisted.isMemoryIsolationCutoverAgent,
}));

import {
  resolveScopedMemoryDelegationDenial,
  SCOPED_MEMORY_DELEGATION_UNAVAILABLE_REASON,
} from "./scoped-memory-delegation.js";

describe("resolveScopedMemoryDelegationDenial", () => {
  beforeEach(() => {
    hoisted.isMemoryIsolationCutoverAgent.mockReset().mockReturnValue(false);
  });

  it("keeps legacy-to-legacy delegation available", () => {
    expect(
      resolveScopedMemoryDelegationDenial({
        requesterAgentId: "main",
        targetAgentId: "reviewer",
      }),
    ).toBeUndefined();
  });

  it.each(["main", "reviewer"])(
    "denies when the %s endpoint is at scoped-memory cutover",
    (cutoverAgentId) => {
      hoisted.isMemoryIsolationCutoverAgent.mockImplementation(
        (agentId: string) => agentId === cutoverAgentId,
      );

      expect(
        resolveScopedMemoryDelegationDenial({
          requesterAgentId: "main",
          targetAgentId: "reviewer",
        }),
      ).toBe(SCOPED_MEMORY_DELEGATION_UNAVAILABLE_REASON);
    },
  );

  it("does not check one endpoint twice for same-agent delegation", () => {
    resolveScopedMemoryDelegationDenial({ requesterAgentId: "main", targetAgentId: "main" });

    expect(hoisted.isMemoryIsolationCutoverAgent).toHaveBeenCalledTimes(1);
  });
});
