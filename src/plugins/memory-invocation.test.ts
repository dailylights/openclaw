import { describe, expect, it } from "vitest";
import type { AuthorizedResourceHandle } from "../memory-host-sdk/host/authorization.js";
import { memoryInvocationTesting } from "./memory-invocation.test-support.js";

function createHandle(handleId: string, resourceRevision: string): AuthorizedResourceHandle {
  return {
    version: 1,
    handleId,
    planId: "plan-1",
    contextFingerprint: "context-1",
    resourceRevision,
    policyRevision: "policy-1",
    expiresAt: "2099-01-01T00:00:00.000Z",
  };
}

describe("memory invocation display handles", () => {
  it("resolves one immutable revision and fails closed for an ambiguous display path", () => {
    const registry = memoryInvocationTesting.createDisplayHandleRegistry();
    const first = createHandle("handle-1", "revision-1");
    const second = createHandle("handle-2", "revision-2");

    memoryInvocationTesting.rememberDisplayHandle(registry, "MEMORY.md", first);
    expect(memoryInvocationTesting.resolveUniqueDisplayHandle(registry, "MEMORY.md")).toBe(first);

    memoryInvocationTesting.rememberDisplayHandle(registry, "MEMORY.md", second);
    expect(
      memoryInvocationTesting.resolveUniqueDisplayHandle(registry, "MEMORY.md"),
    ).toBeUndefined();
    expect(
      memoryInvocationTesting.resolveUniqueDisplayHandle(registry, "unknown.md"),
    ).toBeUndefined();
  });
});
