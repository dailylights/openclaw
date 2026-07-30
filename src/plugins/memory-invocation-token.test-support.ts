import "./memory-invocation-token.js";

type MemoryInvocationTokenTesting = {
  readState(token: unknown): "created" | "active" | "revoked" | undefined;
};

function getTesting(): MemoryInvocationTokenTesting {
  return (globalThis as Record<PropertyKey, unknown>)[
    Symbol.for("openclaw.memoryInvocationTokenTestApi")
  ] as MemoryInvocationTokenTesting;
}

export const memoryInvocationTokenTesting: MemoryInvocationTokenTesting = {
  readState: (token) => getTesting().readState(token),
};
