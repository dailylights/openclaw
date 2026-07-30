import { AsyncLocalStorage } from "node:async_hooks";

const memoryInvocationTokenBrand: unique symbol = Symbol("openclaw.memory-invocation-token");

export type MemoryInvocationToken = Readonly<{
  version: 1;
  [memoryInvocationTokenBrand]: true;
}>;

type MemoryInvocationTokenState = "created" | "active" | "revoked";

const tokenStates = new WeakMap<object, MemoryInvocationTokenState>();
const activeMemoryInvocation = new AsyncLocalStorage<MemoryInvocationToken>();

export function createMemoryInvocationToken(): MemoryInvocationToken {
  const token = Object.freeze({
    version: 1 as const,
    [memoryInvocationTokenBrand]: true as const,
  });
  tokenStates.set(token, "created");
  return token;
}

function isAuthenticMemoryInvocationToken(value: unknown): value is MemoryInvocationToken {
  return (
    typeof value === "object" &&
    value !== null &&
    tokenStates.has(value) &&
    (value as Record<symbol, unknown>)[memoryInvocationTokenBrand] === true &&
    Object.isFrozen(value)
  );
}

/** Any supplied token means the caller selected enforced mode, even if the token is malformed. */
export function isMemoryInvocationEnforced(token?: unknown): boolean {
  return token !== undefined || activeMemoryInvocation.getStore() !== undefined;
}

export function isActiveMemoryInvocationToken(token: unknown): token is MemoryInvocationToken {
  return (
    isAuthenticMemoryInvocationToken(token) &&
    tokenStates.get(token) === "active" &&
    activeMemoryInvocation.getStore() === token
  );
}

export function getCurrentMemoryInvocationToken(): MemoryInvocationToken | undefined {
  return activeMemoryInvocation.getStore();
}

/** Binds one authentic token once and revokes it after the complete async run. */
export async function withMemoryInvocationToken<T>(
  token: MemoryInvocationToken | undefined,
  run: () => Promise<T>,
): Promise<T> {
  if (token === undefined) {
    return await run();
  }
  if (
    activeMemoryInvocation.getStore() !== undefined ||
    !isAuthenticMemoryInvocationToken(token) ||
    tokenStates.get(token) !== "created"
  ) {
    throw new Error("memory invocation is unavailable");
  }
  tokenStates.set(token, "active");
  try {
    return await activeMemoryInvocation.run(token, run);
  } finally {
    // Async descendants can retain the ALS value, so every operation also checks this state.
    tokenStates.set(token, "revoked");
  }
}

const memoryInvocationTokenTesting = {
  readState(token: unknown): MemoryInvocationTokenState | undefined {
    return isAuthenticMemoryInvocationToken(token) ? tokenStates.get(token) : undefined;
  },
};

if (process.env.VITEST || process.env.NODE_ENV === "test") {
  (globalThis as Record<PropertyKey, unknown>)[
    Symbol.for("openclaw.memoryInvocationTokenTestApi")
  ] = memoryInvocationTokenTesting;
}
