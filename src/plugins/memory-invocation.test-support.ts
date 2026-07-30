import type { AuthorizedResourceHandle } from "../memory-host-sdk/host/authorization.js";
import type { MemoryInvocationToken } from "./memory-invocation-token.js";
import "./memory-invocation.js";

type MemoryInvocationTesting = {
  createDisplayHandleRegistry(): Map<string, Map<string, AuthorizedResourceHandle>>;
  getState(token: MemoryInvocationToken): unknown;
  rememberDisplayHandle(
    registry: Map<string, Map<string, AuthorizedResourceHandle>>,
    path: string,
    handle: AuthorizedResourceHandle,
  ): void;
  resolveUniqueDisplayHandle(
    registry: Map<string, Map<string, AuthorizedResourceHandle>>,
    path: string,
  ): AuthorizedResourceHandle | undefined;
};

function getTesting(): MemoryInvocationTesting {
  return (globalThis as Record<PropertyKey, unknown>)[
    Symbol.for("openclaw.memoryInvocationTestApi")
  ] as MemoryInvocationTesting;
}

export const memoryInvocationTesting: MemoryInvocationTesting = {
  createDisplayHandleRegistry: () => getTesting().createDisplayHandleRegistry(),
  getState: (token) => getTesting().getState(token),
  rememberDisplayHandle: (registry, path, handle) =>
    getTesting().rememberDisplayHandle(registry, path, handle),
  resolveUniqueDisplayHandle: (registry, path) =>
    getTesting().resolveUniqueDisplayHandle(registry, path),
};
