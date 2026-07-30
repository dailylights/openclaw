import type { MemoryPluginRuntime } from "openclaw/plugin-sdk/memory-core-host-runtime-core";

/** Builtin scoped memory implements the complete Phase 2A authorization surface. */
export const MEMORY_CORE_AUTHORIZATION_CAPABILITIES = Object.freeze({
  version: 1,
  scopedCandidates: true,
  exactReadByAuthorizedHandle: true,
  scopedSync: true,
  scopedWrite: true,
  scopedImport: true,
  scopedExport: true,
  scopedStatus: true,
  exposureReceipts: true,
  egressReceipts: true,
}) satisfies NonNullable<MemoryPluginRuntime["authorization"]>;

export { builtinScopedMemoryConformanceAdapter } from "./memory/scoped-memory-policy.js";
