import type { MemoryPluginRuntime } from "openclaw/plugin-sdk/memory-core-host-runtime-core";

/** Phase 1B advertises only the authorized read surface that is implemented and admitted. */
export const MEMORY_CORE_AUTHORIZATION_CAPABILITIES = Object.freeze({
  version: 1,
  scopedCandidates: true,
  exactReadByAuthorizedHandle: true,
  scopedSync: false,
  scopedWrite: false,
  scopedImport: false,
  scopedExport: false,
  scopedStatus: false,
  exposureReceipts: true,
  egressReceipts: true,
}) satisfies NonNullable<MemoryPluginRuntime["authorization"]>;

export { builtinScopedMemoryConformanceAdapter } from "./memory/scoped-memory-policy.js";
