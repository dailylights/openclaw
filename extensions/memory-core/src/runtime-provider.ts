// Memory Core provider module implements model/runtime integration.
import {
  isMemoryIsolationCutoverAgent,
  type MemoryPluginRuntime,
} from "openclaw/plugin-sdk/memory-core-host-runtime-core";
import { resolveMemoryBackendConfig } from "openclaw/plugin-sdk/memory-core-host-runtime-files";
import { configureMemoryCoreDreamingState } from "./dreaming-state.js";
import {
  builtinScopedMemoryConformanceAdapter,
  MEMORY_CORE_AUTHORIZATION_CAPABILITIES,
} from "./authorization.js";
import {
  closeAllMemorySearchManagers,
  closeMemorySearchManager,
  getMemorySearchManager,
} from "./memory/index.js";
import type { MemoryCoreRuntimeHost } from "./memory/runtime-host.js";
import { createBuiltinScopedMemoryRuntime } from "./memory/scoped-memory-runtime.js";

export function createMemoryRuntime(host: MemoryCoreRuntimeHost = {}): MemoryPluginRuntime {
  if (host.openKeyedStore) {
    configureMemoryCoreDreamingState(host.openKeyedStore);
  }

  const authorizedRuntime = createBuiltinScopedMemoryRuntime();
  return {
    authorization: MEMORY_CORE_AUTHORIZATION_CAPABILITIES,
    authorizationConformance: builtinScopedMemoryConformanceAdapter,
    authorize: authorizedRuntime.authorize,
    searchAuthorized: authorizedRuntime.searchAuthorized,
    readAuthorized: authorizedRuntime.readAuthorized,
    writeAuthorized: authorizedRuntime.writeAuthorized,
    importAuthorized: authorizedRuntime.importAuthorized,
    syncAuthorized: authorizedRuntime.syncAuthorized,
    exportAuthorized: authorizedRuntime.exportAuthorized,
    statusAuthorized: authorizedRuntime.statusAuthorized,
    async getMemorySearchManager(params) {
      if (isMemoryIsolationCutoverAgent(params.agentId)) {
        return { manager: null, error: "memory unavailable" };
      }
      const { manager, debug, error } = await getMemorySearchManager({
        ...params,
        ...(host.acquireLocalService ? { acquireLocalService: host.acquireLocalService } : {}),
        ...(host.withLease ? { withLease: host.withLease } : {}),
      });
      return {
        manager,
        debug,
        error,
      };
    },
    resolveMemoryBackendConfig(params) {
      return resolveMemoryBackendConfig(params);
    },
    async authorizeSearchHits(params) {
      const { filterMemorySearchHitsBySessionVisibility } =
        await import("./session-search-visibility.js");
      return await filterMemorySearchHitsBySessionVisibility(params);
    },
    async closeAllMemorySearchManagers() {
      await closeAllMemorySearchManagers();
    },
    async closeMemorySearchManager(params) {
      await closeMemorySearchManager(params);
    },
  };
}

export const memoryRuntime = createMemoryRuntime();
