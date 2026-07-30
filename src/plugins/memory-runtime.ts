// Runtime bridge for plugin-owned memory hooks and state.
import { resolveAgentWorkspaceDir } from "../agents/agent-scope.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import type { MemoryAccessContext } from "../memory-host-sdk/host/authorization.js";
import { resolveUserPath } from "../utils.js";
import { normalizePluginsConfig } from "./config-state.js";
import { loadPluginRegistryHandle, resolvePluginRegistryLoadCacheKey } from "./loader.js";
import {
  brandAuthorizedMemoryPlan,
  isTrustedMemoryAccessContext,
  MemoryAccessContextError,
} from "./memory-access-context.js";
import {
  admitMemoryAuthorizationReadRuntime,
  admitMemoryAuthorizationRuntime,
} from "./memory-authorization-runtime.js";
import { emitMemoryAuthorizationShadowSurfaceInspection } from "./memory-authorization-shadow.js";
import { isMemoryIsolationCutoverAgent } from "./memory-cutover.js";
import {
  getMemoryRuntime,
  resolveMemoryCapabilityRegistration,
  setStandaloneMemoryManagerActive,
} from "./memory-state.js";
import type { MemoryPluginRuntime } from "./registry-contribution-types.js";
import type { PluginRegistry } from "./registry-types.js";
import { withPluginRuntimeRegistryScope } from "./runtime/gateway-request-scope.js";

type MemoryRuntime = NonNullable<
  PluginRegistry["memoryCapabilities"][number]["capability"]["runtime"]
>;
type MemorySearchAuthorization = Parameters<
  NonNullable<MemoryPluginRuntime["authorizeSearchHits"]>
>[0];
type MemoryRuntimeOwner = { runtime: MemoryRuntime; registry?: PluginRegistry };
let standaloneMemoryRegistrySlot:
  | { key: string; registry: PluginRegistry; retiredRuntimes: Map<MemoryRuntime, PluginRegistry> }
  | undefined;

/** Resolves the configured memory slot to the single runtime plugin that may load memory. */
function resolveMemoryRuntimePluginIds(config: OpenClawConfig): string[] {
  const plugins = normalizePluginsConfig(config.plugins);
  const memorySlot = plugins.slots.memory;
  if (!plugins.enabled || typeof memorySlot !== "string" || memorySlot.trim().length === 0) {
    return [];
  }
  const pluginId = memorySlot.trim();
  if (plugins.deny.includes(pluginId) || plugins.entries[pluginId]?.enabled === false) {
    return [];
  }
  return [pluginId];
}

function resolveMemoryRuntimeWorkspaceDir(
  cfg: OpenClawConfig,
  agentId: string,
): string | undefined {
  const dir = resolveAgentWorkspaceDir(cfg, agentId);
  if (typeof dir !== "string" || !dir.trim()) {
    return undefined;
  }
  return resolveUserPath(dir);
}

function resolveMemoryRuntimeFromRegistry(registry: PluginRegistry) {
  return resolveMemoryCapabilityRegistration(registry.memoryCapabilities)?.capability.runtime;
}

function listCurrentMemoryRuntimeOwners(): MemoryRuntimeOwner[] {
  const current = getMemoryRuntime();
  const owners = new Map<MemoryRuntime, MemoryRuntimeOwner>();
  for (const [runtime, registry] of standaloneMemoryRegistrySlot?.retiredRuntimes ?? []) {
    owners.set(runtime, { runtime, registry });
  }
  if (current) {
    owners.set(current, { runtime: current });
  }
  if (standaloneMemoryRegistrySlot) {
    const runtime = resolveMemoryRuntimeFromRegistry(standaloneMemoryRegistrySlot.registry);
    if (runtime) {
      owners.set(runtime, { runtime, registry: standaloneMemoryRegistrySlot.registry });
    }
  }
  return [...owners.values()];
}

function withMemoryRuntimeOwner<T>(
  owner: MemoryRuntimeOwner,
  run: (runtime: MemoryRuntime) => T,
): T {
  return withPluginRuntimeRegistryScope(owner.registry, () => run(owner.runtime));
}

function toMemoryRuntimeOwner(
  runtime: MemoryRuntime,
  registry?: PluginRegistry,
): MemoryRuntimeOwner {
  emitMemoryAuthorizationShadowSurfaceInspection(runtime);
  return registry ? { runtime, registry } : { runtime };
}

function ensureMemoryRuntime(params?: {
  cfg: OpenClawConfig;
  agentId: string;
}): MemoryRuntimeOwner | undefined {
  const current = getMemoryRuntime();
  if (current || !params) {
    return current ? toMemoryRuntimeOwner(current) : undefined;
  }
  const onlyPluginIds = resolveMemoryRuntimePluginIds(params.cfg);
  if (onlyPluginIds.length === 0) {
    return undefined;
  }
  const workspaceDir = resolveMemoryRuntimeWorkspaceDir(params.cfg, params.agentId);
  const loadOptions = {
    config: params.cfg,
    onlyPluginIds,
    workspaceDir,
    activate: false as const,
  };
  const key = resolvePluginRegistryLoadCacheKey(loadOptions);
  if (standaloneMemoryRegistrySlot?.key === key) {
    const runtime = resolveMemoryRuntimeFromRegistry(standaloneMemoryRegistrySlot.registry);
    return runtime
      ? toMemoryRuntimeOwner(runtime, standaloneMemoryRegistrySlot.registry)
      : undefined;
  }
  const registry = loadPluginRegistryHandle(loadOptions);
  if (!registry) {
    return undefined;
  }
  const runtime = resolveMemoryRuntimeFromRegistry(registry);
  const previousSlot = standaloneMemoryRegistrySlot;
  const retiredRuntimes = new Map(previousSlot?.retiredRuntimes);
  const previousRuntime = previousSlot
    ? resolveMemoryRuntimeFromRegistry(previousSlot.registry)
    : undefined;
  if (previousSlot && previousRuntime && previousRuntime !== runtime) {
    retiredRuntimes.set(previousRuntime, previousSlot.registry);
  }
  standaloneMemoryRegistrySlot = { key, registry, retiredRuntimes };
  return runtime ? toMemoryRuntimeOwner(runtime, registry) : undefined;
}

/** Returns the active plugin-backed memory search manager for an agent. */
export async function getActiveMemorySearchManager(params: {
  cfg: OpenClawConfig;
  agentId: string;
  purpose?: "default" | "status" | "cli";
}) {
  if (isMemoryIsolationCutoverAgent(params.agentId)) {
    return { manager: null, error: "memory unavailable" };
  }
  const owner = ensureMemoryRuntime(params);
  if (!owner) {
    return { manager: null, error: "memory plugin unavailable" };
  }
  if (owner.registry) {
    setStandaloneMemoryManagerActive(true);
  }
  return await withMemoryRuntimeOwner(
    owner,
    async (runtime) => await runtime.getMemorySearchManager(params),
  );
}

/** Applies the selected memory plugin's authorization policy to raw search hits. */
export async function authorizeActiveMemorySearchHits(
  params: MemorySearchAuthorization,
): Promise<MemorySearchAuthorization["hits"]> {
  const owner = ensureMemoryRuntime(params);
  if (!owner) {
    // Session artifacts need plugin-owned identity mapping before they are safe
    // to expose. Runtimes without that capability may still return memory hits.
    return params.hits.filter((hit) => hit.source !== "sessions");
  }
  return await withMemoryRuntimeOwner(owner, async (runtime) => {
    if (!runtime.authorizeSearchHits) {
      return params.hits.filter((hit) => hit.source !== "sessions");
    }
    return await runtime.authorizeSearchHits(params);
  });
}

/** Resolves current memory backend config without constructing a manager. */
export function resolveActiveMemoryBackendConfig(params: { cfg: OpenClawConfig; agentId: string }) {
  const owner = ensureMemoryRuntime(params);
  return owner
    ? withMemoryRuntimeOwner(owner, (runtime) => runtime.resolveMemoryBackendConfig(params))
    : null;
}

/**
 * Acquires and authorizes the selected runtime without touching the legacy manager.
 * Reads use the Phase 1B surface; later operations require the complete Phase 2A contract.
 * QMD remains unavailable until it supplies its own isolated conformance proof.
 */
export async function authorizeActiveMemoryAccess(params: {
  cfg: OpenClawConfig;
  context: MemoryAccessContext;
}) {
  if (
    !isTrustedMemoryAccessContext(params.context) ||
    params.context.agentId !== params.context.agentId.trim()
  ) {
    throw new MemoryAccessContextError("invalid-context");
  }
  const owner = ensureMemoryRuntime({
    cfg: params.cfg,
    agentId: params.context.agentId,
  });
  if (!owner) {
    return {
      runtime: null,
      plan: null,
      error: "authorized memory plugin unavailable",
    } as const;
  }
  return await withMemoryRuntimeOwner(owner, async (runtime) => {
    const backend = runtime.resolveMemoryBackendConfig({
      cfg: params.cfg,
      agentId: params.context.agentId,
    });
    if (backend.backend !== "builtin") {
      return {
        runtime: null,
        plan: null,
        error: "authorized memory backend unavailable",
      } as const;
    }
    const admission =
      params.context.operation === "read" || params.context.operation === "retrieve"
        ? await admitMemoryAuthorizationReadRuntime(runtime)
        : await admitMemoryAuthorizationRuntime(runtime);
    if (!admission.ok) {
      return {
        runtime: null,
        plan: null,
        error: "authorized memory backend nonconforming",
      } as const;
    }
    const issuedPlan = await admission.runtime.authorize(params.context);
    const plan = brandAuthorizedMemoryPlan({ context: params.context, plan: issuedPlan });
    return { runtime: admission.runtime, plan } as const;
  });
}

/** Closes all active plugin-backed memory search managers. */
export async function closeActiveMemorySearchManagers(cfg?: OpenClawConfig): Promise<void> {
  void cfg;
  await Promise.all(
    listCurrentMemoryRuntimeOwners().map((owner) =>
      withMemoryRuntimeOwner(owner, async (runtime) => {
        await runtime.closeAllMemorySearchManagers?.();
      }),
    ),
  );
  standaloneMemoryRegistrySlot?.retiredRuntimes.clear();
  setStandaloneMemoryManagerActive(false);
}

/** Closes the plugin-backed memory search manager for one agent. */
export async function closeActiveMemorySearchManager(params: {
  cfg: OpenClawConfig;
  agentId: string;
}): Promise<void> {
  await Promise.all(
    listCurrentMemoryRuntimeOwners().map((owner) =>
      withMemoryRuntimeOwner(owner, async (runtime) => {
        await runtime.closeMemorySearchManager?.(params);
      }),
    ),
  );
}

function resetStandaloneMemoryRegistrySlot(): void {
  standaloneMemoryRegistrySlot = undefined;
  setStandaloneMemoryManagerActive(false);
}

if (process.env.VITEST || process.env.NODE_ENV === "test") {
  (globalThis as Record<PropertyKey, unknown>)[Symbol.for("openclaw.memoryRuntimeTestApi")] = {
    resetStandaloneMemoryRegistrySlot,
  };
}
