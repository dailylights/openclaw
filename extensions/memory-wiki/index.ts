// Memory Wiki plugin entrypoint registers its OpenClaw integration.
import fs from "node:fs/promises";
import path from "node:path";
import { isMemoryInvocationEnforced } from "openclaw/plugin-sdk/memory-core-host-runtime-core";
import { definePluginEntry, type OpenClawConfig } from "./api.js";
import { registerWikiCli } from "./src/cli.js";
import {
  activateMemoryWikiCompiledCacheOwner,
  configureMemoryWikiCompiledCacheStore,
  createMemoryWikiCompiledCacheStore,
  deactivateMemoryWikiCompiledCacheOwnersExcept,
  reconcileMemoryWikiCompiledCacheOwner,
  resolveMemoryWikiCompiledCacheOwnerId,
} from "./src/compiled-cache.js";
import {
  memoryWikiConfigSchema,
  isMemoryWikiReadIsolationUnavailable,
  resolveMemoryWikiAgentConfig,
  resolveMemoryWikiConfig,
  resolveMemoryWikiConfiguredAgentIds,
  type MemoryWikiConfigResolver,
} from "./src/config.js";
import { createWikiCorpusSupplement } from "./src/corpus-supplement.js";
import { registerMemoryWikiGatewayMethods } from "./src/gateway.js";
import {
  configureMemoryWikiImportRunStateStore,
  createMemoryWikiImportRunStateStore,
} from "./src/import-runs-state.js";
import {
  ensureMemoryWikiVaultGeneration,
  loadMemoryWikiValidatedVaultIdentity,
} from "./src/log.js";
import {
  createWikiPromptSectionBuilder,
  createWikiPromptSectionPreparer,
} from "./src/prompt-section.js";
import {
  configureMemoryWikiSourceSyncStateStore,
  createMemoryWikiSourceSyncStateStore,
} from "./src/source-sync-state.js";
import {
  createWikiApplyTool,
  createWikiGetTool,
  createWikiLintTool,
  createWikiSearchTool,
  createWikiStatusTool,
} from "./src/tool.js";

async function loadConfiguredVaultIdentity(vaultRoot: string): Promise<{
  vaultGeneration: string;
  compiledCachePublicationId: string | null;
} | null> {
  const identity = await loadMemoryWikiValidatedVaultIdentity(vaultRoot);
  if (identity.vaultGeneration) {
    return {
      vaultGeneration: identity.vaultGeneration,
      compiledCachePublicationId: identity.compiledCachePublicationId,
    };
  }
  try {
    const stat = await fs.stat(path.join(vaultRoot, ".openclaw-wiki", "log.jsonl"));
    if (!stat.isFile()) {
      return null;
    }
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return null;
    }
    throw error;
  }
  // Cache data is rebuildable, but an initialized pre-generation vault still
  // needs a stable owner identity before an external compiler can publish it.
  return {
    vaultGeneration: await ensureMemoryWikiVaultGeneration(vaultRoot),
    compiledCachePublicationId: null,
  };
}

export default definePluginEntry({
  id: "memory-wiki",
  name: "Memory Wiki",
  description: "Persistent wiki compiler and Obsidian-friendly knowledge vault for OpenClaw.",
  configSchema: memoryWikiConfigSchema,
  register(api) {
    const config = resolveMemoryWikiConfig(api.pluginConfig);
    const getAppConfig = () =>
      (api.runtime.config?.current?.() ?? api.config) as OpenClawConfig | undefined;
    const resolveConfig: MemoryWikiConfigResolver = (agentId, appConfig = getAppConfig()) =>
      resolveMemoryWikiAgentConfig({ config, appConfig, agentId });
    const resolveToolContext = (agentId?: string) => {
      const appConfig = getAppConfig();
      const configuredAgentIds = resolveMemoryWikiConfiguredAgentIds(appConfig);
      const requestedAgentId = agentId?.trim();
      if (
        isMemoryWikiReadIsolationUnavailable({
          config,
          appConfig,
          ...(requestedAgentId ? { agentId: requestedAgentId } : {}),
        })
      ) {
        return null;
      }
      const effectiveAgentId = requestedAgentId ?? configuredAgentIds[0];
      if (!effectiveAgentId) {
        return null;
      }
      return { appConfig, config: resolveConfig(effectiveAgentId, appConfig) };
    };
    configureMemoryWikiSourceSyncStateStore(
      createMemoryWikiSourceSyncStateStore(api.runtime.state.openKeyedStore),
    );
    configureMemoryWikiImportRunStateStore(
      createMemoryWikiImportRunStateStore(api.runtime.state.openKeyedStore),
    );
    const compiledCacheStore = createMemoryWikiCompiledCacheStore(api.runtime.state.openBlobStore, {
      onReadError(error) {
        api.logger.warn(`memory-wiki: compiled cache unavailable: ${String(error)}`);
      },
    });
    configureMemoryWikiCompiledCacheStore(compiledCacheStore);
    api.registerService({
      id: "memory-wiki-compiled-cache-owner-cleanup",
      async start() {
        const appConfig = getAppConfig();
        const configuredAgentIds = resolveMemoryWikiConfiguredAgentIds(appConfig);
        const legacyAgentIds = configuredAgentIds.filter(
          (agentId) => !isMemoryWikiReadIsolationUnavailable({ config, appConfig, agentId }),
        );
        const activeConfigs =
          config.vault.scope === "global"
            ? legacyAgentIds.length > 0
              ? [resolveConfig(legacyAgentIds[0], appConfig)]
              : []
            : legacyAgentIds.map((agentId) => resolveConfig(agentId, appConfig));
        // Clear every previously trusted owner before fallible vault reads. A failed
        // lifecycle refresh must leave prompt preparation closed, not stale-but-active.
        deactivateMemoryWikiCompiledCacheOwnersExcept(new Set());
        const preparedOwners: Array<{
          config: ReturnType<MemoryWikiConfigResolver>;
          identity: {
            vaultGeneration: string;
            compiledCachePublicationId: string | null;
          };
        }> = [];
        for (const activeConfig of activeConfigs) {
          const identity = await loadConfiguredVaultIdentity(activeConfig.vault.path);
          if (identity) {
            preparedOwners.push({ config: activeConfig, identity });
          }
        }
        const activeOwnerIds = new Set<string>();
        try {
          for (const { config: activeConfig, identity } of preparedOwners) {
            activateMemoryWikiCompiledCacheOwner(
              activeConfig,
              identity.vaultGeneration,
              identity.compiledCachePublicationId,
            );
            await reconcileMemoryWikiCompiledCacheOwner(activeConfig, () =>
              loadMemoryWikiValidatedVaultIdentity(activeConfig.vault.path),
            );
            activeOwnerIds.add(resolveMemoryWikiCompiledCacheOwnerId(activeConfig));
          }
        } catch (error) {
          deactivateMemoryWikiCompiledCacheOwnersExcept(new Set());
          throw error;
        }
        deactivateMemoryWikiCompiledCacheOwnersExcept(activeOwnerIds);
        await compiledCacheStore.deleteOwnersExcept(activeOwnerIds);
      },
    });

    const promptBuilder = createWikiPromptSectionBuilder();
    api.registerMemoryPromptSupplement((params) =>
      isMemoryWikiReadIsolationUnavailable({
        config,
        appConfig: getAppConfig(),
        ...(params.agentId ? { agentId: params.agentId } : {}),
      })
        ? []
        : promptBuilder(params),
    );
    const promptPreparer = createWikiPromptSectionPreparer({ config, resolveConfig });
    api.registerMemoryPromptPreparation(async (params) =>
      isMemoryWikiReadIsolationUnavailable({
        config,
        appConfig: getAppConfig(),
        ...(params.agentId ? { agentId: params.agentId } : {}),
      })
        ? []
        : await promptPreparer(params),
    );
    const corpusSupplement = createWikiCorpusSupplement({ resolveConfig, getAppConfig });
    api.registerMemoryCorpusSupplement({
      search: async (params) =>
        isMemoryWikiReadIsolationUnavailable({
          config,
          appConfig: getAppConfig(),
          ...(params.agentId ? { agentId: params.agentId } : {}),
        })
          ? []
          : await corpusSupplement.search(params),
      get: async (params) =>
        isMemoryWikiReadIsolationUnavailable({
          config,
          appConfig: getAppConfig(),
          ...(params.agentId ? { agentId: params.agentId } : {}),
        })
          ? null
          : await corpusSupplement.get(params),
    });
    registerMemoryWikiGatewayMethods({
      api,
      config,
      appConfig: api.config,
      getAppConfig,
      resolveConfig,
    });
    api.registerTool(
      (ctx) => {
        if (isMemoryInvocationEnforced(ctx.memoryInvocationToken)) {
          return null;
        }
        const resolved = resolveToolContext(ctx.agentId);
        return resolved
          ? createWikiStatusTool(resolved.config, resolved.appConfig, {
              agentId: resolved.config.agentId ?? ctx.agentId,
            })
          : null;
      },
      { name: "wiki_status" },
    );
    api.registerTool(
      (ctx) => {
        if (isMemoryInvocationEnforced(ctx.memoryInvocationToken)) {
          return null;
        }
        const resolved = resolveToolContext(ctx.agentId);
        return resolved ? createWikiLintTool(resolved.config, resolved.appConfig) : null;
      },
      { name: "wiki_lint" },
    );
    api.registerTool(
      (ctx) => {
        if (isMemoryInvocationEnforced(ctx.memoryInvocationToken)) {
          return null;
        }
        const resolved = resolveToolContext(ctx.agentId);
        return resolved ? createWikiApplyTool(resolved.config, resolved.appConfig) : null;
      },
      { name: "wiki_apply" },
    );
    api.registerTool(
      (ctx) => {
        if (isMemoryInvocationEnforced(ctx.memoryInvocationToken)) {
          return null;
        }
        const resolved = resolveToolContext(ctx.agentId);
        if (!resolved) {
          return null;
        }
        return createWikiSearchTool(resolved.config, resolved.appConfig, {
          agentId: resolved.config.agentId ?? ctx.agentId,
          agentSessionKey: ctx.sessionKey,
          sandboxed: ctx.sandboxed,
          conversationRecall: ctx.conversationRecall,
        });
      },
      { name: "wiki_search" },
    );
    api.registerTool(
      (ctx) => {
        if (isMemoryInvocationEnforced(ctx.memoryInvocationToken)) {
          return null;
        }
        const resolved = resolveToolContext(ctx.agentId);
        if (!resolved) {
          return null;
        }
        return createWikiGetTool(resolved.config, resolved.appConfig, {
          agentId: resolved.config.agentId ?? ctx.agentId,
          agentSessionKey: ctx.sessionKey,
          sandboxed: ctx.sandboxed,
          conversationRecall: ctx.conversationRecall,
        });
      },
      { name: "wiki_get" },
    );
    api.registerCli(
      ({ program }) => {
        registerWikiCli(program, { config, resolveConfig, getAppConfig });
      },
      {
        descriptors: [
          {
            name: "wiki",
            description: "Inspect and initialize the memory wiki vault",
            hasSubcommands: true,
          },
        ],
      },
    );
  },
});
