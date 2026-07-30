import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { OpenClawConfig } from "openclaw/plugin-sdk/config-contracts";
import { resolveAgentWorkspaceDir } from "openclaw/plugin-sdk/memory-core-host-engine-foundation";
import type { PluginDoctorStateMigration } from "openclaw/plugin-sdk/runtime-doctor";

const MAX_DISCOVERED_ENTRIES = 100_000;
const SAFE_AGENT_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/u;

type StructuralCounts = {
  curatedFiles: number;
  memoryFiles: number;
  transcriptFiles: number;
  bytes: number;
  symlinks: number;
  unreadable: number;
  invalidAgentIds: number;
  sandboxBlockers: number;
  qmdBlockers: number;
  dmScopeBlockers: number;
};

type MigrationPreview = Readonly<{
  counts: StructuralCounts;
  lines: readonly string[];
}>;

function emptyCounts(): StructuralCounts {
  return {
    curatedFiles: 0,
    memoryFiles: 0,
    transcriptFiles: 0,
    bytes: 0,
    symlinks: 0,
    unreadable: 0,
    invalidAgentIds: 0,
    sandboxBlockers: 0,
    qmdBlockers: 0,
    dmScopeBlockers: 0,
  };
}

function countFile(
  pathname: string,
  counts: StructuralCounts,
  kind: "curated" | "memory" | "transcript",
): void {
  try {
    const stat = fs.lstatSync(pathname);
    if (stat.isSymbolicLink()) {
      counts.symlinks += 1;
      return;
    }
    if (!stat.isFile()) {
      return;
    }
    counts.bytes += stat.size;
    if (kind === "curated") {
      counts.curatedFiles += 1;
    } else if (kind === "memory") {
      counts.memoryFiles += 1;
    } else {
      counts.transcriptFiles += 1;
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      counts.unreadable += 1;
    }
  }
}

function scanDirectory(
  root: string,
  counts: StructuralCounts,
  kind: "memory" | "transcript",
  visited: { count: number },
): void {
  if (visited.count >= MAX_DISCOVERED_ENTRIES) {
    counts.unreadable += 1;
    return;
  }
  let entries: fs.Dirent[];
  try {
    const stat = fs.lstatSync(root);
    if (stat.isSymbolicLink()) {
      counts.symlinks += 1;
      return;
    }
    if (!stat.isDirectory()) {
      return;
    }
    entries = fs
      .readdirSync(root, { withFileTypes: true })
      .toSorted((left, right) => left.name.localeCompare(right.name, "en"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      counts.unreadable += 1;
    }
    return;
  }
  for (const entry of entries) {
    visited.count += 1;
    if (visited.count > MAX_DISCOVERED_ENTRIES) {
      counts.unreadable += 1;
      return;
    }
    const pathname = path.join(root, entry.name);
    if (entry.isSymbolicLink()) {
      counts.symlinks += 1;
    } else if (entry.isDirectory()) {
      scanDirectory(pathname, counts, kind, visited);
    } else if (
      entry.isFile() &&
      (kind === "memory" ? entry.name.toLowerCase().endsWith(".md") : true)
    ) {
      countFile(pathname, counts, kind);
    }
  }
}

function configuredAgents(config: OpenClawConfig): Array<{
  id: string;
  sandboxMode: string | undefined;
  workspaceAccess: string | undefined;
}> {
  const defaults = config.agents?.defaults;
  const fromList = config.agents?.list ?? [];
  const agents =
    fromList.length > 0
      ? fromList
      : Object.entries(config.agents?.entries ?? {}).map(([id, entry]) =>
          Object.assign({ id }, entry),
        );
  const resolved = agents.length > 0 ? agents : [{ id: "main" }];
  return resolved
    .map((agent) => ({
      id: agent.id,
      sandboxMode: agent.sandbox?.mode ?? defaults?.sandbox?.mode,
      workspaceAccess: agent.sandbox?.workspaceAccess ?? defaults?.sandbox?.workspaceAccess,
    }))
    .toSorted((left, right) => left.id.localeCompare(right.id, "en"));
}

function buildPreview(params: {
  config: OpenClawConfig;
  env: NodeJS.ProcessEnv;
  stateDir: string;
}): MigrationPreview | null {
  const counts = emptyCounts();
  const agents = configuredAgents(params.config);
  const visited = { count: 0 };
  for (const agent of agents) {
    if (!SAFE_AGENT_ID.test(agent.id)) {
      counts.invalidAgentIds += 1;
      continue;
    }
    try {
      const workspace = resolveAgentWorkspaceDir(params.config, agent.id, params.env);
      countFile(path.join(workspace, "MEMORY.md"), counts, "curated");
      countFile(path.join(workspace, "USER.md"), counts, "curated");
      scanDirectory(path.join(workspace, "memory"), counts, "memory", visited);
    } catch {
      counts.unreadable += 1;
    }
    scanDirectory(
      path.join(params.stateDir, "agents", agent.id, "sessions"),
      counts,
      "transcript",
      visited,
    );
    if (agent.sandboxMode && agent.sandboxMode !== "off" && agent.workspaceAccess !== "rw") {
      counts.sandboxBlockers += 1;
    }
  }
  if (params.config.memory?.backend === "qmd") {
    counts.qmdBlockers = agents.length;
  }
  if ((params.config.session?.dmScope ?? "main") === "main") {
    counts.dmScopeBlockers = agents.length;
  }
  const artifactCount = counts.curatedFiles + counts.memoryFiles + counts.transcriptFiles;
  const blockerCount =
    counts.symlinks +
    counts.unreadable +
    counts.invalidAgentIds +
    counts.sandboxBlockers +
    counts.qmdBlockers +
    counts.dmScopeBlockers;
  if (artifactCount === 0 && blockerCount === 0) {
    return null;
  }
  const ambiguous = (counts.dmScopeBlockers > 0 ? artifactCount : 0) + counts.symlinks;
  const planMaterial = JSON.stringify({ agents: agents.length, ...counts, ambiguous });
  const planHash = createHash("sha256").update(planMaterial).digest("hex").slice(0, 16);
  const lines = [
    `Scoped memory migration preview v1 (${planHash}).`,
    `Classification: agents=${agents.length}, curated=${counts.curatedFiles}, memory=${counts.memoryFiles}, transcripts=${counts.transcriptFiles}, ambiguous=${ambiguous}, quarantine=${ambiguous}.`,
    `Estimate: backupFiles=${artifactCount}, copyFiles=${artifactCount}, bytes=${counts.bytes}, reindexInputs=${artifactCount}.`,
    "Plan: classify -> backup -> copy -> reindex -> verify -> cutover; owner/admin choices remain required for ambiguous inputs.",
    `Blockers: dmScope=${counts.dmScopeBlockers}, backend=${counts.qmdBlockers}, filesystem=${counts.unreadable + counts.symlinks}, sandbox=${counts.sandboxBlockers}, invalidAgent=${counts.invalidAgentIds}.`,
    "Dry-run only: files=unchanged, database=unchanged, cutover=disabled.",
  ] as const;
  return Object.freeze({ counts, lines: Object.freeze([...lines]) });
}

/** Doctor-owned Phase 1B preview. Both detection and --fix remain deliberately non-mutating. */
export const scopedMemoryMigrationPreview: PluginDoctorStateMigration = {
  id: "memory-core-scoped-memory-migration-preview-v1",
  label: "Preview scoped memory migration",
  doctorOnly: true,
  detectLegacyState(params) {
    const preview = buildPreview({
      config: params.config,
      env: params.env,
      stateDir: params.stateDir,
    });
    return preview ? { preview: [...preview.lines] } : null;
  },
  migrateLegacyState(params) {
    const preview = buildPreview({
      config: params.config,
      env: params.env,
      stateDir: params.stateDir,
    });
    return {
      changes: [],
      warnings: preview ? ["Scoped memory cutover is not enabled in this release."] : [],
      notices: preview ? [...preview.lines] : [],
    };
  },
};
