import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { listGitTrackedFiles } from "../test-utils/repo-files.js";
import {
  MEMORY_AUTHORIZATION_PATH_DISPOSITIONS,
  MEMORY_AUTHORIZATION_PATH_INVENTORY,
  type MemoryAuthorizationPathInventoryEntry,
} from "./memory-authorization-path-inventory.test-support.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const REQUIRED_PHASE_0_PATH_IDS = [
  "selected-runtime-manager-acquisition",
  "bootstrap-memory-and-user-files",
  "startup-recent-memory-context",
  "memory-search-tool",
  "memory-get-tool",
  "session-transcript-search",
  "active-memory-trigger-recall",
  "memory-wiki-prompt-guidance",
  "memory-wiki-corpus-search-and-read",
  "memory-wiki-gateway",
  "memory-wiki-cli",
  "memory-wiki-bridge-and-public-artifacts",
  "lancedb-tool-recall",
  "lancedb-tool-store",
  "lancedb-tool-forget",
  "lancedb-auto-recall",
  "lancedb-auto-capture",
  "memory-prompt-supplements",
  "memory-prompt-preparations",
  "memory-corpus-supplements",
  "talk-fast-context",
  "project-memory-bootstrap",
  "memory-status-command",
  "memory-cli-sync-and-reindex",
  "memory-import",
  "memory-export",
  "memory-public-artifacts",
  "generic-file-read",
  "generic-file-write",
  "generic-file-edit",
  "generic-file-apply-patch",
  "sandbox-workspace-mounts",
  "unsandboxed-exec",
  "memory-flush",
  "transcript-event-write",
  "transcript-history-and-replay",
  "compaction-summary",
  "compaction-checkpoint",
  "compaction-checkpoint-operator-branch-and-restore",
  "dreaming-source-recall",
  "dreaming-derived-artifacts",
  "profile-and-short-term-promotion",
  "child-agent-delegation",
  "child-agent-completion-handoff",
  "cron-triggered-run",
  "heartbeat-triggered-run",
  "webhook-triggered-run",
  "system-triggered-run",
  "final-reply-delivery",
  "message-tool-delivery",
  "session-send-delivery",
  "plugin-and-mcp-outbound-actions",
] as const;

function isProductionTypeScript(file: string): boolean {
  return (
    file.endsWith(".ts") &&
    !file.endsWith(".d.ts") &&
    !file.includes(".test.") &&
    !file.includes(".spec.") &&
    !file.includes(".test-") &&
    !/(^|\/)test-[^/]+\.ts$/u.test(file) &&
    !/(^|\/)tests?\//u.test(file)
  );
}

describe("memory authorization path inventory", () => {
  const inventory: readonly MemoryAuthorizationPathInventoryEntry[] =
    MEMORY_AUTHORIZATION_PATH_INVENTORY;

  it("records every required path with one owner and one explicit disposition", () => {
    const ids = inventory.map((entry) => entry.id);

    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toEqual(expect.arrayContaining([...REQUIRED_PHASE_0_PATH_IDS]));
    expect(inventory.length).toBeGreaterThanOrEqual(55);
    for (const entry of inventory) {
      expect(entry.owner.length).toBeGreaterThan(0);
      expect(MEMORY_AUTHORIZATION_PATH_DISPOSITIONS).toContain(entry.disposition);
      expect(entry.surfaces.length).toBeGreaterThan(0);
    }
  });

  it("keeps Phase 0 shadow-only and makes every enforced bypass fail closed", () => {
    expect(inventory.filter((entry) => entry.disposition === "authorized")).toEqual([]);
    expect(
      inventory.filter((entry) => entry.disposition === "operator-only-authenticated"),
    ).toEqual([]);
    expect(inventory.some((entry) => entry.disposition === "blocked-in-enforced-mode")).toBe(true);
    expect(inventory.some((entry) => entry.disposition === "legacy-only")).toBe(true);
  });

  it("points only at existing repository surfaces", () => {
    const missing = inventory.flatMap((entry) =>
      entry.surfaces
        .filter((surface) => !fs.existsSync(path.join(REPO_ROOT, surface)))
        .map((surface) => `${entry.id}:${surface}`),
    );
    expect(missing).toEqual([]);
  });

  it("classifies every production context-free manager call site", () => {
    const tracked =
      listGitTrackedFiles({
        repoRoot: REPO_ROOT,
        pathspecs: ["src", "extensions", "packages"],
      }) ?? [];
    const callPattern =
      /\bgetActiveMemorySearchManager\s*\(|\bgetMemorySearchManager\s*\(|\.getMemorySearchManager\s*\(/u;
    const directCallSurfaces = tracked
      .filter(isProductionTypeScript)
      .filter((file) => callPattern.test(fs.readFileSync(path.join(REPO_ROOT, file), "utf8")));
    const inventoriedSurfaces = new Set<string>(inventory.flatMap((entry) => entry.surfaces));

    expect(directCallSurfaces.filter((surface) => !inventoriedSurfaces.has(surface))).toEqual([]);
  });
});
