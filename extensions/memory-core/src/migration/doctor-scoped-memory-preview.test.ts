import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { OpenClawConfig } from "openclaw/plugin-sdk/config-contracts";
import type { PluginDoctorStateMigrationContext } from "openclaw/plugin-sdk/runtime-doctor";
import { afterEach, describe, expect, it } from "vitest";
import { scopedMemoryMigrationPreview } from "./doctor-scoped-memory-preview.js";

const roots = new Set<string>();

afterEach(() => {
  for (const root of roots) {
    fs.rmSync(root, { recursive: true, force: true });
  }
  roots.clear();
});

function snapshotFiles(root: string): Record<string, string> {
  const snapshot: Record<string, string> = {};
  const visit = (directory: string): void => {
    for (const entry of fs
      .readdirSync(directory, { withFileTypes: true })
      .toSorted((left, right) => left.name.localeCompare(right.name, "en"))) {
      const pathname = path.join(directory, entry.name);
      const relative = path.relative(root, pathname);
      if (entry.isDirectory()) {
        snapshot[`${relative}/`] = "directory";
        visit(pathname);
      } else if (entry.isFile()) {
        snapshot[relative] = fs.readFileSync(pathname).toString("base64");
      } else if (entry.isSymbolicLink()) {
        snapshot[relative] = `symlink:${fs.readlinkSync(pathname)}`;
      }
    }
  };
  visit(root);
  return snapshot;
}

function migrationParams(params: { config: OpenClawConfig; root: string; stateDir: string }) {
  return {
    config: params.config,
    env: {
      HOME: params.root,
      OPENCLAW_STATE_DIR: params.stateDir,
    },
    stateDir: params.stateDir,
    oauthDir: path.join(params.root, "oauth"),
    context: {} as PluginDoctorStateMigrationContext,
  };
}

describe("scoped memory doctor migration preview", () => {
  it("is deterministic, content-redacted, and non-mutating", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-scoped-memory-doctor-"));
    roots.add(root);
    const workspace = path.join(root, "workspace");
    const stateDir = path.join(root, "state");
    const sessionsDir = path.join(stateDir, "agents", "main", "sessions");
    fs.mkdirSync(path.join(workspace, "memory"), { recursive: true });
    fs.mkdirSync(sessionsDir, { recursive: true });
    fs.writeFileSync(path.join(workspace, "MEMORY.md"), "private-curated-sentinel");
    fs.writeFileSync(
      path.join(workspace, "memory", "private-memory-name.md"),
      "private-memory-content-sentinel",
    );
    fs.writeFileSync(
      path.join(sessionsDir, "private-session-name.jsonl"),
      "private-transcript-content-sentinel",
    );
    const config = {
      memory: { backend: "qmd" },
      session: { dmScope: "main" },
      agents: {
        list: [
          {
            id: "main",
            workspace,
            sandbox: { mode: "all", workspaceAccess: "ro" },
          },
        ],
      },
    } satisfies OpenClawConfig;
    const params = migrationParams({ config, root, stateDir });
    const beforeFiles = snapshotFiles(root);
    const beforeConfig = structuredClone(config);

    const firstPreview = await scopedMemoryMigrationPreview.detectLegacyState(params);
    const secondPreview = await scopedMemoryMigrationPreview.detectLegacyState(params);
    const firstMigration = await scopedMemoryMigrationPreview.migrateLegacyState(params);
    const secondMigration = await scopedMemoryMigrationPreview.migrateLegacyState(params);

    expect(secondPreview).toEqual(firstPreview);
    expect(secondMigration).toEqual(firstMigration);
    expect(firstMigration.changes).toEqual([]);
    expect(firstMigration.notices).toEqual(firstPreview?.preview);
    const report = JSON.stringify({ firstPreview, firstMigration });
    expect(report).toContain("curated=1, memory=1, transcripts=1");
    expect(report).toContain("dmScope=1, backend=1, filesystem=0, sandbox=1");
    expect(report).toContain("classify -> backup -> copy -> reindex -> verify -> cutover");
    expect(report).not.toMatch(/private-(?:curated|memory|session|transcript)/u);
    expect(snapshotFiles(root)).toEqual(beforeFiles);
    expect(config).toEqual(beforeConfig);
    expect(
      fs.existsSync(path.join(stateDir, "agents", "main", "agent", "openclaw-agent.sqlite")),
    ).toBe(false);
  });

  it("never treats a traversal-shaped agent id as a state path", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-scoped-memory-doctor-"));
    roots.add(root);
    const stateDir = path.join(root, "state");
    const config = {
      agents: { list: [{ id: ".." }] },
    } as OpenClawConfig;

    const preview = await scopedMemoryMigrationPreview.detectLegacyState(
      migrationParams({ config, root, stateDir }),
    );

    expect(preview?.preview.join("\n")).toContain("invalidAgent=1");
    expect(preview?.preview.join("\n")).toContain("transcripts=0");
  });
});
