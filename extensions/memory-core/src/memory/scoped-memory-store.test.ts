import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { openOpenClawAgentDatabase } from "openclaw/plugin-sdk/sqlite-runtime";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createBuiltinScopedMemoryResource,
  createBuiltinScopedMemoryResourceRevision,
  createBuiltinScopedMemoryStore,
  createOpaqueScopedMemoryDirectory,
  reviseBuiltinScopedMemoryPolicy,
  setBuiltinScopedMemoryRevisionLifecycle,
} from "../../test-api.js";
import { resolveScopedMemoryArtifactBase } from "./scoped-memory-db.js";
import { resolveBuiltinScopedMemoryArtifactPath } from "./scoped-memory-resources.js";

describe("builtin scoped memory store", () => {
  let stateDir = "";
  const openedAgents = new Set<string>();

  beforeEach(() => {
    stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-scoped-memory-store-"));
    vi.stubEnv("OPENCLAW_STATE_DIR", stateDir);
  });

  afterEach(() => {
    for (const agentId of openedAgents) {
      try {
        openOpenClawAgentDatabase({ agentId }).db.close();
      } catch {}
    }
    openedAgents.clear();
    vi.unstubAllEnvs();
    fs.rmSync(stateDir, { recursive: true, force: true });
  });

  function storeFor(agentId = "main", audienceId = "principal-owner") {
    openedAgents.add(agentId);
    return createBuiltinScopedMemoryStore({
      agentId,
      scopeKind: "user",
      audienceKind: "user",
      audienceId,
      authorityKind: "user",
      authorityOwnerId: audienceId,
      defaultCapabilities: ["retrieve", "read"],
      actor: { kind: "human", id: audienceId },
      reason: "test placement",
      nowMs: 1_000,
    });
  }

  it("retries opaque directory collisions and rejects traversal", () => {
    const baseDir = path.join(stateDir, "opaque");
    const first = `s1_${"a".repeat(32)}`;
    const second = `s1_${"b".repeat(32)}`;
    fs.mkdirSync(path.join(baseDir, first), { recursive: true });
    const generated = [first, second];

    const allocated = createOpaqueScopedMemoryDirectory(baseDir, {
      generatePathKey: () => generated.shift() ?? second,
    });

    expect(allocated.pathKey).toBe(second);
    expect(fs.statSync(allocated.directoryPath).isDirectory()).toBe(true);
    expect(() =>
      createOpaqueScopedMemoryDirectory(baseDir, {
        generatePathKey: () => "../principal-owner",
      }),
    ).toThrow("path key is invalid");
    expect(() =>
      resolveBuiltinScopedMemoryArtifactPath({
        databasePath: path.join(stateDir, "agent.sqlite"),
        pathKey: second,
        artifactLocator: "../private.md",
      }),
    ).toThrow("artifact locator is invalid");
  });

  it("uses opaque paths and preserves immutable revision history", () => {
    const store = storeFor();
    const first = createBuiltinScopedMemoryResource({
      agentId: "main",
      store,
      logicalLocator: "MEMORY.md",
      content: "first immutable revision",
      actor: { kind: "human", id: "principal-owner" },
      nowMs: 2_000,
    });
    const second = createBuiltinScopedMemoryResourceRevision({
      agentId: "main",
      resourceId: first.resourceId,
      content: "second immutable revision",
      lifecycleState: "active",
      actor: { kind: "human", id: "principal-owner" },
      nowMs: 3_000,
    });
    const database = openOpenClawAgentDatabase({ agentId: "main" });
    const root = database.db
      .prepare("SELECT path_key, authority_owner_id FROM memory_storage_roots")
      .get() as { path_key: string; authority_owner_id: string };
    const revisions = database.db
      .prepare(
        "SELECT revision_id, revision_number, lifecycle_state FROM memory_resource_revisions ORDER BY revision_number",
      )
      .all();

    expect(root.authority_owner_id).toBe("principal-owner");
    expect(root.path_key).not.toContain("principal-owner");
    expect(resolveScopedMemoryArtifactBase(database.path)).not.toContain("principal-owner");
    expect(revisions).toEqual([
      { revision_id: first.revisionId, revision_number: 1, lifecycle_state: "tombstoned" },
      { revision_id: second.revisionId, revision_number: 2, lifecycle_state: "active" },
    ]);
    expect(() =>
      database.db
        .prepare("UPDATE memory_resource_revisions SET content_hash = ? WHERE revision_id = ?")
        .run("rewritten", second.revisionId),
    ).toThrow("immutable");
    expect(() =>
      setBuiltinScopedMemoryRevisionLifecycle({
        agentId: "main",
        revisionId: first.revisionId,
        lifecycleState: "active",
        nowMs: 4_000,
      }),
    ).toThrow("invalid scoped-memory revision lifecycle transition");
  });

  it("binds a new resource revision to the policy current at commit time", () => {
    const store = storeFor();
    const first = createBuiltinScopedMemoryResource({
      agentId: "main",
      store,
      logicalLocator: "MEMORY.md",
      content: "first revision",
      actor: { kind: "human", id: "principal-owner" },
      nowMs: 2_000,
    });
    const writeFileSync = fs.writeFileSync.bind(fs);
    let racedPolicy: ReturnType<typeof reviseBuiltinScopedMemoryPolicy> | undefined;
    vi.spyOn(fs, "writeFileSync").mockImplementationOnce((file, data, options) => {
      writeFileSync(file, data, options);
      racedPolicy = reviseBuiltinScopedMemoryPolicy({
        agentId: "main",
        policyId: store.policyId,
        entries: [],
        actor: { kind: "human", id: "principal-owner" },
        reason: "concurrent policy revision",
        nowMs: 2_500,
      });
    });

    const second = createBuiltinScopedMemoryResourceRevision({
      agentId: "main",
      resourceId: first.resourceId,
      content: "second revision",
      lifecycleState: "active",
      actor: { kind: "human", id: "principal-owner" },
      nowMs: 3_000,
    });

    if (!racedPolicy) {
      throw new Error("expected policy revision race");
    }
    expect(second.policyRevisionId).toBe(racedPolicy.policyRevisionId);
    expect(second.sourcePolicySetId).toBe(racedPolicy.sourcePolicySetId);
    expect(
      openOpenClawAgentDatabase({ agentId: "main" })
        .db.prepare(
          "SELECT policy_revision_id, source_policy_set_id FROM memory_resource_revisions WHERE revision_id = ?",
        )
        .get(second.revisionId),
    ).toEqual({
      policy_revision_id: racedPolicy.policyRevisionId,
      source_policy_set_id: racedPolicy.sourcePolicySetId,
    });
  });

  it("never writes scoped resources into legacy index tables", () => {
    const store = storeFor();
    const database = openOpenClawAgentDatabase({ agentId: "main" });
    database.db
      .prepare(
        "INSERT INTO memory_index_sources (path, source, hash, mtime, size) VALUES (?, 'memory', ?, 1, 10)",
      )
      .run("legacy.md", "legacy-source-hash");
    database.db
      .prepare(
        `INSERT INTO memory_index_chunks
          (id, path, source, start_line, end_line, hash, model, text, embedding, updated_at)
         VALUES (?, ?, 'memory', 1, 1, ?, 'legacy', ?, '[]', 1)`,
      )
      .run("legacy-chunk", "legacy.md", "legacy-chunk-hash", "legacy sentinel");
    const before = {
      sources: database.db.prepare("SELECT * FROM memory_index_sources").all(),
      chunks: database.db.prepare("SELECT * FROM memory_index_chunks").all(),
    };

    createBuiltinScopedMemoryResource({
      agentId: "main",
      store,
      logicalLocator: "private.md",
      content: "scoped-only sentinel",
      actor: { kind: "human", id: "principal-owner" },
      nowMs: 2_000,
    });

    expect(database.db.prepare("SELECT * FROM memory_index_sources").all()).toEqual(before.sources);
    expect(database.db.prepare("SELECT * FROM memory_index_chunks").all()).toEqual(before.chunks);
    expect(
      database.db
        .prepare("SELECT text FROM memory_index_chunks WHERE text LIKE '%scoped-only%'")
        .all(),
    ).toEqual([]);
  });
});
