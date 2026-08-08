import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { normalizeAgentId } from "openclaw/plugin-sdk/routing";
import { executeSqliteQuerySync, getNodeSqliteKysely } from "openclaw/plugin-sdk/sqlite-runtime";
import { resolveScopedMemoryArtifactBase, type ScopedMemoryDatabase } from "./scoped-memory-db.js";

const OPAQUE_ARTIFACT_ATTEMPTS = 8;
const OPAQUE_PATH_KEY_PATTERN = /^s1_[A-Za-z0-9_-]{24,}$/u;
const OPAQUE_ARTIFACT_PATTERN = /^r1_[A-Za-z0-9_-]{18,}\.md$/u;
const SCOPED_CHUNK_MAX_LINES = 40;
const SCOPED_CHUNK_MAX_CHARS = 4_000;

type BuiltinScopedMemoryChunk = Readonly<{
  ordinal: number;
  startLine: number;
  endLine: number;
  text: string;
}>;

export function hashScopedMemoryText(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function createOpaqueArtifactLocator(): string {
  return `r1_${randomBytes(18).toString("base64url")}.md`;
}

function assertOpaquePathKey(pathKey: string): void {
  if (!OPAQUE_PATH_KEY_PATTERN.test(pathKey)) {
    throw new Error("generated scoped-memory path key is invalid");
  }
}

function assertOpaqueArtifactLocator(locator: string): void {
  if (!OPAQUE_ARTIFACT_PATTERN.test(locator)) {
    throw new Error("scoped-memory artifact locator is invalid");
  }
}

function resolveChildPath(base: string, child: string): string {
  const resolvedBase = path.resolve(base);
  const resolved = path.resolve(resolvedBase, child);
  if (path.dirname(resolved) !== resolvedBase || path.basename(resolved) !== child) {
    throw new Error("scoped-memory locator escaped its storage root");
  }
  return resolved;
}

export function resolveBuiltinScopedMemoryArtifactPath(params: {
  databasePath: string;
  pathKey: string;
  artifactLocator: string;
}): string {
  assertOpaquePathKey(params.pathKey);
  assertOpaqueArtifactLocator(params.artifactLocator);
  const storeDir = resolveChildPath(
    resolveScopedMemoryArtifactBase(params.databasePath),
    params.pathKey,
  );
  return resolveChildPath(storeDir, params.artifactLocator);
}

/**
 * Remove builtin artifacts only after their catalog revisions are durably tombstoned.
 * A missing file is a completed earlier cleanup; other failures leave the tombstone for retry.
 */
export function removeTombstonedBuiltinScopedMemoryArtifacts(params: {
  database: DatabaseSync;
  databasePath: string;
  agentId: string;
  revisionIds: readonly string[];
}): void {
  const agentId = normalizeAgentId(params.agentId);
  const revisionIds = [...new Set(params.revisionIds)].toSorted();
  if (revisionIds.length === 0) {
    return;
  }
  const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
  const rows = executeSqliteQuerySync(
    params.database,
    db
      .selectFrom("memory_resource_revisions as revision")
      .innerJoin("memory_resources as resource", "resource.resource_id", "revision.resource_id")
      .innerJoin("memory_stores as store", "store.store_id", "resource.store_id")
      .innerJoin("memory_storage_roots as root", "root.storage_root_id", "store.storage_root_id")
      .select([
        "revision.revision_id",
        "revision.artifact_locator",
        "revision.lifecycle_state",
        "root.backend_kind",
        "root.path_key",
      ])
      .where("revision.revision_id", "in", revisionIds)
      .where("resource.agent_id", "=", agentId)
      .orderBy("revision.revision_id"),
  ).rows;
  if (rows.length !== revisionIds.length) {
    throw new Error("tombstoned scoped-memory artifact is unavailable");
  }
  for (const row of rows) {
    if (row.lifecycle_state !== "tombstoned" || row.backend_kind !== "builtin" || !row.path_key) {
      throw new Error("tombstoned scoped-memory artifact is unavailable");
    }
    const artifactPath = resolveBuiltinScopedMemoryArtifactPath({
      databasePath: params.databasePath,
      pathKey: row.path_key,
      artifactLocator: row.artifact_locator,
    });
    try {
      fs.unlinkSync(artifactPath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw error;
      }
    }
  }
}

export function writeBuiltinScopedMemoryArtifact(params: {
  databasePath: string;
  pathKey: string;
  content: string;
}): { artifactLocator: string; artifactPath: string } {
  for (let attempt = 0; attempt < OPAQUE_ARTIFACT_ATTEMPTS; attempt += 1) {
    const artifactLocator = createOpaqueArtifactLocator();
    const artifactPath = resolveBuiltinScopedMemoryArtifactPath({
      databasePath: params.databasePath,
      pathKey: params.pathKey,
      artifactLocator,
    });
    try {
      fs.writeFileSync(artifactPath, params.content, {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
      });
      return { artifactLocator, artifactPath };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
        throw error;
      }
    }
  }
  throw new Error("could not allocate an opaque scoped-memory artifact");
}

export function removeBuiltinScopedMemoryArtifact(artifactPath: string): void {
  try {
    fs.unlinkSync(artifactPath);
  } catch {}
}

export function chunkBuiltinScopedMemoryContent(content: string): BuiltinScopedMemoryChunk[] {
  const lines = content.split(/\r?\n/u);
  const chunks: BuiltinScopedMemoryChunk[] = [];
  let start = 0;
  while (start < lines.length) {
    let end = start;
    let chars = 0;
    while (end < lines.length && end - start < SCOPED_CHUNK_MAX_LINES) {
      const nextChars = chars + (lines[end]?.length ?? 0) + (end === start ? 0 : 1);
      if (end > start && nextChars > SCOPED_CHUNK_MAX_CHARS) {
        break;
      }
      chars = nextChars;
      end += 1;
    }
    chunks.push({
      ordinal: chunks.length,
      startLine: start + 1,
      endLine: Math.max(start + 1, end),
      text: lines.slice(start, end).join("\n"),
    });
    start = end;
  }
  return chunks;
}
