/**
 * Path policy for the constrained memory virtual filesystem.
 *
 * The generic file tools may only reach memory through opaque virtual paths.
 * This recognises the legacy workspace names as well as aliases that resolve
 * to them, so a symlink or hard link cannot restore raw artifact access.
 */
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const CONTROLLED_MEMORY_FILE_NAMES = new Set(["memory.md", "user.md"]);

function normalizedRelativePath(root: string, candidate: string): string | undefined {
  const relative = path.relative(root, candidate).split(path.sep).join("/");
  if (!relative || relative === ".." || relative.startsWith("../")) {
    return undefined;
  }
  return relative.normalize("NFKC").toLowerCase();
}

function isControlledMemoryRelativePath(relative: string | undefined): boolean {
  return Boolean(
    relative &&
    (CONTROLLED_MEMORY_FILE_NAMES.has(relative) ||
      relative === "memory" ||
      relative.startsWith("memory/")),
  );
}

function parseFilePath(value: string): string | undefined {
  if (!value.startsWith("file://")) {
    return value;
  }
  try {
    const url = new URL(value);
    if (url.protocol !== "file:" || /%2f|%5c/iu.test(url.pathname)) {
      return undefined;
    }
    return fileURLToPath(url);
  } catch {
    return undefined;
  }
}

function resolveWorkspaceCandidate(params: {
  root: string;
  pathname: string;
  containerWorkdir?: string;
}): string | undefined {
  const filePath = parseFilePath(
    params.pathname.startsWith("@") ? params.pathname.slice(1) : params.pathname,
  );
  if (!filePath) {
    return undefined;
  }
  const workdir = params.containerWorkdir?.replace(/\/+$/u, "");
  if (workdir && (filePath === workdir || filePath.startsWith(`${workdir}/`))) {
    return path.resolve(params.root, filePath.slice(workdir.length + 1));
  }
  return path.resolve(params.root, filePath);
}

async function canonicalizeViaExistingAncestor(candidate: string): Promise<string | undefined> {
  let current = candidate;
  const missing: string[] = [];
  while (true) {
    try {
      const canonical = await fs.realpath(current);
      return path.resolve(canonical, ...missing);
    } catch (error: unknown) {
      if (!(error instanceof Error) || (error as NodeJS.ErrnoException).code !== "ENOENT") {
        return undefined;
      }
      const parent = path.dirname(current);
      if (parent === current) {
        return undefined;
      }
      missing.unshift(path.basename(current));
      current = parent;
    }
  }
}

async function isHardLinkToControlledMemoryFile(params: {
  root: string;
  candidate: string;
}): Promise<boolean> {
  let candidateStat: Awaited<ReturnType<typeof fs.stat>>;
  try {
    candidateStat = await fs.stat(params.candidate);
  } catch {
    return false;
  }
  if (!candidateStat.isFile()) {
    return false;
  }
  let entries: string[];
  try {
    entries = await fs.readdir(params.root);
  } catch {
    return false;
  }
  for (const fileName of entries) {
    if (!CONTROLLED_MEMORY_FILE_NAMES.has(fileName.normalize("NFKC").toLowerCase())) {
      continue;
    }
    try {
      const controlledStat = await fs.stat(path.join(params.root, fileName));
      if (
        controlledStat.isFile() &&
        controlledStat.dev === candidateStat.dev &&
        controlledStat.ino === candidateStat.ino
      ) {
        return true;
      }
    } catch {
      // A missing optional workspace memory file cannot be an alias target.
    }
  }
  return false;
}

/**
 * Returns true when a model-supplied workspace path reaches a raw memory
 * artifact. The check is deliberately alias-aware before the ordinary file
 * tool is invoked, so read-only workspace access cannot become a bypass.
 */
export async function isRawControlledMemoryWorkspacePath(params: {
  root: string;
  pathname: string;
  containerWorkdir?: string;
}): Promise<boolean> {
  const root = path.resolve(params.root);
  const candidate = resolveWorkspaceCandidate({ ...params, root });
  if (!candidate || !normalizedRelativePath(root, candidate)) {
    return false;
  }
  if (isControlledMemoryRelativePath(normalizedRelativePath(root, candidate))) {
    return true;
  }
  const [canonicalRoot, canonicalCandidate] = await Promise.all([
    canonicalizeViaExistingAncestor(root),
    canonicalizeViaExistingAncestor(candidate),
  ]);
  if (
    canonicalRoot &&
    canonicalCandidate &&
    isControlledMemoryRelativePath(normalizedRelativePath(canonicalRoot, canonicalCandidate))
  ) {
    return true;
  }
  return await isHardLinkToControlledMemoryFile({ root, candidate });
}
