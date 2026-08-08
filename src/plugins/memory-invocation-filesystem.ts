import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type {
  AuthorizedMemoryPlan,
  MemoryAccessContext,
} from "../memory-host-sdk/host/authorization.js";
import type { MemoryVirtualFilesystemView } from "./memory-invocation-receipts.js";
import { hashMemoryRevision } from "./memory-invocation-serialization.js";

const MEMORY_VIRTUAL_ROOTS = new Set([
  "private",
  "channel",
  "shared",
  "projections",
  "postbox-review",
]);

type MemoryVirtualRoot = "private" | "channel" | "shared" | "projections" | "postbox-review";

export function normalizeMemoryVirtualPath(value: string): string | undefined {
  const normalized = value.normalize("NFKC").replaceAll("\\", "/");
  if (normalized !== value || normalized.startsWith("/") || normalized.includes("\0")) {
    return undefined;
  }
  const parts = normalized.split("/");
  if (
    parts.length !== 3 ||
    parts.some((part) => !part || part === "." || part === "..") ||
    !MEMORY_VIRTUAL_ROOTS.has(parts[0] ?? "")
  ) {
    return undefined;
  }
  const [root, mountHandle, fileName] = parts;
  if (
    !root ||
    !mountHandle ||
    !fileName ||
    !/^mm1_[A-Za-z0-9_-]{24,}$/u.test(mountHandle) ||
    !/^mrh1_[A-Za-z0-9_-]{24,}\.md$/u.test(fileName)
  ) {
    return undefined;
  }
  return normalized;
}

export function isMemoryVirtualRootPath(value: string): boolean {
  const normalized = value.normalize("NFKC").replaceAll("\\", "/");
  const root = normalized.split("/", 1)[0]?.toLowerCase();
  return typeof root === "string" && MEMORY_VIRTUAL_ROOTS.has(root);
}

export async function createMemoryVirtualFilesystemView(params: {
  context: MemoryAccessContext;
  plan: AuthorizedMemoryPlan;
}): Promise<MemoryVirtualFilesystemView> {
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-memory-view-"));
  try {
    const roots = await Promise.all(
      params.plan.mounts.map(async (mount) => {
        const virtualRoot = mount.virtualRoot as MemoryVirtualRoot;
        const sourcePath = path.join(rootDir, virtualRoot, mount.mountHandle);
        await fs.mkdir(sourcePath, { recursive: true, mode: 0o500 });
        await fs.chmod(sourcePath, 0o500);
        return Object.freeze({ virtualRoot, mountHandle: mount.mountHandle, sourcePath });
      }),
    );
    await fs.chmod(rootDir, 0o700);
    return Object.freeze({
      viewId: hashMemoryRevision("mvv1", {
        contextFingerprint: params.context.contextFingerprint,
        planId: params.plan.planId,
        mounts: roots.map((root) => `${root.virtualRoot}\0${root.mountHandle}`).toSorted(),
      }),
      rootDir,
      roots: Object.freeze(roots),
    });
  } catch (error) {
    await fs.rm(rootDir, { recursive: true, force: true });
    throw error;
  }
}
