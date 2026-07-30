/**
 * Sandbox workspace mount argument builder.
 *
 * Creates Docker bind specs for writable workspaces and read-only skill source mounts.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { isPathInside } from "../../infra/path-guards.js";
import { splitSandboxBindSpec } from "./bind-spec.js";
import { SANDBOX_AGENT_WORKSPACE_MOUNT } from "./constants.js";
import { resolveSandboxHostPathViaExistingAncestor } from "./host-paths.js";
import { normalizeContainerPath } from "./path-utils.js";
import type { SandboxMemoryVirtualMount, SandboxWorkspaceAccess } from "./types.js";

export const SANDBOX_MOUNT_FORMAT_VERSION = 4;
const MATERIALIZED_SANDBOX_SKILLS_WORKSPACE_PARTS = [".openclaw", "sandbox-skills"] as const;

/** Read-only skill directory mounted from the agent workspace into the sandbox workspace. */
export type ReadOnlyWorkspaceSkillMount = {
  hostPath: string;
  containerPath: string;
};

const MEMORY_VIRTUAL_ROOTS = new Set([
  "private",
  "channel",
  "shared",
  "projections",
  "postbox-review",
]);

function assertMemoryVirtualMount(mount: SandboxMemoryVirtualMount, workdir: string): void {
  const normalizedWorkdir = workdir.replace(/\/+$/u, "") || "/";
  const normalizedSource = path.resolve(mount.sourcePath);
  const viewRoot = path.resolve(normalizedSource, "../..");
  const tempRoot = path.resolve(os.tmpdir());
  const target = containerJoin(normalizedWorkdir, mount.virtualRoot, mount.mountHandle);
  if (
    !MEMORY_VIRTUAL_ROOTS.has(mount.virtualRoot) ||
    !/^mm1_[A-Za-z0-9_-]{24,}$/u.test(mount.mountHandle) ||
    !path.isAbsolute(mount.sourcePath) ||
    normalizedSource !== path.join(viewRoot, mount.virtualRoot, mount.mountHandle) ||
    !path.basename(viewRoot).startsWith("openclaw-memory-view-") ||
    !isPathInside(tempRoot, viewRoot) ||
    !path.posix.isAbsolute(normalizedWorkdir) ||
    path.posix.normalize(normalizedWorkdir) !== normalizedWorkdir ||
    normalizedWorkdir === "/" ||
    normalizedWorkdir === SANDBOX_AGENT_WORKSPACE_MOUNT ||
    !target.startsWith(`${normalizedWorkdir}/`)
  ) {
    throw new Error("invalid sandbox memory virtual mount");
  }
  const stat = fs.lstatSync(mount.sourcePath);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error("sandbox memory virtual mount must be a real directory");
  }
  const canonicalViewRoot = path.resolve(fs.realpathSync.native(viewRoot));
  const canonicalSource = path.resolve(fs.realpathSync.native(normalizedSource));
  if (canonicalSource !== path.join(canonicalViewRoot, mount.virtualRoot, mount.mountHandle)) {
    throw new Error("sandbox memory virtual mount must not use a symlinked ancestor");
  }
}

/** Stable config-hash input for ephemeral, read-only authorized memory mounts. */
export function formatMemoryVirtualMountHashState(
  mounts: readonly SandboxMemoryVirtualMount[],
  workdir: string,
): string[] {
  return mounts
    .map((mount) => {
      const containerPath = resolveMemoryVirtualMountContainerPath(mount, workdir);
      return `${mount.viewId}:${mount.sourcePath}:${containerPath}:ro`;
    })
    .toSorted();
}

/** Mount each authorization-specific root over the workspace as read-only. */
export function appendMemoryVirtualMountArgs(params: {
  args: string[];
  workdir: string;
  mounts: readonly SandboxMemoryVirtualMount[];
}): void {
  for (const mount of [...params.mounts].toSorted((left, right) =>
    `${left.virtualRoot}/${left.mountHandle}`.localeCompare(
      `${right.virtualRoot}/${right.mountHandle}`,
    ),
  )) {
    const containerPath = resolveMemoryVirtualMountContainerPath(mount, params.workdir);
    params.args.push(
      "-v",
      formatManagedWorkspaceBind({
        hostPath: mount.sourcePath,
        containerPath,
        readOnly: true,
      }),
    );
  }
}

function formatManagedWorkspaceBind(params: {
  hostPath: string;
  containerPath: string;
  readOnly: boolean;
}): string {
  return `${params.hostPath}:${params.containerPath}:${params.readOnly ? "ro,z" : "z"}`;
}

function containerJoin(root: string, ...parts: string[]): string {
  const normalizedRoot = root.endsWith("/") && root !== "/" ? root.slice(0, -1) : root;
  const suffix = parts
    .map((part) => part.replace(/^\/+|\/+$/g, ""))
    .filter(Boolean)
    .join("/");
  return suffix ? `${normalizedRoot}/${suffix}` : normalizedRoot;
}

function normalizeMountContainerPath(containerPath: string): string {
  return normalizeContainerPath(containerPath).replace(/\/+$/, "") || "/";
}

function resolveMemoryVirtualMountContainerPath(
  mount: SandboxMemoryVirtualMount,
  workdir: string,
): string {
  assertMemoryVirtualMount(mount, workdir);
  return containerJoin(workdir, mount.virtualRoot, mount.mountHandle);
}

/** Returns normalized memory targets reserved from custom bind mounts. */
export function resolveMemoryVirtualMountContainerPaths(params: {
  mounts: readonly SandboxMemoryVirtualMount[];
  workdir: string;
}): Set<string> {
  return new Set(
    params.mounts.map((mount) =>
      normalizeMountContainerPath(resolveMemoryVirtualMountContainerPath(mount, params.workdir)),
    ),
  );
}

/** Hidden workspace used to materialize non-workspace skills for rw sandboxes. */
export function resolveMaterializedSandboxSkillsWorkspaceDir(rootDir: string): string {
  return path.join(rootDir, ...MATERIALIZED_SANDBOX_SKILLS_WORKSPACE_PARTS);
}

/** Returns true when a skill mount source exists inside the canonical mount root. */
export function isExistingWorkspaceSkillMountSource(params: {
  rootDir: string;
  hostPath: string;
}): boolean {
  try {
    if (!fs.lstatSync(params.hostPath).isDirectory()) {
      return false;
    }
  } catch {
    return false;
  }

  const agentRoot = resolveSandboxHostPathViaExistingAncestor(path.resolve(params.rootDir));
  const canonicalSource = resolveSandboxHostPathViaExistingAncestor(path.resolve(params.hostPath));
  return isPathInside(agentRoot, canonicalSource);
}

/** Finds agent-workspace skill directories that should be mounted read-only in rw workspaces. */
export function resolveReadOnlyWorkspaceSkillMounts(params: {
  workspaceDir: string;
  agentWorkspaceDir: string;
  skillsWorkspaceDir?: string;
  workdir: string;
  workspaceAccess: SandboxWorkspaceAccess;
}): ReadOnlyWorkspaceSkillMount[] {
  if (params.workspaceAccess !== "rw") {
    return [];
  }

  // RW workspaces mount the project as writable, but skill sources remain read-only so agent
  // instructions are visible without letting sandbox commands mutate them.
  const materializedSkillsWorkspaceDir =
    params.skillsWorkspaceDir ??
    resolveMaterializedSandboxSkillsWorkspaceDir(params.agentWorkspaceDir);
  const mounts = [
    {
      hostPath: path.join(params.agentWorkspaceDir, "skills"),
      containerPath: containerJoin(params.workdir, "skills"),
      rootDir: params.agentWorkspaceDir,
    },
    {
      hostPath: path.join(params.agentWorkspaceDir, ".agents", "skills"),
      containerPath: containerJoin(params.workdir, ".agents", "skills"),
      rootDir: params.agentWorkspaceDir,
    },
    {
      hostPath: path.join(materializedSkillsWorkspaceDir, "skills"),
      containerPath: containerJoin(
        params.workdir,
        ...MATERIALIZED_SANDBOX_SKILLS_WORKSPACE_PARTS,
        "skills",
      ),
      rootDir: materializedSkillsWorkspaceDir,
    },
  ];

  return mounts
    .filter((mount) =>
      isExistingWorkspaceSkillMountSource({
        rootDir: mount.rootDir,
        hostPath: mount.hostPath,
      }),
    )
    .map(({ hostPath, containerPath }) => ({ hostPath, containerPath }));
}

/** Returns stable mount state for sandbox config hashes. */
export function formatReadOnlyWorkspaceSkillMountHashState(
  mounts: readonly ReadOnlyWorkspaceSkillMount[],
): string[] {
  return mounts.map((mount) => `${mount.hostPath}:${mount.containerPath}:ro`);
}

/**
 * Returns the set of container paths that are protected by read-only skill mounts.
 *
 * User-defined binds that target any path in this set must be skipped so the
 * container engine sees one authoritative read-only mount for each destination.
 */
export function resolveProtectedSkillMountContainerPaths(
  mounts: readonly ReadOnlyWorkspaceSkillMount[],
): Set<string> {
  return new Set(mounts.map((mount) => normalizeMountContainerPath(mount.containerPath)));
}

/**
 * Returns a filtered copy of `binds` with entries whose container path conflicts with a
 * protected mount removed. Protected mounts always take precedence so checked-in skills and
 * authorized memory views cannot be shadowed by a user bind.
 */
export function filterBindsConflictingWithProtectedMounts(
  binds: readonly string[] | undefined,
  protectedContainerPaths: ReadonlySet<string>,
): string[] {
  if (!binds?.length) {
    return [];
  }
  if (protectedContainerPaths.size === 0) {
    return [...binds];
  }
  const filtered: string[] = [];
  for (const bind of binds) {
    const spec = splitSandboxBindSpec(bind);
    if (!spec) {
      filtered.push(bind);
      continue;
    }
    const containerPath = normalizeMountContainerPath(spec.container);
    if (!protectedContainerPaths.has(containerPath)) {
      filtered.push(bind);
    }
  }
  return filtered;
}

/** Appends Docker `-v` args for read-only skill mounts. */
export function appendReadOnlyWorkspaceSkillMountArgs(params: {
  args: string[];
  readOnlyWorkspaceSkillMounts: readonly ReadOnlyWorkspaceSkillMount[];
}): void {
  for (const mount of params.readOnlyWorkspaceSkillMounts) {
    params.args.push(
      "-v",
      formatManagedWorkspaceBind({
        hostPath: mount.hostPath,
        containerPath: mount.containerPath,
        readOnly: true,
      }),
    );
  }
}

/** Appends Docker workspace mount args for the project, agent workspace, and skill overlays. */
export function appendWorkspaceMountArgs(params: {
  args: string[];
  workspaceDir: string;
  agentWorkspaceDir: string;
  skillsWorkspaceDir?: string;
  workdir: string;
  workspaceAccess: SandboxWorkspaceAccess;
  readOnlyWorkspaceSkillMounts?: readonly ReadOnlyWorkspaceSkillMount[];
  includeReadOnlyWorkspaceSkillMounts?: boolean;
}) {
  const { args, workspaceDir, agentWorkspaceDir, workdir, workspaceAccess } = params;

  args.push(
    "-v",
    formatManagedWorkspaceBind({
      hostPath: workspaceDir,
      containerPath: workdir,
      readOnly: workspaceAccess !== "rw",
    }),
  );

  if (workspaceAccess !== "none" && workspaceDir !== agentWorkspaceDir) {
    args.push(
      "-v",
      formatManagedWorkspaceBind({
        hostPath: agentWorkspaceDir,
        containerPath: SANDBOX_AGENT_WORKSPACE_MOUNT,
        readOnly: workspaceAccess === "ro",
      }),
    );
  }

  if (params.includeReadOnlyWorkspaceSkillMounts !== false) {
    appendReadOnlyWorkspaceSkillMountArgs({
      args,
      readOnlyWorkspaceSkillMounts:
        params.readOnlyWorkspaceSkillMounts ??
        resolveReadOnlyWorkspaceSkillMounts({
          workspaceDir,
          agentWorkspaceDir,
          skillsWorkspaceDir: params.skillsWorkspaceDir,
          workdir,
          workspaceAccess,
        }),
    });
  }
}
