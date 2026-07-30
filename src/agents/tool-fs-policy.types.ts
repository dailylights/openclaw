/** Runtime-light description of a plugin-issued virtual memory mount. */
export type ToolFsVirtualMemoryMount = Readonly<{
  virtualRoot: "private" | "channel" | "shared" | "projections" | "postbox-review";
  mountHandle: string;
}>;

type ToolFsWorkspacePolicy = {
  kind: "workspace";
  workspaceOnly: boolean;
};

type ToolFsAuthorizedMemoryVirtualPolicy = {
  kind: "authorized-memory-virtual";
  workspaceOnly: true;
  memoryMounts: readonly ToolFsVirtualMemoryMount[];
};

type ToolFsSandboxMountPlanPolicy = {
  kind: "sandbox-memory-mount-plan";
  workspaceOnly: true;
  memoryMounts: readonly ToolFsVirtualMemoryMount[];
  viewId: string;
};

type ToolFsBlockedMemoryPolicy = {
  kind: "memory-blocked";
  workspaceOnly: true;
  reason: "memory-unavailable" | "sandbox-view-unavailable";
};

/** Closed filesystem policy for ordinary workspaces and enforced memory views. */
export type ToolFsPolicy =
  | ToolFsWorkspacePolicy
  | ToolFsAuthorizedMemoryVirtualPolicy
  | ToolFsSandboxMountPlanPolicy
  | ToolFsBlockedMemoryPolicy;
