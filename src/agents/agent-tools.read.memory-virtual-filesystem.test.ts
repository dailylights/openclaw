import { describe, expect, it, vi } from "vitest";
import { wrapReadToolWithMemoryVirtualFilesystem } from "./agent-tools.read.js";
import type { AnyAgentTool } from "./agent-tools.types.js";

const validVirtualPath = "private/mm1_abcdefghijklmnopqrstuvwx/mrh1_abcdefghijklmnopqrstuvwx.md";

function createTool() {
  const execute = vi.fn(async () => ({ content: [{ type: "text", text: "host file" }] }));
  const tool = {
    name: "read",
    description: "test read",
    inputSchema: { type: "object", properties: {} },
    execute,
  } as unknown as AnyAgentTool;
  return { execute, tool };
}

function virtualOrReservedPath(pathname: string): string | undefined {
  return pathname.normalize("NFKC").replaceAll("\\", "/").split("/", 1)[0]?.toLowerCase() ===
    "private"
    ? pathname
    : undefined;
}

describe("wrapReadToolWithMemoryVirtualFilesystem", () => {
  it("serves an authorized opaque virtual path through the broker", async () => {
    const { execute, tool } = createTool();
    const readVirtualPath = vi.fn(async () => ({
      path: validVirtualPath,
      text: "authorized text",
      truncated: true,
      nextFrom: 21,
    }));
    const wrapped = wrapReadToolWithMemoryVirtualFilesystem(tool, {
      resolveVirtualPath: virtualOrReservedPath,
      isControlledWorkspacePath: () => false,
      readVirtualPath,
    });

    await expect(wrapped.execute("call-1", { path: validVirtualPath })).resolves.toMatchObject({
      content: [
        {
          type: "text",
          text: "authorized text\n\n[More lines are available. Use offset=21 to continue.]",
        },
      ],
      details: { path: validVirtualPath },
    });
    expect(readVirtualPath).toHaveBeenCalledWith({ path: validVirtualPath });
    expect(execute).not.toHaveBeenCalled();
  });

  it("fails closed for stale and traversal-shaped virtual paths without calling the host tool", async () => {
    const { execute, tool } = createTool();
    const readVirtualPath = vi.fn(async () => ({ unavailable: true }));
    const wrapped = wrapReadToolWithMemoryVirtualFilesystem(tool, {
      resolveVirtualPath: virtualOrReservedPath,
      isControlledWorkspacePath: () => false,
      readVirtualPath,
    });

    await expect(wrapped.execute("call-stale", { path: validVirtualPath })).rejects.toThrow(
      "Memory virtual path is unavailable.",
    );
    await expect(
      wrapped.execute("call-traverse", {
        path: "private/mm1_abcdefghijklmnopqrstuvwx/../../MEMORY.md",
      }),
    ).rejects.toThrow("Memory virtual path is unavailable.");
    expect(execute).not.toHaveBeenCalled();
  });

  it.each([
    `PRIVATE/mm1_abcdefghijklmnopqrstuvwx/mrh1_abcdefghijklmnopqrstuvwx.md`,
    `ｐｒｉｖａｔｅ/mm1_abcdefghijklmnopqrstuvwx/mrh1_abcdefghijklmnopqrstuvwx.md`,
    "private/mm1_abcdefghijklmnopqrstuvwx/../../MEMORY.md",
  ])("does not fall through reserved virtual path %s to the host tool", async (pathname) => {
    const { execute, tool } = createTool();
    const wrapped = wrapReadToolWithMemoryVirtualFilesystem(tool, {
      resolveVirtualPath: virtualOrReservedPath,
      isControlledWorkspacePath: () => false,
      readVirtualPath: async () => ({ unavailable: true }),
    });

    await expect(wrapped.execute("call-reserved", { path: pathname })).rejects.toThrow(
      "Memory virtual path is unavailable.",
    );
    expect(execute).not.toHaveBeenCalled();
  });

  it("rejects raw controlled memory paths before the underlying file tool", async () => {
    const { execute, tool } = createTool();
    const wrapped = wrapReadToolWithMemoryVirtualFilesystem(tool, {
      resolveVirtualPath: virtualOrReservedPath,
      isControlledWorkspacePath: async (pathname) => pathname === "/workspace/MEMORY.md",
      readVirtualPath: async () => ({ unavailable: true }),
    });

    await expect(
      wrapped.execute("call-controlled", { path: "/workspace/MEMORY.md" }),
    ).rejects.toThrow("Raw controlled-memory paths are unavailable.");
    expect(execute).not.toHaveBeenCalled();
  });
});
