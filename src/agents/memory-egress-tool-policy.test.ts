import { describe, expect, it, vi } from "vitest";
import type { AnyAgentTool } from "./agent-tools.types.js";

const mocks = vi.hoisted(() => ({ blocked: false }));

vi.mock("../plugins/memory-invocation.js", () => ({
  isMemoryScopedToolEgressBlocked: () => mocks.blocked,
}));

const { wrapToolWithMemoryEgressPolicy } = await import("./memory-egress-tool-policy.js");

function createTool(name: string) {
  const execute = vi.fn(async () => ({ content: [{ type: "text", text: "ok" }] }));
  const tool = {
    name,
    description: "test tool",
    inputSchema: { type: "object", properties: {} },
    execute,
  } as unknown as AnyAgentTool;
  return { execute, tool };
}

describe("wrapToolWithMemoryEgressPolicy", () => {
  it("allows ordinary tool calls before scoped content is exposed", async () => {
    mocks.blocked = false;
    const { execute, tool } = createTool("message");
    const wrapped = wrapToolWithMemoryEgressPolicy(tool, {} as never);

    await expect(wrapped.execute("before-exposure", {})).resolves.toBeDefined();
    expect(execute).toHaveBeenCalledOnce();
  });

  it.each([
    "message",
    "browser",
    "process",
    "sessions_send",
    "mcp_server__call",
    "unknown_plugin_tool",
  ])("denies %s after scoped content is exposed", async (name) => {
    mocks.blocked = true;
    const { execute, tool } = createTool(name);
    const wrapped = wrapToolWithMemoryEgressPolicy(tool, {} as never);

    await expect(wrapped.execute("after-exposure", {})).rejects.toThrow("Memory egress capability");
    expect(execute).not.toHaveBeenCalled();
  });

  it("keeps only model-read-only tools callable after exposure", async () => {
    mocks.blocked = true;
    const { execute, tool } = createTool("read");
    const wrapped = wrapToolWithMemoryEgressPolicy(tool, {} as never);

    await expect(wrapped.execute("read-after-exposure", {})).resolves.toBeDefined();
    expect(execute).toHaveBeenCalledOnce();
  });
});
