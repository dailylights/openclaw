// Memory sharing CLI tests cover its Gateway-only control-plane mapping.
import { Command } from "commander";
import type { callGatewayFromCli } from "openclaw/plugin-sdk/gateway-runtime";
import { describe, expect, it, vi } from "vitest";
import { registerMemoryCli } from "./cli.js";
import { registerMemorySharingCli } from "./memory-sharing-cli.js";

function createSharingCli() {
  const callGateway = vi.fn<typeof callGatewayFromCli>(async () => ({ accepted: true }));
  const writeResult = vi.fn();
  const program = new Command();
  program.name("test");
  program.exitOverride();
  program.configureOutput({ writeErr: () => {}, writeOut: () => {} });
  const memory = program.command("memory");
  registerMemorySharingCli(memory, { callGateway, writeResult });
  return { callGateway, program, writeResult };
}

async function runSharingCommand(program: Command, args: readonly string[]) {
  await program.parseAsync(["memory", "sharing", ...args], { from: "user" });
}

describe("memory sharing CLI", () => {
  it("registers sharing beneath the memory command", () => {
    const program = new Command();
    registerMemoryCli(program);

    const memory = program.commands.find((command) => command.name() === "memory");
    expect(memory?.commands.map((command) => command.name())).toContain("sharing");
  });

  it.each([
    {
      name: "status",
      args: [
        "status",
        "--agent",
        "operator-1",
        "--url",
        "ws://gateway.test",
        "--token",
        "cli-token",
        "--timeout",
        "1234",
        "--json",
      ],
      method: "memory.sharing.status",
      params: {},
    },
    {
      name: "postbox list",
      args: ["postbox", "list", "--agent", "operator-1"],
      method: "memory.sharing.postbox.list",
      params: {},
    },
    {
      name: "postbox inspect",
      args: ["postbox", "inspect", "--agent", "operator-1", "--postbox-item-id", "postbox-1"],
      method: "memory.sharing.postbox.inspect",
      params: { postboxItemId: "postbox-1" },
    },
    {
      name: "projection preview",
      args: [
        "projection",
        "preview",
        "--agent",
        "operator-1",
        "--source-revision",
        "revision-1",
        "--target-kind",
        "role",
        "--target-id",
        "support",
        "--purpose",
        "handoff continuity",
        "--expires-at",
        "2026-09-01T00:00:00.000Z",
        "--supersedes-projection-id",
        "  projection-old  ",
      ],
      method: "memory.sharing.projection.preview",
      params: {
        sourceRevisionId: "revision-1",
        targetKind: "role",
        targetId: "support",
        purpose: "handoff continuity",
        expiresAt: "2026-09-01T00:00:00.000Z",
        supersedesProjectionId: "projection-old",
      },
    },
    {
      name: "projection create",
      args: ["projection", "create", "--agent", "operator-1", "--preview-id", "preview-1"],
      method: "memory.sharing.projection.create",
      params: { previewId: "preview-1" },
    },
    {
      name: "projection refresh",
      args: ["projection", "refresh", "--agent", "operator-1", "--preview-id", "preview-1"],
      method: "memory.sharing.projection.refresh",
      params: { previewId: "preview-1" },
    },
    {
      name: "projection review",
      args: [
        "projection",
        "review",
        "--agent",
        "operator-1",
        "--projection-id",
        "projection-1",
        "--decision",
        "reject",
        "--reason",
        "  outside the approved purpose  ",
      ],
      method: "memory.sharing.projection.review",
      params: {
        projectionId: "projection-1",
        decision: "reject",
        reason: "outside the approved purpose",
      },
    },
    {
      name: "projection revoke",
      args: ["projection", "revoke", "--agent", "operator-1", "--projection-id", "projection-1"],
      method: "memory.sharing.projection.revoke",
      params: { projectionId: "projection-1" },
    },
    {
      name: "projection impact",
      args: ["projection", "impact", "--agent", "operator-1", "--projection-id", "projection-1"],
      method: "memory.sharing.projection.impact",
      params: { projectionId: "projection-1" },
    },
    {
      name: "postbox review",
      args: [
        "postbox",
        "review",
        "--agent",
        "operator-1",
        "--postbox-item-id",
        "postbox-1",
        "--decision",
        "approve",
        "--edited-content",
        "  owner-entered replacement  ",
      ],
      method: "memory.sharing.postbox.review",
      params: {
        postboxItemId: "postbox-1",
        decision: "approve",
        editedContent: "owner-entered replacement",
      },
    },
    {
      name: "postbox purge",
      args: ["postbox", "purge", "--agent", "operator-1", "--postbox-item-id", "postbox-1"],
      method: "memory.sharing.postbox.purge",
      params: { postboxItemId: "postbox-1" },
    },
  ])("routes $name through the reviewed Gateway surface", async ({ args, method, params }) => {
    const { callGateway, program, writeResult } = createSharingCli();

    await runSharingCommand(program, args);

    expect(callGateway).toHaveBeenCalledOnce();
    expect(callGateway).toHaveBeenCalledWith(
      method,
      expect.objectContaining({ agent: "operator-1" }),
      { agentId: "operator-1", ...params },
      { scopes: ["operator.admin"] },
    );
    expect(writeResult).toHaveBeenCalledExactlyOnceWith({ accepted: true });

    if (method === "memory.sharing.status") {
      expect(callGateway.mock.calls[0]?.[1]).toMatchObject({
        agent: "operator-1",
        url: "ws://gateway.test",
        token: "cli-token",
        timeout: "1234",
        json: true,
      });
    }
  });

  it("requires a nonblank agent before Gateway delegation", async () => {
    const { callGateway, program, writeResult } = createSharingCli();

    await expect(runSharingCommand(program, ["status", "--agent", "   "])).rejects.toThrow(
      "--agent is required.",
    );

    expect(callGateway).not.toHaveBeenCalled();
    expect(writeResult).not.toHaveBeenCalled();
  });

  it.each([
    ["projection", "review", "--projection-id", "projection-1"],
    ["postbox", "review", "--postbox-item-id", "postbox-1"],
  ])("requires a nonblank reject reason before Gateway delegation: %s", async (...prefix) => {
    const { callGateway, program, writeResult } = createSharingCli();

    await expect(
      runSharingCommand(program, [
        ...prefix,
        "--agent",
        "operator-1",
        "--decision",
        "reject",
        "--reason",
        "   ",
      ]),
    ).rejects.toThrow("--reason is required when --decision reject.");

    expect(callGateway).not.toHaveBeenCalled();
    expect(writeResult).not.toHaveBeenCalled();
  });
});
