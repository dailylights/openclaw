import { describe, expect, it } from "vitest";
import { readChannelIngressMemorySubjectCapability } from "./memory-subject-capability.js";
import { resolveStableChannelMessageIngress } from "./runtime.js";

async function resolveIngress(params: {
  conversation: { kind: "direct" | "group" | "channel"; id: string };
  stableId?: string;
  dmPolicy?: "open" | "disabled";
  groupPolicy?: "open" | "disabled";
}) {
  return await resolveStableChannelMessageIngress({
    channelId: "test-channel",
    accountId: "account-1",
    subject: { stableId: params.stableId },
    conversation: params.conversation,
    dmPolicy: params.dmPolicy ?? "open",
    groupPolicy: params.groupPolicy ?? "open",
    allowFrom: ["*"],
    groupAllowFrom: ["*"],
  });
}

describe("channel ingress memory subject capability", () => {
  it("carries only the normalized stable sender for an admitted direct message", async () => {
    const resolved = await resolveIngress({
      conversation: { kind: "direct", id: "dm-route" },
      stableId: "  sender-1  ",
    });

    expect(readChannelIngressMemorySubjectCapability(resolved.memorySubjectCapability)).toEqual({
      kind: "isolated-dm",
      channel: "test-channel",
      accountId: "account-1",
      stableSenderId: "sender-1",
    });
    expect(JSON.stringify(resolved.memorySubjectCapability)).toBe("{}");
  });

  it.each(["group", "channel"] as const)(
    "carries the admitted %s conversation instead of its actor",
    async (kind) => {
      const resolved = await resolveIngress({
        conversation: { kind, id: "room-1" },
        stableId: "sender-1",
      });

      expect(readChannelIngressMemorySubjectCapability(resolved.memorySubjectCapability)).toEqual({
        kind: "conversation",
        channel: "test-channel",
        accountId: "account-1",
        conversationId: "room-1",
      });
    },
  );

  it("downgrades blocked or sender-less events to ambiguous facts", async () => {
    const blocked = await resolveIngress({
      conversation: { kind: "group", id: "room-1" },
      stableId: "sender-1",
      groupPolicy: "disabled",
    });
    const senderless = await resolveIngress({
      conversation: { kind: "direct", id: "dm-route" },
    });

    expect(readChannelIngressMemorySubjectCapability(blocked.memorySubjectCapability)).toEqual({
      kind: "ambiguous",
    });
    expect(readChannelIngressMemorySubjectCapability(senderless.memorySubjectCapability)).toEqual({
      kind: "ambiguous",
    });
  });

  it("rejects capability-shaped objects that did not come from the resolver", () => {
    expect(
      readChannelIngressMemorySubjectCapability(
        Object.freeze({}) as NonNullable<
          Awaited<ReturnType<typeof resolveIngress>>["memorySubjectCapability"]
        >,
      ),
    ).toBeUndefined();
  });
});
