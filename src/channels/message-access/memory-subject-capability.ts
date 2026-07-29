import type { ChannelIngressDecision, ChannelIngressStateInput } from "./types.js";

const channelIngressMemorySubjectCapabilityBrand: unique symbol = Symbol(
  "openclaw.channel-ingress-memory-subject-capability",
);

type ChannelIngressMemorySubjectFacts =
  | Readonly<{
      kind: "conversation";
      channel: string;
      accountId: string;
      conversationId: string;
    }>
  | Readonly<{
      kind: "isolated-dm";
      channel: string;
      accountId: string;
      stableSenderId: string;
    }>
  | Readonly<{ kind: "ambiguous" }>;

/**
 * Opaque proof that a subject candidate came from the authenticated channel
 * ingress resolver rather than message text or the extensible prompt context.
 */
export type ChannelIngressMemorySubjectCapability = Readonly<{
  [channelIngressMemorySubjectCapabilityBrand]: true;
}>;

const trustedCapabilities = new WeakMap<object, ChannelIngressMemorySubjectFacts>();

function requireText(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized) {
    throw new TypeError(`${label} must not be empty`);
  }
  return normalized;
}

export function createChannelIngressMemorySubjectCapability(params: {
  channel: string;
  accountId: string;
  conversation: ChannelIngressStateInput["conversation"];
  ingress: ChannelIngressDecision;
  stableSenderId?: string;
}): ChannelIngressMemorySubjectCapability {
  const admitted =
    params.ingress.decision === "allow" &&
    (params.ingress.admission === "dispatch" || params.ingress.admission === "observe");
  let facts: ChannelIngressMemorySubjectFacts = { kind: "ambiguous" };
  if (admitted && params.conversation.kind !== "direct") {
    facts = {
      kind: "conversation",
      channel: requireText(params.channel, "channel").toLowerCase(),
      accountId: requireText(params.accountId, "accountId"),
      conversationId: requireText(params.conversation.id, "conversationId"),
    };
  } else if (admitted && params.stableSenderId) {
    facts = {
      kind: "isolated-dm",
      channel: requireText(params.channel, "channel").toLowerCase(),
      accountId: requireText(params.accountId, "accountId"),
      stableSenderId: requireText(params.stableSenderId, "stableSenderId"),
    };
  }

  const capability = {} as {
    [channelIngressMemorySubjectCapabilityBrand]?: true;
  };
  Object.defineProperty(capability, channelIngressMemorySubjectCapabilityBrand, {
    value: true,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  trustedCapabilities.set(capability, Object.freeze(facts));
  return Object.freeze(capability) as ChannelIngressMemorySubjectCapability;
}

/** Internal consumer used only after the opaque capability reaches core reply dispatch. */
export function readChannelIngressMemorySubjectCapability(
  capability: ChannelIngressMemorySubjectCapability | undefined,
): ChannelIngressMemorySubjectFacts | undefined {
  if (
    !capability ||
    !Object.isFrozen(capability) ||
    (capability as Record<symbol, unknown>)[channelIngressMemorySubjectCapabilityBrand] !== true
  ) {
    return undefined;
  }
  return trustedCapabilities.get(capability);
}
