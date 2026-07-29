// Synology Chat plugin module implements inbound context behavior.
import type { ResolvedChannelMessageIngress } from "openclaw/plugin-sdk/channel-ingress-runtime";

type ChannelIngressMemorySubjectCapability = NonNullable<
  ResolvedChannelMessageIngress["memorySubjectCapability"]
>;

export type SynologyInboundMessage = {
  memorySubjectCapability?: ChannelIngressMemorySubjectCapability;
  body: string;
  from: string;
  senderName: string;
  provider: string;
  chatType: string;
  accountId: string;
  commandAuthorized: boolean;
  chatUserId?: string;
};
