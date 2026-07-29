import {
  readChannelIngressMemorySubjectCapability,
  type ChannelIngressMemorySubjectCapability,
} from "../../channels/message-access/memory-subject-capability.js";
import {
  prepareAmbiguousSessionMemorySubjectSeed,
  prepareChannelBindingSessionMemorySubjectSeed,
  prepareConversationSessionMemorySubjectSeed,
  type TrustedSessionMemorySubjectSeed,
} from "../../config/sessions/session-accessor.js";

/** Converts an opaque admitted-ingress capability into the seed owned by session storage. */
export function prepareChannelIngressSessionMemorySubjectSeed(
  capability: ChannelIngressMemorySubjectCapability | undefined,
): TrustedSessionMemorySubjectSeed {
  const facts = readChannelIngressMemorySubjectCapability(capability);
  if (!facts || facts.kind === "ambiguous") {
    return prepareAmbiguousSessionMemorySubjectSeed("unbound");
  }
  return facts.kind === "conversation"
    ? prepareConversationSessionMemorySubjectSeed(facts)
    : prepareChannelBindingSessionMemorySubjectSeed(facts);
}
