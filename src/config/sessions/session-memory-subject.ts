import { normalizeAgentId } from "@openclaw/normalization-core/agent-id";
import type { SessionMemorySubject } from "../../memory-host-sdk/host/authorization.js";
import {
  memoryIdentityLifecycle,
  type MemoryIdentityBindingAssurance,
} from "../../state/memory-identity.js";
import type { OpenClawStateDatabaseOptions } from "../../state/openclaw-state-db.js";
import {
  createTrustedSessionMemorySubjectSeed,
  InvalidSessionMemorySubjectSeedError,
  isTrustedSessionMemorySubjectSnapshot,
  requireSessionMemorySubjectText,
  type TrustedSessionMemorySubjectSeed,
  type TrustedSessionMemorySubjectSnapshot,
} from "./session-memory-subject-trust.js";

export {
  persistSessionMemorySubjectInTransaction,
  prepareCurrentSessionMemorySubjectLineageSeedInTransaction,
  readOrCreateSessionMemorySubjectInTransaction,
  readSessionMemorySubjectFromDatabase,
  rehomeSessionMemorySubjectAliases,
  restoreSessionMemorySubjectIdentityRevisionInTransaction,
  tryRehomeSessionMemorySubjectSnapshot,
} from "./session-memory-subject-persistence.js";
export {
  InvalidSessionMemorySubjectSeedError,
  prepareSessionMemorySubjectLineageSeed,
  SessionMemorySubjectReboundError,
} from "./session-memory-subject-trust.js";
export type {
  SessionMemoryScope,
  TrustedSessionMemorySubjectSeed,
  TrustedSessionMemorySubjectSnapshot,
} from "./session-memory-subject-trust.js";

const {
  ensureConversationMemoryPrincipal,
  ensureExplicitMemoryPrincipal,
  ensureGatewayProfileMemoryPrincipal,
  resolveCurrentMemoryIdentityBinding,
  resolveMemoryIdentityBinding,
  resolveMemoryPrincipal,
} = memoryIdentityLifecycle;

export type SessionMemorySubjectAuthority =
  | Readonly<{
      kind: "current";
      currentPrincipalId?: string;
      assurance?: "gateway-profile" | MemoryIdentityBindingAssurance | "service";
      evidenceRevision?: string;
      expiresAt?: number;
    }>
  | Readonly<{
      kind: "denied";
      reason: "ambiguous" | "binding-revoked" | "principal-revoked" | "shared-main-private-subject";
    }>;

export function prepareGatewayProfileSessionMemorySubjectSeed(
  profileId: string,
  options: OpenClawStateDatabaseOptions = {},
): TrustedSessionMemorySubjectSeed | undefined {
  const principal = ensureGatewayProfileMemoryPrincipal(profileId, options);
  return principal
    ? createTrustedSessionMemorySubjectSeed({
        subject: {
          version: 1,
          kind: "user",
          principalId: principal.principalId,
          creationEvidence: {
            kind: "gateway-profile",
            revision: principal.evidenceRevision,
          },
        },
      })
    : undefined;
}

export function prepareChannelBindingSessionMemorySubjectSeed(params: {
  channel: string;
  accountId: string;
  stableSenderId: string;
  now?: number;
  options?: OpenClawStateDatabaseOptions;
}): TrustedSessionMemorySubjectSeed {
  const resolution = resolveMemoryIdentityBinding(params);
  if (resolution.kind === "conflicting-bindings") {
    return createTrustedSessionMemorySubjectSeed({
      subject: { version: 1, kind: "ambiguous", reason: "conflicting-bindings" },
    });
  }
  if (resolution.kind === "unbound") {
    return createTrustedSessionMemorySubjectSeed({
      subject: { version: 1, kind: "ambiguous", reason: "unbound" },
    });
  }
  return createTrustedSessionMemorySubjectSeed({
    subject: {
      version: 1,
      kind: "user",
      principalId: resolution.principalId,
      creationEvidence: {
        kind: "channel-binding",
        revision: resolution.evidenceRevision,
      },
    },
    creationBindingId: resolution.bindingId,
  });
}

export function prepareConversationSessionMemorySubjectSeed(params: {
  channel: string;
  accountId: string;
  conversationId: string;
  canonicalConversationRef?: string;
  now?: number;
  options?: OpenClawStateDatabaseOptions;
}): TrustedSessionMemorySubjectSeed {
  const channel = requireSessionMemorySubjectText(params.channel, "channel").toLowerCase();
  const accountId = requireSessionMemorySubjectText(params.accountId, "accountId");
  const principal = ensureConversationMemoryPrincipal({
    channel,
    accountId,
    conversationId: params.conversationId,
    now: params.now,
    options: params.options,
  });
  return createTrustedSessionMemorySubjectSeed({
    subject: {
      version: 1,
      kind: "conversation",
      conversationPrincipalId: principal.principalId,
      channel,
      accountId,
    },
    canonicalConversationRef: params.canonicalConversationRef,
  });
}

export function prepareExplicitSessionMemorySubjectSeed(params: {
  kind: "service" | "agent" | "system";
  stableSubjectId: string;
  issuer?: string;
  now?: number;
  expiresAt?: number;
  options?: OpenClawStateDatabaseOptions;
}): TrustedSessionMemorySubjectSeed {
  const principal = ensureExplicitMemoryPrincipal(params);
  return createTrustedSessionMemorySubjectSeed({
    subject: {
      version: 1,
      kind: params.kind,
      principalId: principal.principalId,
    },
  });
}

/** Resolves autonomous work to the stable principal owned by one canonical agent. */
export function prepareAutonomousAgentSessionMemorySubjectSeed(
  agentId: string,
  options: OpenClawStateDatabaseOptions = {},
): TrustedSessionMemorySubjectSeed {
  const canonicalAgentId = normalizeAgentId(requireSessionMemorySubjectText(agentId, "agentId"));
  return prepareExplicitSessionMemorySubjectSeed({
    kind: "agent",
    stableSubjectId: canonicalAgentId,
    options,
  });
}

export function prepareAmbiguousSessionMemorySubjectSeed(
  reason: Extract<SessionMemorySubject, { kind: "ambiguous" }>["reason"],
): TrustedSessionMemorySubjectSeed {
  return createTrustedSessionMemorySubjectSeed({
    subject: { version: 1, kind: "ambiguous", reason },
  });
}

export function resolveSessionMemorySubjectAuthority(
  snapshot: TrustedSessionMemorySubjectSnapshot,
  options: OpenClawStateDatabaseOptions = {},
  now = Date.now(),
): SessionMemorySubjectAuthority {
  if (!isTrustedSessionMemorySubjectSnapshot(snapshot)) {
    throw new InvalidSessionMemorySubjectSeedError();
  }
  if (snapshot.sessionScope === "shared-main" && snapshot.subject.kind !== "ambiguous") {
    return { kind: "denied", reason: "shared-main-private-subject" };
  }
  const subject = snapshot.subject;
  if (subject.kind === "ambiguous") {
    return { kind: "denied", reason: "ambiguous" };
  }
  const principalId =
    subject.kind === "conversation" ? subject.conversationPrincipalId : subject.principalId;
  const principal = resolveMemoryPrincipal(principalId, options, now);
  if (principal.kind !== "current") {
    return { kind: "denied", reason: "principal-revoked" };
  }
  let currentPrincipal = principal.principal;
  if (currentPrincipal.kind === "gateway-profile") {
    if (!currentPrincipal.userProfileId) {
      return { kind: "denied", reason: "principal-revoked" };
    }
    const reconciled = ensureGatewayProfileMemoryPrincipal(currentPrincipal.userProfileId, options);
    if (!reconciled) {
      return { kind: "denied", reason: "principal-revoked" };
    }
    currentPrincipal = reconciled;
  }
  if (subject.kind === "user" && snapshot.creationBindingId) {
    const binding = resolveCurrentMemoryIdentityBinding({
      bindingId: snapshot.creationBindingId,
      principalId: subject.principalId,
      evidenceRevision: subject.creationEvidence.revision,
      now,
      options,
    });
    if (binding.kind !== "verified") {
      // Distinguish a principal revoked between the first check and the binding
      // recheck from a revoked binding while still failing both races closed.
      const latestPrincipal = resolveMemoryPrincipal(subject.principalId, options, now);
      return latestPrincipal.kind === "current"
        ? { kind: "denied", reason: "binding-revoked" }
        : { kind: "denied", reason: "principal-revoked" };
    }
    return {
      kind: "current",
      currentPrincipalId: binding.principalId,
      assurance: binding.assurance,
      evidenceRevision: binding.evidenceRevision,
      ...(binding.expiresAt === undefined ? {} : { expiresAt: binding.expiresAt }),
    };
  }
  return {
    kind: "current",
    currentPrincipalId: currentPrincipal.principalId,
    assurance:
      subject.kind === "user" && subject.creationEvidence.kind === "gateway-profile"
        ? "gateway-profile"
        : subject.kind === "service" || subject.kind === "agent" || subject.kind === "system"
          ? "service"
          : undefined,
    evidenceRevision: currentPrincipal.evidenceRevision,
    ...(currentPrincipal.expiresAt === undefined ? {} : { expiresAt: currentPrincipal.expiresAt }),
  };
}
