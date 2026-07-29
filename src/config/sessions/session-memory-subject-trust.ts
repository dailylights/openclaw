import { generateSecureUuid } from "../../infra/secure-random.js";
import type { SessionMemorySubject } from "../../memory-host-sdk/host/authorization.js";

const trustedSeedBrand: unique symbol = Symbol("openclaw.trusted-session-memory-subject-seed");
const trustedSnapshotBrand: unique symbol = Symbol(
  "openclaw.trusted-session-memory-subject-snapshot",
);
const trustedSeeds = new WeakSet<object>();
const trustedSnapshots = new WeakSet<object>();

export type SessionMemoryScope = "conversation" | "shared-main" | "group" | "channel";

export type TrustedSessionMemorySubjectSeed = Readonly<{
  [trustedSeedBrand]: true;
  subject: SessionMemorySubject;
  subjectRevision: string;
  creationBindingId?: string;
  canonicalConversationRef?: string;
}>;

export type TrustedSessionMemorySubjectSnapshot = Readonly<{
  [trustedSnapshotBrand]: true;
  sessionKey: string;
  sessionId: string;
  sessionScope: SessionMemoryScope;
  sessionIdentityRevision: string;
  subjectRevision: string;
  subject: SessionMemorySubject;
  creationBindingId?: string;
  canonicalConversationRef?: string;
}>;

export class SessionMemorySubjectReboundError extends Error {
  readonly code = "SESSION_MEMORY_SUBJECT_REBOUND";

  constructor(sessionId: string) {
    super(`Session memory subject snapshot conflicts with reused session id: ${sessionId}`);
    this.name = "SessionMemorySubjectReboundError";
  }
}

export class InvalidSessionMemorySubjectSeedError extends Error {
  readonly code = "INVALID_SESSION_MEMORY_SUBJECT_SEED";

  constructor() {
    super("Session memory subject seed is not host-trusted");
    this.name = "InvalidSessionMemorySubjectSeedError";
  }
}

export function requireSessionMemorySubjectText(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized) {
    throw new TypeError(`${label} must not be empty`);
  }
  return normalized;
}

function cloneSubject(subject: SessionMemorySubject): SessionMemorySubject {
  if (subject.version !== 1) {
    throw new TypeError("unsupported session memory subject version");
  }
  switch (subject.kind) {
    case "user":
      return {
        version: 1,
        kind: "user",
        principalId: requireSessionMemorySubjectText(subject.principalId, "principalId"),
        creationEvidence: {
          kind: subject.creationEvidence.kind,
          revision: requireSessionMemorySubjectText(
            subject.creationEvidence.revision,
            "creation evidence revision",
          ),
        },
      };
    case "conversation":
      return {
        version: 1,
        kind: "conversation",
        conversationPrincipalId: requireSessionMemorySubjectText(
          subject.conversationPrincipalId,
          "conversationPrincipalId",
        ),
        channel: requireSessionMemorySubjectText(subject.channel, "channel").toLowerCase(),
        accountId: requireSessionMemorySubjectText(subject.accountId, "accountId"),
      };
    case "service":
    case "agent":
    case "system":
      return {
        version: 1,
        kind: subject.kind,
        principalId: requireSessionMemorySubjectText(subject.principalId, "principalId"),
      };
    case "ambiguous":
      return { version: 1, kind: "ambiguous", reason: subject.reason };
  }
  throw new TypeError("unsupported session memory subject kind");
}

function deepFreeze<T extends object>(value: T): T {
  for (const nested of Object.values(value)) {
    if (nested && typeof nested === "object" && !Object.isFrozen(nested)) {
      deepFreeze(nested as object);
    }
  }
  return Object.freeze(value);
}

export function createTrustedSessionMemorySubjectSeed(params: {
  subject: SessionMemorySubject;
  subjectRevision?: string;
  creationBindingId?: string;
  canonicalConversationRef?: string;
}): TrustedSessionMemorySubjectSeed {
  const seed = {
    subject: cloneSubject(params.subject),
    subjectRevision: requireSessionMemorySubjectText(
      params.subjectRevision ?? generateSecureUuid(),
      "subjectRevision",
    ),
    ...(params.creationBindingId
      ? {
          creationBindingId: requireSessionMemorySubjectText(
            params.creationBindingId,
            "creationBindingId",
          ),
        }
      : {}),
    ...(params.canonicalConversationRef
      ? {
          canonicalConversationRef: requireSessionMemorySubjectText(
            params.canonicalConversationRef,
            "canonicalConversationRef",
          ),
        }
      : {}),
  } as Omit<TrustedSessionMemorySubjectSeed, typeof trustedSeedBrand> & {
    [trustedSeedBrand]?: true;
  };
  Object.defineProperty(seed, trustedSeedBrand, {
    value: true,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  trustedSeeds.add(seed);
  return deepFreeze(seed) as TrustedSessionMemorySubjectSeed;
}

export function isTrustedSessionMemorySubjectSeed(
  value: unknown,
): value is TrustedSessionMemorySubjectSeed {
  return Boolean(
    value &&
    typeof value === "object" &&
    trustedSeeds.has(value) &&
    (value as Record<symbol, unknown>)[trustedSeedBrand] === true &&
    Object.isFrozen(value),
  );
}

export function createTrustedSessionMemorySubjectSnapshot(params: {
  sessionKey: string;
  sessionId: string;
  sessionScope: SessionMemoryScope;
  sessionIdentityRevision: string;
  subjectRevision: string;
  subject: SessionMemorySubject;
  creationBindingId?: string;
  canonicalConversationRef?: string;
}): TrustedSessionMemorySubjectSnapshot {
  const snapshot = {
    sessionKey: requireSessionMemorySubjectText(params.sessionKey, "sessionKey"),
    sessionId: requireSessionMemorySubjectText(params.sessionId, "sessionId"),
    sessionScope: params.sessionScope,
    sessionIdentityRevision: requireSessionMemorySubjectText(
      params.sessionIdentityRevision,
      "sessionIdentityRevision",
    ),
    subjectRevision: requireSessionMemorySubjectText(params.subjectRevision, "subjectRevision"),
    subject: cloneSubject(params.subject),
    ...(params.creationBindingId ? { creationBindingId: params.creationBindingId } : {}),
    ...(params.canonicalConversationRef
      ? { canonicalConversationRef: params.canonicalConversationRef }
      : {}),
  } as Omit<TrustedSessionMemorySubjectSnapshot, typeof trustedSnapshotBrand> & {
    [trustedSnapshotBrand]?: true;
  };
  Object.defineProperty(snapshot, trustedSnapshotBrand, {
    value: true,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  trustedSnapshots.add(snapshot);
  return deepFreeze(snapshot) as TrustedSessionMemorySubjectSnapshot;
}

export function isTrustedSessionMemorySubjectSnapshot(
  value: unknown,
): value is TrustedSessionMemorySubjectSnapshot {
  return Boolean(
    value &&
    typeof value === "object" &&
    trustedSnapshots.has(value) &&
    (value as Record<symbol, unknown>)[trustedSnapshotBrand] === true &&
    Object.isFrozen(value),
  );
}

/** Copies persisted provenance exactly; arbitrary snapshot-shaped objects are rejected. */
export function prepareSessionMemorySubjectLineageSeed(
  snapshot: TrustedSessionMemorySubjectSnapshot,
): TrustedSessionMemorySubjectSeed {
  if (!isTrustedSessionMemorySubjectSnapshot(snapshot)) {
    throw new InvalidSessionMemorySubjectSeedError();
  }
  return createTrustedSessionMemorySubjectSeed({
    subject: snapshot.subject,
    subjectRevision: snapshot.subjectRevision,
    creationBindingId: snapshot.creationBindingId,
    canonicalConversationRef: snapshot.canonicalConversationRef,
  });
}
