import { randomUUID } from "node:crypto";
import { stableStringify } from "@openclaw/normalization-core";
import { readCurrentSessionMemorySubjectAuthority } from "../config/sessions/session-memory-subject-access.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import type {
  AudienceRef,
  MemoryAccessContext,
  MemoryActorEvidence,
  VerifiedPrincipalRef,
} from "../memory-host-sdk/host/authorization.js";
import type {
  MemoryReadResult,
  MemorySearchResult,
  MemorySource,
} from "../memory-host-sdk/host/types.js";
import {
  createMemoryAccessContextFactory,
  type MemoryAccessContextFacts,
} from "./memory-access-context.js";
import { isMemoryIsolationCutoverAgent } from "./memory-cutover.js";
import {
  advanceMemoryRunExposure,
  createMemoryDisplayHandleRegistry,
  mergeMemoryInvocationEnvelope,
  rememberMemoryDisplayHandle,
  resolveUniqueMemoryDisplayHandle,
  type MemoryInvocationState,
  type TranscriptMemoryRunExposureSnapshot,
} from "./memory-invocation-receipts.js";
import {
  createEffectiveMemoryPolicySetId,
  createMemoryOpaqueId,
  equalMemoryAudiences,
  hashMemoryRevision,
  parseCanonicalMemoryAudiences,
  parseCanonicalMemoryStringArray,
  sortedMemoryAudiences,
} from "./memory-invocation-serialization.js";
import {
  createMemoryInvocationToken as createOpaqueMemoryInvocationToken,
  getCurrentMemoryInvocationToken,
  isActiveMemoryInvocationToken,
  type MemoryInvocationToken,
  withMemoryInvocationToken,
} from "./memory-invocation-token.js";
import { authorizeActiveMemoryAccess } from "./memory-runtime.js";
import {
  setTranscriptMemoryPolicyLabelReader,
  type TranscriptMemoryPolicyLabel,
} from "./memory-transcript-policy-label.js";

export type { MemoryInvocationToken } from "./memory-invocation-token.js";
export { isMemoryInvocationEnforced } from "./memory-invocation-token.js";

type MemoryInvocationUnavailable = Readonly<{
  disabled: true;
  unavailable: true;
  error: "memory unavailable";
}>;

export const MEMORY_INVOCATION_UNAVAILABLE: MemoryInvocationUnavailable = Object.freeze({
  disabled: true,
  unavailable: true,
  error: "memory unavailable",
});

type AuthorizedMemoryToolSearchResult = Readonly<{
  results: readonly MemorySearchResult[];
}>;

const invocationStateByToken = new WeakMap<MemoryInvocationToken, MemoryInvocationState>();

function buildAuthorityFacts(params: {
  agentId: string;
  sessionId: string;
  sessionKey: string;
  runId: string;
  messageChannel?: string;
  agentAccountId?: string;
  messageTo?: string;
  messageThreadId?: string | number;
}): MemoryAccessContextFacts | undefined {
  const current = readCurrentSessionMemorySubjectAuthority({
    agentId: params.agentId,
    sessionKey: params.sessionKey,
  });
  if (!current || current.authority.kind !== "current") {
    return undefined;
  }
  const { snapshot, authority } = current;
  if (snapshot.sessionId !== params.sessionId) {
    return undefined;
  }
  const subject = snapshot.subject;
  let actor: MemoryActorEvidence;
  let verifiedPrincipals: VerifiedPrincipalRef[] = [];
  let audiences: AudienceRef[];
  let sinkKind: MemoryAccessContext["delivery"]["sinkKind"];
  let conversation: MemoryAccessContext["conversation"] | undefined;
  const evidenceRevision = authority.evidenceRevision ?? snapshot.subjectRevision;
  const expiresAt =
    authority.expiresAt === undefined ? undefined : new Date(authority.expiresAt).toISOString();

  if (subject.kind === "user") {
    if (!authority.currentPrincipalId || !authority.assurance) {
      return undefined;
    }
    actor = {
      kind: "principal",
      actorKind: "human",
      principalId: authority.currentPrincipalId,
      assurance: authority.assurance,
      evidenceRevision,
      ...(expiresAt ? { expiresAt } : {}),
    };
    verifiedPrincipals = [
      {
        principalId: authority.currentPrincipalId,
        assurance: authority.assurance,
        evidenceRevision,
        ...(expiresAt ? { expiresAt } : {}),
      },
    ];
    audiences = [{ kind: "user", id: authority.currentPrincipalId }];
    sinkKind = "private";
  } else if (subject.kind === "conversation") {
    actor = {
      kind: "unattributed",
      transportAuditRef: hashMemoryRevision("mta1", {
        channel: subject.channel,
        accountId: subject.accountId,
        sessionId: snapshot.sessionId,
      }),
      evidenceRevision,
    };
    audiences = [{ kind: "conversation", id: subject.conversationPrincipalId }];
    sinkKind = "channel";
    conversation = {
      conversationPrincipalId: subject.conversationPrincipalId,
      channel: subject.channel,
      accountId: subject.accountId,
      evidenceRevision,
    };
  } else if (subject.kind === "service" || subject.kind === "agent" || subject.kind === "system") {
    if (!authority.currentPrincipalId) {
      return undefined;
    }
    const actorKind = subject.kind === "agent" ? "agent" : subject.kind;
    actor = {
      kind: "principal",
      actorKind,
      principalId: authority.currentPrincipalId,
      assurance: "service",
      evidenceRevision,
      ...(expiresAt ? { expiresAt } : {}),
    };
    verifiedPrincipals = [
      {
        principalId: authority.currentPrincipalId,
        assurance: "service",
        evidenceRevision,
        ...(expiresAt ? { expiresAt } : {}),
      },
    ];
    audiences = [{ kind: "agent", id: authority.currentPrincipalId }];
    sinkKind = "internal";
  } else {
    return undefined;
  }

  const egressCapabilityIds = ["message.send", "reply.final"];
  const deliveryBinding = {
    sinkKind,
    audiences: sortedMemoryAudiences(audiences),
    channel: params.messageChannel ?? null,
    accountId: params.agentAccountId ?? null,
    to: params.messageTo ?? null,
    threadId: params.messageThreadId ?? null,
  };
  const deliveryRevision = hashMemoryRevision("mdr1", deliveryBinding);
  const egressRegistryRevision = hashMemoryRevision("mer1", egressCapabilityIds);
  const hostFactsRevision = hashMemoryRevision("mhf1", {
    sessionIdentityRevision: snapshot.sessionIdentityRevision,
    subjectRevision: snapshot.subjectRevision,
    evidenceRevision,
    deliveryRevision,
    egressRegistryRevision,
  });
  return {
    contextId: createMemoryOpaqueId("mctx1"),
    requestId: randomUUID(),
    runId: params.runId,
    agentId: params.agentId,
    sessionKey: params.sessionKey,
    sessionId: snapshot.sessionId,
    sessionIdentityRevision: snapshot.sessionIdentityRevision,
    subjectRevision: snapshot.subjectRevision,
    subject,
    actor,
    verifiedPrincipals,
    ...(conversation ? { conversation } : {}),
    delivery: {
      sinkKind,
      audiences,
      egressCapabilityIds,
      egressRegistryRevision,
      deliveryRevision,
    },
    collaboration: { kind: "not-applicable" },
    verifiedMemberships: [],
    operation: "read",
    hostFactsRevision,
  };
}

function revalidateInvocation(token: MemoryInvocationToken, state: MemoryInvocationState): boolean {
  const context = state.context;
  const plan = state.plan;
  if (
    !isActiveMemoryInvocationToken(token) ||
    state.initialization !== "ready" ||
    !context ||
    !plan ||
    !state.runtime
  ) {
    return false;
  }
  if (Date.parse(plan.expiresAt) <= Date.now()) {
    return false;
  }
  const current = readCurrentSessionMemorySubjectAuthority({
    agentId: state.agentId,
    sessionKey: state.sessionKey,
  });
  if (!current || current.authority.kind !== "current") {
    return false;
  }
  return (
    current.snapshot.sessionId === context.sessionId &&
    current.snapshot.sessionIdentityRevision === context.sessionIdentityRevision &&
    current.snapshot.subjectRevision === context.subjectRevision &&
    stableStringify(current.snapshot.subject) === stableStringify(context.subject) &&
    plan.contextFingerprint === context.contextFingerprint &&
    plan.runId === context.runId &&
    plan.deliveryRevision === context.delivery.deliveryRevision
  );
}

/** Creates only the opaque enforcement token before runtime/config admission. */
export function createMemoryInvocation(params: {
  agentId: string;
  sessionId: string;
  sessionKey: string;
  runId: string;
}): MemoryInvocationToken | undefined {
  if (!isMemoryIsolationCutoverAgent(params.agentId)) {
    return undefined;
  }
  const token = createOpaqueMemoryInvocationToken();
  invocationStateByToken.set(token, {
    agentId: params.agentId,
    sessionId: params.sessionId,
    sessionKey: params.sessionKey,
    runId: params.runId,
    initialization: "created",
    displayHandles: createMemoryDisplayHandleRegistry(),
    mergeTail: Promise.resolve(),
  });
  return token;
}

/** Initializes authorization only after the run is rebound and runtime plugins are loaded. */
export async function initializeMemoryInvocation(params: {
  token: MemoryInvocationToken;
  cfg: OpenClawConfig;
  agentId: string;
  sessionId: string;
  sessionKey: string;
  runId: string;
  messageChannel?: string;
  agentAccountId?: string;
  messageTo?: string;
  messageThreadId?: string | number;
}): Promise<void> {
  const state = invocationStateByToken.get(params.token);
  if (
    !state ||
    !isActiveMemoryInvocationToken(params.token) ||
    state.initialization !== "created"
  ) {
    throw new Error("memory invocation is unavailable");
  }
  state.initialization = "initializing";
  if (
    state.agentId !== params.agentId ||
    state.sessionId !== params.sessionId ||
    state.sessionKey !== params.sessionKey ||
    state.runId !== params.runId
  ) {
    state.initialization = "unavailable";
    return;
  }
  try {
    const facts = buildAuthorityFacts(params);
    if (!facts) {
      state.initialization = "unavailable";
      return;
    }
    const createContext = createMemoryAccessContextFactory({
      readCurrentSessionIdentity: async ({ agentId, sessionKey }) => {
        const current = readCurrentSessionMemorySubjectAuthority({ agentId, sessionKey });
        return current?.authority.kind === "current"
          ? {
              sessionId: current.snapshot.sessionId,
              sessionIdentityRevision: current.snapshot.sessionIdentityRevision,
              subjectRevision: current.snapshot.subjectRevision,
              subject: current.snapshot.subject,
            }
          : null;
      },
    });
    const context = await createContext(facts);
    state.context = context;
    const authorization = await authorizeActiveMemoryAccess({ cfg: params.cfg, context });
    if (!authorization.runtime || !authorization.plan) {
      state.initialization = "unavailable";
      return;
    }
    state.runtime = authorization.runtime;
    state.plan = authorization.plan;
    advanceMemoryRunExposure({
      state,
      sourcePolicySetIds: [],
      exposedResourceRevisions: [],
      exposureReceiptIds: [],
      egressReceiptIds: [],
    });
    state.initialization = "ready";
  } catch {
    state.context = undefined;
    state.plan = undefined;
    state.runtime = undefined;
    state.runExposure = undefined;
    state.initialization = "unavailable";
  }
}

export async function withMemoryInvocation<T>(
  token: MemoryInvocationToken | undefined,
  run: () => Promise<T>,
): Promise<T> {
  return await withMemoryInvocationToken(token, run);
}

function readInvocationState(token: MemoryInvocationToken): MemoryInvocationState | undefined {
  return isActiveMemoryInvocationToken(token) ? invocationStateByToken.get(token) : undefined;
}

export async function searchAuthorizedMemoryForInvocation(params: {
  token: MemoryInvocationToken;
  query: string;
  sources?: readonly MemorySource[];
  limit?: number;
  signal?: AbortSignal;
}): Promise<AuthorizedMemoryToolSearchResult | MemoryInvocationUnavailable> {
  const state = readInvocationState(params.token);
  if (
    !state ||
    !revalidateInvocation(params.token, state) ||
    !state.context ||
    !state.plan ||
    !state.runtime
  ) {
    return MEMORY_INVOCATION_UNAVAILABLE;
  }
  try {
    const envelope = await state.runtime.searchAuthorized({
      context: state.context,
      plan: state.plan,
      query: params.query,
      sources: params.sources,
      limit: Math.max(1, Math.min(100, Math.trunc(params.limit ?? 10))),
      signal: params.signal,
    });
    const handles = envelope.value.map((result) => result.resourceHandle);
    await mergeMemoryInvocationEnvelope({
      state,
      envelope,
      expectedResourceRevisions: handles.map((handle) => handle.resourceRevision),
      isInvocationValid: () => revalidateInvocation(params.token, state),
    });
    const results = envelope.value.map((result) => {
      rememberMemoryDisplayHandle(state.displayHandles, result.path, result.resourceHandle);
      const { resourceHandle: _resourceHandle, ...safe } = result;
      return Object.freeze(safe);
    });
    return Object.freeze({ results: Object.freeze(results) });
  } catch {
    return MEMORY_INVOCATION_UNAVAILABLE;
  }
}

export async function readAuthorizedMemoryForInvocation(params: {
  token: MemoryInvocationToken;
  path: string;
  from?: number;
  lines?: number;
}): Promise<MemoryReadResult | MemoryInvocationUnavailable> {
  const state = readInvocationState(params.token);
  if (
    !state ||
    !revalidateInvocation(params.token, state) ||
    !state.context ||
    !state.plan ||
    !state.runtime
  ) {
    return MEMORY_INVOCATION_UNAVAILABLE;
  }
  const handle = resolveUniqueMemoryDisplayHandle(state.displayHandles, params.path);
  if (!handle) {
    return MEMORY_INVOCATION_UNAVAILABLE;
  }
  try {
    const envelope = await state.runtime.readAuthorized({
      context: state.context,
      plan: state.plan,
      handle,
      from: params.from,
      lines: params.lines,
    });
    await mergeMemoryInvocationEnvelope({
      state,
      envelope,
      expectedResourceRevisions: [handle.resourceRevision],
      isInvocationValid: () => revalidateInvocation(params.token, state),
    });
    return Object.freeze({ ...envelope.value });
  } catch {
    return MEMORY_INVOCATION_UNAVAILABLE;
  }
}

function isCurrentRunExposureValid(
  state: MemoryInvocationState,
  exposure: TranscriptMemoryRunExposureSnapshot,
): boolean {
  const context = state.context;
  const plan = state.plan;
  if (!context || !plan) {
    return false;
  }
  const memberPolicySetIds = parseCanonicalMemoryStringArray(exposure.sourcePolicySetIdsJson);
  const audiences = parseCanonicalMemoryAudiences(exposure.deliveryAudiencesJson);
  return Boolean(
    memberPolicySetIds &&
    audiences &&
    parseCanonicalMemoryStringArray(exposure.exposedResourceRevisionsJson) &&
    parseCanonicalMemoryStringArray(exposure.exposureReceiptIdsJson) &&
    parseCanonicalMemoryStringArray(exposure.egressReceiptIdsJson) &&
    exposure.agentId === state.agentId &&
    exposure.runId === state.runId &&
    exposure.contextFingerprint === context.contextFingerprint &&
    exposure.planId === plan.planId &&
    exposure.memoryPolicyRevision === plan.memoryPolicyRevision &&
    exposure.deliveryRevision === context.delivery.deliveryRevision &&
    exposure.egressRegistryRevision === context.delivery.egressRegistryRevision &&
    equalMemoryAudiences(audiences, context.delivery.audiences) &&
    createEffectiveMemoryPolicySetId({
      memoryPolicyRevision: plan.memoryPolicyRevision,
      memberPolicySetIds,
    }) === exposure.effectiveSourcePolicySetId &&
    exposure.revisionNumber === (exposure.previous?.revisionNumber ?? 0) + 1 &&
    (!exposure.previous || exposure.previous.exposureSetId !== exposure.exposureSetId),
  );
}

/** Returns an immutable label draft for atomic persistence with the next transcript event. */
function readCurrentTranscriptMemoryPolicyLabel(params: {
  agentId: string;
  sessionId: string;
}): TranscriptMemoryPolicyLabel | undefined {
  const token = getCurrentMemoryInvocationToken();
  const state = token ? invocationStateByToken.get(token) : undefined;
  const context = state?.context;
  const exposure = state?.runExposure;
  if (
    !token ||
    !state ||
    !revalidateInvocation(token, state) ||
    !context ||
    !exposure ||
    state.agentId !== params.agentId ||
    state.sessionId !== params.sessionId
  ) {
    return undefined;
  }
  if (!isCurrentRunExposureValid(state, exposure)) {
    return undefined;
  }
  return {
    sourcePolicySetId: exposure.effectiveSourcePolicySetId,
    runExposureSetId: exposure.exposureSetId,
    runExposureRevision: exposure.revisionNumber,
    deliveryAudiencesJson: exposure.deliveryAudiencesJson,
    sessionIdentityRevision: context.sessionIdentityRevision,
    subjectRevision: context.subjectRevision,
    runId: context.runId,
    contextFingerprint: context.contextFingerprint,
    runExposure: exposure,
  };
}

setTranscriptMemoryPolicyLabelReader(readCurrentTranscriptMemoryPolicyLabel);

const memoryInvocationTesting = {
  getState(token: MemoryInvocationToken): MemoryInvocationState | undefined {
    return invocationStateByToken.get(token);
  },
  createDisplayHandleRegistry: createMemoryDisplayHandleRegistry,
  rememberDisplayHandle: rememberMemoryDisplayHandle,
  resolveUniqueDisplayHandle: resolveUniqueMemoryDisplayHandle,
};

if (process.env.VITEST || process.env.NODE_ENV === "test") {
  (globalThis as Record<PropertyKey, unknown>)[Symbol.for("openclaw.memoryInvocationTestApi")] =
    memoryInvocationTesting;
}
