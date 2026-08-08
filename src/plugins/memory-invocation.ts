import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import { stableStringify } from "@openclaw/normalization-core";
import { readCurrentSessionMemorySubjectAuthority } from "../config/sessions/session-memory-subject-access.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import type {
  AudienceRef,
  MemoryAccessContext,
  MemoryActorEvidence,
  MemoryOperation,
  MemoryWriteResult,
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
import { listMemoryEgressCapabilityIds } from "./memory-egress-registry.js";
import {
  createMemoryVirtualFilesystemView,
  isMemoryVirtualRootPath,
  normalizeMemoryVirtualPath,
} from "./memory-invocation-filesystem.js";
import {
  advanceMemoryRunExposure,
  createMemoryDisplayHandleRegistry,
  hasCurrentMemoryEgressReceipts,
  mergeMemoryInvocationEnvelope,
  refreshMemoryInvocationTranscriptPolicy,
  rememberMemoryDisplayHandle,
  resolveUniqueMemoryDisplayHandle,
  type MemoryInvocationState,
  type MemoryVirtualFilesystemView,
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
  operation?: MemoryOperation;
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

  // Phase 1D starts with a constrained pilot: only the already-bound final
  // reply can carry scoped content. Every other side-effect is classified but
  // unavailable until it has an audience-bound delivery contract.
  const egressCapabilityIds = ["reply.final"];
  const deliveryBinding = {
    sinkKind,
    audiences: sortedMemoryAudiences(audiences),
    channel: params.messageChannel ?? null,
    accountId: params.agentAccountId ?? null,
    to: params.messageTo ?? null,
    threadId: params.messageThreadId ?? null,
  };
  const deliveryRevision = hashMemoryRevision("mdr1", deliveryBinding);
  const egressRegistryRevision = hashMemoryRevision("mer1", listMemoryEgressCapabilityIds());
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
    operation: params.operation ?? "read",
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
  const facts = buildAuthorityFacts({
    agentId: state.agentId,
    sessionId: state.sessionId,
    sessionKey: state.sessionKey,
    runId: state.runId,
    ...state.deliveryInput,
    operation: state.context?.operation,
  });
  if (!facts) {
    return false;
  }
  return (
    facts.sessionId === context.sessionId &&
    facts.sessionIdentityRevision === context.sessionIdentityRevision &&
    facts.subjectRevision === context.subjectRevision &&
    stableStringify(facts.subject) === stableStringify(context.subject) &&
    facts.delivery.deliveryRevision === context.delivery.deliveryRevision &&
    facts.delivery.egressRegistryRevision === context.delivery.egressRegistryRevision &&
    plan.contextFingerprint === context.contextFingerprint &&
    plan.runId === context.runId &&
    plan.deliveryRevision === facts.delivery.deliveryRevision
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
  trigger?: string;
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
    state.deliveryInput = Object.freeze({
      ...(params.messageChannel !== undefined ? { messageChannel: params.messageChannel } : {}),
      ...(params.agentAccountId !== undefined ? { agentAccountId: params.agentAccountId } : {}),
      ...(params.messageTo !== undefined ? { messageTo: params.messageTo } : {}),
      ...(params.messageThreadId !== undefined ? { messageThreadId: params.messageThreadId } : {}),
    });
    const facts = buildAuthorityFacts({
      ...params,
      operation: params.trigger === "memory" ? "append" : "read",
    });
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
    state.virtualFilesystem = await createMemoryVirtualFilesystemView({
      context,
      plan: authorization.plan,
    });
    advanceMemoryRunExposure({
      state,
      sourcePolicySetIds: [],
      exposedResourceRevisions: [],
      exposureReceiptIds: [],
      egressReceiptIds: [],
    });
    await refreshMemoryInvocationTranscriptPolicy(state);
    state.initialization = "ready";
  } catch {
    state.context = undefined;
    state.plan = undefined;
    state.runtime = undefined;
    state.runExposure = undefined;
    state.transcriptPolicy = undefined;
    state.virtualFilesystem = undefined;
    state.initialization = "unavailable";
  }
}

export async function withMemoryInvocation<T>(
  token: MemoryInvocationToken | undefined,
  run: () => Promise<T>,
): Promise<T> {
  try {
    return await withMemoryInvocationToken(token, run);
  } finally {
    const view = token ? invocationStateByToken.get(token)?.virtualFilesystem : undefined;
    if (view) {
      await fs.rm(view.rootDir, { recursive: true, force: true });
    }
  }
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
      const mount = state.plan?.mounts.find((entry) => entry.mountHandle === result.mountHandle);
      const virtualPath =
        mount && state.virtualFilesystem
          ? `${mount.virtualRoot}/${mount.mountHandle}/${result.resourceHandle.handleId}.md`
          : undefined;
      if (!virtualPath) {
        throw new Error("memory virtual view is unavailable");
      }
      rememberMemoryDisplayHandle(state.displayHandles, virtualPath, result.resourceHandle);
      const { resourceHandle: _resourceHandle, mountHandle: _mountHandle, ...safe } = result;
      return Object.freeze({
        ...safe,
        path: virtualPath,
        citation: `${virtualPath}#L${result.startLine}-L${result.endLine}`,
      });
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
    return Object.freeze({ ...envelope.value, path: params.path });
  } catch {
    return MEMORY_INVOCATION_UNAVAILABLE;
  }
}

/** Commits one maintenance memory note without exposing a filesystem destination. */
export async function rememberAuthorizedMemoryForInvocation(params: {
  token: MemoryInvocationToken;
  content: string;
  toolCallId: string;
}): Promise<
  Readonly<Pick<MemoryWriteResult, "status" | "committedAt">> | MemoryInvocationUnavailable
> {
  const state = readInvocationState(params.token);
  if (
    !state ||
    !revalidateInvocation(params.token, state) ||
    state.context?.operation !== "append" ||
    !state.context ||
    !state.plan ||
    !state.runtime ||
    !("writeAuthorized" in state.runtime) ||
    typeof state.runtime.writeAuthorized !== "function" ||
    !params.content.trim() ||
    !params.toolCallId.trim()
  ) {
    return MEMORY_INVOCATION_UNAVAILABLE;
  }
  const mutationId = hashMemoryRevision("mfm1", {
    contextFingerprint: state.context.contextFingerprint,
    planId: state.plan.planId,
    toolCallId: params.toolCallId,
    content: params.content,
  });
  try {
    const result = await state.runtime.writeAuthorized({
      context: state.context,
      plan: state.plan,
      mutation: {
        version: 1,
        kind: "remember",
        mutationId,
        idempotencyKey: mutationId,
        content: params.content,
        contentType: "markdown",
      },
    });
    return Object.freeze({ status: result.status, committedAt: result.committedAt });
  } catch {
    return MEMORY_INVOCATION_UNAVAILABLE;
  }
}

/** Returns the ephemeral mount plan only while its invocation remains current. */
export function getMemoryVirtualFilesystemView(
  token: MemoryInvocationToken | undefined,
): MemoryVirtualFilesystemView | undefined {
  if (!token) {
    return undefined;
  }
  const state = readInvocationState(token);
  return state && revalidateInvocation(token, state) ? state.virtualFilesystem : undefined;
}

/** Recognizes any reserved virtual root, including malformed/case-confused paths. */
export function isMemoryVirtualFilesystemPath(pathname: string): boolean {
  return isMemoryVirtualRootPath(pathname);
}

/** Reads one opaque virtual file through the authorization broker, never host storage. */
export async function readVirtualMemoryFilesystemPath(params: {
  token: MemoryInvocationToken;
  path: string;
  offset?: number;
  limit?: number;
}): Promise<MemoryReadResult | MemoryInvocationUnavailable> {
  const normalizedPath = normalizeMemoryVirtualPath(params.path);
  if (!normalizedPath) {
    return MEMORY_INVOCATION_UNAVAILABLE;
  }
  return await readAuthorizedMemoryForInvocation({
    token: params.token,
    path: normalizedPath,
    from: params.offset,
    lines: params.limit,
  });
}

/**
 * Side-effect tools cannot run after a scoped read in the constrained pilot.
 * Final delivery is checked separately because it is bound to the original route.
 */
export function isMemoryScopedToolEgressBlocked(token: MemoryInvocationToken | undefined): boolean {
  if (!token) {
    return false;
  }
  const state = readInvocationState(token);
  const exposure = state?.runExposure;
  const resourceRevisions = exposure
    ? parseCanonicalMemoryStringArray(exposure.exposedResourceRevisionsJson)
    : undefined;
  return !resourceRevisions || resourceRevisions.length > 0;
}

/** Final reply delivery may proceed only with current route and egress receipts. */
export function assertMemoryFinalReplyEgressAuthorized(
  token: MemoryInvocationToken | undefined,
): void {
  if (!token) {
    return;
  }
  const state = readInvocationState(token);
  const exposure = state?.runExposure;
  const resourceRevisions = exposure
    ? parseCanonicalMemoryStringArray(exposure.exposedResourceRevisionsJson)
    : undefined;
  if (resourceRevisions?.length === 0) {
    return;
  }
  if (
    !state ||
    !revalidateInvocation(token, state) ||
    !state.context?.delivery.egressCapabilityIds.includes("reply.final") ||
    !exposure ||
    !isCurrentRunExposureValid(state, exposure) ||
    !hasCurrentMemoryEgressReceipts(state)
  ) {
    throw new Error("memory final reply egress is unavailable");
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
  const transcriptPolicy = state?.transcriptPolicy;
  if (
    !token ||
    !state ||
    !revalidateInvocation(token, state) ||
    !context ||
    !exposure ||
    !transcriptPolicy ||
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
    policySetRevision: transcriptPolicy.policySetRevision,
    runExposureSetId: exposure.exposureSetId,
    runExposureRevision: exposure.revisionNumber,
    deliveryAudiencesJson: exposure.deliveryAudiencesJson,
    actorEvidenceJson: JSON.stringify({
      actor: context.actor,
      collaboration: context.collaboration,
      conversation: context.conversation ?? null,
      verifiedMemberships: context.verifiedMemberships,
      verifiedPrincipals: context.verifiedPrincipals,
    }),
    delegationJson: JSON.stringify(context.delegation ?? null),
    finalizedEgressAudiencesJson: exposure.deliveryAudiencesJson,
    exposedResourceRevisionsJson: exposure.exposedResourceRevisionsJson,
    sessionIdentityRevision: context.sessionIdentityRevision,
    subjectRevision: context.subjectRevision,
    runId: context.runId,
    contextFingerprint: context.contextFingerprint,
    runExposure: exposure,
    transcriptPolicy,
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
