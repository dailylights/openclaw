import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { useAutoCleanupTempDirTracker } from "../../../test/helpers/temp-dir.js";
import { memoryIdentityLifecycle } from "../../state/memory-identity.js";
import { closeOpenClawAgentDatabasesForTest } from "../../state/openclaw-agent-db.js";
import { closeOpenClawStateDatabaseForTest } from "../../state/openclaw-state-db.js";
import { ensureProfileForEmail, linkEmail } from "../../state/user-profiles.js";
import {
  prepareAmbiguousSessionMemorySubjectSeed,
  prepareChannelBindingSessionMemorySubjectSeed,
  prepareExplicitSessionMemorySubjectSeed,
  prepareGatewayProfileSessionMemorySubjectSeed,
  readCurrentSessionMemorySubject,
  readCurrentSessionMemorySubjectAuthority,
  resetSessionEntryLifecycle,
  SessionMemorySubjectReboundError,
  upsertSessionEntry,
} from "./session-accessor.js";

const {
  createMemoryIdentityBinding,
  ensureEnterpriseMemoryPrincipal,
  ensureGatewayProfileMemoryPrincipal,
  revokeMemoryIdentityBinding,
  revokeMemoryPrincipal,
} = memoryIdentityLifecycle;

const tempDirectories = useAutoCleanupTempDirTracker(afterEach);

function createPaths() {
  const directory = tempDirectories.make("openclaw-session-memory-subject-");
  return {
    stateOptions: { path: path.join(directory, "state.sqlite") },
    storePath: path.join(directory, "sessions.json"),
  };
}

afterEach(() => {
  closeOpenClawAgentDatabasesForTest();
  closeOpenClawStateDatabaseForTest();
});

describe("session memory subject", () => {
  it("keeps the first trusted subject immutable across later entry writes", async () => {
    const { stateOptions, storePath } = createPaths();
    const scope = { agentId: "main", sessionKey: "agent:main:service:task-1", storePath };
    const originalSeed = prepareExplicitSessionMemorySubjectSeed({
      kind: "service",
      stableSubjectId: "task-service",
      now: 100,
      options: stateOptions,
    });
    const replacementSeed = prepareExplicitSessionMemorySubjectSeed({
      kind: "system",
      stableSubjectId: "attempted-replacement",
      now: 100,
      options: stateOptions,
    });

    await upsertSessionEntry(
      scope,
      { sessionId: "session-1", updatedAt: 100 },
      { memorySubjectSeed: originalSeed },
    );
    const first = readCurrentSessionMemorySubject(scope);
    await upsertSessionEntry(
      scope,
      { label: "updated", updatedAt: 110 },
      { memorySubjectSeed: replacementSeed },
    );
    const second = readCurrentSessionMemorySubject(scope);

    expect(first?.subject).toMatchObject({ kind: "service" });
    expect(second).toMatchObject({
      sessionId: "session-1",
      subjectRevision: first?.subjectRevision,
      subject: first?.subject,
    });
  });

  it("forces a shared-main direct session to an explicit ambiguous subject", async () => {
    const { stateOptions, storePath } = createPaths();
    const scope = { agentId: "main", sessionKey: "agent:main:main", storePath };
    const privateSeed = prepareExplicitSessionMemorySubjectSeed({
      kind: "agent",
      stableSubjectId: "main",
      now: 100,
      options: stateOptions,
    });

    await upsertSessionEntry(
      scope,
      { chatType: "direct", sessionId: "shared-main", updatedAt: 100 },
      { memorySubjectSeed: privateSeed },
    );

    expect(readCurrentSessionMemorySubject(scope)?.subject).toEqual({
      version: 1,
      kind: "ambiguous",
      reason: "shared-main",
    });
  });

  it("copies the exact subject revision into a reset window", async () => {
    const { stateOptions, storePath } = createPaths();
    const sessionKey = "agent:main:service:reset";
    const scope = { agentId: "main", sessionKey, storePath };
    const seed = prepareExplicitSessionMemorySubjectSeed({
      kind: "service",
      stableSubjectId: "reset-service",
      now: 100,
      options: stateOptions,
    });
    await upsertSessionEntry(
      scope,
      { sessionId: "before-reset", updatedAt: 100 },
      { memorySubjectSeed: seed },
    );
    const before = readCurrentSessionMemorySubject(scope);

    await resetSessionEntryLifecycle({
      buildNextEntry: () => ({ sessionId: "after-reset", updatedAt: 200 }),
      storePath,
      target: { canonicalKey: sessionKey, storeKeys: [sessionKey] },
    });
    const after = readCurrentSessionMemorySubject(scope);

    expect(after).toMatchObject({
      sessionId: "after-reset",
      subjectRevision: before?.subjectRevision,
      subject: before?.subject,
    });
    expect(after?.sessionIdentityRevision).not.toBe(before?.sessionIdentityRevision);
  });

  it("rejects reuse of one transcript session id by another logical subject", async () => {
    const { stateOptions, storePath } = createPaths();
    const firstScope = { agentId: "main", sessionKey: "agent:main:first", storePath };
    const secondScope = { agentId: "main", sessionKey: "agent:main:second", storePath };
    const firstSeed = prepareExplicitSessionMemorySubjectSeed({
      kind: "agent",
      stableSubjectId: "first",
      now: 100,
      options: stateOptions,
    });
    const secondSeed = prepareExplicitSessionMemorySubjectSeed({
      kind: "agent",
      stableSubjectId: "second",
      now: 100,
      options: stateOptions,
    });
    await upsertSessionEntry(
      firstScope,
      { sessionId: "reused-session-id", updatedAt: 100 },
      { memorySubjectSeed: firstSeed },
    );

    await expect(
      upsertSessionEntry(
        secondScope,
        { sessionId: "reused-session-id", updatedAt: 110 },
        { memorySubjectSeed: secondSeed },
      ),
    ).rejects.toBeInstanceOf(SessionMemorySubjectReboundError);
    expect(readCurrentSessionMemorySubject(firstScope)?.subject).toMatchObject({
      kind: "agent",
    });
    expect(readCurrentSessionMemorySubject(secondScope)).toBeUndefined();
  });

  it("preserves denied subject identity across legacy aliases of one transcript", async () => {
    const { storePath } = createPaths();
    const firstScope = { agentId: "main", sessionKey: "legacy-alias", storePath };
    const secondScope = { agentId: "main", sessionKey: "agent:main:legacy-alias", storePath };

    await upsertSessionEntry(firstScope, { sessionId: "legacy-alias-session", updatedAt: 100 });
    await upsertSessionEntry(secondScope, { sessionId: "legacy-alias-session", updatedAt: 110 });

    const first = readCurrentSessionMemorySubject(firstScope);
    const second = readCurrentSessionMemorySubject(secondScope);
    expect(first?.subject).toEqual({ version: 1, kind: "ambiguous", reason: "unbound" });
    expect(second).toMatchObject({
      sessionIdentityRevision: first?.sessionIdentityRevision,
      subjectRevision: first?.subjectRevision,
      subject: first?.subject,
    });
  });

  it("does not infer private lineage from an unseeded reused transcript id", async () => {
    const { stateOptions, storePath } = createPaths();
    const firstScope = { agentId: "main", sessionKey: "agent:main:private", storePath };
    const secondScope = { agentId: "main", sessionKey: "agent:main:untrusted-alias", storePath };
    const privateSeed = prepareExplicitSessionMemorySubjectSeed({
      kind: "agent",
      stableSubjectId: "private",
      now: 100,
      options: stateOptions,
    });
    await upsertSessionEntry(
      firstScope,
      { sessionId: "private-session-id", updatedAt: 100 },
      { memorySubjectSeed: privateSeed },
    );

    await expect(
      upsertSessionEntry(secondScope, { sessionId: "private-session-id", updatedAt: 110 }),
    ).rejects.toBeInstanceOf(SessionMemorySubjectReboundError);
    expect(readCurrentSessionMemorySubject(secondScope)).toBeUndefined();
  });

  it("lazily backfills old session rows as unbound instead of opening private authority", async () => {
    const { storePath } = createPaths();
    const scope = { agentId: "main", sessionKey: "agent:main:legacy", storePath };
    await upsertSessionEntry(scope, { sessionId: "legacy-session", updatedAt: 100 });

    expect(readCurrentSessionMemorySubject(scope)?.subject).toEqual(
      prepareAmbiguousSessionMemorySubjectSeed("unbound").subject,
    );
  });

  it("does not treat previousSessionId alone as private subject lineage", async () => {
    const { stateOptions, storePath } = createPaths();
    const sourceScope = { agentId: "main", sessionKey: "agent:main:private-source", storePath };
    const targetScope = { agentId: "main", sessionKey: "agent:main:unproven-target", storePath };
    const sourceSeed = prepareExplicitSessionMemorySubjectSeed({
      kind: "service",
      stableSubjectId: "private-source",
      now: 100,
      options: stateOptions,
    });
    await upsertSessionEntry(
      sourceScope,
      { sessionId: "private-source-session", updatedAt: 100 },
      { memorySubjectSeed: sourceSeed },
    );
    const source = readCurrentSessionMemorySubject(sourceScope);

    await upsertSessionEntry(targetScope, {
      previousSessionId: "private-source-session",
      sessionId: "unproven-target-session",
      updatedAt: 110,
    });
    const target = readCurrentSessionMemorySubject(targetScope);

    expect(target?.subject).toEqual({ version: 1, kind: "ambiguous", reason: "unbound" });
    expect(target?.subjectRevision).not.toBe(source?.subjectRevision);
  });

  it("reports a revoked captured binding separately from its current principal", async () => {
    const { stateOptions, storePath } = createPaths();
    const scope = { agentId: "main", sessionKey: "agent:main:bound-user", storePath };
    const principal = ensureEnterpriseMemoryPrincipal({
      issuer: "test-issuer",
      stableSubjectId: "bound-user",
      now: 100,
      options: stateOptions,
    });
    const binding = createMemoryIdentityBinding({
      channel: "telegram",
      accountId: "default",
      stableSenderId: "telegram-user-1",
      principalId: principal.principalId,
      adapterId: "telegram-pairing",
      assurance: "adapter-attested",
      verificationMethod: "pairing",
      evidenceRevision: "binding-revision-1",
      createdBy: "operator-1",
      now: 100,
      options: stateOptions,
    });
    const seed = prepareChannelBindingSessionMemorySubjectSeed({
      channel: "telegram",
      accountId: "default",
      stableSenderId: "telegram-user-1",
      now: 101,
      options: stateOptions,
    });
    await upsertSessionEntry(
      scope,
      { sessionId: "bound-user-session", updatedAt: 101 },
      { memorySubjectSeed: seed },
    );

    expect(
      revokeMemoryIdentityBinding({
        bindingId: binding.bindingId,
        revokedBy: "operator-2",
        now: 102,
        options: stateOptions,
      }),
    ).toBe(true);
    expect(readCurrentSessionMemorySubjectAuthority(scope, stateOptions, 103)?.authority).toEqual({
      kind: "denied",
      reason: "binding-revoked",
    });
  });

  it("reports principal revocation before a still-present captured binding", async () => {
    const { stateOptions, storePath } = createPaths();
    const scope = { agentId: "main", sessionKey: "agent:main:revoked-user", storePath };
    const principal = ensureEnterpriseMemoryPrincipal({
      issuer: "test-issuer",
      stableSubjectId: "revoked-user",
      now: 100,
      options: stateOptions,
    });
    createMemoryIdentityBinding({
      channel: "signal",
      accountId: "primary",
      stableSenderId: "signal-user-1",
      principalId: principal.principalId,
      adapterId: "signal-link",
      assurance: "oidc",
      verificationMethod: "oidc",
      evidenceRevision: "binding-revision-1",
      createdBy: "operator-1",
      now: 100,
      options: stateOptions,
    });
    const seed = prepareChannelBindingSessionMemorySubjectSeed({
      channel: "signal",
      accountId: "primary",
      stableSenderId: "signal-user-1",
      now: 101,
      options: stateOptions,
    });
    await upsertSessionEntry(
      scope,
      { sessionId: "revoked-user-session", updatedAt: 101 },
      { memorySubjectSeed: seed },
    );

    expect(
      revokeMemoryPrincipal({
        principalId: principal.principalId,
        now: 102,
        options: stateOptions,
      }),
    ).toBe(true);
    expect(readCurrentSessionMemorySubjectAuthority(scope, stateOptions, 103)?.authority).toEqual({
      kind: "denied",
      reason: "principal-revoked",
    });
  });

  it("reconciles an old Gateway-profile session after linkEmail merges its profile", async () => {
    const { stateOptions, storePath } = createPaths();
    const scope = { agentId: "main", sessionKey: "agent:main:gateway-profile", storePath };
    const sourceProfile = ensureProfileForEmail("source@example.test", stateOptions);
    const targetProfile = ensureProfileForEmail("target@example.test", stateOptions);
    const sourcePrincipal = ensureGatewayProfileMemoryPrincipal(sourceProfile.id, stateOptions);
    const targetPrincipal = ensureGatewayProfileMemoryPrincipal(targetProfile.id, stateOptions);
    const seed = prepareGatewayProfileSessionMemorySubjectSeed(sourceProfile.id, stateOptions);
    if (!sourcePrincipal || !targetPrincipal || !seed) {
      throw new Error("expected Gateway profile memory principals");
    }
    await upsertSessionEntry(
      scope,
      { sessionId: "gateway-profile-session", updatedAt: 100 },
      { memorySubjectSeed: seed },
    );

    linkEmail("source@example.test", targetProfile.id, stateOptions);

    expect(readCurrentSessionMemorySubjectAuthority(scope, stateOptions)?.authority).toEqual({
      kind: "current",
      currentPrincipalId: targetPrincipal.principalId,
      assurance: "gateway-profile",
      evidenceRevision: targetPrincipal.evidenceRevision,
    });
    expect(sourcePrincipal.principalId).not.toBe(targetPrincipal.principalId);
  });
});
