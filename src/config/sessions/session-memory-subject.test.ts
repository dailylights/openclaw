import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useAutoCleanupTempDirTracker } from "../../../test/helpers/temp-dir.js";
import { memoryIdentityLifecycle } from "../../state/memory-identity.js";
import { closeOpenClawAgentDatabasesForTest } from "../../state/openclaw-agent-db.js";
import { closeOpenClawStateDatabaseForTest } from "../../state/openclaw-state-db.js";
import { ensureProfileForEmail, linkEmail } from "../../state/user-profiles.js";
import {
  prepareAmbiguousSessionMemorySubjectSeed,
  prepareAutonomousAgentSessionMemorySubjectSeed,
  prepareChannelBindingSessionMemorySubjectSeed,
  prepareConversationSessionMemorySubjectSeed,
  prepareExplicitSessionMemorySubjectSeed,
  prepareGatewayProfileSessionMemorySubjectSeed,
  prepareSessionMemorySubjectLineageSeed,
  readCurrentSessionMemorySubject,
  readCurrentSessionMemorySubjectAuthority,
  replaceSessionEntrySync,
  resetSessionEntryLifecycle,
  SessionMemorySubjectReboundError,
  upsertSessionEntry,
} from "./session-accessor.js";
import { importSqliteSessionRows } from "./session-accessor.sqlite.js";
import * as sessionMemorySubjectModule from "./session-memory-subject.js";

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
  vi.restoreAllMocks();
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

  it("persists the isolated DM, group, and channel subject matrix", async () => {
    const { stateOptions, storePath } = createPaths();
    const principal = ensureEnterpriseMemoryPrincipal({
      issuer: "test-issuer",
      stableSubjectId: "isolated-dm-user",
      now: 100,
      options: stateOptions,
    });
    createMemoryIdentityBinding({
      channel: "telegram",
      accountId: "default",
      stableSenderId: "telegram-dm-user",
      principalId: principal.principalId,
      adapterId: "telegram-pairing",
      assurance: "adapter-attested",
      verificationMethod: "pairing",
      evidenceRevision: "dm-binding-revision",
      createdBy: "operator-1",
      now: 100,
      options: stateOptions,
    });
    const cases = [
      {
        label: "isolated DM",
        sessionKey: "agent:main:telegram:direct:telegram-dm-user",
        chatType: "direct" as const,
        sessionScope: "conversation",
        seed: prepareChannelBindingSessionMemorySubjectSeed({
          channel: "telegram",
          accountId: "default",
          stableSenderId: "telegram-dm-user",
          now: 101,
          options: stateOptions,
        }),
      },
      {
        label: "group",
        sessionKey: "agent:main:telegram:group:group-1",
        chatType: "group" as const,
        sessionScope: "group",
        seed: prepareConversationSessionMemorySubjectSeed({
          channel: "telegram",
          accountId: "default",
          conversationId: "group-1",
          canonicalConversationRef: "telegram:default:group:group-1",
          now: 101,
          options: stateOptions,
        }),
      },
      {
        label: "channel",
        sessionKey: "agent:main:discord:channel:channel-1",
        chatType: "channel" as const,
        sessionScope: "channel",
        seed: prepareConversationSessionMemorySubjectSeed({
          channel: "discord",
          accountId: "primary",
          conversationId: "channel-1",
          canonicalConversationRef: "discord:primary:channel:channel-1",
          now: 101,
          options: stateOptions,
        }),
      },
    ];

    for (const testCase of cases) {
      const scope = { agentId: "main", sessionKey: testCase.sessionKey, storePath };
      await upsertSessionEntry(
        scope,
        {
          chatType: testCase.chatType,
          sessionId: `${testCase.label.replaceAll(" ", "-")}-session`,
          updatedAt: 101,
        },
        { memorySubjectSeed: testCase.seed },
      );
      const snapshot = readCurrentSessionMemorySubject(scope);
      if (!snapshot) {
        throw new Error(`expected persisted ${testCase.label} memory subject`);
      }
      expect(snapshot.sessionScope).toBe(testCase.sessionScope);
      expect(snapshot.subjectRevision).toBe(testCase.seed.subjectRevision);
      expect(snapshot.subject).toEqual(testCase.seed.subject);
    }
  });

  it("normalizes autonomous agent IDs before resolving their principal", () => {
    const { stateOptions } = createPaths();
    const autonomous = prepareAutonomousAgentSessionMemorySubjectSeed(
      "  Research Agent  ",
      stateOptions,
    );
    const canonical = prepareExplicitSessionMemorySubjectSeed({
      kind: "agent",
      stableSubjectId: "research-agent",
      now: 100,
      options: stateOptions,
    });

    expect(autonomous.subject).toEqual(canonical.subject);
    expect(autonomous.subject).toMatchObject({ version: 1, kind: "agent" });
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
    if (!before) {
      throw new Error("expected pre-reset memory subject");
    }

    await resetSessionEntryLifecycle({
      buildNextEntry: () => ({ sessionId: "after-reset", updatedAt: 200 }),
      storePath,
      target: { canonicalKey: sessionKey, storeKeys: [sessionKey] },
    });
    const after = readCurrentSessionMemorySubject(scope);
    if (!after) {
      throw new Error("expected post-reset memory subject");
    }

    expect(after.sessionId).toBe("after-reset");
    expect(after.subjectRevision).toBe(before.subjectRevision);
    expect(after.subject).toEqual(before.subject);
    expect(after.sessionIdentityRevision).not.toBe(before.sessionIdentityRevision);
  });

  it("preserves confirmed import lineage and quarantines unconfirmed imports", async () => {
    const { stateOptions, storePath } = createPaths();
    const sourceScope = { agentId: "main", sessionKey: "agent:main:import-source", storePath };
    const sourceSeed = prepareExplicitSessionMemorySubjectSeed({
      kind: "service",
      stableSubjectId: "confirmed-import-source",
      now: 100,
      options: stateOptions,
    });
    await upsertSessionEntry(
      sourceScope,
      { sessionId: "import-source-session", updatedAt: 100 },
      { memorySubjectSeed: sourceSeed },
    );
    const source = readCurrentSessionMemorySubject(sourceScope);
    if (!source) {
      throw new Error("expected source import memory subject");
    }

    const confirmedKey = "agent:main:confirmed-import";
    await importSqliteSessionRows({
      agentId: "main",
      storePath,
      sessionKey: confirmedKey,
      entry: { sessionId: "confirmed-import-session", updatedAt: 110 },
      confirmedMemorySubjectLineage: prepareSessionMemorySubjectLineageSeed(source),
    });
    const confirmed = readCurrentSessionMemorySubject({
      agentId: "main",
      sessionKey: confirmedKey,
      storePath,
    });
    if (!confirmed) {
      throw new Error("expected confirmed import memory subject");
    }
    expect(confirmed.subjectRevision).toBe(source.subjectRevision);
    expect(confirmed.subject).toEqual(source.subject);

    const unconfirmedKey = "agent:main:unconfirmed-import";
    await importSqliteSessionRows({
      agentId: "main",
      storePath,
      sessionKey: unconfirmedKey,
      entry: { sessionId: "unconfirmed-import-session", updatedAt: 120 },
    });
    const unconfirmed = readCurrentSessionMemorySubject({
      agentId: "main",
      sessionKey: unconfirmedKey,
      storePath,
    });
    if (!unconfirmed) {
      throw new Error("expected unconfirmed import memory subject");
    }
    expect(unconfirmed.subject).toEqual({ version: 1, kind: "ambiguous", reason: "unbound" });
    expect(unconfirmed.subjectRevision).not.toBe(source.subjectRevision);
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
      verificationMethod: "oauth",
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

  it("fails closed when a binding is revoked between authority checks", async () => {
    const { stateOptions, storePath } = createPaths();
    const scope = { agentId: "main", sessionKey: "agent:main:binding-race", storePath };
    const principal = ensureEnterpriseMemoryPrincipal({
      issuer: "test-issuer",
      stableSubjectId: "binding-race-user",
      now: 100,
      options: stateOptions,
    });
    const binding = createMemoryIdentityBinding({
      channel: "telegram",
      accountId: "default",
      stableSenderId: "binding-race-user",
      principalId: principal.principalId,
      adapterId: "telegram-pairing",
      assurance: "adapter-attested",
      verificationMethod: "pairing",
      evidenceRevision: "binding-race-revision",
      createdBy: "operator-1",
      now: 100,
      options: stateOptions,
    });
    const seed = prepareChannelBindingSessionMemorySubjectSeed({
      channel: "telegram",
      accountId: "default",
      stableSenderId: "binding-race-user",
      now: 101,
      options: stateOptions,
    });
    await upsertSessionEntry(
      scope,
      { sessionId: "binding-race-session", updatedAt: 101 },
      { memorySubjectSeed: seed },
    );

    const resolveAuthority = sessionMemorySubjectModule.resolveSessionMemorySubjectAuthority;
    let authorityChecks = 0;
    const resolveAuthoritySpy = vi
      .spyOn(sessionMemorySubjectModule, "resolveSessionMemorySubjectAuthority")
      .mockImplementation((snapshot, options, now) => {
        const result = resolveAuthority(snapshot, options, now);
        authorityChecks += 1;
        if (authorityChecks === 1) {
          expect(result.kind).toBe("current");
          revokeMemoryIdentityBinding({
            bindingId: binding.bindingId,
            revokedBy: "operator-2",
            now: 102,
            options: stateOptions,
          });
        }
        return result;
      });

    expect(readCurrentSessionMemorySubjectAuthority(scope, stateOptions, 103)?.authority).toEqual({
      kind: "denied",
      reason: "binding-revoked",
    });
    expect(resolveAuthoritySpy).toHaveBeenCalledTimes(2);
  });

  it("rejects a session window replaced between authority checks", async () => {
    const { stateOptions, storePath } = createPaths();
    const scope = { agentId: "main", sessionKey: "agent:main:rebound-race", storePath };
    const seed = prepareExplicitSessionMemorySubjectSeed({
      kind: "service",
      stableSubjectId: "rebound-race-service",
      now: 100,
      options: stateOptions,
    });
    await upsertSessionEntry(
      scope,
      { sessionId: "rebound-race-before", updatedAt: 101 },
      { memorySubjectSeed: seed },
    );

    const resolveAuthority = sessionMemorySubjectModule.resolveSessionMemorySubjectAuthority;
    let replaced = false;
    const resolveAuthoritySpy = vi
      .spyOn(sessionMemorySubjectModule, "resolveSessionMemorySubjectAuthority")
      .mockImplementation((snapshot, options, now) => {
        const result = resolveAuthority(snapshot, options, now);
        if (!replaced) {
          replaced = true;
          replaceSessionEntrySync(scope, {
            sessionId: "rebound-race-after",
            updatedAt: 102,
          });
        }
        return result;
      });

    expect(() => readCurrentSessionMemorySubjectAuthority(scope, stateOptions, 103)).toThrow(
      SessionMemorySubjectReboundError,
    );
    expect(resolveAuthoritySpy).toHaveBeenCalledOnce();
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
