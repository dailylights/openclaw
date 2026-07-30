import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { useAutoCleanupTempDirTracker } from "../../test/helpers/temp-dir.js";
import { memoryIdentityLifecycle } from "./memory-identity.js";
import {
  closeOpenClawStateDatabaseForTest,
  openOpenClawStateDatabase,
} from "./openclaw-state-db.js";
import { ensureProfileForEmail } from "./user-profiles.js";

const {
  createMemoryIdentityBinding,
  ensureEnterpriseMemoryPrincipal,
  ensureExplicitMemoryPrincipal,
  ensureGatewayProfileMemoryPrincipal,
  mergeMemoryPrincipals,
  resolveCurrentMemoryIdentityBinding,
  resolveMemoryIdentityBinding,
  resolveMemoryPrincipal,
  revokeMemoryIdentityBinding,
  revokeMemoryPrincipal,
} = memoryIdentityLifecycle;

const tempDirectories = useAutoCleanupTempDirTracker(afterEach);

function createStateOptions() {
  const directory = tempDirectories.make("openclaw-memory-identity-");
  return { path: path.join(directory, "openclaw.sqlite") };
}

afterEach(() => {
  closeOpenClawStateDatabaseForTest();
});

describe("memory identity", () => {
  it("maps a durable Gateway profile to one idempotent principal", () => {
    const options = createStateOptions();
    const profile = ensureProfileForEmail("owner@example.test", options);

    const first = ensureGatewayProfileMemoryPrincipal(profile.id, options);
    const second = ensureGatewayProfileMemoryPrincipal(profile.id, options);

    expect(first).toMatchObject({
      kind: "gateway-profile",
      state: "active",
      userProfileId: profile.id,
    });
    expect(second).toEqual(first);
  });

  it("resolves a verified sender binding without retaining the raw sender id", () => {
    const options = createStateOptions();
    const profile = ensureProfileForEmail("owner@example.test", options);
    const principal = ensureGatewayProfileMemoryPrincipal(profile.id, options);
    if (!principal) {
      throw new Error("expected Gateway profile principal");
    }
    const stableSenderId = "provider-user-raw-123";
    const binding = createMemoryIdentityBinding({
      channel: "Telegram",
      accountId: "default",
      stableSenderId,
      principalId: principal.principalId,
      adapterId: "telegram-pairing",
      assurance: "adapter-attested",
      verificationMethod: "pairing",
      evidenceRevision: "pairing-revision-1",
      createdBy: "operator-1",
      now: 100,
      options,
    });

    expect(
      resolveMemoryIdentityBinding({
        channel: "telegram",
        accountId: "default",
        stableSenderId,
        now: 101,
        options,
      }),
    ).toEqual({
      kind: "verified",
      bindingId: binding.bindingId,
      principalId: principal.principalId,
      assurance: "adapter-attested",
      evidenceRevision: "pairing-revision-1",
    });
    const row = openOpenClawStateDatabase(options)
      .db.prepare(
        "SELECT channel, account_id, sender_lookup_hmac FROM memory_identity_bindings WHERE binding_id = ?",
      )
      .get(binding.bindingId) as
      | { channel: string; account_id: string; sender_lookup_hmac: string }
      | undefined;
    expect(row).toMatchObject({ channel: "telegram", account_id: "default" });
    expect(row?.sender_lookup_hmac).not.toBe(stableSenderId);
    expect(JSON.stringify(row)).not.toContain(stableSenderId);
  });

  it("fails closed for conflicting, expired, and revoked binding evidence", () => {
    const options = createStateOptions();
    const first = ensureEnterpriseMemoryPrincipal({
      issuer: "test-issuer",
      stableSubjectId: "service-a",
      now: 100,
      options,
    });
    const second = ensureEnterpriseMemoryPrincipal({
      issuer: "test-issuer",
      stableSubjectId: "service-b",
      now: 100,
      options,
    });
    const createBinding = (principalId: string, evidenceRevision: string, expiresAt?: number) =>
      createMemoryIdentityBinding({
        channel: "signal",
        accountId: "primary",
        stableSenderId: "sender-1",
        principalId,
        adapterId: "signal-link",
        assurance: "oidc",
        verificationMethod: "oauth",
        evidenceRevision,
        createdBy: "operator-1",
        expiresAt,
        now: 100,
        options,
      });
    const firstBinding = createBinding(first.principalId, "evidence-a");
    const secondBinding = createBinding(second.principalId, "evidence-b", 200);

    expect(
      resolveMemoryIdentityBinding({
        channel: "signal",
        accountId: "primary",
        stableSenderId: "sender-1",
        now: 150,
        options,
      }),
    ).toEqual({ kind: "conflicting-bindings" });

    expect(
      revokeMemoryIdentityBinding({
        bindingId: secondBinding.bindingId,
        revokedBy: "operator-2",
        reason: "wrong account",
        now: 151,
        options,
      }),
    ).toBe(true);
    expect(
      resolveMemoryIdentityBinding({
        channel: "signal",
        accountId: "primary",
        stableSenderId: "sender-1",
        now: 152,
        options,
      }),
    ).toMatchObject({
      kind: "verified",
      bindingId: firstBinding.bindingId,
      principalId: first.principalId,
    });

    expect(
      revokeMemoryIdentityBinding({
        bindingId: firstBinding.bindingId,
        revokedBy: "operator-2",
        now: 153,
        options,
      }),
    ).toBe(true);
    expect(
      resolveCurrentMemoryIdentityBinding({
        bindingId: firstBinding.bindingId,
        principalId: first.principalId,
        evidenceRevision: "evidence-a",
        now: 154,
        options,
      }),
    ).toEqual({ kind: "unbound" });
    expect(
      resolveMemoryIdentityBinding({
        channel: "signal",
        accountId: "primary",
        stableSenderId: "sender-1",
        now: 201,
        options,
      }),
    ).toEqual({ kind: "unbound" });
  });

  it("follows merge heads and denies authority after the head is revoked", () => {
    const options = createStateOptions();
    const source = ensureEnterpriseMemoryPrincipal({
      issuer: "test-issuer",
      stableSubjectId: "source",
      now: 100,
      options,
    });
    const target = ensureEnterpriseMemoryPrincipal({
      issuer: "test-issuer",
      stableSubjectId: "target",
      now: 100,
      options,
    });
    const binding = createMemoryIdentityBinding({
      channel: "irc",
      accountId: "default",
      stableSenderId: "nick-account-id",
      principalId: source.principalId,
      adapterId: "irc-account-link",
      assurance: "adapter-attested",
      verificationMethod: "admin-link",
      evidenceRevision: "binding-revision",
      createdBy: "operator-1",
      now: 100,
      options,
    });

    expect(
      mergeMemoryPrincipals({
        sourcePrincipalId: source.principalId,
        targetPrincipalId: target.principalId,
        now: 110,
        options,
      }),
    ).toMatchObject({ principalId: target.principalId });
    expect(resolveMemoryPrincipal(source.principalId, options, 111)).toMatchObject({
      kind: "current",
      principal: { principalId: target.principalId },
    });
    expect(
      resolveCurrentMemoryIdentityBinding({
        bindingId: binding.bindingId,
        principalId: source.principalId,
        evidenceRevision: binding.evidenceRevision,
        now: 111,
        options,
      }),
    ).toMatchObject({ kind: "verified", principalId: target.principalId });

    expect(revokeMemoryPrincipal({ principalId: target.principalId, now: 120, options })).toBe(
      true,
    );
    expect(resolveMemoryPrincipal(source.principalId, options, 121)).toEqual({ kind: "revoked" });
    expect(
      resolveCurrentMemoryIdentityBinding({
        bindingId: binding.bindingId,
        principalId: source.principalId,
        evidenceRevision: binding.evidenceRevision,
        now: 121,
        options,
      }),
    ).toEqual({ kind: "unbound" });
  });

  it("rejects channel bindings to non-user principals", () => {
    const options = createStateOptions();
    const service = ensureExplicitMemoryPrincipal({
      kind: "service",
      stableSubjectId: "background-task",
      now: 100,
      options,
    });

    expect(() =>
      createMemoryIdentityBinding({
        channel: "telegram",
        accountId: "default",
        stableSenderId: "sender-1",
        principalId: service.principalId,
        adapterId: "telegram-pairing",
        assurance: "adapter-attested",
        verificationMethod: "pairing",
        evidenceRevision: "pairing-revision-1",
        createdBy: "operator-1",
        now: 100,
        options,
      }),
    ).toThrow("memory binding principal must be a verified user: service");
  });

  it("accepts only pairing, OAuth, or admin-link verification methods", () => {
    const options = createStateOptions();
    const principal = ensureEnterpriseMemoryPrincipal({
      issuer: "test-issuer",
      stableSubjectId: "verified-user",
      now: 100,
      options,
    });

    expect(() =>
      createMemoryIdentityBinding({
        channel: "signal",
        accountId: "default",
        stableSenderId: "sender-1",
        principalId: principal.principalId,
        adapterId: "signal-link",
        assurance: "oidc",
        verificationMethod: "oidc" as never,
        evidenceRevision: "evidence-1",
        createdBy: "operator-1",
        now: 100,
        options,
      }),
    ).toThrow("verificationMethod must be pairing, oauth, or admin-link");
  });
});
