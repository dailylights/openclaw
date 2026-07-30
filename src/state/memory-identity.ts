import type { DatabaseSync } from "node:sqlite";
import type { Selectable } from "kysely";
import {
  clearAuditIdentityKeyCacheForDatabase,
  loadOrCreateAuditIdentityKey,
  pseudonymizeAuditIdentity,
} from "../audit/audit-identity.js";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
} from "../infra/kysely-sync.js";
import { generateSecureUuid } from "../infra/secure-random.js";
import { MEMORY_IDENTITY_SCHEMA_SQL } from "./memory-identity-schema.js";
import type { DB as OpenClawStateKyselyDatabase } from "./openclaw-state-db.generated.js";
import {
  openOpenClawStateDatabase,
  runOpenClawStateWriteTransaction,
  type OpenClawStateDatabaseOptions,
} from "./openclaw-state-db.js";
import { resolveUserProfileId } from "./user-profiles.js";

type MemoryPrincipalKind =
  | "gateway-profile"
  | "enterprise"
  | "service"
  | "agent"
  | "system"
  | "conversation";

type MemoryPrincipal = Readonly<{
  principalId: string;
  kind: MemoryPrincipalKind;
  userProfileId?: string;
  issuer?: string;
  state: "active" | "revoked" | "merged";
  evidenceRevision: string;
  mergedInto?: string;
  expiresAt?: number;
  revokedAt?: number;
  createdAt: number;
  updatedAt: number;
}>;

export type MemoryIdentityBindingAssurance = "adapter-attested" | "oidc";
type MemoryIdentityVerificationMethod = "pairing" | "oauth" | "admin-link";

type MemoryIdentityBinding = Readonly<{
  bindingId: string;
  channel: string;
  accountId: string;
  principalId: string;
  adapterId: string;
  assurance: MemoryIdentityBindingAssurance;
  verificationMethod: MemoryIdentityVerificationMethod;
  evidenceRevision: string;
  createdBy: string;
  createdAt: number;
  expiresAt?: number;
  revokedAt?: number;
}>;

type MemoryIdentityBindingResolution =
  | Readonly<{
      kind: "verified";
      bindingId: string;
      principalId: string;
      assurance: MemoryIdentityBindingAssurance;
      evidenceRevision: string;
      expiresAt?: number;
    }>
  | Readonly<{ kind: "unbound" }>
  | Readonly<{ kind: "conflicting-bindings" }>;

type MemoryPrincipalResolution =
  | Readonly<{ kind: "current"; principal: MemoryPrincipal }>
  | Readonly<{ kind: "missing" | "revoked" | "expired" | "merge-cycle" }>;

type MemoryIdentityDatabase = Pick<
  OpenClawStateKyselyDatabase,
  "memory_identity_bindings" | "memory_principals"
>;
type MemoryPrincipalRow = Selectable<MemoryIdentityDatabase["memory_principals"]>;
type MemoryIdentityBindingRow = Selectable<MemoryIdentityDatabase["memory_identity_bindings"]>;

const ensuredDatabases = new WeakSet<DatabaseSync>();
const MAX_PRINCIPAL_MERGE_DEPTH = 64;

function memoryIdentityDb(db: DatabaseSync) {
  return getNodeSqliteKysely<MemoryIdentityDatabase>(db);
}

function requireText(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized) {
    throw new TypeError(`${label} must not be empty`);
  }
  return normalized;
}

function normalizeChannel(value: string): string {
  return requireText(value, "channel").toLowerCase();
}

function requireMemoryIdentityVerificationMethod(value: string): MemoryIdentityVerificationMethod {
  const normalized = requireText(value, "verificationMethod");
  if (normalized === "pairing" || normalized === "oauth" || normalized === "admin-link") {
    return normalized;
  }
  throw new TypeError("verificationMethod must be pairing, oauth, or admin-link");
}

function optionalNumber(value: number | null): number | undefined {
  return value === null ? undefined : value;
}

function toMemoryPrincipal(row: MemoryPrincipalRow): MemoryPrincipal {
  return {
    principalId: row.principal_id,
    kind: row.kind as MemoryPrincipalKind,
    ...(row.user_profile_id ? { userProfileId: row.user_profile_id } : {}),
    ...(row.issuer ? { issuer: row.issuer } : {}),
    state: row.state as MemoryPrincipal["state"],
    evidenceRevision: row.evidence_revision,
    ...(row.merged_into ? { mergedInto: row.merged_into } : {}),
    ...(row.expires_at === null ? {} : { expiresAt: row.expires_at }),
    ...(row.revoked_at === null ? {} : { revokedAt: row.revoked_at }),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function toMemoryIdentityBinding(row: MemoryIdentityBindingRow): MemoryIdentityBinding {
  return {
    bindingId: row.binding_id,
    channel: row.channel,
    accountId: row.account_id,
    principalId: row.principal_id,
    adapterId: row.adapter_id,
    assurance: row.assurance as MemoryIdentityBindingAssurance,
    verificationMethod: requireMemoryIdentityVerificationMethod(row.verification_method),
    evidenceRevision: row.evidence_revision,
    createdBy: row.created_by,
    createdAt: row.created_at,
    ...(row.expires_at === null ? {} : { expiresAt: row.expires_at }),
    ...(row.revoked_at === null ? {} : { revokedAt: row.revoked_at }),
  };
}

function ensureMemoryIdentitySchema(options: OpenClawStateDatabaseOptions): void {
  const database = openOpenClawStateDatabase(options);
  if (ensuredDatabases.has(database.db)) {
    return;
  }
  runOpenClawStateWriteTransaction(
    ({ db }) => {
      db.exec(MEMORY_IDENTITY_SCHEMA_SQL);
    },
    options,
    { operationLabel: "memory-identity.schema.ensure" },
  );
  ensuredDatabases.add(database.db);
}

function readPrincipalRow(db: DatabaseSync, principalId: string): MemoryPrincipalRow | undefined {
  return executeSqliteQueryTakeFirstSync(
    db,
    memoryIdentityDb(db)
      .selectFrom("memory_principals")
      .selectAll()
      .where("principal_id", "=", principalId),
  );
}

function resolvePrincipalInDatabase(
  db: DatabaseSync,
  principalId: string,
  now: number,
): MemoryPrincipalResolution {
  let currentId = principalId;
  const visited = new Set<string>();
  for (let depth = 0; depth < MAX_PRINCIPAL_MERGE_DEPTH; depth++) {
    if (visited.has(currentId)) {
      return { kind: "merge-cycle" };
    }
    visited.add(currentId);
    const row = readPrincipalRow(db, currentId);
    if (!row) {
      return { kind: "missing" };
    }
    if (row.state === "merged") {
      if (!row.merged_into) {
        return { kind: "missing" };
      }
      currentId = row.merged_into;
      continue;
    }
    if (row.state === "revoked") {
      return { kind: "revoked" };
    }
    if (row.expires_at !== null && row.expires_at <= now) {
      return { kind: "expired" };
    }
    return { kind: "current", principal: toMemoryPrincipal(row) };
  }
  return { kind: "merge-cycle" };
}

function identityLookupHmac(params: {
  db: DatabaseSync;
  channel: string;
  accountId: string;
  value: string;
}): string {
  // Reuse the installation-local audit identity key with its existing corruption and
  // rollback handling. The audit helper domain-separates actor pseudonyms and retains
  // no raw provider sender identifier.
  const value = pseudonymizeAuditIdentity({
    identity: loadOrCreateAuditIdentityKey(params.db),
    kind: "actor",
    channel: params.channel,
    accountId: params.accountId,
    value: params.value,
  });
  if (!value) {
    throw new Error("memory identity lookup HMAC could not be created");
  }
  return value;
}

function runMemoryIdentityTransaction<T>(
  options: OpenClawStateDatabaseOptions,
  operationLabel: string,
  operation: (db: DatabaseSync) => T,
): T {
  ensureMemoryIdentitySchema(options);
  let database: DatabaseSync | undefined;
  try {
    return runOpenClawStateWriteTransaction(
      ({ db }) => {
        database = db;
        return operation(db);
      },
      options,
      { operationLabel },
    );
  } catch (error) {
    if (database) {
      clearAuditIdentityKeyCacheForDatabase(database);
    }
    throw error;
  }
}

function ensureOpaquePrincipal(params: {
  kind: Exclude<MemoryPrincipalKind, "gateway-profile">;
  issuer: string;
  stableSubjectId: string;
  expiresAt?: number;
  now?: number;
  options?: OpenClawStateDatabaseOptions;
}): MemoryPrincipal {
  const issuer = requireText(params.issuer, "issuer");
  const stableSubjectId = requireText(params.stableSubjectId, "stableSubjectId");
  const now = params.now ?? Date.now();
  if (params.expiresAt !== undefined && params.expiresAt <= now) {
    throw new TypeError("expiresAt must be in the future");
  }
  return runMemoryIdentityTransaction(params.options ?? {}, "memory-principal.ensure", (db) => {
    const subjectKey = identityLookupHmac({
      db,
      channel: `memory-principal:${params.kind}`,
      accountId: issuer,
      value: stableSubjectId,
    });
    const kysely = memoryIdentityDb(db);
    let row = executeSqliteQueryTakeFirstSync(
      db,
      kysely
        .selectFrom("memory_principals")
        .selectAll()
        .where("kind", "=", params.kind)
        .where("issuer", "=", issuer)
        .where("subject_key", "=", subjectKey),
    );
    if (!row) {
      const principalId = generateSecureUuid();
      executeSqliteQuerySync(
        db,
        kysely.insertInto("memory_principals").values({
          principal_id: principalId,
          kind: params.kind,
          user_profile_id: null,
          issuer,
          subject_key: subjectKey,
          state: "active",
          evidence_revision: generateSecureUuid(),
          merged_into: null,
          expires_at: params.expiresAt ?? null,
          revoked_at: null,
          created_at: now,
          updated_at: now,
        }),
      );
      row = readPrincipalRow(db, principalId);
    }
    if (!row) {
      throw new Error("memory principal could not be created");
    }
    const resolved = resolvePrincipalInDatabase(db, row.principal_id, now);
    if (resolved.kind !== "current") {
      throw new Error(`memory principal is not current: ${resolved.kind}`);
    }
    return resolved.principal;
  });
}

/** Resolves an authenticated durable Gateway profile into its canonical principal. */
function ensureGatewayProfileMemoryPrincipal(
  profileId: string,
  options: OpenClawStateDatabaseOptions = {},
): MemoryPrincipal | undefined {
  const requestedProfileId = requireText(profileId, "profileId");
  const resolvedProfileId = resolveUserProfileId(requestedProfileId, options);
  if (!resolvedProfileId) {
    return undefined;
  }
  const now = Date.now();
  return runMemoryIdentityTransaction(options, "memory-principal.gateway-profile.ensure", (db) => {
    const kysely = memoryIdentityDb(db);
    let head = executeSqliteQueryTakeFirstSync(
      db,
      kysely
        .selectFrom("memory_principals")
        .selectAll()
        .where("user_profile_id", "=", resolvedProfileId),
    );
    if (!head) {
      const principalId = generateSecureUuid();
      executeSqliteQuerySync(
        db,
        kysely.insertInto("memory_principals").values({
          principal_id: principalId,
          kind: "gateway-profile",
          user_profile_id: resolvedProfileId,
          issuer: null,
          subject_key: null,
          state: "active",
          evidence_revision: generateSecureUuid(),
          merged_into: null,
          expires_at: null,
          revoked_at: null,
          created_at: now,
          updated_at: now,
        }),
      );
      head = readPrincipalRow(db, principalId);
    }
    if (!head) {
      throw new Error("Gateway profile memory principal could not be created");
    }
    if (requestedProfileId !== resolvedProfileId) {
      const source = executeSqliteQueryTakeFirstSync(
        db,
        kysely
          .selectFrom("memory_principals")
          .selectAll()
          .where("user_profile_id", "=", requestedProfileId),
      );
      if (source && source.principal_id !== head.principal_id && source.state !== "revoked") {
        executeSqliteQuerySync(
          db,
          kysely
            .updateTable("memory_principals")
            .set({ state: "merged", merged_into: head.principal_id, updated_at: now })
            .where("principal_id", "=", source.principal_id),
        );
      }
    }
    const resolved = resolvePrincipalInDatabase(db, head.principal_id, now);
    return resolved.kind === "current" ? resolved.principal : undefined;
  });
}

function ensureEnterpriseMemoryPrincipal(params: {
  issuer: string;
  stableSubjectId: string;
  expiresAt?: number;
  now?: number;
  options?: OpenClawStateDatabaseOptions;
}): MemoryPrincipal {
  return ensureOpaquePrincipal({ ...params, kind: "enterprise" });
}

function ensureExplicitMemoryPrincipal(params: {
  kind: "service" | "agent" | "system";
  issuer?: string;
  stableSubjectId: string;
  expiresAt?: number;
  now?: number;
  options?: OpenClawStateDatabaseOptions;
}): MemoryPrincipal {
  return ensureOpaquePrincipal({
    ...params,
    issuer: params.issuer ?? "openclaw",
  });
}

function ensureConversationMemoryPrincipal(params: {
  channel: string;
  accountId: string;
  conversationId: string;
  now?: number;
  options?: OpenClawStateDatabaseOptions;
}): MemoryPrincipal {
  const channel = normalizeChannel(params.channel);
  const accountId = requireText(params.accountId, "accountId");
  return ensureOpaquePrincipal({
    kind: "conversation",
    issuer: channel,
    stableSubjectId: JSON.stringify([
      accountId,
      requireText(params.conversationId, "conversationId"),
    ]),
    now: params.now,
    options: params.options,
  });
}

/** Creates verified channel-to-principal evidence without retaining the raw sender id. */
function createMemoryIdentityBinding(params: {
  channel: string;
  accountId: string;
  stableSenderId: string;
  principalId: string;
  adapterId: string;
  assurance: MemoryIdentityBindingAssurance;
  verificationMethod: MemoryIdentityVerificationMethod;
  evidenceRevision: string;
  createdBy: string;
  expiresAt?: number;
  now?: number;
  options?: OpenClawStateDatabaseOptions;
}): MemoryIdentityBinding {
  const channel = normalizeChannel(params.channel);
  const accountId = requireText(params.accountId, "accountId");
  const stableSenderId = requireText(params.stableSenderId, "stableSenderId");
  const principalId = requireText(params.principalId, "principalId");
  const adapterId = requireText(params.adapterId, "adapterId");
  const verificationMethod = requireMemoryIdentityVerificationMethod(params.verificationMethod);
  const evidenceRevision = requireText(params.evidenceRevision, "evidenceRevision");
  const createdBy = requireText(params.createdBy, "createdBy");
  const now = params.now ?? Date.now();
  if (params.expiresAt !== undefined && params.expiresAt <= now) {
    throw new TypeError("expiresAt must be in the future");
  }
  return runMemoryIdentityTransaction(
    params.options ?? {},
    "memory-identity-binding.create",
    (db) => {
      const principal = resolvePrincipalInDatabase(db, principalId, now);
      if (principal.kind !== "current") {
        throw new Error(`memory binding principal is not current: ${principal.kind}`);
      }
      if (
        principal.principal.kind !== "gateway-profile" &&
        principal.principal.kind !== "enterprise"
      ) {
        throw new Error(
          `memory binding principal must be a verified user: ${principal.principal.kind}`,
        );
      }
      const bindingId = generateSecureUuid();
      const senderLookupHmac = identityLookupHmac({
        db,
        channel,
        accountId,
        value: stableSenderId,
      });
      executeSqliteQuerySync(
        db,
        memoryIdentityDb(db)
          .insertInto("memory_identity_bindings")
          .values({
            binding_id: bindingId,
            channel,
            account_id: accountId,
            sender_lookup_hmac: senderLookupHmac,
            principal_id: principal.principal.principalId,
            adapter_id: adapterId,
            assurance: params.assurance,
            verification_method: verificationMethod,
            evidence_revision: evidenceRevision,
            created_by: createdBy,
            created_at: now,
            expires_at: params.expiresAt ?? null,
            revoked_at: null,
            revoked_by: null,
            revocation_reason: null,
          }),
      );
      const row = executeSqliteQueryTakeFirstSync(
        db,
        memoryIdentityDb(db)
          .selectFrom("memory_identity_bindings")
          .selectAll()
          .where("binding_id", "=", bindingId),
      );
      if (!row) {
        throw new Error("memory identity binding could not be created");
      }
      return toMemoryIdentityBinding(row);
    },
  );
}

/** Revokes a binding while retaining its verification history. */
function revokeMemoryIdentityBinding(params: {
  bindingId: string;
  revokedBy: string;
  reason?: string;
  now?: number;
  options?: OpenClawStateDatabaseOptions;
}): boolean {
  const bindingId = requireText(params.bindingId, "bindingId");
  const revokedBy = requireText(params.revokedBy, "revokedBy");
  const reason = params.reason?.trim() || null;
  const now = params.now ?? Date.now();
  return runMemoryIdentityTransaction(
    params.options ?? {},
    "memory-identity-binding.revoke",
    (db) => {
      const result = executeSqliteQuerySync(
        db,
        memoryIdentityDb(db)
          .updateTable("memory_identity_bindings")
          .set({ revoked_at: now, revoked_by: revokedBy, revocation_reason: reason })
          .where("binding_id", "=", bindingId)
          .where("revoked_at", "is", null),
      );
      return Number(result.numAffectedRows ?? 0n) > 0;
    },
  );
}

/** Resolves active evidence to one current merge head; ambiguity fails closed. */
function resolveMemoryIdentityBinding(params: {
  channel: string;
  accountId: string;
  stableSenderId: string;
  now?: number;
  options?: OpenClawStateDatabaseOptions;
}): MemoryIdentityBindingResolution {
  const channel = normalizeChannel(params.channel);
  const accountId = requireText(params.accountId, "accountId");
  const stableSenderId = requireText(params.stableSenderId, "stableSenderId");
  const options = params.options ?? {};
  const now = params.now ?? Date.now();
  ensureMemoryIdentitySchema(options);
  const { db } = openOpenClawStateDatabase(options);
  const hasBindings = executeSqliteQueryTakeFirstSync(
    db,
    memoryIdentityDb(db).selectFrom("memory_identity_bindings").select("binding_id").limit(1),
  );
  if (!hasBindings) {
    return { kind: "unbound" };
  }
  const senderLookupHmac = identityLookupHmac({ db, channel, accountId, value: stableSenderId });
  const rows = executeSqliteQuerySync(
    db,
    memoryIdentityDb(db)
      .selectFrom("memory_identity_bindings")
      .selectAll()
      .where("channel", "=", channel)
      .where("account_id", "=", accountId)
      .where("sender_lookup_hmac", "=", senderLookupHmac),
  ).rows;
  const current = new Map<string, { row: MemoryIdentityBindingRow; principal: MemoryPrincipal }>();
  for (const row of rows) {
    if (row.revoked_at !== null || (row.expires_at !== null && row.expires_at <= now)) {
      continue;
    }
    const principal = resolvePrincipalInDatabase(db, row.principal_id, now);
    if (principal.kind !== "current") {
      continue;
    }
    current.set(principal.principal.principalId, { row, principal: principal.principal });
  }
  if (current.size === 0) {
    return { kind: "unbound" };
  }
  if (current.size > 1) {
    return { kind: "conflicting-bindings" };
  }
  const onlyBinding = current.values().next().value;
  if (!onlyBinding) {
    return { kind: "unbound" };
  }
  const { row, principal } = onlyBinding;
  return {
    kind: "verified",
    bindingId: row.binding_id,
    principalId: principal.principalId,
    assurance: row.assurance as MemoryIdentityBindingAssurance,
    evidenceRevision: row.evidence_revision,
    ...(optionalNumber(row.expires_at) === undefined
      ? {}
      : { expiresAt: row.expires_at ?? undefined }),
  };
}

/** Rechecks one captured binding and its current principal merge head. */
function resolveCurrentMemoryIdentityBinding(params: {
  bindingId: string;
  principalId: string;
  evidenceRevision: string;
  now?: number;
  options?: OpenClawStateDatabaseOptions;
}): MemoryIdentityBindingResolution {
  const options = params.options ?? {};
  const now = params.now ?? Date.now();
  ensureMemoryIdentitySchema(options);
  const { db } = openOpenClawStateDatabase(options);
  const row = executeSqliteQueryTakeFirstSync(
    db,
    memoryIdentityDb(db)
      .selectFrom("memory_identity_bindings")
      .selectAll()
      .where("binding_id", "=", requireText(params.bindingId, "bindingId")),
  );
  if (
    !row ||
    row.evidence_revision !== params.evidenceRevision ||
    row.revoked_at !== null ||
    (row.expires_at !== null && row.expires_at <= now)
  ) {
    return { kind: "unbound" };
  }
  const principal = resolvePrincipalInDatabase(db, row.principal_id, now);
  const capturedPrincipal = resolvePrincipalInDatabase(
    db,
    requireText(params.principalId, "principalId"),
    now,
  );
  if (
    principal.kind !== "current" ||
    capturedPrincipal.kind !== "current" ||
    principal.principal.principalId !== capturedPrincipal.principal.principalId
  ) {
    return { kind: "unbound" };
  }
  return {
    kind: "verified",
    bindingId: row.binding_id,
    principalId: principal.principal.principalId,
    assurance: row.assurance as MemoryIdentityBindingAssurance,
    evidenceRevision: row.evidence_revision,
    ...(row.expires_at === null ? {} : { expiresAt: row.expires_at }),
  };
}

function resolveMemoryPrincipal(
  principalId: string,
  options: OpenClawStateDatabaseOptions = {},
  now = Date.now(),
): MemoryPrincipalResolution {
  ensureMemoryIdentitySchema(options);
  return resolvePrincipalInDatabase(
    openOpenClawStateDatabase(options).db,
    requireText(principalId, "principalId"),
    now,
  );
}

/** Leaves a durable tombstone that redirects future authority checks to one head. */
function mergeMemoryPrincipals(params: {
  sourcePrincipalId: string;
  targetPrincipalId: string;
  now?: number;
  options?: OpenClawStateDatabaseOptions;
}): MemoryPrincipal {
  const sourcePrincipalId = requireText(params.sourcePrincipalId, "sourcePrincipalId");
  const targetPrincipalId = requireText(params.targetPrincipalId, "targetPrincipalId");
  if (sourcePrincipalId === targetPrincipalId) {
    throw new TypeError("memory principal cannot merge into itself");
  }
  const now = params.now ?? Date.now();
  return runMemoryIdentityTransaction(params.options ?? {}, "memory-principal.merge", (db) => {
    const source = resolvePrincipalInDatabase(db, sourcePrincipalId, now);
    const target = resolvePrincipalInDatabase(db, targetPrincipalId, now);
    if (source.kind !== "current" || target.kind !== "current") {
      throw new Error("memory principal merge requires two current principals");
    }
    if (source.principal.principalId === target.principal.principalId) {
      return target.principal;
    }
    executeSqliteQuerySync(
      db,
      memoryIdentityDb(db)
        .updateTable("memory_principals")
        .set({ state: "merged", merged_into: target.principal.principalId, updated_at: now })
        .where("principal_id", "=", source.principal.principalId),
    );
    return target.principal;
  });
}

function revokeMemoryPrincipal(params: {
  principalId: string;
  now?: number;
  options?: OpenClawStateDatabaseOptions;
}): boolean {
  const principalId = requireText(params.principalId, "principalId");
  const now = params.now ?? Date.now();
  return runMemoryIdentityTransaction(params.options ?? {}, "memory-principal.revoke", (db) => {
    const result = executeSqliteQuerySync(
      db,
      memoryIdentityDb(db)
        .updateTable("memory_principals")
        .set({ state: "revoked", revoked_at: now, updated_at: now })
        .where("principal_id", "=", principalId)
        .where("state", "=", "active"),
    );
    return Number(result.numAffectedRows ?? 0n) > 0;
  });
}

/** Core-owned lifecycle for canonical principals and verified transport bindings. */
export const memoryIdentityLifecycle = Object.freeze({
  createMemoryIdentityBinding,
  ensureConversationMemoryPrincipal,
  ensureEnterpriseMemoryPrincipal,
  ensureExplicitMemoryPrincipal,
  ensureGatewayProfileMemoryPrincipal,
  mergeMemoryPrincipals,
  resolveCurrentMemoryIdentityBinding,
  resolveMemoryIdentityBinding,
  resolveMemoryPrincipal,
  revokeMemoryIdentityBinding,
  revokeMemoryPrincipal,
});
