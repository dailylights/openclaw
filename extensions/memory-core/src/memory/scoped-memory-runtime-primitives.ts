import { createHash, randomBytes, randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import type {
  AudienceRef,
  AuthorizedMemoryMutation,
  AuthorizedMemoryResultEnvelope,
  AuthorizedResourceHandle,
  DeepReadonly,
  MemoryAccessContext,
  MemoryEgressAuthorizationReceipt,
  MemoryExposureReceipt,
} from "openclaw/plugin-sdk/memory-authorization";
import type { MemorySource } from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import { executeSqliteQuerySync, getNodeSqliteKysely } from "openclaw/plugin-sdk/sqlite-runtime";
import type { ScopedMemoryRevisionPolicyRequirement } from "./scoped-memory-authorization.js";
import type { ScopedMemoryCandidatePageReader } from "./scoped-memory-candidates.js";
import type { ScopedMemoryDatabase } from "./scoped-memory-db.js";

export const PLAN_TTL_MS = 5 * 60_000;
export const DEFAULT_MAX_PLANS = 1_024;
export const DEFAULT_MAX_HANDLES = 8_192;
const OPAQUE_ID_ATTEMPTS = 8;
export const MAX_SEARCH_RESULTS = 100;
export const MAX_CANDIDATES_SCANNED = 10_000;
const SCOPED_CHUNK_MAX_LINES = 40;
const SCOPED_CHUNK_MAX_CHARS = 4_000;
const MAX_PROJECTION_EXPOSURE_LINEAGE_DEPTH = 256;
export const STAGED_ARTIFACT_PATTERN = /^mwst1_[A-Za-z0-9_-]{18,}\.tmp$/u;
export const CALLER_SELECTED_MUTATION_DESTINATION_FIELDS = [
  "artifactLocator",
  "audience",
  "audienceId",
  "destinationAudience",
  "destinationHandle",
  "destinationOwnerId",
  "destinationStoreId",
  "logicalLocator",
  "owner",
  "ownerId",
  "path",
  "placementHandle",
  "root",
  "rootId",
  "store",
  "storeId",
] as const;

export type OpaqueIdKind = "plan" | "mount" | "resource" | "intent" | "stage";

export type HandleRecord = Readonly<{
  handle: AuthorizedResourceHandle;
  planId: string;
  storeId: string;
  resourceId: string;
  revisionId: string;
  expiresAtMs: number;
}>;

export type BuiltinScopedMemoryRuntimeDependencies = Readonly<{
  now?: () => number;
  generateOpaqueId?: (kind: OpaqueIdKind) => string;
  readFile?: typeof fs.readFileSync;
  candidatePageReader?: ScopedMemoryCandidatePageReader;
  embedQuery?: (query: string) => readonly number[] | Promise<readonly number[]>;
  maxPlans?: number;
  maxHandles?: number;
  /** Test-only interruption hook. It is called only between lifecycle transactions. */
  onMutationPhase?: (phase: "staged" | "pending" | "renamed" | "activated" | "indexed") => void;
}>;

function createOpaqueId(kind: OpaqueIdKind): string {
  const prefix =
    kind === "plan"
      ? "mp1"
      : kind === "mount"
        ? "mm1"
        : kind === "resource"
          ? "mrh1"
          : kind === "intent"
            ? "mwi1"
            : "mwst1";
  return `${prefix}_${randomBytes(24).toString("base64url")}`;
}

function assertOpaqueId(value: string): void {
  if (!/^[a-z0-9]+_[A-Za-z0-9_-]{24,}$/u.test(value)) {
    throw new Error("scoped-memory opaque identifier is invalid");
  }
}

export function allocateOpaqueId(params: {
  kind: OpaqueIdKind;
  occupied: (candidate: string) => boolean;
  generate?: (kind: OpaqueIdKind) => string;
}): string {
  for (let attempt = 0; attempt < OPAQUE_ID_ATTEMPTS; attempt += 1) {
    const candidate = params.generate?.(params.kind) ?? createOpaqueId(params.kind);
    assertOpaqueId(candidate);
    if (!params.occupied(candidate)) {
      return candidate;
    }
  }
  throw new Error("could not allocate a scoped-memory opaque identifier");
}

export function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function collectProjectionExposureAncestorRevisionIds(params: {
  database: DatabaseSync;
  revisionIds: readonly string[];
}): readonly string[] {
  const ancestorRevisionIds = new Set(params.revisionIds);
  const db = getNodeSqliteKysely<ScopedMemoryDatabase>(params.database);
  let frontier = [...ancestorRevisionIds];
  let depth = 0;
  while (frontier.length > 0) {
    // Exposure evidence must include every projection root that led to a shown
    // descendant. Bound this walk so malformed lineage fails closed, not partial.
    if (depth >= MAX_PROJECTION_EXPOSURE_LINEAGE_DEPTH) {
      throw new Error("memory projection exposure lineage is too deep");
    }
    const parents = executeSqliteQuerySync(
      params.database,
      db
        .selectFrom("memory_lineage_edges")
        .select("parent_revision_id")
        .where("child_revision_id", "in", frontier)
        .orderBy("child_revision_id")
        .orderBy("parent_revision_id"),
    ).rows;
    frontier = parents.flatMap((parent) => {
      if (ancestorRevisionIds.has(parent.parent_revision_id)) {
        return [];
      }
      ancestorRevisionIds.add(parent.parent_revision_id);
      return [parent.parent_revision_id];
    });
    depth += 1;
  }
  return [...ancestorRevisionIds].toSorted(compareText);
}

export type MemoryLineageEdgeKind = "revision" | "derive" | "project" | "publish";

export function mergeRevisionPolicyRequirements(
  requirements: readonly ScopedMemoryRevisionPolicyRequirement[],
): ScopedMemoryRevisionPolicyRequirement[] {
  const byPolicyId = new Map<string, ScopedMemoryRevisionPolicyRequirement>();
  for (const requirement of requirements) {
    const existing = byPolicyId.get(requirement.stablePolicyId);
    if (
      existing &&
      (existing.capturedRevisionId !== requirement.capturedRevisionId ||
        existing.expectedActiveRevisionId !== requirement.expectedActiveRevisionId ||
        existing.expectedRevocationEpoch !== requirement.expectedRevocationEpoch)
    ) {
      throw new Error("authorized memory mutation source policy is unavailable");
    }
    byPolicyId.set(requirement.stablePolicyId, requirement);
  }
  return [...byPolicyId.values()].toSorted((left, right) =>
    compareText(left.stablePolicyId, right.stablePolicyId),
  );
}

export function audienceKey(audience: AudienceRef): string {
  return `${audience.kind}\0${audience.id}`;
}

export function earliestContextExpiry(context: MemoryAccessContext): number | undefined {
  const expiries: number[] = [];
  if (context.actor.kind === "principal" && context.actor.expiresAt) {
    expiries.push(Date.parse(context.actor.expiresAt));
  }
  for (const principal of context.verifiedPrincipals) {
    if (principal.expiresAt) {
      expiries.push(Date.parse(principal.expiresAt));
    }
  }
  for (const membership of context.verifiedMemberships) {
    expiries.push(Date.parse(membership.expiresAt));
  }
  const valid = expiries.filter(Number.isFinite);
  return valid.length > 0 ? Math.min(...valid) : undefined;
}

export function normalizeSources(sources: readonly MemorySource[] | undefined): MemorySource[] {
  const normalized = [...new Set<MemorySource>(sources ?? ["memory", "sessions"])];
  if (normalized.some((source) => source !== "memory" && source !== "sessions")) {
    throw new Error("authorized memory source is invalid");
  }
  return normalized.toSorted(compareText);
}

export function freezeEnvelope<T>(params: {
  value: DeepReadonly<T>;
  exposureReceipt: MemoryExposureReceipt;
  egressReceipt: MemoryEgressAuthorizationReceipt;
}): AuthorizedMemoryResultEnvelope<T> {
  return Object.freeze({
    version: 1,
    value: params.value,
    exposureReceipt: params.exposureReceipt,
    egressReceipt: params.egressReceipt,
  });
}

export function hashText(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function createFinalArtifactLocator(): string {
  return `r1_${randomBytes(18).toString("base64url")}.md`;
}

export function createStagedArtifactLocator(): string {
  return `mwst1_${randomBytes(18).toString("base64url")}.tmp`;
}

export function resolveScopedArtifactChild(base: string, locator: string, pattern: RegExp): string {
  if (!pattern.test(locator)) {
    throw new Error("scoped-memory artifact locator is invalid");
  }
  const resolvedBase = path.resolve(base);
  const resolved = path.resolve(resolvedBase, locator);
  if (path.dirname(resolved) !== resolvedBase || path.basename(resolved) !== locator) {
    throw new Error("scoped-memory artifact locator escaped its storage root");
  }
  return resolved;
}

export function syncDirectory(directory: string): void {
  try {
    const descriptor = fs.openSync(directory, "r");
    try {
      fs.fsyncSync(descriptor);
    } finally {
      fs.closeSync(descriptor);
    }
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    // Windows cannot fsync directories. The staged file itself is always fsynced
    // before rename, so this is the narrow platform capability exception.
    if (code !== "EINVAL" && code !== "EPERM" && code !== "EISDIR") {
      throw error;
    }
  }
}

export function writeStagedArtifact(params: {
  directory: string;
  locator: string;
  content: string;
}): string {
  const pathname = resolveScopedArtifactChild(
    params.directory,
    params.locator,
    STAGED_ARTIFACT_PATTERN,
  );
  const descriptor = fs.openSync(pathname, "wx", 0o600);
  try {
    fs.writeFileSync(descriptor, params.content, "utf8");
    fs.fchmodSync(descriptor, 0o600);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  syncDirectory(params.directory);
  return pathname;
}

export function readVerifiedArtifact(params: {
  pathname: string;
  expectedHash: string;
  expectedBytes: number;
}): string | undefined {
  try {
    const content = fs.readFileSync(params.pathname, "utf8");
    return Buffer.byteLength(content) === params.expectedBytes &&
      hashText(content) === params.expectedHash
      ? content
      : undefined;
  } catch {
    return undefined;
  }
}

export function quarantineArtifact(pathname: string): void {
  try {
    const storeDirectory = path.dirname(pathname);
    const quarantineDirectory = path.join(path.dirname(storeDirectory), ".quarantine");
    fs.mkdirSync(quarantineDirectory, { recursive: true, mode: 0o700 });
    fs.chmodSync(quarantineDirectory, 0o700);
    fs.renameSync(pathname, path.join(quarantineDirectory, `orphan_${randomUUID()}`));
    syncDirectory(quarantineDirectory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
  }
}

export function chunkContent(content: string): Array<{
  ordinal: number;
  startLine: number;
  endLine: number;
  text: string;
}> {
  const lines = content.split(/\r?\n/u);
  const chunks: Array<{ ordinal: number; startLine: number; endLine: number; text: string }> = [];
  let start = 0;
  while (start < lines.length) {
    let end = start;
    let chars = 0;
    while (end < lines.length && end - start < SCOPED_CHUNK_MAX_LINES) {
      const nextChars = chars + (lines[end]?.length ?? 0) + (end === start ? 0 : 1);
      if (end > start && nextChars > SCOPED_CHUNK_MAX_CHARS) {
        break;
      }
      chars = nextChars;
      end += 1;
    }
    chunks.push({
      ordinal: chunks.length,
      startLine: start + 1,
      endLine: Math.max(start + 1, end),
      text: lines.slice(start, end).join("\n"),
    });
    start = end;
  }
  return chunks;
}

export function mutationOperation(
  mutation: AuthorizedMemoryMutation,
): MemoryAccessContext["operation"] {
  switch (mutation.kind) {
    case "remember":
    case "append":
      return "append";
    case "replace":
      return "replace";
    case "derive":
      return "derive";
    case "deposit":
      return "deposit";
    case "project":
      return "project";
    case "publish":
      return "publish";
    case "import":
      return "import";
    case "delete":
    case "tombstone":
      return "delete";
    case "admin-reclassify":
      return "policy-admin";
    default:
      throw new Error("authorized memory mutation kind is unsupported");
  }
}

export function actorRef(context: MemoryAccessContext): string {
  const value =
    context.actor.kind === "principal"
      ? `${context.actor.actorKind}\0${context.actor.principalId}\0${context.actor.evidenceRevision}`
      : `unattributed\0${context.actor.transportAuditRef}\0${context.actor.evidenceRevision}`;
  return `sha256:${hashText(value)}`;
}

export function subjectRef(context: MemoryAccessContext): string {
  return `sha256:${hashText(JSON.stringify(context.subject))}`;
}

export function actorRecord(context: MemoryAccessContext): {
  kind: "human" | "agent" | "service" | "system" | "unattributed";
  id: string | null;
} {
  if (context.actor.kind === "unattributed") {
    return { kind: "unattributed", id: null };
  }
  return { kind: context.actor.actorKind, id: context.actor.principalId };
}

/** Creates one isolated runtime instance; caches are bounded, expiring, and process-local. */
