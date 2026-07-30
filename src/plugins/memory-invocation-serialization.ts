import { randomBytes } from "node:crypto";
import { stableStringify } from "@openclaw/normalization-core";
import { sha256Hex } from "../infra/crypto-digest.js";
import type { AudienceRef } from "../memory-host-sdk/host/authorization.js";

export function createMemoryOpaqueId(prefix: string): string {
  return `${prefix}_${randomBytes(24).toString("base64url")}`;
}

export function hashMemoryRevision(prefix: string, value: unknown): string {
  return `${prefix}_${sha256Hex(stableStringify(value))}`;
}

function audienceKey(audience: AudienceRef): string {
  return `${audience.kind}\0${audience.id}`;
}

export function sortedMemoryAudiences(audiences: readonly AudienceRef[]): AudienceRef[] {
  return [...audiences].toSorted((left, right) =>
    audienceKey(left).localeCompare(audienceKey(right)),
  );
}

export function sortedUniqueMemoryStrings(values: readonly string[]): string[] {
  return [...new Set(values)].toSorted();
}

export function equalMemoryStringArrays(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export function equalMemoryAudiences(
  left: readonly AudienceRef[],
  right: readonly AudienceRef[],
): boolean {
  return (
    stableStringify(sortedMemoryAudiences(left)) === stableStringify(sortedMemoryAudiences(right))
  );
}

export function parseCanonicalMemoryStringArray(value: string): string[] | undefined {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (
      !Array.isArray(parsed) ||
      !parsed.every((entry) => typeof entry === "string" && entry.trim().length > 0)
    ) {
      return undefined;
    }
    const canonical = sortedUniqueMemoryStrings(parsed);
    return JSON.stringify(canonical) === value ? canonical : undefined;
  } catch {
    return undefined;
  }
}

export function canonicalMemoryStringArrayJson(values: readonly string[]): string {
  return JSON.stringify(sortedUniqueMemoryStrings(values));
}

export function createEffectiveMemoryPolicySetId(params: {
  memoryPolicyRevision: string;
  memberPolicySetIds: readonly string[];
}): string {
  return hashMemoryRevision("mpset1", {
    memoryPolicyRevision: params.memoryPolicyRevision,
    memberPolicySetIds: sortedUniqueMemoryStrings(params.memberPolicySetIds),
  });
}

export function parseCanonicalMemoryAudiences(value: string): AudienceRef[] | undefined {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!Array.isArray(parsed)) {
      return undefined;
    }
    const audiences: AudienceRef[] = [];
    for (const entry of parsed) {
      if (!entry || typeof entry !== "object") {
        return undefined;
      }
      const record = entry as Record<string, unknown>;
      if (
        typeof record.id !== "string" ||
        record.id.trim().length === 0 ||
        !["user", "conversation", "role", "agent-shared", "agent", "internal"].includes(
          String(record.kind),
        )
      ) {
        return undefined;
      }
      audiences.push({ kind: record.kind as AudienceRef["kind"], id: record.id });
    }
    const canonical = sortedMemoryAudiences(audiences);
    if (
      new Set(canonical.map(audienceKey)).size !== canonical.length ||
      JSON.stringify(canonical) !== value
    ) {
      return undefined;
    }
    return canonical;
  } catch {
    return undefined;
  }
}

export function canonicalMemoryAudiencesJson(audiences: readonly AudienceRef[]): string {
  return JSON.stringify(sortedMemoryAudiences(audiences));
}
