import { resolveStorePath } from "../config/sessions/paths.js";
import {
  prepareAmbiguousSessionMemorySubjectSeed,
  prepareSessionMemorySubjectLineageSeed,
  readCurrentSessionMemorySubject,
  type TrustedSessionMemorySubjectSeed,
} from "../config/sessions/session-accessor.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { resolveSessionStoreKey } from "../gateway/session-store-key.js";

export function resolveAcpSpawnMemorySubjectSeed(params: {
  cfg: OpenClawConfig;
  requesterInternalKey: string;
  requesterAgentId: string;
}): TrustedSessionMemorySubjectSeed {
  const parentStoreKey = resolveSessionStoreKey({
    cfg: params.cfg,
    sessionKey: params.requesterInternalKey,
    storeAgentId: params.requesterAgentId,
  });
  // Capture parent provenance before the child database transaction starts.
  // Session access redirects incognito keys to their process-local database.
  const parentMemorySubject = readCurrentSessionMemorySubject({
    agentId: params.requesterAgentId,
    sessionKey: parentStoreKey,
    storePath: resolveStorePath(params.cfg.session?.store, {
      agentId: params.requesterAgentId,
    }),
  });
  return parentMemorySubject
    ? prepareSessionMemorySubjectLineageSeed(parentMemorySubject)
    : prepareAmbiguousSessionMemorySubjectSeed("unbound");
}
