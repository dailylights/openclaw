import { createHash } from "node:crypto";
import { runOpenClawAgentWriteTransaction } from "../../state/openclaw-agent-db.js";
import { readExactSessionEntryRowForCanonicalRepair } from "./session-accessor.sqlite-canonical-repair.js";
import type { TranscriptEvent } from "./session-accessor.sqlite-contract.js";
import { publishSqliteSessionEntryCacheInvalidation } from "./session-accessor.sqlite-entry-cache.js";
import { writeSessionEntry } from "./session-accessor.sqlite-entry-store.js";
import { readTranscriptEventJsonSetInTransaction } from "./session-accessor.sqlite-read.js";
import {
  formatSqliteSessionReferenceForScope,
  resolveSqliteScope,
  runExclusiveSqliteSessionWrite,
  toDatabaseOptions,
} from "./session-accessor.sqlite-scope.js";
import {
  advanceTranscriptMutationAtInTransaction,
  touchTranscriptMutationInTransaction,
} from "./session-accessor.sqlite-transcript-state.js";
import { appendTranscriptEventInTransaction } from "./session-accessor.sqlite-transcript-store.js";
import {
  restoreSessionMemorySubjectIdentityRevisionInTransaction,
  type TrustedSessionMemorySubjectSeed,
} from "./session-memory-subject.js";
import { reconcileSessionTranscriptIndexInTransaction } from "./session-transcript-index.js";
import type {
  PreservedTranscriptMemoryPolicy,
  TranscriptMemoryPolicyExportManifest,
} from "./session-transcript-memory-policy.js";
import type { SessionEntry } from "./types.js";

/** Internal doctor/migration import target for one legacy session row. */
type SqliteSessionImportRowsParams = {
  allowMalformedRowRepair?: boolean;
  agentId?: string;
  env?: NodeJS.ProcessEnv;
  preserveExactStoredKey?: boolean;
  storePath?: string;
  sessionKey: string;
  entry: SessionEntry;
  /** Exact trusted provenance for an import whose source lineage was confirmed. */
  confirmedMemorySubjectLineage?: TrustedSessionMemorySubjectSeed;
  /** Byte-bound companion evidence from a trusted same-agent archive or export manifest. */
  confirmedTranscriptPolicyManifest?: TranscriptMemoryPolicyExportManifest;
  readTranscriptEvents?: (append: (event: TranscriptEvent) => void) => void;
  transcriptMtimeMs?: number;
};

/** Summary of rows written by an internal doctor/migration import. */
type SqliteSessionImportRowsResult = {
  sessionId: string;
  sessionKey: string;
  transcriptEvents: number;
};

type ConfirmedTranscriptPolicyImport = {
  orderedEventBindings: readonly Readonly<{
    contentSha256: string;
    preserved: PreservedTranscriptMemoryPolicy;
  }>[];
  sessionIdentityRevision?: string;
};

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function prepareConfirmedTranscriptPolicyImport(params: {
  confirmedMemorySubjectLineage?: TrustedSessionMemorySubjectSeed;
  manifest?: TranscriptMemoryPolicyExportManifest;
  sessionId: string;
}): ConfirmedTranscriptPolicyImport | undefined {
  const manifest = params.manifest;
  const seed = params.confirmedMemorySubjectLineage;
  if (!manifest || !seed || manifest.sessionId !== params.sessionId) {
    return undefined;
  }
  const orderedEventBindings: Array<
    Readonly<{ contentSha256: string; preserved: PreservedTranscriptMemoryPolicy }>
  > = [];
  const identityRevisions = new Set<string>();
  let previousEventSeq = -1;
  for (const event of manifest.events) {
    const { contentSha256, eventSeq, preserved } = event;
    const policy = preserved.policy;
    if (
      !/^[a-f0-9]{64}$/u.test(contentSha256) ||
      !Number.isSafeInteger(eventSeq) ||
      eventSeq < 0 ||
      eventSeq <= previousEventSeq ||
      policy.authorization_status !== "authorized" ||
      policy.session_id !== params.sessionId ||
      policy.event_seq !== eventSeq ||
      policy.subject_revision !== seed.subjectRevision ||
      policy.session_identity_revision === null ||
      preserved.detail.session_id !== params.sessionId ||
      preserved.detail.event_seq !== eventSeq ||
      preserved.lineage.session_id !== params.sessionId ||
      preserved.lineage.event_seq !== eventSeq
    ) {
      return undefined;
    }
    previousEventSeq = eventSeq;
    identityRevisions.add(policy.session_identity_revision);
    orderedEventBindings.push({ contentSha256, preserved });
  }
  if (identityRevisions.size > 1) {
    return undefined;
  }
  return {
    orderedEventBindings,
    ...(identityRevisions.size === 1 ? { sessionIdentityRevision: [...identityRevisions][0] } : {}),
  };
}

/** Imports one legacy session entry and its transcript rows for doctor migration. */
export async function importSqliteSessionRows(
  params: SqliteSessionImportRowsParams,
): Promise<SqliteSessionImportRowsResult> {
  const resolvedScope = resolveSqliteScope({
    ...(params.agentId ? { agentId: params.agentId } : {}),
    ...(params.env ? { env: params.env } : {}),
    sessionKey: params.sessionKey,
    ...(params.storePath ? { storePath: params.storePath } : {}),
  });
  // Doctor can stage the exact legacy key so canonical repair compares every alias candidate.
  const resolved = params.preserveExactStoredKey
    ? { ...resolvedScope, sessionKey: params.sessionKey }
    : resolvedScope;
  return await runExclusiveSqliteSessionWrite(resolved, async () => {
    let transcriptEvents = 0;
    runOpenClawAgentWriteTransaction((database) => {
      // Doctor may have staged another legacy alias in this database already. Inspect only this
      // exact import target; runtime-wide canonical validation runs after the import phase.
      const currentEntry = readExactSessionEntryRowForCanonicalRepair(
        database,
        resolved.sessionKey,
        {
          allowMalformedRowRepair: params.allowMalformedRowRepair === true,
        },
      )?.entry;
      const preservedHarnessId =
        params.entry.agentHarnessId === undefined &&
        currentEntry?.sessionId === params.entry.sessionId &&
        currentEntry.lifecycleRevision === params.entry.lifecycleRevision
          ? currentEntry.agentHarnessId?.trim()
          : undefined;
      // Plugin doctor migrations can claim a legacy session before the full
      // session import runs. Preserve that same-generation canonical owner.
      const importedEntry = {
        ...params.entry,
        ...(preservedHarnessId ? { agentHarnessId: preservedHarnessId } : {}),
        sessionFile: formatSqliteSessionReferenceForScope({
          ...resolved,
          sessionId: params.entry.sessionId,
        }),
      };
      // Doctor imports legacy aliases verbatim; canonical-key repair owns their normalization.
      writeSessionEntry(database, resolved.sessionKey, importedEntry, {
        allowStoredAliases: true,
        previousEntry: currentEntry ?? null,
        ...(params.confirmedMemorySubjectLineage
          ? { memorySubjectSeed: params.confirmedMemorySubjectLineage }
          : {}),
      });
      let confirmedPolicyImport = prepareConfirmedTranscriptPolicyImport({
        confirmedMemorySubjectLineage: params.confirmedMemorySubjectLineage,
        manifest: params.confirmedTranscriptPolicyManifest,
        sessionId: params.entry.sessionId,
      });
      if (
        confirmedPolicyImport?.sessionIdentityRevision &&
        !restoreSessionMemorySubjectIdentityRevisionInTransaction({
          database,
          expectedSessionIdentityRevision: confirmedPolicyImport.sessionIdentityRevision,
          expectedSubjectRevision: params.confirmedMemorySubjectLineage?.subjectRevision ?? "",
          sessionId: params.entry.sessionId,
        })
      ) {
        // A confirmed manifest must not change a source identity it cannot
        // restore exactly. Its events remain pending through the normal path.
        confirmedPolicyImport = undefined;
      }
      if (params.readTranscriptEvents) {
        const transcriptScope = {
          ...resolved,
          sessionId: params.entry.sessionId,
        };
        const existingEventJson = readTranscriptEventJsonSetInTransaction(
          database,
          params.entry.sessionId,
        );
        let sourceEventIndex = 0;
        params.readTranscriptEvents((event) => {
          // Visible exports omit denied rows, so the manifest's sorted order is
          // its portable position binding; hashes alone could remap duplicates.
          const manifestEvent = confirmedPolicyImport?.orderedEventBindings[sourceEventIndex];
          sourceEventIndex += 1;
          const eventJson = JSON.stringify(event);
          if (existingEventJson.has(eventJson)) {
            return;
          }
          const preservedMemoryPolicy =
            manifestEvent?.contentSha256 === sha256(eventJson)
              ? manifestEvent.preserved
              : undefined;
          if (
            appendTranscriptEventInTransaction(database, transcriptScope, event, {
              allowStoredAlias: true,
              // A raw legacy import does not prove a source event companion.
              // Do not rebuild authorization from its payload or session key.
              forceMemoryPolicyPending: true,
              ...(preservedMemoryPolicy ? { preservedMemoryPolicy } : {}),
              scheduleProjectionReconcile: false,
              touchMutation: false,
            })
          ) {
            existingEventJson.add(eventJson);
            transcriptEvents += 1;
          }
        });
        reconcileSessionTranscriptIndexInTransaction(database.db, params.entry.sessionId);
        publishSqliteSessionEntryCacheInvalidation(database);
      }
      if (params.transcriptMtimeMs !== undefined) {
        advanceTranscriptMutationAtInTransaction(
          database,
          params.entry.sessionId,
          params.transcriptMtimeMs,
        );
      } else if (transcriptEvents > 0) {
        touchTranscriptMutationInTransaction(database, params.entry.sessionId);
      }
    }, toDatabaseOptions(resolved));
    return {
      sessionId: params.entry.sessionId,
      sessionKey: resolved.sessionKey,
      transcriptEvents,
    };
  });
}
