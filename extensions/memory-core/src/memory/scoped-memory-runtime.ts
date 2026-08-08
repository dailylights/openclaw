import fs from "node:fs";
import type {
  AuthorizedMemoryPlan,
  AuthorizedMemoryMutation,
  MemoryAccessContext,
  MemoryWriteResult,
} from "openclaw/plugin-sdk/memory-authorization";
import type { ScopedMemoryPlanRecord } from "./scoped-memory-authorization.js";
import { readScopedMemoryFtsCandidatePage } from "./scoped-memory-candidates.js";
import { createScopedMemoryRuntimeOperations } from "./scoped-memory-runtime-operations.js";
import { createScopedMemoryRuntimePlanOperations } from "./scoped-memory-runtime-plans.js";
import {
  DEFAULT_MAX_HANDLES,
  DEFAULT_MAX_PLANS,
  type BuiltinScopedMemoryRuntimeDependencies,
  type HandleRecord,
} from "./scoped-memory-runtime-primitives.js";
import { createScopedMemoryRuntimeRecoveryOperations } from "./scoped-memory-runtime-recovery.js";
import { createScopedMemoryRuntimeWriteOperations } from "./scoped-memory-runtime-writes.js";

/** Creates one isolated runtime instance; caches are bounded, expiring, and process-local. */
export function createBuiltinScopedMemoryRuntime(
  dependencies: BuiltinScopedMemoryRuntimeDependencies = {},
) {
  const plans = new Map<string, ScopedMemoryPlanRecord>();
  const handles = new Map<string, HandleRecord>();
  const now = dependencies.now ?? Date.now;
  const readFile = dependencies.readFile ?? fs.readFileSync;
  const candidatePageReader = dependencies.candidatePageReader ?? readScopedMemoryFtsCandidatePage;
  const maxPlans = Math.max(1, dependencies.maxPlans ?? DEFAULT_MAX_PLANS);
  const maxHandles = Math.max(1, dependencies.maxHandles ?? DEFAULT_MAX_HANDLES);

  const planOperations = createScopedMemoryRuntimePlanOperations({
    plans,
    handles,
    now,
    maxPlans,
    maxHandles,
    generateOpaqueId: dependencies.generateOpaqueId,
  });
  const { purgeExpired, validatePlan, issueHandle, persistReceipts } = planOperations;
  const recoveryOperations = createScopedMemoryRuntimeRecoveryOperations({ plans, handles, now });
  const { assertMutationHandle, recoverPendingWrites } = recoveryOperations;
  const { writeAuthorized } = createScopedMemoryRuntimeWriteOperations({
    dependencies,
    now,
    planOperations,
    recoveryOperations,
  });
  const importAuthorized = async (params: {
    context: MemoryAccessContext;
    plan: AuthorizedMemoryPlan;
    mutation: Extract<AuthorizedMemoryMutation, { kind: "import" | "deposit" }> & {
      kind: "import";
    };
  }): Promise<MemoryWriteResult> => await writeAuthorized(params);

  const {
    syncAuthorized,
    exportAuthorized,
    statusAuthorized,
    prepareTranscriptPolicy,
    authorize,
    searchAuthorized,
    readAuthorized,
  } = createScopedMemoryRuntimeOperations({
    dependencies,
    plans,
    handles,
    now,
    readFile,
    candidatePageReader,
    purgeExpired,
    validatePlan,
    issueHandle,
    persistReceipts,
    recoverPendingWrites,
    assertMutationHandle,
  });
  return Object.freeze({
    authorize,
    searchAuthorized,
    readAuthorized,
    writeAuthorized,
    importAuthorized,
    syncAuthorized,
    exportAuthorized,
    statusAuthorized,
    prepareTranscriptPolicy,
  });
}
