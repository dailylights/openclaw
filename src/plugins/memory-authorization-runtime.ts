import {
  runMemoryAuthorizationConformanceSuite,
  type MemoryAuthorizationConformanceAdapter,
} from "../memory-host-sdk/host/authorization-conformance.js";
import {
  MEMORY_AUTHORIZATION_CAPABILITY_NAMES,
  MEMORY_AUTHORIZATION_CONTRACT_VERSION,
  hasCompleteMemoryAuthorizationCapabilities,
  isMemoryAuthorizationCapabilities,
  type AuthorizedMemoryRuntime,
  type MemoryAuthorizationCapabilityName,
} from "../memory-host-sdk/host/authorization.js";

const AUTHORIZED_MEMORY_RUNTIME_METHOD_NAMES = [
  "authorize",
  "searchAuthorized",
  "readAuthorized",
  "writeAuthorized",
  "importAuthorized",
  "syncAuthorized",
  "exportAuthorized",
  "statusAuthorized",
] as const satisfies readonly (keyof AuthorizedMemoryRuntime)[];

type AuthorizedMemoryRuntimeMethodName = (typeof AUTHORIZED_MEMORY_RUNTIME_METHOD_NAMES)[number];

const AUTHORIZED_MEMORY_READ_CAPABILITIES = [
  "scopedCandidates",
  "exactReadByAuthorizedHandle",
  "exposureReceipts",
  "egressReceipts",
] as const satisfies readonly MemoryAuthorizationCapabilityName[];

export type AdmittedAuthorizedMemoryReadRuntime = Readonly<
  Pick<
    AuthorizedMemoryRuntime,
    "authorization" | "authorize" | "searchAuthorized" | "readAuthorized"
  >
>;

type MemoryAuthorizationRuntimeAdmission =
  | Readonly<{
      ok: true;
      runtime: AdmittedAuthorizedMemoryReadRuntime;
    }>
  | Readonly<{
      ok: false;
      reasonCode: "backend-nonconforming";
    }>;

const readAdmissionCache = new WeakMap<object, Promise<MemoryAuthorizationRuntimeAdmission>>();

export type AdmittedAuthorizedMemoryRuntime = Readonly<AuthorizedMemoryRuntime>;

type CompleteMemoryAuthorizationRuntimeAdmission =
  | Readonly<{
      ok: true;
      runtime: AdmittedAuthorizedMemoryRuntime;
    }>
  | Readonly<{
      ok: false;
      reasonCode: "backend-nonconforming";
    }>;

const completeAdmissionCache = new WeakMap<
  object,
  Promise<CompleteMemoryAuthorizationRuntimeAdmission>
>();

type MemoryAuthorizationRuntimeInspection = Readonly<{
  version: 1;
  capabilityDeclaration: "missing" | "malformed" | "partial" | "complete";
  declaredCapabilityCount: number;
  requiredCapabilityCount: number;
  implementedMethodCount: number;
  requiredMethodCount: number;
  missingCapabilities: readonly MemoryAuthorizationCapabilityName[];
  missingMethods: readonly AuthorizedMemoryRuntimeMethodName[];
  surfaceComplete: boolean;
  reasonCode: "surface-complete" | "backend-nonconforming";
}>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/**
 * Inspect only contract shape. This result cannot admit an enforced backend; Phase 1B must bind
 * the runtime implementation to host-verified conformance evidence before enabling it.
 */
export function inspectMemoryAuthorizationRuntime(
  runtime: unknown,
): MemoryAuthorizationRuntimeInspection {
  const runtimeRecord = isRecord(runtime) ? runtime : {};
  const declaration = runtimeRecord.authorization;
  const declarationRecord = isRecord(declaration) ? declaration : {};
  const declaredCapabilityCount = MEMORY_AUTHORIZATION_CAPABILITY_NAMES.filter(
    (name) => declarationRecord[name] === true,
  ).length;
  const missingCapabilities = MEMORY_AUTHORIZATION_CAPABILITY_NAMES.filter(
    (name) => declarationRecord[name] !== true,
  );
  const missingMethods = AUTHORIZED_MEMORY_RUNTIME_METHOD_NAMES.filter(
    (name) => typeof runtimeRecord[name] !== "function",
  );
  const capabilityDeclaration =
    declaration === undefined
      ? "missing"
      : !isMemoryAuthorizationCapabilities(declaration)
        ? "malformed"
        : hasCompleteMemoryAuthorizationCapabilities(declaration)
          ? "complete"
          : "partial";
  const surfaceComplete = capabilityDeclaration === "complete" && missingMethods.length === 0;

  return Object.freeze({
    version: MEMORY_AUTHORIZATION_CONTRACT_VERSION,
    capabilityDeclaration,
    declaredCapabilityCount,
    requiredCapabilityCount: MEMORY_AUTHORIZATION_CAPABILITY_NAMES.length,
    implementedMethodCount: AUTHORIZED_MEMORY_RUNTIME_METHOD_NAMES.length - missingMethods.length,
    requiredMethodCount: AUTHORIZED_MEMORY_RUNTIME_METHOD_NAMES.length,
    missingCapabilities: Object.freeze([...missingCapabilities]),
    missingMethods: Object.freeze([...missingMethods]),
    surfaceComplete,
    reasonCode: surfaceComplete ? "surface-complete" : "backend-nonconforming",
  });
}

function isConformanceAdapter(value: unknown): value is MemoryAuthorizationConformanceAdapter {
  return (
    isRecord(value) && typeof value.evaluate === "function" && typeof value.prefilter === "function"
  );
}

/**
 * Admit only the Phase 1B authorized read surface. Capability flags remain truthful: later write,
 * sync, import, export, and status phases are not required or inferred here.
 */
export async function admitMemoryAuthorizationReadRuntime(
  runtime: unknown,
): Promise<MemoryAuthorizationRuntimeAdmission> {
  if (!isRecord(runtime)) {
    return Object.freeze({ ok: false, reasonCode: "backend-nonconforming" });
  }
  const cached = readAdmissionCache.get(runtime);
  if (cached) {
    return await cached;
  }
  const admission = (async (): Promise<MemoryAuthorizationRuntimeAdmission> => {
    const authorization = runtime.authorization;
    const authorizationConformance = runtime.authorizationConformance;
    const authorize = runtime.authorize;
    const searchAuthorized = runtime.searchAuthorized;
    const readAuthorized = runtime.readAuthorized;
    if (
      !isMemoryAuthorizationCapabilities(authorization) ||
      AUTHORIZED_MEMORY_READ_CAPABILITIES.some((capability) => !authorization[capability]) ||
      typeof authorize !== "function" ||
      typeof searchAuthorized !== "function" ||
      typeof readAuthorized !== "function" ||
      !isConformanceAdapter(authorizationConformance)
    ) {
      return Object.freeze({ ok: false, reasonCode: "backend-nonconforming" });
    }
    let report;
    try {
      report = await runMemoryAuthorizationConformanceSuite(authorizationConformance);
    } catch {
      return Object.freeze({ ok: false, reasonCode: "backend-nonconforming" });
    }
    if (!report.ok) {
      return Object.freeze({ ok: false, reasonCode: "backend-nonconforming" });
    }
    const admittedAuthorization = Object.freeze({ ...authorization });
    const admittedRuntime: AdmittedAuthorizedMemoryReadRuntime = Object.freeze({
      authorization: admittedAuthorization,
      authorize: (authorize as AuthorizedMemoryRuntime["authorize"]).bind(runtime),
      searchAuthorized: (searchAuthorized as AuthorizedMemoryRuntime["searchAuthorized"]).bind(
        runtime,
      ),
      readAuthorized: (readAuthorized as AuthorizedMemoryRuntime["readAuthorized"]).bind(runtime),
    });
    return Object.freeze({ ok: true, runtime: admittedRuntime });
  })();
  readAdmissionCache.set(runtime, admission);
  return await admission;
}

/** Admit every Phase 2A operation only when the selected backend implements the complete contract. */
export async function admitMemoryAuthorizationRuntime(
  runtime: unknown,
): Promise<CompleteMemoryAuthorizationRuntimeAdmission> {
  if (!isRecord(runtime)) {
    return Object.freeze({ ok: false, reasonCode: "backend-nonconforming" });
  }
  const cached = completeAdmissionCache.get(runtime);
  if (cached) {
    return await cached;
  }
  const admission = (async (): Promise<CompleteMemoryAuthorizationRuntimeAdmission> => {
    const authorization = runtime.authorization;
    const authorizationConformance = runtime.authorizationConformance;
    if (
      !hasCompleteMemoryAuthorizationCapabilities(authorization) ||
      AUTHORIZED_MEMORY_RUNTIME_METHOD_NAMES.some((name) => typeof runtime[name] !== "function") ||
      !isConformanceAdapter(authorizationConformance)
    ) {
      return Object.freeze({ ok: false, reasonCode: "backend-nonconforming" });
    }
    try {
      const report = await runMemoryAuthorizationConformanceSuite(authorizationConformance);
      if (!report.ok) {
        return Object.freeze({ ok: false, reasonCode: "backend-nonconforming" });
      }
    } catch {
      return Object.freeze({ ok: false, reasonCode: "backend-nonconforming" });
    }
    const admittedRuntime: AdmittedAuthorizedMemoryRuntime = Object.freeze({
      authorization: Object.freeze({ ...authorization }),
      authorize: (runtime.authorize as AuthorizedMemoryRuntime["authorize"]).bind(runtime),
      searchAuthorized: (
        runtime.searchAuthorized as AuthorizedMemoryRuntime["searchAuthorized"]
      ).bind(runtime),
      readAuthorized: (runtime.readAuthorized as AuthorizedMemoryRuntime["readAuthorized"]).bind(
        runtime,
      ),
      writeAuthorized: (runtime.writeAuthorized as AuthorizedMemoryRuntime["writeAuthorized"]).bind(
        runtime,
      ),
      importAuthorized: (
        runtime.importAuthorized as AuthorizedMemoryRuntime["importAuthorized"]
      ).bind(runtime),
      syncAuthorized: (runtime.syncAuthorized as AuthorizedMemoryRuntime["syncAuthorized"]).bind(
        runtime,
      ),
      exportAuthorized: (
        runtime.exportAuthorized as AuthorizedMemoryRuntime["exportAuthorized"]
      ).bind(runtime),
      statusAuthorized: (
        runtime.statusAuthorized as AuthorizedMemoryRuntime["statusAuthorized"]
      ).bind(runtime),
    });
    return Object.freeze({ ok: true, runtime: admittedRuntime });
  })();
  completeAdmissionCache.set(runtime, admission);
  return await admission;
}
