/** Test-only access to scoped-memory seams that production consumes internally. */
export {
  readScopedMemorySqliteVecCandidatePage,
  readScopedMemoryVectorCandidatePage,
} from "./src/memory/scoped-memory-candidates.js";
export {
  createBuiltinScopedMemoryResource,
  createBuiltinScopedMemoryResourceRevision,
  setBuiltinScopedMemoryRevisionLifecycle,
} from "./src/memory/scoped-memory-resources.js";
export {
  createBuiltinScopedMemoryStore,
  createOpaqueScopedMemoryDirectory,
  reviseBuiltinScopedMemoryPolicy,
} from "./src/memory/scoped-memory-store.js";
