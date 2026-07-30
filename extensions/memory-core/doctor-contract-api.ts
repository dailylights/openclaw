import type { PluginDoctorStateMigration } from "openclaw/plugin-sdk/runtime-doctor";
import { dreamingStateMigration } from "./src/migration/doctor-dreaming-state.js";
import { hostEventsStateMigration } from "./src/migration/doctor-host-events.js";
import {
  memorySidecarStateMigration,
  qmdLocksStateMigration,
} from "./src/migration/doctor-memory-sidecar.js";
import { scopedMemoryMigrationPreview } from "./src/migration/doctor-scoped-memory-preview.js";
import { vectorIndexProviderDiagnostic } from "./src/migration/doctor-vector-index-provider.js";

export const stateMigrations: PluginDoctorStateMigration[] = [
  scopedMemoryMigrationPreview,
  hostEventsStateMigration,
  dreamingStateMigration,
  memorySidecarStateMigration,
  qmdLocksStateMigration,
  vectorIndexProviderDiagnostic,
];
