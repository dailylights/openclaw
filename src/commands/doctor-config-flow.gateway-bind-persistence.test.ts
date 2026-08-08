// Verifies Doctor persists legacy gateway bind repairs through the real config writer.
import fs from "node:fs/promises";
import { afterEach, describe, expect, it, vi } from "vitest";
import { readConfigFileSnapshot } from "../config/config.js";
import { withTempHome, writeOpenClawConfig } from "../config/test-helpers.js";
import { runInitialConfigWriteHealth } from "../flows/doctor-health-contribution-runners.config.js";
import type { DoctorHealthFlowContext } from "../flows/doctor-health-contribution-types.js";
import type { RuntimeEnv } from "../runtime.js";
import { closeOpenClawStateDatabaseForTest } from "../state/openclaw-state-db.js";
import { runDoctorConfigPreflight } from "./doctor-config-preflight.js";
import { createDoctorPrompter, type DoctorOptions } from "./doctor-prompter.js";
import { finalizeDoctorConfigFlow } from "./doctor/finalize-config-flow.js";
import { applyLegacyCompatibilityStep } from "./doctor/shared/config-flow-steps.js";

describe("Doctor gateway bind persistence", () => {
  afterEach(() => {
    closeOpenClawStateDatabaseForTest();
  });

  it.each([
    ["localhost", "loopback"],
    ["0.0.0.0", "lan"],
  ] as const)("persists gateway bind %s as %s", async (legacyBind, canonicalBind) => {
    await withTempHome(async (home) => {
      const configPath = await writeOpenClawConfig(home, {
        gateway: { mode: "local", bind: legacyBind },
      });
      const runtime: RuntimeEnv = {
        error: vi.fn(),
        exit: vi.fn(),
        log: vi.fn(),
      };
      const options: DoctorOptions = { nonInteractive: true, repair: true };
      const prompter = createDoctorPrompter({ runtime, options });
      const preflight = await runDoctorConfigPreflight({
        migrateState: false,
        preparePluginMetadataSnapshot: false,
      });
      const legacyStep = applyLegacyCompatibilityStep({
        snapshot: preflight.snapshot,
        state: {
          cfg: preflight.baseConfig,
          candidate: structuredClone(preflight.baseConfig),
          pendingChanges: false,
          fixHints: [],
        },
        shouldRepair: true,
        doctorFixCommand: "openclaw doctor --fix",
      });
      const finalized = await finalizeDoctorConfigFlow({
        ...legacyStep.state,
        shouldRepair: true,
        confirm: (params) => prompter.confirm(params),
        note: vi.fn(),
      });
      const configResult: DoctorHealthFlowContext["configResult"] = {
        cfg: finalized.cfg,
        path: configPath,
        shouldWriteConfig: finalized.shouldWriteConfig,
        sourceConfigValid: preflight.snapshot.valid,
      };
      const ctx: DoctorHealthFlowContext = {
        runtime,
        options,
        prompter,
        configResult,
        cfg: configResult.cfg,
        cfgForPersistence: structuredClone(configResult.cfg),
        sourceConfigValid: configResult.sourceConfigValid ?? false,
        configPath,
        stateDirExistedAtStart: true,
      };

      await runInitialConfigWriteHealth(ctx);

      const snapshot = await readConfigFileSnapshot();
      expect(snapshot.valid).toBe(true);
      expect(snapshot.config.gateway?.bind).toBe(canonicalBind);
      expect(await fs.readFile(configPath, "utf-8")).not.toContain(`"bind": "${legacyBind}"`);
    });
  });
});
