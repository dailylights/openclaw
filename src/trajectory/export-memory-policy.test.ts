// Trajectory exports keep policy evidence separate from transcript event payloads.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { replaceTranscriptEvents } from "../config/sessions/session-accessor.js";
import { closeOpenClawAgentDatabasesForTest } from "../state/openclaw-agent-db.js";

const hoisted = vi.hoisted(() => ({
  readTranscriptMemoryPolicyExportManifestMock: vi.fn<() => unknown>(() => undefined),
}));

vi.mock("../config/sessions/session-accessor.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../config/sessions/session-accessor.js")>();
  return {
    ...actual,
    readTranscriptMemoryPolicyExportManifest: hoisted.readTranscriptMemoryPolicyExportManifestMock,
  };
});

const { exportTrajectoryBundle } = await import("./export.js");

const tempDirs: string[] = [];

afterEach(() => {
  closeOpenClawAgentDatabasesForTest();
  for (const directory of tempDirs.splice(0)) {
    fs.rmSync(directory, { force: true, recursive: true });
  }
  vi.clearAllMocks();
});

describe("trajectory memory policy export", () => {
  it("writes the read-only current-policy manifest beside the filtered transcript", async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-trajectory-policy-"));
    tempDirs.push(directory);
    const sessionId = "policy-session";
    const sessionKey = "agent:main:policy-session";
    const storePath = path.join(directory, "sessions.json");
    const memoryPolicyManifest = {
      events: [
        {
          eventSeq: 1,
          preserved: {
            detail: { policy_set_revision: "policy-set-revision-1" },
            lineage: {
              created_at: 1,
              origin_event_seq: 1,
              origin_session_id: sessionId,
              source_event_seq: 1,
              source_session_id: sessionId,
              transition_kind: "append",
            },
            policy: { source_policy_set_id: "policy-set-1" },
          },
        },
      ],
      schemaVersion: 1,
      sessionId,
    };
    hoisted.readTranscriptMemoryPolicyExportManifestMock.mockReturnValueOnce(memoryPolicyManifest);
    await replaceTranscriptEvents({ agentId: "main", sessionId, sessionKey, storePath }, [
      { type: "session", version: 3, id: sessionId, timestamp: "2026-07-30T00:00:00.000Z" },
      {
        type: "message",
        id: "message-1",
        parentId: null,
        timestamp: "2026-07-30T00:00:01.000Z",
        message: { role: "user", content: "authorized transcript content" },
      },
    ]);

    const outputDir = path.join(directory, "bundle");
    const bundle = await exportTrajectoryBundle({
      outputDir,
      sessionId,
      sessionKey,
      sessionTarget: { agentId: "main", sessionId, sessionKey, storePath },
      workspaceDir: directory,
    });

    expect(hoisted.readTranscriptMemoryPolicyExportManifestMock).toHaveBeenCalledWith({
      agentId: "main",
      sessionId,
      sessionKey,
      storePath,
    });
    expect(bundle.manifest).toMatchObject({ memoryPolicyManifest });
    expect(
      JSON.parse(fs.readFileSync(path.join(outputDir, "manifest.json"), "utf8")),
    ).toMatchObject({
      memoryPolicyManifest,
    });
  });
});
