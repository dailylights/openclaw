/** Test-owned Phase 0 inventory of every known path that can ingest, expose, or derive memory. */
export const MEMORY_AUTHORIZATION_PATH_DISPOSITIONS = [
  "authorized",
  "blocked-in-enforced-mode",
  "legacy-only",
  "operator-only-authenticated",
] as const;

type MemoryAuthorizationPathDisposition = (typeof MEMORY_AUTHORIZATION_PATH_DISPOSITIONS)[number];

type MemoryAuthorizationPathDirection = "control" | "ingress" | "egress" | "derive";

type MemoryAuthorizationPathOwner =
  | "core-access-host"
  | "core-agent-runtime"
  | "core-session-runtime"
  | "core-tool-runtime"
  | "operator-memory-host"
  | "selected-memory-plugin"
  | "supplemental-memory-plugin"
  | "transport-egress-host"
  | "autonomous-run-host";

export type MemoryAuthorizationPathInventoryEntry = Readonly<{
  id: string;
  direction: MemoryAuthorizationPathDirection;
  owner: MemoryAuthorizationPathOwner;
  disposition: MemoryAuthorizationPathDisposition;
  surfaces: readonly [string, ...string[]];
}>;

/**
 * `authorized` is intentionally absent in Phase 0: the rollout is shadow-only. Paths marked
 * `legacy-only` retain existing personal-agent behavior; every other path must fail closed once
 * an agent enters enforced mode until its owning phase converts it.
 */
export const MEMORY_AUTHORIZATION_PATH_INVENTORY = [
  {
    id: "selected-runtime-manager-acquisition",
    direction: "control",
    owner: "core-access-host",
    disposition: "legacy-only",
    surfaces: [
      "src/plugins/memory-runtime.ts",
      "src/plugins/memory-state.ts",
      "src/plugin-sdk/memory-host-search.ts",
      "extensions/memory-core/src/runtime-provider.ts",
      "extensions/memory-core/src/memory/search-manager.ts",
    ],
  },
  {
    id: "selected-runtime-backend-resolution",
    direction: "control",
    owner: "core-access-host",
    disposition: "legacy-only",
    surfaces: ["src/plugins/memory-runtime.ts"],
  },
  {
    id: "selected-runtime-startup-warmup-and-sync",
    direction: "control",
    owner: "selected-memory-plugin",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["extensions/memory-core/index.ts", "src/gateway/server-startup-memory.ts"],
  },
  {
    id: "bootstrap-memory-and-user-files",
    direction: "egress",
    owner: "core-agent-runtime",
    disposition: "legacy-only",
    surfaces: ["src/agents/bootstrap-files.ts", "src/agents/workspace-bootstrap-read.ts"],
  },
  {
    id: "startup-recent-memory-context",
    direction: "egress",
    owner: "core-agent-runtime",
    disposition: "legacy-only",
    surfaces: ["src/auto-reply/reply/startup-context.ts"],
  },
  {
    id: "memory-search-tool",
    direction: "egress",
    owner: "selected-memory-plugin",
    disposition: "legacy-only",
    surfaces: ["extensions/memory-core/src/tools.ts", "extensions/memory-core/src/tools.shared.ts"],
  },
  {
    id: "memory-get-tool",
    direction: "egress",
    owner: "selected-memory-plugin",
    disposition: "legacy-only",
    surfaces: ["extensions/memory-core/src/tools.ts"],
  },
  {
    id: "session-transcript-search",
    direction: "egress",
    owner: "selected-memory-plugin",
    disposition: "legacy-only",
    surfaces: [
      "extensions/memory-core/src/session-search-visibility.ts",
      "extensions/memory-core/src/tools.ts",
    ],
  },
  {
    id: "active-memory-trigger-recall",
    direction: "egress",
    owner: "supplemental-memory-plugin",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["extensions/active-memory/trigger-recall.ts"],
  },
  {
    id: "active-memory-session-recall",
    direction: "egress",
    owner: "supplemental-memory-plugin",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["extensions/active-memory/recall.ts", "extensions/active-memory/recall-run.ts"],
  },
  {
    id: "memory-wiki-prompt-guidance",
    direction: "egress",
    owner: "supplemental-memory-plugin",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["extensions/memory-wiki/src/prompt-section.ts"],
  },
  {
    id: "memory-wiki-corpus-search-and-read",
    direction: "egress",
    owner: "supplemental-memory-plugin",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["extensions/memory-wiki/src/query.ts"],
  },
  {
    id: "memory-wiki-gateway",
    direction: "egress",
    owner: "operator-memory-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["extensions/memory-wiki/src/gateway.ts"],
  },
  {
    id: "memory-wiki-cli",
    direction: "egress",
    owner: "operator-memory-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["extensions/memory-wiki/src/cli.ts"],
  },
  {
    id: "memory-wiki-bridge-and-public-artifacts",
    direction: "egress",
    owner: "supplemental-memory-plugin",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["extensions/memory-wiki/src/bridge.ts", "extensions/memory-wiki/src/status.ts"],
  },
  {
    id: "lancedb-tool-recall",
    direction: "egress",
    owner: "supplemental-memory-plugin",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["extensions/memory-lancedb/index.ts"],
  },
  {
    id: "lancedb-tool-store",
    direction: "ingress",
    owner: "supplemental-memory-plugin",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["extensions/memory-lancedb/index.ts"],
  },
  {
    id: "lancedb-tool-forget",
    direction: "ingress",
    owner: "supplemental-memory-plugin",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["extensions/memory-lancedb/index.ts"],
  },
  {
    id: "lancedb-auto-recall",
    direction: "egress",
    owner: "supplemental-memory-plugin",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["extensions/memory-lancedb/index.ts"],
  },
  {
    id: "lancedb-auto-capture",
    direction: "ingress",
    owner: "supplemental-memory-plugin",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["extensions/memory-lancedb/index.ts"],
  },
  {
    id: "memory-prompt-supplements",
    direction: "egress",
    owner: "core-access-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/plugins/memory-state.ts"],
  },
  {
    id: "memory-prompt-preparations",
    direction: "egress",
    owner: "core-access-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/plugins/memory-state.ts"],
  },
  {
    id: "memory-corpus-supplements",
    direction: "egress",
    owner: "core-access-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/plugins/memory-state.ts", "extensions/memory-core/src/tools.shared.ts"],
  },
  {
    id: "talk-fast-context",
    direction: "egress",
    owner: "core-agent-runtime",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/talk/fast-context-runtime.ts"],
  },
  {
    id: "project-memory-bootstrap",
    direction: "egress",
    owner: "core-agent-runtime",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/agents/project-memory-bootstrap.ts"],
  },
  {
    id: "memory-status-command",
    direction: "egress",
    owner: "operator-memory-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: [
      "extensions/memory-core/src/cli-status.runtime.ts",
      "src/commands/status.scan-memory.ts",
      "src/commands/status.scan.deps.runtime.ts",
      "src/commands/status.scan.shared.ts",
    ],
  },
  {
    id: "memory-cli-search-and-get",
    direction: "egress",
    owner: "operator-memory-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: [
      "extensions/memory-core/src/cli-index-search.runtime.ts",
      "extensions/memory-core/src/cli-runtime-common.ts",
    ],
  },
  {
    id: "memory-cli-sync-and-reindex",
    direction: "control",
    owner: "operator-memory-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["extensions/memory-core/src/cli-index-search.runtime.ts"],
  },
  {
    id: "memory-doctor-inspection-and-repair",
    direction: "control",
    owner: "operator-memory-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/commands/doctor-memory-search.ts", "src/gateway/server-methods/doctor.ts"],
  },
  {
    id: "gateway-memory-search",
    direction: "egress",
    owner: "operator-memory-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/gateway/server-methods/memory-search.ts"],
  },
  {
    id: "memory-import",
    direction: "ingress",
    owner: "operator-memory-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["extensions/memory-core/src/cli-rem.runtime.ts"],
  },
  {
    id: "memory-export",
    direction: "egress",
    owner: "operator-memory-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["extensions/memory-core/src/cli-index-search.runtime.ts"],
  },
  {
    id: "memory-public-artifacts",
    direction: "egress",
    owner: "core-access-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/plugins/memory-state.ts", "extensions/memory-core/src/public-artifacts.ts"],
  },
  {
    id: "generic-file-read",
    direction: "egress",
    owner: "core-tool-runtime",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/agents/agent-tools.read.ts", "src/agents/tool-fs-policy.ts"],
  },
  {
    id: "generic-file-write",
    direction: "ingress",
    owner: "core-tool-runtime",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/agents/agent-tools.read.ts", "src/agents/tool-fs-policy.ts"],
  },
  {
    id: "generic-file-edit",
    direction: "ingress",
    owner: "core-tool-runtime",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/agents/agent-tools.read.ts", "src/agents/tool-fs-policy.ts"],
  },
  {
    id: "generic-file-apply-patch",
    direction: "ingress",
    owner: "core-tool-runtime",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/agents/apply-patch.ts", "src/agents/tool-fs-policy.ts"],
  },
  {
    id: "sandbox-workspace-mounts",
    direction: "control",
    owner: "core-tool-runtime",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/agents/sandbox/workspace-mounts.ts"],
  },
  {
    id: "unsandboxed-exec",
    direction: "egress",
    owner: "core-tool-runtime",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/agents/bash-tools.ts", "src/agents/tool-fs-policy.ts"],
  },
  {
    id: "memory-flush",
    direction: "derive",
    owner: "core-agent-runtime",
    disposition: "blocked-in-enforced-mode",
    surfaces: [
      "src/auto-reply/reply/agent-runner-memory.ts",
      "src/agents/embedded-agent-runner/compaction-hooks.ts",
      "extensions/memory-core/src/flush-plan.ts",
    ],
  },
  {
    id: "transcript-event-write",
    direction: "ingress",
    owner: "core-session-runtime",
    disposition: "blocked-in-enforced-mode",
    surfaces: [
      "src/agents/sessions/session-manager-persistence.ts",
      "src/config/sessions/session-accessor.sqlite-transcript-write.ts",
      "src/config/sessions/transcript-write-context.ts",
    ],
  },
  {
    id: "transcript-history-and-replay",
    direction: "egress",
    owner: "core-session-runtime",
    disposition: "blocked-in-enforced-mode",
    surfaces: [
      "src/gateway/session-transcript-readers.ts",
      "src/agents/embedded-agent-runner/transcript-rewrite.ts",
    ],
  },
  {
    id: "compaction-summary",
    direction: "derive",
    owner: "core-agent-runtime",
    disposition: "blocked-in-enforced-mode",
    surfaces: [
      "src/agents/compaction.ts",
      "src/agents/embedded-agent-runner/compaction-session-execution.ts",
    ],
  },
  {
    id: "compaction-checkpoint",
    direction: "derive",
    owner: "core-agent-runtime",
    disposition: "blocked-in-enforced-mode",
    surfaces: [
      "src/agents/embedded-agent-runner/compaction-checkpoint.ts",
      "src/agents/main-session-restart-recovery-checkpoint.ts",
      "src/gateway/session-compaction-checkpoints.ts",
    ],
  },
  {
    id: "compaction-checkpoint-operator-branch-and-restore",
    direction: "control",
    owner: "operator-memory-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/gateway/server-methods/sessions-compaction-checkpoints.ts"],
  },
  {
    id: "dreaming-source-recall",
    direction: "egress",
    owner: "selected-memory-plugin",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["extensions/memory-core/src/dreaming-phases.ts"],
  },
  {
    id: "dreaming-derived-artifacts",
    direction: "derive",
    owner: "selected-memory-plugin",
    disposition: "blocked-in-enforced-mode",
    surfaces: [
      "extensions/memory-core/src/dreaming-narrative.ts",
      "extensions/memory-core/src/dreaming-markdown.ts",
    ],
  },
  {
    id: "profile-and-short-term-promotion",
    direction: "derive",
    owner: "selected-memory-plugin",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["extensions/memory-core/src/short-term-promotion-apply.ts"],
  },
  {
    id: "child-agent-delegation",
    direction: "egress",
    owner: "core-agent-runtime",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/agents/subagent-registry.ts", "src/agents/openclaw-tools.ts"],
  },
  {
    id: "child-agent-completion-handoff",
    direction: "egress",
    owner: "core-agent-runtime",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/agents/subagent-announce-delivery.ts"],
  },
  {
    id: "cron-triggered-run",
    direction: "control",
    owner: "autonomous-run-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/cron/service/timer-execution.ts"],
  },
  {
    id: "heartbeat-triggered-run",
    direction: "control",
    owner: "autonomous-run-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/infra/heartbeat-runner.ts"],
  },
  {
    id: "webhook-triggered-run",
    direction: "control",
    owner: "autonomous-run-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/gateway/server/hooks-request-handler.ts"],
  },
  {
    id: "system-triggered-run",
    direction: "control",
    owner: "autonomous-run-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/gateway/server-methods/system-agent.ts"],
  },
  {
    id: "final-reply-delivery",
    direction: "egress",
    owner: "transport-egress-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/auto-reply/reply/reply-delivery.ts"],
  },
  {
    id: "message-tool-delivery",
    direction: "egress",
    owner: "transport-egress-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/agents/tools/message-tool.ts"],
  },
  {
    id: "session-send-delivery",
    direction: "egress",
    owner: "transport-egress-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/agents/tools/sessions-send-tool.ts"],
  },
  {
    id: "plugin-and-mcp-outbound-actions",
    direction: "egress",
    owner: "transport-egress-host",
    disposition: "blocked-in-enforced-mode",
    surfaces: ["src/plugins/tools.ts", "src/agents/mcp-transport.ts"],
  },
] as const satisfies readonly MemoryAuthorizationPathInventoryEntry[];
