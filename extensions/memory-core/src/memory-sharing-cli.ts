// The sharing CLI stays a Gateway client: sharing state and authorization live
// behind the plugin-owned RPC methods, never in a second local CLI path.
import type { Command } from "commander";
import {
  addGatewayClientOptions,
  callGatewayFromCli,
  type GatewayRpcOpts,
} from "openclaw/plugin-sdk/gateway-runtime";

type SharingCliOptions = GatewayRpcOpts & {
  agent: string;
  sourceRevision?: string;
  targetKind?: string;
  targetId?: string;
  purpose?: string;
  expiresAt?: string;
  supersedesProjectionId?: string;
  previewId?: string;
  projectionId?: string;
  postboxItemId?: string;
  decision?: string;
  reason?: string;
  editedContent?: string;
};

type SharingCliDependencies = {
  callGateway?: typeof callGatewayFromCli;
  writeResult?: (value: unknown) => void;
};

// CLI token authentication has no authenticated user-profile projection, so
// request the admin capability rather than advertising an unusable owner path.
const SHARING_SCOPE = ["operator.admin"] as const;

function writeJsonResult(value: unknown): void {
  // JSON escaping keeps redacted Gateway values inert when sent to a terminal.
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function trimRequired(value: string | undefined, option: string): string {
  const trimmed = value?.trim();
  if (!trimmed) {
    throw new Error(`${option} is required.`);
  }
  return trimmed;
}

function trimOptional(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed || undefined;
}

function readReviewDecision(opts: SharingCliOptions): {
  decision: "approve" | "reject";
  reason?: string;
} {
  if (opts.decision !== "approve" && opts.decision !== "reject") {
    throw new Error("--decision must be approve or reject.");
  }
  const reason = trimOptional(opts.reason);
  if (opts.decision === "reject" && !reason) {
    throw new Error("--reason is required when --decision reject.");
  }
  return { decision: opts.decision, ...(reason ? { reason } : {}) };
}

function addSharingGatewayOptions(command: Command): Command {
  addGatewayClientOptions(command);
  return command.requiredOption("--agent <id>", "Agent id").option("--json", "Print JSON", false);
}

function registerSharingAction(
  command: Command,
  method: string,
  toParams: (opts: SharingCliOptions) => Record<string, unknown>,
  dependencies: Required<SharingCliDependencies>,
): void {
  command.action(async (opts: SharingCliOptions) => {
    const agentId = trimRequired(opts.agent, "--agent");
    const result = await dependencies.callGateway(
      method,
      opts,
      {
        agentId,
        ...toParams(opts),
      },
      { scopes: [...SHARING_SCOPE] },
    );
    dependencies.writeResult(result);
  });
}

/** Registers the operator-facing client for the reviewed sharing control plane. */
export function registerMemorySharingCli(
  memory: Command,
  dependencies: SharingCliDependencies = {},
): void {
  const resolvedDependencies: Required<SharingCliDependencies> = {
    callGateway: dependencies.callGateway ?? callGatewayFromCli,
    writeResult: dependencies.writeResult ?? writeJsonResult,
  };
  const sharing = memory
    .command("sharing")
    .description("Inspect and review explicit memory sharing and postbox items");
  const projection = sharing.command("projection").description("Manage reviewed projections");
  const postbox = sharing.command("postbox").description("Review quarantined postbox items");

  registerSharingAction(
    addSharingGatewayOptions(sharing.command("status").description("Show reviewed sharing status")),
    "memory.sharing.status",
    () => ({}),
    resolvedDependencies,
  );
  registerSharingAction(
    addSharingGatewayOptions(postbox.command("list").description("List redacted postbox items")),
    "memory.sharing.postbox.list",
    () => ({}),
    resolvedDependencies,
  );
  registerSharingAction(
    addSharingGatewayOptions(
      postbox
        .command("inspect")
        .description("Read one pending postbox item for owner or admin review")
        .requiredOption("--postbox-item-id <id>", "Postbox item id"),
    ),
    "memory.sharing.postbox.inspect",
    (opts) => ({ postboxItemId: trimRequired(opts.postboxItemId, "--postbox-item-id") }),
    resolvedDependencies,
  );

  registerSharingAction(
    addSharingGatewayOptions(
      projection
        .command("preview")
        .description("Prepare one reviewed projection")
        .requiredOption("--source-revision <id>", "Immutable source revision id")
        .requiredOption("--target-kind <kind>", "Target kind: conversation, role, or agent-shared")
        .requiredOption("--target-id <id>", "Named target audience id")
        .requiredOption("--purpose <text>", "Human-readable sharing purpose")
        .requiredOption("--expires-at <timestamp>", "Future ISO-8601 expiry timestamp")
        .option("--supersedes-projection-id <id>", "Projection id this refresh supersedes"),
    ),
    "memory.sharing.projection.preview",
    (opts) => {
      const supersedesProjectionId = trimOptional(opts.supersedesProjectionId);
      return {
        sourceRevisionId: trimRequired(opts.sourceRevision, "--source-revision"),
        targetKind: trimRequired(opts.targetKind, "--target-kind"),
        targetId: trimRequired(opts.targetId, "--target-id"),
        purpose: trimRequired(opts.purpose, "--purpose"),
        expiresAt: trimRequired(opts.expiresAt, "--expires-at"),
        ...(supersedesProjectionId ? { supersedesProjectionId } : {}),
      };
    },
    resolvedDependencies,
  );
  for (const [name, method, description] of [
    ["create", "memory.sharing.projection.create", "Create a pending reviewed projection"],
    ["refresh", "memory.sharing.projection.refresh", "Create a pending refreshed projection"],
  ] as const) {
    registerSharingAction(
      addSharingGatewayOptions(
        projection
          .command(name)
          .description(description)
          .requiredOption("--preview-id <id>", "Gateway-issued projection preview id"),
      ),
      method,
      (opts) => ({ previewId: trimRequired(opts.previewId, "--preview-id") }),
      resolvedDependencies,
    );
  }
  registerSharingAction(
    addSharingGatewayOptions(
      projection
        .command("review")
        .description("Approve or reject a pending projection")
        .requiredOption("--projection-id <id>", "Projection id")
        .requiredOption("--decision <decision>", "approve or reject")
        .option("--reason <text>", "Reason, required when rejecting"),
    ),
    "memory.sharing.projection.review",
    (opts) => ({
      projectionId: trimRequired(opts.projectionId, "--projection-id"),
      ...readReviewDecision(opts),
    }),
    resolvedDependencies,
  );
  for (const [name, method, description] of [
    ["revoke", "memory.sharing.projection.revoke", "Revoke an approved projection"],
    ["impact", "memory.sharing.projection.impact", "Show redacted prior-exposure count"],
  ] as const) {
    registerSharingAction(
      addSharingGatewayOptions(
        projection
          .command(name)
          .description(description)
          .requiredOption("--projection-id <id>", "Projection id"),
      ),
      method,
      (opts) => ({ projectionId: trimRequired(opts.projectionId, "--projection-id") }),
      resolvedDependencies,
    );
  }
  registerSharingAction(
    addSharingGatewayOptions(
      postbox
        .command("review")
        .description("Approve or reject a quarantined postbox item")
        .requiredOption("--postbox-item-id <id>", "Postbox item id")
        .requiredOption("--decision <decision>", "approve or reject")
        .option("--reason <text>", "Reason, required when rejecting")
        .option("--edited-content <text>", "Owner-entered replacement content for approval"),
    ),
    "memory.sharing.postbox.review",
    (opts) => {
      const editedContent = trimOptional(opts.editedContent);
      return {
        postboxItemId: trimRequired(opts.postboxItemId, "--postbox-item-id"),
        ...readReviewDecision(opts),
        ...(editedContent ? { editedContent } : {}),
      };
    },
    resolvedDependencies,
  );
  registerSharingAction(
    addSharingGatewayOptions(
      postbox
        .command("purge")
        .description("Purge a quarantined or reviewed postbox item")
        .requiredOption("--postbox-item-id <id>", "Postbox item id"),
    ),
    "memory.sharing.postbox.purge",
    (opts) => ({ postboxItemId: trimRequired(opts.postboxItemId, "--postbox-item-id") }),
    resolvedDependencies,
  );

  sharing.action(() => sharing.outputHelp());
  projection.action(() => projection.outputHelp());
  postbox.action(() => postbox.outputHelp());
}
