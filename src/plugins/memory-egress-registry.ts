/**
 * Stable memory-egress capability registry.
 *
 * A scoped-memory run starts with only the original final-reply route enabled.
 * Other side-effect surfaces remain classified here, but are unavailable until
 * a later phase adds an audience-bound delivery capability for each one.
 */

const MEMORY_EGRESS_CAPABILITY_IDS = [
  "browser.control",
  "fanout.send",
  "file.delivery",
  "mcp.call",
  "message.send",
  "network.request",
  "plugin.call",
  "process.execute",
  "reply.final",
  "session.send",
  "upload.export",
  "webhook.call",
] as const;

type MemoryEgressCapabilityId = (typeof MEMORY_EGRESS_CAPABILITY_IDS)[number];

const CAPABILITY_BY_TOOL_NAME: Readonly<Record<string, MemoryEgressCapabilityId>> = {
  browser: "browser.control",
  exec: "process.execute",
  message: "message.send",
  process: "process.execute",
  sessions_send: "session.send",
  web_fetch: "network.request",
  web_search: "network.request",
  x_search: "network.request",
};

/** Returns a stable registry key for built-ins, or undefined for unknown/plugin/MCP tools. */
export function resolveMemoryEgressCapabilityId(
  toolName: string,
): MemoryEgressCapabilityId | undefined {
  const normalized = toolName.trim().toLowerCase();
  if (!normalized) {
    return undefined;
  }
  if (normalized.startsWith("mcp_") || normalized.includes("__")) {
    return "mcp.call";
  }
  return CAPABILITY_BY_TOOL_NAME[normalized];
}

/** Registry order is a contract: its hash invalidates old egress receipts. */
export function listMemoryEgressCapabilityIds(): readonly MemoryEgressCapabilityId[] {
  return MEMORY_EGRESS_CAPABILITY_IDS;
}
