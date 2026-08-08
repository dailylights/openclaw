import { html, type TemplateResult } from "lit";
import type { ApplicationContext } from "../../app/context.ts";
import { readGatewayOperatorAccess } from "../../app/operator-access.ts";
import { hasMemorySharingGatewayMethods } from "./memory-sharing-protocol.ts";
import "./memory-sharing.ts";

type GatewaySnapshot = ApplicationContext["gateway"]["snapshot"];

/** Keep the Settings page focused on configuration state, not sharing-element wiring. */
export function renderMemorySharingHost(
  gateway: GatewaySnapshot,
  agentId: string | null,
): TemplateResult {
  return html`
    <openclaw-memory-sharing
      .client=${gateway.client}
      .connected=${gateway.phase === "connected"}
      .canWrite=${readGatewayOperatorAccess(gateway).canWrite}
      .methodsAvailable=${hasMemorySharingGatewayMethods(gateway)}
      .agentId=${agentId}
    ></openclaw-memory-sharing>
  `;
}
