import type {
  MemoryInvocationState,
  TranscriptMemoryRunExposureSnapshot,
} from "./memory-invocation-receipts.js";

export type TranscriptMemoryPolicyLabel = Readonly<{
  sourcePolicySetId: string;
  policySetRevision: string;
  runExposureSetId: string;
  runExposureRevision: number;
  deliveryAudiencesJson: string;
  actorEvidenceJson: string;
  delegationJson: string;
  finalizedEgressAudiencesJson: string;
  exposedResourceRevisionsJson: string;
  sessionIdentityRevision: string;
  subjectRevision: string;
  runId: string;
  contextFingerprint: string;
  runExposure: TranscriptMemoryRunExposureSnapshot;
  transcriptPolicy: NonNullable<MemoryInvocationState["transcriptPolicy"]>;
}>;

type TranscriptMemoryPolicyLabelReader = (params: {
  agentId: string;
  sessionId: string;
}) => TranscriptMemoryPolicyLabel | undefined;

let currentLabelReader: TranscriptMemoryPolicyLabelReader | undefined;

/** Registers the request-scoped invocation bridge without importing the plugin runtime from sessions. */
export function setTranscriptMemoryPolicyLabelReader(
  reader: TranscriptMemoryPolicyLabelReader,
): void {
  currentLabelReader = reader;
}

/** Reads the active invocation's immutable label draft, if the invocation admitted one. */
export function readCurrentTranscriptMemoryPolicyLabel(params: {
  agentId: string;
  sessionId: string;
}): TranscriptMemoryPolicyLabel | undefined {
  return currentLabelReader?.(params);
}
