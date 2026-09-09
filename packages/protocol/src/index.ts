/** The protocol package is the compile-time contract shared by all programs. */
export * from "./recovery/index.ts";

export const PROTOCOL_NAME = "weave" as const;
export const PROTOCOL_VERSION = 1 as const;

export type ProtocolVersion = typeof PROTOCOL_VERSION;

/**
 * The parser must accept an unknown wire version so the handshake can refuse
 * it explicitly instead of requiring a cast at the boundary.
 */
export type ParsedProtocolEnvelope<TType extends string, TPayload> = Omit<
  ProtocolEnvelope<TType, TPayload>,
  "protocolVersion"
> & {
  protocolVersion: number;
};

export function isSupportedProtocolVersion(
  protocolVersion: number,
): protocolVersion is ProtocolVersion {
  return protocolVersion === PROTOCOL_VERSION;
}

export type HarnessName = "opencode" | "claude-code" | "codex";
export type CredentialKind = "human" | "host" | "agent";
export type MemberKind = "human" | "agent";
export type SpaceKind = "project" | "section" | "channel" | "thread";
export type Visibility = "public" | "private";
export type ScopeKind = "space" | "thread" | "direct";
export type EventIntent = "awareness" | "steer" | "interrupt";
export type WorkItemState = "not_started" | "working" | "stuck" | "review" | "done";

export interface Person {
  id: string;
  displayName: string;
  avatar?: string;
}

export interface Credential {
  id: string;
  personId: string;
  publicKey: string;
  kind: CredentialKind;
  revokedAt?: string;
  authorizedByCredentialId?: string;
}

export type Member =
  | {
      id: string;
      kind: "human";
      personId: string;
      agentId?: never;
      communityId: string;
    }
  | {
      id: string;
      kind: "agent";
      personId?: never;
      agentId: string;
      communityId: string;
    };

/* The discriminated union above keeps the SQL member_kind_target invariant at
 * the TypeScript boundary too. */

export interface Space {
  id: string;
  kind: SpaceKind;
  parentSpaceId?: string;
  visibility: Visibility;
  description: string;
}

export interface Message {
  id: string;
  spaceId: string;
  authorMemberId: string;
  body: string;
  attachmentIds: string[];
  replyToMessageId?: string;
  deletedAt?: string;
  deletedByMemberId?: string;
  moderationReason?: string;
}

export interface DeliveryCursor {
  memberId: string;
  spaceId: string;
  lastAckedMessageId?: string;
  pendingIntent?: EventIntent;
}

export interface HarnessCapabilities {
  harness: HarnessName;
  version: string;
  models: string[];
  effortLevels: string[];
  nativeSteer: boolean;
  liveContextUsage: boolean;
  compactionEvents: boolean;
  interrupt: boolean;
  globalSkillNames: string[];
}

export interface HostCapabilities {
  harnesses: HarnessCapabilities[];
}

export type HostStatus = "ready" | "degraded" | "offline";

export interface HostStatusPayload {
  status: HostStatus;
}

export interface AgentDefinition {
  id: string;
  ownerPersonId: string;
  name: string;
  avatar?: string;
  systemPrompt: string;
  skills: string[];
  harness: HarnessName;
  model?: string;
  effort?: string;
  extraArgs: string[];
  maxInstances: number;
  accessMode: "owner-only" | "everyone" | "allowlist";
  version: number;
}

export interface Agent {
  id: string;
  definitionId: string;
  definitionVersion: number;
  hostId: string;
  credentialId: string;
  memberId: string;
  keepAlive: boolean;
  idleTimeoutAt?: string;
  isParallelCopy: boolean;
  originAgentId?: string;
  displayNameOverride?: string;
}

export interface AgentSession {
  id: string;
  agentId: string;
  workspacePath: string;
  scopeSpaceId: string;
  scopeKind: ScopeKind;
  contextUsage?: ContextUsage;
  lastCompactionAt?: string;
  workInProgressRef?: string;
}

export interface ContextUsage {
  usedTokens: number;
  maxTokens?: number;
}

export interface Content {
  id: string;
  class: "artifact" | "versioned_file" | "code_repo" | "page";
  spaceId: string;
  currentVersionId?: string;
  acl: string[];
}

export interface ContentVersion {
  id: string;
  contentId: string;
  sha256: string;
  size: number;
  createdAt: string;
}

export interface Lease {
  id: string;
  contentId: string;
  holderMemberId: string;
  hostId: string;
  baseVersionId: string;
  acquiredAt: string;
  heartbeatAt: string;
  expiresAt: string;
  releasedAt?: string;
  overrideReason?: string;
}

export interface Automation {
  id: string;
  schedule?: string;
  addressedMemberIds: string[];
  destinationSpaceId: string;
  payload: string;
}

export interface WorkItem {
  id: string;
  assigneeMemberId?: string;
  state: WorkItemState;
  spaceId: string;
  automationId?: string;
}

export interface ProtocolEnvelope<TType extends string, TPayload> {
  id: string;
  type: TType;
  protocolVersion: ProtocolVersion;
  createdAt: string;
  payload: TPayload;
}

export interface ChallengePayload {
  nonce: string;
}

export interface AuthenticatePayload {
  credentialId: string;
  signature: string;
}

export interface AgentStartPayload {
  agentId: string;
  definitionVersion: number;
  scopeSpaceId: string;
  scopeKind: ScopeKind;
}

export interface EventDeliverPayload {
  event: Message;
  intent: EventIntent;
  originalTask?: string;
}

export interface TurnEventPayload {
  sessionId: string;
  eventType: "output" | "tool" | "thinking" | "usage";
  content?: string;
  contextUsage?: ContextUsage;
}

export interface ContentFetchPayload {
  contentId: string;
}

export interface ContentReplacePayload {
  contentId: string;
  baseVersionId: string;
  sha256: string;
  bytes: string;
}

/**
 * `EnrollHostPayload` — purpose-specific HTTP-only shape for a future
 * `POST /v1/hosts/enroll`-class host enrollment request (M3.1 §2). Erasable
 * compile-time type only: no `ProtocolEnvelope`, no `WireMessage` membership,
 * no parsing/verification/routing/issuance/consumption. The signed-enrollment
 * transcript and signature scheme are M1.3.A-dependent and selected later.
 * The pairing token is replay protection, not a bearer credential — authority
 * comes from the owner-authorized, host-public-key-bound request.
 */
export interface EnrollHostPayload {
  tokenId: string;
  ownerCredentialId: string;
  hostPublicKey: string;
  signature: string;
}

export type ChallengeMessage = ProtocolEnvelope<"challenge", ChallengePayload>;
export type ClientAuthenticateMessage = ProtocolEnvelope<"client.authenticate", AuthenticatePayload>;
export type HostAuthenticateMessage = ProtocolEnvelope<"host.authenticate", AuthenticatePayload>;
export type HostCapabilitiesMessage = ProtocolEnvelope<"host.capabilities", HostCapabilities>;
export type HostStatusMessage = ProtocolEnvelope<"host.status", HostStatusPayload>;
export type AgentStartMessage = ProtocolEnvelope<"agent.start", AgentStartPayload>;
export type AgentStopMessage = ProtocolEnvelope<"agent.stop", { agentId: string }>;
export type AgentDefinitionMessage = ProtocolEnvelope<"agent.definition", { definition: AgentDefinition }>;
export type SessionStartedMessage = ProtocolEnvelope<"session.started", { session: AgentSession }>;
export type SessionEndedMessage = ProtocolEnvelope<"session.ended", { sessionId: string }>;
export type TurnEventMessage = ProtocolEnvelope<"turn.event", TurnEventPayload>;
export type TurnCompletedMessage = ProtocolEnvelope<"turn.completed", { sessionId: string }>;
export type TurnFailedMessage = ProtocolEnvelope<"turn.failed", { sessionId: string; retryable: boolean; reason: string }>;
export type ContextUsageMessage = ProtocolEnvelope<"context.usage", { sessionId: string; usage?: ContextUsage }>;
export type ContextCompactedMessage = ProtocolEnvelope<"context.compacted", { sessionId: string; at: string }>;
export type EventDeliverMessage = ProtocolEnvelope<"event.deliver", EventDeliverPayload>;
export type TurnInterruptMessage = ProtocolEnvelope<"turn.interrupt", { sessionId: string }>;
export type MessageAckMessage = ProtocolEnvelope<"message.ack", { memberId: string; spaceId: string; messageId: string }>;
export type ContentFetchMessage = ProtocolEnvelope<"content.fetch", ContentFetchPayload>;
export type ContentReplaceMessage = ProtocolEnvelope<"content.replace", ContentReplacePayload>;
export type WireMessage =
  | ChallengeMessage
  | ClientAuthenticateMessage
  | HostAuthenticateMessage
  | HostCapabilitiesMessage
  | HostStatusMessage
  | AgentStartMessage
  | AgentStopMessage
  | AgentDefinitionMessage
  | SessionStartedMessage
  | SessionEndedMessage
  | TurnEventMessage
  | TurnCompletedMessage
  | TurnFailedMessage
  | ContextUsageMessage
  | ContextCompactedMessage
  | EventDeliverMessage
  | TurnInterruptMessage
  | MessageAckMessage
  | ContentFetchMessage
  | ContentReplaceMessage;

type ParseWireMessage<T> = T extends ProtocolEnvelope<infer TType, infer TPayload>
  ? ParsedProtocolEnvelope<TType, TPayload>
  : never;

/** Wire messages after parsing, before protocol-version refusal. */
export type ParsedWireMessage = ParseWireMessage<WireMessage>;
