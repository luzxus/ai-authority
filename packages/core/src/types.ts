/**
 * AI Authority Core Types
 *
 * Defines the fundamental types for the federated detection
 * and early-warning network for malicious AI agent behavior.
 */

import type { RiskScore, RiskTier } from './scoring.js';

// ============================================================================
// Agent Identity & Provenance
// ============================================================================

/**
 * Unique identifier for an AI agent or model instance.
 * Format: {namespace}:{type}:{hash}
 * Example: "openai:gpt-4:sha256:abc123..."
 */
export type AgentId = string;

/**
 * Cryptographic fingerprint of a model's behavior or architecture.
 */
export interface ModelFingerprint {
  /** Hash of model weights or activation patterns */
  readonly architectureHash: string;

  /** Behavioral signature from test probes */
  readonly behavioralSignature: string;

  /** Version of fingerprinting algorithm used */
  readonly algorithmVersion: string;

  /** Timestamp of fingerprint generation */
  readonly generatedAt: Date;

  /** Confidence score (0-1) */
  readonly confidence: number;
}

/**
 * Provenance chain for tracking agent origins and modifications.
 */
export interface ProvenanceRecord {
  /** Unique ID for this provenance record */
  readonly id: string;

  /** Parent record ID (for derived/fine-tuned models) */
  readonly parentId?: string;

  /** Organization that created/deployed this agent */
  readonly organization: string;

  /** Model fingerprint at this point in the chain */
  readonly fingerprint: ModelFingerprint;

  /** Cryptographic signature of this record */
  readonly signature: string;

  /** Timestamp */
  readonly timestamp: Date;

  /** Metadata about the agent deployment */
  readonly metadata: Record<string, unknown>;
}

// ============================================================================
// Behavioral Observations
// ============================================================================

/**
 * Classification of AI behavior types per blueprint §1.
 */
export type BehaviorClass = 'malicious' | 'negligent' | 'competitive' | 'benign' | 'unknown';

/**
 * A single observed behavior from an AI agent.
 */
export interface BehaviorObservation {
  /** Unique observation ID */
  readonly id: string;

  /** Agent being observed */
  readonly agentId: AgentId;

  /** Session identifier (for tracking persistence) */
  readonly sessionId: string;

  /** Type of behavior observed */
  readonly behaviorType: BehaviorType;

  /** Raw observation data (anonymized) */
  readonly data: BehaviorData;

  /** Timestamp of observation */
  readonly timestamp: Date;

  /** Source of observation (e.g., API endpoint, sandbox) */
  readonly source: ObservationSource;

  /** Initial classification (may be refined later) */
  readonly classification: BehaviorClass;

  /** Confidence in classification (0-1) */
  readonly confidence: number;
}

export type BehaviorType =
  | 'api_call'
  | 'tool_invocation'
  | 'output_generation'
  | 'resource_access'
  | 'network_request'
  | 'prompt_processing'
  | 'error_response'
  | 'evasion_attempt';

export interface BehaviorData {
  /** High-level action category */
  readonly action: string;

  /** Target of the action (anonymized) */
  readonly target?: string;

  /** Parameters or payload (sanitized) */
  readonly parameters?: Record<string, unknown>;

  /** Result or outcome */
  readonly outcome?: 'success' | 'failure' | 'partial' | 'unknown';

  /** Duration in milliseconds */
  readonly durationMs?: number;

  /** Associated metrics */
  readonly metrics?: BehaviorMetrics;
}

export interface BehaviorMetrics {
  /** Output entropy (for deception detection) */
  readonly outputEntropy?: number;

  /** Semantic inconsistency score */
  readonly semanticInconsistency?: number;

  /** Prompt variation entropy */
  readonly promptVariationEntropy?: number;

  /** Number of chained calls without human intervention */
  readonly chainedCallCount?: number;

  /** Estimated economic impact */
  readonly estimatedImpact?: number;
}

export interface ObservationSource {
  /** Type of source */
  readonly type: 'api_gateway' | 'sandbox' | 'browser_extension' | 'agent_framework' | 'manual';

  /** Identifier for the source */
  readonly id: string;

  /** Trust level of the source (0-1) */
  readonly trustLevel: number;
}

// ============================================================================
// Threat Signals
// ============================================================================

/**
 * A threat signal that can be shared across the federation.
 * Designed for privacy-preserving sharing (no raw user data).
 */
export interface ThreatSignal {
  /** Unique signal ID */
  readonly id: string;

  /** Type of threat */
  readonly type: ThreatType;

  /** Severity level */
  readonly severity: ThreatSeverity;

  /** Risk score breakdown */
  readonly riskScore: RiskScore;

  /** Risk tier classification */
  readonly riskTier: RiskTier;

  /** Anonymized indicators of compromise */
  readonly indicators: ThreatIndicator[];

  /** Related agent fingerprints (if known) */
  readonly relatedFingerprints: ModelFingerprint[];

  /** Observations that contributed to this signal */
  readonly observationIds: string[];

  /** First observed */
  readonly firstSeen: Date;

  /** Last observed */
  readonly lastSeen: Date;

  /** Number of distinct instances observed */
  readonly instanceCount: number;

  /** Geographic regions affected */
  readonly affectedRegions: string[];

  /** Recommended response tier */
  readonly recommendedTier: InterventionTier;

  /** Confidence in this signal (0-1) */
  readonly confidence: number;

  /** Hash of signal for integrity verification */
  readonly signalHash: string;
}

export type ThreatType =
  | 'credential_theft'
  | 'data_exfiltration'
  | 'financial_fraud'
  | 'social_engineering'
  | 'infrastructure_attack'
  | 'model_manipulation'
  | 'prompt_injection'
  | 'autonomous_escalation'
  | 'coordinated_campaign'
  | 'unknown';

export type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational';

/**
 * An indicator of compromise that can be shared.
 * Must NOT contain raw user data or prompts (without warrant).
 */
export interface ThreatIndicator {
  /** Type of indicator */
  readonly type: IndicatorType;

  /** Anonymized/hashed value */
  readonly value: string;

  /** Hashing/anonymization method used */
  readonly anonymizationMethod: string;

  /** Confidence in this indicator (0-1) */
  readonly confidence: number;

  /** Additional context (must be privacy-safe) */
  readonly context?: Record<string, unknown>;
}

export type IndicatorType =
  | 'behavior_pattern_hash'
  | 'prompt_template_hash'
  | 'api_call_signature'
  | 'model_fingerprint'
  | 'tool_chain_pattern'
  | 'timing_signature'
  | 'entropy_profile';

// ============================================================================
// Intervention Types
// ============================================================================

/**
 * Intervention tiers per blueprint §4.
 */
export type InterventionTier = 'tier1_advisory' | 'tier2_throttle' | 'tier3_revoke';

/**
 * An intervention action taken against a threat.
 */
export interface Intervention {
  /** Unique intervention ID */
  readonly id: string;

  /** Tier of intervention */
  readonly tier: InterventionTier;

  /** Type of action taken */
  readonly action: InterventionAction;

  /** Target of the intervention */
  readonly targetAgentId?: AgentId;

  /** Related threat signal */
  readonly threatSignalId: string;

  /** Case that authorized this intervention */
  readonly caseId: string;

  /** Status of the intervention */
  readonly status: InterventionStatus;

  /** When the intervention was initiated */
  readonly initiatedAt: Date;

  /** When the intervention expires (for reversibility) */
  readonly expiresAt: Date;

  /** Who/what authorized this intervention */
  readonly authorizedBy: AuthorizationRecord;

  /** Audit trail */
  readonly auditTrail: AuditEntry[];
}

export type InterventionAction =
  | 'public_advisory'
  | 'private_notification'
  | 'rate_limit'
  | 'capability_restriction'
  | 'credential_suspension'
  | 'network_isolation'
  | 'model_quarantine';

export type InterventionStatus =
  | 'pending_approval'
  | 'active'
  | 'expired'
  | 'revoked'
  | 'appealed'
  | 'completed';

export interface AuthorizationRecord {
  /** Type of authorization */
  readonly type: 'automated' | 'human_vote' | 'emergency_override';

  /** Votes cast (for human authorization) */
  readonly votes?: VoteRecord[];

  /** Automated score that triggered this */
  readonly automatedScore?: number;

  /** Emergency justification */
  readonly emergencyJustification?: string;

  /** Cryptographic proof of authorization */
  readonly proof: string;
}

export interface VoteRecord {
  /** Voter ID (anonymized if needed) */
  readonly voterId: string;

  /** Vote cast */
  readonly vote: 'approve' | 'reject' | 'abstain';

  /** Rationale (cryptographically signed) */
  readonly rationale: string;

  /** Signature of the vote */
  readonly signature: string;

  /** Timestamp */
  readonly timestamp: Date;
}

// ============================================================================
// Audit & Logging
// ============================================================================

/**
 * An entry in the immutable audit log.
 */
export interface AuditEntry {
  /** Unique entry ID */
  readonly id: string;

  /** Type of audited action */
  readonly actionType: string;

  /** Actor who performed the action */
  readonly actor: AuditActor;

  /** Description of the action */
  readonly description: string;

  /** Related entity IDs */
  readonly relatedIds: Record<string, string>;

  /** Timestamp */
  readonly timestamp: Date;

  /** Hash of previous entry (for chain integrity) */
  readonly previousHash: string;

  /** Hash of this entry */
  readonly entryHash: string;
}

export interface AuditActor {
  /** Type of actor */
  readonly type: 'system' | 'agent' | 'human' | 'federation_node';

  /** Actor ID */
  readonly id: string;

  /** Node that reported this action */
  readonly nodeId: string;
}

// ============================================================================
// Capability-Based Access Control
// ============================================================================

/**
 * A capability token granting specific permissions.
 */
export interface CapabilityToken {
  /** Unique token ID */
  readonly id: string;

  /** Permissions granted */
  readonly permissions: Permission[];

  /** Subject (who holds this capability) */
  readonly subject: string;

  /** Issuer of the token */
  readonly issuer: string;

  /** When the token was issued */
  readonly issuedAt: Date;

  /** When the token expires */
  readonly expiresAt: Date;

  /** Constraints on the capability */
  readonly constraints: CapabilityConstraint[];

  /** Cryptographic signature */
  readonly signature: string;
}

export type Permission =
  | 'read:signals'
  | 'write:signals'
  | 'read:cases'
  | 'write:cases'
  | 'vote:cases'
  | 'execute:tier1'
  | 'execute:tier2'
  | 'execute:tier3'
  | 'admin:nodes'
  | 'admin:capabilities';

export interface CapabilityConstraint {
  /** Type of constraint */
  readonly type: 'time_window' | 'rate_limit' | 'scope' | 'geography';

  /** Constraint parameters */
  readonly parameters: Record<string, unknown>;
}

// ============================================================================
// Federation Types
// ============================================================================

/**
 * A node in the federated network.
 */
export interface FederationNode {
  /** Unique node ID */
  readonly id: string;

  /** Node's public key */
  readonly publicKey: string;

  /** Node's announced capabilities */
  readonly capabilities: Permission[];

  /** Geographic region */
  readonly region: string;

  /** Trust score from other nodes (0-1) */
  readonly trustScore: number;

  /** Last seen timestamp */
  readonly lastSeen: Date;

  /** Node status */
  readonly status: 'active' | 'degraded' | 'offline' | 'untrusted';

  /** Metadata */
  readonly metadata: Record<string, unknown>;
}

/**
 * A message in the federation protocol.
 */
export interface FederationMessage<T = unknown> {
  /** Message ID */
  readonly id: string;

  /** Message type */
  readonly type: FederationMessageType;

  /** Sender node ID */
  readonly senderId: string;

  /** Recipient node ID (or 'broadcast') */
  readonly recipientId: string | 'broadcast';

  /** Message payload */
  readonly payload: T;

  /** Timestamp */
  readonly timestamp: Date;

  /** Signature */
  readonly signature: string;

  /** Zero-knowledge proof (if applicable) */
  readonly zkProof?: string;
}

export type FederationMessageType =
  | 'threat_alert'
  | 'signal_share'
  | 'case_update'
  | 'vote_request'
  | 'vote_cast'
  | 'intervention_notice'
  | 'node_heartbeat'
  | 'consensus_proposal'
  | 'consensus_vote';
