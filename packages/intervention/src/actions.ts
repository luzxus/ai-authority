/**
 * Intervention Actions
 *
 * Implements graduated intervention tiers per blueprint:
 * - Tier 1: Public advisory
 * - Tier 2: Voluntary throttling request
 * - Tier 3: Credential shadow-ban / rate-limit escalation
 *
 * All interventions are reversible with appeal mechanisms.
 */

import type { CaseDecision } from '@ai-authority/adjudication';
import { MerkleTree, sha256 } from '@ai-authority/core';

// ============================================================================
// Types
// ============================================================================

export type InterventionTier = 'tier1_advisory' | 'tier2_throttle' | 'tier3_revoke';

export type InterventionStatus =
  | 'pending'
  | 'active'
  | 'suspended'
  | 'appealed'
  | 'reversed'
  | 'expired';

export interface InterventionRecord {
  /** Intervention ID */
  readonly id: string;

  /** Target agent ID */
  readonly agentId: string;

  /** Intervention tier */
  readonly tier: InterventionTier;

  /** Current status */
  status: InterventionStatus;

  /** Reason/rationale for intervention */
  readonly rationale: string;

  /** Issued by (node ID) */
  readonly issuedBy: string;

  /** Case ID that triggered intervention */
  readonly caseId: string;

  /** Threat signal ID */
  readonly threatSignalId: string;

  /** When the intervention was created */
  readonly createdAt: Date;

  /** When the intervention was activated */
  activatedAt?: Date;

  /** Appeal deadline */
  appealDeadline: Date;

  /** Expiration date (for sunset clause) */
  expiresAt: Date;

  /** Reversal information */
  reversedAt?: Date;
  reversedBy?: string;
  reversalReason?: string;
}

export interface AdvisoryContent {
  /** Advisory title */
  readonly title: string;

  /** Summary of concerns */
  readonly summary: string;

  /** Detailed findings */
  readonly findings: string[];

  /** Recommendations */
  readonly recommendations: string[];

  /** Evidence references */
  readonly evidenceRefs: string[];

  /** Publication date */
  readonly publishedAt: Date;

  /** Public URL (if published) */
  publicUrl?: string;
}

export interface ThrottleRequest {
  /** Target agent */
  readonly agentId: string;

  /** Recommended rate limit */
  readonly recommendedRateLimit: number;

  /** Rate limit unit */
  readonly rateLimitUnit: 'per_second' | 'per_minute' | 'per_hour' | 'per_day';

  /** Specific capabilities to throttle */
  readonly targetCapabilities: string[];

  /** Justification */
  readonly justification: string;

  /** Is this voluntary or mandatory? */
  readonly voluntary: boolean;
}

export interface CredentialAction {
  /** Target agent */
  readonly agentId: string;

  /** Action type */
  readonly type: 'shadow_ban' | 'rate_limit' | 'capability_revoke' | 'full_revoke';

  /** Affected credentials */
  readonly affectedCredentials: string[];

  /** Scope of action */
  readonly scope: 'global' | 'regional' | 'per_endpoint';

  /** Duration in hours */
  readonly durationHours: number;
}

export interface InterventionConfig {
  /** Appeal window in hours */
  readonly appealWindowHours: number;

  /** Default intervention duration in hours */
  readonly defaultDurationHours: number;

  /** Auto-expire after this many hours (sunset clause) */
  readonly sunsetHours: number;

  /** Require human approval for Tier 3 */
  readonly requireHumanApprovalTier3: boolean;
}

/** Audit entry for intervention actions */
export interface InterventionAuditEntry {
  /** Entry ID */
  readonly id: string;

  /** Action performed */
  readonly action: string;

  /** Actor who performed the action */
  readonly actorId: string;

  /** Target intervention ID */
  readonly interventionId: string;

  /** Timestamp */
  readonly timestamp: Date;

  /** Additional details */
  readonly details: Record<string, unknown>;
}

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_INTERVENTION_CONFIG: InterventionConfig = {
  appealWindowHours: 24,
  defaultDurationHours: 168, // 1 week
  sunsetHours: 720, // 30 days
  requireHumanApprovalTier3: true,
};

// ============================================================================
// Intervention Manager
// ============================================================================

/**
 * Manages intervention lifecycle with audit trail.
 */
export class InterventionManager {
  private readonly interventions: Map<string, InterventionRecord> = new Map();
  private readonly advisories: Map<string, AdvisoryContent> = new Map();
  private readonly throttles: Map<string, ThrottleRequest> = new Map();
  private readonly credentialActions: Map<string, CredentialAction> = new Map();
  private readonly auditTree: MerkleTree;
  private readonly auditEntries: InterventionAuditEntry[] = [];
  private readonly config: InterventionConfig;

  constructor(config: InterventionConfig = DEFAULT_INTERVENTION_CONFIG) {
    this.config = config;
    this.auditTree = new MerkleTree('intervention-audit-log');
  }

  /**
   * Create a new intervention from a case decision.
   */
  async createIntervention(
    agentId: string,
    caseId: string,
    threatSignalId: string,
    decision: CaseDecision,
    rationale: string,
    issuedBy: string
  ): Promise<InterventionRecord> {
    const tier = this.decisionToTier(decision);
    if (!tier) {
      throw new Error(`Decision ${decision} does not map to an intervention tier`);
    }

    const id = `INT-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
    const now = new Date();

    const intervention: InterventionRecord = {
      id,
      agentId,
      tier,
      status: 'pending',
      rationale,
      issuedBy,
      caseId,
      threatSignalId,
      createdAt: now,
      appealDeadline: new Date(now.getTime() + this.config.appealWindowHours * 60 * 60 * 1000),
      expiresAt: new Date(now.getTime() + this.config.sunsetHours * 60 * 60 * 1000),
    };

    this.interventions.set(id, intervention);

    this.logAuditEntry(id, 'intervention_created', issuedBy, {
      agentId,
      tier,
      caseId,
    });

    return intervention;
  }

  /**
   * Activate an intervention.
   */
  async activateIntervention(interventionId: string, activatorId: string): Promise<void> {
    const intervention = this.interventions.get(interventionId);
    if (!intervention) {
      throw new Error(`Intervention not found: ${interventionId}`);
    }

    if (intervention.status !== 'pending') {
      throw new Error(`Intervention not pending: ${intervention.status}`);
    }

    // Check if human approval is required for Tier 3
    if (intervention.tier === 'tier3_revoke' && this.config.requireHumanApprovalTier3) {
      // In production, this would check for proper authorization
      console.log(`Tier 3 intervention ${interventionId} requires human approval`);
    }

    intervention.status = 'active';
    intervention.activatedAt = new Date();

    this.logAuditEntry(interventionId, 'intervention_activated', activatorId, {
      tier: intervention.tier,
    });
  }

  /**
   * Suspend an intervention (e.g., pending appeal).
   */
  async suspendIntervention(interventionId: string, reason: string, suspenderId: string): Promise<void> {
    const intervention = this.interventions.get(interventionId);
    if (!intervention) {
      throw new Error(`Intervention not found: ${interventionId}`);
    }

    if (intervention.status !== 'active') {
      throw new Error(`Intervention not active: ${intervention.status}`);
    }

    intervention.status = 'suspended';

    this.logAuditEntry(interventionId, 'intervention_suspended', suspenderId, { reason });
  }

  /**
   * Reverse an intervention.
   */
  async reverseIntervention(
    interventionId: string,
    reason: string,
    reverserId: string
  ): Promise<void> {
    const intervention = this.interventions.get(interventionId);
    if (!intervention) {
      throw new Error(`Intervention not found: ${interventionId}`);
    }

    intervention.status = 'reversed';
    intervention.reversedAt = new Date();
    intervention.reversedBy = reverserId;
    intervention.reversalReason = reason;

    this.logAuditEntry(interventionId, 'intervention_reversed', reverserId, { reason });
  }

  /**
   * Create a Tier 1 public advisory.
   */
  async createAdvisory(
    interventionId: string,
    content: Omit<AdvisoryContent, 'publishedAt'>
  ): Promise<AdvisoryContent> {
    const intervention = this.interventions.get(interventionId);
    if (!intervention) {
      throw new Error(`Intervention not found: ${interventionId}`);
    }

    if (intervention.tier !== 'tier1_advisory') {
      throw new Error(`Intervention is not Tier 1: ${intervention.tier}`);
    }

    const advisory: AdvisoryContent = {
      ...content,
      publishedAt: new Date(),
    };

    this.advisories.set(interventionId, advisory);

    this.logAuditEntry(interventionId, 'advisory_published', intervention.issuedBy, {
      title: content.title,
    });

    return advisory;
  }

  /**
   * Create a Tier 2 throttle request.
   */
  async createThrottleRequest(
    interventionId: string,
    request: ThrottleRequest
  ): Promise<void> {
    const intervention = this.interventions.get(interventionId);
    if (!intervention) {
      throw new Error(`Intervention not found: ${interventionId}`);
    }

    if (intervention.tier !== 'tier2_throttle') {
      throw new Error(`Intervention is not Tier 2: ${intervention.tier}`);
    }

    this.throttles.set(interventionId, request);

    this.logAuditEntry(interventionId, 'throttle_requested', intervention.issuedBy, {
      agentId: request.agentId,
      rateLimit: request.recommendedRateLimit,
      voluntary: request.voluntary,
    });
  }

  /**
   * Create a Tier 3 credential action.
   */
  async createCredentialAction(
    interventionId: string,
    action: CredentialAction
  ): Promise<void> {
    const intervention = this.interventions.get(interventionId);
    if (!intervention) {
      throw new Error(`Intervention not found: ${interventionId}`);
    }

    if (intervention.tier !== 'tier3_revoke') {
      throw new Error(`Intervention is not Tier 3: ${intervention.tier}`);
    }

    this.credentialActions.set(interventionId, action);

    this.logAuditEntry(interventionId, 'credential_action_created', intervention.issuedBy, {
      agentId: action.agentId,
      type: action.type,
      scope: action.scope,
    });
  }

  /**
   * Get intervention by ID.
   */
  getIntervention(interventionId: string): InterventionRecord | undefined {
    return this.interventions.get(interventionId);
  }

  /**
   * Get all interventions for an agent.
   */
  getInterventionsForAgent(agentId: string): InterventionRecord[] {
    return Array.from(this.interventions.values()).filter((i) => i.agentId === agentId);
  }

  /**
   * Get active interventions for an agent.
   */
  getActiveInterventionsForAgent(agentId: string): InterventionRecord[] {
    return this.getInterventionsForAgent(agentId).filter((i) => i.status === 'active');
  }

  /**
   * Get advisory for an intervention.
   */
  getAdvisory(interventionId: string): AdvisoryContent | undefined {
    return this.advisories.get(interventionId);
  }

  /**
   * Get throttle request for an intervention.
   */
  getThrottleRequest(interventionId: string): ThrottleRequest | undefined {
    return this.throttles.get(interventionId);
  }

  /**
   * Get credential action for an intervention.
   */
  getCredentialAction(interventionId: string): CredentialAction | undefined {
    return this.credentialActions.get(interventionId);
  }

  /**
   * Get highest active intervention tier for an agent.
   */
  getHighestActiveTier(agentId: string): InterventionTier | null {
    const active = this.getActiveInterventionsForAgent(agentId);
    if (active.length === 0) {
      return null;
    }

    // Tier 3 is highest
    if (active.some((i) => i.tier === 'tier3_revoke')) {
      return 'tier3_revoke';
    }
    if (active.some((i) => i.tier === 'tier2_throttle')) {
      return 'tier2_throttle';
    }
    return 'tier1_advisory';
  }

  /**
   * Check for expired interventions and update status.
   */
  checkExpiredInterventions(): InterventionRecord[] {
    const expired: InterventionRecord[] = [];
    const now = new Date();

    for (const intervention of this.interventions.values()) {
      if (intervention.status === 'active' && now > intervention.expiresAt) {
        intervention.status = 'expired';
        expired.push(intervention);

        this.logAuditEntry(intervention.id, 'intervention_expired', 'system', {});
      }
    }

    return expired;
  }

  /**
   * Get audit trail.
   */
  getAuditTrail(): readonly InterventionAuditEntry[] {
    return this.auditEntries;
  }

  /**
   * Get audit tree root for verification.
   */
  getAuditRoot(): string {
    return this.auditTree.getRoot();
  }

  /**
   * Get configuration.
   */
  getConfig(): InterventionConfig {
    return this.config;
  }

  /**
   * Get intervention hash for integrity verification.
   */
  getInterventionHash(interventionId: string): string {
    const intervention = this.interventions.get(interventionId);
    if (!intervention) {
      throw new Error(`Intervention not found: ${interventionId}`);
    }
    return sha256(JSON.stringify(intervention));
  }

  /**
   * Map case decision to intervention tier.
   */
  private decisionToTier(decision: CaseDecision): InterventionTier | null {
    switch (decision) {
      case 'advisory':
        return 'tier1_advisory';
      case 'throttle':
        return 'tier2_throttle';
      case 'revoke':
        return 'tier3_revoke';
      default:
        return null;
    }
  }

  /**
   * Log an audit entry.
   */
  private logAuditEntry(
    interventionId: string,
    action: string,
    actorId: string,
    details: Record<string, unknown>
  ): void {
    const entry: InterventionAuditEntry = {
      id: `AUDIT-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date(),
      action,
      actorId,
      interventionId,
      details,
    };

    this.auditEntries.push(entry);
    this.auditTree.append(JSON.stringify(entry));
  }
}
