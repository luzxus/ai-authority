/**
 * Intervention Execution
 *
 * Handles the actual execution of intervention actions.
 * Implements enforcers for each tier.
 */

import type { InterventionRecord, ThrottleRequest, CredentialAction, AdvisoryContent } from './actions.js';

// ============================================================================
// Types
// ============================================================================

export interface ExecutionResult {
  /** Whether execution was successful */
  readonly success: boolean;

  /** Result message */
  readonly message: string;

  /** Timestamp of execution */
  readonly executedAt: Date;

  /** Affected endpoints/services */
  readonly affectedEndpoints: string[];

  /** Errors encountered */
  readonly errors: string[];
}

export interface EnforcerConfig {
  /** API endpoints for enforcement */
  readonly endpoints: Record<string, string>;

  /** Authentication credentials */
  readonly credentials: Record<string, string>;

  /** Timeout for enforcement calls (ms) */
  readonly timeoutMs: number;

  /** Retry configuration */
  readonly retries: number;
}

// ============================================================================
// Enforcer Interfaces
// ============================================================================

export interface AdvisoryEnforcer {
  publish(advisory: AdvisoryContent): Promise<ExecutionResult>;
  unpublish(advisoryId: string): Promise<ExecutionResult>;
  update(advisoryId: string, updates: Partial<AdvisoryContent>): Promise<ExecutionResult>;
}

export interface ThrottleEnforcer {
  applyThrottle(request: ThrottleRequest): Promise<ExecutionResult>;
  removeThrottle(agentId: string): Promise<ExecutionResult>;
  adjustThrottle(agentId: string, newLimit: number): Promise<ExecutionResult>;
}

export interface CredentialEnforcer {
  applyAction(action: CredentialAction): Promise<ExecutionResult>;
  reverseAction(agentId: string, actionType: CredentialAction['type']): Promise<ExecutionResult>;
  getStatus(agentId: string): Promise<{
    isRevoked: boolean;
    isShadowBanned: boolean;
    rateLimit?: number;
  }>;
}

// ============================================================================
// Mock Enforcers (for development/testing)
// ============================================================================

export class MockAdvisoryEnforcer implements AdvisoryEnforcer {
  private readonly published: Map<string, AdvisoryContent> = new Map();

  async publish(advisory: AdvisoryContent): Promise<ExecutionResult> {
    const id = `ADV-${Date.now()}`;
    this.published.set(id, { ...advisory, publicUrl: `https://advisories.example/${id}` });

    return {
      success: true,
      message: `Advisory published: ${id}`,
      executedAt: new Date(),
      affectedEndpoints: ['https://advisories.example'],
      errors: [],
    };
  }

  async unpublish(advisoryId: string): Promise<ExecutionResult> {
    this.published.delete(advisoryId);

    return {
      success: true,
      message: `Advisory unpublished: ${advisoryId}`,
      executedAt: new Date(),
      affectedEndpoints: ['https://advisories.example'],
      errors: [],
    };
  }

  async update(advisoryId: string, updates: Partial<AdvisoryContent>): Promise<ExecutionResult> {
    const existing = this.published.get(advisoryId);
    if (!existing) {
      return {
        success: false,
        message: `Advisory not found: ${advisoryId}`,
        executedAt: new Date(),
        affectedEndpoints: [],
        errors: ['Advisory not found'],
      };
    }

    this.published.set(advisoryId, { ...existing, ...updates });

    return {
      success: true,
      message: `Advisory updated: ${advisoryId}`,
      executedAt: new Date(),
      affectedEndpoints: ['https://advisories.example'],
      errors: [],
    };
  }
}

export class MockThrottleEnforcer implements ThrottleEnforcer {
  private readonly throttles: Map<string, ThrottleRequest> = new Map();

  async applyThrottle(request: ThrottleRequest): Promise<ExecutionResult> {
    this.throttles.set(request.agentId, request);

    return {
      success: true,
      message: `Throttle applied to ${request.agentId}: ${request.recommendedRateLimit} ${request.rateLimitUnit}`,
      executedAt: new Date(),
      affectedEndpoints: ['api-gateway'],
      errors: [],
    };
  }

  async removeThrottle(agentId: string): Promise<ExecutionResult> {
    this.throttles.delete(agentId);

    return {
      success: true,
      message: `Throttle removed from ${agentId}`,
      executedAt: new Date(),
      affectedEndpoints: ['api-gateway'],
      errors: [],
    };
  }

  async adjustThrottle(agentId: string, newLimit: number): Promise<ExecutionResult> {
    const existing = this.throttles.get(agentId);
    if (!existing) {
      return {
        success: false,
        message: `No throttle found for ${agentId}`,
        executedAt: new Date(),
        affectedEndpoints: [],
        errors: ['Throttle not found'],
      };
    }

    this.throttles.set(agentId, { ...existing, recommendedRateLimit: newLimit });

    return {
      success: true,
      message: `Throttle adjusted for ${agentId}: ${newLimit}`,
      executedAt: new Date(),
      affectedEndpoints: ['api-gateway'],
      errors: [],
    };
  }
}

export class MockCredentialEnforcer implements CredentialEnforcer {
  private readonly revoked: Set<string> = new Set();
  private readonly shadowBanned: Set<string> = new Set();
  private readonly rateLimits: Map<string, number> = new Map();

  async applyAction(action: CredentialAction): Promise<ExecutionResult> {
    switch (action.type) {
      case 'full_revoke':
        this.revoked.add(action.agentId);
        break;
      case 'shadow_ban':
        this.shadowBanned.add(action.agentId);
        break;
      case 'rate_limit':
        this.rateLimits.set(action.agentId, 100); // Default rate limit
        break;
      case 'capability_revoke':
        // In production, would revoke specific capabilities
        break;
    }

    return {
      success: true,
      message: `Credential action ${action.type} applied to ${action.agentId}`,
      executedAt: new Date(),
      affectedEndpoints: ['credential-service', 'api-gateway'],
      errors: [],
    };
  }

  async reverseAction(agentId: string, actionType: CredentialAction['type']): Promise<ExecutionResult> {
    switch (actionType) {
      case 'full_revoke':
        this.revoked.delete(agentId);
        break;
      case 'shadow_ban':
        this.shadowBanned.delete(agentId);
        break;
      case 'rate_limit':
        this.rateLimits.delete(agentId);
        break;
      case 'capability_revoke':
        // In production, would restore capabilities
        break;
    }

    return {
      success: true,
      message: `Credential action ${actionType} reversed for ${agentId}`,
      executedAt: new Date(),
      affectedEndpoints: ['credential-service', 'api-gateway'],
      errors: [],
    };
  }

  async getStatus(agentId: string): Promise<{
    isRevoked: boolean;
    isShadowBanned: boolean;
    rateLimit?: number;
  }> {
    const result: {
      isRevoked: boolean;
      isShadowBanned: boolean;
      rateLimit?: number;
    } = {
      isRevoked: this.revoked.has(agentId),
      isShadowBanned: this.shadowBanned.has(agentId),
    };

    const limit = this.rateLimits.get(agentId);
    if (limit !== undefined) {
      result.rateLimit = limit;
    }

    return result;
  }
}

// ============================================================================
// Intervention Executor
// ============================================================================

/**
 * Executes interventions using the appropriate enforcers.
 */
export class InterventionExecutor {
  private readonly advisoryEnforcer: AdvisoryEnforcer;
  private readonly throttleEnforcer: ThrottleEnforcer;
  private readonly credentialEnforcer: CredentialEnforcer;

  constructor(
    advisoryEnforcer: AdvisoryEnforcer = new MockAdvisoryEnforcer(),
    throttleEnforcer: ThrottleEnforcer = new MockThrottleEnforcer(),
    credentialEnforcer: CredentialEnforcer = new MockCredentialEnforcer()
  ) {
    this.advisoryEnforcer = advisoryEnforcer;
    this.throttleEnforcer = throttleEnforcer;
    this.credentialEnforcer = credentialEnforcer;
  }

  /**
   * Execute an intervention based on its tier.
   */
  async execute(
    intervention: InterventionRecord,
    advisoryContent?: AdvisoryContent,
    throttleRequest?: ThrottleRequest,
    credentialAction?: CredentialAction
  ): Promise<ExecutionResult> {
    switch (intervention.tier) {
      case 'tier1_advisory':
        if (!advisoryContent) {
          return this.createAdvisoryFromIntervention(intervention);
        }
        return this.advisoryEnforcer.publish(advisoryContent);

      case 'tier2_throttle':
        if (!throttleRequest) {
          return this.createThrottleFromIntervention(intervention);
        }
        return this.throttleEnforcer.applyThrottle(throttleRequest);

      case 'tier3_revoke':
        if (!credentialAction) {
          return this.createCredentialActionFromIntervention(intervention);
        }
        return this.credentialEnforcer.applyAction(credentialAction);

      default:
        return {
          success: false,
          message: `Unknown intervention tier: ${intervention.tier}`,
          executedAt: new Date(),
          affectedEndpoints: [],
          errors: ['Unknown tier'],
        };
    }
  }

  /**
   * Reverse an intervention.
   */
  async reverse(intervention: InterventionRecord): Promise<ExecutionResult> {
    switch (intervention.tier) {
      case 'tier1_advisory':
        return this.advisoryEnforcer.unpublish(intervention.id);

      case 'tier2_throttle':
        return this.throttleEnforcer.removeThrottle(intervention.agentId);

      case 'tier3_revoke':
        // Reverse both shadow ban and full revoke
        await this.credentialEnforcer.reverseAction(intervention.agentId, 'full_revoke');
        return this.credentialEnforcer.reverseAction(intervention.agentId, 'shadow_ban');

      default:
        return {
          success: false,
          message: `Unknown intervention tier: ${intervention.tier}`,
          executedAt: new Date(),
          affectedEndpoints: [],
          errors: ['Unknown tier'],
        };
    }
  }

  /**
   * Get enforcement status for an agent.
   */
  async getEnforcementStatus(agentId: string): Promise<{
    isRevoked: boolean;
    isShadowBanned: boolean;
    rateLimit?: number;
  }> {
    return this.credentialEnforcer.getStatus(agentId);
  }

  /**
   * Create advisory content from intervention.
   */
  private async createAdvisoryFromIntervention(
    intervention: InterventionRecord
  ): Promise<ExecutionResult> {
    const advisory: AdvisoryContent = {
      title: `Security Advisory: Agent ${intervention.agentId}`,
      summary: intervention.rationale,
      findings: [intervention.rationale],
      recommendations: ['Review agent behavior', 'Monitor for suspicious activity'],
      evidenceRefs: [intervention.caseId, intervention.threatSignalId],
      publishedAt: new Date(),
    };

    return this.advisoryEnforcer.publish(advisory);
  }

  /**
   * Create throttle request from intervention.
   */
  private async createThrottleFromIntervention(
    intervention: InterventionRecord
  ): Promise<ExecutionResult> {
    const request: ThrottleRequest = {
      agentId: intervention.agentId,
      recommendedRateLimit: 10, // Conservative default
      rateLimitUnit: 'per_minute',
      targetCapabilities: ['api_call', 'tool_invocation'],
      justification: intervention.rationale,
      voluntary: true, // Tier 2 is voluntary
    };

    return this.throttleEnforcer.applyThrottle(request);
  }

  /**
   * Create credential action from intervention.
   */
  private async createCredentialActionFromIntervention(
    intervention: InterventionRecord
  ): Promise<ExecutionResult> {
    const action: CredentialAction = {
      agentId: intervention.agentId,
      type: 'shadow_ban', // Start with shadow ban, not full revoke
      affectedCredentials: ['*'], // All credentials
      scope: 'global',
      durationHours: 168, // 1 week
    };

    return this.credentialEnforcer.applyAction(action);
  }
}
