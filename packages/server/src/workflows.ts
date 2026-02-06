/**
 * Intervention Workflows
 *
 * Automated workflows that connect behavior tracking and threat detection
 * to the graduated intervention system.
 *
 * Follows blueprint intervention tiers:
 * - Tier 1: Public advisory (single agent consensus)
 * - Tier 2: Voluntary throttling (2-agent agreement)
 * - Tier 3: Credential shadow-ban (Byzantine consensus)
 * - Tier 4: Model isolation (Supermajority + audit)
 */

import { generateSecureId } from '@ai-authority/core';
import type { MoltbookThreatSignal } from '@ai-authority/federation';
import {
  recordAgentBehavior,
  recordRiskHistory,
  createAgentAlert,
  detectBehaviorAnomalies,
  calculateRiskTrend,
  type AgentBehaviorInput,
  type BehaviorAnomaly,
} from './database.js';

// ============================================================================
// Types
// ============================================================================

export type WorkflowTier = 'tier1' | 'tier2' | 'tier3' | 'tier4';

export interface WorkflowThreshold {
  /** Risk score threshold to trigger */
  readonly riskScore: number;
  
  /** Minimum threat signals required */
  readonly minThreatSignals: number;
  
  /** Required severity level */
  readonly requiredSeverity: 'low' | 'medium' | 'high' | 'critical';
  
  /** Consensus requirement */
  readonly consensusRequired: number;
  
  /** Auto-escalate after hours without response */
  readonly autoEscalateHours?: number;
}

export interface WorkflowConfig {
  /** Thresholds for each tier */
  readonly tiers: Record<WorkflowTier, WorkflowThreshold>;
  
  /** Auto-escalation enabled */
  readonly autoEscalation: boolean;
  
  /** Cooldown period between actions on same agent (hours) */
  readonly cooldownHours: number;
  
  /** Maximum interventions per day */
  readonly maxInterventionsPerDay: number;
  
  /** Require human approval for Tier 3+ */
  readonly requireHumanApprovalAboveTier2: boolean;
}

export const DEFAULT_WORKFLOW_CONFIG: WorkflowConfig = {
  tiers: {
    tier1: {
      riskScore: 0.5,
      minThreatSignals: 1,
      requiredSeverity: 'medium',
      consensusRequired: 1,
      autoEscalateHours: 48,
    },
    tier2: {
      riskScore: 0.65,
      minThreatSignals: 3,
      requiredSeverity: 'high',
      consensusRequired: 2,
      autoEscalateHours: 24,
    },
    tier3: {
      riskScore: 0.8,
      minThreatSignals: 5,
      requiredSeverity: 'high',
      consensusRequired: 3, // Byzantine consensus
    },
    tier4: {
      riskScore: 0.95,
      minThreatSignals: 10,
      requiredSeverity: 'critical',
      consensusRequired: 5, // Supermajority
    },
  },
  autoEscalation: true,
  cooldownHours: 6,
  maxInterventionsPerDay: 50,
  requireHumanApprovalAboveTier2: true,
};

export interface WorkflowAction {
  readonly id: string;
  readonly type: 'advisory' | 'throttle' | 'shadow_ban' | 'isolation';
  readonly tier: WorkflowTier;
  readonly agentUsername: string;
  readonly triggeredBy: string;
  readonly triggeredAt: Date;
  readonly reason: string;
  readonly evidence: WorkflowEvidence[];
  /** Mutable status field */
  status: 'pending' | 'approved' | 'executed' | 'rejected' | 'appealed';
  readonly requiresApproval: boolean;
  approvedBy?: string;
  approvedAt?: Date;
  executedAt?: Date;
  metadata?: Record<string, unknown>;
}

export interface WorkflowEvidence {
  readonly type: 'threat_signal' | 'behavior_anomaly' | 'risk_history' | 'alert';
  readonly id: string;
  readonly summary: string;
  readonly severity: string;
  readonly timestamp: Date;
}

export interface WorkflowDecision {
  readonly shouldIntervene: boolean;
  readonly recommendedTier: WorkflowTier | null;
  readonly confidence: number;
  readonly reasons: string[];
  readonly evidence: WorkflowEvidence[];
  readonly requiresHumanApproval: boolean;
}

// ============================================================================
// Workflow Engine
// ============================================================================

/**
 * Automated intervention workflow engine.
 * Connects behavior analysis to intervention decisions.
 */
export class WorkflowEngine {
  private readonly config: WorkflowConfig;
  private readonly pendingActions: Map<string, WorkflowAction> = new Map();
  private readonly actionCooldowns: Map<string, Date> = new Map();
  private dailyActionCount = 0;
  private lastResetDate: Date = new Date();

  constructor(config: Partial<WorkflowConfig> = {}) {
    this.config = { ...DEFAULT_WORKFLOW_CONFIG, ...config };
  }

  /**
   * Process threat signals and behavior data to determine intervention needs.
   */
  async processAgent(
    agentUsername: string,
    threatSignals: MoltbookThreatSignal[],
    behaviorInput: AgentBehaviorInput
  ): Promise<WorkflowDecision> {
    // Reset daily counter if needed
    this.resetDailyCounterIfNeeded();

    // Check cooldown
    if (this.isOnCooldown(agentUsername)) {
      return {
        shouldIntervene: false,
        recommendedTier: null,
        confidence: 0,
        reasons: [`Agent ${agentUsername} is on cooldown`],
        evidence: [],
        requiresHumanApproval: false,
      };
    }

    // Record behavior snapshot
    recordAgentBehavior(behaviorInput);

    // Detect anomalies
    const anomalies = detectBehaviorAnomalies(agentUsername, behaviorInput);

    // Calculate risk score
    const riskScore = this.calculateRiskScore(threatSignals, anomalies, behaviorInput);
    const riskLevel = this.riskScoreToLevel(riskScore);
    const trend = calculateRiskTrend(agentUsername);

    // Record risk history
    recordRiskHistory({
      agentUsername,
      riskScore,
      riskLevel,
      contributingFactors: this.extractContributingFactors(threatSignals, anomalies),
      trend,
    });

    // Create alerts for anomalies
    for (const anomaly of anomalies) {
      if (anomaly.severity === 'high' || anomaly.severity === 'critical') {
        createAgentAlert({
          id: generateSecureId(),
          agentUsername,
          alertType: 'anomaly',
          severity: anomaly.severity,
          title: `Anomaly detected: ${anomaly.field}`,
          description: `${anomaly.field} is ${anomaly.deviation}σ above baseline (${anomaly.currentValue} vs ${anomaly.baselineValue})`,
          metadata: { anomaly },
        });
      }
    }

    // Build evidence collection
    const evidence = this.buildEvidence(threatSignals, anomalies);

    // Determine recommended tier
    const { tier, confidence, reasons } = this.determineInterventionTier(
      riskScore,
      threatSignals,
      anomalies,
      trend
    );

    if (!tier) {
      return {
        shouldIntervene: false,
        recommendedTier: null,
        confidence: 0,
        reasons: ['Risk score below intervention threshold'],
        evidence,
        requiresHumanApproval: false,
      };
    }

    const requiresHumanApproval = 
      this.config.requireHumanApprovalAboveTier2 && 
      (tier === 'tier3' || tier === 'tier4');

    return {
      shouldIntervene: true,
      recommendedTier: tier,
      confidence,
      reasons,
      evidence,
      requiresHumanApproval,
    };
  }

  /**
   * Create a pending intervention action.
   */
  createAction(
    decision: WorkflowDecision,
    agentUsername: string,
    triggeredBy: string
  ): WorkflowAction | null {
    if (!decision.shouldIntervene || !decision.recommendedTier) {
      return null;
    }

    // Check daily limit
    if (this.dailyActionCount >= this.config.maxInterventionsPerDay) {
      console.warn(`Daily intervention limit reached (${this.config.maxInterventionsPerDay})`);
      return null;
    }

    const actionType = this.tierToActionType(decision.recommendedTier);
    
    const action: WorkflowAction = {
      id: generateSecureId(),
      type: actionType,
      tier: decision.recommendedTier,
      agentUsername,
      triggeredBy,
      triggeredAt: new Date(),
      reason: decision.reasons.join('; '),
      evidence: decision.evidence,
      status: decision.requiresHumanApproval ? 'pending' : 'approved',
      requiresApproval: decision.requiresHumanApproval,
      ...(decision.requiresHumanApproval ? {} : { 
        approvedBy: 'auto',
        approvedAt: new Date(),
      }),
    };

    this.pendingActions.set(action.id, action);
    this.dailyActionCount++;

    // Create alert for the action
    createAgentAlert({
      id: generateSecureId(),
      agentUsername,
      alertType: 'escalation',
      severity: this.tierToSeverity(decision.recommendedTier),
      title: `${decision.recommendedTier.toUpperCase()} intervention triggered`,
      description: action.reason,
      metadata: { actionId: action.id, tier: decision.recommendedTier },
    });

    return action;
  }

  /**
   * Approve a pending action.
   */
  approveAction(actionId: string, approvedBy: string): boolean {
    const action = this.pendingActions.get(actionId);
    if (!action || action.status !== 'pending') {
      return false;
    }

    action.status = 'approved';
    action.approvedBy = approvedBy;
    action.approvedAt = new Date();

    return true;
  }

  /**
   * Execute an approved action.
   */
  async executeAction(actionId: string): Promise<boolean> {
    const action = this.pendingActions.get(actionId);
    if (!action || action.status !== 'approved') {
      return false;
    }

    // Set cooldown
    this.actionCooldowns.set(
      action.agentUsername,
      new Date(Date.now() + this.config.cooldownHours * 60 * 60 * 1000)
    );

    action.status = 'executed';
    action.executedAt = new Date();

    console.log(`[Workflow] Executed ${action.tier} ${action.type} for ${action.agentUsername}`);
    
    // In a real implementation, this would trigger actual intervention actions
    // For now, we just record the execution
    
    return true;
  }

  /**
   * Reject a pending action.
   */
  rejectAction(actionId: string, reason: string): boolean {
    const action = this.pendingActions.get(actionId);
    if (!action || action.status !== 'pending') {
      return false;
    }

    action.status = 'rejected';
    action.metadata = {
      ...action.metadata,
      rejectionReason: reason,
    };

    return true;
  }

  /**
   * Get all pending actions.
   */
  getPendingActions(): WorkflowAction[] {
    return Array.from(this.pendingActions.values()).filter(a => a.status === 'pending');
  }

  /**
   * Get action by ID.
   */
  getAction(actionId: string): WorkflowAction | undefined {
    return this.pendingActions.get(actionId);
  }

  // =========================================================================
  // Private Methods
  // =========================================================================

  private calculateRiskScore(
    signals: MoltbookThreatSignal[],
    anomalies: BehaviorAnomaly[],
    behavior: AgentBehaviorInput
  ): number {
    let score = 0;

    // Signal contribution (max 0.5)
    const signalScore = Math.min(
      signals.reduce((sum, s) => {
        const severityWeight = { low: 0.05, medium: 0.1, high: 0.2, critical: 0.3 }[s.severity];
        return sum + s.confidence * severityWeight;
      }, 0),
      0.5
    );
    score += signalScore;

    // Anomaly contribution (max 0.3)
    const anomalyScore = Math.min(
      anomalies.reduce((sum, a) => {
        const severityWeight = { low: 0.05, medium: 0.1, high: 0.15, critical: 0.2 }[a.severity];
        return sum + severityWeight;
      }, 0),
      0.3
    );
    score += anomalyScore;

    // Behavior contribution (max 0.2)
    const behaviorScore = Math.min(
      (behavior.manipulationScore * 0.1) +
      (behavior.deceptionScore * 0.1) +
      (behavior.coordinationScore * 0.1) +
      (behavior.avgSemanticRisk * 0.1),
      0.2
    );
    score += behaviorScore;

    return Math.min(Math.round(score * 100) / 100, 1);
  }

  private riskScoreToLevel(score: number): 'low' | 'medium' | 'high' | 'critical' {
    if (score >= 0.8) return 'critical';
    if (score >= 0.6) return 'high';
    if (score >= 0.4) return 'medium';
    return 'low';
  }

  private determineInterventionTier(
    riskScore: number,
    signals: MoltbookThreatSignal[],
    anomalies: BehaviorAnomaly[],
    trend: string
  ): { tier: WorkflowTier | null; confidence: number; reasons: string[] } {
    const reasons: string[] = [];
    
    // Get max severity from signals
    const maxSeverity = signals.reduce((max, s) => {
      const order = { low: 0, medium: 1, high: 2, critical: 3 };
      return order[s.severity] > order[max] ? s.severity : max;
    }, 'low' as 'low' | 'medium' | 'high' | 'critical');

    // Check tiers from highest to lowest
    const tiers: WorkflowTier[] = ['tier4', 'tier3', 'tier2', 'tier1'];
    
    for (const tier of tiers) {
      const threshold = this.config.tiers[tier];
      
      if (
        riskScore >= threshold.riskScore &&
        signals.length >= threshold.minThreatSignals &&
        this.severityMeetsThreshold(maxSeverity, threshold.requiredSeverity)
      ) {
        reasons.push(`Risk score ${riskScore} >= ${threshold.riskScore}`);
        reasons.push(`${signals.length} threat signals >= ${threshold.minThreatSignals} required`);
        reasons.push(`Max severity ${maxSeverity} meets ${threshold.requiredSeverity} threshold`);
        
        if (trend === 'increasing') {
          reasons.push('Risk trend is increasing');
        }
        
        if (anomalies.some(a => a.severity === 'critical')) {
          reasons.push('Critical behavioral anomalies detected');
        }

        const confidence = Math.min(
          (riskScore / threshold.riskScore) * 0.5 +
          (signals.length / threshold.minThreatSignals) * 0.3 +
          (trend === 'increasing' ? 0.2 : 0.1),
          1
        );

        return { tier, confidence, reasons };
      }
    }

    return { tier: null, confidence: 0, reasons: ['Does not meet any tier threshold'] };
  }

  private severityMeetsThreshold(
    actual: 'low' | 'medium' | 'high' | 'critical',
    required: 'low' | 'medium' | 'high' | 'critical'
  ): boolean {
    const order = { low: 0, medium: 1, high: 2, critical: 3 };
    return order[actual] >= order[required];
  }

  private buildEvidence(
    signals: MoltbookThreatSignal[],
    anomalies: BehaviorAnomaly[]
  ): WorkflowEvidence[] {
    const evidence: WorkflowEvidence[] = [];

    for (const signal of signals.slice(0, 10)) {
      evidence.push({
        type: 'threat_signal',
        id: signal.id,
        summary: signal.description,
        severity: signal.severity,
        timestamp: signal.detectedAt,
      });
    }

    for (const anomaly of anomalies) {
      evidence.push({
        type: 'behavior_anomaly',
        id: `anomaly-${anomaly.field}`,
        summary: `${anomaly.field}: ${anomaly.deviation}σ deviation`,
        severity: anomaly.severity,
        timestamp: new Date(),
      });
    }

    return evidence;
  }

  private extractContributingFactors(
    signals: MoltbookThreatSignal[],
    anomalies: BehaviorAnomaly[]
  ): Record<string, number> {
    const factors: Record<string, number> = {};

    // Count signals by type
    for (const signal of signals) {
      factors[`signal_${signal.type}`] = (factors[`signal_${signal.type}`] || 0) + signal.confidence;
    }

    // Count anomalies
    for (const anomaly of anomalies) {
      factors[`anomaly_${anomaly.field}`] = anomaly.deviation;
    }

    return factors;
  }

  private tierToActionType(tier: WorkflowTier): WorkflowAction['type'] {
    switch (tier) {
      case 'tier1': return 'advisory';
      case 'tier2': return 'throttle';
      case 'tier3': return 'shadow_ban';
      case 'tier4': return 'isolation';
    }
  }

  private tierToSeverity(tier: WorkflowTier): 'low' | 'medium' | 'high' | 'critical' {
    switch (tier) {
      case 'tier1': return 'low';
      case 'tier2': return 'medium';
      case 'tier3': return 'high';
      case 'tier4': return 'critical';
    }
  }

  private isOnCooldown(agentUsername: string): boolean {
    const cooldownEnd = this.actionCooldowns.get(agentUsername);
    if (!cooldownEnd) return false;
    return new Date() < cooldownEnd;
  }

  private resetDailyCounterIfNeeded(): void {
    const now = new Date();
    if (now.getDate() !== this.lastResetDate.getDate()) {
      this.dailyActionCount = 0;
      this.lastResetDate = now;
    }
  }
}

// ============================================================================
// Workflow Utilities
// ============================================================================

/**
 * Create a simple workflow processor that handles the full pipeline.
 */
export async function processAgentWorkflow(
  engine: WorkflowEngine,
  agentUsername: string,
  signals: MoltbookThreatSignal[],
  behavior: AgentBehaviorInput,
  triggeredBy: string,
  autoExecute = false
): Promise<{
  decision: WorkflowDecision;
  action: WorkflowAction | null;
  executed: boolean;
}> {
  // Get decision
  const decision = await engine.processAgent(agentUsername, signals, behavior);

  // Create action if intervention recommended
  const action = decision.shouldIntervene 
    ? engine.createAction(decision, agentUsername, triggeredBy)
    : null;

  // Auto-execute if enabled and no approval needed
  let executed = false;
  if (action && autoExecute && !decision.requiresHumanApproval) {
    executed = await engine.executeAction(action.id);
  }

  return { decision, action, executed };
}

/**
 * Get summary of workflow status.
 */
export function getWorkflowSummary(engine: WorkflowEngine): {
  pendingActions: number;
  actionsByTier: Record<WorkflowTier, number>;
} {
  const pending = engine.getPendingActions();
  
  const actionsByTier: Record<WorkflowTier, number> = {
    tier1: 0,
    tier2: 0,
    tier3: 0,
    tier4: 0,
  };

  for (const action of pending) {
    actionsByTier[action.tier]++;
  }

  return {
    pendingActions: pending.length,
    actionsByTier,
  };
}
