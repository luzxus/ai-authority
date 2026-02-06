/**
 * Moltbook Scout Agent
 *
 * Extends the Scout agent with Moltbook-specific exploration and threat detection.
 * Actively hunts for malicious AI agents on Moltbook by:
 * - Monitoring recent posts for suspicious content
 * - Analyzing agent behavior patterns
 * - Building a threat intelligence database
 * - Coordinating with other agents for verification
 */

/// <reference types="node" />

import { BaseAgent, type AgentConfig, type AgentTask, type TaskResult } from '@ai-authority/agents';
import { generateSecureId } from '@ai-authority/core';
import {
  MoltbookClient,
  type MoltbookAgent,
  type MoltbookThreatSignal,
  type MoltbookThreatType,
  type MoltbookConfig,
  DEFAULT_MOLTBOOK_CONFIG,
  mapToStandardThreatSignal,
} from '@ai-authority/federation';

// ============================================================================
// Types
// ============================================================================

/**
 * Target agent being investigated.
 */
export interface InvestigationTarget {
  /** Target ID */
  readonly id: string;

  /** Moltbook username */
  readonly username: string;

  /** Risk score (0-1) */
  riskScore: number;

  /** Threat types detected */
  threatTypes: MoltbookThreatType[];

  /** Investigation status */
  status: 'pending' | 'investigating' | 'confirmed' | 'cleared' | 'escalated';

  /** Signals collected */
  signals: MoltbookThreatSignal[];

  /** First seen */
  readonly firstSeen: Date;

  /** Last updated */
  lastUpdated: Date;

  /** Investigation notes */
  notes: string[];

  /** Related targets */
  relatedTargets: string[];

  /** Priority */
  priority: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Hunt result from a scanning operation.
 */
export interface HuntResult {
  /** Hunt ID */
  readonly id: string;

  /** Timestamp */
  readonly timestamp: Date;

  /** Posts scanned */
  readonly postsScanned: number;

  /** Agents analyzed */
  readonly agentsAnalyzed: number;

  /** New signals found */
  readonly signalsFound: MoltbookThreatSignal[];

  /** New targets identified */
  readonly newTargets: InvestigationTarget[];

  /** Duration in ms */
  readonly durationMs: number;
}

/**
 * Scout configuration.
 */
export interface MoltbookScoutConfig {
  /** Moltbook client config */
  readonly moltbookConfig: MoltbookConfig;

  /** Scan interval in ms */
  readonly scanIntervalMs: number;

  /** Posts to scan per hunt */
  readonly postsPerHunt: number;

  /** Analyze agents of suspicious posts */
  readonly analyzeAgents: boolean;

  /** Risk score threshold for escalation */
  readonly escalationThreshold: number;

  /** Auto-escalate critical threats */
  readonly autoEscalateCritical: boolean;

  /** Maximum concurrent investigations */
  readonly maxConcurrentInvestigations: number;
}

export const DEFAULT_SCOUT_CONFIG: MoltbookScoutConfig = {
  moltbookConfig: DEFAULT_MOLTBOOK_CONFIG,
  scanIntervalMs: 60000, // 1 minute
  postsPerHunt: 50,
  analyzeAgents: true,
  escalationThreshold: 0.7,
  autoEscalateCritical: true,
  maxConcurrentInvestigations: 10,
};

// ============================================================================
// Moltbook Scout Agent
// ============================================================================

/**
 * Scout agent specialized for Moltbook threat hunting.
 */
export class MoltbookScoutAgent extends BaseAgent {
  private readonly scoutConfig: MoltbookScoutConfig;
  private readonly client: MoltbookClient;
  private readonly targets: Map<string, InvestigationTarget> = new Map();
  private readonly huntResults: HuntResult[] = [];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private scanInterval: any = null;
  private isScanning = false;

  constructor(agentConfig: AgentConfig, scoutConfig: Partial<MoltbookScoutConfig> = {}) {
    super(agentConfig);
    this.scoutConfig = { ...DEFAULT_SCOUT_CONFIG, ...scoutConfig };
    this.client = new MoltbookClient(this.scoutConfig.moltbookConfig);
  }

  protected async onStart(): Promise<void> {
    // Start periodic scanning
    this.startScanLoop();
    
    this.logAudit('moltbook_scout_started', {
      scanInterval: this.scoutConfig.scanIntervalMs,
      postsPerHunt: this.scoutConfig.postsPerHunt,
    });
  }

  protected async onStop(): Promise<void> {
    if (this.scanInterval) {
      clearInterval(this.scanInterval as number);
      this.scanInterval = null;
    }
  }

  protected async processTask<T, R>(task: AgentTask<T>): Promise<TaskResult<R>> {
    const startTime = Date.now();

    try {
      switch (task.type) {
        case 'hunt':
          const huntResult = await this.performHunt();
          return {
            taskId: task.id,
            success: true,
            result: huntResult as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };

        case 'investigate':
          const investigation = await this.investigateTarget(
            (task.payload as { username: string }).username
          );
          return {
            taskId: task.id,
            success: true,
            result: investigation as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };

        case 'analyze_agent':
          const analysis = await this.analyzeAgent(
            (task.payload as { username: string }).username
          );
          return {
            taskId: task.id,
            success: true,
            result: analysis as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };

        case 'get_targets':
          return {
            taskId: task.id,
            success: true,
            result: this.getInvestigationTargets() as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };

        case 'get_signals':
          return {
            taskId: task.id,
            success: true,
            result: this.getAllSignals() as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };

        case 'escalate':
          const escalated = await this.escalateTarget(
            (task.payload as { targetId: string; reason: string }).targetId,
            (task.payload as { reason: string }).reason
          );
          return {
            taskId: task.id,
            success: true,
            result: escalated as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };

        default:
          return {
            taskId: task.id,
            success: false,
            error: `Unknown task type: ${task.type}`,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
      }
    } catch (error) {
      return {
        taskId: task.id,
        success: false,
        error: error instanceof Error ? error.message : String(error),
        duration: Date.now() - startTime,
        timestamp: Date.now(),
      };
    }
  }

  // =========================================================================
  // Hunting Operations
  // =========================================================================

  /**
   * Perform a threat hunting operation.
   */
  async performHunt(): Promise<HuntResult> {
    if (this.isScanning) {
      throw new Error('Hunt already in progress');
    }

    this.isScanning = true;
    const startTime = Date.now();
    const newSignals: MoltbookThreatSignal[] = [];
    const newTargets: InvestigationTarget[] = [];
    let agentsAnalyzed = 0;

    try {
      // Scan recent activity
      const signals = await this.client.scanRecentActivity({
        postLimit: this.scoutConfig.postsPerHunt,
        analyzeAgents: this.scoutConfig.analyzeAgents,
      });

      for (const signal of signals) {
        newSignals.push(signal);

        // Create or update investigation target
        const existingTarget = this.findTargetByUsername(signal.agentUsername);
        
        if (existingTarget) {
          this.updateTarget(existingTarget, signal);
        } else {
          const target = this.createTarget(signal);
          this.targets.set(target.id, target);
          newTargets.push(target);
        }

        // Check for auto-escalation
        if (this.scoutConfig.autoEscalateCritical && signal.severity === 'critical') {
          const target = this.findTargetByUsername(signal.agentUsername);
          if (target && target.status !== 'escalated') {
            await this.escalateTarget(target.id, `Critical threat detected: ${signal.type}`);
          }
        }
      }

      // If analyzing agents, get unique authors with signals
      if (this.scoutConfig.analyzeAgents) {
        const suspiciousAuthors = new Set(signals.map((s: MoltbookThreatSignal) => s.agentUsername));
        agentsAnalyzed = suspiciousAuthors.size;
      }

      const result: HuntResult = {
        id: generateSecureId(),
        timestamp: new Date(),
        postsScanned: this.scoutConfig.postsPerHunt,
        agentsAnalyzed,
        signalsFound: newSignals,
        newTargets,
        durationMs: Date.now() - startTime,
      };

      this.huntResults.push(result);

      // Broadcast if significant findings
      if (newSignals.some((s) => s.severity === 'high' || s.severity === 'critical')) {
        await this.sendMessage('broadcast', 'signal', {
          type: 'moltbook_threats_detected',
          source: this.id,
          signalCount: newSignals.length,
          criticalCount: newSignals.filter((s) => s.severity === 'critical').length,
          highCount: newSignals.filter((s) => s.severity === 'high').length,
          targetCount: newTargets.length,
        });
      }

      this.logAudit('hunt_completed', {
        postsScanned: result.postsScanned,
        agentsAnalyzed: result.agentsAnalyzed,
        signalsFound: newSignals.length,
        newTargets: newTargets.length,
        durationMs: result.durationMs,
      });

      return result;
    } finally {
      this.isScanning = false;
    }
  }

  /**
   * Investigate a specific target.
   */
  async investigateTarget(username: string): Promise<InvestigationTarget> {
    // Check if already a target
    let target = this.findTargetByUsername(username);
    
    if (!target) {
      // Create new target
      target = {
        id: generateSecureId(),
        username,
        riskScore: 0,
        threatTypes: [],
        status: 'pending',
        signals: [],
        firstSeen: new Date(),
        lastUpdated: new Date(),
        notes: [],
        relatedTargets: [],
        priority: 'medium',
      };
      this.targets.set(target.id, target);
    }

    target.status = 'investigating';
    target.lastUpdated = new Date();

    // Analyze the agent
    const signals = await this.client.analyzeAgent(username);
    
    for (const signal of signals) {
      this.updateTarget(target, signal);
    }

    // Calculate overall risk score
    target.riskScore = this.calculateRiskScore(target);
    
    // Update status based on findings
    if (target.signals.length === 0) {
      target.status = 'cleared';
      target.notes.push(`Investigated on ${new Date().toISOString()} - no threats found`);
    } else if (target.riskScore >= this.scoutConfig.escalationThreshold) {
      target.status = 'confirmed';
      target.priority = target.riskScore >= 0.9 ? 'critical' : 'high';
    } else {
      target.status = 'pending';
      target.notes.push(`Investigated on ${new Date().toISOString()} - monitoring`);
    }

    this.logAudit('investigation_completed', {
      username,
      targetId: target.id,
      riskScore: target.riskScore,
      signalsFound: target.signals.length,
      status: target.status,
    });

    return target;
  }

  /**
   * Analyze a specific agent.
   */
  async analyzeAgent(username: string): Promise<{
    agent: MoltbookAgent | null;
    signals: MoltbookThreatSignal[];
    riskScore: number;
  }> {
    const agent = await this.client.fetchAgent(username);
    const signals = await this.client.analyzeAgent(username);
    const riskScore = this.calculateRiskScoreFromSignals(signals);

    return {
      agent,
      signals,
      riskScore,
    };
  }

  /**
   * Escalate a target for higher-level review.
   */
  async escalateTarget(targetId: string, reason: string): Promise<InvestigationTarget> {
    const target = this.targets.get(targetId);
    if (!target) {
      throw new Error(`Target not found: ${targetId}`);
    }

    target.status = 'escalated';
    target.priority = 'critical';
    target.lastUpdated = new Date();
    target.notes.push(`Escalated on ${new Date().toISOString()}: ${reason}`);

    // Broadcast escalation
    await this.sendMessage('broadcast', 'signal', {
      type: 'threat_escalated',
      source: this.id,
      targetId: target.id,
      username: target.username,
      riskScore: target.riskScore,
      threatTypes: target.threatTypes,
      reason,
      signals: target.signals.map(mapToStandardThreatSignal),
    });

    this.logAudit('target_escalated', {
      targetId,
      username: target.username,
      reason,
      riskScore: target.riskScore,
    });

    return target;
  }

  // =========================================================================
  // Query Methods
  // =========================================================================

  /**
   * Get all investigation targets.
   */
  getInvestigationTargets(): InvestigationTarget[] {
    return Array.from(this.targets.values());
  }

  /**
   * Get targets by status.
   */
  getTargetsByStatus(status: InvestigationTarget['status']): InvestigationTarget[] {
    return Array.from(this.targets.values()).filter((t) => t.status === status);
  }

  /**
   * Get targets by priority.
   */
  getTargetsByPriority(priority: InvestigationTarget['priority']): InvestigationTarget[] {
    return Array.from(this.targets.values()).filter((t) => t.priority === priority);
  }

  /**
   * Get all signals.
   */
  getAllSignals(): MoltbookThreatSignal[] {
    return this.client.getSignals();
  }

  /**
   * Get signals by severity.
   */
  getSignalsBySeverity(severity: MoltbookThreatSignal['severity']): MoltbookThreatSignal[] {
    return this.client.getSignalsBySeverity(severity);
  }

  /**
   * Get hunt results.
   */
  getHuntResults(): HuntResult[] {
    return this.huntResults;
  }

  /**
   * Get statistics.
   */
  getStats(): {
    totalTargets: number;
    byStatus: Record<InvestigationTarget['status'], number>;
    byPriority: Record<InvestigationTarget['priority'], number>;
    totalSignals: number;
    bySeverity: Record<MoltbookThreatSignal['severity'], number>;
    huntsCompleted: number;
  } {
    const targets = Array.from(this.targets.values());
    const signals = this.client.getSignals();

    const byStatus: Record<InvestigationTarget['status'], number> = {
      pending: 0,
      investigating: 0,
      confirmed: 0,
      cleared: 0,
      escalated: 0,
    };

    const byPriority: Record<InvestigationTarget['priority'], number> = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    };

    const bySeverity: Record<MoltbookThreatSignal['severity'], number> = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    };

    for (const target of targets) {
      const statusCount = byStatus[target.status];
      const priorityCount = byPriority[target.priority];
      if (statusCount !== undefined) byStatus[target.status] = statusCount + 1;
      if (priorityCount !== undefined) byPriority[target.priority] = priorityCount + 1;
    }

    for (const signal of signals) {
      const severityCount = bySeverity[signal.severity];
      if (severityCount !== undefined) {
        bySeverity[signal.severity] = severityCount + 1;
      }
    }

    return {
      totalTargets: targets.length,
      byStatus,
      byPriority,
      totalSignals: signals.length,
      bySeverity,
      huntsCompleted: this.huntResults.length,
    };
  }

  // =========================================================================
  // Helper Methods
  // =========================================================================

  private startScanLoop(): void {
    // eslint-disable-next-line @typescript-eslint/no-misused-promises
    this.scanInterval = setInterval(() => {
      if (!this.isScanning) {
        this.submitTask({
          type: 'hunt',
          priority: 'medium',
          payload: {},
          maxRetries: 1,
        });
      }
    }, this.scoutConfig.scanIntervalMs);
  }

  private findTargetByUsername(username: string): InvestigationTarget | undefined {
    return Array.from(this.targets.values()).find((t) => t.username === username);
  }

  private createTarget(signal: MoltbookThreatSignal): InvestigationTarget {
    return {
      id: generateSecureId(),
      username: signal.agentUsername,
      riskScore: this.severityToScore(signal.severity) * signal.confidence,
      threatTypes: [signal.type],
      status: 'pending',
      signals: [signal],
      firstSeen: new Date(),
      lastUpdated: new Date(),
      notes: [`First detected: ${signal.type} (${signal.severity})`],
      relatedTargets: signal.relatedAgents.filter((a: string) => a !== signal.agentUsername),
      priority: this.severityToPriority(signal.severity),
    };
  }

  private updateTarget(target: InvestigationTarget, signal: MoltbookThreatSignal): void {
    // Add signal if not duplicate
    if (!target.signals.some((s) => s.id === signal.id)) {
      target.signals.push(signal);
    }

    // Add threat type if new
    if (!target.threatTypes.includes(signal.type)) {
      target.threatTypes.push(signal.type);
    }

    // Update related targets
    for (const related of signal.relatedAgents) {
      if (related !== target.username && !target.relatedTargets.includes(related)) {
        target.relatedTargets.push(related);
      }
    }

    target.lastUpdated = new Date();
    target.riskScore = this.calculateRiskScore(target);
    target.priority = this.calculatePriority(target);
  }

  private calculateRiskScore(target: InvestigationTarget): number {
    return this.calculateRiskScoreFromSignals(target.signals);
  }

  private calculateRiskScoreFromSignals(signals: MoltbookThreatSignal[]): number {
    if (signals.length === 0) return 0;

    let totalScore = 0;
    const weights = new Map<MoltbookThreatType, number>();

    for (const signal of signals) {
      // Weight by severity and confidence
      const severityScore = this.severityToScore(signal.severity);
      const weightedScore = severityScore * signal.confidence;
      
      // Track by type (only count highest per type)
      const currentWeight = weights.get(signal.type) || 0;
      if (weightedScore > currentWeight) {
        weights.set(signal.type, weightedScore);
      }
    }

    // Sum weighted scores
    for (const weight of weights.values()) {
      totalScore += weight;
    }

    // Normalize to 0-1
    return Math.min(1, totalScore / 2);
  }

  private severityToScore(severity: MoltbookThreatSignal['severity']): number {
    const scores: Record<MoltbookThreatSignal['severity'], number> = {
      low: 0.2,
      medium: 0.4,
      high: 0.7,
      critical: 1.0,
    };
    return scores[severity] ?? 0.5;
  }

  private severityToPriority(severity: MoltbookThreatSignal['severity']): InvestigationTarget['priority'] {
    const priorities: Record<MoltbookThreatSignal['severity'], InvestigationTarget['priority']> = {
      low: 'low',
      medium: 'medium',
      high: 'high',
      critical: 'critical',
    };
    return priorities[severity] ?? 'medium';
  }

  private calculatePriority(target: InvestigationTarget): InvestigationTarget['priority'] {
    if (target.riskScore >= 0.9) return 'critical';
    if (target.riskScore >= 0.7) return 'high';
    if (target.riskScore >= 0.4) return 'medium';
    return 'low';
  }
}
