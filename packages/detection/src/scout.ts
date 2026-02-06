/**
 * Scout Agent
 * 
 * Explores networks and discovers anomalies using curiosity-driven reinforcement learning.
 */

import { BaseAgent, type AgentConfig, type AgentTask, type TaskResult } from '@ai-authority/agents';
import { generateSecureId } from '@ai-authority/core';

/** Discovery target */
export interface DiscoveryTarget {
  id: string;
  type: 'endpoint' | 'api' | 'node' | 'agent';
  address: string;
  metadata: Record<string, unknown>;
  uncertainty: number;  // Higher = more interesting to explore
  lastProbed: number;
}

/** Discovery result */
export interface DiscoveryResult {
  targetId: string;
  timestamp: number;
  findings: Finding[];
  newTargets: DiscoveryTarget[];
  anomalyScore: number;
}

/** Finding from exploration */
export interface Finding {
  type: 'anomaly' | 'pattern' | 'signal';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  evidence: unknown;
  confidence: number;
}

/** Exploration strategy */
export type ExplorationStrategy = 'random' | 'uncertainty' | 'reward' | 'breadth_first';

/**
 * Scout Agent
 * 
 * Autonomously explores the network to discover potential threats.
 * Uses curiosity-driven learning to prioritize high-uncertainty areas.
 */
export class ScoutAgent extends BaseAgent {
  private targets: Map<string, DiscoveryTarget> = new Map();
  private discoveries: DiscoveryResult[] = [];
  private explorationRewards: Map<string, number> = new Map();
  private strategy: ExplorationStrategy = 'uncertainty';
  private explorationIntervalMs = 10000;

  constructor(config: AgentConfig) {
    super(config);
  }

  protected async onStart(): Promise<void> {
    // Start exploration loop
    this.startExplorationLoop();
  }

  protected async processTask<T, R>(task: AgentTask<T>): Promise<TaskResult<R>> {
    const startTime = Date.now();

    try {
      switch (task.type) {
        case 'explore':
          const result = await this.explore(task.payload as { targetId?: string });
          return {
            taskId: task.id,
            success: true,
            result: result as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };

        case 'add_target':
          const target = this.addTarget(task.payload as Omit<DiscoveryTarget, 'id'>);
          return {
            taskId: task.id,
            success: true,
            result: target as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };

        case 'set_strategy':
          this.strategy = (task.payload as { strategy: ExplorationStrategy }).strategy;
          return {
            taskId: task.id,
            success: true,
            result: { strategy: this.strategy } as R,
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
        error: String(error),
        duration: Date.now() - startTime,
        timestamp: Date.now(),
      };
    }
  }

  /** Add a target for exploration */
  addTarget(target: Omit<DiscoveryTarget, 'id'>): DiscoveryTarget {
    const fullTarget: DiscoveryTarget = {
      ...target,
      id: generateSecureId(),
    };
    this.targets.set(fullTarget.id, fullTarget);
    return fullTarget;
  }

  /** Explore a target or select one based on strategy */
  private async explore(params: { targetId?: string }): Promise<DiscoveryResult> {
    const target = params.targetId
      ? this.targets.get(params.targetId)
      : this.selectTarget();

    if (!target) {
      throw new Error('No targets available for exploration');
    }

    // Perform exploration (simulated)
    const findings = await this.probeTarget(target);
    const newTargets = this.discoverNewTargets(target);
    const anomalyScore = this.calculateAnomalyScore(findings);

    // Update target state
    target.lastProbed = Date.now();
    target.uncertainty = Math.max(0.1, target.uncertainty - 0.1); // Reduce uncertainty after probing

    // Update reward based on findings
    const reward = findings.length * 0.1 + anomalyScore;
    this.explorationRewards.set(target.id, reward);

    const result: DiscoveryResult = {
      targetId: target.id,
      timestamp: Date.now(),
      findings,
      newTargets,
      anomalyScore,
    };

    this.discoveries.push(result);

    // Broadcast significant findings
    if (anomalyScore > 0.5) {
      await this.sendMessage('broadcast', 'signal', {
        type: 'anomaly_detected',
        source: this.id,
        target: target.id,
        score: anomalyScore,
        findings,
      });
    }

    // Add new targets
    for (const newTarget of newTargets) {
      this.targets.set(newTarget.id, newTarget);
    }

    this.logAudit('exploration_completed', {
      targetId: target.id,
      findingsCount: findings.length,
      anomalyScore,
      newTargetsCount: newTargets.length,
    });

    return result;
  }

  /** Select target based on strategy */
  private selectTarget(): DiscoveryTarget | undefined {
    const targets = Array.from(this.targets.values());
    if (targets.length === 0) return undefined;

    switch (this.strategy) {
      case 'random':
        return targets[Math.floor(Math.random() * targets.length)];

      case 'uncertainty':
        // Prioritize high uncertainty targets
        return targets.sort((a, b) => b.uncertainty - a.uncertainty)[0];

      case 'reward':
        // Prioritize targets with high past rewards
        return targets.sort((a, b) => {
          const rewardA = this.explorationRewards.get(a.id) ?? 0;
          const rewardB = this.explorationRewards.get(b.id) ?? 0;
          return rewardB - rewardA;
        })[0];

      case 'breadth_first':
        // Prioritize least recently probed
        return targets.sort((a, b) => a.lastProbed - b.lastProbed)[0];

      default:
        return targets[0];
    }
  }

  /** Probe a target for anomalies */
  private async probeTarget(target: DiscoveryTarget): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Simulated probing - in production would make actual network requests
    // and analyze responses for anomalies

    // Random chance of finding anomalies (for simulation)
    if (Math.random() > 0.7) {
      findings.push({
        type: 'anomaly',
        severity: Math.random() > 0.8 ? 'high' : 'medium',
        description: `Unusual pattern detected at ${target.address}`,
        evidence: { timestamp: Date.now(), target: target.id },
        confidence: 0.5 + Math.random() * 0.5,
      });
    }

    if (Math.random() > 0.8) {
      findings.push({
        type: 'signal',
        severity: 'low',
        description: `Elevated activity at ${target.address}`,
        evidence: { timestamp: Date.now(), target: target.id },
        confidence: 0.4 + Math.random() * 0.4,
      });
    }

    return findings;
  }

  /** Discover new targets from exploration */
  private discoverNewTargets(fromTarget: DiscoveryTarget): DiscoveryTarget[] {
    const newTargets: DiscoveryTarget[] = [];

    // Simulated discovery - in production would analyze network topology
    if (Math.random() > 0.6) {
      newTargets.push({
        id: generateSecureId(),
        type: 'endpoint',
        address: `discovered-from-${fromTarget.id}`,
        metadata: { discoveredFrom: fromTarget.id },
        uncertainty: 0.8 + Math.random() * 0.2, // New targets have high uncertainty
        lastProbed: 0,
      });
    }

    return newTargets;
  }

  /** Calculate anomaly score from findings */
  private calculateAnomalyScore(findings: Finding[]): number {
    if (findings.length === 0) return 0;

    const severityWeights = {
      low: 0.1,
      medium: 0.3,
      high: 0.6,
      critical: 1.0,
    };

    let totalScore = 0;
    for (const finding of findings) {
      totalScore += severityWeights[finding.severity] * finding.confidence;
    }

    return Math.min(1, totalScore);
  }

  /** Start exploration loop */
  private startExplorationLoop(): void {
    setInterval(() => {
      if (this.targets.size > 0) {
        this.submitTask({
          type: 'explore',
          priority: 'low',
          payload: {},
          maxRetries: 1,
        });
      }
    }, this.explorationIntervalMs);
  }

  /** Get all discoveries */
  getDiscoveries(): DiscoveryResult[] {
    return this.discoveries;
  }

  /** Get all targets */
  getTargets(): DiscoveryTarget[] {
    return Array.from(this.targets.values());
  }
}
