/**
 * Approver Agent
 * 
 * Validates proposals via simulation and votes on changes.
 */

import { BaseAgent, type AgentConfig, type AgentTask, type TaskResult } from '@ai-authority/agents';
import { generateSecureId, sign } from '@ai-authority/core';
import type { Proposal, SimulationResult } from './proposer.js';

/** Vote on a proposal */
export interface ProposalVote {
  id: string;
  proposalId: string;
  voterId: string;
  approve: boolean;
  confidence: number;     // 0-1, confidence in decision
  simulationId?: string;  // ID of simulation run
  rationale: string;
  timestamp: number;
  signature: string;
}

/** Simulation configuration */
export interface SimulationConfig {
  iterations: number;
  testCases: number;
  timeoutMs: number;
  minDetectionRate: number;
  maxFalsePositiveRate: number;
}

const defaultSimConfig: SimulationConfig = {
  iterations: 100,
  testCases: 50,
  timeoutMs: 30000,
  minDetectionRate: 0.7,
  maxFalsePositiveRate: 0.15,
};

/**
 * Approver Agent
 * 
 * Validates proposals through simulation and casts votes.
 */
export class ApproverAgent extends BaseAgent {
  private votes: Map<string, ProposalVote> = new Map();
  private simulations: Map<string, SimulationResult> = new Map();
  private readonly _simConfig: SimulationConfig;

  constructor(config: AgentConfig, simConfig: Partial<SimulationConfig> = {}) {
    super(config);
    this._simConfig = { ...defaultSimConfig, ...simConfig };
  }

  protected async onInitialize(): Promise<void> {
    // Subscribe to proposal messages
  }

  protected async onMessage(message: { type: string; payload: unknown }): Promise<void> {
    if (message.type === 'proposal') {
      // Automatically evaluate incoming proposals
      this.submitTask({
        type: 'evaluate_proposal',
        priority: 'medium',
        payload: message.payload,
        maxRetries: 2,
      });
    }
  }

  protected async processTask<T, R>(task: AgentTask<T>): Promise<TaskResult<R>> {
    const startTime = Date.now();

    try {
      switch (task.type) {
        case 'evaluate_proposal':
          const vote = await this.evaluateProposal(task.payload as Proposal);
          return {
            taskId: task.id,
            success: true,
            result: vote as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };

        case 'run_simulation':
          const simResult = await this.runSimulation(task.payload as { proposal: Proposal });
          return {
            taskId: task.id,
            success: true,
            result: simResult as R,
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

  /** Evaluate a proposal and cast vote */
  private async evaluateProposal(proposal: Proposal): Promise<ProposalVote> {
    // Run simulation
    const simResult = await this.runSimulation({ proposal });
    const simId = generateSecureId();
    this.simulations.set(simId, simResult);

    // Determine vote based on simulation
    const { approve, confidence, rationale } = this.decideVote(proposal, simResult);

    // Create signed vote
    const vote: ProposalVote = {
      id: generateSecureId(),
      proposalId: proposal.id,
      voterId: this.id,
      approve,
      confidence,
      simulationId: simId,
      rationale,
      timestamp: Date.now(),
      signature: '',
    };

    // Sign the vote
    vote.signature = sign(JSON.stringify(vote), this.config.privateKey);

    // Store and broadcast
    this.votes.set(vote.id, vote);
    await this.sendMessage('broadcast', 'vote', vote);

    this.logAudit('vote_cast', {
      voteId: vote.id,
      proposalId: proposal.id,
      approve,
      confidence,
    });

    return vote;
  }

  /** Run simulation for a proposal */
  private async runSimulation(params: { proposal: Proposal }): Promise<SimulationResult> {
    const { proposal } = params;

    // Simulated results - in production would actually run the changes
    // in a sandboxed environment using this._simConfig
    const metrics = await this.simulateImpact(proposal);
    const risks = this.assessRisks(proposal);
    const recommendations = this.generateRecommendations(proposal, metrics, risks);

    return {
      success: metrics.detectionRate >= this._simConfig.minDetectionRate && 
               metrics.falsePositiveRate <= this._simConfig.maxFalsePositiveRate,
      metrics,
      risks,
      recommendations,
    };
  }

  /** Simulate impact of proposal */
  private async simulateImpact(proposal: Proposal): Promise<SimulationResult['metrics']> {
    // Simulated metrics based on proposal type
    // In production, would run actual simulations

    switch (proposal.type) {
      case 'threshold_adjustment':
        return {
          detectionRate: 0.75 + Math.random() * 0.15,
          falsePositiveRate: 0.05 + Math.random() * 0.1,
          latencyImpact: -5 + Math.random() * 10,
        };

      case 'knowledge_update':
        return {
          detectionRate: 0.8 + Math.random() * 0.1,
          falsePositiveRate: 0.03 + Math.random() * 0.07,
          latencyImpact: Math.random() * 5,
        };

      case 'rule_modification':
        return {
          detectionRate: 0.7 + Math.random() * 0.2,
          falsePositiveRate: 0.05 + Math.random() * 0.1,
          latencyImpact: -2 + Math.random() * 7,
        };

      case 'architecture_change':
        return {
          detectionRate: 0.75 + Math.random() * 0.15,
          falsePositiveRate: 0.04 + Math.random() * 0.08,
          latencyImpact: 5 + Math.random() * 15,
        };

      default:
        return {
          detectionRate: 0.75,
          falsePositiveRate: 0.08,
          latencyImpact: 0,
        };
    }
  }

  /** Assess risks of proposal */
  private assessRisks(proposal: Proposal): string[] {
    const risks: string[] = [];

    if (proposal.impact === 'high' || proposal.impact === 'critical') {
      risks.push('High impact change requires careful rollout');
    }

    if (proposal.type === 'architecture_change') {
      risks.push('Architecture changes may cause temporary instability');
      risks.push('Requires coordination across all nodes');
    }

    if (proposal.type === 'threshold_adjustment') {
      risks.push('Threshold changes may affect detection rates');
    }

    if (proposal.evidence.length < 3) {
      risks.push('Limited supporting evidence');
    }

    return risks;
  }

  /** Generate recommendations */
  private generateRecommendations(
    proposal: Proposal,
    metrics: SimulationResult['metrics'],
    risks: string[]
  ): string[] {
    const recommendations: string[] = [];

    if (metrics.falsePositiveRate > 0.1) {
      recommendations.push('Consider more conservative thresholds to reduce false positives');
    }

    if (metrics.latencyImpact > 10) {
      recommendations.push('Optimize implementation to reduce latency impact');
    }

    if (risks.length > 2) {
      recommendations.push('Consider phased rollout to mitigate risks');
    }

    if (proposal.impact === 'critical') {
      recommendations.push('Require additional approval for critical changes');
    }

    return recommendations;
  }

  /** Decide vote based on simulation results */
  private decideVote(
    _proposal: Proposal,
    simResult: SimulationResult
  ): { approve: boolean; confidence: number; rationale: string } {
    const { metrics, risks } = simResult;

    // Calculate approval score
    let score = 0;

    // Detection rate (positive)
    score += metrics.detectionRate * 40;

    // False positive rate (negative)
    score -= metrics.falsePositiveRate * 30;

    // Latency impact (negative if too high)
    if (metrics.latencyImpact > 10) {
      score -= (metrics.latencyImpact - 10) * 2;
    }

    // Risk penalty
    score -= risks.length * 5;

    // Normalize to 0-100
    score = Math.max(0, Math.min(100, score));

    const approve = score >= 50;
    const confidence = Math.abs(score - 50) / 50; // Higher confidence when further from threshold

    let rationale = `Simulation score: ${score.toFixed(1)}. `;
    rationale += `Detection rate: ${(metrics.detectionRate * 100).toFixed(1)}%, `;
    rationale += `FP rate: ${(metrics.falsePositiveRate * 100).toFixed(1)}%, `;
    rationale += `Risks identified: ${risks.length}.`;

    return { approve, confidence, rationale };
  }

  /** Get votes for a proposal */
  getVotesForProposal(proposalId: string): ProposalVote[] {
    return Array.from(this.votes.values()).filter((v) => v.proposalId === proposalId);
  }

  /** Get simulation result */
  getSimulation(id: string): SimulationResult | undefined {
    return this.simulations.get(id);
  }
}
