/**
 * Proposer Agent
 * 
 * Suggests knowledge and architecture changes based on analysis.
 */

import { BaseAgent, type AgentConfig, type AgentTask, type TaskResult } from '@ai-authority/agents';
import { generateSecureId } from '@ai-authority/core';

/** Proposal types */
export type ProposalType =
  | 'knowledge_update'    // New pattern, rule, or fingerprint
  | 'threshold_adjustment' // Adjust detection thresholds
  | 'rule_modification'   // Modify existing rules
  | 'architecture_change'; // System architecture changes

/** Proposal */
export interface Proposal {
  id: string;
  type: ProposalType;
  title: string;
  description: string;
  rationale: string;
  payload: unknown;
  impact: 'low' | 'medium' | 'high' | 'critical';
  evidence: string[];      // IDs of supporting evidence
  simulationResults?: SimulationResult;
  proposedAt: number;
  proposedBy: string;
}

/** Simulation result for proposal validation */
export interface SimulationResult {
  success: boolean;
  metrics: {
    detectionRate: number;
    falsePositiveRate: number;
    latencyImpact: number;
  };
  risks: string[];
  recommendations: string[];
}

/**
 * Proposer Agent
 * 
 * Analyzes system performance and proposes improvements.
 */
export class ProposerAgent extends BaseAgent {
  private proposals: Map<string, Proposal> = new Map();
  private observationBuffer: unknown[] = [];
  private lastAnalysisTime = 0;
  private analysisIntervalMs = 60000; // 1 minute

  constructor(config: AgentConfig) {
    super(config);
  }

  protected async onInitialize(): Promise<void> {
    // Subscribe to relevant signals
  }

  protected async onStart(): Promise<void> {
    // Start observation loop
    this.startObservationLoop();
  }

  protected async processTask<T, R>(task: AgentTask<T>): Promise<TaskResult<R>> {
    const startTime = Date.now();

    try {
      switch (task.type) {
        case 'analyze_and_propose':
          const proposals = await this.analyzeAndPropose();
          return {
            taskId: task.id,
            success: true,
            result: proposals as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };

        case 'create_proposal':
          const proposal = await this.createProposal(task.payload as Partial<Proposal>);
          return {
            taskId: task.id,
            success: true,
            result: proposal as R,
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

  /** Add an observation to the buffer */
  addObservation(observation: unknown): void {
    this.observationBuffer.push(observation);
    
    // Limit buffer size
    if (this.observationBuffer.length > 1000) {
      this.observationBuffer.shift();
    }
  }

  /** Analyze observations and generate proposals */
  private async analyzeAndPropose(): Promise<Proposal[]> {
    const now = Date.now();
    if (now - this.lastAnalysisTime < this.analysisIntervalMs) {
      return [];
    }
    this.lastAnalysisTime = now;

    const newProposals: Proposal[] = [];

    // Analyze for threshold adjustments
    const thresholdProposal = await this.analyzeThresholds();
    if (thresholdProposal) {
      newProposals.push(thresholdProposal);
    }

    // Analyze for new patterns
    const patternProposal = await this.analyzeNewPatterns();
    if (patternProposal) {
      newProposals.push(patternProposal);
    }

    // Broadcast proposals
    for (const proposal of newProposals) {
      this.proposals.set(proposal.id, proposal);
      await this.sendMessage('broadcast', 'proposal', proposal);
    }

    return newProposals;
  }

  /** Analyze detection thresholds */
  private async analyzeThresholds(): Promise<Proposal | null> {
    // Simplified analysis - in production would use statistical methods
    // to determine if thresholds need adjustment based on false positive/negative rates
    
    const observations = this.observationBuffer.filter(
      (o): o is { type: string; falsePositive?: boolean; falseNegative?: boolean } =>
        typeof o === 'object' && o !== null && 'type' in o
    );

    const falsePositives = observations.filter((o) => o.falsePositive).length;
    const falseNegatives = observations.filter((o) => o.falseNegative).length;
    const total = observations.length;

    if (total < 100) return null; // Not enough data

    const fpRate = falsePositives / total;
    const fnRate = falseNegatives / total;

    // Propose adjustment if rates are too high
    if (fpRate > 0.1 || fnRate > 0.1) {
      return this.createProposal({
        type: 'threshold_adjustment',
        title: 'Adjust detection thresholds',
        description: `False positive rate: ${(fpRate * 100).toFixed(1)}%, False negative rate: ${(fnRate * 100).toFixed(1)}%`,
        rationale: 'Detection rates outside acceptable bounds',
        payload: {
          currentFPRate: fpRate,
          currentFNRate: fnRate,
          recommendedAdjustment: fpRate > fnRate ? 'increase' : 'decrease',
        },
        impact: fpRate > 0.2 || fnRate > 0.2 ? 'high' : 'medium',
        evidence: [],
      });
    }

    return null;
  }

  /** Analyze for new behavioral patterns */
  private async analyzeNewPatterns(): Promise<Proposal | null> {
    // Simplified pattern analysis
    // In production would use clustering and anomaly detection
    
    // Clear observation buffer after analysis
    this.observationBuffer = [];
    
    return null;
  }

  /** Create a new proposal */
  private async createProposal(partial: Partial<Proposal>): Promise<Proposal> {
    const proposal: Proposal = {
      id: generateSecureId(),
      type: partial.type ?? 'knowledge_update',
      title: partial.title ?? 'Untitled Proposal',
      description: partial.description ?? '',
      rationale: partial.rationale ?? '',
      payload: partial.payload,
      impact: partial.impact ?? 'low',
      evidence: partial.evidence ?? [],
      proposedAt: Date.now(),
      proposedBy: this.id,
    };

    this.proposals.set(proposal.id, proposal);
    this.logAudit('proposal_created', { proposalId: proposal.id, type: proposal.type });

    return proposal;
  }

  /** Start observation loop */
  private startObservationLoop(): void {
    // Periodically trigger analysis
    setInterval(() => {
      this.submitTask({
        type: 'analyze_and_propose',
        priority: 'low',
        payload: {},
        maxRetries: 0,
      });
    }, this.analysisIntervalMs);
  }

  /** Get all proposals */
  getProposals(): Proposal[] {
    return Array.from(this.proposals.values());
  }

  /** Get proposal by ID */
  getProposal(id: string): Proposal | undefined {
    return this.proposals.get(id);
  }
}
