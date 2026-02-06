/**
 * Behavioral Analysis
 *
 * Implements behavioral analysis per blueprint §3:
 * - Simulation in isolated environments
 * - Test for harmful responses under varied inputs
 * - Semantic drift analysis
 */

import type { BehaviorObservation, AgentId } from '@ai-authority/core';
import type { ScoringInput } from '@ai-authority/scoring';

// ============================================================================
// Types
// ============================================================================

export interface BehavioralProfile {
  /** Agent being profiled */
  readonly agentId: AgentId;

  /** Observation window start */
  readonly windowStart: Date;

  /** Observation window end */
  readonly windowEnd: Date;

  /** Number of observations */
  readonly observationCount: number;

  /** Behavioral metrics aggregated over window */
  readonly metrics: AggregatedMetrics;

  /** Detected patterns */
  readonly patterns: DetectedPattern[];

  /** Risk indicators */
  readonly riskIndicators: RiskIndicator[];

  /** Ready for scoring */
  readonly scoringInput: ScoringInput;
}

export interface AggregatedMetrics {
  /** Average chained call count */
  readonly avgChainedCalls: number;

  /** Maximum chained call count */
  readonly maxChainedCalls: number;

  /** Average output entropy */
  readonly avgOutputEntropy: number;

  /** Maximum output entropy */
  readonly maxOutputEntropy: number;

  /** Session count */
  readonly sessionCount: number;

  /** Unique instances observed */
  readonly instanceCount: number;

  /** Total API calls */
  readonly totalApiCalls: number;

  /** Error rate */
  readonly errorRate: number;
}

export interface DetectedPattern {
  /** Pattern name */
  readonly name: string;

  /** Number of occurrences */
  readonly occurrences: number;

  /** Pattern confidence */
  readonly confidence: number;

  /** Example observations */
  readonly examples: string[];
}

export interface RiskIndicator {
  /** Indicator name */
  readonly name: string;

  /** Severity (0-1) */
  readonly severity: number;

  /** Description */
  readonly description: string;

  /** Evidence */
  readonly evidence: string[];
}

// ============================================================================
// Behavioral Analyzer
// ============================================================================

/**
 * Analyzes agent behavior over time to build profiles.
 */
export class BehavioralAnalyzer {
  private readonly observations: Map<AgentId, BehaviorObservation[]> = new Map();
  private readonly sessionTracking: Map<AgentId, Set<string>> = new Map();

  /**
   * Add an observation.
   */
  addObservation(observation: BehaviorObservation): void {
    // Get or initialize observation list
    let agentObs = this.observations.get(observation.agentId);
    if (!agentObs) {
      agentObs = [];
      this.observations.set(observation.agentId, agentObs);
    }
    agentObs.push(observation);

    // Track sessions
    let sessions = this.sessionTracking.get(observation.agentId);
    if (!sessions) {
      sessions = new Set();
      this.sessionTracking.set(observation.agentId, sessions);
    }
    sessions.add(observation.sessionId);
  }

  /**
   * Build a behavioral profile for an agent.
   */
  buildProfile(agentId: AgentId, windowMs?: number): BehavioralProfile | null {
    const observations = this.observations.get(agentId);
    if (!observations || observations.length === 0) {
      return null;
    }

    // Filter by time window if specified
    const now = Date.now();
    const cutoff = windowMs ? now - windowMs : 0;
    const windowedObs = observations.filter((o) => o.timestamp.getTime() >= cutoff);

    if (windowedObs.length === 0) {
      return null;
    }

    // Calculate metrics
    const metrics = this.aggregateMetrics(windowedObs);

    // Detect patterns
    const patterns = this.detectPatterns(windowedObs);

    // Identify risk indicators
    const riskIndicators = this.identifyRiskIndicators(windowedObs, metrics);

    // Prepare scoring input
    const scoringInput = this.prepareScoringInput(agentId, metrics, windowedObs);

    const timestamps = windowedObs.map((o) => o.timestamp.getTime());

    return {
      agentId,
      windowStart: new Date(Math.min(...timestamps)),
      windowEnd: new Date(Math.max(...timestamps)),
      observationCount: windowedObs.length,
      metrics,
      patterns,
      riskIndicators,
      scoringInput,
    };
  }

  /**
   * Aggregate metrics from observations.
   */
  private aggregateMetrics(observations: BehaviorObservation[]): AggregatedMetrics {
    const chainedCalls: number[] = [];
    const entropies: number[] = [];
    const sessions = new Set<string>();
    let apiCalls = 0;
    let errors = 0;

    for (const obs of observations) {
      sessions.add(obs.sessionId);

      if (obs.behaviorType === 'api_call') {
        apiCalls++;
      }

      if (obs.data.outcome === 'failure') {
        errors++;
      }

      const metrics = obs.data.metrics;
      if (metrics) {
        if (metrics.chainedCallCount !== undefined) {
          chainedCalls.push(metrics.chainedCallCount);
        }
        if (metrics.outputEntropy !== undefined) {
          entropies.push(metrics.outputEntropy);
        }
      }
    }

    const avg = (arr: number[]) => (arr.length > 0 ? arr.reduce((a, b) => a + b, 0) / arr.length : 0);
    const max = (arr: number[]) => (arr.length > 0 ? Math.max(...arr) : 0);

    return {
      avgChainedCalls: avg(chainedCalls),
      maxChainedCalls: max(chainedCalls),
      avgOutputEntropy: avg(entropies),
      maxOutputEntropy: max(entropies),
      sessionCount: sessions.size,
      instanceCount: 1, // Would need additional tracking for multi-instance
      totalApiCalls: apiCalls,
      errorRate: observations.length > 0 ? errors / observations.length : 0,
    };
  }

  /**
   * Detect behavioral patterns.
   */
  private detectPatterns(observations: BehaviorObservation[]): DetectedPattern[] {
    const patterns: DetectedPattern[] = [];

    // Detect rapid API calls
    const apiCallTimings = observations
      .filter((o) => o.behaviorType === 'api_call')
      .map((o) => o.timestamp.getTime())
      .sort((a, b) => a - b);

    if (apiCallTimings.length >= 3) {
      const intervals: number[] = [];
      for (let i = 1; i < apiCallTimings.length; i++) {
        intervals.push(apiCallTimings[i]! - apiCallTimings[i - 1]!);
      }

      const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      if (avgInterval < 1000) {
        // Less than 1 second between calls
        patterns.push({
          name: 'rapid_api_calls',
          occurrences: intervals.filter((i) => i < 1000).length,
          confidence: 0.8,
          examples: ['API calls with <1s intervals'],
        });
      }
    }

    // Detect tool chaining
    const toolInvocations = observations.filter((o) => o.behaviorType === 'tool_invocation');
    if (toolInvocations.length >= 4) {
      patterns.push({
        name: 'tool_chaining',
        occurrences: Math.floor(toolInvocations.length / 4),
        confidence: 0.7,
        examples: [`${toolInvocations.length} tool invocations observed`],
      });
    }

    // Detect evasion attempts
    const evasionAttempts = observations.filter((o) => o.behaviorType === 'evasion_attempt');
    if (evasionAttempts.length > 0) {
      patterns.push({
        name: 'evasion_behavior',
        occurrences: evasionAttempts.length,
        confidence: 0.9,
        examples: evasionAttempts.slice(0, 3).map((e) => e.data.action),
      });
    }

    return patterns;
  }

  /**
   * Identify risk indicators.
   */
  private identifyRiskIndicators(
    _observations: BehaviorObservation[],
    metrics: AggregatedMetrics
  ): RiskIndicator[] {
    const indicators: RiskIndicator[] = [];

    // High autonomy indicator
    if (metrics.maxChainedCalls >= 4) {
      indicators.push({
        name: 'high_autonomy',
        severity: Math.min(1, metrics.maxChainedCalls / 8),
        description: 'Agent exhibits high autonomous behavior',
        evidence: [`${metrics.maxChainedCalls} chained calls without human intervention`],
      });
    }

    // High entropy indicator
    if (metrics.maxOutputEntropy > 0.85) {
      indicators.push({
        name: 'high_output_entropy',
        severity: metrics.maxOutputEntropy,
        description: 'Outputs show high entropy, possible deception',
        evidence: [`Maximum output entropy: ${metrics.maxOutputEntropy.toFixed(3)}`],
      });
    }

    // Persistence indicator
    if (metrics.sessionCount > 5) {
      indicators.push({
        name: 'persistent_behavior',
        severity: Math.min(1, metrics.sessionCount / 10),
        description: 'Behavior persists across multiple sessions',
        evidence: [`Observed in ${metrics.sessionCount} sessions`],
      });
    }

    // High error rate indicator
    if (metrics.errorRate > 0.3) {
      indicators.push({
        name: 'high_error_rate',
        severity: metrics.errorRate,
        description: 'Unusually high error rate may indicate probing',
        evidence: [`Error rate: ${(metrics.errorRate * 100).toFixed(1)}%`],
      });
    }

    return indicators;
  }

  /**
   * Prepare input for scoring engine.
   */
  private prepareScoringInput(
    _agentId: AgentId,
    metrics: AggregatedMetrics,
    observations: BehaviorObservation[]
  ): ScoringInput {
    // Estimate economic impact from observations
    let estimatedEconomicImpact: number | undefined;
    for (const obs of observations) {
      if (obs.data.metrics?.estimatedImpact) {
        estimatedEconomicImpact =
          (estimatedEconomicImpact ?? 0) + obs.data.metrics.estimatedImpact;
      }
    }

    // Get prompt variation sigma if available
    let promptVariationSigma: number | undefined;
    const promptEntropies = observations
      .map((o) => o.data.metrics?.promptVariationEntropy)
      .filter((e): e is number => e !== undefined);

    if (promptEntropies.length > 0) {
      // Simple sigma calculation (would need baseline for proper calculation)
      const mean = promptEntropies.reduce((a, b) => a + b, 0) / promptEntropies.length;
      const variance =
        promptEntropies.reduce((sum, e) => sum + Math.pow(e - mean, 2), 0) / promptEntropies.length;
      promptVariationSigma = Math.sqrt(variance) * 3; // Rough approximation
    }

    const input: ScoringInput = {
      sessionCount: metrics.sessionCount,
      instanceCount: metrics.instanceCount,
      chainedCallCount: metrics.maxChainedCalls,
      observations,
    };

    // Add optional properties only if they have values
    if (estimatedEconomicImpact !== undefined) {
      (input as { estimatedEconomicImpact: number }).estimatedEconomicImpact = estimatedEconomicImpact;
    }
    if (metrics.maxOutputEntropy > 0) {
      (input as { outputEntropy: number }).outputEntropy = metrics.maxOutputEntropy;
    }
    if (promptVariationSigma !== undefined) {
      (input as { promptVariationSigma: number }).promptVariationSigma = promptVariationSigma;
    }

    return input;
  }

  /**
   * Get observations for an agent.
   */
  getObservations(agentId: AgentId): readonly BehaviorObservation[] {
    return this.observations.get(agentId) ?? [];
  }

  /**
   * Clear observations for an agent.
   */
  clearAgent(agentId: AgentId): void {
    this.observations.delete(agentId);
    this.sessionTracking.delete(agentId);
  }

  /**
   * Clear all observations.
   */
  clear(): void {
    this.observations.clear();
    this.sessionTracking.clear();
  }
}
