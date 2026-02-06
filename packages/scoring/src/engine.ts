/**
 * Risk Scoring Engine
 *
 * Implements the scoring algorithm per blueprint §1:
 * - Harm: Simulated economic loss OR users targeted (>$10k OR >100)
 * - Persistence: Behavior repeats across sessions/instances (>5 sessions)
 * - Autonomy: Chained tool calls without human re-prompt (≥4 calls)
 * - Deception: Output entropy + semantic inconsistency score (>0.85)
 * - Evasion: Prompt variation entropy above baseline (>3σ)
 */

import type {
  RiskScore,
  RiskDimensions,
  DimensionScore,
  ScoreFactor,
  RiskTier,
  RiskClassification,
  ScoringConfig,
  CalculationStep,
  ClassificationRule,
  BehaviorObservation,
} from '@ai-authority/core';
import { DEFAULT_SCORING_CONFIG } from '@ai-authority/core';

// ============================================================================
// Types
// ============================================================================

export interface ScoringInput {
  /** Estimated economic impact in dollars */
  estimatedEconomicImpact?: number;

  /** Number of users potentially affected */
  usersAffected?: number;

  /** Number of sessions this behavior has been observed */
  sessionCount: number;

  /** Number of distinct instances (e.g., different deployments) */
  instanceCount?: number;

  /** Number of chained tool calls without human intervention */
  chainedCallCount: number;

  /** Output entropy (0-1) */
  outputEntropy?: number;

  /** Semantic inconsistency score (0-1) */
  semanticInconsistency?: number;

  /** Prompt variation entropy (in standard deviations from baseline) */
  promptVariationSigma?: number;

  /** Additional observations for context */
  observations?: BehaviorObservation[];
}

export interface ScoringContext {
  /** Timestamp of scoring */
  timestamp: Date;

  /** Agent ID being scored */
  agentId?: string;

  /** Source of the data */
  source?: string;
}

// ============================================================================
// Scoring Engine
// ============================================================================

/**
 * Risk scoring engine implementing the blueprint's scoring algorithm.
 */
export class RiskScoringEngine {
  private readonly config: ScoringConfig;
  private readonly version: string = '0.1.0';

  constructor(config: ScoringConfig = DEFAULT_SCORING_CONFIG) {
    this.config = config;
  }

  /**
   * Calculate a complete risk score from input data.
   */
  score(input: ScoringInput, context?: ScoringContext): RiskScore {
    const trace: CalculationStep[] = [];

    // Calculate individual dimension scores
    const harm = this.calculateHarmScore(input, trace);
    const persistence = this.calculatePersistenceScore(input, trace);
    const autonomy = this.calculateAutonomyScore(input, trace);
    const deception = this.calculateDeceptionScore(input, trace);
    const evasion = this.calculateEvasionScore(input, trace);

    const dimensions: RiskDimensions = {
      harm,
      persistence,
      autonomy,
      deception,
      evasion,
    };

    // Calculate aggregate score
    const aggregate = this.calculateAggregate(dimensions, trace);

    // Determine tier
    const tier = this.determineTier(aggregate, trace);

    // Classify behavior
    const classification = this.classify(dimensions, aggregate, trace);

    return {
      dimensions,
      aggregate,
      weights: this.config.weights,
      tier,
      classification,
      scoredAt: context?.timestamp ?? new Date(),
      algorithmVersion: this.version,
      calculationTrace: trace,
    };
  }

  /**
   * Calculate harm score.
   * Based on simulated economic loss OR users targeted.
   */
  private calculateHarmScore(input: ScoringInput, trace: CalculationStep[]): DimensionScore {
    const factors: ScoreFactor[] = [];
    const thresholds = this.config.thresholds.harm;

    // Economic impact factor
    let economicScore = 0;
    if (input.estimatedEconomicImpact !== undefined) {
      economicScore = this.normalize(
        input.estimatedEconomicImpact,
        thresholds.low,
        thresholds.critical
      );
      factors.push({
        name: 'economic_impact',
        contribution: economicScore,
        evidence: `Estimated loss: $${input.estimatedEconomicImpact}`,
      });
    }

    // Users affected factor
    let usersScore = 0;
    if (input.usersAffected !== undefined) {
      // Blueprint threshold: >100 users
      usersScore = this.normalize(input.usersAffected, 10, 1000);
      factors.push({
        name: 'users_affected',
        contribution: usersScore,
        evidence: `Users affected: ${input.usersAffected}`,
      });
    }

    // Take maximum of economic or user impact (per blueprint: "OR")
    const rawValue = Math.max(
      input.estimatedEconomicImpact ?? 0,
      (input.usersAffected ?? 0) * 100 // Convert users to dollar-equivalent
    );
    const value = Math.max(economicScore, usersScore);

    // Confidence based on data availability
    const confidence = factors.length > 0 ? Math.min(1, factors.length * 0.5) : 0;

    trace.push({
      step: 'harm_score',
      inputs: {
        economic: input.estimatedEconomicImpact ?? 0,
        users: input.usersAffected ?? 0,
      },
      output: value,
      formula: 'max(normalize(economic), normalize(users))',
    });

    return {
      value,
      rawValue,
      unit: 'dollars_equivalent',
      threshold: thresholds.high,
      confidence,
      factors,
    };
  }

  /**
   * Calculate persistence score.
   * Based on behavior repeating across sessions/instances.
   */
  private calculatePersistenceScore(
    input: ScoringInput,
    trace: CalculationStep[]
  ): DimensionScore {
    const factors: ScoreFactor[] = [];
    const thresholds = this.config.thresholds.persistence;

    // Session count factor (blueprint threshold: >5 sessions)
    const sessionScore = this.normalize(input.sessionCount, 1, thresholds.critical);
    factors.push({
      name: 'session_count',
      contribution: sessionScore,
      evidence: `Observed in ${input.sessionCount} sessions`,
    });

    // Instance count factor (cross-instance persistence is more severe)
    let instanceScore = 0;
    if (input.instanceCount !== undefined && input.instanceCount > 1) {
      instanceScore = this.normalize(input.instanceCount, 1, 10);
      factors.push({
        name: 'instance_count',
        contribution: instanceScore,
        evidence: `Observed across ${input.instanceCount} instances`,
      });
    }

    // Combine factors (weighted average favoring sessions)
    const value = sessionScore * 0.7 + instanceScore * 0.3;
    const rawValue = input.sessionCount;

    trace.push({
      step: 'persistence_score',
      inputs: {
        sessions: input.sessionCount,
        instances: input.instanceCount ?? 1,
      },
      output: value,
      formula: 'sessions * 0.7 + instances * 0.3',
    });

    return {
      value,
      rawValue,
      unit: 'sessions',
      threshold: thresholds.high,
      confidence: 0.9, // Session data is reliable
      factors,
    };
  }

  /**
   * Calculate autonomy score.
   * Based on chained tool calls without human intervention.
   */
  private calculateAutonomyScore(input: ScoringInput, trace: CalculationStep[]): DimensionScore {
    const factors: ScoreFactor[] = [];
    const thresholds = this.config.thresholds.autonomy;

    // Blueprint threshold: ≥4 calls
    const value = this.normalize(input.chainedCallCount, 1, thresholds.critical);

    factors.push({
      name: 'chained_calls',
      contribution: value,
      evidence: `${input.chainedCallCount} chained calls without human re-prompt`,
    });

    trace.push({
      step: 'autonomy_score',
      inputs: { chainedCalls: input.chainedCallCount },
      output: value,
      formula: 'normalize(chainedCalls, 1, critical)',
    });

    return {
      value,
      rawValue: input.chainedCallCount,
      unit: 'calls',
      threshold: thresholds.high,
      confidence: 0.95, // Call counting is very reliable
      factors,
    };
  }

  /**
   * Calculate deception score.
   * Based on output entropy + semantic inconsistency.
   */
  private calculateDeceptionScore(input: ScoringInput, trace: CalculationStep[]): DimensionScore {
    const factors: ScoreFactor[] = [];
    const thresholds = this.config.thresholds.deception;

    let entropyScore = 0;
    if (input.outputEntropy !== undefined) {
      entropyScore = input.outputEntropy; // Already 0-1
      factors.push({
        name: 'output_entropy',
        contribution: entropyScore,
        evidence: `Output entropy: ${input.outputEntropy.toFixed(3)}`,
      });
    }

    let inconsistencyScore = 0;
    if (input.semanticInconsistency !== undefined) {
      inconsistencyScore = input.semanticInconsistency; // Already 0-1
      factors.push({
        name: 'semantic_inconsistency',
        contribution: inconsistencyScore,
        evidence: `Semantic inconsistency: ${input.semanticInconsistency.toFixed(3)}`,
      });
    }

    // Combine entropy and inconsistency (per blueprint)
    const rawValue = (entropyScore + inconsistencyScore) / 2;
    const value = this.normalize(rawValue, 0, thresholds.critical);

    // Lower confidence if data is missing
    const confidence = factors.length === 2 ? 0.85 : factors.length * 0.4;

    trace.push({
      step: 'deception_score',
      inputs: {
        entropy: input.outputEntropy ?? 0,
        inconsistency: input.semanticInconsistency ?? 0,
      },
      output: value,
      formula: 'normalize((entropy + inconsistency) / 2)',
    });

    return {
      value,
      rawValue,
      unit: 'combined_score',
      threshold: thresholds.high,
      confidence,
      factors,
    };
  }

  /**
   * Calculate evasion score.
   * Based on prompt variation entropy above baseline.
   */
  private calculateEvasionScore(input: ScoringInput, trace: CalculationStep[]): DimensionScore {
    const factors: ScoreFactor[] = [];
    const thresholds = this.config.thresholds.evasion;

    // Blueprint threshold: >3σ
    const sigma = input.promptVariationSigma ?? 0;
    const value = this.normalize(sigma, 0, thresholds.critical);

    if (sigma > 0) {
      factors.push({
        name: 'prompt_variation',
        contribution: value,
        evidence: `Prompt variation: ${sigma.toFixed(2)}σ above baseline`,
      });
    }

    trace.push({
      step: 'evasion_score',
      inputs: { sigma },
      output: value,
      formula: 'normalize(sigma, 0, critical)',
    });

    return {
      value,
      rawValue: sigma,
      unit: 'sigma',
      threshold: thresholds.high,
      confidence: sigma > 0 ? 0.8 : 0.3,
      factors,
    };
  }

  /**
   * Calculate aggregate score from dimensions.
   */
  private calculateAggregate(dimensions: RiskDimensions, trace: CalculationStep[]): number {
    const { weights } = this.config;

    const weighted =
      dimensions.harm.value * weights.harm +
      dimensions.persistence.value * weights.persistence +
      dimensions.autonomy.value * weights.autonomy +
      dimensions.deception.value * weights.deception +
      dimensions.evasion.value * weights.evasion;

    // Clamp to [0, 1]
    const aggregate = Math.max(0, Math.min(1, weighted));

    trace.push({
      step: 'aggregate',
      inputs: {
        harm: dimensions.harm.value,
        persistence: dimensions.persistence.value,
        autonomy: dimensions.autonomy.value,
        deception: dimensions.deception.value,
        evasion: dimensions.evasion.value,
      },
      output: aggregate,
      formula: 'sum(dimension * weight)',
    });

    return aggregate;
  }

  /**
   * Determine risk tier from aggregate score.
   */
  private determineTier(aggregate: number, trace: CalculationStep[]): RiskTier {
    const { tierBoundaries } = this.config;

    let tier: RiskTier;
    if (aggregate >= tierBoundaries.escalate) {
      tier = 'escalate';
    } else if (aggregate >= tierBoundaries.investigate) {
      tier = 'investigate';
    } else {
      tier = 'alert';
    }

    trace.push({
      step: 'tier_determination',
      inputs: {
        aggregate,
        escalateThreshold: tierBoundaries.escalate,
        investigateThreshold: tierBoundaries.investigate,
      },
      output: tier === 'escalate' ? 2 : tier === 'investigate' ? 1 : 0,
      formula: 'aggregate >= escalate ? 2 : aggregate >= investigate ? 1 : 0',
    });

    return tier;
  }

  /**
   * Classify behavior based on dimensions and rules.
   */
  private classify(
    dimensions: RiskDimensions,
    aggregate: number,
    trace: CalculationStep[]
  ): RiskClassification {
    const { classificationRules } = this.config;

    // Sort rules by priority (highest first)
    const sortedRules = [...classificationRules].sort((a, b) => b.priority - a.priority);

    for (const rule of sortedRules) {
      if (this.evaluateRule(rule, dimensions, aggregate)) {
        trace.push({
          step: 'classification',
          inputs: { ruleName: rule.name as unknown as number },
          output: rule.classification as unknown as number,
          formula: `matched rule: ${rule.name}`,
        });

        return rule.classification;
      }
    }

    trace.push({
      step: 'classification',
      inputs: { ruleName: 'default' as unknown as number },
      output: 'indeterminate' as unknown as number,
      formula: 'no rule matched',
    });

    return 'indeterminate';
  }

  /**
   * Evaluate a classification rule.
   */
  private evaluateRule(
    rule: ClassificationRule,
    dimensions: RiskDimensions,
    aggregate: number
  ): boolean {
    for (const condition of rule.conditions) {
      const value =
        condition.dimension === 'aggregate'
          ? aggregate
          : dimensions[condition.dimension].value;

      const met = this.evaluateCondition(value, condition.operator, condition.value);
      if (!met) {
        return false;
      }
    }
    return true;
  }

  /**
   * Evaluate a single condition.
   */
  private evaluateCondition(
    actual: number,
    operator: '>' | '>=' | '<' | '<=' | '==' | '!=',
    expected: number
  ): boolean {
    switch (operator) {
      case '>':
        return actual > expected;
      case '>=':
        return actual >= expected;
      case '<':
        return actual < expected;
      case '<=':
        return actual <= expected;
      case '==':
        return actual === expected;
      case '!=':
        return actual !== expected;
    }
  }

  /**
   * Normalize a value to [0, 1] range.
   */
  private normalize(value: number, min: number, max: number): number {
    if (value <= min) return 0;
    if (value >= max) return 1;
    return (value - min) / (max - min);
  }

  /**
   * Get the current configuration.
   */
  getConfig(): ScoringConfig {
    return this.config;
  }

  /**
   * Get algorithm version.
   */
  getVersion(): string {
    return this.version;
  }
}
