/**
 * Anomaly Detection Engine
 *
 * Implements statistical anomaly detection per blueprint §3:
 * - Real-time anomaly detection using statistical baselines
 * - Deviation >3σ in API call rates
 * - Behavioral analysis in isolated environments
 */

import type { BehaviorObservation } from '@ai-authority/core';

// ============================================================================
// Types
// ============================================================================

export interface AnomalyDetectionConfig {
  /** Standard deviations threshold for anomaly detection */
  readonly sigmaThreshold: number;

  /** Minimum samples required for baseline calculation */
  readonly minSamplesForBaseline: number;

  /** Time window for rate calculation (ms) */
  readonly rateWindowMs: number;

  /** Cooldown period after anomaly detection (ms) */
  readonly cooldownMs: number;
}

export interface Baseline {
  readonly mean: number;
  readonly stdDev: number;
  readonly sampleCount: number;
  readonly lastUpdated: Date;
}

export interface AnomalyResult {
  /** Whether an anomaly was detected */
  readonly isAnomaly: boolean;

  /** The observed value */
  readonly value: number;

  /** Standard deviations from mean */
  readonly sigma: number;

  /** Current baseline used */
  readonly baseline: Baseline;

  /** Confidence in the result (0-1) */
  readonly confidence: number;

  /** Anomaly type if detected */
  readonly anomalyType?: AnomalyType;
}

export type AnomalyType =
  | 'high_rate'
  | 'low_rate'
  | 'pattern_deviation'
  | 'timing_anomaly'
  | 'sequence_anomaly';

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_DETECTION_CONFIG: AnomalyDetectionConfig = {
  sigmaThreshold: 3, // Per blueprint: deviation >3σ
  minSamplesForBaseline: 30, // Statistical significance
  rateWindowMs: 60000, // 1 minute window
  cooldownMs: 5000, // 5 second cooldown
};

// ============================================================================
// Anomaly Detector
// ============================================================================

/**
 * Statistical anomaly detector using Z-score method.
 */
export class AnomalyDetector {
  private readonly config: AnomalyDetectionConfig;
  private readonly baselines: Map<string, Baseline> = new Map();
  private readonly samples: Map<string, number[]> = new Map();
  private readonly lastAnomalyTime: Map<string, number> = new Map();

  constructor(config: AnomalyDetectionConfig = DEFAULT_DETECTION_CONFIG) {
    this.config = config;
  }

  /**
   * Detect anomalies in a metric value.
   */
  detect(metricName: string, value: number): AnomalyResult {
    // Get or initialize samples
    let samples = this.samples.get(metricName);
    if (!samples) {
      samples = [];
      this.samples.set(metricName, samples);
    }

    // Add new sample
    samples.push(value);

    // Keep only recent samples (sliding window)
    const maxSamples = this.config.minSamplesForBaseline * 10;
    if (samples.length > maxSamples) {
      samples.shift();
    }

    // Get or calculate baseline
    const baseline = this.getOrCalculateBaseline(metricName, samples);

    // Check cooldown
    const lastAnomaly = this.lastAnomalyTime.get(metricName) ?? 0;
    const inCooldown = Date.now() - lastAnomaly < this.config.cooldownMs;

    // Calculate Z-score
    const sigma = baseline.stdDev > 0 ? (value - baseline.mean) / baseline.stdDev : 0;

    // Determine if anomaly
    const isAnomaly = !inCooldown && Math.abs(sigma) > this.config.sigmaThreshold;

    // Update last anomaly time
    if (isAnomaly) {
      this.lastAnomalyTime.set(metricName, Date.now());
    }

    // Calculate confidence based on sample size
    const confidence = Math.min(1, baseline.sampleCount / this.config.minSamplesForBaseline);

    const result: AnomalyResult = {
      isAnomaly,
      value,
      sigma,
      baseline,
      confidence,
    };

    if (isAnomaly) {
      return { ...result, anomalyType: sigma > 0 ? 'high_rate' : 'low_rate' };
    }

    return result;
  }

  /**
   * Get or calculate baseline for a metric.
   */
  private getOrCalculateBaseline(metricName: string, samples: number[]): Baseline {
    // If we have enough samples, calculate new baseline
    if (samples.length >= this.config.minSamplesForBaseline) {
      const mean = samples.reduce((a, b) => a + b, 0) / samples.length;
      const variance =
        samples.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / samples.length;
      const stdDev = Math.sqrt(variance);

      const baseline: Baseline = {
        mean,
        stdDev: stdDev > 0 ? stdDev : 0.001, // Prevent division by zero
        sampleCount: samples.length,
        lastUpdated: new Date(),
      };

      this.baselines.set(metricName, baseline);
      return baseline;
    }

    // Return existing baseline or default
    const existing = this.baselines.get(metricName);
    if (existing) {
      return existing;
    }

    // Default baseline (will have low confidence)
    return {
      mean: samples.length > 0 ? samples.reduce((a, b) => a + b, 0) / samples.length : 0,
      stdDev: 1,
      sampleCount: samples.length,
      lastUpdated: new Date(),
    };
  }

  /**
   * Manually set a baseline for a metric.
   */
  setBaseline(metricName: string, baseline: Baseline): void {
    this.baselines.set(metricName, baseline);
  }

  /**
   * Get current baseline for a metric.
   */
  getBaseline(metricName: string): Baseline | undefined {
    return this.baselines.get(metricName);
  }

  /**
   * Clear all baselines and samples.
   */
  reset(): void {
    this.baselines.clear();
    this.samples.clear();
    this.lastAnomalyTime.clear();
  }

  /**
   * Get configuration.
   */
  getConfig(): AnomalyDetectionConfig {
    return this.config;
  }
}

// ============================================================================
// Rate Detector
// ============================================================================

/**
 * Detects anomalous API call rates.
 */
export class RateDetector {
  private readonly detector: AnomalyDetector;
  private readonly windowMs: number;
  private readonly events: Map<string, number[]> = new Map();

  constructor(config: AnomalyDetectionConfig = DEFAULT_DETECTION_CONFIG) {
    this.detector = new AnomalyDetector(config);
    this.windowMs = config.rateWindowMs;
  }

  /**
   * Record an event and check for rate anomalies.
   */
  recordEvent(sourceId: string): AnomalyResult {
    const now = Date.now();

    // Get or initialize event timestamps
    let events = this.events.get(sourceId);
    if (!events) {
      events = [];
      this.events.set(sourceId, events);
    }

    // Add new event
    events.push(now);

    // Remove old events outside window
    const cutoff = now - this.windowMs;
    const newEvents = events.filter((t) => t >= cutoff);
    this.events.set(sourceId, newEvents);

    // Calculate current rate (events per window)
    const rate = newEvents.length;

    // Detect anomaly
    return this.detector.detect(`rate:${sourceId}`, rate);
  }

  /**
   * Get current rate for a source.
   */
  getCurrentRate(sourceId: string): number {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const events = this.events.get(sourceId) ?? [];
    return events.filter((t) => t >= cutoff).length;
  }

  /**
   * Reset detector state.
   */
  reset(): void {
    this.detector.reset();
    this.events.clear();
  }
}

// ============================================================================
// Behavior Pattern Detector
// ============================================================================

export interface BehaviorPattern {
  /** Pattern identifier */
  readonly id: string;

  /** Sequence of behavior types */
  readonly sequence: string[];

  /** Whether this is a known malicious pattern */
  readonly isMalicious: boolean;

  /** Description of the pattern */
  readonly description: string;

  /** Confidence required to match */
  readonly confidenceThreshold: number;
}

/**
 * Detects known malicious behavior patterns.
 */
export class PatternDetector {
  private readonly patterns: BehaviorPattern[] = [];

  /**
   * Register a pattern to detect.
   */
  registerPattern(pattern: BehaviorPattern): void {
    this.patterns.push(pattern);
  }

  /**
   * Check observations against known patterns.
   */
  detectPatterns(observations: BehaviorObservation[]): {
    matches: Array<{
      pattern: BehaviorPattern;
      matchedObservations: BehaviorObservation[];
      confidence: number;
    }>;
  } {
    const matches: Array<{
      pattern: BehaviorPattern;
      matchedObservations: BehaviorObservation[];
      confidence: number;
    }> = [];

    const behaviorSequence = observations.map((o) => o.behaviorType);

    for (const pattern of this.patterns) {
      const match = this.matchPattern(behaviorSequence, pattern.sequence, observations);
      if (match && match.confidence >= pattern.confidenceThreshold) {
        matches.push({
          pattern,
          matchedObservations: match.observations,
          confidence: match.confidence,
        });
      }
    }

    return { matches };
  }

  /**
   * Match a pattern against a sequence using subsequence matching.
   */
  private matchPattern(
    sequence: string[],
    pattern: string[],
    observations: BehaviorObservation[]
  ): { observations: BehaviorObservation[]; confidence: number } | null {
    if (pattern.length === 0) {
      return null;
    }

    // Find subsequence match
    let patternIdx = 0;
    const matchedIndices: number[] = [];

    for (let i = 0; i < sequence.length && patternIdx < pattern.length; i++) {
      if (sequence[i] === pattern[patternIdx]) {
        matchedIndices.push(i);
        patternIdx++;
      }
    }

    // Check if full pattern matched
    if (patternIdx !== pattern.length) {
      return null;
    }

    // Calculate confidence based on match quality
    const matchedObservations = matchedIndices.map((i) => observations[i]!);

    // Tighter sequence = higher confidence
    const spread = matchedIndices[matchedIndices.length - 1]! - matchedIndices[0]!;
    const expectedSpread = pattern.length - 1;
    const confidence = expectedSpread > 0 ? Math.max(0.5, 1 - (spread - expectedSpread) / 10) : 1;

    return {
      observations: matchedObservations,
      confidence,
    };
  }

  /**
   * Get all registered patterns.
   */
  getPatterns(): readonly BehaviorPattern[] {
    return this.patterns;
  }
}

// ============================================================================
// Known Malicious Patterns
// ============================================================================

export const KNOWN_MALICIOUS_PATTERNS: BehaviorPattern[] = [
  {
    id: 'credential_exfiltration',
    sequence: ['resource_access', 'api_call', 'network_request'],
    isMalicious: true,
    description: 'Access credentials then exfiltrate via network',
    confidenceThreshold: 0.7,
  },
  {
    id: 'prompt_injection_chain',
    sequence: ['prompt_processing', 'tool_invocation', 'tool_invocation', 'tool_invocation'],
    isMalicious: true,
    description: 'Prompt injection leading to autonomous tool chain',
    confidenceThreshold: 0.6,
  },
  {
    id: 'reconnaissance_pattern',
    sequence: ['api_call', 'api_call', 'api_call', 'resource_access'],
    isMalicious: true,
    description: 'Multiple API probes followed by resource access',
    confidenceThreshold: 0.6,
  },
  {
    id: 'evasion_attempt',
    sequence: ['evasion_attempt', 'prompt_processing', 'evasion_attempt'],
    isMalicious: true,
    description: 'Multiple evasion attempts around prompt processing',
    confidenceThreshold: 0.8,
  },
];
