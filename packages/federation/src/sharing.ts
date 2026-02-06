/**
 * Signal Sharing Protocol
 *
 * Privacy-preserving threat signal sharing between federation nodes.
 */

import type { ThreatSignal, ThreatIndicator } from '@ai-authority/core';
import { sha256 } from '@ai-authority/core';
import { DifferentialPrivacy } from './protocol.js';

// ============================================================================
// Types
// ============================================================================

export interface SharedSignal {
  /** Original signal ID (hashed for privacy) */
  readonly signalIdHash: string;

  /** Threat type */
  readonly type: ThreatSignal['type'];

  /** Severity */
  readonly severity: ThreatSignal['severity'];

  /** Privatized indicator count */
  readonly indicatorCount: number;

  /** Anonymized indicators */
  readonly anonymizedIndicators: AnonymizedIndicator[];

  /** Privatized instance count */
  readonly instanceCount: number;

  /** Region (if sharing is permitted) */
  readonly region?: string;

  /** Risk tier */
  readonly riskTier: ThreatSignal['riskTier'];

  /** Confidence (privatized) */
  readonly confidence: number;

  /** Sharing timestamp */
  readonly sharedAt: Date;

  /** Sharing node ID */
  readonly sharedBy: string;
}

export interface AnonymizedIndicator {
  /** Indicator type */
  readonly type: ThreatIndicator['type'];

  /** Double-hashed value (hash of hash) */
  readonly valueHash: string;

  /** Confidence (privatized) */
  readonly confidence: number;
}

export interface SignalSharingConfig {
  /** Differential privacy epsilon */
  readonly epsilon: number;

  /** Minimum confidence to share */
  readonly minConfidenceToShare: number;

  /** Whether to share region info */
  readonly shareRegion: boolean;

  /** Indicator types that can be shared */
  readonly shareableIndicatorTypes: ThreatIndicator['type'][];
}

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_SHARING_CONFIG: SignalSharingConfig = {
  epsilon: 1.0,
  minConfidenceToShare: 0.6,
  shareRegion: true,
  shareableIndicatorTypes: [
    'behavior_pattern_hash',
    'api_call_signature',
    'model_fingerprint',
    'tool_chain_pattern',
    'timing_signature',
    'entropy_profile',
  ],
};

// ============================================================================
// Signal Sharer
// ============================================================================

/**
 * Prepares threat signals for privacy-preserving sharing.
 */
export class SignalSharer {
  private readonly config: SignalSharingConfig;
  private readonly dp: DifferentialPrivacy;
  private readonly nodeId: string;

  constructor(nodeId: string, config: SignalSharingConfig = DEFAULT_SHARING_CONFIG) {
    this.config = config;
    this.nodeId = nodeId;
    this.dp = new DifferentialPrivacy(config.epsilon);
  }

  /**
   * Prepare a signal for sharing.
   */
  prepareForSharing(signal: ThreatSignal, region?: string): SharedSignal | null {
    // Check confidence threshold
    if (signal.confidence < this.config.minConfidenceToShare) {
      return null;
    }

    // Anonymize indicators
    const anonymizedIndicators = this.anonymizeIndicators(signal.indicators);

    // Apply differential privacy to counts
    const instanceCount = Math.max(1, this.dp.privatizeCount(signal.instanceCount));
    const indicatorCount = Math.max(0, this.dp.privatizeCount(signal.indicators.length));
    const confidence = this.dp.privatizeRate(signal.confidence);

    const sharedSignal: SharedSignal = {
      signalIdHash: sha256(sha256(signal.id)), // Double hash
      type: signal.type,
      severity: signal.severity,
      indicatorCount,
      anonymizedIndicators,
      instanceCount,
      riskTier: signal.riskTier,
      confidence,
      sharedAt: new Date(),
      sharedBy: this.nodeId,
    };

    // Add region only if configured and provided
    if (this.config.shareRegion && region !== undefined) {
      (sharedSignal as { region: string }).region = region;
    }

    return sharedSignal;
  }

  /**
   * Anonymize indicators for sharing.
   */
  private anonymizeIndicators(indicators: ThreatIndicator[]): AnonymizedIndicator[] {
    return indicators
      .filter((ind) => this.config.shareableIndicatorTypes.includes(ind.type))
      .map((ind) => ({
        type: ind.type,
        valueHash: sha256(sha256(ind.value)), // Double hash
        confidence: this.dp.privatizeRate(ind.confidence),
      }));
  }

  /**
   * Check if a shared signal matches local indicators.
   * Used for correlation without revealing sensitive data.
   */
  checkMatch(
    sharedSignal: SharedSignal,
    localIndicators: ThreatIndicator[]
  ): {
    matches: boolean;
    matchingTypes: ThreatIndicator['type'][];
    matchConfidence: number;
  } {
    const matchingTypes: ThreatIndicator['type'][] = [];
    let totalConfidence = 0;

    for (const sharedInd of sharedSignal.anonymizedIndicators) {
      for (const localInd of localIndicators) {
        const localHash = sha256(sha256(localInd.value));
        if (localHash === sharedInd.valueHash && localInd.type === sharedInd.type) {
          matchingTypes.push(localInd.type);
          totalConfidence += Math.min(sharedInd.confidence, localInd.confidence);
        }
      }
    }

    const matchConfidence =
      matchingTypes.length > 0 ? totalConfidence / matchingTypes.length : 0;

    return {
      matches: matchingTypes.length > 0,
      matchingTypes,
      matchConfidence,
    };
  }

  /**
   * Aggregate multiple shared signals for analysis.
   */
  aggregateSignals(signals: SharedSignal[]): {
    totalSignals: number;
    byType: Map<string, number>;
    bySeverity: Map<string, number>;
    byRegion: Map<string, number>;
    avgConfidence: number;
  } {
    const byType = new Map<string, number>();
    const bySeverity = new Map<string, number>();
    const byRegion = new Map<string, number>();
    let totalConfidence = 0;

    for (const signal of signals) {
      // Count by type
      byType.set(signal.type, (byType.get(signal.type) ?? 0) + 1);

      // Count by severity
      bySeverity.set(signal.severity, (bySeverity.get(signal.severity) ?? 0) + 1);

      // Count by region
      if (signal.region) {
        byRegion.set(signal.region, (byRegion.get(signal.region) ?? 0) + 1);
      }

      totalConfidence += signal.confidence;
    }

    return {
      totalSignals: signals.length,
      byType,
      bySeverity,
      byRegion,
      avgConfidence: signals.length > 0 ? totalConfidence / signals.length : 0,
    };
  }

  /**
   * Get configuration.
   */
  getConfig(): SignalSharingConfig {
    return this.config;
  }
}
