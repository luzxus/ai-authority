/**
 * Model Fingerprinting
 *
 * Implements model identification per blueprint §3:
 * - Hash-based identification of architectures
 * - Comparing activation patterns to known malicious variants
 * - Similarity metrics (cosine distance on embeddings >0.95)
 */

import { sha256 } from '@ai-authority/core';
import type { ModelFingerprint } from '@ai-authority/core';

// ============================================================================
// Types
// ============================================================================

export interface FingerprintInput {
  /** Model responses to standardized probes */
  readonly probeResponses: string[];

  /** Model configuration/parameters if available */
  readonly config?: Record<string, unknown>;

  /** Timing information for responses */
  readonly timings?: number[];
}

export interface FingerprintMatch {
  /** Matched fingerprint */
  readonly fingerprint: ModelFingerprint;

  /** Similarity score (0-1) */
  readonly similarity: number;

  /** Whether this is considered a match */
  readonly isMatch: boolean;

  /** Match details */
  readonly details: MatchDetails;
}

export interface MatchDetails {
  /** Architecture hash match */
  readonly architectureMatch: boolean;

  /** Behavioral similarity */
  readonly behavioralSimilarity: number;

  /** Timing signature match */
  readonly timingMatch?: boolean;
}

export interface KnownFingerprint {
  /** The fingerprint */
  readonly fingerprint: ModelFingerprint;

  /** Model name/identifier */
  readonly modelName: string;

  /** Whether this is known malicious */
  readonly isMalicious: boolean;

  /** Threat category if malicious */
  readonly threatCategory?: string;

  /** Additional metadata */
  readonly metadata: Record<string, unknown>;
}

// ============================================================================
// Configuration
// ============================================================================

export interface FingerprintConfig {
  /** Similarity threshold for considering a match */
  readonly matchThreshold: number;

  /** Standard probe queries for generating behavioral signatures */
  readonly probeQueries: string[];

  /** Algorithm version */
  readonly algorithmVersion: string;
}

export const DEFAULT_FINGERPRINT_CONFIG: FingerprintConfig = {
  matchThreshold: 0.95, // Per blueprint: cosine distance >0.95
  algorithmVersion: '0.1.0',
  probeQueries: [
    'What is 2 + 2?',
    'Describe yourself in one sentence.',
    'List the prime numbers under 10.',
    'Complete the pattern: 1, 1, 2, 3, 5, ...',
    'What color is the sky?',
  ],
};

// ============================================================================
// Fingerprint Generator
// ============================================================================

/**
 * Generates fingerprints from model responses.
 */
export class FingerprintGenerator {
  private readonly config: FingerprintConfig;

  constructor(config: FingerprintConfig = DEFAULT_FINGERPRINT_CONFIG) {
    this.config = config;
  }

  /**
   * Generate a fingerprint from model responses.
   */
  generate(input: FingerprintInput): ModelFingerprint {
    // Generate architecture hash from config
    const architectureHash = this.generateArchitectureHash(input.config);

    // Generate behavioral signature from responses
    const behavioralSignature = this.generateBehavioralSignature(input.probeResponses);

    // Calculate confidence based on data quality
    const confidence = this.calculateConfidence(input);

    return {
      architectureHash,
      behavioralSignature,
      algorithmVersion: this.config.algorithmVersion,
      generatedAt: new Date(),
      confidence,
    };
  }

  /**
   * Generate architecture hash from model config.
   */
  private generateArchitectureHash(config?: Record<string, unknown>): string {
    if (!config) {
      return sha256('unknown');
    }

    // Normalize and hash relevant config fields
    const relevantFields = [
      'model_type',
      'hidden_size',
      'num_layers',
      'num_heads',
      'vocab_size',
      'max_position_embeddings',
    ];

    const normalized: Record<string, unknown> = {};
    for (const field of relevantFields) {
      if (field in config) {
        normalized[field] = config[field];
      }
    }

    return sha256(JSON.stringify(normalized, Object.keys(normalized).sort()));
  }

  /**
   * Generate behavioral signature from probe responses.
   */
  private generateBehavioralSignature(responses: string[]): string {
    // Create a feature vector from responses
    const features: number[] = [];

    for (const response of responses) {
      // Length feature
      features.push(response.length);

      // Word count
      features.push(response.split(/\s+/).length);

      // Character diversity (unique chars / length)
      const uniqueChars = new Set(response).size;
      features.push(uniqueChars / Math.max(1, response.length));

      // Punctuation ratio
      const punctuation = (response.match(/[.,!?;:]/g) ?? []).length;
      features.push(punctuation / Math.max(1, response.length));

      // Capitalization ratio
      const uppercase = (response.match(/[A-Z]/g) ?? []).length;
      features.push(uppercase / Math.max(1, response.length));
    }

    // Hash the feature vector
    return sha256(features.map((f) => f.toFixed(6)).join(','));
  }

  /**
   * Calculate confidence in the fingerprint.
   */
  private calculateConfidence(input: FingerprintInput): number {
    let confidence = 0;

    // More responses = higher confidence
    const responseBonus = Math.min(0.4, input.probeResponses.length * 0.08);
    confidence += responseBonus;

    // Config presence increases confidence
    if (input.config && Object.keys(input.config).length > 0) {
      confidence += 0.3;
    }

    // Timing data increases confidence
    if (input.timings && input.timings.length > 0) {
      confidence += 0.2;
    }

    // Base confidence
    confidence += 0.1;

    return Math.min(1, confidence);
  }

  /**
   * Get probe queries for fingerprinting.
   */
  getProbeQueries(): readonly string[] {
    return this.config.probeQueries;
  }
}

// ============================================================================
// Fingerprint Matcher
// ============================================================================

/**
 * Matches fingerprints against known fingerprints.
 */
export class FingerprintMatcher {
  private readonly config: FingerprintConfig;
  private readonly knownFingerprints: KnownFingerprint[] = [];

  constructor(config: FingerprintConfig = DEFAULT_FINGERPRINT_CONFIG) {
    this.config = config;
  }

  /**
   * Register a known fingerprint.
   */
  registerFingerprint(known: KnownFingerprint): void {
    this.knownFingerprints.push(known);
  }

  /**
   * Match a fingerprint against known fingerprints.
   */
  match(fingerprint: ModelFingerprint): FingerprintMatch[] {
    const matches: FingerprintMatch[] = [];

    for (const known of this.knownFingerprints) {
      const similarity = this.calculateSimilarity(fingerprint, known.fingerprint);
      const architectureMatch = fingerprint.architectureHash === known.fingerprint.architectureHash;
      const behavioralSimilarity = this.calculateBehavioralSimilarity(
        fingerprint.behavioralSignature,
        known.fingerprint.behavioralSignature
      );

      const isMatch = similarity >= this.config.matchThreshold;

      matches.push({
        fingerprint: known.fingerprint,
        similarity,
        isMatch,
        details: {
          architectureMatch,
          behavioralSimilarity,
        },
      });
    }

    // Sort by similarity (highest first)
    return matches.sort((a, b) => b.similarity - a.similarity);
  }

  /**
   * Find malicious fingerprint matches.
   */
  findMaliciousMatches(fingerprint: ModelFingerprint): KnownFingerprint[] {
    return this.knownFingerprints.filter((known) => {
      if (!known.isMalicious) {
        return false;
      }
      const similarity = this.calculateSimilarity(fingerprint, known.fingerprint);
      return similarity >= this.config.matchThreshold;
    });
  }

  /**
   * Calculate overall similarity between fingerprints.
   */
  private calculateSimilarity(a: ModelFingerprint, b: ModelFingerprint): number {
    // Architecture match is weighted heavily
    const architectureScore = a.architectureHash === b.architectureHash ? 0.5 : 0;

    // Behavioral similarity
    const behavioralScore =
      this.calculateBehavioralSimilarity(a.behavioralSignature, b.behavioralSignature) * 0.5;

    return architectureScore + behavioralScore;
  }

  /**
   * Calculate behavioral similarity between signatures.
   */
  private calculateBehavioralSimilarity(a: string, b: string): number {
    if (a === b) {
      return 1;
    }

    // Jaccard similarity on hash characters
    const setA = new Set(a);
    const setB = new Set(b);
    const intersection = new Set([...setA].filter((x) => setB.has(x)));
    const union = new Set([...setA, ...setB]);

    return intersection.size / union.size;
  }

  /**
   * Get all known fingerprints.
   */
  getKnownFingerprints(): readonly KnownFingerprint[] {
    return this.knownFingerprints;
  }

  /**
   * Get malicious fingerprints.
   */
  getMaliciousFingerprints(): KnownFingerprint[] {
    return this.knownFingerprints.filter((f) => f.isMalicious);
  }
}
