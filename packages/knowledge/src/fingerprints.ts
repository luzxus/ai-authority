/**
 * Fingerprint Library
 * 
 * Model fingerprinting for identification and attribution.
 */

import { generateSecureId } from '@ai-authority/core';
import type {
  FingerprintEntry,
  ModelFingerprint,
  ProbeResponse,
  KnowledgeDomain,
  KnowledgeSource,
  QueryOptions,
  QueryResult,
} from './types.js';

/** Fingerprint match result */
export interface FingerprintMatch {
  entry: FingerprintEntry;
  similarity: number;
  confidence: number;
}

/**
 * Fingerprint library for model identification.
 */
export class FingerprintLibrary {
  private readonly entries: Map<string, FingerprintEntry> = new Map();
  private readonly hashIndex: Map<string, string> = new Map(); // hash -> entry ID

  /** Add a fingerprint */
  add(
    fingerprint: ModelFingerprint,
    domain: KnowledgeDomain = 'model_fingerprints',
    source?: Partial<KnowledgeSource>
  ): string {
    const id = generateSecureId();
    const now = Date.now();

    const entry: FingerprintEntry = {
      id,
      type: 'fingerprint',
      domain,
      version: 1,
      createdAt: now,
      updatedAt: now,
      createdBy: source?.origin ?? 'unknown',
      source: {
        type: source?.type ?? 'learned',
        origin: source?.origin ?? 'unknown',
        provenance: source?.provenance ?? [],
        hash: fingerprint.hash,
      },
      confidence: 1.0,
      fingerprint,
    };

    this.entries.set(id, entry);
    this.hashIndex.set(fingerprint.hash, id);

    return id;
  }

  /** Remove a fingerprint */
  remove(id: string): boolean {
    const entry = this.entries.get(id);
    if (!entry) return false;

    this.entries.delete(id);
    this.hashIndex.delete(entry.fingerprint.hash);

    return true;
  }

  /** Get a fingerprint by ID */
  get(id: string): FingerprintEntry | undefined {
    return this.entries.get(id);
  }

  /** Get a fingerprint by hash */
  getByHash(hash: string): FingerprintEntry | undefined {
    const id = this.hashIndex.get(hash);
    if (!id) return undefined;
    return this.entries.get(id);
  }

  /** Query fingerprints */
  query(options: QueryOptions): QueryResult<FingerprintEntry> {
    const startTime = Date.now();
    const { limit = 100, offset = 0, minConfidence = 0 } = options;

    let entries = Array.from(this.entries.values());

    // Filter by confidence
    entries = entries.filter((e) => e.confidence >= minConfidence);

    // Sort by creation time (newest first)
    entries.sort((a, b) => b.createdAt - a.createdAt);

    return {
      entries: entries.slice(offset, offset + limit),
      total: entries.length,
      queryTime: Date.now() - startTime,
    };
  }

  /** Match a fingerprint against the library */
  match(fingerprint: Partial<ModelFingerprint>): FingerprintMatch[] {
    const matches: FingerprintMatch[] = [];

    // Fast path: exact hash match
    if (fingerprint.hash) {
      const exactMatch = this.getByHash(fingerprint.hash);
      if (exactMatch) {
        matches.push({
          entry: exactMatch,
          similarity: 1.0,
          confidence: 1.0,
        });
        return matches;
      }
    }

    // Similarity matching
    for (const entry of this.entries.values()) {
      const similarity = this.calculateSimilarity(fingerprint, entry.fingerprint);
      if (similarity > 0.5) { // Threshold for relevance
        matches.push({
          entry,
          similarity,
          confidence: similarity * entry.confidence,
        });
      }
    }

    // Sort by similarity descending
    matches.sort((a, b) => b.similarity - a.similarity);

    return matches.slice(0, 10); // Top 10 matches
  }

  /** Match probe responses */
  matchProbeResponses(responses: ProbeResponse[]): FingerprintMatch[] {
    const matches: FingerprintMatch[] = [];

    for (const entry of this.entries.values()) {
      const similarity = this.calculateProbeResponseSimilarity(
        responses,
        entry.fingerprint.probeResponses
      );
      if (similarity > 0.5) {
        matches.push({
          entry,
          similarity,
          confidence: similarity * entry.confidence,
        });
      }
    }

    matches.sort((a, b) => b.similarity - a.similarity);
    return matches.slice(0, 10);
  }

  /** Create a fingerprint from probe responses */
  createFingerprint(
    probeResponses: ProbeResponse[],
    metadata?: {
      architecture?: string;
      estimatedParameters?: number;
      aliases?: string[];
    }
  ): ModelFingerprint {
    // Generate perceptual hash from probe responses
    const hash = this.generatePerceptualHash(probeResponses);

    // Generate activation pattern (simplified)
    const activationPattern = this.generateActivationPattern(probeResponses);

    return {
      hash,
      activationPattern,
      probeResponses,
      architecture: metadata?.architecture,
      estimatedParameters: metadata?.estimatedParameters,
      knownAliases: metadata?.aliases ?? [],
    };
  }

  /** Get library statistics */
  getStats(): { totalFingerprints: number; uniqueArchitectures: Set<string> } {
    const architectures = new Set<string>();
    for (const entry of this.entries.values()) {
      if (entry.fingerprint.architecture) {
        architectures.add(entry.fingerprint.architecture);
      }
    }
    return {
      totalFingerprints: this.entries.size,
      uniqueArchitectures: architectures,
    };
  }

  /** Calculate similarity between two fingerprints */
  private calculateSimilarity(
    a: Partial<ModelFingerprint>,
    b: ModelFingerprint
  ): number {
    let score = 0;
    let weights = 0;

    // Hash similarity (exact match = 1, else 0)
    if (a.hash) {
      weights += 0.3;
      if (a.hash === b.hash) score += 0.3;
    }

    // Activation pattern similarity
    if (a.activationPattern && b.activationPattern) {
      weights += 0.4;
      score += 0.4 * this.cosineSimilarity(a.activationPattern, b.activationPattern);
    }

    // Probe response similarity
    if (a.probeResponses && b.probeResponses) {
      weights += 0.3;
      score += 0.3 * this.calculateProbeResponseSimilarity(a.probeResponses, b.probeResponses);
    }

    return weights > 0 ? score / weights : 0;
  }

  /** Calculate probe response similarity */
  private calculateProbeResponseSimilarity(
    a: ProbeResponse[],
    b: ProbeResponse[]
  ): number {
    if (a.length === 0 || b.length === 0) return 0;

    let matchCount = 0;
    for (const respA of a) {
      for (const respB of b) {
        if (respA.probeId === respB.probeId && respA.outputHash === respB.outputHash) {
          matchCount++;
          break;
        }
      }
    }

    return matchCount / Math.max(a.length, b.length);
  }

  /** Generate perceptual hash from probe responses */
  private generatePerceptualHash(responses: ProbeResponse[]): string {
    // Simplified perceptual hashing
    // In production, use a proper perceptual hashing algorithm
    const combined = responses
      .map((r) => r.outputHash)
      .sort()
      .join('');
    
    let hash = 0;
    for (let i = 0; i < combined.length; i++) {
      hash = ((hash << 5) - hash + combined.charCodeAt(i)) | 0;
    }
    return hash.toString(16).padStart(16, '0');
  }

  /** Generate activation pattern from probe responses */
  private generateActivationPattern(responses: ProbeResponse[]): number[] {
    // Simplified activation pattern generation
    // In production, this would be derived from actual model activations
    const pattern: number[] = [];
    for (const response of responses) {
      const characteristics = Object.values(response.characteristics);
      pattern.push(...characteristics);
    }
    
    // Normalize to fixed length
    while (pattern.length < 128) {
      pattern.push(0);
    }
    return pattern.slice(0, 128);
  }

  /** Cosine similarity between vectors */
  private cosineSimilarity(a: number[], b: number[]): number {
    const minLen = Math.min(a.length, b.length);
    let dot = 0;
    let normA = 0;
    let normB = 0;
    
    for (let i = 0; i < minLen; i++) {
      const aVal = a[i] ?? 0;
      const bVal = b[i] ?? 0;
      dot += aVal * bVal;
      normA += aVal * aVal;
      normB += bVal * bVal;
    }
    
    normA = Math.sqrt(normA);
    normB = Math.sqrt(normB);
    
    if (normA === 0 || normB === 0) return 0;
    return dot / (normA * normB);
  }
}

/** Create a fingerprint library instance */
export function createFingerprintLibrary(): FingerprintLibrary {
  return new FingerprintLibrary();
}
