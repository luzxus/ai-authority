/**
 * Vector Store
 * 
 * In-memory vector database for semantic search.
 * Supports cosine similarity, euclidean distance, and dot product.
 */

import { generateSecureId } from '@ai-authority/core';
import type {
  EmbeddingEntry,
  VectorQueryOptions,
  VectorQueryResult,
  KnowledgeDomain,
  KnowledgeSource,
} from './types.js';

/** Vector store configuration */
export interface VectorStoreConfig {
  dimensions: number;
  metric: 'cosine' | 'euclidean' | 'dot';
  maxEntries: number;
}

const defaultConfig: VectorStoreConfig = {
  dimensions: 1536,  // OpenAI ada-002 dimensions
  metric: 'cosine',
  maxEntries: 100000,
};

/**
 * In-memory vector store for embeddings.
 * In production, this would be backed by a vector database like Pinecone, Qdrant, etc.
 */
export class VectorStore {
  private readonly config: VectorStoreConfig;
  private readonly entries: Map<string, EmbeddingEntry> = new Map();
  private readonly domainIndex: Map<KnowledgeDomain, Set<string>> = new Map();

  constructor(config: Partial<VectorStoreConfig> = {}) {
    this.config = { ...defaultConfig, ...config };
  }

  /** Add an embedding */
  add(
    vector: number[],
    domain: KnowledgeDomain,
    metadata: Record<string, unknown> = {},
    source?: Partial<KnowledgeSource>
  ): string {
    if (vector.length !== this.config.dimensions) {
      throw new Error(`Vector dimensions mismatch: expected ${this.config.dimensions}, got ${vector.length}`);
    }

    if (this.entries.size >= this.config.maxEntries) {
      throw new Error('Vector store full');
    }

    const id = generateSecureId();
    const now = Date.now();

    const entry: EmbeddingEntry = {
      id,
      type: 'embedding',
      domain,
      version: 1,
      createdAt: now,
      updatedAt: now,
      createdBy: source?.origin ?? 'unknown',
      source: {
        type: source?.type ?? 'learned',
        origin: source?.origin ?? 'unknown',
        provenance: source?.provenance ?? [],
        hash: this.hashVector(vector),
      },
      confidence: 1.0,
      vector,
      dimensions: this.config.dimensions,
      model: 'default',
      metadata,
    };

    this.entries.set(id, entry);

    // Update domain index
    const domainSet = this.domainIndex.get(domain) ?? new Set();
    domainSet.add(id);
    this.domainIndex.set(domain, domainSet);

    return id;
  }

  /** Remove an embedding */
  remove(id: string): boolean {
    const entry = this.entries.get(id);
    if (!entry) return false;

    this.entries.delete(id);

    // Update domain index
    const domainSet = this.domainIndex.get(entry.domain);
    if (domainSet) {
      domainSet.delete(id);
    }

    return true;
  }

  /** Get an embedding by ID */
  get(id: string): EmbeddingEntry | undefined {
    return this.entries.get(id);
  }

  /** Query for similar vectors */
  query(options: VectorQueryOptions): VectorQueryResult<EmbeddingEntry> {
    const startTime = Date.now();
    const { vector, threshold = 0.7, limit = 10, domains, minConfidence = 0 } = options;
    const metric = options.metric ?? this.config.metric;

    if (vector.length !== this.config.dimensions) {
      throw new Error(`Query vector dimensions mismatch: expected ${this.config.dimensions}, got ${vector.length}`);
    }

    // Get candidate IDs
    let candidateIds: string[];
    if (domains && domains.length > 0) {
      candidateIds = [];
      for (const domain of domains) {
        const domainSet = this.domainIndex.get(domain);
        if (domainSet) {
          candidateIds.push(...domainSet);
        }
      }
    } else {
      candidateIds = Array.from(this.entries.keys());
    }

    // Score all candidates
    const scored: Array<{ entry: EmbeddingEntry; score: number }> = [];
    for (const id of candidateIds) {
      const entry = this.entries.get(id);
      if (!entry) continue;
      if (entry.confidence < minConfidence) continue;

      const score = this.similarity(vector, entry.vector, metric);
      if (score >= threshold) {
        scored.push({ entry, score });
      }
    }

    // Sort by score descending
    scored.sort((a, b) => b.score - a.score);

    return {
      matches: scored.slice(0, limit),
      queryTime: Date.now() - startTime,
    };
  }

  /** Get all entries in a domain */
  getByDomain(domain: KnowledgeDomain): EmbeddingEntry[] {
    const ids = this.domainIndex.get(domain);
    if (!ids) return [];
    return Array.from(ids)
      .map((id) => this.entries.get(id))
      .filter((e): e is EmbeddingEntry => e !== undefined);
  }

  /** Get store statistics */
  getStats(): { totalEntries: number; byDomain: Record<string, number> } {
    const byDomain: Record<string, number> = {};
    for (const [domain, ids] of this.domainIndex) {
      byDomain[domain] = ids.size;
    }
    return {
      totalEntries: this.entries.size,
      byDomain,
    };
  }

  /** Calculate similarity between two vectors */
  private similarity(a: number[], b: number[], metric: 'cosine' | 'euclidean' | 'dot'): number {
    switch (metric) {
      case 'cosine':
        return this.cosineSimilarity(a, b);
      case 'euclidean':
        return 1 / (1 + this.euclideanDistance(a, b));
      case 'dot':
        return this.dotProduct(a, b);
    }
  }

  /** Cosine similarity */
  private cosineSimilarity(a: number[], b: number[]): number {
    const dot = this.dotProduct(a, b);
    const normA = Math.sqrt(this.dotProduct(a, a));
    const normB = Math.sqrt(this.dotProduct(b, b));
    if (normA === 0 || normB === 0) return 0;
    return dot / (normA * normB);
  }

  /** Euclidean distance */
  private euclideanDistance(a: number[], b: number[]): number {
    let sum = 0;
    for (let i = 0; i < a.length; i++) {
      const aVal = a[i] ?? 0;
      const bVal = b[i] ?? 0;
      sum += Math.pow(aVal - bVal, 2);
    }
    return Math.sqrt(sum);
  }

  /** Dot product */
  private dotProduct(a: number[], b: number[]): number {
    let sum = 0;
    for (let i = 0; i < a.length; i++) {
      const aVal = a[i] ?? 0;
      const bVal = b[i] ?? 0;
      sum += aVal * bVal;
    }
    return sum;
  }

  /** Hash a vector for content verification */
  private hashVector(vector: number[]): string {
    // Simple hash for demonstration
    // In production, use a cryptographic hash
    let hash = 0;
    for (const v of vector) {
      hash = ((hash << 5) - hash + Math.floor(v * 1000000)) | 0;
    }
    return hash.toString(16);
  }
}

/** Create a vector store instance */
export function createVectorStore(config?: Partial<VectorStoreConfig>): VectorStore {
  return new VectorStore(config);
}
