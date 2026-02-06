/**
 * Knowledge Base
 * 
 * Unified knowledge base combining vectors, rules, and fingerprints.
 */

import { generateSecureId, MerkleTree, getTracer } from '@ai-authority/core';
import type {
  KnowledgeDomain,
  KnowledgeUpdate,
  QueryOptions,
  VectorQueryOptions,
  EmbeddingEntry,
  RuleEntry,
  FingerprintEntry,
  PatternEntry,
  BehaviorPattern,
  RuleCondition,
  RuleAction,
  ModelFingerprint,
} from './types.js';
import { VectorStore, createVectorStore } from './vectors.js';
import { RuleEngine, createRuleEngine, createDefaultRules, type EvaluationContext, type AggregateResult } from './rules.js';
import { FingerprintLibrary, createFingerprintLibrary, type FingerprintMatch } from './fingerprints.js';

const tracer = getTracer();

/** Knowledge base configuration */
export interface KnowledgeBaseConfig {
  vectorDimensions: number;
  maxEntries: number;
  requireConsensusForWrites: boolean;
  minApprovers: number;
}

const defaultConfig: KnowledgeBaseConfig = {
  vectorDimensions: 1536,
  maxEntries: 100000,
  requireConsensusForWrites: true,
  minApprovers: 2,
};

/** Pending knowledge update */
interface PendingUpdate {
  update: KnowledgeUpdate;
  approvers: string[];
  status: 'pending' | 'approved' | 'rejected';
}

/**
 * Unified knowledge base.
 */
export class KnowledgeBase {
  private readonly config: KnowledgeBaseConfig;
  private readonly vectors: VectorStore;
  private readonly rules: RuleEngine;
  private readonly fingerprints: FingerprintLibrary;
  private readonly patterns: Map<string, PatternEntry> = new Map();
  private readonly updateHistory: MerkleTree;
  private readonly pendingUpdates: Map<string, PendingUpdate> = new Map();

  constructor(config: Partial<KnowledgeBaseConfig> = {}) {
    this.config = { ...defaultConfig, ...config };
    this.vectors = createVectorStore({ dimensions: this.config.vectorDimensions });
    this.rules = createRuleEngine();
    this.fingerprints = createFingerprintLibrary();
    this.updateHistory = new MerkleTree();

    // Initialize default rules
    createDefaultRules(this.rules);
  }

  /** Add an embedding */
  addEmbedding(
    vector: number[],
    domain: KnowledgeDomain,
    metadata: Record<string, unknown> = {},
    proposedBy: string = 'system'
  ): string | { pendingId: string } {
    if (this.config.requireConsensusForWrites) {
      return this.proposeUpdate({
        operation: 'create',
        entry: {
          id: generateSecureId(),
          type: 'embedding',
          domain,
          version: 1,
          createdAt: Date.now(),
          updatedAt: Date.now(),
          createdBy: proposedBy,
          source: { type: 'proposed', origin: proposedBy, provenance: [], hash: '' },
          confidence: 1.0,
          vector,
          dimensions: vector.length,
          model: 'default',
          metadata,
        } as EmbeddingEntry,
        reason: 'New embedding',
        proposedBy,
        timestamp: Date.now(),
      });
    }
    return this.vectors.add(vector, domain, metadata, { origin: proposedBy });
  }

  /** Query embeddings */
  queryEmbeddings(options: VectorQueryOptions) {
    return this.vectors.query(options);
  }

  /** Add a rule */
  addRule(
    condition: RuleCondition,
    action: RuleAction,
    domain: KnowledgeDomain,
    priority: number = 0,
    proposedBy: string = 'system'
  ): string | { pendingId: string } {
    if (this.config.requireConsensusForWrites) {
      return this.proposeUpdate({
        operation: 'create',
        entry: {
          id: generateSecureId(),
          type: 'rule',
          domain,
          version: 1,
          createdAt: Date.now(),
          updatedAt: Date.now(),
          createdBy: proposedBy,
          source: { type: 'proposed', origin: proposedBy, provenance: [], hash: '' },
          confidence: 1.0,
          condition,
          action,
          priority,
          enabled: true,
        } as RuleEntry,
        reason: 'New rule',
        proposedBy,
        timestamp: Date.now(),
      });
    }
    return this.rules.add(condition, action, domain, priority, { origin: proposedBy });
  }

  /** Evaluate rules against context */
  evaluateRules(context: EvaluationContext, domains?: KnowledgeDomain[]): AggregateResult {
    return this.rules.evaluateAll(context, domains);
  }

  /** Add a fingerprint */
  addFingerprint(
    fingerprint: ModelFingerprint,
    proposedBy: string = 'system'
  ): string | { pendingId: string } {
    if (this.config.requireConsensusForWrites) {
      return this.proposeUpdate({
        operation: 'create',
        entry: {
          id: generateSecureId(),
          type: 'fingerprint',
          domain: 'model_fingerprints',
          version: 1,
          createdAt: Date.now(),
          updatedAt: Date.now(),
          createdBy: proposedBy,
          source: { type: 'proposed', origin: proposedBy, provenance: [], hash: fingerprint.hash },
          confidence: 1.0,
          fingerprint,
        } as FingerprintEntry,
        reason: 'New fingerprint',
        proposedBy,
        timestamp: Date.now(),
      });
    }
    return this.fingerprints.add(fingerprint, 'model_fingerprints', { origin: proposedBy });
  }

  /** Match a fingerprint */
  matchFingerprint(fingerprint: Partial<ModelFingerprint>): FingerprintMatch[] {
    return this.fingerprints.match(fingerprint);
  }

  /** Add a behavioral pattern */
  addPattern(
    pattern: BehaviorPattern,
    domain: KnowledgeDomain,
    proposedBy: string = 'system'
  ): string | { pendingId: string } {
    const entry: PatternEntry = {
      id: generateSecureId(),
      type: 'pattern',
      domain,
      version: 1,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      createdBy: proposedBy,
      source: { type: 'proposed', origin: proposedBy, provenance: [], hash: '' },
      confidence: 1.0,
      pattern,
      frequency: 1,
      lastSeen: Date.now(),
    };

    if (this.config.requireConsensusForWrites) {
      return this.proposeUpdate({
        operation: 'create',
        entry,
        reason: 'New pattern',
        proposedBy,
        timestamp: Date.now(),
      });
    }

    this.patterns.set(entry.id, entry);
    return entry.id;
  }

  /** Get a pattern by ID */
  getPattern(id: string): PatternEntry | undefined {
    return this.patterns.get(id);
  }

  /** Query patterns */
  queryPatterns(options: QueryOptions) {
    const startTime = Date.now();
    const { limit = 100, offset = 0, domains, minConfidence = 0 } = options;

    let entries = Array.from(this.patterns.values());

    if (domains && domains.length > 0) {
      entries = entries.filter((e) => domains.includes(e.domain));
    }

    entries = entries.filter((e) => e.confidence >= minConfidence);
    entries.sort((a, b) => b.lastSeen - a.lastSeen);

    return {
      entries: entries.slice(offset, offset + limit),
      total: entries.length,
      queryTime: Date.now() - startTime,
    };
  }

  /** Propose a knowledge update (requires consensus) */
  proposeUpdate(update: KnowledgeUpdate): { pendingId: string } {
    const pendingId = generateSecureId();
    this.pendingUpdates.set(pendingId, {
      update,
      approvers: [],
      status: 'pending',
    });

    this.logUpdate(update, 'proposed');
    return { pendingId };
  }

  /** Approve a pending update */
  approveUpdate(pendingId: string, approverId: string): boolean {
    const pending = this.pendingUpdates.get(pendingId);
    if (!pending || pending.status !== 'pending') return false;

    // Check if already approved by this agent
    if (pending.approvers.includes(approverId)) return false;

    pending.approvers.push(approverId);

    // Check if enough approvals
    if (pending.approvers.length >= this.config.minApprovers) {
      this.executeUpdate(pending.update);
      pending.status = 'approved';
      this.logUpdate(pending.update, 'approved');
    }

    return true;
  }

  /** Reject a pending update */
  rejectUpdate(pendingId: string, _rejecterId: string, reason: string): boolean {
    const pending = this.pendingUpdates.get(pendingId);
    if (!pending || pending.status !== 'pending') return false;

    pending.status = 'rejected';
    this.logUpdate({ ...pending.update, reason }, 'rejected');
    return true;
  }

  /** Get pending updates */
  getPendingUpdates(): Array<{ id: string; update: KnowledgeUpdate; approvers: string[] }> {
    return Array.from(this.pendingUpdates.entries())
      .filter(([_, p]) => p.status === 'pending')
      .map(([id, p]) => ({ id, update: p.update, approvers: p.approvers }));
  }

  /** Execute an approved update */
  private executeUpdate(update: KnowledgeUpdate): void {
    tracer.startActiveSpan('knowledge.executeUpdate', (span) => {
      try {
        const entry = update.entry;
        switch (entry.type) {
          case 'embedding':
            const emb = entry as EmbeddingEntry;
            this.vectors.add(emb.vector, emb.domain, emb.metadata, emb.source);
            break;
          case 'rule':
            const rule = entry as RuleEntry;
            this.rules.add(rule.condition, rule.action, rule.domain, rule.priority, rule.source);
            break;
          case 'fingerprint':
            const fp = entry as FingerprintEntry;
            this.fingerprints.add(fp.fingerprint, fp.domain, fp.source);
            break;
          case 'pattern':
            const pat = entry as PatternEntry;
            this.patterns.set(pat.id, pat);
            break;
        }
        span.setStatus({ code: 1 });
      } catch (error) {
        span.setStatus({ code: 2, message: String(error) });
        throw error;
      } finally {
        span.end();
      }
    });
  }

  /** Log update to history */
  private logUpdate(update: KnowledgeUpdate, status: string): void {
    this.updateHistory.append(JSON.stringify({
      timestamp: Date.now(),
      status,
      operation: update.operation,
      entryType: update.entry.type,
      entryId: update.entry.id,
      proposedBy: update.proposedBy,
      reason: update.reason,
    }));
  }

  /** Get knowledge base statistics */
  getStats() {
    return {
      vectors: this.vectors.getStats(),
      rules: this.rules.query({}).total,
      fingerprints: this.fingerprints.getStats(),
      patterns: this.patterns.size,
      pendingUpdates: this.getPendingUpdates().length,
      historyRoot: this.updateHistory.getRoot(),
    };
  }

  /** Export knowledge for sharing */
  export(domains?: KnowledgeDomain[]): {
    embeddings: EmbeddingEntry[];
    rules: RuleEntry[];
    fingerprints: FingerprintEntry[];
    patterns: PatternEntry[];
  } {
    const options: QueryOptions = { domains, limit: this.config.maxEntries };
    
    return {
      embeddings: domains 
        ? domains.flatMap((d) => this.vectors.getByDomain(d))
        : [],
      rules: this.rules.query(options).entries,
      fingerprints: this.fingerprints.query(options).entries,
      patterns: this.queryPatterns(options).entries,
    };
  }
}

/** Create a knowledge base instance */
export function createKnowledgeBase(config?: Partial<KnowledgeBaseConfig>): KnowledgeBase {
  return new KnowledgeBase(config);
}
