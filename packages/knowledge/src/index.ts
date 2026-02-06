/**
 * AI Authority - Knowledge Package
 * 
 * Knowledge base infrastructure for autonomous AI Authority network.
 */

// Types
export * from './types.js';

// Vector store
export { VectorStore, createVectorStore } from './vectors.js';
export type { VectorStoreConfig } from './vectors.js';

// Rule engine
export { RuleEngine, createRuleEngine, createDefaultRules } from './rules.js';
export type { EvaluationContext, EvaluationResult, AggregateResult } from './rules.js';

// Fingerprint library
export { FingerprintLibrary, createFingerprintLibrary } from './fingerprints.js';
export type { FingerprintMatch } from './fingerprints.js';

// Knowledge base
export { KnowledgeBase, createKnowledgeBase } from './base.js';
export type { KnowledgeBaseConfig } from './base.js';
