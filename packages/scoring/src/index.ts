/**
 * AI Authority Scoring Package
 *
 * Risk scoring engine implementing the blueprint's scoring algorithm.
 */

export * from './engine.js';
export * from './metrics.js';

export { ForensicAgent } from './forensic.js';
export type {
  AttributionTarget,
  ForensicEvidence,
  CustodyRecord,
  AttributionResult,
  AttributionCandidate,
  ObfuscationFinding,
  ReasoningStep,
  ObfuscationTechnique,
} from './forensic.js';
