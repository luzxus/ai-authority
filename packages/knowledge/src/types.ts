/**
 * Knowledge Types
 * 
 * Type definitions for the knowledge base system.
 */

/** Knowledge entry types */
export type KnowledgeType =
  | 'embedding'           // Vector embedding for semantic search
  | 'rule'                // Decision rule (threshold-based)
  | 'pattern'             // Behavioral pattern
  | 'fingerprint'         // Model fingerprint
  | 'signature'           // Code/API signature
  | 'incident'            // Historical incident record
  | 'template';           // Prompt template or skill module

/** Knowledge domain categories */
export type KnowledgeDomain =
  | 'malicious_patterns'  // Known malicious behaviors
  | 'api_misuse'          // API abuse patterns
  | 'obfuscation'         // Obfuscation techniques
  | 'evasion'             // Evasion tactics
  | 'model_fingerprints'  // Model identification
  | 'incident_history'    // Past incidents
  | 'intervention_rules'; // Intervention decision rules

/** Base knowledge entry */
export interface KnowledgeEntry {
  id: string;
  type: KnowledgeType;
  domain: KnowledgeDomain;
  version: number;
  createdAt: number;
  updatedAt: number;
  createdBy: string;       // Agent ID or 'bootstrap'
  source: KnowledgeSource;
  confidence: number;      // 0-1, confidence in accuracy
  validatedAt?: number | undefined;
  validatedBy?: string | undefined;
}

/** Knowledge source */
export interface KnowledgeSource {
  type: 'bootstrap' | 'learned' | 'proposed' | 'external';
  origin: string;          // Dataset name, agent ID, or external URL
  provenance: string[];    // Chain of derivation
  hash: string;            // Content hash for verification
}

/** Vector embedding entry */
export interface EmbeddingEntry extends KnowledgeEntry {
  type: 'embedding';
  vector: number[];        // Embedding vector
  dimensions: number;
  model: string;           // Embedding model used
  text?: string | undefined;           // Original text (if applicable)
  metadata: Record<string, unknown>;
}

/** Decision rule entry */
export interface RuleEntry extends KnowledgeEntry {
  type: 'rule';
  condition: RuleCondition;
  action: RuleAction;
  priority: number;
  enabled: boolean;
}

/** Rule condition */
export interface RuleCondition {
  type: 'threshold' | 'composite' | 'pattern';
  field?: string | undefined;
  operator?: 'gt' | 'gte' | 'lt' | 'lte' | 'eq' | 'neq' | 'contains' | 'matches' | undefined;
  value?: unknown | undefined;
  children?: RuleCondition[] | undefined;
  logic?: 'and' | 'or' | 'not' | undefined;
}

/** Rule action */
export interface RuleAction {
  type: 'classify' | 'score' | 'alert' | 'intervene' | 'log';
  parameters: Record<string, unknown>;
}

/** Behavioral pattern entry */
export interface PatternEntry extends KnowledgeEntry {
  type: 'pattern';
  pattern: BehaviorPattern;
  frequency: number;       // How often observed
  lastSeen: number;
}

/** Behavior pattern */
export interface BehaviorPattern {
  name: string;
  description: string;
  indicators: PatternIndicator[];
  severity: 'low' | 'medium' | 'high' | 'critical';
  classification: 'malicious' | 'negligent' | 'competitive' | 'unknown';
}

/** Pattern indicator */
export interface PatternIndicator {
  type: 'api_call' | 'data_flow' | 'timing' | 'output' | 'resource';
  signature: string;
  weight: number;
}

/** Model fingerprint entry */
export interface FingerprintEntry extends KnowledgeEntry {
  type: 'fingerprint';
  fingerprint: ModelFingerprint;
}

/** Model fingerprint */
export interface ModelFingerprint {
  hash: string;            // Perceptual hash
  activationPattern: number[]; // Characteristic activation pattern
  probeResponses: ProbeResponse[];
  architecture?: string | undefined;
  estimatedParameters?: number | undefined;
  knownAliases: string[];
}

/** Probe response for fingerprinting */
export interface ProbeResponse {
  probeId: string;
  input: string;
  outputHash: string;
  characteristics: Record<string, number>;
}

/** Code/API signature entry */
export interface SignatureEntry extends KnowledgeEntry {
  type: 'signature';
  signature: CodeSignature;
}

/** Code signature */
export interface CodeSignature {
  type: 'api_sequence' | 'code_pattern' | 'data_pattern';
  pattern: string;         // Regex or structured pattern
  context: string[];
  riskLevel: number;       // 0-1
}

/** Historical incident entry */
export interface IncidentEntry extends KnowledgeEntry {
  type: 'incident';
  incident: IncidentRecord;
}

/** Incident record */
export interface IncidentRecord {
  timestamp: number;
  description: string;
  actors: string[];
  victims: string[];
  impact: ImpactMetrics;
  resolution: string;
  lessonsLearned: string[];
  relatedPatterns: string[]; // Pattern entry IDs
}

/** Impact metrics */
export interface ImpactMetrics {
  economic: number;
  usersAffected: number;
  systemsCompromised: number;
  dataExfiltrated: boolean;
  serviceDisruption: number; // Hours
}

/** Query options */
export interface QueryOptions {
  limit?: number | undefined;
  offset?: number | undefined;
  minConfidence?: number | undefined;
  domains?: KnowledgeDomain[] | undefined;
  types?: KnowledgeType[] | undefined;
  createdAfter?: number | undefined;
  createdBefore?: number | undefined;
}

/** Vector query options */
export interface VectorQueryOptions extends QueryOptions {
  vector: number[];
  threshold?: number | undefined;      // Minimum similarity score
  metric?: 'cosine' | 'euclidean' | 'dot' | undefined;
}

/** Query result */
export interface QueryResult<T extends KnowledgeEntry = KnowledgeEntry> {
  entries: T[];
  total: number;
  queryTime: number;
}

/** Vector query result */
export interface VectorQueryResult<T extends KnowledgeEntry = KnowledgeEntry> {
  matches: Array<{ entry: T; score: number }>;
  queryTime: number;
}

/** Knowledge update */
export interface KnowledgeUpdate {
  operation: 'create' | 'update' | 'delete';
  entry: KnowledgeEntry;
  reason: string;
  proposedBy: string;
  approvedBy?: string[] | undefined;
  timestamp: number;
}
