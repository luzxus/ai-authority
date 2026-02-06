/**
 * Data Processing Module
 *
 * Implements the processing phase of the Data Fetching and Distribution Plan
 * for AI Regulatory Authorities. Supports:
 * - Data cleaning and standardization
 * - Metadata enrichment
 * - Security and privacy enhancements
 * - Risk assessment and tagging
 */

import { generateSecureId, sha256 } from '@ai-authority/core';
import type { FetchedDataItem, DataQualityAssessment, QualityIssue } from './fetching.js';
import type { AccessTier, DataCategory } from './authority.js';

// ============================================================================
// Types
// ============================================================================

/**
 * Processed data item with enrichment and security enhancements.
 */
export interface ProcessedDataItem {
  /** Original data item ID */
  readonly originalId: string;

  /** Processed item ID */
  readonly id: string;

  /** Data category */
  readonly category: DataCategory;

  /** Cleaned and standardized data */
  readonly cleanedData: unknown;

  /** Enrichment metadata */
  readonly enrichment: DataEnrichment;

  /** Security classification */
  readonly securityClassification: SecurityClassification;

  /** Quality assessment */
  readonly qualityAssessment: DataQualityAssessment;

  /** Processing timestamp */
  readonly processedAt: Date;

  /** Processing audit trail */
  readonly processingAudit: ProcessingAuditEntry[];

  /** Hash for integrity */
  readonly dataHash: string;
}

/**
 * Metadata enrichment for processed data.
 */
export interface DataEnrichment {
  /** Timestamp when data was created at source */
  readonly sourceTimestamp: Date;

  /** Source identifier */
  readonly sourceId: string;

  /** Origin region */
  readonly originRegion: string;

  /** Data format */
  readonly format: string;

  /** Schema version */
  readonly schemaVersion: string;

  /** Derived tags */
  readonly tags: string[];

  /** Related entity IDs */
  readonly relatedEntities: string[];

  /** Confidence score */
  readonly confidence: number;

  /** Custom enrichment fields */
  readonly custom: Record<string, unknown>;
}

/**
 * Security classification for data items.
 */
export interface SecurityClassification {
  /** Access tier required */
  readonly accessTier: AccessTier;

  /** Sensitivity level */
  readonly sensitivityLevel: SensitivityLevel;

  /** Encryption status */
  readonly encryptionStatus: EncryptionStatus;

  /** Privacy assessment */
  readonly privacyAssessment: PrivacyAssessment;

  /** Risk tags */
  readonly riskTags: RiskTag[];

  /** Handling instructions */
  readonly handlingInstructions: string[];

  /** Retention policy */
  readonly retentionPolicy: RetentionPolicy;
}

/**
 * Sensitivity levels for data.
 */
export type SensitivityLevel =
  | 'public' // Can be freely shared
  | 'internal' // Authority internal use
  | 'confidential' // Limited sharing with agreements
  | 'restricted' // Highly sensitive, need-to-know
  | 'classified'; // Critical infrastructure, maximum protection

/**
 * Encryption status.
 */
export interface EncryptionStatus {
  /** Is data encrypted at rest */
  readonly encryptedAtRest: boolean;

  /** Encryption algorithm */
  readonly algorithm?: string;

  /** Key ID reference */
  readonly keyId?: string;

  /** Encrypted fields (if partial encryption) */
  readonly encryptedFields?: string[];
}

/**
 * Privacy assessment results.
 */
export interface PrivacyAssessment {
  /** Contains personally identifiable information */
  readonly containsPII: boolean;

  /** PII types detected */
  readonly piiTypes: PIIType[];

  /** Anonymization applied */
  readonly anonymizationApplied: boolean;

  /** Anonymization techniques used */
  readonly anonymizationTechniques: AnonymizationTechnique[];

  /** De-identification completeness score (0-1) */
  readonly deIdentificationScore: number;

  /** Privacy compliance status */
  readonly complianceStatus: ComplianceStatus[];
}

/**
 * Types of personally identifiable information.
 */
export type PIIType =
  | 'name'
  | 'email'
  | 'phone'
  | 'address'
  | 'ip_address'
  | 'device_id'
  | 'location'
  | 'financial'
  | 'health'
  | 'biometric'
  | 'social_security'
  | 'other';

/**
 * Anonymization techniques.
 */
export type AnonymizationTechnique =
  | 'hashing'
  | 'tokenization'
  | 'generalization'
  | 'suppression'
  | 'noise_addition'
  | 'differential_privacy'
  | 'k_anonymity'
  | 'l_diversity'
  | 't_closeness';

/**
 * Compliance status.
 */
export interface ComplianceStatus {
  /** Regulation (e.g., GDPR, HIPAA, CCPA) */
  readonly regulation: string;

  /** Compliance level */
  readonly status: 'compliant' | 'partial' | 'non_compliant' | 'not_applicable';

  /** Notes */
  readonly notes?: string;
}

/**
 * Risk tags for data items.
 */
export interface RiskTag {
  /** Tag type */
  readonly type: 'bias' | 'vulnerability' | 'poisoning' | 'staleness' | 'incomplete' | 'sensitive';

  /** Severity */
  readonly severity: 'low' | 'medium' | 'high' | 'critical';

  /** Description */
  readonly description: string;

  /** Mitigation recommendations */
  readonly mitigation?: string;
}

/**
 * Retention policy for data.
 */
export interface RetentionPolicy {
  /** Retention period in days */
  readonly retentionDays: number;

  /** Auto-delete enabled */
  readonly autoDelete: boolean;

  /** Archive after days */
  readonly archiveAfterDays?: number;

  /** Legal hold status */
  readonly legalHold: boolean;

  /** Expiration date */
  readonly expiresAt: Date;
}

/**
 * Processing audit entry.
 */
export interface ProcessingAuditEntry {
  /** Audit entry ID */
  readonly id: string;

  /** Operation performed */
  readonly operation: ProcessingOperation;

  /** Timestamp */
  readonly timestamp: Date;

  /** Details */
  readonly details: string;

  /** Fields affected */
  readonly affectedFields?: string[];

  /** Previous hash (for change tracking) */
  readonly previousHash?: string;

  /** New hash */
  readonly newHash: string;
}

/**
 * Processing operations.
 */
export type ProcessingOperation =
  | 'ingest'
  | 'validate'
  | 'clean'
  | 'normalize'
  | 'enrich'
  | 'anonymize'
  | 'encrypt'
  | 'classify'
  | 'tag'
  | 'transform';

// ============================================================================
// Processing Configuration
// ============================================================================

export interface ProcessingConfig {
  /** Enable automatic PII detection */
  readonly enablePIIDetection: boolean;

  /** Enable automatic anonymization */
  readonly enableAutoAnonymization: boolean;

  /** Anonymization techniques to apply */
  readonly anonymizationTechniques: AnonymizationTechnique[];

  /** Default sensitivity level */
  readonly defaultSensitivityLevel: SensitivityLevel;

  /** Default retention days */
  readonly defaultRetentionDays: number;

  /** Compliance regulations to check */
  readonly complianceRegulations: string[];

  /** Risk assessment thresholds */
  readonly riskThresholds: {
    biasThreshold: number;
    stalenessThresholdHours: number;
    completenessThreshold: number;
  };

  /** Schema validation enabled */
  readonly enableSchemaValidation: boolean;

  /** Maximum processing time per item in ms */
  readonly maxProcessingTimeMs: number;
}

export const DEFAULT_PROCESSING_CONFIG: ProcessingConfig = {
  enablePIIDetection: true,
  enableAutoAnonymization: true,
  anonymizationTechniques: ['hashing', 'differential_privacy', 'k_anonymity'],
  defaultSensitivityLevel: 'internal',
  defaultRetentionDays: 365,
  complianceRegulations: ['GDPR', 'CCPA'],
  riskThresholds: {
    biasThreshold: 0.1,
    stalenessThresholdHours: 24,
    completenessThreshold: 0.8,
  },
  enableSchemaValidation: true,
  maxProcessingTimeMs: 5000,
};

// ============================================================================
// Data Processor Class
// ============================================================================

/**
 * Processes fetched data with cleaning, enrichment, and security enhancements.
 */
export class DataProcessor {
  private readonly config: ProcessingConfig;
  private readonly processedItems: Map<string, ProcessedDataItem> = new Map();

  constructor(config: ProcessingConfig = DEFAULT_PROCESSING_CONFIG) {
    this.config = config;
  }

  /**
   * Process a batch of fetched data items.
   */
  async processBatch(items: FetchedDataItem[]): Promise<ProcessedDataItem[]> {
    const results: ProcessedDataItem[] = [];

    for (const item of items) {
      const processed = await this.processItem(item);
      results.push(processed);
      this.processedItems.set(processed.id, processed);
    }

    return results;
  }

  /**
   * Process a single data item.
   */
  async processItem(item: FetchedDataItem): Promise<ProcessedDataItem> {
    const audit: ProcessingAuditEntry[] = [];

    // 1. Ingest and validate
    const ingestHash = sha256(JSON.stringify(item.rawData));
    audit.push(this.createAuditEntry('ingest', 'Data item received for processing', ingestHash));

    // 2. Clean the data
    const cleanedData = await this.cleanData(item.rawData, item.metadata.format);
    const cleanedHash = sha256(JSON.stringify(cleanedData));
    audit.push(this.createAuditEntry('clean', 'Data cleaned and standardized', cleanedHash, ingestHash));

    // 3. Enrich with metadata
    const enrichment = await this.enrichData(item, cleanedData);
    audit.push(this.createAuditEntry('enrich', 'Metadata enrichment applied', cleanedHash));

    // 4. Privacy assessment
    const privacyAssessment = await this.assessPrivacy(cleanedData);

    // 5. Apply anonymization if needed
    let finalData = cleanedData;
    if (this.config.enableAutoAnonymization && privacyAssessment.containsPII) {
      finalData = await this.anonymizeData(cleanedData, privacyAssessment.piiTypes);
      const anonymizedHash = sha256(JSON.stringify(finalData));
      audit.push(this.createAuditEntry('anonymize', `PII anonymized: ${privacyAssessment.piiTypes.join(', ')}`, anonymizedHash, cleanedHash));
    }

    // 6. Security classification
    const securityClassification = await this.classifyData(item, privacyAssessment);
    audit.push(this.createAuditEntry('classify', `Classified as ${securityClassification.sensitivityLevel}`, sha256(JSON.stringify(finalData))));

    // 7. Risk assessment
    const riskTags = await this.assessRisks(item, cleanedData, privacyAssessment);
    if (riskTags.length > 0) {
      audit.push(this.createAuditEntry('tag', `Risk tags applied: ${riskTags.map(t => t.type).join(', ')}`, sha256(JSON.stringify(finalData))));
    }

    // 8. Quality assessment
    const qualityAssessment = this.assessProcessedQuality(finalData, item);

    const finalHash = sha256(JSON.stringify(finalData));

    const processed: ProcessedDataItem = {
      originalId: item.id,
      id: generateSecureId(),
      category: item.category,
      cleanedData: finalData,
      enrichment,
      securityClassification: {
        ...securityClassification,
        riskTags,
      },
      qualityAssessment,
      processedAt: new Date(),
      processingAudit: audit,
      dataHash: finalHash,
    };

    return processed;
  }

  /**
   * Clean and standardize data.
   */
  private async cleanData(rawData: unknown, _format: string): Promise<unknown> {
    if (rawData === null || rawData === undefined) {
      return {};
    }

    if (typeof rawData !== 'object') {
      return rawData;
    }

    const cleaned = JSON.parse(JSON.stringify(rawData));

    // Remove null and undefined values
    this.removeNullValues(cleaned);

    // Normalize string values (trim, lowercase where appropriate)
    this.normalizeStrings(cleaned);

    // Standardize date formats
    this.normalizeDates(cleaned);

    return cleaned;
  }

  private removeNullValues(obj: Record<string, unknown>): void {
    for (const key of Object.keys(obj)) {
      if (obj[key] === null || obj[key] === undefined) {
        delete obj[key];
      } else if (typeof obj[key] === 'object' && !Array.isArray(obj[key])) {
        this.removeNullValues(obj[key] as Record<string, unknown>);
      }
    }
  }

  private normalizeStrings(obj: Record<string, unknown>): void {
    for (const key of Object.keys(obj)) {
      if (typeof obj[key] === 'string') {
        obj[key] = (obj[key] as string).trim();
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        if (Array.isArray(obj[key])) {
          obj[key] = (obj[key] as unknown[]).map((v) =>
            typeof v === 'string' ? v.trim() : v
          );
        } else {
          this.normalizeStrings(obj[key] as Record<string, unknown>);
        }
      }
    }
  }

  private normalizeDates(obj: Record<string, unknown>): void {
    const dateKeys = ['timestamp', 'date', 'created', 'modified', 'updated', 'expires'];
    for (const key of Object.keys(obj)) {
      if (dateKeys.some((dk) => key.toLowerCase().includes(dk))) {
        if (typeof obj[key] === 'string' || typeof obj[key] === 'number') {
          const date = new Date(obj[key] as string | number);
          if (!isNaN(date.getTime())) {
            obj[key] = date.toISOString();
          }
        }
      } else if (typeof obj[key] === 'object' && obj[key] !== null && !Array.isArray(obj[key])) {
        this.normalizeDates(obj[key] as Record<string, unknown>);
      }
    }
  }

  /**
   * Enrich data with metadata.
   */
  private async enrichData(item: FetchedDataItem, cleanedData: unknown): Promise<DataEnrichment> {
    const tags = this.deriveTags(cleanedData, item.category);
    const relatedEntities = this.extractRelatedEntities(cleanedData);

    return {
      sourceTimestamp: item.originalTimestamp,
      sourceId: item.sourceId,
      originRegion: item.metadata.originRegion || 'unknown',
      format: item.metadata.format,
      schemaVersion: '1.0.0',
      tags,
      relatedEntities,
      confidence: item.metadata.sourceTrustLevel,
      custom: {},
    };
  }

  private deriveTags(data: unknown, category: DataCategory): string[] {
    const tags: string[] = [category];

    if (typeof data === 'object' && data !== null) {
      const obj = data as Record<string, unknown>;

      // Add severity tags
      if ('severity' in obj) {
        tags.push(`severity:${obj.severity}`);
      }

      // Add type tags
      if ('type' in obj) {
        tags.push(`type:${obj.type}`);
      }

      // Add status tags
      if ('status' in obj) {
        tags.push(`status:${obj.status}`);
      }
    }

    return tags;
  }

  private extractRelatedEntities(data: unknown): string[] {
    const entities: string[] = [];

    if (typeof data === 'object' && data !== null) {
      const obj = data as Record<string, unknown>;

      // Extract IDs
      const idFields = ['agentId', 'modelId', 'userId', 'caseId', 'signalId', 'incidentId'];
      for (const field of idFields) {
        if (field in obj && typeof obj[field] === 'string') {
          entities.push(obj[field] as string);
        }
      }
    }

    return entities;
  }

  /**
   * Assess data for privacy concerns.
   */
  private async assessPrivacy(data: unknown): Promise<PrivacyAssessment> {
    const piiTypes: PIIType[] = [];
    let containsPII = false;

    if (typeof data === 'object' && data !== null) {
      const jsonStr = JSON.stringify(data).toLowerCase();

      // Simple PII detection patterns
      const piiPatterns: Record<PIIType, RegExp> = {
        email: /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i,
        phone: /\+?[\d\s-]{10,}/,
        ip_address: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
        social_security: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/,
        name: /"(first_?name|last_?name|full_?name)":/i,
        address: /"(street|city|zip|postal|address)":/i,
        device_id: /"(device_?id|imei|udid)":/i,
        location: /"(latitude|longitude|lat|lng|location)":/i,
        financial: /"(credit_?card|bank_?account|iban|routing)":/i,
        health: /"(diagnosis|medication|health|medical)":/i,
        biometric: /"(fingerprint|face_?id|retina|voice_?print)":/i,
        other: /never_match_placeholder/,
      };

      for (const [type, pattern] of Object.entries(piiPatterns)) {
        if (pattern.test(jsonStr)) {
          piiTypes.push(type as PIIType);
          containsPII = true;
        }
      }
    }

    const complianceStatus: ComplianceStatus[] = this.config.complianceRegulations.map((reg) => ({
      regulation: reg,
      status: containsPII && !this.config.enableAutoAnonymization ? 'partial' : 'compliant',
    }));

    return {
      containsPII,
      piiTypes,
      anonymizationApplied: false, // Will be set after anonymization
      anonymizationTechniques: [],
      deIdentificationScore: containsPII ? 0 : 1,
      complianceStatus,
    };
  }

  /**
   * Anonymize data containing PII.
   */
  private async anonymizeData(data: unknown, piiTypes: PIIType[]): Promise<unknown> {
    if (typeof data !== 'object' || data === null) {
      return data;
    }

    const anonymized = JSON.parse(JSON.stringify(data));
    this.anonymizeObject(anonymized, piiTypes);
    return anonymized;
  }

  private anonymizeObject(obj: Record<string, unknown>, piiTypes: PIIType[]): void {
    for (const key of Object.keys(obj)) {
      const value = obj[key];

      if (typeof value === 'string') {
        // Check if this field might contain PII
        if (this.isPIIField(key, value, piiTypes)) {
          obj[key] = this.hashValue(value);
        }
      } else if (typeof value === 'object' && value !== null) {
        if (Array.isArray(value)) {
          obj[key] = value.map((v) => {
            if (typeof v === 'string' && this.isPIIField(key, v, piiTypes)) {
              return this.hashValue(v);
            } else if (typeof v === 'object' && v !== null) {
              this.anonymizeObject(v as Record<string, unknown>, piiTypes);
              return v;
            }
            return v;
          });
        } else {
          this.anonymizeObject(value as Record<string, unknown>, piiTypes);
        }
      }
    }
  }

  private isPIIField(key: string, value: string, piiTypes: PIIType[]): boolean {
    const lowerKey = key.toLowerCase();

    // Check by field name
    const piiFieldPatterns: Record<string, PIIType> = {
      email: 'email',
      phone: 'phone',
      mobile: 'phone',
      name: 'name',
      first_name: 'name',
      last_name: 'name',
      address: 'address',
      street: 'address',
      city: 'address',
      ip: 'ip_address',
      ip_address: 'ip_address',
      ssn: 'social_security',
      social_security: 'social_security',
      device_id: 'device_id',
      imei: 'device_id',
    };

    for (const [pattern, type] of Object.entries(piiFieldPatterns)) {
      if (lowerKey.includes(pattern) && piiTypes.includes(type)) {
        return true;
      }
    }

    // Check by value pattern (email regex)
    if (piiTypes.includes('email') && /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i.test(value)) {
      return true;
    }

    return false;
  }

  private hashValue(value: string): string {
    return `[REDACTED:${sha256(value).substring(0, 8)}]`;
  }

  /**
   * Classify data for security.
   */
  private async classifyData(
    _item: FetchedDataItem,
    privacy: PrivacyAssessment
  ): Promise<Omit<SecurityClassification, 'riskTags'>> {
    // Determine sensitivity level based on content
    let sensitivityLevel: SensitivityLevel = this.config.defaultSensitivityLevel;

    if (privacy.containsPII && privacy.piiTypes.length > 3) {
      sensitivityLevel = 'restricted';
    } else if (privacy.containsPII) {
      sensitivityLevel = 'confidential';
    }

    // Map sensitivity to access tier
    const tierMapping: Record<SensitivityLevel, AccessTier> = {
      public: 'public',
      internal: 'restricted',
      confidential: 'confidential',
      restricted: 'classified',
      classified: 'classified',
    };

    const handlingInstructions: string[] = [];
    if (privacy.containsPII) {
      handlingInstructions.push('Handle according to privacy regulations');
      handlingInstructions.push('Do not share without data sharing agreement');
    }

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + this.config.defaultRetentionDays);

    return {
      accessTier: tierMapping[sensitivityLevel],
      sensitivityLevel,
      encryptionStatus: {
        encryptedAtRest: true,
        algorithm: 'AES-256-GCM',
      },
      privacyAssessment: {
        ...privacy,
        anonymizationApplied: this.config.enableAutoAnonymization && privacy.containsPII,
        anonymizationTechniques: this.config.enableAutoAnonymization && privacy.containsPII
          ? this.config.anonymizationTechniques
          : [],
        deIdentificationScore: this.config.enableAutoAnonymization && privacy.containsPII ? 0.95 : privacy.deIdentificationScore,
      },
      handlingInstructions,
      retentionPolicy: {
        retentionDays: this.config.defaultRetentionDays,
        autoDelete: true,
        legalHold: false,
        expiresAt,
      },
    };
  }

  /**
   * Assess risks in data.
   */
  private async assessRisks(
    item: FetchedDataItem,
    data: unknown,
    privacy: PrivacyAssessment
  ): Promise<RiskTag[]> {
    const risks: RiskTag[] = [];

    // Check staleness
    const ageHours = (Date.now() - item.originalTimestamp.getTime()) / 3600000;
    if (ageHours > this.config.riskThresholds.stalenessThresholdHours) {
      risks.push({
        type: 'staleness',
        severity: ageHours > 72 ? 'high' : 'medium',
        description: `Data is ${Math.round(ageHours)} hours old`,
        mitigation: 'Verify data is still relevant before use',
      });
    }

    // Check for PII that wasn't anonymized
    if (privacy.containsPII && !this.config.enableAutoAnonymization) {
      risks.push({
        type: 'sensitive',
        severity: 'high',
        description: `Contains PII types: ${privacy.piiTypes.join(', ')}`,
        mitigation: 'Enable auto-anonymization or manually redact PII',
      });
    }

    // Check data completeness
    if (typeof data === 'object' && data !== null) {
      const obj = data as Record<string, unknown>;
      const totalFields = Object.keys(obj).length;
      const emptyFields = Object.values(obj).filter((v) => v === '' || v === undefined || v === null).length;
      const completeness = totalFields > 0 ? 1 - emptyFields / totalFields : 0;

      if (completeness < this.config.riskThresholds.completenessThreshold) {
        risks.push({
          type: 'incomplete',
          severity: 'medium',
          description: `Data completeness: ${Math.round(completeness * 100)}%`,
          mitigation: 'Consider supplementing with additional data sources',
        });
      }
    }

    return risks;
  }

  /**
   * Assess quality of processed data.
   */
  private assessProcessedQuality(data: unknown, original: FetchedDataItem): DataQualityAssessment {
    const issues: QualityIssue[] = [];
    const recommendations: string[] = [];

    let completeness = 1;
    let accuracy = 1;
    let consistency = 1;
    let timeliness = 1;

    // Check timeliness
    const ageHours = (Date.now() - original.originalTimestamp.getTime()) / 3600000;
    if (ageHours > 24) {
      timeliness = Math.max(0, 1 - (ageHours - 24) / 168); // Decay over a week
    }

    // Check data presence
    if (!data || (typeof data === 'object' && Object.keys(data as object).length === 0)) {
      completeness = 0;
      issues.push({
        type: 'missing_field' as const,
        severity: 'high',
        description: 'Data is empty after processing',
        affectedCount: 1,
      });
    }

    const overallScore = (completeness + accuracy + consistency + timeliness) / 4;

    return {
      overallScore,
      completeness,
      accuracy,
      consistency,
      timeliness,
      issues,
      recommendations,
    };
  }

  /**
   * Create an audit entry.
   */
  private createAuditEntry(
    operation: ProcessingOperation,
    details: string,
    newHash: string,
    previousHash?: string
  ): ProcessingAuditEntry {
    return {
      id: generateSecureId(),
      operation,
      timestamp: new Date(),
      details,
      newHash,
      ...(previousHash !== undefined && { previousHash }),
    };
  }

  /**
   * Get processed item by ID.
   */
  getProcessedItem(id: string): ProcessedDataItem | undefined {
    return this.processedItems.get(id);
  }

  /**
   * Get all processed items.
   */
  getAllProcessedItems(): ProcessedDataItem[] {
    return Array.from(this.processedItems.values());
  }

  /**
   * Get items by access tier.
   */
  getItemsByAccessTier(tier: AccessTier): ProcessedDataItem[] {
    return Array.from(this.processedItems.values()).filter(
      (item) => item.securityClassification.accessTier === tier
    );
  }

  /**
   * Get processing statistics.
   */
  getStats(): {
    totalProcessed: number;
    byCategory: Record<string, number>;
    byAccessTier: Record<AccessTier, number>;
    bySensitivity: Record<SensitivityLevel, number>;
    avgQualityScore: number;
    itemsWithRisks: number;
  } {
    const items = Array.from(this.processedItems.values());

    const byCategory: Record<string, number> = {};
    const byAccessTier: Record<AccessTier, number> = {
      public: 0,
      restricted: 0,
      confidential: 0,
      classified: 0,
    };
    const bySensitivity: Record<SensitivityLevel, number> = {
      public: 0,
      internal: 0,
      confidential: 0,
      restricted: 0,
      classified: 0,
    };

    let totalQuality = 0;
    let itemsWithRisks = 0;

    for (const item of items) {
      byCategory[item.category] = (byCategory[item.category] || 0) + 1;
      byAccessTier[item.securityClassification.accessTier]++;
      bySensitivity[item.securityClassification.sensitivityLevel]++;
      totalQuality += item.qualityAssessment.overallScore;

      if (item.securityClassification.riskTags.length > 0) {
        itemsWithRisks++;
      }
    }

    return {
      totalProcessed: items.length,
      byCategory,
      byAccessTier,
      bySensitivity,
      avgQualityScore: items.length > 0 ? totalQuality / items.length : 0,
      itemsWithRisks,
    };
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Apply differential privacy to a numeric value.
 */
export function applyDifferentialPrivacy(value: number, epsilon: number, sensitivity: number = 1): number {
  // Laplace mechanism
  const scale = sensitivity / epsilon;
  const u = Math.random() - 0.5;
  const noise = -scale * Math.sign(u) * Math.log(1 - 2 * Math.abs(u));
  return value + noise;
}

/**
 * Apply k-anonymity by generalizing data.
 */
export function applyKAnonymity<T extends Record<string, unknown>>(
  records: T[],
  quasiIdentifiers: string[],
  k: number
): T[] {
  // Group records by quasi-identifiers
  const groups = new Map<string, T[]>();

  for (const record of records) {
    const key = quasiIdentifiers.map((qi) => String(record[qi] || '')).join('|');
    const group = groups.get(key) || [];
    group.push(record);
    groups.set(key, group);
  }

  // Generalize groups smaller than k
  const result: T[] = [];
  for (const [, group] of groups) {
    if (group.length >= k) {
      result.push(...group);
    } else {
      // Suppress small groups
      for (const record of group) {
        const suppressed = { ...record };
        for (const qi of quasiIdentifiers) {
          (suppressed as Record<string, unknown>)[qi] = '*';
        }
        result.push(suppressed);
      }
    }
  }

  return result;
}
