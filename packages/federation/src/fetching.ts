/**
 * Data Fetching Module
 *
 * Implements the fetching phase of the Data Fetching and Distribution Plan
 * for AI Regulatory Authorities. Supports:
 * - Active fetching (on-demand requests)
 * - Passive fetching (mandatory reporting channels)
 * - Collaborative fetching (joint data collection)
 */

import { generateSecureId, sha256 } from '@ai-authority/core';
import type {
  DataCategory,
  AccessTier,
} from './authority.js';

// ============================================================================
// Types
// ============================================================================

/**
 * Data source types for fetching.
 */
export type DataSourceType =
  | 'internal_audit' // Authority's own audits
  | 'industry_submission' // Mandatory AI impact reports
  | 'public_dataset' // Open-source AI models, public registries
  | 'private_partnership' // Data from private sector partners
  | 'peer_authority' // Data from other regulatory authorities
  | 'api_feed' // Real-time API feeds
  | 'manual_upload'; // Manual data uploads

/**
 * Fetching method classification.
 */
export type FetchingMethod =
  | 'active' // On-demand requests via portal
  | 'passive' // Mandatory reporting channels
  | 'collaborative'; // Joint data collection between authorities

/**
 * Data source configuration.
 */
export interface DataSource {
  /** Unique source ID */
  readonly id: string;

  /** Human-readable name */
  readonly name: string;

  /** Source type */
  readonly type: DataSourceType;

  /** Source endpoint (URL, path, or identifier) */
  readonly endpoint: string;

  /** Authentication method */
  readonly authMethod: 'api_key' | 'oauth2' | 'mtls' | 'none';

  /** Categories of data this source provides */
  readonly dataCategories: DataCategory[];

  /** Access tier required */
  readonly requiredTier: AccessTier;

  /** Trust level (0-1) */
  readonly trustLevel: number;

  /** Update frequency */
  readonly updateFrequency: 'realtime' | 'hourly' | 'daily' | 'weekly' | 'on_demand';

  /** Source status */
  status: 'active' | 'inactive' | 'error' | 'rate_limited';

  /** Last successful fetch */
  lastFetchAt?: Date;

  /** Metadata */
  readonly metadata: Record<string, unknown>;
}

/**
 * Fetch request configuration.
 */
export interface FetchRequest {
  /** Request ID */
  readonly id: string;

  /** Requesting authority */
  readonly requesterId: string;

  /** Fetching method */
  readonly method: FetchingMethod;

  /** Target data sources */
  readonly sourceIds: string[];

  /** Data categories requested */
  readonly categories: DataCategory[];

  /** Filter criteria */
  readonly criteria: FetchCriteria;

  /** Request timestamp */
  readonly requestedAt: Date;

  /** Request expiry */
  readonly expiresAt: Date;

  /** Request status */
  status: 'pending' | 'processing' | 'completed' | 'failed' | 'expired';

  /** Priority level */
  readonly priority: 'low' | 'normal' | 'high' | 'critical';
}

/**
 * Criteria for filtering fetched data.
 */
export interface FetchCriteria {
  /** Time range */
  readonly timeRange?: {
    from: Date;
    to: Date;
  };

  /** Geographic regions */
  readonly regions?: string[];

  /** Severity levels */
  readonly severities?: string[];

  /** Specific categories */
  readonly categories?: DataCategory[];

  /** Keyword search */
  readonly keywords?: string[];

  /** Minimum confidence */
  readonly minConfidence?: number;

  /** Maximum results */
  readonly maxResults?: number;

  /** Custom filters */
  readonly customFilters?: Record<string, unknown>;
}

/**
 * Result of a fetch operation.
 */
export interface FetchResult {
  /** Request ID */
  readonly requestId: string;

  /** Source ID */
  readonly sourceId: string;

  /** Fetch status */
  readonly status: 'success' | 'partial' | 'error';

  /** Fetched data items */
  readonly items: FetchedDataItem[];

  /** Total available (may be more than fetched) */
  readonly totalAvailable: number;

  /** Fetch timestamp */
  readonly fetchedAt: Date;

  /** Duration in ms */
  durationMs: number;

  /** Error message if failed */
  readonly error?: string;

  /** Quality assessment */
  readonly qualityAssessment: DataQualityAssessment;
}

/**
 * A single fetched data item.
 */
export interface FetchedDataItem {
  /** Item ID */
  readonly id: string;

  /** Data category */
  readonly category: DataCategory;

  /** Source ID */
  readonly sourceId: string;

  /** Raw data (will be processed) */
  readonly rawData: unknown;

  /** Metadata */
  readonly metadata: DataItemMetadata;

  /** Original timestamp */
  readonly originalTimestamp: Date;

  /** Fetch timestamp */
  readonly fetchedAt: Date;

  /** Hash for integrity */
  readonly dataHash: string;
}

/**
 * Metadata for fetched data items.
 */
export interface DataItemMetadata {
  /** Data format */
  readonly format: 'json' | 'xml' | 'csv' | 'binary' | 'text';

  /** Size in bytes */
  readonly sizeBytes: number;

  /** Source trust level */
  readonly sourceTrustLevel: number;

  /** Whether data is anonymized */
  readonly isAnonymized: boolean;

  /** Anonymization method used */
  readonly anonymizationMethod?: string;

  /** Originating region */
  readonly originRegion?: string;

  /** Additional metadata */
  readonly custom?: Record<string, unknown>;
}

/**
 * Data quality assessment.
 */
export interface DataQualityAssessment {
  /** Overall quality score (0-1) */
  readonly overallScore: number;

  /** Completeness score (0-1) */
  readonly completeness: number;

  /** Accuracy score (0-1) */
  readonly accuracy: number;

  /** Consistency score (0-1) */
  readonly consistency: number;

  /** Timeliness score (0-1) */
  readonly timeliness: number;

  /** Issues found */
  readonly issues: QualityIssue[];

  /** Recommendations */
  readonly recommendations: string[];
}

/**
 * Quality issue found during assessment.
 */
export interface QualityIssue {
  /** Issue type */
  readonly type: 'missing_field' | 'invalid_format' | 'duplicate' | 'outdated' | 'bias_detected' | 'inconsistent';

  /** Severity */
  readonly severity: 'low' | 'medium' | 'high';

  /** Description */
  readonly description: string;

  /** Affected items */
  readonly affectedCount: number;
}

/**
 * Collaborative fetch session.
 */
export interface CollaborativeFetchSession {
  /** Session ID */
  readonly id: string;

  /** Participating authorities */
  readonly participants: string[];

  /** Coordinating authority */
  readonly coordinatorId: string;

  /** Session purpose */
  readonly purpose: string;

  /** Target data categories */
  readonly targetCategories: DataCategory[];

  /** Shared fetch criteria */
  readonly sharedCriteria: FetchCriteria;

  /** Session status */
  status: 'planning' | 'active' | 'completed' | 'cancelled';

  /** Created at */
  readonly createdAt: Date;

  /** Contributions from participants */
  contributions: CollaborativeContribution[];
}

/**
 * Contribution to a collaborative fetch.
 */
export interface CollaborativeContribution {
  /** Authority ID */
  readonly authorityId: string;

  /** Fetch results contributed */
  readonly resultIds: string[];

  /** Items contributed count */
  readonly itemCount: number;

  /** Contributed at */
  readonly contributedAt: Date;
}

// ============================================================================
// Fetch Configuration
// ============================================================================

export interface FetchingConfig {
  /** Maximum concurrent fetch operations */
  readonly maxConcurrentFetches: number;

  /** Default request timeout in ms */
  readonly requestTimeoutMs: number;

  /** Maximum items per fetch */
  readonly maxItemsPerFetch: number;

  /** Retry configuration */
  readonly retry: {
    maxAttempts: number;
    backoffMs: number;
    backoffMultiplier: number;
  };

  /** Quality thresholds */
  readonly qualityThresholds: {
    minCompleteness: number;
    minAccuracy: number;
    minOverallScore: number;
  };

  /** Rate limiting */
  readonly rateLimiting: {
    requestsPerMinute: number;
    requestsPerHour: number;
  };
}

export const DEFAULT_FETCHING_CONFIG: FetchingConfig = {
  maxConcurrentFetches: 10,
  requestTimeoutMs: 30000,
  maxItemsPerFetch: 1000,
  retry: {
    maxAttempts: 3,
    backoffMs: 1000,
    backoffMultiplier: 2,
  },
  qualityThresholds: {
    minCompleteness: 0.8,
    minAccuracy: 0.9,
    minOverallScore: 0.75,
  },
  rateLimiting: {
    requestsPerMinute: 60,
    requestsPerHour: 1000,
  },
};

// ============================================================================
// Data Fetcher Class
// ============================================================================

/**
 * Manages data fetching operations for regulatory authorities.
 */
export class DataFetcher {
  private readonly config: FetchingConfig;
  private readonly sources: Map<string, DataSource> = new Map();
  private readonly requests: Map<string, FetchRequest> = new Map();
  private readonly results: Map<string, FetchResult[]> = new Map();
  private readonly collaborativeSessions: Map<string, CollaborativeFetchSession> = new Map();
  private activeRequests = 0;
  private requestCounts = { minute: 0, hour: 0 };

  constructor(config: FetchingConfig = DEFAULT_FETCHING_CONFIG) {
    this.config = config;
    this.startRateLimitReset();
  }

  private startRateLimitReset(): void {
    // Reset minute counter
    setInterval(() => {
      this.requestCounts.minute = 0;
    }, 60000);

    // Reset hour counter
    setInterval(() => {
      this.requestCounts.hour = 0;
    }, 3600000);
  }

  /**
   * Register a data source.
   */
  registerSource(config: Omit<DataSource, 'id' | 'status'>): DataSource {
    const source: DataSource = {
      ...config,
      id: generateSecureId(),
      status: 'active',
    };

    this.sources.set(source.id, source);
    return source;
  }

  /**
   * Get all registered sources.
   */
  getSources(): DataSource[] {
    return Array.from(this.sources.values());
  }

  /**
   * Get sources by type.
   */
  getSourcesByType(type: DataSourceType): DataSource[] {
    return Array.from(this.sources.values()).filter((s) => s.type === type);
  }

  /**
   * Get sources providing specific data category.
   */
  getSourcesByCategory(category: DataCategory): DataSource[] {
    return Array.from(this.sources.values()).filter((s) =>
      s.dataCategories.includes(category)
    );
  }

  /**
   * Create an active fetch request (on-demand).
   */
  createActiveFetchRequest(
    requesterId: string,
    sourceIds: string[],
    categories: DataCategory[],
    criteria: FetchCriteria,
    priority: FetchRequest['priority'] = 'normal'
  ): FetchRequest {
    const request: FetchRequest = {
      id: generateSecureId(),
      requesterId,
      method: 'active',
      sourceIds,
      categories,
      criteria,
      requestedAt: new Date(),
      expiresAt: new Date(Date.now() + 86400000), // 24 hours
      status: 'pending',
      priority,
    };

    this.requests.set(request.id, request);
    return request;
  }

  /**
   * Execute a fetch request.
   */
  async executeFetch(requestId: string): Promise<FetchResult[]> {
    const request = this.requests.get(requestId);
    if (!request) {
      throw new Error(`Fetch request not found: ${requestId}`);
    }

    // Check rate limits
    if (!this.checkRateLimits()) {
      throw new Error('Rate limit exceeded');
    }

    // Check concurrent fetch limit
    if (this.activeRequests >= this.config.maxConcurrentFetches) {
      throw new Error('Maximum concurrent fetches reached');
    }

    request.status = 'processing';
    this.activeRequests++;

    const results: FetchResult[] = [];

    try {
      for (const sourceId of request.sourceIds) {
        const source = this.sources.get(sourceId);
        if (!source) continue;

        const startTime = Date.now();
        const result = await this.fetchFromSource(source, request);
        result.durationMs = Date.now() - startTime;

        results.push(result);
        this.requestCounts.minute++;
        this.requestCounts.hour++;
      }

      request.status = 'completed';
      this.results.set(requestId, results);
    } catch (error) {
      request.status = 'failed';
      throw error;
    } finally {
      this.activeRequests--;
    }

    return results;
  }

  /**
   * Fetch from a single source.
   */
  private async fetchFromSource(
    _source: DataSource,
    request: FetchRequest
  ): Promise<FetchResult> {
    // Simulate fetch operation (in production, this would call actual APIs)
    const items = await this.simulateFetch(request.criteria);

    const qualityAssessment = this.assessQuality(items);

    return {
      requestId: request.id,
      sourceId: _source.id,
      status: items.length > 0 ? 'success' : 'partial',
      items,
      totalAvailable: items.length,
      fetchedAt: new Date(),
      durationMs: 0, // Set by caller
      qualityAssessment,
    };
  }

  /**
   * Simulate a fetch operation (placeholder for actual implementations).
   */
  private async simulateFetch(
    _criteria: FetchCriteria
  ): Promise<FetchedDataItem[]> {
    // In production, this would connect to actual data sources
    // For now, return empty array
    return [];
  }

  /**
   * Assess data quality.
   */
  assessQuality(items: FetchedDataItem[]): DataQualityAssessment {
    if (items.length === 0) {
      return {
        overallScore: 0,
        completeness: 0,
        accuracy: 0,
        consistency: 0,
        timeliness: 0,
        issues: [],
        recommendations: ['No data items to assess'],
      };
    }

    const issues: QualityIssue[] = [];
    const recommendations: string[] = [];

    // Calculate completeness
    const fieldsExpected = ['id', 'category', 'sourceId', 'rawData', 'metadata', 'originalTimestamp'];
    let missingFields = 0;
    for (const item of items) {
      for (const field of fieldsExpected) {
        if (!(field in item) || (item as unknown as Record<string, unknown>)[field] === undefined) {
          missingFields++;
        }
      }
    }
    const completeness = 1 - missingFields / (items.length * fieldsExpected.length);

    if (completeness < this.config.qualityThresholds.minCompleteness) {
      issues.push({
        type: 'missing_field',
        severity: 'medium',
        description: `${missingFields} missing fields detected`,
        affectedCount: items.filter((i) =>
          fieldsExpected.some((f) => !(f in i))
        ).length,
      });
      recommendations.push('Ensure all required fields are populated');
    }

    // Check for duplicates
    const hashes = new Set<string>();
    let duplicates = 0;
    for (const item of items) {
      if (hashes.has(item.dataHash)) {
        duplicates++;
      } else {
        hashes.add(item.dataHash);
      }
    }
    const accuracy = 1 - duplicates / items.length;

    if (duplicates > 0) {
      issues.push({
        type: 'duplicate',
        severity: 'low',
        description: `${duplicates} duplicate items detected`,
        affectedCount: duplicates,
      });
      recommendations.push('Remove duplicate entries before processing');
    }

    // Check timeliness
    const now = Date.now();
    const maxAge = 86400000; // 24 hours
    let outdatedCount = 0;
    for (const item of items) {
      if (now - item.originalTimestamp.getTime() > maxAge) {
        outdatedCount++;
      }
    }
    const timeliness = 1 - outdatedCount / items.length;

    if (outdatedCount > 0) {
      issues.push({
        type: 'outdated',
        severity: 'low',
        description: `${outdatedCount} items older than 24 hours`,
        affectedCount: outdatedCount,
      });
    }

    // Calculate consistency (based on metadata coherence)
    const consistency = 0.9; // Simplified for now

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
   * Check rate limits.
   */
  private checkRateLimits(): boolean {
    return (
      this.requestCounts.minute < this.config.rateLimiting.requestsPerMinute &&
      this.requestCounts.hour < this.config.rateLimiting.requestsPerHour
    );
  }

  /**
   * Create a collaborative fetch session.
   */
  createCollaborativeSession(
    coordinatorId: string,
    participants: string[],
    purpose: string,
    targetCategories: DataCategory[],
    sharedCriteria: FetchCriteria
  ): CollaborativeFetchSession {
    const session: CollaborativeFetchSession = {
      id: generateSecureId(),
      participants: [coordinatorId, ...participants],
      coordinatorId,
      purpose,
      targetCategories,
      sharedCriteria,
      status: 'planning',
      createdAt: new Date(),
      contributions: [],
    };

    this.collaborativeSessions.set(session.id, session);
    return session;
  }

  /**
   * Start a collaborative session.
   */
  startCollaborativeSession(sessionId: string): boolean {
    const session = this.collaborativeSessions.get(sessionId);
    if (!session || session.status !== 'planning') return false;

    session.status = 'active';
    return true;
  }

  /**
   * Contribute to a collaborative session.
   */
  contributeToSession(
    sessionId: string,
    authorityId: string,
    resultIds: string[]
  ): boolean {
    const session = this.collaborativeSessions.get(sessionId);
    if (!session || session.status !== 'active') return false;
    if (!session.participants.includes(authorityId)) return false;

    // Calculate total items from results
    let itemCount = 0;
    for (const resultId of resultIds) {
      const results = this.results.get(resultId);
      if (results) {
        for (const result of results) {
          itemCount += result.items.length;
        }
      }
    }

    session.contributions.push({
      authorityId,
      resultIds,
      itemCount,
      contributedAt: new Date(),
    });

    return true;
  }

  /**
   * Complete a collaborative session.
   */
  completeCollaborativeSession(sessionId: string): CollaborativeFetchSession | null {
    const session = this.collaborativeSessions.get(sessionId);
    if (!session || session.status !== 'active') return null;

    session.status = 'completed';
    return session;
  }

  /**
   * Get fetch statistics.
   */
  getStats(): {
    totalSources: number;
    activeSources: number;
    totalRequests: number;
    pendingRequests: number;
    completedRequests: number;
    failedRequests: number;
    activeSessions: number;
  } {
    const sources = Array.from(this.sources.values());
    const requests = Array.from(this.requests.values());
    const sessions = Array.from(this.collaborativeSessions.values());

    return {
      totalSources: sources.length,
      activeSources: sources.filter((s) => s.status === 'active').length,
      totalRequests: requests.length,
      pendingRequests: requests.filter((r) => r.status === 'pending').length,
      completedRequests: requests.filter((r) => r.status === 'completed').length,
      failedRequests: requests.filter((r) => r.status === 'failed').length,
      activeSessions: sessions.filter((s) => s.status === 'active').length,
    };
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Hash data for integrity verification.
 */
export function hashDataItem(data: unknown): string {
  const serialized = JSON.stringify(data, Object.keys(data as object).sort());
  return sha256(serialized);
}

/**
 * Create a FetchedDataItem from raw data.
 */
export function createFetchedDataItem(
  category: DataCategory,
  sourceId: string,
  rawData: unknown,
  metadata: Omit<DataItemMetadata, 'sizeBytes'>,
  originalTimestamp?: Date
): FetchedDataItem {
  const serialized = JSON.stringify(rawData);

  return {
    id: generateSecureId(),
    category,
    sourceId,
    rawData,
    metadata: {
      ...metadata,
      sizeBytes: new TextEncoder().encode(serialized).length,
    },
    originalTimestamp: originalTimestamp || new Date(),
    fetchedAt: new Date(),
    dataHash: sha256(serialized),
  };
}
