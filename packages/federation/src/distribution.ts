/**
 * Data Distribution Module
 *
 * Implements the distribution phase of the Data Fetching and Distribution Plan
 * for AI Regulatory Authorities. Supports:
 * - Push model (proactive distribution)
 * - Pull model (query-based access)
 * - Hybrid model (event-driven notifications)
 * - Multi-tier access control
 */

import { generateSecureId, sha256 } from '@ai-authority/core';
import type {
  DataCategory,
  AccessTier,
} from './authority.js';
import type { ProcessedDataItem } from './processing.js';

// ============================================================================
// Types
// ============================================================================

/**
 * Distribution model types.
 */
export type DistributionModel = 'push' | 'pull' | 'hybrid';

/**
 * Distribution channel configuration.
 */
export interface DistributionChannel {
  /** Channel ID */
  readonly id: string;

  /** Channel name */
  readonly name: string;

  /** Distribution model */
  readonly model: DistributionModel;

  /** Supported data categories */
  readonly supportedCategories: DataCategory[];

  /** Required access tier */
  readonly requiredTier: AccessTier;

  /** Channel endpoint */
  readonly endpoint: string;

  /** Channel protocol */
  readonly protocol: 'https' | 'wss' | 'grpc' | 'amqp';

  /** Encryption required */
  readonly encryptionRequired: boolean;

  /** Active subscriptions */
  readonly subscriptionCount: number;

  /** Channel status */
  status: 'active' | 'inactive' | 'maintenance';

  /** Created at */
  readonly createdAt: Date;
}

/**
 * Distribution request (for pull model).
 */
export interface DistributionRequest {
  /** Request ID */
  readonly id: string;

  /** Requesting authority ID */
  readonly requesterId: string;

  /** Request timestamp */
  readonly requestedAt: Date;

  /** Data categories requested */
  readonly categories: DataCategory[];

  /** Filter criteria */
  readonly criteria: DistributionCriteria;

  /** Pagination */
  readonly pagination: {
    page: number;
    limit: number;
  };

  /** Request status */
  status: 'pending' | 'approved' | 'rejected' | 'fulfilled' | 'expired';

  /** Approval details */
  approval?: RequestApproval;
}

/**
 * Filter criteria for distribution requests.
 */
export interface DistributionCriteria {
  /** Time range */
  readonly timeRange?: {
    from: Date;
    to: Date;
  };

  /** Geographic regions */
  readonly regions?: string[];

  /** Minimum quality score */
  readonly minQualityScore?: number;

  /** Maximum access tier (requester's tier) */
  readonly maxAccessTier: AccessTier;

  /** Tags to filter by */
  readonly tags?: string[];

  /** Custom filters */
  readonly customFilters?: Record<string, unknown>;
}

/**
 * Request approval record.
 */
export interface RequestApproval {
  /** Approver authority ID */
  readonly approverId: string;

  /** Approval timestamp */
  readonly approvedAt: Date;

  /** Approval notes */
  readonly notes?: string;

  /** Conditions attached */
  readonly conditions?: string[];

  /** Expiry of approval */
  readonly expiresAt: Date;
}

/**
 * Distribution event (for push/hybrid models).
 */
export interface DistributionEvent {
  /** Event ID */
  readonly id: string;

  /** Event type */
  readonly type: DistributionEventType;

  /** Source authority ID */
  readonly sourceId: string;

  /** Target authority IDs (or 'broadcast') */
  readonly targetIds: string[] | 'broadcast';

  /** Data items being distributed */
  readonly dataItemIds: string[];

  /** Event priority */
  readonly priority: 'low' | 'normal' | 'high' | 'critical';

  /** Event timestamp */
  readonly timestamp: Date;

  /** Event metadata */
  readonly metadata: Record<string, unknown>;

  /** Delivery status per target */
  deliveryStatus: Map<string, DeliveryStatus>;
}

/**
 * Distribution event types.
 */
export type DistributionEventType =
  | 'new_data' // New data available
  | 'update' // Existing data updated
  | 'alert' // High-priority alert
  | 'retraction' // Data retracted/corrected
  | 'subscription_update'; // Subscription status changed

/**
 * Delivery status for a distribution event.
 */
export interface DeliveryStatus {
  /** Target authority ID */
  readonly targetId: string;

  /** Delivery status */
  status: 'pending' | 'delivered' | 'acknowledged' | 'failed' | 'rejected';

  /** Delivery timestamp */
  deliveredAt?: Date;

  /** Acknowledgment timestamp */
  acknowledgedAt?: Date;

  /** Failure reason */
  failureReason?: string;

  /** Retry count */
  retryCount: number;
}

/**
 * Subscription for push/hybrid distribution.
 */
export interface DistributionSubscription {
  /** Subscription ID */
  readonly id: string;

  /** Subscriber authority ID */
  readonly subscriberId: string;

  /** Channel ID */
  readonly channelId: string;

  /** Data categories subscribed to */
  readonly categories: DataCategory[];

  /** Filter criteria for subscription */
  readonly filters: SubscriptionFilters;

  /** Delivery preferences */
  readonly deliveryPreferences: DeliveryPreferences;

  /** Subscription status */
  status: 'active' | 'paused' | 'cancelled';

  /** Created at */
  readonly createdAt: Date;

  /** Last delivery */
  lastDeliveryAt?: Date;

  /** Items delivered */
  itemsDelivered: number;
}

/**
 * Filters for subscriptions.
 */
export interface SubscriptionFilters {
  /** Minimum severity */
  readonly minSeverity?: string;

  /** Regions of interest */
  readonly regions?: string[];

  /** Tags to include */
  readonly includeTags?: string[];

  /** Tags to exclude */
  readonly excludeTags?: string[];

  /** Minimum quality score */
  readonly minQualityScore?: number;
}

/**
 * Delivery preferences for subscriptions.
 */
export interface DeliveryPreferences {
  /** Delivery mode */
  readonly mode: 'realtime' | 'batched' | 'digest';

  /** Batch interval (for batched mode) in minutes */
  readonly batchIntervalMinutes?: number;

  /** Digest schedule (for digest mode) */
  readonly digestSchedule?: 'hourly' | 'daily' | 'weekly';

  /** Maximum items per delivery */
  readonly maxItemsPerDelivery: number;

  /** Include full data or just references */
  readonly includeFullData: boolean;
}

/**
 * Distribution package (actual data being distributed).
 */
export interface DistributionPackage {
  /** Package ID */
  readonly id: string;

  /** Source authority ID */
  readonly sourceId: string;

  /** Target authority ID */
  readonly targetId: string;

  /** Distribution event ID */
  readonly eventId: string;

  /** Data items */
  readonly items: DistributedDataItem[];

  /** Package metadata */
  readonly metadata: PackageMetadata;

  /** Integrity hash */
  readonly integrityHash: string;

  /** Signature from source */
  readonly signature: string;

  /** Created at */
  readonly createdAt: Date;

  /** Expires at */
  readonly expiresAt: Date;
}

/**
 * Data item as distributed (may be filtered/redacted based on access).
 */
export interface DistributedDataItem {
  /** Original item ID */
  readonly originalId: string;

  /** Item category */
  readonly category: DataCategory;

  /** Data (filtered based on access tier) */
  readonly data: unknown;

  /** Access tier of this item */
  readonly accessTier: AccessTier;

  /** Item hash */
  readonly hash: string;

  /** Redaction summary */
  readonly redactionSummary?: RedactionSummary;
}

/**
 * Summary of redactions applied.
 */
export interface RedactionSummary {
  /** Fields redacted */
  readonly fieldsRedacted: string[];

  /** Redaction reason */
  readonly reason: 'access_tier' | 'pii' | 'agreement_restriction' | 'policy';

  /** Original data hash (for verification) */
  readonly originalHash: string;
}

/**
 * Package metadata.
 */
export interface PackageMetadata {
  /** Total items */
  readonly totalItems: number;

  /** Categories included */
  readonly categories: DataCategory[];

  /** Time range of data */
  readonly timeRange: {
    from: Date;
    to: Date;
  };

  /** Regions represented */
  readonly regions: string[];

  /** Data sharing agreement ID */
  readonly agreementId?: string;

  /** Usage tracking ID */
  readonly usageTrackingId: string;
}

/**
 * Usage tracking record.
 */
export interface UsageRecord {
  /** Record ID */
  readonly id: string;

  /** Package ID */
  readonly packageId: string;

  /** Authority that received data */
  readonly recipientId: string;

  /** Authority that sent data */
  readonly senderId: string;

  /** Data categories accessed */
  readonly categories: DataCategory[];

  /** Item count */
  readonly itemCount: number;

  /** Access timestamp */
  readonly accessedAt: Date;

  /** Purpose of access */
  readonly purpose?: string;

  /** Usage type */
  readonly usageType: 'view' | 'download' | 'process' | 'share';
}

// ============================================================================
// Distribution Configuration
// ============================================================================

export interface DistributionConfig {
  /** Maximum items per distribution */
  readonly maxItemsPerDistribution: number;

  /** Default package expiry in hours */
  readonly packageExpiryHours: number;

  /** Enable usage tracking */
  readonly enableUsageTracking: boolean;

  /** Require acknowledgment for deliveries */
  readonly requireAcknowledgment: boolean;

  /** Maximum retry attempts */
  readonly maxRetryAttempts: number;

  /** Retry backoff in ms */
  readonly retryBackoffMs: number;

  /** Enable digest mode */
  readonly enableDigestMode: boolean;

  /** Digest batch size */
  readonly digestBatchSize: number;

  /** Incentive configuration */
  readonly incentives: {
    shareToAccessEnabled: boolean;
    minShareRatioForAccess: number;
  };
}

export const DEFAULT_DISTRIBUTION_CONFIG: DistributionConfig = {
  maxItemsPerDistribution: 1000,
  packageExpiryHours: 72,
  enableUsageTracking: true,
  requireAcknowledgment: true,
  maxRetryAttempts: 3,
  retryBackoffMs: 5000,
  enableDigestMode: true,
  digestBatchSize: 100,
  incentives: {
    shareToAccessEnabled: true,
    minShareRatioForAccess: 0.5, // Must share at least 50% of what you access
  },
};

// ============================================================================
// Data Distributor Class
// ============================================================================

/**
 * Manages data distribution between regulatory authorities.
 */
export class DataDistributor {
  private readonly config: DistributionConfig;
  private readonly channels: Map<string, DistributionChannel> = new Map();
  private readonly subscriptions: Map<string, DistributionSubscription> = new Map();
  private readonly requests: Map<string, DistributionRequest> = new Map();
  private readonly events: Map<string, DistributionEvent> = new Map();
  private readonly packages: Map<string, DistributionPackage> = new Map();
  private readonly usageRecords: Map<string, UsageRecord> = new Map();
  private readonly dataStore: Map<string, ProcessedDataItem> = new Map();

  // Tracking for reciprocity/incentives
  private readonly shareStats: Map<string, { shared: number; accessed: number }> = new Map();

  constructor(config: DistributionConfig = DEFAULT_DISTRIBUTION_CONFIG) {
    this.config = config;
  }

  /**
   * Register processed data for distribution.
   */
  registerData(items: ProcessedDataItem[]): void {
    for (const item of items) {
      this.dataStore.set(item.id, item);
    }
  }

  /**
   * Create a distribution channel.
   */
  createChannel(
    config: Omit<DistributionChannel, 'id' | 'subscriptionCount' | 'status' | 'createdAt'>
  ): DistributionChannel {
    const channel: DistributionChannel = {
      ...config,
      id: generateSecureId(),
      subscriptionCount: 0,
      status: 'active',
      createdAt: new Date(),
    };

    this.channels.set(channel.id, channel);
    return channel;
  }

  /**
   * Subscribe to a channel (push model).
   */
  subscribe(
    subscriberId: string,
    channelId: string,
    categories: DataCategory[],
    filters: SubscriptionFilters,
    preferences: DeliveryPreferences
  ): DistributionSubscription | null {
    const channel = this.channels.get(channelId);
    if (!channel || channel.status !== 'active') return null;

    // Check if categories are supported
    const validCategories = categories.filter((c) =>
      channel.supportedCategories.includes(c)
    );
    if (validCategories.length === 0) return null;

    const subscription: DistributionSubscription = {
      id: generateSecureId(),
      subscriberId,
      channelId,
      categories: validCategories,
      filters,
      deliveryPreferences: preferences,
      status: 'active',
      createdAt: new Date(),
      itemsDelivered: 0,
    };

    this.subscriptions.set(subscription.id, subscription);

    // Update channel subscription count
    (channel as { subscriptionCount: number }).subscriptionCount++;

    return subscription;
  }

  /**
   * Unsubscribe from a channel.
   */
  unsubscribe(subscriptionId: string): boolean {
    const subscription = this.subscriptions.get(subscriptionId);
    if (!subscription) return false;

    subscription.status = 'cancelled';

    const channel = this.channels.get(subscription.channelId);
    if (channel) {
      (channel as { subscriptionCount: number }).subscriptionCount--;
    }

    return true;
  }

  /**
   * Create a pull request for data.
   */
  createPullRequest(
    requesterId: string,
    categories: DataCategory[],
    criteria: DistributionCriteria,
    pagination: { page: number; limit: number }
  ): DistributionRequest {
    const request: DistributionRequest = {
      id: generateSecureId(),
      requesterId,
      requestedAt: new Date(),
      categories,
      criteria,
      pagination,
      status: 'pending',
    };

    this.requests.set(request.id, request);
    return request;
  }

  /**
   * Approve a pull request.
   */
  approveRequest(
    requestId: string,
    approverId: string,
    notes?: string,
    conditions?: string[]
  ): boolean {
    const request = this.requests.get(requestId);
    if (!request || request.status !== 'pending') return false;

    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + this.config.packageExpiryHours);

    const approval: RequestApproval = {
      approverId,
      approvedAt: new Date(),
      expiresAt,
      ...(notes !== undefined && { notes }),
      ...(conditions !== undefined && { conditions }),
    };
    request.approval = approval;
    request.status = 'approved';

    return true;
  }

  /**
   * Fulfill an approved pull request.
   */
  fulfillRequest(
    requestId: string,
    requesterTier: AccessTier,
    agreementId?: string
  ): DistributionPackage | null {
    const request = this.requests.get(requestId);
    if (!request || request.status !== 'approved') return null;

    // Check reciprocity if enabled
    if (this.config.incentives.shareToAccessEnabled) {
      if (!this.checkReciprocity(request.requesterId)) {
        return null;
      }
    }

    // Get matching data items
    const matchingItems = this.findMatchingItems(
      request.categories,
      request.criteria,
      requesterTier
    );

    // Apply pagination
    const startIdx = (request.pagination.page - 1) * request.pagination.limit;
    const paginatedItems = matchingItems.slice(startIdx, startIdx + request.pagination.limit);

    // Create distributed items (with potential redactions)
    const distributedItems = paginatedItems.map((item) =>
      this.createDistributedItem(item, requesterTier)
    );

    // Create package
    const pkg = this.createPackage(
      'system', // Source is the system for pull requests
      request.requesterId,
      'pull-request',
      distributedItems,
      agreementId
    );

    request.status = 'fulfilled';

    // Track usage
    this.trackUsage(pkg, 'download');

    return pkg;
  }

  /**
   * Push data to subscribers (push model).
   */
  async pushToSubscribers(
    sourceId: string,
    dataItemIds: string[],
    priority: DistributionEvent['priority'] = 'normal'
  ): Promise<DistributionEvent> {
    const items = dataItemIds
      .map((id) => this.dataStore.get(id))
      .filter((i): i is ProcessedDataItem => i !== undefined);

    if (items.length === 0) {
      throw new Error('No valid data items to distribute');
    }

    // Find matching subscriptions
    const categories = [...new Set(items.map((i) => i.category))];
    const matchingSubscriptions = Array.from(this.subscriptions.values()).filter(
      (sub) =>
        sub.status === 'active' &&
        sub.categories.some((c) => categories.includes(c)) &&
        this.matchesFilters(items, sub.filters)
    );

    const targetIds = matchingSubscriptions.map((s) => s.subscriberId);

    // Create event
    const event: DistributionEvent = {
      id: generateSecureId(),
      type: 'new_data',
      sourceId,
      targetIds: targetIds.length > 0 ? targetIds : 'broadcast',
      dataItemIds,
      priority,
      timestamp: new Date(),
      metadata: {
        categories,
        itemCount: items.length,
      },
      deliveryStatus: new Map(),
    };

    // Initialize delivery status for each target
    for (const targetId of targetIds) {
      event.deliveryStatus.set(targetId, {
        targetId,
        status: 'pending',
        retryCount: 0,
      });
    }

    this.events.set(event.id, event);

    // Process deliveries (in production, this would be async)
    await this.processDeliveries(event, items);

    // Update share stats
    this.updateShareStats(sourceId, items.length, 'shared');

    return event;
  }

  /**
   * Process deliveries for a distribution event.
   */
  private async processDeliveries(
    event: DistributionEvent,
    items: ProcessedDataItem[]
  ): Promise<void> {
    const targetIds = event.targetIds === 'broadcast'
      ? Array.from(this.subscriptions.values())
          .filter((s) => s.status === 'active')
          .map((s) => s.subscriberId)
      : event.targetIds;

    for (const targetId of targetIds) {
      const status = event.deliveryStatus.get(targetId);
      if (!status) continue;

      try {
        // Get subscriber's access tier (simplified - in production would look up)
        const accessTier: AccessTier = 'restricted';

        // Create distributed items
        const distributedItems = items.map((item) =>
          this.createDistributedItem(item, accessTier)
        );

        // Create and store package
        const pkg = this.createPackage(
          event.sourceId,
          targetId,
          event.id,
          distributedItems
        );

        status.status = 'delivered';
        status.deliveredAt = new Date();

        // Track usage
        this.trackUsage(pkg, 'view');
        this.updateShareStats(targetId, distributedItems.length, 'accessed');

      } catch (error) {
        status.status = 'failed';
        status.failureReason = error instanceof Error ? error.message : 'Unknown error';
        status.retryCount++;
      }
    }
  }

  /**
   * Create a distributed data item with access-based filtering.
   */
  private createDistributedItem(
    item: ProcessedDataItem,
    recipientTier: AccessTier
  ): DistributedDataItem {
    const tierHierarchy: AccessTier[] = ['public', 'restricted', 'confidential', 'classified'];
    const itemTierIndex = tierHierarchy.indexOf(item.securityClassification.accessTier);
    const recipientTierIndex = tierHierarchy.indexOf(recipientTier);

    let data = item.cleanedData;
    let redactionSummary: RedactionSummary | undefined;

    // Apply redactions if recipient tier is lower than item tier
    if (recipientTierIndex < itemTierIndex) {
      const { redactedData, fieldsRedacted } = this.redactForTier(
        item.cleanedData,
        recipientTier
      );
      data = redactedData;
      redactionSummary = {
        fieldsRedacted,
        reason: 'access_tier',
        originalHash: item.dataHash,
      };
    }

    const result: DistributedDataItem = {
      originalId: item.id,
      category: item.category,
      data,
      accessTier: item.securityClassification.accessTier,
      hash: sha256(JSON.stringify(data)),
      ...(redactionSummary !== undefined && { redactionSummary }),
    };
    return result;
  }

  /**
   * Redact data based on access tier.
   */
  private redactForTier(
    data: unknown,
    tier: AccessTier
  ): { redactedData: unknown; fieldsRedacted: string[] } {
    if (typeof data !== 'object' || data === null) {
      return { redactedData: data, fieldsRedacted: [] };
    }

    const fieldsRedacted: string[] = [];
    const redacted = JSON.parse(JSON.stringify(data));

    // Define sensitive fields by tier
    const sensitiveFields: Record<AccessTier, string[]> = {
      public: ['agentId', 'modelId', 'userId', 'ip', 'location', 'fingerprint', 'signature'],
      restricted: ['fingerprint', 'signature', 'rawPayload'],
      confidential: ['rawPayload'],
      classified: [],
    };

    const fieldsToRedact = sensitiveFields[tier] || [];

    const redactObject = (obj: Record<string, unknown>, path: string = ''): void => {
      for (const key of Object.keys(obj)) {
        const fullPath = path ? `${path}.${key}` : key;

        if (fieldsToRedact.some((f) => key.toLowerCase().includes(f.toLowerCase()))) {
          obj[key] = '[REDACTED]';
          fieldsRedacted.push(fullPath);
        } else if (typeof obj[key] === 'object' && obj[key] !== null && !Array.isArray(obj[key])) {
          redactObject(obj[key] as Record<string, unknown>, fullPath);
        }
      }
    };

    redactObject(redacted as Record<string, unknown>);

    return { redactedData: redacted, fieldsRedacted };
  }

  /**
   * Create a distribution package.
   */
  private createPackage(
    sourceId: string,
    targetId: string,
    eventId: string,
    items: DistributedDataItem[],
    agreementId?: string
  ): DistributionPackage {
    const now = new Date();
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + this.config.packageExpiryHours);

    const categories = [...new Set(items.map((i) => i.category))];
    const usageTrackingId = generateSecureId();

    const pkg: DistributionPackage = {
      id: generateSecureId(),
      sourceId,
      targetId,
      eventId,
      items,
      metadata: {
        totalItems: items.length,
        categories,
        timeRange: {
          from: now,
          to: now,
        },
        regions: [],
        usageTrackingId,
        ...(agreementId !== undefined && { agreementId }),
      },
      integrityHash: sha256(JSON.stringify(items)),
      signature: sha256(`${sourceId}:${targetId}:${Date.now()}`), // Simplified
      createdAt: now,
      expiresAt,
    };

    this.packages.set(pkg.id, pkg);
    return pkg;
  }

  /**
   * Track data usage.
   */
  private trackUsage(pkg: DistributionPackage, usageType: UsageRecord['usageType']): void {
    if (!this.config.enableUsageTracking) return;

    const record: UsageRecord = {
      id: generateSecureId(),
      packageId: pkg.id,
      recipientId: pkg.targetId,
      senderId: pkg.sourceId,
      categories: pkg.metadata.categories,
      itemCount: pkg.items.length,
      accessedAt: new Date(),
      usageType,
    };

    this.usageRecords.set(record.id, record);
  }

  /**
   * Update share statistics for reciprocity tracking.
   */
  private updateShareStats(
    authorityId: string,
    count: number,
    type: 'shared' | 'accessed'
  ): void {
    const stats = this.shareStats.get(authorityId) || { shared: 0, accessed: 0 };
    stats[type] += count;
    this.shareStats.set(authorityId, stats);
  }

  /**
   * Check if authority meets reciprocity requirements.
   */
  private checkReciprocity(authorityId: string): boolean {
    if (!this.config.incentives.shareToAccessEnabled) return true;

    const stats = this.shareStats.get(authorityId);
    if (!stats) return true; // Allow first access

    if (stats.accessed === 0) return true;

    const ratio = stats.shared / stats.accessed;
    return ratio >= this.config.incentives.minShareRatioForAccess;
  }

  /**
   * Find data items matching criteria.
   */
  private findMatchingItems(
    categories: DataCategory[],
    criteria: DistributionCriteria,
    maxTier: AccessTier
  ): ProcessedDataItem[] {
    const tierHierarchy: AccessTier[] = ['public', 'restricted', 'confidential', 'classified'];
    const maxTierIndex = tierHierarchy.indexOf(maxTier);

    return Array.from(this.dataStore.values()).filter((item) => {
      // Check category
      if (!categories.includes(item.category)) return false;

      // Check access tier
      const itemTierIndex = tierHierarchy.indexOf(item.securityClassification.accessTier);
      if (itemTierIndex > maxTierIndex) return false;

      // Check time range
      if (criteria.timeRange) {
        const itemTime = item.processedAt.getTime();
        if (itemTime < criteria.timeRange.from.getTime() || itemTime > criteria.timeRange.to.getTime()) {
          return false;
        }
      }

      // Check quality score
      if (criteria.minQualityScore !== undefined) {
        if (item.qualityAssessment.overallScore < criteria.minQualityScore) {
          return false;
        }
      }

      // Check tags
      if (criteria.tags && criteria.tags.length > 0) {
        if (!criteria.tags.some((t) => item.enrichment.tags.includes(t))) {
          return false;
        }
      }

      return true;
    });
  }

  /**
   * Check if items match subscription filters.
   */
  private matchesFilters(items: ProcessedDataItem[], filters: SubscriptionFilters): boolean {
    // Check if any item matches the filters
    return items.some((item) => {
      if (filters.minQualityScore !== undefined) {
        if (item.qualityAssessment.overallScore < filters.minQualityScore) {
          return false;
        }
      }

      if (filters.includeTags && filters.includeTags.length > 0) {
        if (!filters.includeTags.some((t) => item.enrichment.tags.includes(t))) {
          return false;
        }
      }

      if (filters.excludeTags && filters.excludeTags.length > 0) {
        if (filters.excludeTags.some((t) => item.enrichment.tags.includes(t))) {
          return false;
        }
      }

      return true;
    });
  }

  /**
   * Acknowledge receipt of a delivery.
   */
  acknowledgeDelivery(eventId: string, targetId: string): boolean {
    const event = this.events.get(eventId);
    if (!event) return false;

    const status = event.deliveryStatus.get(targetId);
    if (!status || status.status !== 'delivered') return false;

    status.status = 'acknowledged';
    status.acknowledgedAt = new Date();

    return true;
  }

  /**
   * Get distribution statistics.
   */
  getStats(): {
    totalChannels: number;
    activeChannels: number;
    totalSubscriptions: number;
    activeSubscriptions: number;
    totalRequests: number;
    fulfilledRequests: number;
    totalEvents: number;
    totalPackages: number;
    totalUsageRecords: number;
    reciprocityStats: { authorityId: string; shared: number; accessed: number; ratio: number }[];
  } {
    const channels = Array.from(this.channels.values());
    const subscriptions = Array.from(this.subscriptions.values());
    const requests = Array.from(this.requests.values());

    const reciprocityStats = Array.from(this.shareStats.entries()).map(([id, stats]) => ({
      authorityId: id,
      shared: stats.shared,
      accessed: stats.accessed,
      ratio: stats.accessed > 0 ? stats.shared / stats.accessed : 0,
    }));

    return {
      totalChannels: channels.length,
      activeChannels: channels.filter((c) => c.status === 'active').length,
      totalSubscriptions: subscriptions.length,
      activeSubscriptions: subscriptions.filter((s) => s.status === 'active').length,
      totalRequests: requests.length,
      fulfilledRequests: requests.filter((r) => r.status === 'fulfilled').length,
      totalEvents: this.events.size,
      totalPackages: this.packages.size,
      totalUsageRecords: this.usageRecords.size,
      reciprocityStats,
    };
  }

  /**
   * Get usage records for an authority.
   */
  getUsageRecordsForAuthority(authorityId: string): UsageRecord[] {
    return Array.from(this.usageRecords.values()).filter(
      (r) => r.recipientId === authorityId || r.senderId === authorityId
    );
  }

  /**
   * Get package by ID.
   */
  getPackage(packageId: string): DistributionPackage | undefined {
    return this.packages.get(packageId);
  }

  /**
   * Get subscription by ID.
   */
  getSubscription(subscriptionId: string): DistributionSubscription | undefined {
    return this.subscriptions.get(subscriptionId);
  }

  /**
   * Get all channels.
   */
  getChannels(): DistributionChannel[] {
    return Array.from(this.channels.values());
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Create a standard distribution channel for common use cases.
 */
export function createStandardChannel(
  name: string,
  model: DistributionModel,
  categories: DataCategory[],
  tier: AccessTier = 'restricted'
): Omit<DistributionChannel, 'id' | 'subscriptionCount' | 'status' | 'createdAt'> {
  return {
    name,
    model,
    supportedCategories: categories,
    requiredTier: tier,
    endpoint: `/api/distribution/${name.toLowerCase().replace(/\s+/g, '-')}`,
    protocol: model === 'hybrid' ? 'wss' : 'https',
    encryptionRequired: tier !== 'public',
  };
}

/**
 * Create default subscription filters.
 */
export function createDefaultFilters(): SubscriptionFilters {
  return {
    minQualityScore: 0.7,
  };
}

/**
 * Create default delivery preferences.
 */
export function createDefaultPreferences(
  mode: DeliveryPreferences['mode'] = 'realtime'
): DeliveryPreferences {
  return {
    mode,
    ...(mode === 'batched' && { batchIntervalMinutes: 15 }),
    ...(mode === 'digest' && { digestSchedule: 'daily' as const }),
    maxItemsPerDelivery: 100,
    includeFullData: true,
  };
}
