/**
 * Federation Monitoring Module
 *
 * Implements the monitoring phase of the Data Fetching and Distribution Plan
 * for AI Regulatory Authorities. Supports:
 * - Performance metrics tracking
 * - Feedback loops for continuous improvement
 * - Incident response protocols
 * - Compliance monitoring
 */

import { generateSecureId } from '@ai-authority/core';
import type { FetchResult } from './fetching.js';
import type { DistributionEvent } from './distribution.js';

// ============================================================================
// Types
// ============================================================================

/**
 * Metric types tracked by the monitoring system.
 */
export type MetricType =
  | 'data_utilization'
  | 'sharing_latency'
  | 'quality_score'
  | 'compliance_rate'
  | 'incident_count'
  | 'reciprocity_ratio'
  | 'authority_participation'
  | 'request_fulfillment';

/**
 * Metric data point.
 */
export interface MetricDataPoint {
  /** Metric ID */
  readonly id: string;

  /** Metric type */
  readonly type: MetricType;

  /** Value */
  readonly value: number;

  /** Unit */
  readonly unit: string;

  /** Timestamp */
  readonly timestamp: Date;

  /** Dimensions (for grouping/filtering) */
  readonly dimensions: Record<string, string>;

  /** Additional metadata */
  readonly metadata?: Record<string, unknown>;
}

/**
 * Aggregated metrics over a time period.
 */
export interface AggregatedMetric {
  /** Metric type */
  readonly type: MetricType;

  /** Aggregation period */
  readonly period: MetricPeriod;

  /** Start time */
  readonly startTime: Date;

  /** End time */
  readonly endTime: Date;

  /** Aggregated values */
  readonly values: {
    count: number;
    sum: number;
    avg: number;
    min: number;
    max: number;
    p50: number;
    p95: number;
    p99: number;
  };

  /** Breakdown by dimension */
  readonly breakdown?: Record<string, Record<string, number>>;
}

/**
 * Metric aggregation periods.
 */
export type MetricPeriod = 'minute' | 'hour' | 'day' | 'week' | 'month';

/**
 * Performance dashboard data.
 */
export interface DashboardData {
  /** Current metrics snapshot */
  readonly currentMetrics: Record<MetricType, number>;

  /** Trends over time */
  readonly trends: MetricTrend[];

  /** Active alerts */
  readonly alerts: MonitoringAlert[];

  /** Authority leaderboard */
  readonly leaderboard: AuthorityLeaderboardEntry[];

  /** Recent incidents */
  readonly recentIncidents: Incident[];

  /** Health status */
  readonly healthStatus: HealthStatus;

  /** Last updated */
  readonly lastUpdated: Date;
}

/**
 * Metric trend data.
 */
export interface MetricTrend {
  /** Metric type */
  readonly type: MetricType;

  /** Trend direction */
  readonly direction: 'up' | 'down' | 'stable';

  /** Percentage change */
  readonly changePercent: number;

  /** Time series data */
  readonly timeSeries: Array<{ timestamp: Date; value: number }>;
}

/**
 * Authority leaderboard entry.
 */
export interface AuthorityLeaderboardEntry {
  /** Authority ID */
  readonly authorityId: string;

  /** Authority name */
  readonly authorityName: string;

  /** Data shared count */
  readonly dataShared: number;

  /** Data accessed count */
  readonly dataAccessed: number;

  /** Reciprocity ratio */
  readonly reciprocityRatio: number;

  /** Quality score average */
  readonly avgQualityScore: number;

  /** Participation score */
  readonly participationScore: number;

  /** Rank */
  readonly rank: number;
}

/**
 * System health status.
 */
export interface HealthStatus {
  /** Overall status */
  readonly status: 'healthy' | 'degraded' | 'unhealthy';

  /** Component statuses */
  readonly components: ComponentHealth[];

  /** Last check timestamp */
  readonly lastCheck: Date;
}

/**
 * Component health status.
 */
export interface ComponentHealth {
  /** Component name */
  readonly name: string;

  /** Status */
  readonly status: 'healthy' | 'degraded' | 'unhealthy';

  /** Response time in ms */
  readonly responseTimeMs?: number;

  /** Error count */
  readonly errorCount: number;

  /** Details */
  readonly details?: string;
}

/**
 * Monitoring alert.
 */
export interface MonitoringAlert {
  /** Alert ID */
  readonly id: string;

  /** Alert type */
  readonly type: AlertType;

  /** Severity */
  readonly severity: 'info' | 'warning' | 'error' | 'critical';

  /** Alert message */
  readonly message: string;

  /** Metric that triggered the alert */
  readonly triggeredBy: MetricType;

  /** Threshold that was breached */
  readonly threshold: number;

  /** Actual value */
  readonly actualValue: number;

  /** Affected entities */
  readonly affectedEntities: string[];

  /** Alert timestamp */
  readonly timestamp: Date;

  /** Alert status */
  status: 'active' | 'acknowledged' | 'resolved';

  /** Acknowledged by */
  acknowledgedBy?: string;

  /** Resolved at */
  resolvedAt?: Date;
}

/**
 * Alert types.
 */
export type AlertType =
  | 'quality_degradation'
  | 'latency_spike'
  | 'low_utilization'
  | 'compliance_violation'
  | 'reciprocity_imbalance'
  | 'security_breach'
  | 'system_error';

/**
 * Incident record.
 */
export interface Incident {
  /** Incident ID */
  readonly id: string;

  /** Incident type */
  readonly type: IncidentType;

  /** Severity */
  readonly severity: 'low' | 'medium' | 'high' | 'critical';

  /** Description */
  readonly description: string;

  /** Affected authorities */
  readonly affectedAuthorities: string[];

  /** Affected data items */
  readonly affectedDataItems: string[];

  /** Incident timestamp */
  readonly timestamp: Date;

  /** Detection method */
  readonly detectionMethod: 'automated' | 'manual' | 'external_report';

  /** Status */
  status: 'open' | 'investigating' | 'contained' | 'resolved' | 'closed';

  /** Response actions taken */
  readonly responseActions: IncidentAction[];

  /** Root cause (once determined) */
  rootCause?: string;

  /** Lessons learned */
  lessonsLearned?: string;

  /** Closed at */
  closedAt?: Date;
}

/**
 * Incident types.
 */
export type IncidentType =
  | 'data_breach'
  | 'unauthorized_access'
  | 'data_corruption'
  | 'system_outage'
  | 'compliance_violation'
  | 'data_poisoning'
  | 'denial_of_service';

/**
 * Incident response action.
 */
export interface IncidentAction {
  /** Action ID */
  readonly id: string;

  /** Action type */
  readonly type: IncidentActionType;

  /** Description */
  readonly description: string;

  /** Taken by */
  readonly takenBy: string;

  /** Timestamp */
  readonly timestamp: Date;

  /** Success status */
  readonly success: boolean;

  /** Notes */
  readonly notes?: string;
}

/**
 * Incident action types.
 */
export type IncidentActionType =
  | 'access_revocation'
  | 'data_quarantine'
  | 'system_isolation'
  | 'notification_sent'
  | 'forensics_started'
  | 'patch_applied'
  | 'rollback_performed';

/**
 * Feedback submission.
 */
export interface Feedback {
  /** Feedback ID */
  readonly id: string;

  /** Submitting authority ID */
  readonly authorityId: string;

  /** Feedback type */
  readonly type: FeedbackType;

  /** Subject */
  readonly subject: string;

  /** Details */
  readonly details: string;

  /** Related data item IDs */
  readonly relatedItems?: string[];

  /** Severity/importance */
  readonly importance: 'low' | 'medium' | 'high';

  /** Submission timestamp */
  readonly submittedAt: Date;

  /** Status */
  status: 'submitted' | 'under_review' | 'accepted' | 'rejected' | 'implemented';

  /** Resolution notes */
  resolutionNotes?: string;
}

/**
 * Feedback types.
 */
export type FeedbackType =
  | 'data_quality_issue'
  | 'feature_request'
  | 'bug_report'
  | 'process_improvement'
  | 'compliance_concern'
  | 'general';

/**
 * Compliance check result.
 */
export interface ComplianceCheckResult {
  /** Check ID */
  readonly id: string;

  /** Authority ID */
  readonly authorityId: string;

  /** Regulation being checked */
  readonly regulation: string;

  /** Check timestamp */
  readonly timestamp: Date;

  /** Overall compliance status */
  readonly status: 'compliant' | 'partial' | 'non_compliant';

  /** Individual check results */
  readonly checks: ComplianceCheck[];

  /** Recommendations */
  readonly recommendations: string[];

  /** Next scheduled check */
  readonly nextCheckAt: Date;
}

/**
 * Individual compliance check.
 */
export interface ComplianceCheck {
  /** Check name */
  readonly name: string;

  /** Passed */
  readonly passed: boolean;

  /** Details */
  readonly details: string;

  /** Evidence reference */
  readonly evidenceRef?: string;
}

// ============================================================================
// Monitoring Configuration
// ============================================================================

export interface MonitoringConfig {
  /** Metric collection interval in ms */
  readonly collectionIntervalMs: number;

  /** Alert thresholds */
  readonly alertThresholds: Record<MetricType, AlertThreshold>;

  /** Retention periods */
  readonly retention: {
    metricsHours: number;
    alertsDays: number;
    incidentsDays: number;
    feedbackDays: number;
  };

  /** Health check interval in ms */
  readonly healthCheckIntervalMs: number;

  /** Enable automatic alerting */
  readonly enableAutoAlerts: boolean;

  /** Dashboard refresh interval in ms */
  readonly dashboardRefreshMs: number;
}

/**
 * Alert threshold configuration.
 */
export interface AlertThreshold {
  /** Warning threshold */
  readonly warning: number;

  /** Error threshold */
  readonly error: number;

  /** Critical threshold */
  readonly critical: number;

  /** Comparison operator */
  readonly operator: 'gt' | 'lt' | 'eq' | 'gte' | 'lte';
}

export const DEFAULT_MONITORING_CONFIG: MonitoringConfig = {
  collectionIntervalMs: 60000, // 1 minute
  alertThresholds: {
    data_utilization: { warning: 0.3, error: 0.2, critical: 0.1, operator: 'lt' },
    sharing_latency: { warning: 5000, error: 10000, critical: 30000, operator: 'gt' },
    quality_score: { warning: 0.7, error: 0.5, critical: 0.3, operator: 'lt' },
    compliance_rate: { warning: 0.95, error: 0.9, critical: 0.8, operator: 'lt' },
    incident_count: { warning: 5, error: 10, critical: 20, operator: 'gt' },
    reciprocity_ratio: { warning: 0.4, error: 0.3, critical: 0.2, operator: 'lt' },
    authority_participation: { warning: 0.5, error: 0.3, critical: 0.1, operator: 'lt' },
    request_fulfillment: { warning: 0.9, error: 0.8, critical: 0.7, operator: 'lt' },
  },
  retention: {
    metricsHours: 168, // 7 days
    alertsDays: 30,
    incidentsDays: 365,
    feedbackDays: 90,
  },
  healthCheckIntervalMs: 30000, // 30 seconds
  enableAutoAlerts: true,
  dashboardRefreshMs: 10000, // 10 seconds
};

// ============================================================================
// Federation Monitor Class
// ============================================================================

/**
 * Monitors federation health, performance, and compliance.
 */
export class FederationMonitor {
  private readonly config: MonitoringConfig;
  private readonly metrics: Map<string, MetricDataPoint> = new Map();
  private readonly alerts: Map<string, MonitoringAlert> = new Map();
  private readonly incidents: Map<string, Incident> = new Map();
  private readonly feedback: Map<string, Feedback> = new Map();
  private readonly complianceResults: Map<string, ComplianceCheckResult> = new Map();

  private healthStatus: HealthStatus;
  private collectionInterval?: NodeJS.Timeout;
  private healthCheckInterval?: NodeJS.Timeout;

  constructor(config: MonitoringConfig = DEFAULT_MONITORING_CONFIG) {
    this.config = config;
    this.healthStatus = {
      status: 'healthy',
      components: [],
      lastCheck: new Date(),
    };
  }

  /**
   * Start monitoring.
   */
  start(): void {
    // Start metric collection
    this.collectionInterval = setInterval(
      () => this.collectMetrics(),
      this.config.collectionIntervalMs
    );

    // Start health checks
    this.healthCheckInterval = setInterval(
      () => this.performHealthCheck(),
      this.config.healthCheckIntervalMs
    );

    console.log('Federation monitoring started');
  }

  /**
   * Stop monitoring.
   */
  stop(): void {
    if (this.collectionInterval) {
      clearInterval(this.collectionInterval);
    }
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }
    console.log('Federation monitoring stopped');
  }

  /**
   * Record a metric data point.
   */
  recordMetric(
    type: MetricType,
    value: number,
    unit: string,
    dimensions: Record<string, string> = {},
    metadata?: Record<string, unknown>
  ): MetricDataPoint {
    const metric: MetricDataPoint = {
      id: generateSecureId(),
      type,
      value,
      unit,
      timestamp: new Date(),
      dimensions,
      ...(metadata !== undefined && { metadata }),
    };

    this.metrics.set(metric.id, metric);

    // Check alert thresholds
    if (this.config.enableAutoAlerts) {
      this.checkAlertThreshold(type, value);
    }

    // Clean up old metrics
    this.cleanupOldMetrics();

    return metric;
  }

  /**
   * Record multiple metrics from a fetch result.
   */
  recordFetchMetrics(result: FetchResult): void {
    // Record latency
    this.recordMetric('sharing_latency', result.durationMs, 'ms', {
      sourceId: result.sourceId,
      status: result.status,
    });

    // Record quality
    this.recordMetric('quality_score', result.qualityAssessment.overallScore, 'ratio', {
      sourceId: result.sourceId,
    });

    // Record utilization
    if (result.totalAvailable > 0) {
      const utilization = result.items.length / result.totalAvailable;
      this.recordMetric('data_utilization', utilization, 'ratio', {
        sourceId: result.sourceId,
      });
    }
  }

  /**
   * Record distribution event metrics.
   */
  recordDistributionMetrics(event: DistributionEvent): void {
    const delivered = Array.from(event.deliveryStatus.values()).filter(
      (s) => s.status === 'delivered' || s.status === 'acknowledged'
    ).length;
    const total = event.deliveryStatus.size;

    if (total > 0) {
      this.recordMetric('request_fulfillment', delivered / total, 'ratio', {
        eventType: event.type,
        priority: event.priority,
      });
    }
  }

  /**
   * Record authority participation.
   */
  recordAuthorityMetrics(
    authorityId: string,
    shared: number,
    accessed: number
  ): void {
    const ratio = accessed > 0 ? shared / accessed : 1;
    this.recordMetric('reciprocity_ratio', ratio, 'ratio', {
      authorityId,
    });
  }

  /**
   * Check if a metric value breaches alert thresholds.
   */
  private checkAlertThreshold(type: MetricType, value: number): void {
    const threshold = this.config.alertThresholds[type];
    if (!threshold) return;

    const compare = (v: number, t: number, op: string): boolean => {
      switch (op) {
        case 'gt': return v > t;
        case 'lt': return v < t;
        case 'gte': return v >= t;
        case 'lte': return v <= t;
        case 'eq': return v === t;
        default: return false;
      }
    };

    let severity: MonitoringAlert['severity'] | null = null;
    let breachedThreshold = 0;

    if (compare(value, threshold.critical, threshold.operator)) {
      severity = 'critical';
      breachedThreshold = threshold.critical;
    } else if (compare(value, threshold.error, threshold.operator)) {
      severity = 'error';
      breachedThreshold = threshold.error;
    } else if (compare(value, threshold.warning, threshold.operator)) {
      severity = 'warning';
      breachedThreshold = threshold.warning;
    }

    if (severity) {
      this.createAlert(
        this.mapMetricToAlertType(type),
        severity,
        `${type} threshold breached: ${value} ${threshold.operator} ${breachedThreshold}`,
        type,
        breachedThreshold,
        value
      );
    }
  }

  /**
   * Map metric type to alert type.
   */
  private mapMetricToAlertType(metricType: MetricType): AlertType {
    const mapping: Record<MetricType, AlertType> = {
      data_utilization: 'low_utilization',
      sharing_latency: 'latency_spike',
      quality_score: 'quality_degradation',
      compliance_rate: 'compliance_violation',
      incident_count: 'system_error',
      reciprocity_ratio: 'reciprocity_imbalance',
      authority_participation: 'low_utilization',
      request_fulfillment: 'system_error',
    };
    return mapping[metricType] || 'system_error';
  }

  /**
   * Create an alert.
   */
  createAlert(
    type: AlertType,
    severity: MonitoringAlert['severity'],
    message: string,
    triggeredBy: MetricType,
    threshold: number,
    actualValue: number,
    affectedEntities: string[] = []
  ): MonitoringAlert {
    // Check for duplicate active alerts
    const existingAlert = Array.from(this.alerts.values()).find(
      (a) => a.status === 'active' && a.type === type && a.triggeredBy === triggeredBy
    );

    if (existingAlert) {
      return existingAlert;
    }

    const alert: MonitoringAlert = {
      id: generateSecureId(),
      type,
      severity,
      message,
      triggeredBy,
      threshold,
      actualValue,
      affectedEntities,
      timestamp: new Date(),
      status: 'active',
    };

    this.alerts.set(alert.id, alert);
    return alert;
  }

  /**
   * Acknowledge an alert.
   */
  acknowledgeAlert(alertId: string, acknowledgedBy: string): boolean {
    const alert = this.alerts.get(alertId);
    if (!alert || alert.status !== 'active') return false;

    alert.status = 'acknowledged';
    alert.acknowledgedBy = acknowledgedBy;
    return true;
  }

  /**
   * Resolve an alert.
   */
  resolveAlert(alertId: string): boolean {
    const alert = this.alerts.get(alertId);
    if (!alert || alert.status === 'resolved') return false;

    alert.status = 'resolved';
    alert.resolvedAt = new Date();
    return true;
  }

  /**
   * Create an incident.
   */
  createIncident(
    type: IncidentType,
    severity: Incident['severity'],
    description: string,
    affectedAuthorities: string[] = [],
    affectedDataItems: string[] = [],
    detectionMethod: Incident['detectionMethod'] = 'automated'
  ): Incident {
    const incident: Incident = {
      id: generateSecureId(),
      type,
      severity,
      description,
      affectedAuthorities,
      affectedDataItems,
      timestamp: new Date(),
      detectionMethod,
      status: 'open',
      responseActions: [],
    };

    this.incidents.set(incident.id, incident);

    // Create related alert
    this.createAlert(
      'security_breach',
      severity === 'critical' ? 'critical' : severity === 'high' ? 'error' : 'warning',
      `Incident created: ${description}`,
      'incident_count',
      0,
      1,
      affectedAuthorities
    );

    return incident;
  }

  /**
   * Add action to an incident.
   */
  addIncidentAction(
    incidentId: string,
    actionType: IncidentActionType,
    description: string,
    takenBy: string,
    success: boolean,
    notes?: string
  ): boolean {
    const incident = this.incidents.get(incidentId);
    if (!incident) return false;

    const action: IncidentAction = {
      id: generateSecureId(),
      type: actionType,
      description,
      takenBy,
      timestamp: new Date(),
      success,
      ...(notes !== undefined && { notes }),
    };

    (incident.responseActions as IncidentAction[]).push(action);
    return true;
  }

  /**
   * Update incident status.
   */
  updateIncidentStatus(
    incidentId: string,
    status: Incident['status'],
    rootCause?: string,
    lessonsLearned?: string
  ): boolean {
    const incident = this.incidents.get(incidentId);
    if (!incident) return false;

    incident.status = status;
    if (rootCause) incident.rootCause = rootCause;
    if (lessonsLearned) incident.lessonsLearned = lessonsLearned;
    if (status === 'closed') incident.closedAt = new Date();

    return true;
  }

  /**
   * Submit feedback.
   */
  submitFeedback(
    authorityId: string,
    type: FeedbackType,
    subject: string,
    details: string,
    importance: Feedback['importance'] = 'medium',
    relatedItems?: string[]
  ): Feedback {
    const feedback: Feedback = {
      id: generateSecureId(),
      authorityId,
      type,
      subject,
      details,
      ...(relatedItems !== undefined && { relatedItems }),
      importance,
      submittedAt: new Date(),
      status: 'submitted',
    };

    this.feedback.set(feedback.id, feedback);
    return feedback;
  }

  /**
   * Update feedback status.
   */
  updateFeedbackStatus(
    feedbackId: string,
    status: Feedback['status'],
    resolutionNotes?: string
  ): boolean {
    const fb = this.feedback.get(feedbackId);
    if (!fb) return false;

    fb.status = status;
    if (resolutionNotes) fb.resolutionNotes = resolutionNotes;
    return true;
  }

  /**
   * Perform compliance check.
   */
  performComplianceCheck(
    authorityId: string,
    regulation: string,
    checks: ComplianceCheck[]
  ): ComplianceCheckResult {
    const passedChecks = checks.filter((c) => c.passed).length;
    const totalChecks = checks.length;
    const passRate = totalChecks > 0 ? passedChecks / totalChecks : 0;

    let status: ComplianceCheckResult['status'];
    if (passRate >= 1) status = 'compliant';
    else if (passRate >= 0.8) status = 'partial';
    else status = 'non_compliant';

    const recommendations: string[] = [];
    for (const check of checks) {
      if (!check.passed) {
        recommendations.push(`Address: ${check.name} - ${check.details}`);
      }
    }

    const nextCheck = new Date();
    nextCheck.setMonth(nextCheck.getMonth() + 3); // Quarterly checks

    const result: ComplianceCheckResult = {
      id: generateSecureId(),
      authorityId,
      regulation,
      timestamp: new Date(),
      status,
      checks,
      recommendations,
      nextCheckAt: nextCheck,
    };

    this.complianceResults.set(result.id, result);

    // Record compliance metric
    this.recordMetric('compliance_rate', passRate, 'ratio', {
      authorityId,
      regulation,
    });

    return result;
  }

  /**
   * Perform health check.
   */
  private performHealthCheck(): void {
    const components: ComponentHealth[] = [
      {
        name: 'metrics_collection',
        status: 'healthy',
        errorCount: 0,
        details: `${this.metrics.size} metrics collected`,
      },
      {
        name: 'alert_system',
        status: 'healthy',
        errorCount: 0,
        details: `${this.alerts.size} alerts tracked`,
      },
      {
        name: 'incident_management',
        status: this.getActiveIncidentCount() > 5 ? 'degraded' : 'healthy',
        errorCount: this.getActiveIncidentCount(),
        details: `${this.getActiveIncidentCount()} active incidents`,
      },
    ];

    const hasUnhealthy = components.some((c) => c.status === 'unhealthy');
    const hasDegraded = components.some((c) => c.status === 'degraded');

    this.healthStatus = {
      status: hasUnhealthy ? 'unhealthy' : hasDegraded ? 'degraded' : 'healthy',
      components,
      lastCheck: new Date(),
    };
  }

  /**
   * Get active incident count.
   */
  private getActiveIncidentCount(): number {
    return Array.from(this.incidents.values()).filter(
      (i) => i.status !== 'closed' && i.status !== 'resolved'
    ).length;
  }

  /**
   * Collect metrics (called periodically).
   */
  private collectMetrics(): void {
    // Record system-level metrics
    this.recordMetric('incident_count', this.getActiveIncidentCount(), 'count', {});

    // Could add more system metrics here
  }

  /**
   * Clean up old metrics based on retention policy.
   */
  private cleanupOldMetrics(): void {
    const cutoff = new Date();
    cutoff.setHours(cutoff.getHours() - this.config.retention.metricsHours);

    for (const [id, metric] of this.metrics) {
      if (metric.timestamp < cutoff) {
        this.metrics.delete(id);
      }
    }
  }

  /**
   * Get aggregated metrics for a period.
   */
  getAggregatedMetrics(
    type: MetricType,
    period: MetricPeriod,
    startTime: Date,
    endTime: Date
  ): AggregatedMetric {
    const relevantMetrics = Array.from(this.metrics.values()).filter(
      (m) =>
        m.type === type &&
        m.timestamp >= startTime &&
        m.timestamp <= endTime
    );

    const values = relevantMetrics.map((m) => m.value).sort((a, b) => a - b);

    const count = values.length;
    const sum = values.reduce((a, b) => a + b, 0);
    const avg = count > 0 ? sum / count : 0;
    const min = count > 0 ? values[0]! : 0;
    const max = count > 0 ? values[count - 1]! : 0;

    const percentile = (p: number): number => {
      if (count === 0) return 0;
      const idx = Math.ceil(count * p) - 1;
      return values[Math.max(0, Math.min(idx, count - 1))]!;
    };

    return {
      type,
      period,
      startTime,
      endTime,
      values: {
        count,
        sum,
        avg,
        min,
        max,
        p50: percentile(0.5),
        p95: percentile(0.95),
        p99: percentile(0.99),
      },
    };
  }

  /**
   * Get dashboard data.
   */
  getDashboardData(_authorityNames?: Map<string, string>): DashboardData {
    const now = new Date();
    const hourAgo = new Date(now.getTime() - 3600000);

    // Current metrics
    const currentMetrics: Record<MetricType, number> = {
      data_utilization: 0,
      sharing_latency: 0,
      quality_score: 0,
      compliance_rate: 0,
      incident_count: this.getActiveIncidentCount(),
      reciprocity_ratio: 0,
      authority_participation: 0,
      request_fulfillment: 0,
    };

    // Calculate averages for each metric type
    const metricTypes: MetricType[] = Object.keys(currentMetrics) as MetricType[];
    for (const type of metricTypes) {
      const agg = this.getAggregatedMetrics(type, 'hour', hourAgo, now);
      currentMetrics[type] = agg.values.avg;
    }

    // Trends
    const trends: MetricTrend[] = metricTypes.map((type) => {
      // Get aggregated metrics for trend calculation
      this.getAggregatedMetrics(type, 'hour', hourAgo, now);
      return {
        type,
        direction: 'stable' as const,
        changePercent: 0,
        timeSeries: [],
      };
    });

    // Active alerts
    const activeAlerts = Array.from(this.alerts.values())
      .filter((a) => a.status === 'active')
      .sort((a, b) => {
        const severityOrder = { critical: 0, error: 1, warning: 2, info: 3 };
        return severityOrder[a.severity] - severityOrder[b.severity];
      });

    // Recent incidents
    const recentIncidents = Array.from(this.incidents.values())
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, 10);

    // Leaderboard (simplified)
    const leaderboard: AuthorityLeaderboardEntry[] = [];

    return {
      currentMetrics,
      trends,
      alerts: activeAlerts,
      leaderboard,
      recentIncidents,
      healthStatus: this.healthStatus,
      lastUpdated: now,
    };
  }

  /**
   * Get all active alerts.
   */
  getActiveAlerts(): MonitoringAlert[] {
    return Array.from(this.alerts.values()).filter((a) => a.status === 'active');
  }

  /**
   * Get all incidents.
   */
  getIncidents(): Incident[] {
    return Array.from(this.incidents.values());
  }

  /**
   * Get all feedback.
   */
  getFeedback(): Feedback[] {
    return Array.from(this.feedback.values());
  }

  /**
   * Get compliance results for an authority.
   */
  getComplianceResults(authorityId: string): ComplianceCheckResult[] {
    return Array.from(this.complianceResults.values()).filter(
      (r) => r.authorityId === authorityId
    );
  }

  /**
   * Get monitoring statistics.
   */
  getStats(): {
    totalMetrics: number;
    totalAlerts: number;
    activeAlerts: number;
    totalIncidents: number;
    activeIncidents: number;
    totalFeedback: number;
    pendingFeedback: number;
    healthStatus: HealthStatus['status'];
  } {
    const alerts = Array.from(this.alerts.values());
    const incidents = Array.from(this.incidents.values());
    const feedback = Array.from(this.feedback.values());

    return {
      totalMetrics: this.metrics.size,
      totalAlerts: alerts.length,
      activeAlerts: alerts.filter((a) => a.status === 'active').length,
      totalIncidents: incidents.length,
      activeIncidents: incidents.filter(
        (i) => i.status !== 'closed' && i.status !== 'resolved'
      ).length,
      totalFeedback: feedback.length,
      pendingFeedback: feedback.filter(
        (f) => f.status === 'submitted' || f.status === 'under_review'
      ).length,
      healthStatus: this.healthStatus.status,
    };
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Create a standard compliance check set for common regulations.
 */
export function createGDPRComplianceChecks(
  hasConsent: boolean,
  hasPrivacyPolicy: boolean,
  hasDataProcessingAgreement: boolean,
  hasRightToErasure: boolean,
  hasDataPortability: boolean
): ComplianceCheck[] {
  return [
    {
      name: 'User Consent',
      passed: hasConsent,
      details: hasConsent ? 'Valid consent mechanisms in place' : 'Missing consent mechanisms',
    },
    {
      name: 'Privacy Policy',
      passed: hasPrivacyPolicy,
      details: hasPrivacyPolicy ? 'Privacy policy available' : 'Privacy policy missing or outdated',
    },
    {
      name: 'Data Processing Agreement',
      passed: hasDataProcessingAgreement,
      details: hasDataProcessingAgreement ? 'DPA in place' : 'DPA missing',
    },
    {
      name: 'Right to Erasure',
      passed: hasRightToErasure,
      details: hasRightToErasure ? 'Erasure process implemented' : 'No erasure process',
    },
    {
      name: 'Data Portability',
      passed: hasDataPortability,
      details: hasDataPortability ? 'Portability feature available' : 'No portability support',
    },
  ];
}

/**
 * Create default monitoring configuration with custom thresholds.
 */
export function createMonitoringConfig(
  customThresholds?: Partial<Record<MetricType, AlertThreshold>>
): MonitoringConfig {
  return {
    ...DEFAULT_MONITORING_CONFIG,
    alertThresholds: {
      ...DEFAULT_MONITORING_CONFIG.alertThresholds,
      ...customThresholds,
    },
  };
}
