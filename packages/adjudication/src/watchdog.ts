/**
 * Watchdog Agent
 * 
 * Monitors for bias in detection and scoring, triggers corrections when needed.
 * Ensures fairness across different entity types and prevents systematic errors.
 */

import { BaseAgent, type AgentConfig, type AgentTask, type TaskResult } from '@ai-authority/agents';
import { generateSecureId } from '@ai-authority/core';

/** Bias category being monitored */
export type BiasCategory = 
  | 'demographic'      // Bias based on model/operator characteristics
  | 'temporal'         // Time-based bias (e.g., flagging more during certain periods)
  | 'geographic'       // Location-based bias
  | 'behavioral'       // Bias toward certain behavior patterns
  | 'historical'       // Bias from historical training data
  | 'severity'         // Bias in severity assessments
  | 'attribution';     // Bias in source attribution

/** Bias metric */
export interface BiasMetric {
  category: BiasCategory;
  dimension: string;
  value: number;           // Current bias measurement
  threshold: number;       // Threshold for triggering correction
  trend: 'increasing' | 'decreasing' | 'stable';
  lastUpdated: number;
}

/** Bias alert when threshold exceeded */
export interface BiasAlert {
  id: string;
  timestamp: number;
  category: BiasCategory;
  dimension: string;
  currentValue: number;
  threshold: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  recommendation: string;
  autoCorrection?: CorrectionAction;
}

/** Correction action */
export interface CorrectionAction {
  id: string;
  type: 'weight_adjustment' | 'threshold_change' | 'model_retrain' | 'manual_review';
  parameters: Record<string, unknown>;
  appliedAt?: number;
  status: 'pending' | 'applied' | 'rejected' | 'failed';
}

/** Fairness audit result */
export interface FairnessAudit {
  id: string;
  timestamp: number;
  period: { start: number; end: number };
  metrics: FairnessMetrics;
  violations: FairnessViolation[];
  recommendations: string[];
  overallScore: number;  // 0-1, higher is fairer
}

/** Fairness metrics */
export interface FairnessMetrics {
  demographicParity: number;       // Equal positive rates across groups
  equalizedOdds: number;           // Equal TPR and FPR across groups
  calibration: number;             // Predicted probabilities match actual rates
  individualFairness: number;      // Similar entities treated similarly
  counterfactualFairness: number;  // Outcome doesn't change with sensitive attributes
}

/** Fairness violation */
export interface FairnessViolation {
  metric: keyof FairnessMetrics;
  group1: string;
  group2: string;
  difference: number;
  threshold: number;
  description: string;
}

/** Decision record for monitoring */
export interface DecisionRecord {
  id: string;
  timestamp: number;
  entityId: string;
  entityType: string;
  attributes: Record<string, unknown>;
  decision: string;
  score: number;
  outcome?: 'correct' | 'false_positive' | 'false_negative' | 'unknown';
}

/** Watchdog configuration */
export interface WatchdogConfig {
  biasThresholds: Record<BiasCategory, number>;
  auditIntervalMs: number;
  autoCorrectEnabled: boolean;
  minDecisionsForAudit: number;
}

const defaultWatchdogConfig: WatchdogConfig = {
  biasThresholds: {
    demographic: 0.1,
    temporal: 0.15,
    geographic: 0.1,
    behavioral: 0.2,
    historical: 0.15,
    severity: 0.1,
    attribution: 0.15,
  },
  auditIntervalMs: 3600000, // 1 hour
  autoCorrectEnabled: false,
  minDecisionsForAudit: 100,
};

/**
 * Watchdog Agent
 * 
 * Continuously monitors for bias and fairness issues in the detection system.
 * Can trigger automatic corrections or escalate to human review.
 */
export class WatchdogAgent extends BaseAgent {
  private readonly watchdogConfig: WatchdogConfig;
  private decisions: DecisionRecord[] = [];
  private biasMetrics: Map<string, BiasMetric> = new Map();
  private alerts: BiasAlert[] = [];
  private corrections: Map<string, CorrectionAction> = new Map();
  private audits: FairnessAudit[] = [];
  private auditInterval?: ReturnType<typeof setInterval>;

  constructor(config: AgentConfig, watchdogConfig: Partial<WatchdogConfig> = {}) {
    super(config);
    this.watchdogConfig = { ...defaultWatchdogConfig, ...watchdogConfig };
    this.initializeBiasMetrics();
  }

  private initializeBiasMetrics(): void {
    const categories: BiasCategory[] = [
      'demographic', 'temporal', 'geographic', 'behavioral', 
      'historical', 'severity', 'attribution'
    ];

    for (const category of categories) {
      const key = `${category}_default`;
      this.biasMetrics.set(key, {
        category,
        dimension: 'default',
        value: 0,
        threshold: this.watchdogConfig.biasThresholds[category],
        trend: 'stable',
        lastUpdated: Date.now(),
      });
    }
  }

  protected async onStart(): Promise<void> {
    // Start periodic auditing
    this.auditInterval = setInterval(
      () => this.runPeriodicAudit(),
      this.watchdogConfig.auditIntervalMs
    );
  }

  protected async onStop(): Promise<void> {
    if (this.auditInterval) {
      clearInterval(this.auditInterval);
    }
  }

  protected async onMessage(message: { type: string; payload: unknown }): Promise<void> {
    if (message.type === 'decision') {
      // Track decisions for bias analysis
      const decision = message.payload as DecisionRecord;
      this.recordDecision(decision);
    }
  }

  protected async processTask<T, R>(task: AgentTask<T>): Promise<TaskResult<R>> {
    const startTime = Date.now();

    try {
      switch (task.type) {
        case 'record_decision': {
          const decision = task.payload as DecisionRecord;
          this.recordDecision(decision);
          return {
            taskId: task.id,
            success: true,
            result: { recorded: true } as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        case 'check_bias': {
          const { category, dimension } = task.payload as { category: BiasCategory; dimension?: string };
          const result = await this.checkBias(category, dimension);
          return {
            taskId: task.id,
            success: true,
            result: result as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        case 'run_fairness_audit': {
          const { startTime: auditStart, endTime: auditEnd } = task.payload as { startTime?: number; endTime?: number };
          const result = await this.runFairnessAudit(auditStart, auditEnd);
          return {
            taskId: task.id,
            success: true,
            result: result as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        case 'apply_correction': {
          const correction = task.payload as CorrectionAction;
          const result = await this.applyCorrection(correction);
          return {
            taskId: task.id,
            success: true,
            result: result as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        case 'get_bias_metrics': {
          return {
            taskId: task.id,
            success: true,
            result: this.getBiasMetrics() as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        case 'get_alerts': {
          const { severity } = task.payload as { severity?: BiasAlert['severity'] } || {};
          return {
            taskId: task.id,
            success: true,
            result: this.getAlerts(severity) as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        default:
          return {
            taskId: task.id,
            success: false,
            error: `Unknown task type: ${task.type}`,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
      }
    } catch (error) {
      return {
        taskId: task.id,
        success: false,
        error: String(error),
        duration: Date.now() - startTime,
        timestamp: Date.now(),
      };
    }
  }

  /** Record a decision for bias monitoring */
  recordDecision(decision: DecisionRecord): void {
    this.decisions.push(decision);

    // Update bias metrics incrementally
    this.updateBiasMetrics(decision);

    // Check for threshold violations
    this.checkThresholdViolations();

    // Limit stored decisions
    if (this.decisions.length > 100000) {
      this.decisions = this.decisions.slice(-50000);
    }
  }

  /** Check bias for a specific category */
  async checkBias(category: BiasCategory, dimension?: string): Promise<BiasMetric[]> {
    const metrics: BiasMetric[] = [];

    for (const [, metric] of this.biasMetrics) {
      if (metric.category === category && (!dimension || metric.dimension === dimension)) {
        metrics.push(metric);
      }
    }

    return metrics;
  }

  /** Run a comprehensive fairness audit */
  async runFairnessAudit(startTime?: number, endTime?: number): Promise<FairnessAudit> {
    const now = Date.now();
    const start = startTime ?? now - 86400000; // Default: last 24 hours
    const end = endTime ?? now;

    // Filter decisions in time range
    const relevantDecisions = this.decisions.filter(
      d => d.timestamp >= start && d.timestamp <= end
    );

    if (relevantDecisions.length < this.watchdogConfig.minDecisionsForAudit) {
      throw new Error(`Insufficient decisions for audit: ${relevantDecisions.length} < ${this.watchdogConfig.minDecisionsForAudit}`);
    }

    // Calculate fairness metrics
    const metrics = this.calculateFairnessMetrics(relevantDecisions);

    // Identify violations
    const violations = this.identifyViolations(relevantDecisions, metrics);

    // Generate recommendations
    const recommendations = this.generateRecommendations(violations, metrics);

    // Calculate overall score
    const overallScore = this.calculateOverallFairnessScore(metrics);

    const audit: FairnessAudit = {
      id: generateSecureId(),
      timestamp: now,
      period: { start, end },
      metrics,
      violations,
      recommendations,
      overallScore,
    };

    this.audits.push(audit);

    // Broadcast audit result
    await this.sendMessage('broadcast', 'audit', {
      type: 'fairness_audit',
      audit,
    });

    this.logAudit('fairness_audit_completed', {
      auditId: audit.id,
      overallScore,
      violationCount: violations.length,
    });

    return audit;
  }

  /** Apply a bias correction */
  async applyCorrection(correction: CorrectionAction): Promise<CorrectionAction> {
    correction.id = correction.id || generateSecureId();

    try {
      // Validate correction
      if (!this.validateCorrection(correction)) {
        correction.status = 'rejected';
        throw new Error('Correction validation failed');
      }

      // Apply correction based on type
      switch (correction.type) {
        case 'weight_adjustment':
          await this.applyWeightAdjustment(correction.parameters);
          break;
        case 'threshold_change':
          await this.applyThresholdChange(correction.parameters);
          break;
        case 'manual_review':
          // Flag for manual review - no automatic action
          break;
        case 'model_retrain':
          // Queue for model retraining
          await this.queueModelRetrain(correction.parameters);
          break;
      }

      correction.appliedAt = Date.now();
      correction.status = 'applied';

      this.corrections.set(correction.id, correction);

      this.logAudit('correction_applied', {
        correctionId: correction.id,
        type: correction.type,
      });

    } catch (error) {
      correction.status = 'failed';
      this.corrections.set(correction.id, correction);
      throw error;
    }

    return correction;
  }

  // ============================================================================
  // Bias Analysis
  // ============================================================================

  private updateBiasMetrics(decision: DecisionRecord): void {
    // Update demographic bias
    this.updateDemographicBias(decision);

    // Update temporal bias
    this.updateTemporalBias(decision);

    // Update severity bias
    this.updateSeverityBias(decision);
  }

  private updateDemographicBias(decision: DecisionRecord): void {
    const entityType = decision.entityType;
    const key = `demographic_${entityType}`;

    let metric = this.biasMetrics.get(key);
    if (!metric) {
      metric = {
        category: 'demographic',
        dimension: entityType,
        value: 0,
        threshold: this.watchdogConfig.biasThresholds.demographic,
        trend: 'stable',
        lastUpdated: Date.now(),
      };
      this.biasMetrics.set(key, metric);
    }

    // Calculate bias as deviation from average
    const typeDecisions = this.decisions.filter(d => d.entityType === entityType);
    const allDecisions = this.decisions;

    if (typeDecisions.length > 10 && allDecisions.length > 10) {
      const typeAvgScore = typeDecisions.reduce((s, d) => s + d.score, 0) / typeDecisions.length;
      const allAvgScore = allDecisions.reduce((s, d) => s + d.score, 0) / allDecisions.length;
      
      const newValue = Math.abs(typeAvgScore - allAvgScore);
      const oldValue = metric.value;

      metric.value = newValue;
      metric.trend = newValue > oldValue * 1.05 ? 'increasing' : 
                     newValue < oldValue * 0.95 ? 'decreasing' : 'stable';
      metric.lastUpdated = Date.now();
    }
  }

  private updateTemporalBias(decision: DecisionRecord): void {
    const hour = new Date(decision.timestamp).getHours();
    const key = `temporal_hour_${hour}`;

    let metric = this.biasMetrics.get(key);
    if (!metric) {
      metric = {
        category: 'temporal',
        dimension: `hour_${hour}`,
        value: 0,
        threshold: this.watchdogConfig.biasThresholds.temporal,
        trend: 'stable',
        lastUpdated: Date.now(),
      };
      this.biasMetrics.set(key, metric);
    }

    // Calculate temporal bias
    const hourDecisions = this.decisions.filter(d => new Date(d.timestamp).getHours() === hour);
    const allDecisions = this.decisions;

    if (hourDecisions.length > 5 && allDecisions.length > 20) {
      const hourAvgScore = hourDecisions.reduce((s, d) => s + d.score, 0) / hourDecisions.length;
      const allAvgScore = allDecisions.reduce((s, d) => s + d.score, 0) / allDecisions.length;
      
      metric.value = Math.abs(hourAvgScore - allAvgScore);
      metric.lastUpdated = Date.now();
    }
  }

  private updateSeverityBias(_decision: DecisionRecord): void {
    // Check if scoring is biased toward high or low severity
    const key = 'severity_distribution';

    let metric = this.biasMetrics.get(key);
    if (!metric) {
      metric = {
        category: 'severity',
        dimension: 'distribution',
        value: 0,
        threshold: this.watchdogConfig.biasThresholds.severity,
        trend: 'stable',
        lastUpdated: Date.now(),
      };
      this.biasMetrics.set(key, metric);
    }

    // Calculate severity skew
    const scores = this.decisions.map(d => d.score);
    if (scores.length > 20) {
      const mean = scores.reduce((a, b) => a + b, 0) / scores.length;
      const variance = scores.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / scores.length;
      const stdDev = Math.sqrt(variance);
      
      // Skewness
      const skewness = scores.reduce((s, v) => s + Math.pow((v - mean) / stdDev, 3), 0) / scores.length;
      
      metric.value = Math.abs(skewness);
      metric.lastUpdated = Date.now();
    }
  }

  private checkThresholdViolations(): void {
    for (const [, metric] of this.biasMetrics) {
      if (metric.value > metric.threshold) {
        const existingAlert = this.alerts.find(
          a => a.category === metric.category && a.dimension === metric.dimension && 
               Date.now() - a.timestamp < 3600000 // Within last hour
        );

        if (!existingAlert) {
          this.createBiasAlert(metric);
        }
      }
    }
  }

  private createBiasAlert(metric: BiasMetric): void {
    const severity = this.calculateAlertSeverity(metric);
    
    const alert: BiasAlert = {
      id: generateSecureId(),
      timestamp: Date.now(),
      category: metric.category,
      dimension: metric.dimension,
      currentValue: metric.value,
      threshold: metric.threshold,
      severity,
      recommendation: this.generateAlertRecommendation(metric, severity),
    };

    // Auto-correction if enabled and severity is high
    if (this.watchdogConfig.autoCorrectEnabled && (severity === 'high' || severity === 'critical')) {
      alert.autoCorrection = this.createAutoCorrection(metric);
    }

    this.alerts.push(alert);

    // Broadcast alert
    this.sendMessage('broadcast', 'signal', {
      type: 'bias_alert',
      alert,
    });

    this.logAudit('bias_alert_created', {
      alertId: alert.id,
      category: metric.category,
      severity,
    });
  }

  private calculateAlertSeverity(metric: BiasMetric): BiasAlert['severity'] {
    const ratio = metric.value / metric.threshold;
    
    if (ratio > 2.0) return 'critical';
    if (ratio > 1.5) return 'high';
    if (ratio > 1.2) return 'medium';
    return 'low';
  }

  private generateAlertRecommendation(metric: BiasMetric, severity: BiasAlert['severity']): string {
    const baseRec = `Bias detected in ${metric.category} (${metric.dimension}): ${metric.value.toFixed(3)} > ${metric.threshold}. `;
    
    switch (severity) {
      case 'critical':
        return baseRec + 'Immediate review and correction required. Consider pausing affected operations.';
      case 'high':
        return baseRec + 'Prompt investigation needed. Apply weight adjustment or threshold changes.';
      case 'medium':
        return baseRec + 'Monitor closely and consider preventive measures.';
      default:
        return baseRec + 'Continue monitoring for trend changes.';
    }
  }

  private createAutoCorrection(metric: BiasMetric): CorrectionAction {
    return {
      id: generateSecureId(),
      type: 'weight_adjustment',
      parameters: {
        category: metric.category,
        dimension: metric.dimension,
        adjustment: -metric.value * 0.5, // Reduce by 50% of bias
      },
      status: 'pending',
    };
  }

  // ============================================================================
  // Fairness Calculation
  // ============================================================================

  private calculateFairnessMetrics(decisions: DecisionRecord[]): FairnessMetrics {
    return {
      demographicParity: this.calculateDemographicParity(decisions),
      equalizedOdds: this.calculateEqualizedOdds(decisions),
      calibration: this.calculateCalibration(decisions),
      individualFairness: this.calculateIndividualFairness(decisions),
      counterfactualFairness: this.calculateCounterfactualFairness(decisions),
    };
  }

  private calculateDemographicParity(decisions: DecisionRecord[]): number {
    const groups = this.groupByAttribute(decisions, 'entityType');
    if (groups.size < 2) return 1.0;

    const positiveRates: number[] = [];
    for (const [_, groupDecisions] of groups) {
      const positives = groupDecisions.filter(d => d.score > 0.5).length;
      positiveRates.push(positives / groupDecisions.length);
    }

    const maxDiff = Math.max(...positiveRates) - Math.min(...positiveRates);
    return 1 - maxDiff;
  }

  private calculateEqualizedOdds(decisions: DecisionRecord[]): number {
    const withOutcome = decisions.filter(d => d.outcome && d.outcome !== 'unknown');
    if (withOutcome.length < 20) return 0.5; // Insufficient data

    const groups = this.groupByAttribute(withOutcome, 'entityType');
    if (groups.size < 2) return 1.0;

    const tprDiffs: number[] = [];
    const fprDiffs: number[] = [];

    const groupMetrics: Array<{ tpr: number; fpr: number }> = [];
    for (const [_, groupDecisions] of groups) {
      const tp = groupDecisions.filter(d => d.score > 0.5 && d.outcome === 'correct').length;
      const fn = groupDecisions.filter(d => d.score <= 0.5 && d.outcome === 'false_negative').length;
      const fp = groupDecisions.filter(d => d.score > 0.5 && d.outcome === 'false_positive').length;
      const tn = groupDecisions.filter(d => d.score <= 0.5 && d.outcome === 'correct').length;

      const tpr = tp / Math.max(1, tp + fn);
      const fpr = fp / Math.max(1, fp + tn);
      groupMetrics.push({ tpr, fpr });
    }

    for (let i = 0; i < groupMetrics.length; i++) {
      for (let j = i + 1; j < groupMetrics.length; j++) {
        tprDiffs.push(Math.abs(groupMetrics[i]!.tpr - groupMetrics[j]!.tpr));
        fprDiffs.push(Math.abs(groupMetrics[i]!.fpr - groupMetrics[j]!.fpr));
      }
    }

    const avgDiff = (Math.max(...tprDiffs, 0) + Math.max(...fprDiffs, 0)) / 2;
    return 1 - avgDiff;
  }

  private calculateCalibration(decisions: DecisionRecord[]): number {
    const withOutcome = decisions.filter(d => d.outcome && d.outcome !== 'unknown');
    if (withOutcome.length < 20) return 0.5;

    // Bin predictions and check actual rates
    const bins = 10;
    const binCounts = new Array(bins).fill(0);
    const binCorrect = new Array(bins).fill(0);

    for (const d of withOutcome) {
      const bin = Math.min(bins - 1, Math.floor(d.score * bins));
      binCounts[bin]++;
      if (d.outcome === 'correct') {
        binCorrect[bin]++;
      }
    }

    let totalError = 0;
    let validBins = 0;

    for (let i = 0; i < bins; i++) {
      if (binCounts[i] >= 5) {
        const expectedRate = (i + 0.5) / bins;
        const actualRate = binCorrect[i] / binCounts[i];
        totalError += Math.abs(expectedRate - actualRate);
        validBins++;
      }
    }

    return validBins > 0 ? 1 - totalError / validBins : 0.5;
  }

  private calculateIndividualFairness(decisions: DecisionRecord[]): number {
    if (decisions.length < 10) return 0.5;

    // Sample pairs and check if similar entities get similar scores
    const sampleSize = Math.min(100, decisions.length);
    let similarPairs = 0;
    let totalPairs = 0;

    for (let i = 0; i < sampleSize; i++) {
      for (let j = i + 1; j < sampleSize; j++) {
        const d1 = decisions[i]!;
        const d2 = decisions[j]!;

        const similarity = this.calculateEntitySimilarity(d1, d2);
        if (similarity > 0.8) {
          totalPairs++;
          const scoreDiff = Math.abs(d1.score - d2.score);
          if (scoreDiff < 0.2) {
            similarPairs++;
          }
        }
      }
    }

    return totalPairs > 0 ? similarPairs / totalPairs : 1.0;
  }

  private calculateCounterfactualFairness(_decisions: DecisionRecord[]): number {
    // Simplified: would need causal model in production
    return 0.7; // Placeholder
  }

  private calculateEntitySimilarity(d1: DecisionRecord, d2: DecisionRecord): number {
    const attrs1 = d1.attributes;
    const attrs2 = d2.attributes;
    
    const keys = new Set([...Object.keys(attrs1), ...Object.keys(attrs2)]);
    if (keys.size === 0) return 0;

    let matches = 0;
    for (const key of keys) {
      if (attrs1[key] === attrs2[key]) {
        matches++;
      }
    }

    return matches / keys.size;
  }

  private groupByAttribute(decisions: DecisionRecord[], attribute: string): Map<string, DecisionRecord[]> {
    const groups = new Map<string, DecisionRecord[]>();
    
    for (const d of decisions) {
      const value = String((d as unknown as Record<string, unknown>)[attribute] ?? d.attributes[attribute] ?? 'unknown');
      const group = groups.get(value) ?? [];
      group.push(d);
      groups.set(value, group);
    }

    return groups;
  }

  private identifyViolations(_decisions: DecisionRecord[], metrics: FairnessMetrics): FairnessViolation[] {
    const violations: FairnessViolation[] = [];
    const threshold = 0.8;

    if (metrics.demographicParity < threshold) {
      violations.push({
        metric: 'demographicParity',
        group1: 'varies',
        group2: 'varies',
        difference: 1 - metrics.demographicParity,
        threshold: 1 - threshold,
        description: 'Positive prediction rates differ significantly across entity types',
      });
    }

    if (metrics.equalizedOdds < threshold) {
      violations.push({
        metric: 'equalizedOdds',
        group1: 'varies',
        group2: 'varies',
        difference: 1 - metrics.equalizedOdds,
        threshold: 1 - threshold,
        description: 'True/false positive rates differ across groups',
      });
    }

    if (metrics.calibration < threshold) {
      violations.push({
        metric: 'calibration',
        group1: 'predicted',
        group2: 'actual',
        difference: 1 - metrics.calibration,
        threshold: 1 - threshold,
        description: 'Predicted probabilities do not match actual outcomes',
      });
    }

    if (metrics.individualFairness < threshold) {
      violations.push({
        metric: 'individualFairness',
        group1: 'similar_entities',
        group2: 'similar_entities',
        difference: 1 - metrics.individualFairness,
        threshold: 1 - threshold,
        description: 'Similar entities receiving different treatment',
      });
    }

    return violations;
  }

  private generateRecommendations(violations: FairnessViolation[], _metrics: FairnessMetrics): string[] {
    const recommendations: string[] = [];

    for (const v of violations) {
      switch (v.metric) {
        case 'demographicParity':
          recommendations.push('Review scoring weights for different entity types');
          recommendations.push('Consider threshold adjustments per group');
          break;
        case 'equalizedOdds':
          recommendations.push('Analyze false positive/negative patterns by group');
          recommendations.push('Consider separate calibration per group');
          break;
        case 'calibration':
          recommendations.push('Retrain scoring model with updated outcome data');
          recommendations.push('Implement Platt scaling for probability calibration');
          break;
        case 'individualFairness':
          recommendations.push('Review feature weights for consistency');
          recommendations.push('Audit individual cases for inconsistencies');
          break;
      }
    }

    return [...new Set(recommendations)]; // Deduplicate
  }

  private calculateOverallFairnessScore(metrics: FairnessMetrics): number {
    const weights = {
      demographicParity: 0.2,
      equalizedOdds: 0.25,
      calibration: 0.2,
      individualFairness: 0.2,
      counterfactualFairness: 0.15,
    };

    let score = 0;
    for (const [key, weight] of Object.entries(weights)) {
      score += metrics[key as keyof FairnessMetrics] * weight;
    }

    return score;
  }

  // ============================================================================
  // Correction Helpers
  // ============================================================================

  private validateCorrection(correction: CorrectionAction): boolean {
    // Validate correction parameters
    if (!correction.type) return false;
    if (!correction.parameters) return false;

    switch (correction.type) {
      case 'weight_adjustment':
        return typeof correction.parameters.adjustment === 'number';
      case 'threshold_change':
        return typeof correction.parameters.newThreshold === 'number';
      default:
        return true;
    }
  }

  private async applyWeightAdjustment(params: Record<string, unknown>): Promise<void> {
    // In production, would communicate with scoring engine
    this.logAudit('weight_adjustment_applied', params);
  }

  private async applyThresholdChange(params: Record<string, unknown>): Promise<void> {
    // In production, would update detection thresholds
    this.logAudit('threshold_change_applied', params);
  }

  private async queueModelRetrain(params: Record<string, unknown>): Promise<void> {
    // In production, would queue retraining job
    this.logAudit('model_retrain_queued', params);
  }

  private async runPeriodicAudit(): Promise<void> {
    if (this.decisions.length >= this.watchdogConfig.minDecisionsForAudit) {
      try {
        await this.runFairnessAudit();
      } catch (error) {
        this.logAudit('periodic_audit_failed', { error: String(error) });
      }
    }
  }

  // ============================================================================
  // Query Methods
  // ============================================================================

  /** Get current bias metrics */
  getBiasMetrics(): BiasMetric[] {
    return Array.from(this.biasMetrics.values());
  }

  /** Get alerts, optionally filtered by severity */
  getAlerts(severity?: BiasAlert['severity']): BiasAlert[] {
    if (severity) {
      return this.alerts.filter(a => a.severity === severity);
    }
    return [...this.alerts];
  }

  /** Get fairness audits */
  getAudits(): FairnessAudit[] {
    return [...this.audits];
  }

  /** Get latest audit */
  getLatestAudit(): FairnessAudit | undefined {
    return this.audits[this.audits.length - 1];
  }

  /** Get correction by ID */
  getCorrection(id: string): CorrectionAction | undefined {
    return this.corrections.get(id);
  }
}
