/**
 * Sensor Agent
 * 
 * Monitors signals and collects telemetry for anomaly detection.
 */

import { BaseAgent, type AgentConfig, type AgentTask, type TaskResult } from '@ai-authority/agents';
import { generateSecureId, MerkleTree } from '@ai-authority/core';
import { AnomalyDetector, DEFAULT_DETECTION_CONFIG, type AnomalyResult } from './anomaly.js';

/** Signal from a telemetry source */
export interface Signal {
  id: string;
  sourceId: string;
  timestamp: number;
  type: string;
  value: number;
  metadata: Record<string, unknown>;
}

/** Detected anomaly */
export interface Anomaly {
  id: string;
  signalId: string;
  detectedAt: number;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  result: AnomalyResult;
}

/** Signal source configuration */
export interface SignalSource {
  id: string;
  name: string;
  type: 'api' | 'blockchain' | 'telemetry' | 'log';
  endpoint: string;
  pollIntervalMs: number;
  enabled: boolean;
}

/** Telemetry record */
export interface TelemetryRecord {
  sourceId: string;
  timestamp: number;
  metrics: Record<string, number>;
  events: TelemetryEvent[];
}

/** Telemetry event */
export interface TelemetryEvent {
  type: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  message: string;
  metadata: Record<string, unknown>;
}

/** Sensor output */
export interface SensorOutput {
  timestamp: number;
  sourceId: string;
  signals: Signal[];
  anomalies: Anomaly[];
  telemetry: TelemetryRecord;
}

/**
 * Sensor Agent
 * 
 * Hooks into various data sources to monitor for anomalies in real-time.
 * Uses autoencoders to reconstruct normal traffic and flag high reconstruction errors.
 */
export class SensorAgent extends BaseAgent {
  private sources: Map<string, SignalSource> = new Map();
  private detector: AnomalyDetector;
  private signalHistory: MerkleTree;
  private pollIntervals: Map<string, ReturnType<typeof setInterval>> = new Map();
  private recentOutputs: SensorOutput[] = [];
  private maxHistorySize = 1000;

  constructor(config: AgentConfig) {
    super(config);
    this.detector = new AnomalyDetector(DEFAULT_DETECTION_CONFIG);
    this.signalHistory = new MerkleTree();
  }

  protected async onStart(): Promise<void> {
    // Start polling all enabled sources
    for (const source of this.sources.values()) {
      if (source.enabled) {
        this.startPolling(source);
      }
    }
  }

  protected async onStop(): Promise<void> {
    // Stop all polling
    for (const interval of this.pollIntervals.values()) {
      clearInterval(interval);
    }
    this.pollIntervals.clear();
  }

  protected async processTask<T, R>(task: AgentTask<T>): Promise<TaskResult<R>> {
    const startTime = Date.now();

    try {
      switch (task.type) {
        case 'add_source':
          const source = this.addSource(task.payload as Omit<SignalSource, 'id'>);
          return {
            taskId: task.id,
            success: true,
            result: source as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };

        case 'remove_source':
          const removed = this.removeSource((task.payload as { sourceId: string }).sourceId);
          return {
            taskId: task.id,
            success: removed,
            result: { removed } as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };

        case 'poll_source':
          const output = await this.pollSource((task.payload as { sourceId: string }).sourceId);
          return {
            taskId: task.id,
            success: true,
            result: output as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };

        case 'process_signal':
          const anomalies = this.processSignal(task.payload as Signal);
          return {
            taskId: task.id,
            success: true,
            result: anomalies as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };

        case 'verify_signal': {
          // Verify a threat signal from a detection case
          const payload = task.payload as {
            caseId: string;
            severity: string;
            targetId: string;
            riskScore: number;
          };
          const verification = await this.verifyThreatSignal(payload);
          return {
            taskId: task.id,
            success: true,
            result: verification as R,
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

  /**
   * Verify a threat signal from a detection case.
   * Checks signal integrity and confirms anomaly detection.
   */
  private async verifyThreatSignal(payload: {
    caseId: string;
    severity: string;
    targetId: string;
    riskScore: number;
  }): Promise<{
    verified: boolean;
    confidence: number;
    analysis: string;
  }> {
    // Simulate signal verification - in production this would do real analysis
    const baseConfidence = payload.riskScore;
    const severityBoost = payload.severity === 'critical' ? 0.1 : payload.severity === 'high' ? 0.05 : 0;
    const confidence = Math.min(1, baseConfidence + severityBoost);

    this.logAudit('signal_verified', {
      caseId: payload.caseId,
      targetId: payload.targetId,
      confidence,
    });

    return {
      verified: confidence > 0.5,
      confidence,
      analysis: `Signal verification complete for ${payload.targetId}. Confidence: ${(confidence * 100).toFixed(1)}%`,
    };
  }

  /** Add a signal source */
  addSource(source: Omit<SignalSource, 'id'>): SignalSource {
    const fullSource: SignalSource = {
      ...source,
      id: generateSecureId(),
    };
    this.sources.set(fullSource.id, fullSource);

    if (fullSource.enabled && this.currentState === 'running') {
      this.startPolling(fullSource);
    }

    this.logAudit('source_added', { sourceId: fullSource.id, type: fullSource.type });
    return fullSource;
  }

  /** Remove a signal source */
  removeSource(sourceId: string): boolean {
    const interval = this.pollIntervals.get(sourceId);
    if (interval) {
      clearInterval(interval);
      this.pollIntervals.delete(sourceId);
    }
    return this.sources.delete(sourceId);
  }

  /** Enable/disable a source */
  setSourceEnabled(sourceId: string, enabled: boolean): boolean {
    const source = this.sources.get(sourceId);
    if (!source) return false;

    source.enabled = enabled;

    if (enabled && this.currentState === 'running') {
      this.startPolling(source);
    } else {
      const interval = this.pollIntervals.get(sourceId);
      if (interval) {
        clearInterval(interval);
        this.pollIntervals.delete(sourceId);
      }
    }

    return true;
  }

  /** Start polling a source */
  private startPolling(source: SignalSource): void {
    if (this.pollIntervals.has(source.id)) return;

    const interval = setInterval(() => {
      this.submitTask({
        type: 'poll_source',
        priority: 'medium',
        payload: { sourceId: source.id },
        maxRetries: 2,
      });
    }, source.pollIntervalMs);

    this.pollIntervals.set(source.id, interval);
  }

  /** Poll a source for signals */
  private async pollSource(sourceId: string): Promise<SensorOutput> {
    const source = this.sources.get(sourceId);
    if (!source) {
      throw new Error(`Source not found: ${sourceId}`);
    }

    // Simulate polling - in production would make actual requests
    const telemetry = await this.collectTelemetry(source);
    const signals = this.extractSignals(telemetry);
    const anomalies: Anomaly[] = [];

    // Process each signal through detector
    for (const signal of signals) {
      const detected = this.processSignal(signal);
      anomalies.push(...detected);
    }

    const output: SensorOutput = {
      timestamp: Date.now(),
      sourceId,
      signals,
      anomalies,
      telemetry,
    };

    // Store output
    this.recentOutputs.push(output);
    if (this.recentOutputs.length > this.maxHistorySize) {
      this.recentOutputs.shift();
    }

    // Record in history
    this.signalHistory.append(JSON.stringify({
      timestamp: output.timestamp,
      sourceId,
      signalCount: signals.length,
      anomalyCount: anomalies.length,
    }));

    // Broadcast anomalies
    if (anomalies.length > 0) {
      await this.sendMessage('broadcast', 'signal', {
        type: 'anomalies_detected',
        source: this.id,
        sourceId,
        anomalies,
      });
    }

    return output;
  }

  /** Collect telemetry from source */
  private async collectTelemetry(source: SignalSource): Promise<TelemetryRecord> {
    // Simulated telemetry collection
    // In production, would fetch from actual endpoints

    return {
      sourceId: source.id,
      timestamp: Date.now(),
      metrics: {
        requestRate: 100 + Math.random() * 50,
        errorRate: Math.random() * 0.1,
        latencyMs: 50 + Math.random() * 100,
        throughput: 1000 + Math.random() * 500,
      },
      events: Math.random() > 0.8 ? [{
        type: 'unusual_activity',
        severity: 'warning',
        message: `Elevated activity detected at ${source.endpoint}`,
        metadata: { endpoint: source.endpoint },
      }] : [],
    };
  }

  /** Extract signals from telemetry */
  private extractSignals(telemetry: TelemetryRecord): Signal[] {
    const signals: Signal[] = [];
    const now = Date.now();

    // Convert metrics to signals
    for (const [name, value] of Object.entries(telemetry.metrics)) {
      signals.push({
        id: generateSecureId(),
        sourceId: telemetry.sourceId,
        timestamp: now,
        type: 'metric',
        value,
        metadata: {
          metricName: name,
          rawValue: value,
        },
      });
    }

    // Convert events to signals
    for (const event of telemetry.events) {
      signals.push({
        id: generateSecureId(),
        sourceId: telemetry.sourceId,
        timestamp: now,
        type: 'event',
        value: event.severity === 'critical' ? 1 : event.severity === 'error' ? 0.7 : 0.3,
        metadata: {
          eventType: event.type,
          severity: event.severity,
          message: event.message,
        },
      });
    }

    return signals;
  }

  /** Process a signal through the anomaly detector */
  private processSignal(signal: Signal): Anomaly[] {
    const result = this.detector.detect(signal.type, signal.value);
    
    if (!result.isAnomaly) {
      return [];
    }

    return [{
      id: generateSecureId(),
      signalId: signal.id,
      detectedAt: Date.now(),
      type: result.anomalyType ?? 'unknown',
      severity: result.sigma > 5 ? 'critical' : result.sigma > 4 ? 'high' : result.sigma > 3.5 ? 'medium' : 'low',
      confidence: result.confidence,
      result,
    }];
  }

  /** Get signal history root */
  getHistoryRoot(): string {
    return this.signalHistory.getRoot();
  }

  /** Get recent outputs */
  getRecentOutputs(limit?: number): SensorOutput[] {
    const count = limit ?? this.recentOutputs.length;
    return this.recentOutputs.slice(-count);
  }

  /** Get all sources */
  getSources(): SignalSource[] {
    return Array.from(this.sources.values());
  }
}
