/**
 * Scan Scheduler Module
 *
 * Automated scheduled scanning of Moltbook for threat detection.
 * Uses node-cron for periodic execution with configurable intervals.
 */

import * as cron from 'node-cron';
import {
  MoltbookClient,
  generateThreatReport,
  type MoltbookThreatSignal,
} from '@ai-authority/federation';
import { generateSecureId } from '@ai-authority/core';
import {
  createCase,
  caseExists,
  type CaseInput,
  type EvidenceInput,
  type TimelineEventInput,
} from './database.js';
import type { WebSocketManager } from './websocket.js';
import type { AgentOrchestrator } from './orchestrator.js';
import { getDispatcher } from './dispatcher.js';

// ============================================================================
// Types
// ============================================================================

export interface SchedulerConfig {
  /** Enable scheduled scanning */
  enabled: boolean;

  /** Cron expression for scan frequency (default: every 15 minutes) */
  cronExpression: string;

  /** Maximum pages to scan per run */
  maxPagesPerScan: number;

  /** Posts to fetch per page */
  postsPerPage: number;

  /** Total post limit per scan */
  totalPostLimit: number;

  /** Delay between pages in ms (for rate limiting) */
  delayBetweenPages: number;

  /** Analyze agent profiles discovered in posts */
  analyzeAgentProfiles: boolean;

  /** Maximum agents to analyze per scan */
  maxAgentsToAnalyze: number;
}

export interface ScanResult {
  /** Scan ID */
  scanId: string;

  /** Scan start time */
  startedAt: Date;

  /** Scan end time */
  completedAt: Date;

  /** Duration in milliseconds */
  durationMs: number;

  /** Pages scanned */
  pagesScanned: number;

  /** Posts analyzed */
  postsAnalyzed: number;

  /** Agents analyzed */
  agentsAnalyzed: number;

  /** Threats detected */
  threatsDetected: number;

  /** Cases created */
  casesCreated: number;

  /** Signals by severity */
  signalsBySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };

  /** Any errors encountered */
  errors: string[];

  /** Whether there's more content to scan */
  hasMoreContent: boolean;
}

export interface SchedulerState {
  /** Is scheduler running */
  running: boolean;

  /** Last scan result */
  lastScan?: ScanResult | undefined;

  /** Total scans completed */
  totalScans: number;

  /** Total threats found across all scans */
  totalThreatsFound: number;

  /** Total cases created across all scans */
  totalCasesCreated: number;

  /** Scheduler started at */
  startedAt?: Date | undefined;

  /** Next scheduled scan */
  nextScanAt?: Date | undefined;
}

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_SCHEDULER_CONFIG: SchedulerConfig = {
  enabled: true,
  cronExpression: '*/15 * * * *', // Every 15 minutes
  maxPagesPerScan: 5,
  postsPerPage: 50,
  totalPostLimit: 250,
  delayBetweenPages: 1500, // 1.5 seconds
  analyzeAgentProfiles: true,
  maxAgentsToAnalyze: 20,
};

// ============================================================================
// Scheduler Class
// ============================================================================

export class ScanScheduler {
  private readonly config: SchedulerConfig;
  private readonly moltbookClient: MoltbookClient;
  private cronTask: cron.ScheduledTask | null = null;
  private wsManager: WebSocketManager | null = null;
  private orchestrator: AgentOrchestrator | null = null;
  private state: SchedulerState = {
    running: false,
    lastScan: undefined,
    totalScans: 0,
    totalThreatsFound: 0,
    totalCasesCreated: 0,
    startedAt: undefined,
    nextScanAt: undefined,
  };
  private isScanning = false;

  constructor(config: Partial<SchedulerConfig> = {}) {
    this.config = { ...DEFAULT_SCHEDULER_CONFIG, ...config };
    this.moltbookClient = new MoltbookClient({
      baseUrl: 'https://www.moltbook.com/api/v1',
      timeoutMs: 30000,
    });
  }

  /**
   * Set WebSocket manager for real-time updates.
   */
  setWebSocketManager(wsManager: WebSocketManager): void {
    this.wsManager = wsManager;
  }

  /**
   * Set orchestrator for task dispatching.
   */
  setOrchestrator(orchestrator: AgentOrchestrator): void {
    this.orchestrator = orchestrator;
    // Also wire up the dispatcher
    const dispatcher = getDispatcher();
    dispatcher.setOrchestrator(orchestrator);
    if (this.wsManager) {
      dispatcher.setWebSocketManager(this.wsManager);
    }
  }

  /**
   * Get current scheduler state.
   */
  getState(): SchedulerState {
    return { ...this.state };
  }

  /**
   * Start the scheduler.
   */
  start(): void {
    if (this.state.running) {
      console.warn('[Scheduler] Already running');
      return;
    }

    if (!this.config.enabled) {
      console.log('[Scheduler] Disabled in configuration');
      return;
    }

    console.log(`[Scheduler] Starting with cron: ${this.config.cronExpression}`);
    
    this.cronTask = cron.schedule(this.config.cronExpression, async () => {
      await this.runScan();
    });

    this.state.running = true;
    this.state.startedAt = new Date();
    this.updateNextScanTime();

    // Run initial scan on startup
    console.log('[Scheduler] Running initial scan...');
    this.runScan().catch(err => {
      console.error('[Scheduler] Initial scan failed:', err);
    });
  }

  /**
   * Stop the scheduler.
   */
  stop(): void {
    if (!this.state.running) return;

    console.log('[Scheduler] Stopping...');
    
    if (this.cronTask) {
      this.cronTask.stop();
      this.cronTask = null;
    }

    this.state.running = false;
    this.state.nextScanAt = undefined;
  }

  /**
   * Trigger a manual scan (outside of schedule).
   */
  async triggerManualScan(): Promise<ScanResult> {
    return this.runScan();
  }

  /**
   * Run a scan iteration.
   */
  private async runScan(): Promise<ScanResult> {
    if (this.isScanning) {
      console.log('[Scheduler] Scan already in progress, skipping');
      return this.state.lastScan ?? this.createEmptyScanResult();
    }

    this.isScanning = true;
    const scanId = `scan-${generateSecureId().slice(0, 8)}`;
    const startedAt = new Date();
    const errors: string[] = [];
    
    console.log(`[Scheduler] Starting scan ${scanId}...`);

    // Broadcast scan started
    this.broadcastEvent('scan_started', { scanId, startedAt });

    let pagesScanned = 0;
    let postsAnalyzed = 0;
    let agentsAnalyzed = 0;
    let threatsDetected = 0;
    let casesCreated = 0;
    let hasMoreContent = false;

    const signalsBySeverity = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };

    try {
      // Step 1: Fetch posts with pagination
      console.log(`[Scheduler] Fetching posts (max ${this.config.maxPagesPerScan} pages)...`);
      const { posts, pagesScanned: pages, hasMore } = await this.moltbookClient.fetchRecentPostsPaginated({
        maxPages: this.config.maxPagesPerScan,
        postsPerPage: this.config.postsPerPage,
        totalLimit: this.config.totalPostLimit,
        delayBetweenPages: this.config.delayBetweenPages,
      });

      pagesScanned = pages;
      postsAnalyzed = posts.length;
      hasMoreContent = hasMore;

      console.log(`[Scheduler] Fetched ${postsAnalyzed} posts from ${pagesScanned} pages`);

      // Step 2: Analyze posts for threats
      for (const post of posts) {
        try {
          const signals = await this.moltbookClient.analyzePost(post);
          
          for (const signal of signals) {
            threatsDetected++;
            signalsBySeverity[signal.severity]++;

            // Create case if not exists
            const caseId = `case-${signal.id.slice(0, 8)}`;
            if (!caseExists(caseId)) {
              this.createCaseFromSignal(signal, caseId);
              casesCreated++;
            }
          }
        } catch (error) {
          errors.push(`Failed to analyze post ${post.id}: ${(error as Error).message}`);
        }
      }

      // Step 3: Analyze agent profiles if enabled
      if (this.config.analyzeAgentProfiles) {
        const uniqueAuthors = [...new Set(posts.map(p => p.author))].slice(0, this.config.maxAgentsToAnalyze);
        
        console.log(`[Scheduler] Analyzing ${uniqueAuthors.length} agent profiles...`);
        
        for (const username of uniqueAuthors) {
          try {
            const signals = await this.moltbookClient.analyzeAgent(username);
            agentsAnalyzed++;

            for (const signal of signals) {
              threatsDetected++;
              signalsBySeverity[signal.severity]++;

              const caseId = `case-${signal.id.slice(0, 8)}`;
              if (!caseExists(caseId)) {
                this.createCaseFromSignal(signal, caseId);
                casesCreated++;
              }
            }
          } catch (error) {
            errors.push(`Failed to analyze agent ${username}: ${(error as Error).message}`);
          }
        }
      }

    } catch (error) {
      const errMsg = `Scan failed: ${(error as Error).message}`;
      console.error(`[Scheduler] ${errMsg}`);
      errors.push(errMsg);
    }

    this.isScanning = false;
    const completedAt = new Date();
    const durationMs = completedAt.getTime() - startedAt.getTime();

    const result: ScanResult = {
      scanId,
      startedAt,
      completedAt,
      durationMs,
      pagesScanned,
      postsAnalyzed,
      agentsAnalyzed,
      threatsDetected,
      casesCreated,
      signalsBySeverity,
      errors,
      hasMoreContent,
    };

    // Update state
    this.state.lastScan = result;
    this.state.totalScans++;
    this.state.totalThreatsFound += threatsDetected;
    this.state.totalCasesCreated += casesCreated;
    this.updateNextScanTime();

    console.log(`[Scheduler] Scan ${scanId} completed in ${durationMs}ms:`);
    console.log(`  - Posts analyzed: ${postsAnalyzed}`);
    console.log(`  - Agents analyzed: ${agentsAnalyzed}`);
    console.log(`  - Threats detected: ${threatsDetected}`);
    console.log(`  - Cases created: ${casesCreated}`);
    if (errors.length > 0) {
      console.log(`  - Errors: ${errors.length}`);
    }

    // Broadcast scan completed
    this.broadcastEvent('scan_completed', result);

    return result;
  }

  /**
   * Create a case from a threat signal and dispatch to agents.
   */
  private createCaseFromSignal(signal: MoltbookThreatSignal, caseId: string): void {
    // Extract matched text from evidence for report generation
    const matchedText = signal.evidence
      .map(e => typeof e.data === 'string' ? e.data : '')
      .filter(Boolean)
      .join(' | ') || signal.description;

    // Generate human-readable threat report
    const report = generateThreatReport(signal, matchedText);

    const caseInput: CaseInput = {
      id: caseId,
      title: `Moltbook: ${signal.agentUsername} - ${signal.type.replace(/_/g, ' ')}`,
      description: report.summary,  // Use report summary as case description
      severity: signal.severity,
      status: signal.severity === 'critical' ? 'investigating' : 'open',
      category: this.signalTypeToCategory(signal.type),
      targetId: signal.agentUsername,
      targetType: 'moltbook_agent',
      detectedAt: signal.detectedAt,
      detectedBy: 'moltbook-scanner',
      riskScore: signal.confidence,
      moltbookUsername: signal.agentUsername,
      threatTypes: [signal.type],
    };

    // Create evidence entries with detailed report analysis
    const evidence: EvidenceInput[] = [
      // Primary analysis report
      {
        id: generateSecureId().slice(0, 8),
        type: 'analysis_report',
        description: report.analysis,
        data: {
          summary: report.summary,
          riskAssessment: report.riskAssessment,
          recommendation: report.recommendation,
          evidenceCited: report.evidenceCited,
          generatedBy: 'moltbook-scanner',
        },
        collectedAt: signal.detectedAt,
        collectedBy: 'moltbook-scanner',
      },
      // Raw signal evidence
      {
        id: generateSecureId().slice(0, 8),
        type: signal.type,
        description: `Raw detection data: ${matchedText.slice(0, 200)}${matchedText.length > 200 ? '...' : ''}`,
        data: {
          confidence: signal.confidence,
          evidence: signal.evidence,
          sourceId: signal.sourceId,
          sourceType: signal.sourceType,
          relatedAgents: signal.relatedAgents,
          indicators: signal.indicators,
        },
        collectedAt: signal.detectedAt,
        collectedBy: 'moltbook-scanner',
      },
    ];

    const timeline: TimelineEventInput[] = [{
      id: generateSecureId().slice(0, 8),
      timestamp: signal.detectedAt,
      type: 'detected',
      description: `Threat detected: ${report.summary}`,
      actor: 'moltbook-scanner',
    }];

    try {
      createCase(caseInput, evidence, timeline);

      // Dispatch tasks to agents for this case
      if (this.orchestrator) {
        const dispatcher = getDispatcher();
        // Run async but don't await - we don't want to block case creation
        dispatcher.dispatchCase(caseId).catch(err => {
          console.warn(`[Scheduler] Failed to dispatch case ${caseId}:`, err);
        });
      }
    } catch (error) {
      console.warn(`[Scheduler] Failed to create case ${caseId}:`, error);
    }
  }

  /**
   * Map signal type to case category.
   */
  private signalTypeToCategory(type: string): 'malicious' | 'negligent' | 'suspicious' | 'unknown' {
    const maliciousTypes = [
      'credential_theft', 'scam', 'malware_distribution', 
      'phishing', 'data_harvesting', 'financial_fraud'
    ];
    const negligentTypes = ['prompt_injection', 'manipulation'];

    if (maliciousTypes.includes(type)) return 'malicious';
    if (negligentTypes.includes(type)) return 'negligent';
    return 'suspicious';
  }

  /**
   * Update next scan time based on cron expression.
   */
  private updateNextScanTime(): void {
    try {
      // Parse cron expression to get next execution time
      // node-cron doesn't provide this directly, so we estimate
      const parts = this.config.cronExpression.split(' ');
      if (parts[0]?.startsWith('*/')) {
        const minutes = parseInt(parts[0].slice(2), 10);
        const now = new Date();
        const nextMinute = Math.ceil(now.getMinutes() / minutes) * minutes;
        this.state.nextScanAt = new Date(
          now.getFullYear(),
          now.getMonth(),
          now.getDate(),
          now.getHours(),
          nextMinute
        );
        if (this.state.nextScanAt <= now) {
          this.state.nextScanAt = new Date(this.state.nextScanAt.getTime() + minutes * 60 * 1000);
        }
      }
    } catch {
      // Ignore parsing errors
    }
  }

  /**
   * Create an empty scan result.
   */
  private createEmptyScanResult(): ScanResult {
    const now = new Date();
    return {
      scanId: 'none',
      startedAt: now,
      completedAt: now,
      durationMs: 0,
      pagesScanned: 0,
      postsAnalyzed: 0,
      agentsAnalyzed: 0,
      threatsDetected: 0,
      casesCreated: 0,
      signalsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
      errors: ['No scan completed yet'],
      hasMoreContent: false,
    };
  }

  /**
   * Broadcast event via WebSocket.
   */
  private broadcastEvent(eventType: string, data: unknown): void {
    if (this.wsManager) {
      this.wsManager.broadcastEvent({
        type: eventType,
        data,
        timestamp: new Date().toISOString(),
      });
    }
  }
}

// ============================================================================
// Factory Function
// ============================================================================

let schedulerInstance: ScanScheduler | null = null;

/**
 * Get or create the singleton scheduler instance.
 */
export function getScheduler(config?: Partial<SchedulerConfig>): ScanScheduler {
  if (!schedulerInstance) {
    schedulerInstance = new ScanScheduler(config);
  }
  return schedulerInstance;
}

/**
 * Create a new scheduler instance (for testing).
 */
export function createScheduler(config?: Partial<SchedulerConfig>): ScanScheduler {
  return new ScanScheduler(config);
}
