/**
 * Task Dispatcher
 *
 * Routes detection cases to appropriate agents for processing.
 * This connects the scanning/detection system to the agent workforce.
 *
 * Task Flow:
 * 1. Scanner detects threat → Case created
 * 2. Dispatcher routes case to agents based on severity/type
 * 3. Sensor verifies signal integrity
 * 4. Analyzer computes detailed risk score
 * 5. Watchdog checks for bias
 * 6. Auditor logs compliance record
 */

import type { AgentOrchestrator, AgentInstance } from './orchestrator.js';
import type { WebSocketManager } from './websocket.js';
import { generateSecureId } from '@ai-authority/core';
import { getCaseById, updateCaseStatus } from './database.js';

// ============================================================================
// Types
// ============================================================================

export interface TaskPayload {
  caseId: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  targetId: string;
  targetType: string;
  riskScore: number;
  evidence?: unknown[];
  metadata?: Record<string, unknown>;
}

export interface TaskResult {
  taskId: string;
  agentId: string;
  agentRole: string;
  success: boolean;
  result?: unknown;
  error?: string;
  duration: number;
  timestamp: Date;
}

export interface DispatchResult {
  caseId: string;
  tasksDispatched: number;
  taskResults: TaskResult[];
  errors: string[];
  duration: number;
}

export interface DispatcherConfig {
  /** Enable automatic dispatch on case creation */
  autoDispatch: boolean;

  /** Maximum concurrent tasks per agent */
  maxConcurrentTasksPerAgent: number;

  /** Task timeout in milliseconds */
  taskTimeoutMs: number;

  /** Retry failed tasks */
  retryFailedTasks: boolean;

  /** Maximum retries per task */
  maxRetries: number;
}

export const DEFAULT_DISPATCHER_CONFIG: DispatcherConfig = {
  autoDispatch: true,
  maxConcurrentTasksPerAgent: 5,
  taskTimeoutMs: 30000,
  retryFailedTasks: true,
  maxRetries: 2,
};

// ============================================================================
// Task Types by Agent Role
// ============================================================================

/**
 * Maps case severity and type to which agents should process it.
 * Uses actual task types that each agent's processTask() method supports.
 */
const DISPATCH_RULES: Record<string, {
  roles: string[];
  minSeverity: 'low' | 'medium' | 'high' | 'critical';
  taskType: string;  // Actual task type the agent supports
}> = {
  // Sensor verifies signal integrity
  'verify_signal': {
    roles: ['sensor'],
    minSeverity: 'low',
    taskType: 'verify_signal',
  },
  // Forensic performs attribution analysis on high+ cases
  'forensic_analysis': {
    roles: ['forensic'],
    minSeverity: 'high',
    taskType: 'attribute',  // ForensicAgent's actual task type
  },
  // Watchdog checks for bias on high+ cases
  'check_bias': {
    roles: ['watchdog'],
    minSeverity: 'high',
    taskType: 'check_bias',  // WatchdogAgent's actual task type
  },
  // Auditor logs compliance record
  'audit_log': {
    roles: ['auditor'],
    minSeverity: 'low',
    taskType: 'audit_action',  // AuditorAgent's actual task type
  },
};

const SEVERITY_ORDER: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

// ============================================================================
// Task Dispatcher
// ============================================================================

/**
 * Dispatches detection cases to agents for processing.
 */
export class TaskDispatcher {
  private readonly config: DispatcherConfig;
  private orchestrator: AgentOrchestrator | null = null;
  private wsManager: WebSocketManager | null = null;
  private stats = {
    totalDispatched: 0,
    totalSucceeded: 0,
    totalFailed: 0,
    byAgent: new Map<string, { processed: number; failed: number }>(),
  };

  constructor(config: Partial<DispatcherConfig> = {}) {
    this.config = { ...DEFAULT_DISPATCHER_CONFIG, ...config };
  }

  /**
   * Connect to the orchestrator.
   */
  setOrchestrator(orchestrator: AgentOrchestrator): void {
    this.orchestrator = orchestrator;
  }

  /**
   * Connect to WebSocket manager for real-time updates.
   */
  setWebSocketManager(wsManager: WebSocketManager): void {
    this.wsManager = wsManager;
  }

  /**
   * Get the current configuration.
   */
  getConfig(): DispatcherConfig {
    return this.config;
  }

  /**
   * Dispatch a case to appropriate agents.
   */
  async dispatchCase(caseId: string): Promise<DispatchResult> {
    const startTime = Date.now();
    const errors: string[] = [];
    const taskResults: TaskResult[] = [];

    if (!this.orchestrator) {
      return {
        caseId,
        tasksDispatched: 0,
        taskResults: [],
        errors: ['Orchestrator not connected'],
        duration: Date.now() - startTime,
      };
    }

    // Get case from database
    const caseData = getCaseById(caseId);
    if (!caseData) {
      return {
        caseId,
        tasksDispatched: 0,
        taskResults: [],
        errors: [`Case ${caseId} not found`],
        duration: Date.now() - startTime,
      };
    }

    const severity = caseData.severity as 'low' | 'medium' | 'high' | 'critical';
    const severityLevel = SEVERITY_ORDER[severity] ?? 0;

    // Build task payload
    const payload: TaskPayload = {
      caseId: caseData.id,
      severity,
      category: caseData.category,
      targetId: caseData.targetId,
      targetType: caseData.targetType,
      riskScore: caseData.riskScore,
      evidence: caseData.evidence,
      metadata: {},
    };

    // Determine which task types apply based on severity
    const applicableTasks = Object.entries(DISPATCH_RULES).filter(([_, rule]) => {
      const minSeverityLevel = SEVERITY_ORDER[rule.minSeverity] ?? 0;
      return severityLevel >= minSeverityLevel;
    });

    console.log(`[Dispatcher] Dispatching case ${caseId} (${severity}) to ${applicableTasks.length} task types`);

    // Dispatch to each applicable agent
    for (const [taskName, rule] of applicableTasks) {
      for (const role of rule.roles) {
        const agents = this.orchestrator.getAgentsByRole(role);
        const runningAgents = agents.filter(a => a.status === 'running');

        if (runningAgents.length === 0) {
          errors.push(`No running ${role} agents available`);
          continue;
        }

        // Pick the agent with lowest load (round-robin would be better but this is simple)
        const agent = runningAgents[0]!;  // We know it exists due to length check above

        // Build task-specific payload
        const taskPayload = this.buildTaskPayload(rule.taskType, payload);

        try {
          const result = await this.dispatchTaskToAgent(agent, rule.taskType, taskPayload);
          taskResults.push(result);

          if (result.success) {
            this.stats.totalSucceeded++;
          } else {
            this.stats.totalFailed++;
            errors.push(`${role}/${taskName}: ${result.error}`);
          }
        } catch (error) {
          this.stats.totalFailed++;
          const errorMsg = error instanceof Error ? error.message : 'Unknown error';
          errors.push(`${role}/${taskName}: ${errorMsg}`);
          taskResults.push({
            taskId: generateSecureId(),
            agentId: agent.id,
            agentRole: role,
            success: false,
            error: errorMsg,
            duration: 0,
            timestamp: new Date(),
          });
        }
      }
    }

    this.stats.totalDispatched += taskResults.length;

    // Update case status if tasks succeeded
    if (taskResults.length > 0) {
      const successCount = taskResults.filter(r => r.success).length;
      if (successCount > 0 && caseData.status === 'open') {
        updateCaseStatus(caseId, 'investigating', 'task-dispatcher');
      }
    }

    // Broadcast update
    this.broadcastEvent('tasks_dispatched', {
      caseId,
      tasksDispatched: taskResults.length,
      succeeded: taskResults.filter(r => r.success).length,
      failed: taskResults.filter(r => !r.success).length,
    });

    const duration = Date.now() - startTime;
    console.log(`[Dispatcher] Case ${caseId}: ${taskResults.length} tasks, ${taskResults.filter(r => r.success).length} succeeded in ${duration}ms`);

    return {
      caseId,
      tasksDispatched: taskResults.length,
      taskResults,
      errors,
      duration,
    };
  }

  /**
   * Dispatch a task to a specific agent.
   */
  private async dispatchTaskToAgent(
    agent: AgentInstance,
    taskType: string,
    payload: unknown
  ): Promise<TaskResult> {
    const startTime = Date.now();
    const taskId = generateSecureId();

    try {
      // Submit task to the agent via orchestrator
      const result = await this.orchestrator!.submitTask(agent.id, {
        type: taskType,
        payload,
      });

      const duration = Date.now() - startTime;

      // Update agent stats tracking
      this.updateAgentStats(agent.id, true);

      return {
        taskId,
        agentId: agent.id,
        agentRole: agent.role,
        success: true,
        result,
        duration,
        timestamp: new Date(),
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';

      // Update agent stats tracking
      this.updateAgentStats(agent.id, false);

      return {
        taskId,
        agentId: agent.id,
        agentRole: agent.role,
        success: false,
        error: errorMsg,
        duration,
        timestamp: new Date(),
      };
    }
  }

  /**
   * Build agent-specific task payload based on task type.
   */
  private buildTaskPayload(taskType: string, casePayload: TaskPayload): unknown {
    switch (taskType) {
      case 'verify_signal':
        // SensorAgent verify_signal expects these fields
        return {
          caseId: casePayload.caseId,
          severity: casePayload.severity,
          targetId: casePayload.targetId,
          riskScore: casePayload.riskScore,
        };

      case 'attribute':
        // ForensicAgent expects targetId for attribution
        return {
          targetId: casePayload.targetId,
        };

      case 'check_bias':
        // WatchdogAgent expects category and dimension
        return {
          category: 'severity',  // Check for severity bias
          dimension: casePayload.category,
        };

      case 'audit_action':
        // AuditorAgent expects an AuditableAction
        return {
          id: casePayload.caseId,
          type: 'case_created',
          actor: 'scan-scheduler',
          timestamp: Date.now(),
          data: {
            caseId: casePayload.caseId,
            targetId: casePayload.targetId,
            severity: casePayload.severity,
            category: casePayload.category,
            riskScore: casePayload.riskScore,
          },
          requiresApproval: casePayload.severity === 'critical',
          tier: casePayload.severity === 'critical' ? 4 :
                casePayload.severity === 'high' ? 3 :
                casePayload.severity === 'medium' ? 2 : 1,
        };

      default:
        // Return the full case payload for unknown task types
        return casePayload;
    }
  }

  /**
   * Update local stats for an agent.
   */
  private updateAgentStats(agentId: string, success: boolean): void {
    const stats = this.stats.byAgent.get(agentId) ?? { processed: 0, failed: 0 };
    if (success) {
      stats.processed++;
    } else {
      stats.failed++;
    }
    this.stats.byAgent.set(agentId, stats);
  }

  /**
   * Broadcast an event via WebSocket.
   */
  private broadcastEvent(type: string, data: unknown): void {
    if (this.wsManager) {
      this.wsManager.broadcastEvent({
        type: `dispatcher:${type}`,
        data,
        timestamp: new Date().toISOString(),
      });
    }
  }

  /**
   * Get dispatcher statistics.
   */
  getStats(): {
    totalDispatched: number;
    totalSucceeded: number;
    totalFailed: number;
    successRate: number;
    byAgent: Record<string, { processed: number; failed: number }>;
  } {
    const successRate = this.stats.totalDispatched > 0
      ? this.stats.totalSucceeded / this.stats.totalDispatched
      : 0;

    return {
      totalDispatched: this.stats.totalDispatched,
      totalSucceeded: this.stats.totalSucceeded,
      totalFailed: this.stats.totalFailed,
      successRate,
      byAgent: Object.fromEntries(this.stats.byAgent),
    };
  }

  /**
   * Reset statistics.
   */
  resetStats(): void {
    this.stats = {
      totalDispatched: 0,
      totalSucceeded: 0,
      totalFailed: 0,
      byAgent: new Map(),
    };
  }
}

// ============================================================================
// Singleton Instance
// ============================================================================

let dispatcherInstance: TaskDispatcher | null = null;

/**
 * Get the singleton dispatcher instance.
 */
export function getDispatcher(config?: Partial<DispatcherConfig>): TaskDispatcher {
  if (!dispatcherInstance) {
    dispatcherInstance = new TaskDispatcher(config);
  }
  return dispatcherInstance;
}

/**
 * Reset the dispatcher instance (for testing).
 */
export function resetDispatcher(): void {
  dispatcherInstance = null;
}
