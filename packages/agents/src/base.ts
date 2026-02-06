/**
 * Base Agent Class
 * 
 * Abstract base class for all autonomous agents in the AI Authority network.
 * Provides lifecycle management, message handling, and common utilities.
 */

import { generateSecureId, sign, getTracer, MerkleTree } from '@ai-authority/core';
import type {
  AgentIdentity,
  AgentConfig,
  AgentState,
  AgentMetrics,
  AgentMessage,
  AgentTask,
  TaskResult,
  MessageType,
  KnowledgeQuery,
  KnowledgeResult,
  AgentRole,
} from './types.js';
import { getLayerForRole } from './types.js';
import { MessageBus } from './messaging.js';

const tracer = getTracer();

/** Event emitter interface for agent events */
export interface AgentEventEmitter {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  on(event: string, listener: (...args: any[]) => void): void;
  emit(event: string, ...args: unknown[]): void;
  removeAllListeners(event?: string): void;
}

/** Simple event emitter implementation */
class SimpleEventEmitter implements AgentEventEmitter {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private listeners: Map<string, Array<(...args: any[]) => void>> = new Map();

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  on(event: string, listener: (...args: any[]) => void): void {
    const existing = this.listeners.get(event) ?? [];
    existing.push(listener);
    this.listeners.set(event, existing);
  }

  emit(event: string, ...args: unknown[]): void {
    const listeners = this.listeners.get(event) ?? [];
    for (const listener of listeners) {
      try {
        listener(...args);
      } catch (e) {
        console.error(`Error in event listener for ${event}:`, e);
      }
    }
  }

  removeAllListeners(event?: string): void {
    if (event) {
      this.listeners.delete(event);
    } else {
      this.listeners.clear();
    }
  }
}

/**
 * Abstract base class for all agents.
 * Subclasses must implement processTask() and can override lifecycle hooks.
 */
export abstract class BaseAgent {
  protected readonly identity: AgentIdentity;
  protected readonly config: AgentConfig;
  protected state: AgentState = 'initializing';
  protected readonly events: AgentEventEmitter;
  protected readonly auditLog: MerkleTree;
  protected readonly metrics: AgentMetrics;
  protected messageBus?: MessageBus;

  private heartbeatInterval?: ReturnType<typeof setInterval>;
  private taskQueue: AgentTask[] = [];
  private activeTasks: Map<string, AgentTask> = new Map();

  constructor(config: AgentConfig) {
    this.config = config;
    this.events = new SimpleEventEmitter();
    this.auditLog = new MerkleTree();

    // Create identity
    this.identity = {
      id: generateSecureId(),
      role: config.role,
      layer: getLayerForRole(config.role),
      publicKey: config.publicKey,
      nodeId: config.nodeId,
      createdAt: Date.now(),
    };

    // Initialize metrics
    this.metrics = {
      agentId: this.identity.id,
      uptime: 0,
      tasksProcessed: 0,
      tasksFailed: 0,
      messagesReceived: 0,
      messagesSent: 0,
      lastHeartbeat: Date.now(),
      averageLatencyMs: 0,
      knowledgeQueriesPerSec: 0,
    };

    // Log creation
    this.logAudit('agent_created', { identity: this.identity });
  }

  /** Get agent ID */
  get id(): string {
    return this.identity.id;
  }

  /** Get agent role */
  get role(): AgentRole {
    return this.identity.role;
  }

  /** Get current state */
  get currentState(): AgentState {
    return this.state;
  }

  /** Get current metrics */
  getMetrics(): AgentMetrics {
    return {
      ...this.metrics,
      uptime: Date.now() - this.identity.createdAt,
    };
  }

  /** Initialize the agent */
  async initialize(messageBus: MessageBus): Promise<void> {
    return tracer.startActiveSpan('agent.initialize', async (span) => {
      try {
        this.messageBus = messageBus;

        // Subscribe to messages
        await messageBus.subscribe(this.identity.id, this.handleMessage.bind(this));
        await messageBus.subscribe('broadcast', this.handleMessage.bind(this));

        // Call subclass initialization
        await this.onInitialize();

        this.setState('ready');
        span.setStatus({ code: 1 }); // OK
      } catch (error) {
        this.setState('error');
        span.setStatus({ code: 2, message: String(error) }); // ERROR
        throw error;
      } finally {
        span.end();
      }
    });
  }

  /** Start the agent */
  async start(): Promise<void> {
    if (this.state !== 'ready' && this.state !== 'paused') {
      throw new Error(`Cannot start agent in state: ${this.state}`);
    }

    this.setState('running');

    // Start heartbeat
    this.heartbeatInterval = setInterval(
      () => this.sendHeartbeat(),
      this.config.heartbeatIntervalMs
    );

    // Call subclass start
    await this.onStart();

    // Start processing tasks
    this.processTaskQueue();

    this.logAudit('agent_started', {});
  }

  /** Stop the agent */
  async stop(): Promise<void> {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }

    this.setState('paused');

    // Call subclass stop
    await this.onStop();

    this.logAudit('agent_stopped', {});
  }

  /** Terminate the agent */
  async terminate(): Promise<void> {
    await this.stop();
    this.setState('terminated');

    // Unsubscribe from messages
    if (this.messageBus) {
      await this.messageBus.unsubscribe(this.identity.id);
    }

    this.events.removeAllListeners();

    this.logAudit('agent_terminated', {});
  }

  /** Submit a task for processing */
  submitTask<T>(task: Omit<AgentTask<T>, 'id' | 'createdAt' | 'retries'>): string {
    const fullTask: AgentTask<T> = {
      ...task,
      id: generateSecureId(),
      createdAt: Date.now(),
      retries: 0,
    };

    this.taskQueue.push(fullTask as AgentTask);
    this.taskQueue.sort((a, b) => {
      const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      return priorityOrder[a.priority] - priorityOrder[b.priority];
    });

    this.events.emit('task', fullTask);
    return fullTask.id;
  }

  /** Send a message to another agent or broadcast */
  async sendMessage<T>(
    to: string | 'broadcast',
    type: MessageType,
    payload: T,
    correlationId?: string
  ): Promise<void> {
    if (!this.messageBus) {
      throw new Error('Agent not initialized');
    }

    const message: AgentMessage<T> = {
      id: generateSecureId(),
      type,
      from: this.identity.id,
      to,
      payload,
      timestamp: Date.now(),
      signature: '',
      correlationId,
    };

    // Sign the message
    message.signature = sign(JSON.stringify(message), this.config.privateKey);

    await this.messageBus.publish(to, message);
    this.metrics.messagesSent++;
  }

  /** Query knowledge base */
  protected async queryKnowledge(_query: KnowledgeQuery): Promise<KnowledgeResult> {
    // TODO: Implement actual knowledge query via knowledge package
    // For now, return empty result
    return {
      matches: [],
      queryTime: 0,
      totalSearched: 0,
    };
  }

  /** Abstract method: process a task (must be implemented by subclasses) */
  protected abstract processTask<T, R>(task: AgentTask<T>): Promise<TaskResult<R>>;

  /** Lifecycle hook: called during initialization */
  protected async onInitialize(): Promise<void> {
    // Override in subclass
  }

  /** Lifecycle hook: called when starting */
  protected async onStart(): Promise<void> {
    // Override in subclass
  }

  /** Lifecycle hook: called when stopping */
  protected async onStop(): Promise<void> {
    // Override in subclass
  }

  /** Handle incoming message */
  private async handleMessage(message: AgentMessage): Promise<void> {
    // TODO: Implement proper signature verification with public key registry
    // For now, skip signature verification in single-node mode
    // The signature is still generated and stored for future distributed mode
    // const msgCopy = { ...message, signature: '' };
    // if (!verify(JSON.stringify(msgCopy), message.signature, message.from)) {
    //   console.warn(`Invalid signature on message from ${message.from}`);
    //   return;
    // }

    this.metrics.messagesReceived++;
    this.events.emit('message', message);

    // Handle by type
    switch (message.type) {
      case 'heartbeat':
        // Heartbeat received - no action needed
        break;
      case 'command':
        await this.handleCommand(message as AgentMessage<{ command: string; args?: unknown }>);
        break;
      default:
        await this.onMessage(message);
    }
  }

  /** Handle command message */
  private async handleCommand(message: AgentMessage<{ command: string; args?: unknown }>): Promise<void> {
    const { command, args } = message.payload;
    switch (command) {
      case 'pause':
        await this.stop();
        break;
      case 'resume':
        await this.start();
        break;
      case 'terminate':
        await this.terminate();
        break;
      default:
        await this.onCommand(command, args);
    }
  }

  /** Message handler hook (override in subclass) */
  protected async onMessage(_message: AgentMessage): Promise<void> {
    // Override in subclass
  }

  /** Command handler hook (override in subclass) */
  protected async onCommand(_command: string, _args: unknown): Promise<void> {
    // Override in subclass
  }

  /** Process task queue */
  private async processTaskQueue(): Promise<void> {
    while (this.state === 'running') {
      // Check if we can process more tasks
      if (this.activeTasks.size >= this.config.maxConcurrentTasks) {
        await this.sleep(100);
        continue;
      }

      // Get next task
      const task = this.taskQueue.shift();
      if (!task) {
        await this.sleep(100);
        continue;
      }

      // Process task
      this.activeTasks.set(task.id, task);
      this.executeTask(task).finally(() => {
        this.activeTasks.delete(task.id);
      });
    }
  }

  /** Execute a single task */
  private async executeTask(task: AgentTask): Promise<void> {
    const startTime = Date.now();

    try {
      const result = await this.processTask(task);

      if (result.success) {
        this.metrics.tasksProcessed++;
      } else {
        // Retry if possible
        if (task.retries < task.maxRetries) {
          task.retries++;
          this.taskQueue.push(task);
        } else {
          this.metrics.tasksFailed++;
        }
      }

      // Update average latency
      const duration = Date.now() - startTime;
      this.metrics.averageLatencyMs =
        (this.metrics.averageLatencyMs * (this.metrics.tasksProcessed - 1) + duration) /
        this.metrics.tasksProcessed;

      this.logAudit('task_completed', {
        taskId: task.id,
        success: result.success,
        duration,
      });
    } catch (error) {
      this.metrics.tasksFailed++;
      this.events.emit('error', error instanceof Error ? error : new Error(String(error)));
      this.logAudit('task_failed', {
        taskId: task.id,
        error: String(error),
      });
    }
  }

  /** Send heartbeat */
  private async sendHeartbeat(): Promise<void> {
    this.metrics.lastHeartbeat = Date.now();
    await this.sendMessage('broadcast', 'heartbeat', {
      agentId: this.identity.id,
      state: this.state,
      metrics: this.getMetrics(),
    });
  }

  /** Set agent state */
  private setState(newState: AgentState): void {
    const oldState = this.state;
    this.state = newState;
    this.events.emit('stateChange', newState);
    this.logAudit('state_changed', { from: oldState, to: newState });
  }

  /** Log to audit trail */
  protected logAudit(action: string, data: Record<string, unknown>): void {
    const entry = {
      timestamp: Date.now(),
      agentId: this.identity.id,
      action,
      data,
    };
    this.auditLog.append(JSON.stringify(entry));
  }

  /** Sleep utility */
  protected sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
