/**
 * Agent Orchestrator
 *
 * Manages the lifecycle and coordination of all agent instances.
 * This is the central nervous system of the AI Authority node.
 */

import { EventEmitter } from 'events';
import { MessageBus, type AgentConfig, type AgentCapabilities, type AgentRole } from '@ai-authority/agents';
import { generateSecureId, generateEd25519KeyPair } from '@ai-authority/core';

// Agent imports
import { ScoutAgent } from '@ai-authority/detection';
import { SensorAgent } from '@ai-authority/detection';
import { LearnerAgent } from '@ai-authority/detection';
import { RiskScoringEngine } from '@ai-authority/scoring';
import { ForensicAgent } from '@ai-authority/scoring';
import { WatchdogAgent, AuditorAgent } from '@ai-authority/adjudication';
import { ProposerAgent, ApproverAgent, CuratorAgent } from '@ai-authority/governance';

// ============================================================================
// Types
// ============================================================================

export interface OrchestratorConfig {
  /** Unique node identifier */
  nodeId: string;

  /** Geographic region */
  region: string;

  /** Auto-start core agents on orchestrator start */
  autoStartAgents: boolean;

  /** Enable federation with other nodes */
  enableFederation: boolean;

  /** Federation bootstrap nodes */
  federationBootstrap?: string[];
}

export interface AgentInstance {
  id: string;
  role: string;
  layer: 'sensing' | 'analysis' | 'decision' | 'governance';
  status: 'initializing' | 'running' | 'stopped' | 'error';
  startedAt?: Date | undefined;
  stoppedAt?: Date | undefined;
  tasksProcessed: number;
  tasksFailed: number;
  lastHeartbeat?: Date | undefined;
  errorMessage?: string | undefined;
  agent: unknown; // The actual agent instance
}

export interface OrchestratorEvent {
  type: 'agent_started' | 'agent_stopped' | 'agent_error' | 'task_completed' | 'metrics_update';
  agentId?: string | undefined;
  data?: unknown;
  timestamp: Date;
}

export type OrchestratorEventHandler = (event: OrchestratorEvent) => void;

export interface OrchestratorMetrics {
  nodeId: string;
  region: string;
  uptime: number;
  totalAgents: number;
  runningAgents: number;
  totalTasksProcessed: number;
  totalTasksFailed: number;
  memoryUsage: NodeJS.MemoryUsage;
  cpuUsage: number;
}

// ============================================================================
// Agent Orchestrator
// ============================================================================

export class AgentOrchestrator extends EventEmitter {
  private readonly config: OrchestratorConfig;
  private readonly messageBus: MessageBus;
  private readonly agents: Map<string, AgentInstance> = new Map();
  private startTime?: Date | undefined;
  private metricsInterval?: ReturnType<typeof setInterval> | undefined;
  private isRunning = false;

  constructor(config: OrchestratorConfig) {
    super();
    this.config = config;
    this.messageBus = new MessageBus();
  }

  // ==========================================================================
  // Lifecycle
  // ==========================================================================

  async start(): Promise<void> {
    if (this.isRunning) {
      throw new Error('Orchestrator is already running');
    }

    console.log(`Starting orchestrator for node ${this.config.nodeId}...`);
    this.startTime = new Date();

    // Start message bus
    this.messageBus.start();

    // Auto-start core agents if configured
    if (this.config.autoStartAgents) {
      await this.startCoreAgents();
    }

    // Start metrics collection
    this.metricsInterval = setInterval(() => {
      this.collectMetrics();
    }, 5000);

    this.isRunning = true;
    console.log(`Orchestrator started with ${this.agents.size} agents`);
  }

  async stop(): Promise<void> {
    if (!this.isRunning) return;

    console.log('Stopping orchestrator...');

    // Clear metrics interval
    if (this.metricsInterval) {
      clearInterval(this.metricsInterval);
    }

    // Stop all agents
    for (const instance of this.agents.values()) {
      await this.stopAgent(instance.id);
    }

    // Stop message bus
    this.messageBus.stop();

    this.isRunning = false;
    console.log('Orchestrator stopped');
  }

  // ==========================================================================
  // Agent Management
  // ==========================================================================

  private async startCoreAgents(): Promise<void> {
    // Sensing layer
    await this.createAgent('scout', 'sensing');
    await this.createAgent('sensor', 'sensing');
    await this.createAgent('learner', 'sensing');

    // Analysis layer
    await this.createAgent('analyzer', 'analysis');
    await this.createAgent('forensic', 'analysis');

    // Decision layer
    await this.createAgent('watchdog', 'decision');
    await this.createAgent('auditor', 'decision');

    // Governance layer
    await this.createAgent('proposer', 'governance');
    await this.createAgent('approver', 'governance');
    await this.createAgent('curator', 'governance');
  }

  async createAgent(
    role: string,
    layer: 'sensing' | 'analysis' | 'decision' | 'governance'
  ): Promise<string> {
    const id = `${role}-${generateSecureId().slice(0, 8)}`;

    const instance: AgentInstance = {
      id,
      role,
      layer,
      status: 'initializing',
      tasksProcessed: 0,
      tasksFailed: 0,
      agent: null,
    };

    try {
      // Create the actual agent based on role
      const agent = this.instantiateAgent(role, id);
      instance.agent = agent;

      // Initialize the agent with message bus
      if (agent && typeof (agent as { initialize?: (bus: MessageBus) => Promise<void> }).initialize === 'function') {
        await (agent as { initialize: (bus: MessageBus) => Promise<void> }).initialize(this.messageBus);
      }

      // Start the agent
      if (agent && typeof (agent as { start?: () => Promise<void> }).start === 'function') {
        await (agent as { start: () => Promise<void> }).start();
      }

      instance.status = 'running';
      instance.startedAt = new Date();
      instance.lastHeartbeat = new Date();

      this.agents.set(id, instance);

      this.emitEvent({
        type: 'agent_started',
        agentId: id,
        data: { role, layer },
        timestamp: new Date(),
      });

      console.log(`  ✓ Started ${role} agent: ${id}`);
      return id;
    } catch (error) {
      instance.status = 'error';
      instance.errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.agents.set(id, instance);

      this.emitEvent({
        type: 'agent_error',
        agentId: id,
        data: { error: instance.errorMessage },
        timestamp: new Date(),
      });

      console.error(`  ✗ Failed to start ${role} agent: ${instance.errorMessage}`);
      return id;
    }
  }

  private instantiateAgent(role: string, _id: string): unknown {
    const config = this.createAgentConfig(role as AgentRole);

    switch (role) {
      case 'scout':
        return new ScoutAgent(config);
      case 'sensor':
        return new SensorAgent(config);
      case 'learner':
        return new LearnerAgent(config);
      case 'analyzer':
        // RiskScoringEngine uses DEFAULT_SCORING_CONFIG when no config provided
        return new RiskScoringEngine();
      case 'forensic':
        return new ForensicAgent(config);
      case 'watchdog':
        return new WatchdogAgent(config);
      case 'auditor':
        return new AuditorAgent(config);
      case 'proposer':
        return new ProposerAgent(config);
      case 'approver':
        return new ApproverAgent(config);
      case 'curator':
        return new CuratorAgent(config);
      default:
        throw new Error(`Unknown agent role: ${role}`);
    }
  }

  private createAgentConfig(role: AgentRole): AgentConfig {
    const capabilities: AgentCapabilities = {
      canRead: ['signals', 'metrics'],
      canWrite: [],
      canExecute: [],
      canPropose: role === 'proposer' || role === 'reflector',
      canApprove: role === 'approver',
      canIntervene: role === 'enforcer',
      maxInterventionTier: role === 'enforcer' ? 4 : 0,
    };

    // Generate real Ed25519 key pair for signing
    const keyPair = generateEd25519KeyPair();

    return {
      role,
      nodeId: this.config.nodeId,
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      capabilities,
      knowledgeEndpoints: [],
      peerAgents: [],
      heartbeatIntervalMs: 30000,
      maxConcurrentTasks: 10,
    };
  }

  async stopAgent(agentId: string): Promise<void> {
    const instance = this.agents.get(agentId);
    if (!instance) return;

    try {
      const agent = instance.agent as { stop?: () => Promise<void> };
      if (agent && typeof agent.stop === 'function') {
        await agent.stop();
      }

      instance.status = 'stopped';
      instance.stoppedAt = new Date();

      this.emitEvent({
        type: 'agent_stopped',
        agentId,
        timestamp: new Date(),
      });
    } catch (error) {
      instance.status = 'error';
      instance.errorMessage = error instanceof Error ? error.message : 'Unknown error';
    }
  }

  async restartAgent(agentId: string): Promise<void> {
    const instance = this.agents.get(agentId);
    if (!instance) {
      throw new Error(`Agent ${agentId} not found`);
    }

    await this.stopAgent(agentId);
    this.agents.delete(agentId);
    await this.createAgent(instance.role, instance.layer);
  }

  // ==========================================================================
  // Task Management
  // ==========================================================================

  async submitTask(agentId: string, task: { type: string; payload: unknown }): Promise<unknown> {
    const instance = this.agents.get(agentId);
    if (!instance || instance.status !== 'running') {
      throw new Error(`Agent ${agentId} is not available`);
    }

    const agent = instance.agent as {
      processTask?: (task: {
        id: string;
        type: string;
        priority: 'low' | 'medium' | 'high' | 'critical';
        payload: unknown;
        createdAt: number;
        retries: number;
        maxRetries: number;
      }) => Promise<unknown>;
    };

    if (!agent || typeof agent.processTask !== 'function') {
      throw new Error(`Agent ${agentId} does not support task processing`);
    }

    // Build a proper AgentTask structure
    const fullTask = {
      id: generateSecureId(),
      type: task.type,
      priority: 'medium' as const,
      payload: task.payload,
      createdAt: Date.now(),
      retries: 0,
      maxRetries: 2,
    };

    try {
      const result = await agent.processTask(fullTask);
      instance.tasksProcessed++;
      instance.lastHeartbeat = new Date();

      this.emitEvent({
        type: 'task_completed',
        agentId,
        data: { taskType: task.type, success: true },
        timestamp: new Date(),
      });

      return result;
    } catch (error) {
      instance.tasksFailed++;
      throw error;
    }
  }

  // ==========================================================================
  // Queries
  // ==========================================================================

  getAgent(agentId: string): AgentInstance | undefined {
    return this.agents.get(agentId);
  }

  getAllAgents(): AgentInstance[] {
    return Array.from(this.agents.values());
  }

  getAgentsByLayer(layer: string): AgentInstance[] {
    return Array.from(this.agents.values()).filter((a) => a.layer === layer);
  }

  getAgentsByRole(role: string): AgentInstance[] {
    return Array.from(this.agents.values()).filter((a) => a.role === role);
  }

  getRunningAgents(): AgentInstance[] {
    return Array.from(this.agents.values()).filter((a) => a.status === 'running');
  }

  getMetrics(): OrchestratorMetrics {
    const agents = Array.from(this.agents.values());
    const memUsage = process.memoryUsage();

    return {
      nodeId: this.config.nodeId,
      region: this.config.region,
      uptime: this.startTime ? Date.now() - this.startTime.getTime() : 0,
      totalAgents: agents.length,
      runningAgents: agents.filter((a) => a.status === 'running').length,
      totalTasksProcessed: agents.reduce((sum, a) => sum + a.tasksProcessed, 0),
      totalTasksFailed: agents.reduce((sum, a) => sum + a.tasksFailed, 0),
      memoryUsage: memUsage,
      cpuUsage: process.cpuUsage().user / 1000000, // Convert to seconds
    };
  }

  getMessageBus(): MessageBus {
    return this.messageBus;
  }

  // ==========================================================================
  // Events
  // ==========================================================================

  onEvent(handler: OrchestratorEventHandler): void {
    this.on('orchestrator_event', handler);
  }

  private emitEvent(event: OrchestratorEvent): void {
    this.emit('orchestrator_event', event);
  }

  private collectMetrics(): void {
    // Update heartbeats for all running agents
    for (const instance of this.agents.values()) {
      if (instance.status === 'running') {
        instance.lastHeartbeat = new Date();
      }
    }

    this.emitEvent({
      type: 'metrics_update',
      data: this.getMetrics(),
      timestamp: new Date(),
    });
  }
}
