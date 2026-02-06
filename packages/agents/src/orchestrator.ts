/**
 * Agent Orchestrator
 * 
 * Manages the lifecycle and coordination of all agents in a node.
 * Handles agent creation, health monitoring, and consensus coordination.
 */

import { generateSecureId, getTracer, MerkleTree } from '@ai-authority/core';
import type {
  AgentRole,
  AgentConfig,
  AgentMetrics,
  AgentMessage,
  ConsensusRequest,
  ConsensusVote,
} from './types.js';
import { getDefaultCapabilities } from './types.js';
import { BaseAgent } from './base.js';
import { MessageBus, createMessageBus } from './messaging.js';

const tracer = getTracer();

/** Orchestrator configuration */
export interface OrchestratorConfig {
  nodeId: string;
  privateKey: string;
  publicKey: string;
  knowledgeEndpoints: string[];
  heartbeatIntervalMs: number;
  healthCheckIntervalMs: number;
  consensusTimeoutMs: number;
  minAgentsForConsensus: number;
}

/** Agent factory function type */
export type AgentFactory = (config: AgentConfig) => BaseAgent;

/** Orchestrator state */
export interface OrchestratorState {
  nodeId: string;
  agents: Map<string, BaseAgent>;
  activeConsensus: Map<string, ConsensusRequest>;
  messageBus: MessageBus;
}

/**
 * Agent Orchestrator
 * 
 * Central coordinator for all agents in a node.
 */
export class AgentOrchestrator {
  private readonly config: OrchestratorConfig;
  private readonly agents: Map<string, BaseAgent> = new Map();
  private readonly agentFactories: Map<AgentRole, AgentFactory> = new Map();
  private readonly messageBus: MessageBus;
  private readonly activeConsensus: Map<string, ConsensusRequest> = new Map();
  private readonly auditLog: MerkleTree;
  private healthCheckInterval?: ReturnType<typeof setInterval>;
  private _running = false;

  constructor(config: OrchestratorConfig) {
    this.config = config;
    this.messageBus = createMessageBus();
    this.auditLog = new MerkleTree();
  }

  /** Check if orchestrator is running */
  get isRunning(): boolean {
    return this._running;
  }

  /** Register an agent factory for a role */
  registerFactory(role: AgentRole, factory: AgentFactory): void {
    this.agentFactories.set(role, factory);
  }

  /** Start the orchestrator */
  async start(): Promise<void> {
    return tracer.startActiveSpan('orchestrator.start', async (span) => {
      try {
        this._running = true;

        // Start health monitoring
        this.healthCheckInterval = setInterval(
          () => this.performHealthCheck(),
          this.config.healthCheckIntervalMs
        );

        // Subscribe to consensus messages
        await this.messageBus.subscribe('consensus', this.handleConsensusMessage.bind(this));

        this.logAudit('orchestrator_started', { nodeId: this.config.nodeId });
        span.setStatus({ code: 1 });
      } catch (error) {
        span.setStatus({ code: 2, message: String(error) });
        throw error;
      } finally {
        span.end();
      }
    });
  }

  /** Stop the orchestrator */
  async stop(): Promise<void> {
    this._running = false;

    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }

    // Stop all agents
    const stopPromises: Promise<void>[] = [];
    for (const agent of this.agents.values()) {
      stopPromises.push(agent.terminate());
    }
    await Promise.all(stopPromises);

    this.messageBus.stop();
    this.logAudit('orchestrator_stopped', { nodeId: this.config.nodeId });
  }

  /** Spawn a new agent */
  async spawnAgent(role: AgentRole, overrides?: Partial<AgentConfig>): Promise<string> {
    const factory = this.agentFactories.get(role);
    if (!factory) {
      throw new Error(`No factory registered for role: ${role}`);
    }

    const config: AgentConfig = {
      role,
      nodeId: this.config.nodeId,
      privateKey: this.config.privateKey,
      publicKey: this.config.publicKey,
      capabilities: getDefaultCapabilities(role),
      knowledgeEndpoints: this.config.knowledgeEndpoints,
      peerAgents: Array.from(this.agents.keys()),
      heartbeatIntervalMs: this.config.heartbeatIntervalMs,
      maxConcurrentTasks: 10,
      ...overrides,
    };

    const agent = factory(config);
    await agent.initialize(this.messageBus);
    await agent.start();

    this.agents.set(agent.id, agent);
    this.logAudit('agent_spawned', { agentId: agent.id, role });

    return agent.id;
  }

  /** Terminate an agent */
  async terminateAgent(agentId: string): Promise<void> {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${agentId}`);
    }

    await agent.terminate();
    this.agents.delete(agentId);
    this.logAudit('agent_terminated', { agentId });
  }

  /** Get agent by ID */
  getAgent(agentId: string): BaseAgent | undefined {
    return this.agents.get(agentId);
  }

  /** Get all agents */
  getAllAgents(): BaseAgent[] {
    return Array.from(this.agents.values());
  }

  /** Get agents by role */
  getAgentsByRole(role: AgentRole): BaseAgent[] {
    return Array.from(this.agents.values()).filter((a) => a.role === role);
  }

  /** Get aggregate metrics */
  getMetrics(): { nodeId: string; agents: AgentMetrics[] } {
    return {
      nodeId: this.config.nodeId,
      agents: Array.from(this.agents.values()).map((a) => a.getMetrics()),
    };
  }

  /** Initiate consensus */
  async initiateConsensus(
    type: ConsensusRequest['type'],
    proposal: unknown,
    requiredApprovals?: number
  ): Promise<string> {
    const request: ConsensusRequest = {
      id: generateSecureId(),
      type,
      proposer: this.config.nodeId,
      proposal,
      requiredApprovals: requiredApprovals ?? Math.ceil(this.agents.size * 0.67),
      deadline: Date.now() + this.config.consensusTimeoutMs,
      votes: [],
    };

    this.activeConsensus.set(request.id, request);

    // Broadcast to all agents
    await this.messageBus.publish('broadcast', {
      id: generateSecureId(),
      type: 'proposal',
      from: this.config.nodeId,
      to: 'broadcast',
      payload: request,
      timestamp: Date.now(),
      signature: '', // Would be signed in production
    });

    this.logAudit('consensus_initiated', { requestId: request.id, type });

    return request.id;
  }

  /** Submit a vote for consensus */
  async submitVote(
    consensusId: string,
    voterId: string,
    approve: boolean,
    reason?: string
  ): Promise<void> {
    const request = this.activeConsensus.get(consensusId);
    if (!request) {
      throw new Error(`Consensus not found: ${consensusId}`);
    }

    if (Date.now() > request.deadline) {
      throw new Error('Consensus deadline passed');
    }

    // Check if already voted
    if (request.votes.some((v) => v.voterId === voterId)) {
      throw new Error('Already voted');
    }

    const vote: ConsensusVote = {
      voterId,
      approve,
      reason,
      timestamp: Date.now(),
      signature: '', // Would be signed in production
    };

    request.votes.push(vote);

    // Check if consensus reached
    const approvals = request.votes.filter((v) => v.approve).length;
    if (approvals >= request.requiredApprovals) {
      await this.executeConsensus(request);
    }

    this.logAudit('consensus_vote', { consensusId, voterId, approve });
  }

  /** Get consensus status */
  getConsensusStatus(consensusId: string): ConsensusRequest | undefined {
    return this.activeConsensus.get(consensusId);
  }

  /** Handle consensus message */
  private async handleConsensusMessage(message: AgentMessage): Promise<void> {
    const payload = message.payload as ConsensusRequest | ConsensusVote;
    // Route to appropriate handler based on payload type
    if ('requiredApprovals' in payload) {
      // New consensus request
      const request = payload as ConsensusRequest;
      if (!this.activeConsensus.has(request.id)) {
        this.activeConsensus.set(request.id, request);
      }
    } else {
      // Vote
      // Handle in submitVote
    }
  }

  /** Execute consensus decision */
  private async executeConsensus(request: ConsensusRequest): Promise<void> {
    this.logAudit('consensus_reached', {
      requestId: request.id,
      type: request.type,
      approvals: request.votes.filter((v) => v.approve).length,
    });

    // Execute based on type
    switch (request.type) {
      case 'intervention':
        // Delegate to enforcer agents
        for (const agent of this.getAgentsByRole('enforcer')) {
          agent.submitTask({
            type: 'execute_intervention',
            priority: 'high',
            payload: request.proposal,
            maxRetries: 3,
          });
        }
        break;
      case 'knowledge_update':
        // Delegate to curator agents
        for (const agent of this.getAgentsByRole('curator')) {
          agent.submitTask({
            type: 'update_knowledge',
            priority: 'medium',
            payload: request.proposal,
            maxRetries: 3,
          });
        }
        break;
      case 'architecture_change':
        // Would require more complex handling
        break;
    }

    this.activeConsensus.delete(request.id);
  }

  /** Perform health check on all agents */
  private performHealthCheck(): void {
    const now = Date.now();
    const unhealthyThreshold = this.config.heartbeatIntervalMs * 3;

    for (const [id, agent] of this.agents) {
      const metrics = agent.getMetrics();
      const lastHeartbeat = metrics.lastHeartbeat;

      if (now - lastHeartbeat > unhealthyThreshold) {
        console.warn(`Agent ${id} appears unhealthy (no heartbeat for ${now - lastHeartbeat}ms)`);
        this.logAudit('agent_unhealthy', { agentId: id, lastHeartbeat });
      }
    }
  }

  /** Log to audit trail */
  private logAudit(action: string, data: Record<string, unknown>): void {
    const entry = {
      timestamp: Date.now(),
      nodeId: this.config.nodeId,
      action,
      data,
    };
    this.auditLog.append(JSON.stringify(entry));
  }
}

/** Create an orchestrator with default configuration */
export function createOrchestrator(
  config: Partial<OrchestratorConfig> & { nodeId: string; privateKey: string; publicKey: string }
): AgentOrchestrator {
  const fullConfig: OrchestratorConfig = {
    knowledgeEndpoints: [],
    heartbeatIntervalMs: 30000,
    healthCheckIntervalMs: 60000,
    consensusTimeoutMs: 300000,
    minAgentsForConsensus: 3,
    ...config,
  };

  return new AgentOrchestrator(fullConfig);
}
