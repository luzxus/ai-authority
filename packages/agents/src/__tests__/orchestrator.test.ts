/**
 * AgentOrchestrator Tests
 */

import { AgentOrchestrator, createOrchestrator, OrchestratorConfig, AgentFactory } from '../orchestrator';
import { BaseAgent } from '../base';
import type { AgentConfig, AgentTask, TaskResult } from '../types';

/** Test agent implementation */
class MockAgent extends BaseAgent {
  public processedTasks: AgentTask[] = [];

  protected async processTask<T, R>(task: AgentTask<T>): Promise<TaskResult<R>> {
    this.processedTasks.push(task as AgentTask);
    return {
      taskId: task.id,
      success: true,
      result: { done: true } as R,
      duration: 5,
      timestamp: Date.now(),
    };
  }
}

/** Create mock agent factory */
function createMockFactory(): AgentFactory {
  return (config: AgentConfig) => new MockAgent(config);
}

/** Default test config */
function createTestOrchestratorConfig(): OrchestratorConfig {
  return {
    nodeId: 'test-node',
    privateKey: 'test-private-key',
    publicKey: 'test-public-key',
    knowledgeEndpoints: ['http://localhost:9000'],
    heartbeatIntervalMs: 60000,
    healthCheckIntervalMs: 60000,
    consensusTimeoutMs: 30000,
    minAgentsForConsensus: 2,
  };
}

describe('AgentOrchestrator', () => {
  let orchestrator: AgentOrchestrator;

  beforeEach(() => {
    orchestrator = new AgentOrchestrator(createTestOrchestratorConfig());
  });

  afterEach(async () => {
    if (orchestrator.isRunning) {
      await orchestrator.stop();
    }
  });

  describe('lifecycle', () => {
    it('should start successfully', async () => {
      await orchestrator.start();
      expect(orchestrator.isRunning).toBe(true);
    });

    it('should stop successfully', async () => {
      await orchestrator.start();
      await orchestrator.stop();
      expect(orchestrator.isRunning).toBe(false);
    });

    it('should not be running initially', () => {
      expect(orchestrator.isRunning).toBe(false);
    });
  });

  describe('agent factory registration', () => {
    it('should register agent factory', () => {
      const factory = createMockFactory();
      orchestrator.registerFactory('analyzer', factory);

      // No error means success
      expect(true).toBe(true);
    });

    it('should allow multiple factories for different roles', () => {
      orchestrator.registerFactory('analyzer', createMockFactory());
      orchestrator.registerFactory('scout', createMockFactory());
      orchestrator.registerFactory('enforcer', createMockFactory());

      // No error means success
      expect(true).toBe(true);
    });
  });

  describe('agent spawning', () => {
    beforeEach(async () => {
      orchestrator.registerFactory('analyzer', createMockFactory());
      orchestrator.registerFactory('scout', createMockFactory());
      await orchestrator.start();
    });

    it('should spawn agent with registered factory', async () => {
      const agentId = await orchestrator.spawnAgent('analyzer');

      expect(typeof agentId).toBe('string');
      expect(agentId.length).toBeGreaterThan(0);
    });

    it('should track spawned agents', async () => {
      const agentId = await orchestrator.spawnAgent('analyzer');
      const agent = orchestrator.getAgent(agentId);

      expect(agent).toBeDefined();
      expect(agent?.role).toBe('analyzer');
    });

    it('should throw error for unregistered role', async () => {
      await expect(orchestrator.spawnAgent('enforcer')).rejects.toThrow('No factory registered');
    });

    it('should spawn multiple agents', async () => {
      await orchestrator.spawnAgent('analyzer');
      await orchestrator.spawnAgent('analyzer');
      await orchestrator.spawnAgent('scout');

      const allAgents = orchestrator.getAllAgents();
      expect(allAgents.length).toBe(3);
    });
  });

  describe('agent management', () => {
    beforeEach(async () => {
      orchestrator.registerFactory('analyzer', createMockFactory());
      orchestrator.registerFactory('scout', createMockFactory());
      await orchestrator.start();
    });

    it('should get agent by ID', async () => {
      const agentId = await orchestrator.spawnAgent('analyzer');
      const agent = orchestrator.getAgent(agentId);

      expect(agent).toBeDefined();
      expect(agent?.id).toBe(agentId);
    });

    it('should return undefined for unknown agent ID', () => {
      const agent = orchestrator.getAgent('unknown-id');
      expect(agent).toBeUndefined();
    });

    it('should get all agents', async () => {
      await orchestrator.spawnAgent('analyzer');
      await orchestrator.spawnAgent('scout');

      const agents = orchestrator.getAllAgents();
      expect(agents.length).toBe(2);
    });

    it('should get agents by role', async () => {
      await orchestrator.spawnAgent('analyzer');
      await orchestrator.spawnAgent('analyzer');
      await orchestrator.spawnAgent('scout');

      const analyzers = orchestrator.getAgentsByRole('analyzer');
      const scouts = orchestrator.getAgentsByRole('scout');

      expect(analyzers.length).toBe(2);
      expect(scouts.length).toBe(1);
    });

    it('should terminate agent', async () => {
      const agentId = await orchestrator.spawnAgent('analyzer');

      await orchestrator.terminateAgent(agentId);

      const agent = orchestrator.getAgent(agentId);
      expect(agent).toBeUndefined();
    });

    it('should throw error when terminating unknown agent', async () => {
      await expect(orchestrator.terminateAgent('unknown')).rejects.toThrow('Agent not found');
    });
  });

  describe('metrics', () => {
    beforeEach(async () => {
      orchestrator.registerFactory('analyzer', createMockFactory());
      await orchestrator.start();
    });

    it('should provide aggregate metrics', async () => {
      await orchestrator.spawnAgent('analyzer');
      await orchestrator.spawnAgent('analyzer');

      const metrics = orchestrator.getMetrics();

      expect(metrics.nodeId).toBe('test-node');
      expect(metrics.agents.length).toBe(2);
    });

    it('should include individual agent metrics', async () => {
      const agentId = await orchestrator.spawnAgent('analyzer');

      const metrics = orchestrator.getMetrics();
      const agentMetrics = metrics.agents.find((m) => m.agentId === agentId);

      expect(agentMetrics).toBeDefined();
      expect(agentMetrics?.tasksProcessed).toBe(0);
    });
  });

  describe('consensus', () => {
    beforeEach(async () => {
      orchestrator.registerFactory('analyzer', createMockFactory());
      orchestrator.registerFactory('enforcer', createMockFactory());
      await orchestrator.start();
    });

    it('should initiate consensus', async () => {
      await orchestrator.spawnAgent('analyzer');
      await orchestrator.spawnAgent('analyzer');

      const consensusId = await orchestrator.initiateConsensus(
        'intervention',
        { target: 'malicious-agent', action: 'throttle' },
        2
      );

      expect(typeof consensusId).toBe('string');
      expect(consensusId.length).toBeGreaterThan(0);
    });

    it('should track consensus status', async () => {
      await orchestrator.spawnAgent('analyzer');

      const consensusId = await orchestrator.initiateConsensus(
        'knowledge_update',
        { rule: 'new-rule' },
        1
      );

      const status = orchestrator.getConsensusStatus(consensusId);

      expect(status).toBeDefined();
      expect(status?.type).toBe('knowledge_update');
      expect(status?.votes.length).toBe(0);
    });

    it('should accept votes', async () => {
      const agentId = await orchestrator.spawnAgent('analyzer');

      const consensusId = await orchestrator.initiateConsensus(
        'intervention',
        { action: 'test' },
        2
      );

      await orchestrator.submitVote(consensusId, agentId, true, 'Approved');

      const status = orchestrator.getConsensusStatus(consensusId);
      expect(status?.votes.length).toBe(1);
      expect(status?.votes[0]!.approve).toBe(true);
    });

    it('should reject duplicate votes', async () => {
      const agentId = await orchestrator.spawnAgent('analyzer');

      const consensusId = await orchestrator.initiateConsensus(
        'intervention',
        { action: 'test' },
        3
      );

      await orchestrator.submitVote(consensusId, agentId, true);

      await expect(
        orchestrator.submitVote(consensusId, agentId, false)
      ).rejects.toThrow('Already voted');
    });

    it('should throw error for unknown consensus', async () => {
      await expect(
        orchestrator.submitVote('unknown-id', 'voter-1', true)
      ).rejects.toThrow('Consensus not found');
    });

    it('should return undefined for unknown consensus status', () => {
      const status = orchestrator.getConsensusStatus('unknown');
      expect(status).toBeUndefined();
    });
  });
});

describe('createOrchestrator helper', () => {
  it('should create orchestrator with partial config', () => {
    const orchestrator = createOrchestrator({
      nodeId: 'helper-node',
      privateKey: 'pk',
      publicKey: 'pub',
    });

    expect(orchestrator).toBeInstanceOf(AgentOrchestrator);
  });

  it('should apply default values', async () => {
    const orchestrator = createOrchestrator({
      nodeId: 'default-node',
      privateKey: 'pk',
      publicKey: 'pub',
    });

    // Should be able to start without error
    await orchestrator.start();
    expect(orchestrator.isRunning).toBe(true);
    await orchestrator.stop();
  });

  it('should allow overriding defaults', () => {
    const orchestrator = createOrchestrator({
      nodeId: 'custom-node',
      privateKey: 'pk',
      publicKey: 'pub',
      heartbeatIntervalMs: 15000,
      consensusTimeoutMs: 60000,
    });

    // Just verify creation works
    expect(orchestrator).toBeDefined();
  });
});
