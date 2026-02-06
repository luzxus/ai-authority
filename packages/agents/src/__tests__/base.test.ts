/**
 * BaseAgent Tests
 */

import { BaseAgent } from '../base';
import { MessageBus, createMessageBus } from '../messaging';
import type { AgentConfig, AgentTask, TaskResult, AgentRole } from '../types';
import { getDefaultCapabilities, getLayerForRole } from '../types';

/** Test implementation of BaseAgent */
class TestAgent extends BaseAgent {
  public processedTasks: AgentTask[] = [];
  public taskResults: Map<string, TaskResult> = new Map();

  protected async processTask<T, R>(task: AgentTask<T>): Promise<TaskResult<R>> {
    this.processedTasks.push(task as AgentTask);

    const result: TaskResult<R> = {
      taskId: task.id,
      success: true,
      result: { processed: true, payload: task.payload } as R,
      duration: 10,
      timestamp: Date.now(),
    };

    this.taskResults.set(task.id, result);
    return result;
  }

  // Expose protected methods for testing
  public async testQueryKnowledge() {
    return this.queryKnowledge({ type: 'embedding', query: 'test' });
  }
}

/** Create test agent config */
function createTestConfig(role: AgentRole = 'analyzer', overrides?: Partial<AgentConfig>): AgentConfig {
  return {
    role,
    nodeId: 'test-node',
    privateKey: 'test-private-key',
    publicKey: 'test-public-key',
    capabilities: getDefaultCapabilities(role),
    knowledgeEndpoints: ['http://localhost:9000'],
    peerAgents: [],
    heartbeatIntervalMs: 60000, // Long interval to avoid noise in tests
    maxConcurrentTasks: 5,
    ...overrides,
  };
}

describe('BaseAgent', () => {
  let messageBus: MessageBus;
  let agent: TestAgent;

  beforeEach(() => {
    messageBus = createMessageBus({ processingIntervalMs: 1 });
  });

  afterEach(async () => {
    if (agent && agent.currentState !== 'terminated') {
      await agent.terminate();
    }
    messageBus.stop();
  });

  describe('construction', () => {
    it('should create agent with unique ID', () => {
      const config = createTestConfig('analyzer');
      agent = new TestAgent(config);

      expect(agent.id).toBeDefined();
      expect(typeof agent.id).toBe('string');
      expect(agent.id.length).toBeGreaterThan(0);
    });

    it('should assign correct role', () => {
      const config = createTestConfig('scout');
      agent = new TestAgent(config);

      expect(agent.role).toBe('scout');
    });

    it('should start in initializing state', () => {
      const config = createTestConfig();
      agent = new TestAgent(config);

      expect(agent.currentState).toBe('initializing');
    });

    it('should generate different IDs for each instance', () => {
      const config = createTestConfig();
      const agent1 = new TestAgent(config);
      const agent2 = new TestAgent(config);

      expect(agent1.id).not.toBe(agent2.id);
    });
  });

  describe('lifecycle', () => {
    it('should initialize and transition to ready state', async () => {
      const config = createTestConfig();
      agent = new TestAgent(config);

      await agent.initialize(messageBus);

      expect(agent.currentState).toBe('ready');
    });

    it('should start and transition to running state', async () => {
      const config = createTestConfig();
      agent = new TestAgent(config);

      await agent.initialize(messageBus);
      await agent.start();

      expect(agent.currentState).toBe('running');
    });

    it('should stop and transition to paused state', async () => {
      const config = createTestConfig();
      agent = new TestAgent(config);

      await agent.initialize(messageBus);
      await agent.start();
      await agent.stop();

      expect(agent.currentState).toBe('paused');
    });

    it('should terminate and transition to terminated state', async () => {
      const config = createTestConfig();
      agent = new TestAgent(config);

      await agent.initialize(messageBus);
      await agent.start();
      await agent.terminate();

      expect(agent.currentState).toBe('terminated');
    });

    it('should throw error when starting from wrong state', async () => {
      const config = createTestConfig();
      agent = new TestAgent(config);

      // Not initialized yet
      await expect(agent.start()).rejects.toThrow('Cannot start agent in state');
    });

    it('should allow restart from paused state', async () => {
      const config = createTestConfig();
      agent = new TestAgent(config);

      await agent.initialize(messageBus);
      await agent.start();
      await agent.stop();
      await agent.start(); // Restart

      expect(agent.currentState).toBe('running');
    });
  });

  describe('metrics', () => {
    it('should provide initial metrics', () => {
      const config = createTestConfig();
      agent = new TestAgent(config);

      const metrics = agent.getMetrics();

      expect(metrics.agentId).toBe(agent.id);
      expect(metrics.tasksProcessed).toBe(0);
      expect(metrics.tasksFailed).toBe(0);
      expect(metrics.messagesReceived).toBe(0);
      expect(metrics.messagesSent).toBe(0);
    });

    it('should calculate uptime', async () => {
      const config = createTestConfig();
      agent = new TestAgent(config);

      // Wait a bit
      await new Promise((resolve) => setTimeout(resolve, 50));

      const metrics = agent.getMetrics();
      expect(metrics.uptime).toBeGreaterThan(0);
    });
  });

  describe('task processing', () => {
    it('should submit and process tasks', async () => {
      const config = createTestConfig();
      agent = new TestAgent(config);

      await agent.initialize(messageBus);
      await agent.start();

      const taskId = agent.submitTask({
        type: 'test-task',
        priority: 'medium',
        payload: { value: 42 },
        maxRetries: 3,
      });

      // Wait for processing
      await new Promise((resolve) => setTimeout(resolve, 100));

      expect(agent.processedTasks.length).toBe(1);
      expect(agent.processedTasks[0]!.id).toBe(taskId);
      expect(agent.processedTasks[0]!.payload).toEqual({ value: 42 });
    });

    it('should prioritize critical tasks', async () => {
      const config = createTestConfig();
      agent = new TestAgent(config);

      await agent.initialize(messageBus);

      // Submit tasks before starting
      agent.submitTask({
        type: 'low-priority',
        priority: 'low',
        payload: { order: 1 },
        maxRetries: 1,
      });

      agent.submitTask({
        type: 'critical-priority',
        priority: 'critical',
        payload: { order: 2 },
        maxRetries: 1,
      });

      agent.submitTask({
        type: 'medium-priority',
        priority: 'medium',
        payload: { order: 3 },
        maxRetries: 1,
      });

      await agent.start();

      // Wait for processing
      await new Promise((resolve) => setTimeout(resolve, 200));

      // Critical should be processed first
      expect(agent.processedTasks[0]!.type).toBe('critical-priority');
    });

    it('should assign unique task IDs', async () => {
      const config = createTestConfig();
      agent = new TestAgent(config);

      await agent.initialize(messageBus);

      const taskId1 = agent.submitTask({
        type: 'task-1',
        priority: 'low',
        payload: {},
        maxRetries: 1,
      });

      const taskId2 = agent.submitTask({
        type: 'task-2',
        priority: 'low',
        payload: {},
        maxRetries: 1,
      });

      expect(taskId1).not.toBe(taskId2);
    });
  });

  describe('knowledge queries', () => {
    it('should return empty result for knowledge queries', async () => {
      const config = createTestConfig();
      agent = new TestAgent(config);

      const result = await agent.testQueryKnowledge();

      expect(result.matches).toEqual([]);
      expect(result.queryTime).toBe(0);
    });
  });
});

describe('getLayerForRole', () => {
  it('should return sensing for sensing roles', () => {
    expect(getLayerForRole('scout')).toBe('sensing');
    expect(getLayerForRole('sensor')).toBe('sensing');
    expect(getLayerForRole('learner')).toBe('sensing');
  });

  it('should return analysis for analysis roles', () => {
    expect(getLayerForRole('analyzer')).toBe('analysis');
    expect(getLayerForRole('forensic')).toBe('analysis');
    expect(getLayerForRole('reflector')).toBe('analysis');
  });

  it('should return decision for decision roles', () => {
    expect(getLayerForRole('enforcer')).toBe('decision');
    expect(getLayerForRole('watchdog')).toBe('decision');
    expect(getLayerForRole('auditor')).toBe('decision');
  });

  it('should return governance for governance roles', () => {
    expect(getLayerForRole('proposer')).toBe('governance');
    expect(getLayerForRole('approver')).toBe('governance');
    expect(getLayerForRole('curator')).toBe('governance');
  });
});

describe('getDefaultCapabilities', () => {
  it('should grant intervention capability only to enforcer', () => {
    const roles: AgentRole[] = ['scout', 'sensor', 'analyzer', 'forensic', 'proposer', 'approver', 'curator'];
    
    for (const role of roles) {
      const caps = getDefaultCapabilities(role);
      expect(caps.canIntervene).toBe(false);
    }

    const enforcerCaps = getDefaultCapabilities('enforcer');
    expect(enforcerCaps.canIntervene).toBe(true);
    expect(enforcerCaps.maxInterventionTier).toBe(3);
  });

  it('should grant propose capability to proposer and reflector', () => {
    const proposerCaps = getDefaultCapabilities('proposer');
    const reflectorCaps = getDefaultCapabilities('reflector');

    expect(proposerCaps.canPropose).toBe(true);
    expect(reflectorCaps.canPropose).toBe(true);
  });

  it('should grant approve capability only to approver', () => {
    const approverCaps = getDefaultCapabilities('approver');
    expect(approverCaps.canApprove).toBe(true);

    // Others should not have approve
    const proposerCaps = getDefaultCapabilities('proposer');
    expect(proposerCaps.canApprove).toBe(false);
  });

  it('should give scout explore and probe capabilities', () => {
    const caps = getDefaultCapabilities('scout');
    expect(caps.canExecute).toContain('explore');
    expect(caps.canExecute).toContain('probe');
  });

  it('should give curator write access to knowledge', () => {
    const caps = getDefaultCapabilities('curator');
    expect(caps.canWrite).toContain('knowledge');
  });
});
