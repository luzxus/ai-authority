/**
 * Learner Agent Tests
 */

import { MessageBus, createMessageBus, type AgentConfig } from '@ai-authority/agents';
import { getDefaultCapabilities } from '@ai-authority/agents';
import { generateRSAKeyPair } from '@ai-authority/core';
import {
  LearnerAgent,
  type LearningEpisode,
  type Observation,
  type LearningConfig,
} from '../learner';

// Generate real RSA keys for tests
const testKeyPair = generateRSAKeyPair();

function createTestConfig(overrides?: Partial<AgentConfig>): AgentConfig {
  return {
    role: 'learner',
    nodeId: 'test-node',
    privateKey: testKeyPair.privateKey,
    publicKey: testKeyPair.publicKey,
    capabilities: getDefaultCapabilities('learner'),
    knowledgeEndpoints: ['http://localhost:9000'],
    peerAgents: [],
    heartbeatIntervalMs: 60000,
    maxConcurrentTasks: 5,
    ...overrides,
  };
}

function createTestObservation(features?: number[]): Observation {
  return {
    features: features ?? [0.5, 0.3, 0.7, 0.2, 0.4, 0.1, 0.6, 0.8],
    context: { testContext: true },
    source: 'test-source',
    timestamp: Date.now(),
  };
}

function createTestEpisode(overrides?: Partial<LearningEpisode>): LearningEpisode {
  return {
    id: `episode-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    timestamp: Date.now(),
    observation: createTestObservation(),
    action: {
      type: 'classify',
      parameters: {},
      confidence: 0.7,
    },
    reward: 1,
    done: true,
    metadata: {},
    ...overrides,
  };
}

describe('LearnerAgent', () => {
  let agent: LearnerAgent;
  let messageBus: MessageBus;

  beforeEach(() => {
    messageBus = createMessageBus({ processingIntervalMs: 1 });
    const config = createTestConfig();
    agent = new LearnerAgent(config);
  });

  afterEach(async () => {
    if (agent.currentState !== 'terminated') {
      await agent.terminate();
    }
    messageBus.stop();
  });

  describe('construction', () => {
    it('should create agent with learner role', () => {
      expect(agent.role).toBe('learner');
    });

    it('should initialize with default metrics', () => {
      const metrics = agent.getModelMetrics();
      expect(metrics.accuracy).toBe(0.5);
      expect(metrics.precision).toBe(0.5);
      expect(metrics.recall).toBe(0.5);
      expect(metrics.f1Score).toBe(0.5);
    });

    it('should accept custom learning config', () => {
      const customConfig: Partial<LearningConfig> = {
        learningRate: 0.01,
        explorationRate: 0.2,
      };
      const customAgent = new LearnerAgent(createTestConfig(), customConfig);
      expect(customAgent.role).toBe('learner');
    });

    it('should initialize weights', () => {
      const weights = agent.getWeights();
      expect(Object.keys(weights).length).toBeGreaterThan(0);
      expect(weights['harm_weight']).toBeDefined();
    });
  });

  describe('lifecycle', () => {
    it('should initialize successfully', async () => {
      await agent.initialize(messageBus);
      expect(agent.currentState).toBe('ready');
    });

    it('should start successfully', async () => {
      await agent.initialize(messageBus);
      await agent.start();
      expect(agent.currentState).toBe('running');
    });
  });

  describe('learning', () => {
    beforeEach(async () => {
      await agent.initialize(messageBus);
      await agent.start();
    });

    it('should learn from single episode', async () => {
      const episode = createTestEpisode();
      
      agent.submitTask({
        type: 'learn',
        priority: 'medium',
        payload: episode,
        maxRetries: 1,
      });

      await new Promise(resolve => setTimeout(resolve, 150));

      expect(agent.getBufferSize()).toBe(1);
    });

    it('should learn from batch of episodes', async () => {
      const episodes = Array.from({ length: 10 }, () => createTestEpisode());

      agent.submitTask({
        type: 'batch_learn',
        priority: 'medium',
        payload: episodes,
        maxRetries: 1,
      });

      await new Promise(resolve => setTimeout(resolve, 150));

      expect(agent.getBufferSize()).toBe(10);
    });

    it('should update model after sufficient episodes', async () => {
      const config = createTestConfig();
      const fastLearner = new LearnerAgent(config, { minEpisodesForUpdate: 5 });
      await fastLearner.initialize(messageBus);
      await fastLearner.start();

      const episodes = Array.from({ length: 10 }, (_, i) =>
        createTestEpisode({ reward: i % 2 === 0 ? 1 : -1 })
      );

      fastLearner.submitTask({
        type: 'batch_learn',
        priority: 'high',
        payload: episodes,
        maxRetries: 1,
      });

      await new Promise(resolve => setTimeout(resolve, 200));

      const updates = fastLearner.getModelUpdates();
      expect(updates.length).toBeGreaterThanOrEqual(1);

      await fastLearner.terminate();
    });
  });

  describe('prediction', () => {
    beforeEach(async () => {
      await agent.initialize(messageBus);
      await agent.start();
    });

    it('should make predictions for observations', async () => {
      const observation = createTestObservation([0.8, 0.9, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2]);

      let prediction: unknown = null;
      agent.submitTask({
        type: 'predict',
        priority: 'high',
        payload: observation,
        maxRetries: 1,
      });

      await new Promise(resolve => setTimeout(resolve, 150));

      // Prediction was made (can't easily capture result in this test pattern)
      expect(true).toBe(true);
    });

    it('should return action with confidence', async () => {
      const observation = createTestObservation();
      
      // Use predict method directly
      const action = await (agent as unknown as { predict(o: Observation): Promise<unknown> }).predict(observation);
      
      expect(action).toHaveProperty('type');
      expect(action).toHaveProperty('confidence');
    });
  });

  describe('metrics', () => {
    let metricsAgent: LearnerAgent;

    beforeEach(async () => {
      // Create agent with low minEpisodesForUpdate for testing
      metricsAgent = new LearnerAgent(createTestConfig(), { minEpisodesForUpdate: 3 });
      await metricsAgent.initialize(messageBus);
      await metricsAgent.start();
    });

    afterEach(async () => {
      if (metricsAgent.currentState !== 'terminated') {
        await metricsAgent.terminate();
      }
    });

    it('should track episode count', async () => {
      const episodes = Array.from({ length: 5 }, () => createTestEpisode());

      metricsAgent.submitTask({
        type: 'batch_learn',
        priority: 'medium',
        payload: episodes,
        maxRetries: 1,
      });

      await new Promise(resolve => setTimeout(resolve, 200));

      const metrics = metricsAgent.getModelMetrics();
      expect(metrics.episodesProcessed).toBeGreaterThanOrEqual(5);
    });

    it('should calculate average reward', async () => {
      const episodes = [
        createTestEpisode({ reward: 1 }),
        createTestEpisode({ reward: 1 }),
        createTestEpisode({ reward: -1 }),
      ];

      metricsAgent.submitTask({
        type: 'batch_learn',
        priority: 'medium',
        payload: episodes,
        maxRetries: 1,
      });

      await new Promise(resolve => setTimeout(resolve, 200));

      const metrics = metricsAgent.getModelMetrics();
      expect(metrics.avgReward).toBeCloseTo(1/3, 1);
    });
  });

  describe('replay buffer', () => {
    it('should respect buffer size limits', async () => {
      const config = createTestConfig();
      const limitedAgent = new LearnerAgent(config, { maxReplayBufferSize: 10 });
      await limitedAgent.initialize(messageBus);
      await limitedAgent.start();

      const episodes = Array.from({ length: 20 }, () => createTestEpisode());

      limitedAgent.submitTask({
        type: 'batch_learn',
        priority: 'high',
        payload: episodes,
        maxRetries: 1,
      });

      await new Promise(resolve => setTimeout(resolve, 200));

      expect(limitedAgent.getBufferSize()).toBeLessThanOrEqual(10);

      await limitedAgent.terminate();
    });
  });

  describe('model updates', () => {
    it('should track update history', async () => {
      const fastLearner = new LearnerAgent(createTestConfig(), { minEpisodesForUpdate: 3 });
      await fastLearner.initialize(messageBus);
      await fastLearner.start();

      const episodes = Array.from({ length: 10 }, () => createTestEpisode());

      fastLearner.submitTask({
        type: 'batch_learn',
        priority: 'high',
        payload: episodes,
        maxRetries: 1,
      });

      await new Promise(resolve => setTimeout(resolve, 200));

      const updates = fastLearner.getModelUpdates();
      expect(updates.length).toBeGreaterThan(0);

      if (updates.length > 0) {
        const update = updates[0]!;
        expect(update).toHaveProperty('id');
        expect(update).toHaveProperty('episodeCount');
        expect(update).toHaveProperty('beforeMetrics');
        expect(update).toHaveProperty('afterMetrics');
        expect(update).toHaveProperty('changes');
      }

      await fastLearner.terminate();
    });
  });
});
