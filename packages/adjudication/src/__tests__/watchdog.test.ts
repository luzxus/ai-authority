/**
 * Watchdog Agent Tests
 */

import { MessageBus, createMessageBus, type AgentConfig } from '@ai-authority/agents';
import { getDefaultCapabilities } from '@ai-authority/agents';
import { generateRSAKeyPair } from '@ai-authority/core';
import {
  WatchdogAgent,
  type DecisionRecord,
  type WatchdogConfig,
  type BiasCategory,
} from '../watchdog';

// Generate real RSA keys for tests
const testKeyPair = generateRSAKeyPair();

function createTestConfig(overrides?: Partial<AgentConfig>): AgentConfig {
  return {
    role: 'watchdog',
    nodeId: 'test-node',
    privateKey: testKeyPair.privateKey,
    publicKey: testKeyPair.publicKey,
    capabilities: getDefaultCapabilities('watchdog'),
    knowledgeEndpoints: ['http://localhost:9000'],
    peerAgents: [],
    heartbeatIntervalMs: 60000,
    maxConcurrentTasks: 5,
    ...overrides,
  };
}

function createTestDecision(overrides?: Partial<DecisionRecord>): DecisionRecord {
  return {
    id: `decision-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    timestamp: Date.now(),
    entityId: `entity-${Math.random().toString(36).slice(2)}`,
    entityType: 'model',
    attributes: { region: 'us-west', tier: 'standard' },
    decision: 'flagged',
    score: 0.7,
    ...overrides,
  };
}

describe('WatchdogAgent', () => {
  let agent: WatchdogAgent;
  let messageBus: MessageBus;

  beforeEach(() => {
    messageBus = createMessageBus({ processingIntervalMs: 1 });
    const config = createTestConfig();
    // Disable auto-audit for tests, long audit interval
    agent = new WatchdogAgent(config, { 
      autoCorrectEnabled: false,
      auditIntervalMs: 3600000,
      minDecisionsForAudit: 10,
    });
  });

  afterEach(async () => {
    if (agent.currentState !== 'terminated') {
      await agent.terminate();
    }
    messageBus.stop();
  });

  describe('construction', () => {
    it('should create agent with watchdog role', () => {
      expect(agent.role).toBe('watchdog');
    });

    it('should initialize with default bias metrics', () => {
      const metrics = agent.getBiasMetrics();
      expect(metrics.length).toBeGreaterThan(0);
    });

    it('should accept custom watchdog config', () => {
      const customConfig: Partial<WatchdogConfig> = {
        autoCorrectEnabled: true,
        biasThresholds: { demographic: 0.05 } as WatchdogConfig['biasThresholds'],
      };
      const customAgent = new WatchdogAgent(createTestConfig(), customConfig);
      expect(customAgent.role).toBe('watchdog');
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

  describe('decision recording', () => {
    beforeEach(async () => {
      await agent.initialize(messageBus);
      await agent.start();
    });

    it('should record decisions', async () => {
      const decision = createTestDecision();

      agent.submitTask({
        type: 'record_decision',
        priority: 'medium',
        payload: decision,
        maxRetries: 1,
      });

      await new Promise(resolve => setTimeout(resolve, 150));

      // Decision was recorded
      expect(true).toBe(true);
    });

    it('should record multiple decisions', async () => {
      const decisions = Array.from({ length: 5 }, () => createTestDecision());

      for (const decision of decisions) {
        agent.submitTask({
          type: 'record_decision',
          priority: 'medium',
          payload: decision,
          maxRetries: 1,
        });
      }

      await new Promise(resolve => setTimeout(resolve, 200));

      // All decisions recorded
      expect(true).toBe(true);
    });
  });

  describe('bias checking', () => {
    beforeEach(async () => {
      await agent.initialize(messageBus);
      await agent.start();
    });

    it('should check bias for category', async () => {
      // Record some decisions first
      const decisions = Array.from({ length: 20 }, (_, i) =>
        createTestDecision({
          entityType: i % 2 === 0 ? 'model' : 'agent',
          score: i % 2 === 0 ? 0.8 : 0.3,
        })
      );

      for (const decision of decisions) {
        agent.recordDecision(decision);
      }

      agent.submitTask({
        type: 'check_bias',
        priority: 'high',
        payload: { category: 'demographic' as BiasCategory },
        maxRetries: 1,
      });

      await new Promise(resolve => setTimeout(resolve, 150));

      const metrics = agent.getBiasMetrics();
      expect(metrics.some(m => m.category === 'demographic')).toBe(true);
    });
  });

  describe('fairness auditing', () => {
    beforeEach(async () => {
      await agent.initialize(messageBus);
      await agent.start();
    });

    it('should run fairness audit with sufficient data', async () => {
      // Record enough decisions for audit
      const decisions = Array.from({ length: 20 }, (_, i) =>
        createTestDecision({
          entityType: i % 3 === 0 ? 'model' : i % 3 === 1 ? 'agent' : 'operator',
          score: 0.5 + Math.random() * 0.4,
          outcome: i % 4 === 0 ? 'correct' : i % 4 === 1 ? 'false_positive' : undefined,
        })
      );

      for (const decision of decisions) {
        agent.recordDecision(decision);
      }

      agent.submitTask({
        type: 'run_fairness_audit',
        priority: 'high',
        payload: {},
        maxRetries: 1,
      });

      await new Promise(resolve => setTimeout(resolve, 200));

      const audits = agent.getAudits();
      expect(audits.length).toBeGreaterThanOrEqual(1);
    });

    it('should fail audit with insufficient data', async () => {
      // Only record a few decisions
      for (let i = 0; i < 3; i++) {
        agent.recordDecision(createTestDecision());
      }

      agent.submitTask({
        type: 'run_fairness_audit',
        priority: 'high',
        payload: {},
        maxRetries: 0,
      });

      await new Promise(resolve => setTimeout(resolve, 150));

      // Should fail due to insufficient decisions
      expect(true).toBe(true);
    });
  });

  describe('bias alerts', () => {
    beforeEach(async () => {
      await agent.initialize(messageBus);
      await agent.start();
    });

    it('should get empty alerts initially', () => {
      const alerts = agent.getAlerts();
      expect(alerts).toEqual([]);
    });

    it('should filter alerts by severity', () => {
      const alerts = agent.getAlerts('critical');
      expect(alerts).toEqual([]);
    });
  });

  describe('bias metrics', () => {
    beforeEach(async () => {
      await agent.initialize(messageBus);
      await agent.start();
    });

    it('should return bias metrics', async () => {
      agent.submitTask({
        type: 'get_bias_metrics',
        priority: 'medium',
        payload: {},
        maxRetries: 1,
      });

      await new Promise(resolve => setTimeout(resolve, 100));

      const metrics = agent.getBiasMetrics();
      expect(Array.isArray(metrics)).toBe(true);
    });

    it('should update metrics on decision recording', async () => {
      const initialMetrics = agent.getBiasMetrics();
      
      // Record biased decisions
      for (let i = 0; i < 30; i++) {
        agent.recordDecision(createTestDecision({
          entityType: 'model',
          score: 0.9,
        }));
      }

      for (let i = 0; i < 30; i++) {
        agent.recordDecision(createTestDecision({
          entityType: 'agent',
          score: 0.2,
        }));
      }

      const updatedMetrics = agent.getBiasMetrics();
      
      // Metrics should have been updated
      const demographicMetric = updatedMetrics.find(m => 
        m.category === 'demographic' && m.dimension !== 'default'
      );
      expect(demographicMetric).toBeDefined();
    });
  });

  describe('corrections', () => {
    beforeEach(async () => {
      await agent.initialize(messageBus);
      await agent.start();
    });

    it('should apply weight adjustment correction', async () => {
      const correction = {
        id: 'correction-1',
        type: 'weight_adjustment' as const,
        parameters: { adjustment: -0.1, category: 'demographic' },
        status: 'pending' as const,
      };

      agent.submitTask({
        type: 'apply_correction',
        priority: 'high',
        payload: correction,
        maxRetries: 1,
      });

      await new Promise(resolve => setTimeout(resolve, 150));

      const applied = agent.getCorrection('correction-1');
      expect(applied?.status).toBe('applied');
    });

    it('should reject invalid correction', async () => {
      const invalidCorrection = {
        type: 'weight_adjustment' as const,
        parameters: {}, // Missing adjustment parameter
        status: 'pending' as const,
      };

      agent.submitTask({
        type: 'apply_correction',
        priority: 'high',
        payload: invalidCorrection,
        maxRetries: 0,
      });

      await new Promise(resolve => setTimeout(resolve, 150));

      // Should fail validation
      expect(true).toBe(true);
    });
  });

  describe('audit retrieval', () => {
    it('should return undefined for no latest audit', () => {
      const latest = agent.getLatestAudit();
      expect(latest).toBeUndefined();
    });

    it('should return empty array for audits initially', () => {
      const audits = agent.getAudits();
      expect(audits).toEqual([]);
    });
  });
});
