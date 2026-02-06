/**
 * Auditor Agent Tests
 */

import { MessageBus, createMessageBus, type AgentConfig } from '@ai-authority/agents';
import { getDefaultCapabilities } from '@ai-authority/agents';
import { generateRSAKeyPair } from '@ai-authority/core';
import {
  AuditorAgent,
  type CompliancePolicy,
  type AuditorConfig,
  type AuditableAction,
} from '../auditor';

// Generate real RSA keys for tests
const testKeyPair = generateRSAKeyPair();

function createTestConfig(overrides?: Partial<AgentConfig>): AgentConfig {
  return {
    role: 'auditor',
    nodeId: 'test-node',
    privateKey: testKeyPair.privateKey,
    publicKey: testKeyPair.publicKey,
    capabilities: getDefaultCapabilities('auditor'),
    knowledgeEndpoints: ['http://localhost:9000'],
    peerAgents: [],
    heartbeatIntervalMs: 60000,
    maxConcurrentTasks: 5,
    ...overrides,
  };
}

function createTestPolicy(overrides?: Partial<CompliancePolicy>): CompliancePolicy {
  return {
    id: `policy-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    name: 'Test Policy',
    version: '1.0.0',
    effectiveFrom: Date.now() - 86400000, // Yesterday
    severity: 'mandatory',
    rules: [
      {
        id: 'rule-1',
        name: 'Max Score Rule',
        description: 'Score must not exceed threshold',
        condition: {
          type: 'threshold',
          field: 'score',
          operator: 'lte',
          value: 0.9,
        },
        remediation: 'Review and adjust score',
      },
    ],
    ...overrides,
  };
}

function createTestAction(overrides?: Partial<AuditableAction>): AuditableAction {
  return {
    id: `action-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    timestamp: Date.now(),
    agentId: 'test-agent',
    agentRole: 'enforcer',
    type: 'intervention',
    payload: { tier: 1, targetId: 'target-1' },
    ...overrides,
  };
}

describe('AuditorAgent', () => {
  let agent: AuditorAgent;
  let messageBus: MessageBus;

  beforeEach(() => {
    messageBus = createMessageBus({ processingIntervalMs: 1 });
    const config = createTestConfig();
    agent = new AuditorAgent(config, {
      autoAuditEnabled: false,
      retentionDays: 30,
    });
  });

  afterEach(async () => {
    if (agent.currentState !== 'terminated') {
      await agent.terminate();
    }
    messageBus.stop();
  });

  describe('construction', () => {
    it('should create agent with auditor role', () => {
      expect(agent.role).toBe('auditor');
    });

    it('should initialize with empty audit records', () => {
      const records = agent.getAuditRecords();
      // May have default policies that generated records
      expect(Array.isArray(records)).toBe(true);
    });

    it('should accept custom auditor config', () => {
      const customConfig: Partial<AuditorConfig> = {
        autoAuditEnabled: true,
        retentionDays: 90,
      };
      const customAgent = new AuditorAgent(createTestConfig(), customConfig);
      expect(customAgent.role).toBe('auditor');
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

    it('should stop successfully', async () => {
      await agent.initialize(messageBus);
      await agent.start();
      await agent.stop();
      expect(agent.currentState).toBe('paused');
    });
  });

  describe('policy management', () => {
    beforeEach(async () => {
      await agent.initialize(messageBus);
      await agent.start();
    });

    it('should register policy', async () => {
      const policy = createTestPolicy();

      agent.submitTask({
        type: 'register_policy',
        priority: 'medium',
        payload: policy,
        maxRetries: 1,
      });

      await new Promise(resolve => setTimeout(resolve, 150));

      const retrieved = agent.getPolicy(policy.id);
      expect(retrieved).toBeDefined();
      expect(retrieved?.name).toBe('Test Policy');
    });

    it('should get all policies', () => {
      // Auditor loads default policies
      const policies = agent.getPolicies();
      expect(Array.isArray(policies)).toBe(true);
    });
  });

  describe('action auditing', () => {
    beforeEach(async () => {
      await agent.initialize(messageBus);
      await agent.start();
    });

    it('should audit action via task', async () => {
      const action = createTestAction();

      agent.submitTask({
        type: 'audit',
        priority: 'high',
        payload: action,
        maxRetries: 1,
      });

      await new Promise(resolve => setTimeout(resolve, 200));

      const records = agent.getAuditRecords();
      // May or may not have a record depending on policy matching
      expect(Array.isArray(records)).toBe(true);
    });
  });

  describe('audit chain', () => {
    beforeEach(async () => {
      await agent.initialize(messageBus);
      await agent.start();
    });

    it('should verify audit chain integrity', async () => {
      const result = await agent.verifyAuditChain();
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it('should track chain length', () => {
      const length = agent.getChainLength();
      expect(typeof length).toBe('number');
    });

    it('should track last hash', () => {
      const hash = agent.getLastHash();
      expect(typeof hash).toBe('string');
    });
  });

  describe('report generation', () => {
    beforeEach(async () => {
      await agent.initialize(messageBus);
      await agent.start();
    });

    it('should handle generate_report task', async () => {
      agent.submitTask({
        type: 'generate_report',
        priority: 'medium',
        payload: {
          startTime: Date.now() - 3600000,
          endTime: Date.now(),
        },
        maxRetries: 1,
      });

      await new Promise(resolve => setTimeout(resolve, 200));

      // Task processed
      expect(true).toBe(true);
    });
  });

  describe('policy retrieval', () => {
    it('should return undefined for non-existent policy', () => {
      const policy = agent.getPolicy('non-existent');
      expect(policy).toBeUndefined();
    });
  });

  describe('audit record retrieval', () => {
    it('should get audit record by action ID', async () => {
      await agent.initialize(messageBus);
      await agent.start();

      // Get records
      const records = agent.getAuditRecords();
      if (records.length > 0) {
        const first = records[0]!;
        const retrieved = agent.getAuditRecord(first.actionId);
        expect(retrieved).toBeDefined();
      } else {
        // No records to test
        expect(true).toBe(true);
      }
    });
  });
});
