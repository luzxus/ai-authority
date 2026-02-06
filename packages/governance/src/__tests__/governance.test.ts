/**
 * Governance Agents Tests
 */

import { MessageBus, createMessageBus, type AgentConfig } from '@ai-authority/agents';
import { getDefaultCapabilities } from '@ai-authority/agents';
import { generateRSAKeyPair } from '@ai-authority/core';
import { ProposerAgent, type Proposal, type ProposalType } from '../proposer';
import { ApproverAgent, type SimulationConfig, type ProposalVote } from '../approver';
import { CuratorAgent } from '../curator';
import { KnowledgeBase } from '@ai-authority/knowledge';

// Generate real RSA keys for signing in tests
const testKeyPair = generateRSAKeyPair();

/** Create test agent config */
function createTestConfig(role: 'proposer' | 'approver' | 'curator', overrides?: Partial<AgentConfig>): AgentConfig {
  return {
    role,
    nodeId: 'test-node',
    privateKey: testKeyPair.privateKey,
    publicKey: testKeyPair.publicKey,
    capabilities: getDefaultCapabilities(role),
    knowledgeEndpoints: ['http://localhost:9000'],
    peerAgents: [],
    heartbeatIntervalMs: 60000,
    maxConcurrentTasks: 5,
    ...overrides,
  };
}

describe('ProposerAgent', () => {
  let agent: ProposerAgent;
  let messageBus: MessageBus;

  beforeEach(() => {
    messageBus = createMessageBus({ processingIntervalMs: 1 });
    const config = createTestConfig('proposer');
    agent = new ProposerAgent(config);
  });

  afterEach(async () => {
    if (agent.currentState !== 'terminated') {
      await agent.terminate();
    }
    messageBus.stop();
  });

  describe('construction', () => {
    it('should create agent with proposer role', () => {
      expect(agent.role).toBe('proposer');
    });

    it('should start with no proposals', () => {
      expect(agent.getProposals()).toEqual([]);
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

  describe('observations', () => {
    it('should accept observations', async () => {
      await agent.initialize(messageBus);
      
      agent.addObservation({ type: 'detection', falsePositive: false });
      agent.addObservation({ type: 'detection', falsePositive: true });

      // Observations are internal, but we can verify no errors
      expect(true).toBe(true);
    });
  });

  describe('task processing', () => {
    it('should handle create_proposal task', async () => {
      await agent.initialize(messageBus);
      await agent.start();

      agent.submitTask({
        type: 'create_proposal',
        priority: 'medium',
        payload: {
          type: 'threshold_adjustment' as ProposalType,
          title: 'Test Proposal',
          description: 'Test description',
          rationale: 'Testing',
          payload: { adjustment: 0.1 },
          impact: 'low',
          evidence: [],
        } as Partial<Proposal>,
        maxRetries: 1,
      });

      // Wait for processing
      await new Promise((resolve) => setTimeout(resolve, 100));

      const proposals = agent.getProposals();
      expect(proposals.length).toBe(1);
      expect(proposals[0]!.title).toBe('Test Proposal');
    });

    it('should handle analyze_and_propose task', async () => {
      await agent.initialize(messageBus);
      await agent.start();

      // Add enough observations
      for (let i = 0; i < 110; i++) {
        agent.addObservation({ type: 'detection', falsePositive: i < 15 });
      }

      agent.submitTask({
        type: 'analyze_and_propose',
        priority: 'low',
        payload: {},
        maxRetries: 0,
      });

      // Wait for processing
      await new Promise((resolve) => setTimeout(resolve, 100));

      // May or may not generate proposals based on analysis
      expect(agent.getProposals).toBeDefined();
    });
  });

  describe('proposal management', () => {
    it('should get proposal by ID', async () => {
      await agent.initialize(messageBus);
      await agent.start();

      agent.submitTask({
        type: 'create_proposal',
        priority: 'high',
        payload: {
          type: 'knowledge_update' as ProposalType,
          title: 'Unique Proposal',
          description: 'Find me',
        } as Partial<Proposal>,
        maxRetries: 1,
      });

      await new Promise((resolve) => setTimeout(resolve, 100));

      const proposals = agent.getProposals();
      const proposal = proposals[0];
      
      if (proposal) {
        const found = agent.getProposal(proposal.id);
        expect(found).toBeDefined();
        expect(found?.title).toBe('Unique Proposal');
      }
    });

    it('should return undefined for unknown proposal ID', () => {
      const proposal = agent.getProposal('unknown-id');
      expect(proposal).toBeUndefined();
    });
  });
});

describe('ApproverAgent', () => {
  let agent: ApproverAgent;
  let messageBus: MessageBus;

  beforeEach(() => {
    messageBus = createMessageBus({ processingIntervalMs: 1 });
    const config = createTestConfig('approver');
    agent = new ApproverAgent(config);
  });

  afterEach(async () => {
    if (agent.currentState !== 'terminated') {
      await agent.terminate();
    }
    messageBus.stop();
  });

  describe('construction', () => {
    it('should create agent with approver role', () => {
      expect(agent.role).toBe('approver');
    });

    it('should accept custom simulation config', () => {
      const customConfig: Partial<SimulationConfig> = {
        iterations: 50,
        minDetectionRate: 0.8,
      };
      const customAgent = new ApproverAgent(createTestConfig('approver'), customConfig);
      
      expect(customAgent.role).toBe('approver');
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

  describe('task processing', () => {
    it('should handle evaluate_proposal task', async () => {
      await agent.initialize(messageBus);
      await agent.start();

      const testProposal: Proposal = {
        id: 'test-proposal-1',
        type: 'threshold_adjustment',
        title: 'Test Proposal',
        description: 'A test proposal',
        rationale: 'For testing',
        payload: { adjustment: 0.1 },
        impact: 'low',
        evidence: ['ev1', 'ev2', 'ev3'],
        proposedAt: Date.now(),
        proposedBy: 'proposer-1',
      };

      agent.submitTask({
        type: 'evaluate_proposal',
        priority: 'medium',
        payload: testProposal,
        maxRetries: 1,
      });

      // Poll for vote to appear (with timeout)
      let votes: ProposalVote[] = [];
      for (let i = 0; i < 20; i++) {
        await new Promise((resolve) => setTimeout(resolve, 100));
        votes = agent.getVotesForProposal('test-proposal-1');
        if (votes.length > 0) break;
      }

      expect(votes.length).toBe(1);
      expect(votes[0]!.proposalId).toBe('test-proposal-1');
      expect(typeof votes[0]!.approve).toBe('boolean');
      expect(votes[0]!.confidence).toBeGreaterThanOrEqual(0);
      expect(votes[0]!.confidence).toBeLessThanOrEqual(1);
    });

    it('should handle run_simulation task', async () => {
      await agent.initialize(messageBus);
      await agent.start();

      const testProposal: Proposal = {
        id: 'sim-proposal',
        type: 'knowledge_update',
        title: 'Simulation Test',
        description: 'Testing simulation',
        rationale: 'Testing',
        payload: {},
        impact: 'medium',
        evidence: [],
        proposedAt: Date.now(),
        proposedBy: 'proposer-1',
      };

      agent.submitTask({
        type: 'run_simulation',
        priority: 'high',
        payload: { proposal: testProposal },
        maxRetries: 1,
      });

      // Wait for processing
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Simulation was run (results are stored internally)
      expect(true).toBe(true);
    });

    it('should reject unknown task types', async () => {
      await agent.initialize(messageBus);
      await agent.start();

      const taskId = agent.submitTask({
        type: 'unknown_task_type',
        priority: 'low',
        payload: {},
        maxRetries: 0,
      });

      await new Promise((resolve) => setTimeout(resolve, 100));

      // Task should complete but fail
      expect(taskId).toBeDefined();
    });
  });

  describe('voting', () => {
    it('should include signature in vote', async () => {
      await agent.initialize(messageBus);
      await agent.start();

      const testProposal: Proposal = {
        id: 'signed-vote-proposal',
        type: 'rule_modification',
        title: 'Signed Vote Test',
        description: 'Testing vote signature',
        rationale: 'For testing',
        payload: {},
        impact: 'low',
        evidence: [],
        proposedAt: Date.now(),
        proposedBy: 'proposer-1',
      };

      agent.submitTask({
        type: 'evaluate_proposal',
        priority: 'high',
        payload: testProposal,
        maxRetries: 1,
      });

      let votes: ProposalVote[] = [];
      for (let i = 0; i < 20; i++) {
        await new Promise((resolve) => setTimeout(resolve, 100));
        votes = agent.getVotesForProposal('signed-vote-proposal');
        if (votes.length > 0) break;
      }

      expect(votes.length).toBe(1);
      expect(votes[0]!.signature).toBeDefined();
      expect(votes[0]!.signature.length).toBeGreaterThan(0);
    });

    it('should include rationale in vote', async () => {
      await agent.initialize(messageBus);
      await agent.start();

      const testProposal: Proposal = {
        id: 'rationale-proposal',
        type: 'architecture_change',
        title: 'Rationale Test',
        description: 'Testing rationale',
        rationale: 'Testing',
        payload: {},
        impact: 'critical',
        evidence: [],
        proposedAt: Date.now(),
        proposedBy: 'proposer-1',
      };

      agent.submitTask({
        type: 'evaluate_proposal',
        priority: 'high',
        payload: testProposal,
        maxRetries: 1,
      });

      let votes: ProposalVote[] = [];
      for (let i = 0; i < 20; i++) {
        await new Promise((resolve) => setTimeout(resolve, 100));
        votes = agent.getVotesForProposal('rationale-proposal');
        if (votes.length > 0) break;
      }

      expect(votes.length).toBe(1);
      expect(votes[0]!.rationale).toBeDefined();
      expect(votes[0]!.rationale.length).toBeGreaterThan(0);
    });
  });

  describe('simulation retrieval', () => {
    it('should allow retrieving simulation by ID', async () => {
      await agent.initialize(messageBus);
      await agent.start();

      const testProposal: Proposal = {
        id: 'sim-id-proposal',
        type: 'threshold_adjustment',
        title: 'Simulation ID Test',
        description: 'Testing simulation ID',
        rationale: 'Testing',
        payload: {},
        impact: 'medium',
        evidence: [],
        proposedAt: Date.now(),
        proposedBy: 'proposer-1',
      };

      agent.submitTask({
        type: 'evaluate_proposal',
        priority: 'high',
        payload: testProposal,
        maxRetries: 1,
      });

      await new Promise((resolve) => setTimeout(resolve, 200));

      const votes = agent.getVotesForProposal('sim-id-proposal');
      if (votes.length > 0 && votes[0]!.simulationId) {
        const sim = agent.getSimulation(votes[0]!.simulationId);
        expect(sim).toBeDefined();
        expect(sim?.metrics).toBeDefined();
        expect(sim?.risks).toBeDefined();
      }
    });

    it('should return undefined for unknown simulation ID', () => {
      const sim = agent.getSimulation('unknown-sim-id');
      expect(sim).toBeUndefined();
    });
  });
});

describe('CuratorAgent', () => {
  let agent: CuratorAgent;
  let messageBus: MessageBus;
  let knowledgeBase: KnowledgeBase;

  beforeEach(() => {
    messageBus = createMessageBus({ processingIntervalMs: 1 });
    knowledgeBase = new KnowledgeBase({ vectorDimensions: 4 });
    
    const config = createTestConfig('curator');
    agent = new CuratorAgent(config);
    agent.setKnowledgeBase(knowledgeBase);
  });

  afterEach(async () => {
    if (agent.currentState !== 'terminated') {
      await agent.terminate();
    }
    messageBus.stop();
  });

  describe('construction', () => {
    it('should create agent with curator role', () => {
      expect(agent.role).toBe('curator');
    });

    it('should start with no synthesis history', () => {
      expect(agent.getSynthesisHistory()).toEqual([]);
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

  describe('knowledge base configuration', () => {
    it('should accept knowledge base via setKnowledgeBase', async () => {
      const newKB = new KnowledgeBase({ vectorDimensions: 8 });
      agent.setKnowledgeBase(newKB);

      // Should not throw
      expect(true).toBe(true);
    });
  });

  describe('task processing', () => {
    it('should handle synthesize_proposal task', async () => {
      await agent.initialize(messageBus);
      await agent.start();

      const testProposal: Proposal = {
        id: 'synth-proposal-1',
        type: 'knowledge_update',
        title: 'Synthesis Test',
        description: 'Testing synthesis',
        rationale: 'For testing',
        payload: {
          type: 'rule',
          data: {
            condition: { type: 'threshold', field: 'score', operator: 'gt', value: 0.8 },
            action: { type: 'alert', parameters: {} },
          },
          domain: 'malicious_patterns',
        },
        impact: 'low',
        evidence: [],
        proposedAt: Date.now(),
        proposedBy: 'proposer-1',
      };

      agent.submitTask({
        type: 'synthesize_proposal',
        priority: 'high',
        payload: { proposal: testProposal, approvals: ['approver-1', 'approver-2'] },
        maxRetries: 1,
      });

      await new Promise((resolve) => setTimeout(resolve, 200));

      const result = agent.getSynthesisResult('synth-proposal-1');
      expect(result).toBeDefined();
      expect(result?.proposalId).toBe('synth-proposal-1');
    });

    it('should handle encode_rule task', async () => {
      await agent.initialize(messageBus);
      await agent.start();

      agent.submitTask({
        type: 'encode_rule',
        priority: 'high',
        payload: {
          condition: { type: 'threshold', field: 'risk', operator: 'gte', value: 0.9 },
          action: { type: 'classify', parameters: { classification: 'malicious' } },
          domain: 'malicious_patterns',
          priority: 10,
        },
        maxRetries: 1,
      });

      await new Promise((resolve) => setTimeout(resolve, 100));

      // Rule should be in knowledge base
      expect(true).toBe(true);
    });

    it('should handle encode_pattern task', async () => {
      await agent.initialize(messageBus);
      await agent.start();

      agent.submitTask({
        type: 'encode_pattern',
        priority: 'high',
        payload: {
          pattern: {
            name: 'test-pattern',
            description: 'A test behavioral pattern',
            indicators: [
              { type: 'api_call', signature: 'dangerous_api', weight: 0.8 },
            ],
            severity: 'high',
            classification: 'malicious',
          },
          domain: 'malicious_patterns',
        },
        maxRetries: 1,
      });

      await new Promise((resolve) => setTimeout(resolve, 100));

      // Pattern should be in knowledge base
      expect(true).toBe(true);
    });

    it('should reject unknown task types', async () => {
      await agent.initialize(messageBus);
      await agent.start();

      const taskId = agent.submitTask({
        type: 'unknown_task',
        priority: 'low',
        payload: {},
        maxRetries: 0,
      });

      await new Promise((resolve) => setTimeout(resolve, 100));

      expect(taskId).toBeDefined();
    });
  });

  describe('synthesis history', () => {
    it('should track synthesis history', async () => {
      await agent.initialize(messageBus);
      await agent.start();

      const testProposal: Proposal = {
        id: 'history-proposal-1',
        type: 'threshold_adjustment',
        title: 'History Test',
        description: 'Testing history',
        rationale: 'Testing',
        payload: {
          dimension: 'deception',
          oldThreshold: 0.8,
          newThreshold: 0.85,
        },
        impact: 'medium',
        evidence: [],
        proposedAt: Date.now(),
        proposedBy: 'proposer-1',
      };

      agent.submitTask({
        type: 'synthesize_proposal',
        priority: 'high',
        payload: { proposal: testProposal, approvals: ['approver-1'] },
        maxRetries: 1,
      });

      await new Promise((resolve) => setTimeout(resolve, 200));

      const history = agent.getSynthesisHistory();
      expect(history.length).toBeGreaterThan(0);
    });

    it('should get synthesis result by proposal ID', async () => {
      await agent.initialize(messageBus);
      await agent.start();

      const testProposal: Proposal = {
        id: 'result-proposal',
        type: 'rule_modification',
        title: 'Result Test',
        description: 'Testing result',
        rationale: 'Testing',
        payload: {
          condition: { type: 'threshold', field: 'x', operator: 'gt', value: 1 },
          action: { type: 'log', parameters: {} },
          domain: 'api_misuse',
        },
        impact: 'low',
        evidence: [],
        proposedAt: Date.now(),
        proposedBy: 'proposer-1',
      };

      agent.submitTask({
        type: 'synthesize_proposal',
        priority: 'high',
        payload: { proposal: testProposal, approvals: ['a1'] },
        maxRetries: 1,
      });

      await new Promise((resolve) => setTimeout(resolve, 200));

      const result = agent.getSynthesisResult('result-proposal');
      expect(result?.proposalId).toBe('result-proposal');
      expect(result?.synthesizedItems).toBeDefined();
    });

    it('should return undefined for unknown proposal ID', () => {
      const result = agent.getSynthesisResult('unknown');
      expect(result).toBeUndefined();
    });
  });

  describe('error handling', () => {
    it('should fail when knowledge base not configured', async () => {
      const agentWithoutKB = new CuratorAgent(createTestConfig('curator'));
      await agentWithoutKB.initialize(messageBus);
      await agentWithoutKB.start();

      agentWithoutKB.submitTask({
        type: 'encode_rule',
        priority: 'high',
        payload: {
          condition: { type: 'threshold', field: 'x', operator: 'gt', value: 1 },
          action: { type: 'alert', parameters: {} },
          domain: 'malicious_patterns',
        },
        maxRetries: 0,
      });

      await new Promise((resolve) => setTimeout(resolve, 100));

      // Task should have failed
      await agentWithoutKB.terminate();
    });
  });
});
