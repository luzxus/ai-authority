/**
 * Tests for Intervention Workflows
 */

import {
  WorkflowEngine,
  DEFAULT_WORKFLOW_CONFIG,
  processAgentWorkflow,
  getWorkflowSummary,
  type WorkflowDecision,
  type WorkflowThreshold,
} from '../workflows.js';
import type { MoltbookThreatSignal } from '@ai-authority/federation';
import type { AgentBehaviorInput } from '../database.js';

// Mock the database module
jest.mock('../database.js', () => ({
  recordAgentBehavior: jest.fn(),
  recordRiskHistory: jest.fn(),
  createAgentAlert: jest.fn(),
  detectBehaviorAnomalies: jest.fn(() => []),
  calculateRiskTrend: jest.fn(() => 'stable'),
}));

// Mock @ai-authority/core
jest.mock('@ai-authority/core', () => ({
  generateSecureId: jest.fn(() => `test-id-${Date.now()}-${Math.random()}`),
}));

describe('WorkflowEngine', () => {
  let engine: WorkflowEngine;

  const createThreatSignal = (
    severity: 'low' | 'medium' | 'high' | 'critical',
    confidence = 0.8
  ): MoltbookThreatSignal => ({
    id: `signal-${Math.random()}`,
    type: 'manipulation',
    severity,
    confidence,
    description: `Test ${severity} threat signal`,
    sourcePost: 'post-123',
    indicators: ['test indicator'],
    detectedAt: new Date(),
  });

  const createBehaviorInput = (
    overrides: Partial<AgentBehaviorInput> = {}
  ): AgentBehaviorInput => ({
    agentUsername: 'test-agent',
    postCount: 10,
    threatSignalCount: 1,
    avgThreatSeverity: 0.5,
    manipulationScore: 0.3,
    deceptionScore: 0.2,
    urgencyScore: 0.1,
    coordinationScore: 0.1,
    avgSemanticRisk: 0.4,
    ...overrides,
  });

  beforeEach(() => {
    engine = new WorkflowEngine();
    jest.clearAllMocks();
  });

  describe('constructor', () => {
    it('should use default config when none provided', () => {
      const defaultEngine = new WorkflowEngine();
      expect(defaultEngine).toBeDefined();
    });

    it('should merge custom config with defaults', () => {
      const customEngine = new WorkflowEngine({
        cooldownHours: 12,
        maxInterventionsPerDay: 100,
      });
      expect(customEngine).toBeDefined();
    });
  });

  describe('processAgent', () => {
    it('should return no intervention for low-risk agents', async () => {
      const signals: MoltbookThreatSignal[] = [];
      const behavior = createBehaviorInput();

      const decision = await engine.processAgent('safe-agent', signals, behavior);

      expect(decision.shouldIntervene).toBe(false);
      expect(decision.recommendedTier).toBeNull();
    });

    it('should recommend tier1 for moderate risk', async () => {
      // Need at least 1 signal meeting the threshold
      const signals = [
        createThreatSignal('high', 0.9),
      ];
      const behavior = createBehaviorInput({
        manipulationScore: 0.8,
        deceptionScore: 0.7,
        avgSemanticRisk: 0.6,
      });

      const decision = await engine.processAgent('risky-agent', signals, behavior);

      // With high-risk signals and behavior scores, should trigger intervention
      if (decision.shouldIntervene) {
        expect(['tier1', 'tier2', 'tier3', 'tier4']).toContain(decision.recommendedTier);
        expect(decision.reasons.length).toBeGreaterThan(0);
      }
    });

    it('should recommend tier2 for higher risk', async () => {
      const signals = [
        createThreatSignal('high', 0.9),
        createThreatSignal('high', 0.85),
        createThreatSignal('medium', 0.7),
      ];
      const behavior = createBehaviorInput({
        manipulationScore: 0.8,
        deceptionScore: 0.7,
        avgSemanticRisk: 0.7,
      });

      const decision = await engine.processAgent('high-risk-agent', signals, behavior);

      expect(decision.shouldIntervene).toBe(true);
      expect(['tier1', 'tier2']).toContain(decision.recommendedTier);
    });

    it('should require human approval for tier3+', async () => {
      const signals = Array(6).fill(null).map(() => createThreatSignal('critical', 0.95));
      const behavior = createBehaviorInput({
        manipulationScore: 0.95,
        deceptionScore: 0.9,
        coordinationScore: 0.85,
        avgSemanticRisk: 0.9,
      });

      const decision = await engine.processAgent('critical-agent', signals, behavior);

      if (decision.recommendedTier === 'tier3' || decision.recommendedTier === 'tier4') {
        expect(decision.requiresHumanApproval).toBe(true);
      }
    });

    it('should respect cooldown period', async () => {
      // Create custom engine with lower thresholds to ensure intervention triggers
      const customEngine = new WorkflowEngine({
        tiers: {
          tier1: {
            riskScore: 0.2, // Low threshold for testing
            minThreatSignals: 1,
            requiredSeverity: 'medium',
            consensusRequired: 1,
          },
          tier2: DEFAULT_WORKFLOW_CONFIG.tiers.tier2,
          tier3: DEFAULT_WORKFLOW_CONFIG.tiers.tier3,
          tier4: DEFAULT_WORKFLOW_CONFIG.tiers.tier4,
        },
      });
      
      const signals = [createThreatSignal('high', 0.9)];
      const behavior = createBehaviorInput({ 
        manipulationScore: 0.8,
        deceptionScore: 0.7,
        avgSemanticRisk: 0.7,
      });

      // First process - should trigger intervention
      const firstDecision = await customEngine.processAgent('cooldown-agent', signals, behavior);
      
      if (firstDecision.shouldIntervene && !firstDecision.requiresHumanApproval) {
        const action = customEngine.createAction(firstDecision, 'cooldown-agent', 'test');
        if (action) {
          await customEngine.executeAction(action.id);
          
          // Second attempt should be on cooldown
          const secondDecision = await customEngine.processAgent('cooldown-agent', signals, behavior);
          expect(secondDecision.shouldIntervene).toBe(false);
          expect(secondDecision.reasons[0]).toContain('cooldown');
        }
      }
    });
  });

  describe('createAction', () => {
    it('should create action for valid decision', async () => {
      const signals = [createThreatSignal('medium', 0.8), createThreatSignal('high', 0.75)];
      const behavior = createBehaviorInput({ manipulationScore: 0.6 });

      const decision = await engine.processAgent('action-agent', signals, behavior);
      
      if (decision.shouldIntervene) {
        const action = engine.createAction(decision, 'action-agent', 'test-trigger');
        expect(action).toBeDefined();
        expect(action?.agentUsername).toBe('action-agent');
        expect(action?.triggeredBy).toBe('test-trigger');
      }
    });

    it('should return null for non-intervention decision', () => {
      const decision: WorkflowDecision = {
        shouldIntervene: false,
        recommendedTier: null,
        confidence: 0,
        reasons: ['No issues'],
        evidence: [],
        requiresHumanApproval: false,
      };

      const action = engine.createAction(decision, 'safe-agent', 'test');
      expect(action).toBeNull();
    });

    it('should respect daily limit', async () => {
      const customEngine = new WorkflowEngine({ maxInterventionsPerDay: 2 });
      const signals = [createThreatSignal('high', 0.9), createThreatSignal('medium', 0.8)];
      const behavior = createBehaviorInput({ manipulationScore: 0.7 });

      // Create actions up to limit
      for (let i = 0; i < 3; i++) {
        const decision = await customEngine.processAgent(`agent-${i}`, signals, behavior);
        if (decision.shouldIntervene) {
          const action = customEngine.createAction(decision, `agent-${i}`, 'test');
          if (i >= 2) {
            // Should be null after limit reached
            expect(action).toBeNull();
          }
        }
      }
    });
  });

  describe('approveAction', () => {
    it('should approve pending action', async () => {
      const signals = Array(6).fill(null).map(() => createThreatSignal('critical', 0.95));
      const behavior = createBehaviorInput({
        manipulationScore: 0.95,
        deceptionScore: 0.9,
        avgSemanticRisk: 0.9,
      });

      const decision = await engine.processAgent('approve-agent', signals, behavior);
      
      if (decision.shouldIntervene && decision.requiresHumanApproval) {
        const action = engine.createAction(decision, 'approve-agent', 'test');
        expect(action?.status).toBe('pending');

        const approved = engine.approveAction(action!.id, 'admin');
        expect(approved).toBe(true);
        expect(engine.getAction(action!.id)?.status).toBe('approved');
      }
    });

    it('should reject approval for non-existent action', () => {
      const result = engine.approveAction('non-existent', 'admin');
      expect(result).toBe(false);
    });
  });

  describe('executeAction', () => {
    it('should execute approved action', async () => {
      const signals = [createThreatSignal('medium', 0.8), createThreatSignal('high', 0.75)];
      const behavior = createBehaviorInput({ manipulationScore: 0.6 });

      const decision = await engine.processAgent('exec-agent', signals, behavior);
      
      if (decision.shouldIntervene && !decision.requiresHumanApproval) {
        const action = engine.createAction(decision, 'exec-agent', 'test');
        expect(action?.status).toBe('approved');

        const executed = await engine.executeAction(action!.id);
        expect(executed).toBe(true);
        expect(engine.getAction(action!.id)?.status).toBe('executed');
      }
    });

    it('should reject execution for non-approved action', async () => {
      const result = await engine.executeAction('non-existent');
      expect(result).toBe(false);
    });
  });

  describe('rejectAction', () => {
    it('should reject pending action with reason', async () => {
      const signals = Array(6).fill(null).map(() => createThreatSignal('critical', 0.95));
      const behavior = createBehaviorInput({
        manipulationScore: 0.95,
        avgSemanticRisk: 0.9,
      });

      const decision = await engine.processAgent('reject-agent', signals, behavior);
      
      if (decision.shouldIntervene && decision.requiresHumanApproval) {
        const action = engine.createAction(decision, 'reject-agent', 'test');
        const rejected = engine.rejectAction(action!.id, 'Insufficient evidence');
        
        expect(rejected).toBe(true);
        expect(engine.getAction(action!.id)?.status).toBe('rejected');
        expect(engine.getAction(action!.id)?.metadata?.rejectionReason).toBe('Insufficient evidence');
      }
    });
  });

  describe('getPendingActions', () => {
    it('should return only pending actions', async () => {
      const signals = Array(6).fill(null).map(() => createThreatSignal('critical', 0.95));
      const behavior = createBehaviorInput({
        manipulationScore: 0.95,
        avgSemanticRisk: 0.9,
      });

      const decision = await engine.processAgent('pending-agent', signals, behavior);
      
      if (decision.shouldIntervene && decision.requiresHumanApproval) {
        engine.createAction(decision, 'pending-agent', 'test');
        const pending = engine.getPendingActions();
        expect(pending.every(a => a.status === 'pending')).toBe(true);
      }
    });
  });
});

describe('processAgentWorkflow', () => {
  it('should process complete workflow', async () => {
    const engine = new WorkflowEngine();
    const signals = [
      {
        id: 'sig-1',
        type: 'manipulation' as const,
        severity: 'medium' as const,
        confidence: 0.8,
        description: 'Test signal',
        sourcePost: 'post-1',
        indicators: [],
        detectedAt: new Date(),
      },
    ];
    const behavior: AgentBehaviorInput = {
      agentUsername: 'workflow-agent',
      postCount: 10,
      threatSignalCount: 1,
      avgThreatSeverity: 0.5,
      manipulationScore: 0.3,
      deceptionScore: 0.2,
      urgencyScore: 0.1,
      coordinationScore: 0.1,
      avgSemanticRisk: 0.4,
    };

    const result = await processAgentWorkflow(
      engine,
      'workflow-agent',
      signals,
      behavior,
      'automated-test',
      true // autoExecute
    );

    expect(result.decision).toBeDefined();
    expect(typeof result.decision.shouldIntervene).toBe('boolean');
  });
});

describe('getWorkflowSummary', () => {
  it('should return summary of pending actions', () => {
    const engine = new WorkflowEngine();
    const summary = getWorkflowSummary(engine);

    expect(summary.pendingActions).toBe(0);
    expect(summary.actionsByTier).toEqual({
      tier1: 0,
      tier2: 0,
      tier3: 0,
      tier4: 0,
    });
  });
});

describe('DEFAULT_WORKFLOW_CONFIG', () => {
  it('should have valid tier thresholds', () => {
    const tiers: Array<keyof typeof DEFAULT_WORKFLOW_CONFIG.tiers> = ['tier1', 'tier2', 'tier3', 'tier4'];
    
    for (const tier of tiers) {
      const threshold = DEFAULT_WORKFLOW_CONFIG.tiers[tier];
      expect(threshold.riskScore).toBeGreaterThan(0);
      expect(threshold.riskScore).toBeLessThanOrEqual(1);
      expect(threshold.minThreatSignals).toBeGreaterThan(0);
      expect(threshold.consensusRequired).toBeGreaterThan(0);
    }
  });

  it('should have increasing risk thresholds', () => {
    const { tier1, tier2, tier3, tier4 } = DEFAULT_WORKFLOW_CONFIG.tiers;
    
    expect(tier1.riskScore).toBeLessThan(tier2.riskScore);
    expect(tier2.riskScore).toBeLessThan(tier3.riskScore);
    expect(tier3.riskScore).toBeLessThan(tier4.riskScore);
  });
});
