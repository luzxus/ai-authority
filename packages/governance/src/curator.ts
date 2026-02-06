/**
 * Curator Agent
 * 
 * Synthesizes knowledge and encodes rules from approved proposals.
 */

import { BaseAgent, type AgentConfig, type AgentTask, type TaskResult } from '@ai-authority/agents';
import { KnowledgeBase, type RuleCondition, type RuleAction, type BehaviorPattern, type KnowledgeDomain } from '@ai-authority/knowledge';
import { generateSecureId } from '@ai-authority/core';
import type { Proposal } from './proposer.js';

/** Knowledge synthesis result */
export interface SynthesisResult {
  proposalId: string;
  synthesizedItems: SynthesizedItem[];
  timestamp: number;
}

/** Synthesized item */
export interface SynthesizedItem {
  id: string;
  type: 'rule' | 'pattern' | 'embedding' | 'fingerprint';
  domain: KnowledgeDomain;
  status: 'pending' | 'applied' | 'failed';
  error?: string;
}

/**
 * Curator Agent
 * 
 * Encodes approved proposals into the knowledge base.
 */
export class CuratorAgent extends BaseAgent {
  private knowledgeBase?: KnowledgeBase;
  private synthesisHistory: Map<string, SynthesisResult> = new Map();

  constructor(config: AgentConfig) {
    super(config);
  }

  /** Set the knowledge base to curate */
  setKnowledgeBase(kb: KnowledgeBase): void {
    this.knowledgeBase = kb;
  }

  protected async processTask<T, R>(task: AgentTask<T>): Promise<TaskResult<R>> {
    const startTime = Date.now();

    try {
      switch (task.type) {
        case 'synthesize_proposal':
          const result = await this.synthesizeProposal(task.payload as { proposal: Proposal; approvals: string[] });
          return {
            taskId: task.id,
            success: true,
            result: result as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };

        case 'encode_rule':
          const ruleId = await this.encodeRule(task.payload as {
            condition: RuleCondition;
            action: RuleAction;
            domain: KnowledgeDomain;
            priority?: number;
          });
          return {
            taskId: task.id,
            success: true,
            result: ruleId as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };

        case 'encode_pattern':
          const patternId = await this.encodePattern(task.payload as {
            pattern: BehaviorPattern;
            domain: KnowledgeDomain;
          });
          return {
            taskId: task.id,
            success: true,
            result: patternId as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };

        default:
          return {
            taskId: task.id,
            success: false,
            error: `Unknown task type: ${task.type}`,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
      }
    } catch (error) {
      return {
        taskId: task.id,
        success: false,
        error: String(error),
        duration: Date.now() - startTime,
        timestamp: Date.now(),
      };
    }
  }

  /** Synthesize an approved proposal into knowledge */
  private async synthesizeProposal(params: {
    proposal: Proposal;
    approvals: string[];
  }): Promise<SynthesisResult> {
    const { proposal, approvals } = params;

    if (!this.knowledgeBase) {
      throw new Error('Knowledge base not configured');
    }

    const synthesizedItems: SynthesizedItem[] = [];

    // Process based on proposal type
    switch (proposal.type) {
      case 'knowledge_update':
        await this.processKnowledgeUpdate(proposal, synthesizedItems);
        break;

      case 'threshold_adjustment':
        await this.processThresholdAdjustment(proposal, synthesizedItems);
        break;

      case 'rule_modification':
        await this.processRuleModification(proposal, synthesizedItems);
        break;

      case 'architecture_change':
        // Architecture changes require special handling
        this.logAudit('architecture_change_deferred', { proposalId: proposal.id });
        break;
    }

    const result: SynthesisResult = {
      proposalId: proposal.id,
      synthesizedItems,
      timestamp: Date.now(),
    };

    this.synthesisHistory.set(proposal.id, result);

    this.logAudit('proposal_synthesized', {
      proposalId: proposal.id,
      itemCount: synthesizedItems.length,
      approvals,
    });

    return result;
  }

  /** Process knowledge update proposal */
  private async processKnowledgeUpdate(
    proposal: Proposal,
    items: SynthesizedItem[]
  ): Promise<void> {
    const payload = proposal.payload as {
      type: 'pattern' | 'rule' | 'embedding';
      data: unknown;
      domain: KnowledgeDomain;
    };

    if (!payload || !payload.type) return;

    const item: SynthesizedItem = {
      id: generateSecureId(),
      type: payload.type,
      domain: payload.domain || 'malicious_patterns',
      status: 'pending',
    };

    try {
      switch (payload.type) {
        case 'pattern':
          await this.encodePattern({
            pattern: payload.data as BehaviorPattern,
            domain: payload.domain,
          });
          break;

        case 'rule':
          const ruleData = payload.data as { condition: RuleCondition; action: RuleAction; priority?: number };
          await this.encodeRule({
            condition: ruleData.condition,
            action: ruleData.action,
            domain: payload.domain,
            ...(ruleData.priority !== undefined && { priority: ruleData.priority }),
          });
          break;

        case 'embedding':
          const embData = payload.data as { vector: number[]; metadata: Record<string, unknown> };
          this.knowledgeBase?.addEmbedding(embData.vector, payload.domain, embData.metadata, this.id);
          break;
      }

      item.status = 'applied';
    } catch (error) {
      item.status = 'failed';
      item.error = String(error);
    }

    items.push(item);
  }

  /** Process threshold adjustment proposal */
  private async processThresholdAdjustment(
    proposal: Proposal,
    items: SynthesizedItem[]
  ): Promise<void> {
    const payload = proposal.payload as {
      dimension: string;
      oldThreshold: number;
      newThreshold: number;
    };

    if (!payload) return;

    // Create a new rule with updated threshold
    const item: SynthesizedItem = {
      id: generateSecureId(),
      type: 'rule',
      domain: 'malicious_patterns',
      status: 'pending',
    };

    try {
      // In production, would update existing rule
      // For now, create a new rule with adjusted threshold
      this.knowledgeBase?.addRule(
        {
          type: 'threshold',
          field: payload.dimension,
          operator: 'gt',
          value: payload.newThreshold,
        },
        {
          type: 'score',
          parameters: { dimension: payload.dimension, adjusted: true },
        },
        'malicious_patterns',
        50,
        this.id
      );

      item.status = 'applied';
    } catch (error) {
      item.status = 'failed';
      item.error = String(error);
    }

    items.push(item);
  }

  /** Process rule modification proposal */
  private async processRuleModification(
    proposal: Proposal,
    items: SynthesizedItem[]
  ): Promise<void> {
    const payload = proposal.payload as {
      ruleId?: string;
      condition: RuleCondition;
      action: RuleAction;
      domain: KnowledgeDomain;
      priority?: number;
    };

    if (!payload) return;

    const item: SynthesizedItem = {
      id: generateSecureId(),
      type: 'rule',
      domain: payload.domain || 'malicious_patterns',
      status: 'pending',
    };

    try {
      await this.encodeRule({
        condition: payload.condition,
        action: payload.action,
        domain: payload.domain || 'malicious_patterns',
        ...(payload.priority !== undefined && { priority: payload.priority }),
      });

      item.status = 'applied';
    } catch (error) {
      item.status = 'failed';
      item.error = String(error);
    }

    items.push(item);
  }

  /** Encode a rule into the knowledge base */
  private async encodeRule(params: {
    condition: RuleCondition;
    action: RuleAction;
    domain: KnowledgeDomain;
    priority?: number;
  }): Promise<string | { pendingId: string }> {
    if (!this.knowledgeBase) {
      throw new Error('Knowledge base not configured');
    }

    return this.knowledgeBase.addRule(
      params.condition,
      params.action,
      params.domain,
      params.priority ?? 0,
      this.id
    );
  }

  /** Encode a pattern into the knowledge base */
  private async encodePattern(params: {
    pattern: BehaviorPattern;
    domain: KnowledgeDomain;
  }): Promise<string | { pendingId: string }> {
    if (!this.knowledgeBase) {
      throw new Error('Knowledge base not configured');
    }

    return this.knowledgeBase.addPattern(params.pattern, params.domain, this.id);
  }

  /** Get synthesis history */
  getSynthesisHistory(): SynthesisResult[] {
    return Array.from(this.synthesisHistory.values());
  }

  /** Get synthesis result for a proposal */
  getSynthesisResult(proposalId: string): SynthesisResult | undefined {
    return this.synthesisHistory.get(proposalId);
  }
}
