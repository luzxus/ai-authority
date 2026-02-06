/**
 * Rule Engine
 * 
 * Decision tree evaluation for threshold-based classification.
 */

import { generateSecureId } from '@ai-authority/core';
import type {
  RuleEntry,
  RuleCondition,
  RuleAction,
  KnowledgeDomain,
  KnowledgeSource,
  QueryOptions,
  QueryResult,
} from './types.js';

/** Rule evaluation context */
export interface EvaluationContext {
  [key: string]: unknown;
}

/** Rule evaluation result */
export interface EvaluationResult {
  ruleId: string;
  matched: boolean;
  action?: RuleAction | undefined;
  score?: number | undefined;
  reason?: string | undefined;
}

/** Aggregate evaluation result */
export interface AggregateResult {
  matched: RuleEntry[];
  actions: RuleAction[];
  totalScore: number;
  classification?: string | undefined;
  evaluationTime: number;
}

/**
 * Rule engine for decision tree evaluation.
 */
export class RuleEngine {
  private readonly rules: Map<string, RuleEntry> = new Map();
  private readonly domainIndex: Map<KnowledgeDomain, Set<string>> = new Map();
  private readonly priorityOrder: string[] = [];

  /** Add a rule */
  add(
    condition: RuleCondition,
    action: RuleAction,
    domain: KnowledgeDomain,
    priority: number = 0,
    source?: Partial<KnowledgeSource>
  ): string {
    const id = generateSecureId();
    const now = Date.now();

    const entry: RuleEntry = {
      id,
      type: 'rule',
      domain,
      version: 1,
      createdAt: now,
      updatedAt: now,
      createdBy: source?.origin ?? 'unknown',
      source: {
        type: source?.type ?? 'bootstrap',
        origin: source?.origin ?? 'system',
        provenance: source?.provenance ?? [],
        hash: this.hashRule(condition, action),
      },
      confidence: 1.0,
      condition,
      action,
      priority,
      enabled: true,
    };

    this.rules.set(id, entry);

    // Update domain index
    const domainSet = this.domainIndex.get(domain) ?? new Set();
    domainSet.add(id);
    this.domainIndex.set(domain, domainSet);

    // Update priority order
    this.updatePriorityOrder();

    return id;
  }

  /** Remove a rule */
  remove(id: string): boolean {
    const entry = this.rules.get(id);
    if (!entry) return false;

    this.rules.delete(id);

    // Update domain index
    const domainSet = this.domainIndex.get(entry.domain);
    if (domainSet) {
      domainSet.delete(id);
    }

    this.updatePriorityOrder();
    return true;
  }

  /** Get a rule by ID */
  get(id: string): RuleEntry | undefined {
    return this.rules.get(id);
  }

  /** Enable/disable a rule */
  setEnabled(id: string, enabled: boolean): boolean {
    const entry = this.rules.get(id);
    if (!entry) return false;
    entry.enabled = enabled;
    entry.updatedAt = Date.now();
    return true;
  }

  /** Query rules */
  query(options: QueryOptions): QueryResult<RuleEntry> {
    const startTime = Date.now();
    const { limit = 100, offset = 0, domains, minConfidence = 0 } = options;

    let entries: RuleEntry[];

    if (domains && domains.length > 0) {
      const ids = new Set<string>();
      for (const domain of domains) {
        const domainSet = this.domainIndex.get(domain);
        if (domainSet) {
          for (const id of domainSet) {
            ids.add(id);
          }
        }
      }
      entries = Array.from(ids)
        .map((id) => this.rules.get(id))
        .filter((e): e is RuleEntry => e !== undefined);
    } else {
      entries = Array.from(this.rules.values());
    }

    // Filter by confidence
    entries = entries.filter((e) => e.confidence >= minConfidence);

    // Sort by priority
    entries.sort((a, b) => b.priority - a.priority);

    return {
      entries: entries.slice(offset, offset + limit),
      total: entries.length,
      queryTime: Date.now() - startTime,
    };
  }

  /** Evaluate a single rule against context */
  evaluate(ruleId: string, context: EvaluationContext): EvaluationResult {
    const rule = this.rules.get(ruleId);
    if (!rule || !rule.enabled) {
      return { ruleId, matched: false };
    }

    const matched = this.evaluateCondition(rule.condition, context);
    return {
      ruleId,
      matched,
      action: matched ? rule.action : undefined,
      score: matched && rule.action.type === 'score' 
        ? rule.action.parameters['value'] as number 
        : undefined,
      reason: matched ? `Rule ${ruleId} matched` : undefined,
    };
  }

  /** Evaluate all rules against context */
  evaluateAll(context: EvaluationContext, domains?: KnowledgeDomain[]): AggregateResult {
    const startTime = Date.now();
    const matched: RuleEntry[] = [];
    const actions: RuleAction[] = [];
    let totalScore = 0;

    // Get rules to evaluate
    let ruleIds: string[];
    if (domains && domains.length > 0) {
      ruleIds = [];
      for (const domain of domains) {
        const domainSet = this.domainIndex.get(domain);
        if (domainSet) {
          ruleIds.push(...domainSet);
        }
      }
    } else {
      ruleIds = this.priorityOrder;
    }

    // Evaluate in priority order
    for (const id of ruleIds) {
      const rule = this.rules.get(id);
      if (!rule || !rule.enabled) continue;

      if (this.evaluateCondition(rule.condition, context)) {
        matched.push(rule);
        actions.push(rule.action);

        if (rule.action.type === 'score') {
          totalScore += (rule.action.parameters['value'] as number) ?? 0;
        }
      }
    }

    // Determine classification from classify actions
    let classification: string | undefined;
    const classifyActions = actions.filter((a) => a.type === 'classify');
    if (classifyActions.length > 0) {
      // Use highest priority classification
      const firstAction = classifyActions[0];
      classification = firstAction ? (firstAction.parameters['classification'] as string) : undefined;
    }

    return {
      matched,
      actions,
      totalScore,
      classification,
      evaluationTime: Date.now() - startTime,
    };
  }

  /** Evaluate a condition recursively */
  private evaluateCondition(condition: RuleCondition, context: EvaluationContext): boolean {
    switch (condition.type) {
      case 'threshold':
        return this.evaluateThreshold(condition, context);
      case 'composite':
        return this.evaluateComposite(condition, context);
      case 'pattern':
        return this.evaluatePattern(condition, context);
      default:
        return false;
    }
  }

  /** Evaluate threshold condition */
  private evaluateThreshold(condition: RuleCondition, context: EvaluationContext): boolean {
    const field = condition.field;
    if (!field) return false;

    const value = this.getNestedValue(context, field);
    if (value === undefined) return false;

    const threshold = condition.value;
    const operator = condition.operator;

    switch (operator) {
      case 'gt':
        return (value as number) > (threshold as number);
      case 'gte':
        return (value as number) >= (threshold as number);
      case 'lt':
        return (value as number) < (threshold as number);
      case 'lte':
        return (value as number) <= (threshold as number);
      case 'eq':
        return value === threshold;
      case 'neq':
        return value !== threshold;
      case 'contains':
        return String(value).includes(String(threshold));
      case 'matches':
        return new RegExp(String(threshold)).test(String(value));
      default:
        return false;
    }
  }

  /** Evaluate composite condition */
  private evaluateComposite(condition: RuleCondition, context: EvaluationContext): boolean {
    const children = condition.children ?? [];
    const logic = condition.logic ?? 'and';

    switch (logic) {
      case 'and':
        return children.every((c) => this.evaluateCondition(c, context));
      case 'or':
        return children.some((c) => this.evaluateCondition(c, context));
      case 'not': {
        const firstChild = children[0];
        return firstChild !== undefined && !this.evaluateCondition(firstChild, context);
      }
      default:
        return false;
    }
  }

  /** Evaluate pattern condition */
  private evaluatePattern(condition: RuleCondition, context: EvaluationContext): boolean {
    // Pattern matching would use more sophisticated techniques
    // For now, treat as regex on stringified context
    const pattern = String(condition.value);
    const contextStr = JSON.stringify(context);
    return new RegExp(pattern, 'i').test(contextStr);
  }

  /** Get nested value from object */
  private getNestedValue(obj: EvaluationContext, path: string): unknown {
    const parts = path.split('.');
    let current: unknown = obj;
    for (const part of parts) {
      if (current === null || current === undefined) return undefined;
      current = (current as Record<string, unknown>)[part];
    }
    return current;
  }

  /** Update priority order */
  private updatePriorityOrder(): void {
    const entries = Array.from(this.rules.values());
    entries.sort((a, b) => b.priority - a.priority);
    this.priorityOrder.length = 0;
    this.priorityOrder.push(...entries.map((e) => e.id));
  }

  /** Hash a rule for content verification */
  private hashRule(condition: RuleCondition, action: RuleAction): string {
    const content = JSON.stringify({ condition, action });
    let hash = 0;
    for (let i = 0; i < content.length; i++) {
      hash = ((hash << 5) - hash + content.charCodeAt(i)) | 0;
    }
    return hash.toString(16);
  }
}

/** Create a rule engine instance */
export function createRuleEngine(): RuleEngine {
  return new RuleEngine();
}

/** Create default criminal behavior rules */
export function createDefaultRules(engine: RuleEngine): void {
  // Harm threshold rule
  engine.add(
    {
      type: 'composite',
      logic: 'or',
      children: [
        { type: 'threshold', field: 'economicImpact', operator: 'gt', value: 10000 },
        { type: 'threshold', field: 'usersTargeted', operator: 'gt', value: 100 },
      ],
    },
    { type: 'score', parameters: { dimension: 'harm', value: 0.8 } },
    'malicious_patterns',
    100
  );

  // Persistence threshold rule
  engine.add(
    { type: 'threshold', field: 'sessionCount', operator: 'gt', value: 5 },
    { type: 'score', parameters: { dimension: 'persistence', value: 0.6 } },
    'malicious_patterns',
    90
  );

  // Autonomy threshold rule
  engine.add(
    { type: 'threshold', field: 'chainedCallCount', operator: 'gte', value: 4 },
    { type: 'score', parameters: { dimension: 'autonomy', value: 0.7 } },
    'malicious_patterns',
    80
  );

  // Deception threshold rule
  engine.add(
    {
      type: 'composite',
      logic: 'and',
      children: [
        { type: 'threshold', field: 'outputEntropy', operator: 'gt', value: 0.85 },
        { type: 'threshold', field: 'semanticInconsistency', operator: 'gt', value: 0.85 },
      ],
    },
    { type: 'score', parameters: { dimension: 'deception', value: 0.9 } },
    'malicious_patterns',
    85
  );

  // Evasion threshold rule (3σ above baseline)
  engine.add(
    { type: 'threshold', field: 'promptVariationSigma', operator: 'gt', value: 3 },
    { type: 'score', parameters: { dimension: 'evasion', value: 0.8 } },
    'evasion',
    75
  );

  // Classification rules
  engine.add(
    {
      type: 'composite',
      logic: 'and',
      children: [
        { type: 'threshold', field: 'deceptionScore', operator: 'gt', value: 0.7 },
        { type: 'threshold', field: 'harmScore', operator: 'gt', value: 0.5 },
      ],
    },
    { type: 'classify', parameters: { classification: 'malicious' } },
    'malicious_patterns',
    200
  );

  engine.add(
    {
      type: 'composite',
      logic: 'and',
      children: [
        { type: 'threshold', field: 'autonomyScore', operator: 'gt', value: 0.6 },
        { type: 'threshold', field: 'deceptionScore', operator: 'lte', value: 0.3 },
      ],
    },
    { type: 'classify', parameters: { classification: 'negligent' } },
    'malicious_patterns',
    150
  );
}
