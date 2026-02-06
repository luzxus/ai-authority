/**
 * RuleEngine Tests
 */

import { RuleEngine } from '../rules';
import type { RuleCondition, RuleAction } from '../types';

describe('RuleEngine', () => {
  let engine: RuleEngine;

  beforeEach(() => {
    engine = new RuleEngine();
  });

  describe('add', () => {
    it('should add a rule and return ID', () => {
      const condition: RuleCondition = {
        type: 'threshold',
        field: 'score',
        operator: 'gt',
        value: 0.8,
      };
      const action: RuleAction = {
        type: 'classify',
        parameters: { classification: 'malicious' },
      };

      const id = engine.add(condition, action, 'malicious_patterns');

      expect(typeof id).toBe('string');
      expect(id.length).toBeGreaterThan(0);
    });

    it('should store rule with priority', () => {
      const condition: RuleCondition = { type: 'threshold', field: 'x', operator: 'gt', value: 1 };
      const action: RuleAction = { type: 'alert', parameters: {} };

      const id = engine.add(condition, action, 'malicious_patterns', 10);
      const rule = engine.get(id);

      expect(rule?.priority).toBe(10);
    });

    it('should enable rules by default', () => {
      const condition: RuleCondition = { type: 'threshold', field: 'x', operator: 'gt', value: 1 };
      const action: RuleAction = { type: 'alert', parameters: {} };

      const id = engine.add(condition, action, 'malicious_patterns');
      const rule = engine.get(id);

      expect(rule?.enabled).toBe(true);
    });
  });

  describe('get', () => {
    it('should retrieve rule by ID', () => {
      const condition: RuleCondition = { type: 'threshold', field: 'risk', operator: 'gte', value: 0.5 };
      const action: RuleAction = { type: 'score', parameters: { value: 10 } };

      const id = engine.add(condition, action, 'api_misuse');
      const rule = engine.get(id);

      expect(rule).toBeDefined();
      expect(rule?.condition).toEqual(condition);
      expect(rule?.action).toEqual(action);
    });

    it('should return undefined for unknown ID', () => {
      const rule = engine.get('unknown-id');
      expect(rule).toBeUndefined();
    });
  });

  describe('remove', () => {
    it('should remove rule and return true', () => {
      const id = engine.add(
        { type: 'threshold', field: 'x', operator: 'gt', value: 1 },
        { type: 'alert', parameters: {} },
        'malicious_patterns'
      );

      const result = engine.remove(id);

      expect(result).toBe(true);
      expect(engine.get(id)).toBeUndefined();
    });

    it('should return false for unknown ID', () => {
      const result = engine.remove('unknown-id');
      expect(result).toBe(false);
    });
  });

  describe('setEnabled', () => {
    it('should disable a rule', () => {
      const id = engine.add(
        { type: 'threshold', field: 'x', operator: 'gt', value: 1 },
        { type: 'alert', parameters: {} },
        'malicious_patterns'
      );

      const result = engine.setEnabled(id, false);

      expect(result).toBe(true);
      expect(engine.get(id)?.enabled).toBe(false);
    });

    it('should enable a disabled rule', () => {
      const id = engine.add(
        { type: 'threshold', field: 'x', operator: 'gt', value: 1 },
        { type: 'alert', parameters: {} },
        'malicious_patterns'
      );

      engine.setEnabled(id, false);
      engine.setEnabled(id, true);

      expect(engine.get(id)?.enabled).toBe(true);
    });

    it('should return false for unknown ID', () => {
      const result = engine.setEnabled('unknown', true);
      expect(result).toBe(false);
    });
  });

  describe('query', () => {
    beforeEach(() => {
      engine.add(
        { type: 'threshold', field: 'a', operator: 'gt', value: 1 },
        { type: 'alert', parameters: {} },
        'malicious_patterns',
        5
      );
      engine.add(
        { type: 'threshold', field: 'b', operator: 'gt', value: 2 },
        { type: 'score', parameters: { value: 10 } },
        'api_misuse',
        10
      );
      engine.add(
        { type: 'threshold', field: 'c', operator: 'gt', value: 3 },
        { type: 'classify', parameters: { classification: 'malicious' } },
        'malicious_patterns',
        15
      );
    });

    it('should return all rules', () => {
      const result = engine.query({});

      expect(result.entries.length).toBe(3);
    });

    it('should filter by domain', () => {
      const result = engine.query({ domains: ['malicious_patterns'] });

      expect(result.entries.length).toBe(2);
      expect(result.entries.every((r) => r.domain === 'malicious_patterns')).toBe(true);
    });

    it('should respect limit', () => {
      const result = engine.query({ limit: 2 });

      expect(result.entries.length).toBe(2);
    });

    it('should respect offset', () => {
      const all = engine.query({});
      const offset = engine.query({ offset: 1 });

      expect(offset.entries.length).toBe(2);
      expect(offset.entries[0]?.id).toBe(all.entries[1]?.id);
    });

    it('should sort by priority descending', () => {
      const result = engine.query({});

      for (let i = 1; i < result.entries.length; i++) {
        expect(result.entries[i - 1]!.priority).toBeGreaterThanOrEqual(result.entries[i]!.priority);
      }
    });
  });

  describe('evaluate', () => {
    describe('threshold conditions', () => {
      it('should evaluate gt operator', () => {
        const id = engine.add(
          { type: 'threshold', field: 'score', operator: 'gt', value: 0.5 },
          { type: 'alert', parameters: {} },
          'malicious_patterns'
        );

        expect(engine.evaluate(id, { score: 0.6 }).matched).toBe(true);
        expect(engine.evaluate(id, { score: 0.5 }).matched).toBe(false);
        expect(engine.evaluate(id, { score: 0.4 }).matched).toBe(false);
      });

      it('should evaluate gte operator', () => {
        const id = engine.add(
          { type: 'threshold', field: 'score', operator: 'gte', value: 0.5 },
          { type: 'alert', parameters: {} },
          'malicious_patterns'
        );

        expect(engine.evaluate(id, { score: 0.6 }).matched).toBe(true);
        expect(engine.evaluate(id, { score: 0.5 }).matched).toBe(true);
        expect(engine.evaluate(id, { score: 0.4 }).matched).toBe(false);
      });

      it('should evaluate lt operator', () => {
        const id = engine.add(
          { type: 'threshold', field: 'score', operator: 'lt', value: 0.5 },
          { type: 'alert', parameters: {} },
          'malicious_patterns'
        );

        expect(engine.evaluate(id, { score: 0.4 }).matched).toBe(true);
        expect(engine.evaluate(id, { score: 0.5 }).matched).toBe(false);
      });

      it('should evaluate eq operator', () => {
        const id = engine.add(
          { type: 'threshold', field: 'status', operator: 'eq', value: 'active' },
          { type: 'alert', parameters: {} },
          'malicious_patterns'
        );

        expect(engine.evaluate(id, { status: 'active' }).matched).toBe(true);
        expect(engine.evaluate(id, { status: 'inactive' }).matched).toBe(false);
      });

      it('should evaluate neq operator', () => {
        const id = engine.add(
          { type: 'threshold', field: 'status', operator: 'neq', value: 'safe' },
          { type: 'alert', parameters: {} },
          'malicious_patterns'
        );

        expect(engine.evaluate(id, { status: 'suspicious' }).matched).toBe(true);
        expect(engine.evaluate(id, { status: 'safe' }).matched).toBe(false);
      });

      it('should evaluate contains operator', () => {
        const id = engine.add(
          { type: 'threshold', field: 'message', operator: 'contains', value: 'malware' },
          { type: 'alert', parameters: {} },
          'malicious_patterns'
        );

        expect(engine.evaluate(id, { message: 'detected malware activity' }).matched).toBe(true);
        expect(engine.evaluate(id, { message: 'all clear' }).matched).toBe(false);
      });

      it('should evaluate matches operator (regex)', () => {
        const id = engine.add(
          { type: 'threshold', field: 'ip', operator: 'matches', value: '^192\\.168\\.' },
          { type: 'alert', parameters: {} },
          'malicious_patterns'
        );

        expect(engine.evaluate(id, { ip: '192.168.1.1' }).matched).toBe(true);
        expect(engine.evaluate(id, { ip: '10.0.0.1' }).matched).toBe(false);
      });

      it('should handle nested fields', () => {
        const id = engine.add(
          { type: 'threshold', field: 'agent.metrics.score', operator: 'gt', value: 0.8 },
          { type: 'alert', parameters: {} },
          'malicious_patterns'
        );

        expect(engine.evaluate(id, { agent: { metrics: { score: 0.9 } } }).matched).toBe(true);
        expect(engine.evaluate(id, { agent: { metrics: { score: 0.7 } } }).matched).toBe(false);
      });

      it('should not match when field is missing', () => {
        const id = engine.add(
          { type: 'threshold', field: 'nonexistent', operator: 'gt', value: 0 },
          { type: 'alert', parameters: {} },
          'malicious_patterns'
        );

        expect(engine.evaluate(id, { other: 1 }).matched).toBe(false);
      });
    });

    describe('composite conditions', () => {
      it('should evaluate AND logic', () => {
        const id = engine.add(
          {
            type: 'composite',
            logic: 'and',
            children: [
              { type: 'threshold', field: 'a', operator: 'gt', value: 5 },
              { type: 'threshold', field: 'b', operator: 'lt', value: 10 },
            ],
          },
          { type: 'alert', parameters: {} },
          'malicious_patterns'
        );

        expect(engine.evaluate(id, { a: 6, b: 8 }).matched).toBe(true);
        expect(engine.evaluate(id, { a: 4, b: 8 }).matched).toBe(false);
        expect(engine.evaluate(id, { a: 6, b: 12 }).matched).toBe(false);
      });

      it('should evaluate OR logic', () => {
        const id = engine.add(
          {
            type: 'composite',
            logic: 'or',
            children: [
              { type: 'threshold', field: 'risk', operator: 'gt', value: 0.9 },
              { type: 'threshold', field: 'alert', operator: 'eq', value: true },
            ],
          },
          { type: 'alert', parameters: {} },
          'malicious_patterns'
        );

        expect(engine.evaluate(id, { risk: 0.95, alert: false }).matched).toBe(true);
        expect(engine.evaluate(id, { risk: 0.5, alert: true }).matched).toBe(true);
        expect(engine.evaluate(id, { risk: 0.5, alert: false }).matched).toBe(false);
      });

      it('should evaluate NOT logic', () => {
        const id = engine.add(
          {
            type: 'composite',
            logic: 'not',
            children: [
              { type: 'threshold', field: 'safe', operator: 'eq', value: true },
            ],
          },
          { type: 'alert', parameters: {} },
          'malicious_patterns'
        );

        expect(engine.evaluate(id, { safe: false }).matched).toBe(true);
        expect(engine.evaluate(id, { safe: true }).matched).toBe(false);
      });

      it('should handle nested composite conditions', () => {
        const id = engine.add(
          {
            type: 'composite',
            logic: 'and',
            children: [
              { type: 'threshold', field: 'score', operator: 'gt', value: 0.5 },
              {
                type: 'composite',
                logic: 'or',
                children: [
                  { type: 'threshold', field: 'category', operator: 'eq', value: 'malware' },
                  { type: 'threshold', field: 'category', operator: 'eq', value: 'phishing' },
                ],
              },
            ],
          },
          { type: 'classify', parameters: { classification: 'malicious' } },
          'malicious_patterns'
        );

        expect(engine.evaluate(id, { score: 0.8, category: 'malware' }).matched).toBe(true);
        expect(engine.evaluate(id, { score: 0.8, category: 'phishing' }).matched).toBe(true);
        expect(engine.evaluate(id, { score: 0.3, category: 'malware' }).matched).toBe(false);
        expect(engine.evaluate(id, { score: 0.8, category: 'benign' }).matched).toBe(false);
      });
    });

    describe('disabled rules', () => {
      it('should not match disabled rules', () => {
        const id = engine.add(
          { type: 'threshold', field: 'score', operator: 'gt', value: 0 },
          { type: 'alert', parameters: {} },
          'malicious_patterns'
        );

        engine.setEnabled(id, false);

        expect(engine.evaluate(id, { score: 100 }).matched).toBe(false);
      });
    });

    describe('action in result', () => {
      it('should include action when matched', () => {
        const action: RuleAction = { type: 'score', parameters: { value: 25 } };
        const id = engine.add(
          { type: 'threshold', field: 'x', operator: 'gt', value: 0 },
          action,
          'malicious_patterns'
        );

        const result = engine.evaluate(id, { x: 1 });

        expect(result.action).toEqual(action);
        expect(result.score).toBe(25);
      });

      it('should not include action when not matched', () => {
        const id = engine.add(
          { type: 'threshold', field: 'x', operator: 'gt', value: 10 },
          { type: 'score', parameters: { value: 25 } },
          'malicious_patterns'
        );

        const result = engine.evaluate(id, { x: 5 });

        expect(result.action).toBeUndefined();
        expect(result.score).toBeUndefined();
      });
    });
  });

  describe('evaluateAll', () => {
    beforeEach(() => {
      engine.add(
        { type: 'threshold', field: 'score', operator: 'gt', value: 0.8 },
        { type: 'score', parameters: { value: 10 } },
        'malicious_patterns',
        10
      );
      engine.add(
        { type: 'threshold', field: 'score', operator: 'gt', value: 0.5 },
        { type: 'score', parameters: { value: 5 } },
        'malicious_patterns',
        5
      );
      engine.add(
        { type: 'threshold', field: 'category', operator: 'eq', value: 'malware' },
        { type: 'classify', parameters: { classification: 'malicious' } },
        'malicious_patterns',
        15
      );
    });

    it('should aggregate scores from matching rules', () => {
      const result = engine.evaluateAll({ score: 0.9 });

      // Both score rules should match (>0.8 and >0.5)
      expect(result.totalScore).toBe(15); // 10 + 5
    });

    it('should include classification from classify actions', () => {
      const result = engine.evaluateAll({ score: 0.9, category: 'malware' });

      expect(result.classification).toBe('malicious');
    });

    it('should return all matched rules', () => {
      const result = engine.evaluateAll({ score: 0.9, category: 'malware' });

      expect(result.matched.length).toBe(3);
    });

    it('should filter by domains', () => {
      engine.add(
        { type: 'threshold', field: 'api_calls', operator: 'gt', value: 100 },
        { type: 'alert', parameters: {} },
        'api_misuse'
      );

      const result = engine.evaluateAll(
        { score: 0.9, api_calls: 200 },
        ['malicious_patterns']
      );

      // Should only match malicious_patterns rules
      expect(result.matched.every((r) => r.domain === 'malicious_patterns')).toBe(true);
    });

    it('should include evaluation time', () => {
      const result = engine.evaluateAll({ score: 0.9 });

      expect(result.evaluationTime).toBeGreaterThanOrEqual(0);
    });
  });
});
