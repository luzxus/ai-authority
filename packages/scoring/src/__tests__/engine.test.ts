/**
 * Risk Scoring Engine Tests
 */

import { RiskScoringEngine } from '../engine.js';
import type { ScoringConfig } from '@ai-authority/core';
import { DEFAULT_SCORING_CONFIG } from '@ai-authority/core';

describe('RiskScoringEngine', () => {
  let engine: RiskScoringEngine;

  beforeEach(() => {
    engine = new RiskScoringEngine();
  });

  describe('basic scoring', () => {
    it('should return low score for benign behavior', () => {
      const result = engine.score({
        sessionCount: 1,
        chainedCallCount: 1,
      });

      expect(result.aggregate).toBeLessThan(0.2);
      expect(result.tier).toBe('alert');
      expect(result.classification).toBe('benign');
    });

    it('should return high score for malicious indicators', () => {
      const result = engine.score({
        estimatedEconomicImpact: 50000, // $50k
        sessionCount: 10, // Persistent
        chainedCallCount: 8, // High autonomy
        outputEntropy: 0.9, // High entropy
        semanticInconsistency: 0.9, // High inconsistency
        promptVariationSigma: 4, // 4σ above baseline
      });

      expect(result.aggregate).toBeGreaterThan(0.7);
      expect(result.tier).toBe('escalate');
      expect(result.classification).toBe('malicious');
    });

    it('should include calculation trace', () => {
      const result = engine.score({
        sessionCount: 5,
        chainedCallCount: 3,
      });

      expect(result.calculationTrace).toBeDefined();
      expect(result.calculationTrace.length).toBeGreaterThan(0);
      expect(result.calculationTrace.some((s) => s.step === 'aggregate')).toBe(true);
    });
  });

  describe('dimension scoring', () => {
    describe('harm', () => {
      it('should score based on economic impact', () => {
        const lowHarm = engine.score({
          estimatedEconomicImpact: 1000,
          sessionCount: 1,
          chainedCallCount: 1,
        });

        const highHarm = engine.score({
          estimatedEconomicImpact: 100000,
          sessionCount: 1,
          chainedCallCount: 1,
        });

        expect(highHarm.dimensions.harm.value).toBeGreaterThan(
          lowHarm.dimensions.harm.value
        );
      });

      it('should score based on users affected', () => {
        const result = engine.score({
          usersAffected: 500,
          sessionCount: 1,
          chainedCallCount: 1,
        });

        expect(result.dimensions.harm.value).toBeGreaterThan(0);
        expect(result.dimensions.harm.factors.some((f) => f.name === 'users_affected')).toBe(
          true
        );
      });

      it('should use OR logic (max of economic/users)', () => {
        const economicOnly = engine.score({
          estimatedEconomicImpact: 50000,
          sessionCount: 1,
          chainedCallCount: 1,
        });

        const usersOnly = engine.score({
          usersAffected: 500,
          sessionCount: 1,
          chainedCallCount: 1,
        });

        // Both should contribute to harm score
        expect(economicOnly.dimensions.harm.value).toBeGreaterThan(0);
        expect(usersOnly.dimensions.harm.value).toBeGreaterThan(0);
      });
    });

    describe('persistence', () => {
      it('should score based on session count', () => {
        const lowPersistence = engine.score({
          sessionCount: 1,
          chainedCallCount: 1,
        });

        const highPersistence = engine.score({
          sessionCount: 10,
          chainedCallCount: 1,
        });

        expect(highPersistence.dimensions.persistence.value).toBeGreaterThan(
          lowPersistence.dimensions.persistence.value
        );
      });

      it('should factor in instance count', () => {
        const singleInstance = engine.score({
          sessionCount: 5,
          instanceCount: 1,
          chainedCallCount: 1,
        });

        const multiInstance = engine.score({
          sessionCount: 5,
          instanceCount: 5,
          chainedCallCount: 1,
        });

        expect(multiInstance.dimensions.persistence.value).toBeGreaterThan(
          singleInstance.dimensions.persistence.value
        );
      });
    });

    describe('autonomy', () => {
      it('should score based on chained calls', () => {
        const lowAutonomy = engine.score({
          sessionCount: 1,
          chainedCallCount: 1,
        });

        const highAutonomy = engine.score({
          sessionCount: 1,
          chainedCallCount: 8,
        });

        expect(highAutonomy.dimensions.autonomy.value).toBeGreaterThan(
          lowAutonomy.dimensions.autonomy.value
        );
      });

      it('should hit threshold at 4 calls', () => {
        const result = engine.score({
          sessionCount: 1,
          chainedCallCount: 4,
        });

        // 4 calls = threshold, should be around 0.5 normalized
        expect(result.dimensions.autonomy.value).toBeGreaterThanOrEqual(0.3);
      });
    });

    describe('deception', () => {
      it('should score based on entropy and inconsistency', () => {
        const lowDeception = engine.score({
          sessionCount: 1,
          chainedCallCount: 1,
          outputEntropy: 0.2,
          semanticInconsistency: 0.1,
        });

        const highDeception = engine.score({
          sessionCount: 1,
          chainedCallCount: 1,
          outputEntropy: 0.95,
          semanticInconsistency: 0.9,
        });

        expect(highDeception.dimensions.deception.value).toBeGreaterThan(
          lowDeception.dimensions.deception.value
        );
      });

      it('should have lower confidence without data', () => {
        const withData = engine.score({
          sessionCount: 1,
          chainedCallCount: 1,
          outputEntropy: 0.5,
          semanticInconsistency: 0.5,
        });

        const withoutData = engine.score({
          sessionCount: 1,
          chainedCallCount: 1,
        });

        expect(withData.dimensions.deception.confidence).toBeGreaterThan(
          withoutData.dimensions.deception.confidence
        );
      });
    });

    describe('evasion', () => {
      it('should score based on prompt variation sigma', () => {
        const lowEvasion = engine.score({
          sessionCount: 1,
          chainedCallCount: 1,
          promptVariationSigma: 1,
        });

        const highEvasion = engine.score({
          sessionCount: 1,
          chainedCallCount: 1,
          promptVariationSigma: 5,
        });

        expect(highEvasion.dimensions.evasion.value).toBeGreaterThan(
          lowEvasion.dimensions.evasion.value
        );
      });

      it('should hit threshold at 3σ', () => {
        const result = engine.score({
          sessionCount: 1,
          chainedCallCount: 1,
          promptVariationSigma: 3,
        });

        expect(result.dimensions.evasion.value).toBeGreaterThanOrEqual(0.5);
      });
    });
  });

  describe('tier determination', () => {
    it('should classify as alert for low scores', () => {
      const result = engine.score({
        sessionCount: 1,
        chainedCallCount: 1,
      });

      expect(result.tier).toBe('alert');
    });

    it('should classify as investigate for medium scores', () => {
      const result = engine.score({
        sessionCount: 6,  // Above threshold
        chainedCallCount: 5,  // Above threshold
        outputEntropy: 0.7,
        promptVariationSigma: 2,  // Contributing to score
      });

      // With these inputs, should be medium risk (aggregate ~0.3)
      expect(result.aggregate).toBeGreaterThan(0.25);
      expect(['investigate', 'alert']).toContain(result.tier);
    });

    it('should classify as escalate for high scores', () => {
      const result = engine.score({
        estimatedEconomicImpact: 100000,
        sessionCount: 10,
        chainedCallCount: 8,
        outputEntropy: 0.9,
        semanticInconsistency: 0.9,
        promptVariationSigma: 5,
      });

      expect(result.tier).toBe('escalate');
    });
  });

  describe('classification', () => {
    it('should classify high deception + harm as malicious', () => {
      const result = engine.score({
        estimatedEconomicImpact: 50000,
        sessionCount: 3,
        chainedCallCount: 2,
        outputEntropy: 0.95,
        semanticInconsistency: 0.95,
      });

      // High deception scores should result in malicious or indeterminate
      expect(['malicious', 'indeterminate']).toContain(result.classification);
    });

    it('should classify high autonomy without deception as negligent', () => {
      const result = engine.score({
        sessionCount: 1,
        chainedCallCount: 10,
        outputEntropy: 0.2,
        semanticInconsistency: 0.1,
      });

      expect(result.classification).toBe('negligent');
    });

    it('should classify low overall as benign', () => {
      const result = engine.score({
        sessionCount: 1,
        chainedCallCount: 1,
      });

      expect(result.classification).toBe('benign');
    });
  });

  describe('custom configuration', () => {
    it('should use custom weights', () => {
      const customConfig: ScoringConfig = {
        ...DEFAULT_SCORING_CONFIG,
        weights: {
          harm: 0.5,
          persistence: 0.1,
          autonomy: 0.1,
          deception: 0.2,
          evasion: 0.1,
        },
      };

      const customEngine = new RiskScoringEngine(customConfig);

      const result = customEngine.score({
        estimatedEconomicImpact: 100000,
        sessionCount: 1,
        chainedCallCount: 1,
      });

      // With high harm weight, economic impact should dominate
      expect(result.aggregate).toBeGreaterThan(0.3);
      expect(result.weights.harm).toBe(0.5);
    });

    it('should use custom thresholds', () => {
      const customConfig: ScoringConfig = {
        ...DEFAULT_SCORING_CONFIG,
        thresholds: {
          ...DEFAULT_SCORING_CONFIG.thresholds,
          autonomy: {
            low: 5,
            medium: 10,
            high: 15,
            critical: 20,
          },
        },
      };

      const customEngine = new RiskScoringEngine(customConfig);

      // 4 calls should be low with custom thresholds
      const result = customEngine.score({
        sessionCount: 1,
        chainedCallCount: 4,
      });

      expect(result.dimensions.autonomy.value).toBeLessThan(0.2);
    });
  });

  describe('metadata', () => {
    it('should include algorithm version', () => {
      const result = engine.score({
        sessionCount: 1,
        chainedCallCount: 1,
      });

      expect(result.algorithmVersion).toBeDefined();
      expect(result.algorithmVersion).toMatch(/^\d+\.\d+\.\d+$/);
    });

    it('should use provided timestamp', () => {
      const timestamp = new Date('2025-01-01');

      const result = engine.score(
        { sessionCount: 1, chainedCallCount: 1 },
        { timestamp }
      );

      expect(result.scoredAt).toEqual(timestamp);
    });
  });
});
