/**
 * Signal Sharing Tests
 */

import { SignalSharer, DEFAULT_SHARING_CONFIG, type SharedSignal } from '../sharing';
import type { ThreatSignal, ThreatIndicator } from '@ai-authority/core';
import { sha256 } from '@ai-authority/core';

describe('SignalSharer', () => {
  let sharer: SignalSharer;
  const nodeId = 'test-node-001';

  beforeEach(() => {
    sharer = new SignalSharer(nodeId, DEFAULT_SHARING_CONFIG);
  });

  const createMockSignal = (overrides: Partial<ThreatSignal> = {}): ThreatSignal => ({
    id: 'signal-001',
    type: 'prompt_injection',
    severity: 'high',
    confidence: 0.85,
    sourceAgentId: 'scout-001',
    detectedAt: new Date(),
    indicators: [
      {
        type: 'behavior_pattern_hash',
        value: 'test-pattern-hash',
        confidence: 0.9,
        source: 'behavioral_analyzer',
      },
      {
        type: 'api_call_signature',
        value: 'api-signature-123',
        confidence: 0.85,
        source: 'api_monitor',
      },
    ],
    instanceCount: 5,
    riskTier: 2,
    ...overrides,
  });

  describe('Signal Preparation', () => {
    it('should prepare signal for sharing', () => {
      const signal = createMockSignal();
      const shared = sharer.prepareForSharing(signal, 'us-east');

      expect(shared).not.toBeNull();
      expect(shared!.type).toBe('prompt_injection');
      expect(shared!.severity).toBe('high');
      expect(shared!.riskTier).toBe(2);
      expect(shared!.sharedBy).toBe(nodeId);
      expect(shared!.sharedAt).toBeInstanceOf(Date);
    });

    it('should double-hash signal ID', () => {
      const signal = createMockSignal();
      const shared = sharer.prepareForSharing(signal);

      const expectedHash = sha256(sha256(signal.id));
      expect(shared!.signalIdHash).toBe(expectedHash);
    });

    it('should reject signals below confidence threshold', () => {
      const signal = createMockSignal({ confidence: 0.3 });
      const shared = sharer.prepareForSharing(signal);

      expect(shared).toBeNull();
    });

    it('should include region when configured', () => {
      const signal = createMockSignal();
      const shared = sharer.prepareForSharing(signal, 'eu-west');

      expect(shared!.region).toBe('eu-west');
    });

    it('should not include region when not provided', () => {
      const signal = createMockSignal();
      const shared = sharer.prepareForSharing(signal);

      expect(shared!.region).toBeUndefined();
    });

    it('should apply differential privacy to counts', () => {
      const signal = createMockSignal({ instanceCount: 100 });
      
      // Run multiple times to check for variation
      const counts = new Set<number>();
      for (let i = 0; i < 10; i++) {
        const shared = sharer.prepareForSharing(signal);
        counts.add(shared!.instanceCount);
      }

      // Should have some variation due to DP
      expect(counts.size).toBeGreaterThanOrEqual(1);
    });

    it('should ensure minimum instance count of 1', () => {
      const signal = createMockSignal({ instanceCount: 1 });
      const shared = sharer.prepareForSharing(signal);

      expect(shared!.instanceCount).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Indicator Anonymization', () => {
    it('should anonymize shareable indicators', () => {
      const signal = createMockSignal();
      const shared = sharer.prepareForSharing(signal);

      expect(shared!.anonymizedIndicators.length).toBeGreaterThan(0);
      
      for (const indicator of shared!.anonymizedIndicators) {
        expect(indicator.type).toBeTruthy();
        expect(indicator.valueHash).toBeTruthy();
        expect(indicator.confidence).toBeGreaterThanOrEqual(0);
        expect(indicator.confidence).toBeLessThanOrEqual(1);
      }
    });

    it('should double-hash indicator values', () => {
      const signal = createMockSignal();
      const shared = sharer.prepareForSharing(signal);

      const originalIndicator = signal.indicators[0];
      const expectedHash = sha256(sha256(originalIndicator.value));
      
      const matchingAnon = shared!.anonymizedIndicators.find(
        (i) => i.type === originalIndicator.type
      );
      
      expect(matchingAnon?.valueHash).toBe(expectedHash);
    });

    it('should filter out non-shareable indicator types', () => {
      const signal = createMockSignal({
        indicators: [
          {
            type: 'behavior_pattern_hash',
            value: 'test',
            confidence: 0.9,
            source: 'test',
          },
          // This type is not in shareableIndicatorTypes
          {
            type: 'raw_input' as ThreatIndicator['type'],
            value: 'sensitive-data',
            confidence: 0.95,
            source: 'test',
          },
        ],
      });
      
      const shared = sharer.prepareForSharing(signal);
      
      // Only the shareable type should be included
      expect(shared!.anonymizedIndicators.every(
        (i) => DEFAULT_SHARING_CONFIG.shareableIndicatorTypes.includes(i.type)
      )).toBe(true);
    });
  });

  describe('Signal Matching', () => {
    it('should detect matching indicators', () => {
      const localIndicators: ThreatIndicator[] = [
        {
          type: 'behavior_pattern_hash',
          value: 'test-pattern-hash',
          confidence: 0.9,
          source: 'local',
        },
      ];

      const signal = createMockSignal();
      const shared = sharer.prepareForSharing(signal)!;

      const result = sharer.checkMatch(shared, localIndicators);

      expect(result.matches).toBe(true);
      expect(result.matchingTypes).toContain('behavior_pattern_hash');
      expect(result.matchConfidence).toBeGreaterThan(0);
    });

    it('should not match different indicators', () => {
      const localIndicators: ThreatIndicator[] = [
        {
          type: 'behavior_pattern_hash',
          value: 'different-hash',
          confidence: 0.9,
          source: 'local',
        },
      ];

      const signal = createMockSignal();
      const shared = sharer.prepareForSharing(signal)!;

      const result = sharer.checkMatch(shared, localIndicators);

      expect(result.matches).toBe(false);
      expect(result.matchingTypes).toHaveLength(0);
    });

    it('should calculate match confidence correctly', () => {
      const localIndicators: ThreatIndicator[] = [
        {
          type: 'behavior_pattern_hash',
          value: 'test-pattern-hash',
          confidence: 0.8,
          source: 'local',
        },
        {
          type: 'api_call_signature',
          value: 'api-signature-123',
          confidence: 0.75,
          source: 'local',
        },
      ];

      const signal = createMockSignal();
      const shared = sharer.prepareForSharing(signal)!;

      const result = sharer.checkMatch(shared, localIndicators);

      expect(result.matchingTypes.length).toBe(2);
      expect(result.matchConfidence).toBeGreaterThan(0);
      expect(result.matchConfidence).toBeLessThanOrEqual(1);
    });
  });

  describe('Signal Aggregation', () => {
    it('should aggregate multiple signals', () => {
      const signals: SharedSignal[] = [
        {
          signalIdHash: 'hash1',
          type: 'prompt_injection',
          severity: 'high',
          indicatorCount: 2,
          anonymizedIndicators: [],
          instanceCount: 5,
          region: 'us-east',
          riskTier: 2,
          confidence: 0.9,
          sharedAt: new Date(),
          sharedBy: 'node-1',
        },
        {
          signalIdHash: 'hash2',
          type: 'data_exfiltration',
          severity: 'critical',
          indicatorCount: 3,
          anonymizedIndicators: [],
          instanceCount: 10,
          region: 'eu-west',
          riskTier: 3,
          confidence: 0.85,
          sharedAt: new Date(),
          sharedBy: 'node-2',
        },
        {
          signalIdHash: 'hash3',
          type: 'prompt_injection',
          severity: 'medium',
          indicatorCount: 1,
          anonymizedIndicators: [],
          instanceCount: 2,
          region: 'us-east',
          riskTier: 1,
          confidence: 0.7,
          sharedAt: new Date(),
          sharedBy: 'node-3',
        },
      ];

      const result = sharer.aggregateSignals(signals);

      expect(result.totalSignals).toBe(3);
      expect(result.byType.get('prompt_injection')).toBe(2);
      expect(result.byType.get('data_exfiltration')).toBe(1);
      expect(result.bySeverity.get('high')).toBe(1);
      expect(result.bySeverity.get('critical')).toBe(1);
      expect(result.bySeverity.get('medium')).toBe(1);
      expect(result.byRegion.get('us-east')).toBe(2);
      expect(result.byRegion.get('eu-west')).toBe(1);
      expect(result.avgConfidence).toBeCloseTo((0.9 + 0.85 + 0.7) / 3, 2);
    });

    it('should handle empty signal list', () => {
      const result = sharer.aggregateSignals([]);

      expect(result.totalSignals).toBe(0);
      expect(result.avgConfidence).toBe(0);
    });
  });

  describe('Configuration', () => {
    it('should return configuration', () => {
      const config = sharer.getConfig();

      expect(config.epsilon).toBe(DEFAULT_SHARING_CONFIG.epsilon);
      expect(config.minConfidenceToShare).toBe(DEFAULT_SHARING_CONFIG.minConfidenceToShare);
      expect(config.shareRegion).toBe(DEFAULT_SHARING_CONFIG.shareRegion);
    });

    it('should respect custom configuration', () => {
      const customConfig = {
        ...DEFAULT_SHARING_CONFIG,
        minConfidenceToShare: 0.9,
        shareRegion: false,
      };
      
      const customSharer = new SignalSharer(nodeId, customConfig);
      const config = customSharer.getConfig();

      expect(config.minConfidenceToShare).toBe(0.9);
      expect(config.shareRegion).toBe(false);
    });
  });
});
