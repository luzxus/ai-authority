/**
 * FingerprintLibrary Tests
 */

import { FingerprintLibrary, createFingerprintLibrary } from '../fingerprints';
import type { ModelFingerprint, ProbeResponse } from '../types';

describe('FingerprintLibrary', () => {
  let library: FingerprintLibrary;

  beforeEach(() => {
    library = new FingerprintLibrary();
  });

  /** Create a test fingerprint */
  function createTestFingerprint(hash: string, responses: ProbeResponse[] = []): ModelFingerprint {
    return {
      hash,
      activationPattern: [0.1, 0.2, 0.3, 0.4],
      probeResponses: responses.length > 0 ? responses : [
        {
          probeId: 'probe-1',
          input: 'test input',
          outputHash: 'output-hash-1',
          characteristics: { entropy: 0.5, coherence: 0.8 },
        },
      ],
      architecture: 'transformer',
      estimatedParameters: 1000000,
      knownAliases: ['test-model'],
    };
  }

  describe('add', () => {
    it('should add a fingerprint and return ID', () => {
      const fingerprint = createTestFingerprint('hash-001');
      const id = library.add(fingerprint);

      expect(typeof id).toBe('string');
      expect(id.length).toBeGreaterThan(0);
    });

    it('should store the fingerprint correctly', () => {
      const fingerprint = createTestFingerprint('hash-002');
      const id = library.add(fingerprint);

      const entry = library.get(id);
      expect(entry?.fingerprint.hash).toBe('hash-002');
      expect(entry?.fingerprint.architecture).toBe('transformer');
    });

    it('should accept custom domain', () => {
      const fingerprint = createTestFingerprint('hash-003');
      const id = library.add(fingerprint, 'obfuscation');

      const entry = library.get(id);
      expect(entry?.domain).toBe('obfuscation');
    });

    it('should default to model_fingerprints domain', () => {
      const fingerprint = createTestFingerprint('hash-004');
      const id = library.add(fingerprint);

      const entry = library.get(id);
      expect(entry?.domain).toBe('model_fingerprints');
    });
  });

  describe('get', () => {
    it('should retrieve fingerprint by ID', () => {
      const fingerprint = createTestFingerprint('hash-get-1');
      const id = library.add(fingerprint);

      const entry = library.get(id);

      expect(entry).toBeDefined();
      expect(entry?.fingerprint).toEqual(fingerprint);
    });

    it('should return undefined for unknown ID', () => {
      const entry = library.get('unknown-id');
      expect(entry).toBeUndefined();
    });
  });

  describe('getByHash', () => {
    it('should retrieve fingerprint by hash', () => {
      const fingerprint = createTestFingerprint('unique-hash-123');
      library.add(fingerprint);

      const entry = library.getByHash('unique-hash-123');

      expect(entry).toBeDefined();
      expect(entry?.fingerprint.hash).toBe('unique-hash-123');
    });

    it('should return undefined for unknown hash', () => {
      const entry = library.getByHash('non-existent-hash');
      expect(entry).toBeUndefined();
    });
  });

  describe('remove', () => {
    it('should remove fingerprint and return true', () => {
      const fingerprint = createTestFingerprint('hash-remove');
      const id = library.add(fingerprint);

      const result = library.remove(id);

      expect(result).toBe(true);
      expect(library.get(id)).toBeUndefined();
    });

    it('should remove from hash index', () => {
      const fingerprint = createTestFingerprint('hash-remove-index');
      const id = library.add(fingerprint);

      library.remove(id);

      expect(library.getByHash('hash-remove-index')).toBeUndefined();
    });

    it('should return false for unknown ID', () => {
      const result = library.remove('unknown-id');
      expect(result).toBe(false);
    });
  });

  describe('query', () => {
    beforeEach(() => {
      library.add(createTestFingerprint('hash-q1'));
      library.add(createTestFingerprint('hash-q2'));
      library.add(createTestFingerprint('hash-q3'));
    });

    it('should return all fingerprints', () => {
      const result = library.query({});

      expect(result.entries.length).toBe(3);
    });

    it('should respect limit', () => {
      const result = library.query({ limit: 2 });

      expect(result.entries.length).toBe(2);
    });

    it('should respect offset', () => {
      const result = library.query({ offset: 1, limit: 10 });

      expect(result.entries.length).toBe(2);
    });

    it('should filter by minimum confidence', () => {
      // Default confidence is 1.0
      const result = library.query({ minConfidence: 0.9 });

      expect(result.entries.length).toBe(3);
      expect(result.entries.every((e) => e.confidence >= 0.9)).toBe(true);
    });

    it('should include total count and query time', () => {
      const result = library.query({});

      expect(result.total).toBe(3);
      expect(result.queryTime).toBeGreaterThanOrEqual(0);
    });
  });

  describe('match', () => {
    beforeEach(() => {
      library.add(createTestFingerprint('exact-match-hash', [
        { probeId: 'p1', input: 'test', outputHash: 'out1', characteristics: { a: 1 } },
      ]));
      library.add(createTestFingerprint('different-hash', [
        { probeId: 'p1', input: 'test', outputHash: 'out2', characteristics: { a: 0.5 } },
      ]));
    });

    it('should find exact hash match', () => {
      const matches = library.match({ hash: 'exact-match-hash' });

      expect(matches.length).toBe(1);
      expect(matches[0]!.similarity).toBe(1.0);
      expect(matches[0]!.entry.fingerprint.hash).toBe('exact-match-hash');
    });

    it('should return empty array when no matches', () => {
      const emptyLib = new FingerprintLibrary();
      const matches = emptyLib.match({ hash: 'non-existent' });

      expect(matches).toEqual([]);
    });

    it('should sort matches by similarity descending', () => {
      library.add(createTestFingerprint('hash-a', [
        { probeId: 'p1', input: 'test', outputHash: 'out1', characteristics: { a: 0.9 } },
      ]));

      const matches = library.match({
        probeResponses: [
          { probeId: 'p1', input: 'test', outputHash: 'out1', characteristics: { a: 1 } },
        ],
      });

      for (let i = 1; i < matches.length; i++) {
        expect(matches[i - 1]!.similarity).toBeGreaterThanOrEqual(matches[i]!.similarity);
      }
    });

    it('should use partial fingerprint for similarity matching', () => {
      const matches = library.match({
        activationPattern: [0.1, 0.2, 0.3, 0.4],
      });

      // Should find matches based on activation pattern similarity
      expect(matches.length).toBeGreaterThan(0);
    });
  });

  describe('matchProbeResponses', () => {
    beforeEach(() => {
      library.add(createTestFingerprint('hash-probe-1', [
        { probeId: 'probe-a', input: 'input-a', outputHash: 'hash-a', characteristics: { x: 1 } },
        { probeId: 'probe-b', input: 'input-b', outputHash: 'hash-b', characteristics: { x: 2 } },
      ]));
      library.add(createTestFingerprint('hash-probe-2', [
        { probeId: 'probe-a', input: 'input-a', outputHash: 'hash-a', characteristics: { x: 1 } },
        { probeId: 'probe-c', input: 'input-c', outputHash: 'hash-c', characteristics: { x: 3 } },
      ]));
    });

    it('should match by probe responses', () => {
      const matches = library.matchProbeResponses([
        { probeId: 'probe-a', input: 'input-a', outputHash: 'hash-a', characteristics: { x: 1 } },
        { probeId: 'probe-b', input: 'input-b', outputHash: 'hash-b', characteristics: { x: 2 } },
      ]);

      expect(matches.length).toBeGreaterThan(0);
      // First match should have higher similarity (both probes match)
      expect(matches[0]!.entry.fingerprint.hash).toBe('hash-probe-1');
    });

    it('should calculate confidence based on similarity', () => {
      // Need at least 2 matching probes to exceed 0.5 threshold
      // hash-probe-1 has probes a and b, so providing both should give similarity = 1.0
      const matches = library.matchProbeResponses([
        { probeId: 'probe-a', input: 'input-a', outputHash: 'hash-a', characteristics: { x: 1 } },
        { probeId: 'probe-b', input: 'input-b', outputHash: 'hash-b', characteristics: { x: 2 } },
      ]);

      expect(matches.length).toBeGreaterThan(0);
      for (const match of matches) {
        expect(match.confidence).toBeLessThanOrEqual(match.similarity * match.entry.confidence);
      }
    });
  });

  describe('createFingerprint', () => {
    it('should create fingerprint from probe responses', () => {
      const responses: ProbeResponse[] = [
        { probeId: 'p1', input: 'hello', outputHash: 'abc123', characteristics: { entropy: 0.7 } },
        { probeId: 'p2', input: 'world', outputHash: 'def456', characteristics: { entropy: 0.8 } },
      ];

      const fingerprint = library.createFingerprint(responses);

      expect(fingerprint.hash).toBeDefined();
      expect(fingerprint.hash.length).toBeGreaterThan(0);
      expect(fingerprint.probeResponses).toEqual(responses);
      expect(fingerprint.activationPattern.length).toBe(128);
    });

    it('should include optional metadata', () => {
      const responses: ProbeResponse[] = [
        { probeId: 'p1', input: 'test', outputHash: 'xyz', characteristics: {} },
      ];

      const fingerprint = library.createFingerprint(responses, {
        architecture: 'gpt-4',
        estimatedParameters: 175000000000,
        aliases: ['gpt-4-turbo', 'gpt-4-0125'],
      });

      expect(fingerprint.architecture).toBe('gpt-4');
      expect(fingerprint.estimatedParameters).toBe(175000000000);
      expect(fingerprint.knownAliases).toEqual(['gpt-4-turbo', 'gpt-4-0125']);
    });

    it('should generate deterministic hash for same responses', () => {
      const responses: ProbeResponse[] = [
        { probeId: 'p1', input: 'test', outputHash: 'hash1', characteristics: { a: 1 } },
      ];

      const fp1 = library.createFingerprint(responses);
      const fp2 = library.createFingerprint(responses);

      expect(fp1.hash).toBe(fp2.hash);
    });
  });

  describe('getStats', () => {
    it('should return library statistics', () => {
      library.add(createTestFingerprint('hash-stat-1'));
      
      const fp2 = createTestFingerprint('hash-stat-2');
      fp2.architecture = 'lstm';
      library.add(fp2);
      
      library.add(createTestFingerprint('hash-stat-3'));

      const stats = library.getStats();

      expect(stats.totalFingerprints).toBe(3);
      expect(stats.uniqueArchitectures.size).toBe(2);
      expect(stats.uniqueArchitectures.has('transformer')).toBe(true);
      expect(stats.uniqueArchitectures.has('lstm')).toBe(true);
    });

    it('should return empty stats for empty library', () => {
      const stats = library.getStats();

      expect(stats.totalFingerprints).toBe(0);
      expect(stats.uniqueArchitectures.size).toBe(0);
    });
  });

  describe('createFingerprintLibrary helper', () => {
    it('should create a new library instance', () => {
      const lib = createFingerprintLibrary();

      expect(lib).toBeInstanceOf(FingerprintLibrary);
      expect(lib.getStats().totalFingerprints).toBe(0);
    });
  });
});
