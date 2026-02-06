/**
 * VectorStore Tests
 */

import { VectorStore, createVectorStore } from '../vectors';

describe('VectorStore', () => {
  let store: VectorStore;
  const dimensions = 4; // Small dimensions for testing

  beforeEach(() => {
    store = new VectorStore({ dimensions, metric: 'cosine', maxEntries: 100 });
  });

  describe('add', () => {
    it('should add a vector and return ID', () => {
      const vector = [1, 0, 0, 0];
      const id = store.add(vector, 'malicious_patterns');

      expect(typeof id).toBe('string');
      expect(id.length).toBeGreaterThan(0);
    });

    it('should reject vector with wrong dimensions', () => {
      const wrongVector = [1, 0]; // Only 2 dimensions

      expect(() => store.add(wrongVector, 'malicious_patterns')).toThrow(
        'Vector dimensions mismatch'
      );
    });

    it('should store metadata', () => {
      const vector = [1, 0, 0, 0];
      const id = store.add(vector, 'malicious_patterns', { label: 'test-pattern' });

      const entry = store.get(id);
      expect(entry?.metadata).toEqual({ label: 'test-pattern' });
    });

    it('should respect maxEntries limit', () => {
      const smallStore = new VectorStore({ dimensions, maxEntries: 2 });

      smallStore.add([1, 0, 0, 0], 'malicious_patterns');
      smallStore.add([0, 1, 0, 0], 'malicious_patterns');

      expect(() => smallStore.add([0, 0, 1, 0], 'malicious_patterns')).toThrow(
        'Vector store full'
      );
    });

    it('should set confidence to 1.0 by default', () => {
      const id = store.add([1, 0, 0, 0], 'malicious_patterns');
      const entry = store.get(id);

      expect(entry?.confidence).toBe(1.0);
    });
  });

  describe('get', () => {
    it('should retrieve entry by ID', () => {
      const vector = [0.5, 0.5, 0, 0];
      const id = store.add(vector, 'api_misuse');

      const entry = store.get(id);

      expect(entry).toBeDefined();
      expect(entry?.vector).toEqual(vector);
      expect(entry?.domain).toBe('api_misuse');
    });

    it('should return undefined for unknown ID', () => {
      const entry = store.get('unknown-id');
      expect(entry).toBeUndefined();
    });
  });

  describe('remove', () => {
    it('should remove entry and return true', () => {
      const id = store.add([1, 0, 0, 0], 'malicious_patterns');

      const result = store.remove(id);

      expect(result).toBe(true);
      expect(store.get(id)).toBeUndefined();
    });

    it('should return false for unknown ID', () => {
      const result = store.remove('unknown-id');
      expect(result).toBe(false);
    });

    it('should update domain index after removal', () => {
      const id = store.add([1, 0, 0, 0], 'malicious_patterns');
      store.remove(id);

      const entries = store.getByDomain('malicious_patterns');
      expect(entries.length).toBe(0);
    });
  });

  describe('query', () => {
    beforeEach(() => {
      // Add some test vectors
      store.add([1, 0, 0, 0], 'malicious_patterns', { name: 'pattern-1' });
      store.add([0.9, 0.1, 0, 0], 'malicious_patterns', { name: 'pattern-2' });
      store.add([0, 1, 0, 0], 'api_misuse', { name: 'api-pattern' });
      store.add([0, 0, 1, 0], 'obfuscation', { name: 'obfuscation-1' });
    });

    it('should find similar vectors', () => {
      const queryVector = [0.95, 0.05, 0, 0];
      const results = store.query({ vector: queryVector, threshold: 0.9 });

      expect(results.matches.length).toBeGreaterThan(0);
      expect(results.matches[0]!.score).toBeGreaterThan(0.9);
    });

    it('should filter by domain', () => {
      const queryVector = [1, 0, 0, 0];
      const results = store.query({
        vector: queryVector,
        threshold: 0,
        domains: ['api_misuse'],
      });

      expect(results.matches.every((m) => m.entry.domain === 'api_misuse')).toBe(true);
    });

    it('should respect limit', () => {
      const queryVector = [1, 0, 0, 0];
      const results = store.query({
        vector: queryVector,
        threshold: 0,
        limit: 2,
      });

      expect(results.matches.length).toBeLessThanOrEqual(2);
    });

    it('should reject query vector with wrong dimensions', () => {
      expect(() => store.query({ vector: [1, 0], threshold: 0.5 })).toThrow(
        'Query vector dimensions mismatch'
      );
    });

    it('should filter by minimum confidence', () => {
      // The default entries have confidence 1.0
      const queryVector = [1, 0, 0, 0];
      const results = store.query({
        vector: queryVector,
        threshold: 0,
        minConfidence: 0.5,
      });

      expect(results.matches.every((m) => m.entry.confidence >= 0.5)).toBe(true);
    });

    it('should return query time', () => {
      const queryVector = [1, 0, 0, 0];
      const results = store.query({ vector: queryVector, threshold: 0.5 });

      expect(results.queryTime).toBeGreaterThanOrEqual(0);
    });

    it('should sort by score descending', () => {
      const queryVector = [1, 0, 0, 0];
      const results = store.query({ vector: queryVector, threshold: 0 });

      for (let i = 1; i < results.matches.length; i++) {
        const prev = results.matches[i - 1];
        const curr = results.matches[i];
        expect(prev && curr && prev.score >= curr.score).toBe(true);
      }
    });
  });

  describe('similarity metrics', () => {
    it('should support cosine similarity', () => {
      const cosineStore = new VectorStore({ dimensions, metric: 'cosine' });
      cosineStore.add([1, 0, 0, 0], 'malicious_patterns');

      const results = cosineStore.query({
        vector: [1, 0, 0, 0],
        threshold: 0.99,
        metric: 'cosine',
      });

      expect(results.matches.length).toBe(1);
      expect(results.matches[0]?.score).toBeCloseTo(1.0, 5);
    });

    it('should support euclidean distance', () => {
      const euclidStore = new VectorStore({ dimensions, metric: 'euclidean' });
      euclidStore.add([1, 0, 0, 0], 'malicious_patterns');

      const results = euclidStore.query({
        vector: [1, 0, 0, 0],
        threshold: 0.99,
        metric: 'euclidean',
      });

      expect(results.matches.length).toBe(1);
      // Euclidean: 1 / (1 + distance) = 1 for identical vectors
      expect(results.matches[0]?.score).toBeCloseTo(1.0, 5);
    });

    it('should support dot product', () => {
      const dotStore = new VectorStore({ dimensions, metric: 'dot' });
      dotStore.add([1, 0, 0, 0], 'malicious_patterns');

      const results = dotStore.query({
        vector: [1, 0, 0, 0],
        threshold: 0.99,
        metric: 'dot',
      });

      expect(results.matches.length).toBe(1);
      expect(results.matches[0]?.score).toBeCloseTo(1.0, 5);
    });
  });

  describe('getByDomain', () => {
    it('should return all entries in a domain', () => {
      store.add([1, 0, 0, 0], 'malicious_patterns');
      store.add([0.5, 0.5, 0, 0], 'malicious_patterns');
      store.add([0, 1, 0, 0], 'api_misuse');

      const patterns = store.getByDomain('malicious_patterns');

      expect(patterns.length).toBe(2);
      expect(patterns.every((e) => e.domain === 'malicious_patterns')).toBe(true);
    });

    it('should return empty array for unknown domain', () => {
      const entries = store.getByDomain('evasion');
      expect(entries).toEqual([]);
    });
  });

  describe('getStats', () => {
    it('should return store statistics', () => {
      store.add([1, 0, 0, 0], 'malicious_patterns');
      store.add([0, 1, 0, 0], 'malicious_patterns');
      store.add([0, 0, 1, 0], 'api_misuse');

      const stats = store.getStats();

      expect(stats.totalEntries).toBe(3);
      expect(stats.byDomain['malicious_patterns']).toBe(2);
      expect(stats.byDomain['api_misuse']).toBe(1);
    });
  });

  describe('createVectorStore helper', () => {
    it('should create store with default config', () => {
      const defaultStore = createVectorStore();

      // Should accept 1536-dimensional vectors (OpenAI ada-002)
      const vector = new Array(1536).fill(0.1);
      const id = defaultStore.add(vector, 'malicious_patterns');

      expect(id).toBeDefined();
    });

    it('should accept partial config', () => {
      const customStore = createVectorStore({ dimensions: 8 });

      const vector = new Array(8).fill(0.1);
      const id = customStore.add(vector, 'api_misuse');

      expect(id).toBeDefined();
    });
  });
});
