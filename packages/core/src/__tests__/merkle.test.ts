/**
 * Merkle Tree Tests
 */

import { MerkleTree, AuditLog } from '../merkle.js';

describe('MerkleTree', () => {
  describe('basic operations', () => {
    it('should create an empty tree', () => {
      const tree = new MerkleTree();
      expect(tree.size).toBe(0);
      expect(tree.getRoot()).toBeDefined();
    });

    it('should append data and update root', () => {
      const tree = new MerkleTree();
      const hash1 = tree.append('data1');
      const root1 = tree.getRoot();

      expect(hash1).toBeDefined();
      expect(tree.size).toBe(1);

      tree.append('data2');
      const root2 = tree.getRoot();

      expect(tree.size).toBe(2);
      expect(root2).not.toBe(root1);
    });

    it('should produce consistent hashes for same data', () => {
      const tree1 = new MerkleTree();
      const tree2 = new MerkleTree();

      tree1.append('test');
      tree2.append('test');

      // Root hashes should match for identical data
      expect(tree1.getRoot()).toBe(tree2.getRoot());
    });
  });

  describe('Merkle proofs', () => {
    it('should generate valid proofs', () => {
      const tree = new MerkleTree();
      tree.append('data1');
      tree.append('data2');
      tree.append('data3');
      tree.append('data4');

      const proof = tree.generateProof(1);

      expect(proof.leafIndex).toBe(1);
      expect(proof.rootHash).toBe(tree.getRoot());
      expect(MerkleTree.verifyProof(proof)).toBe(true);
    });

    it('should reject invalid proofs', () => {
      const tree = new MerkleTree();
      tree.append('data1');
      tree.append('data2');

      const proof = tree.generateProof(0);

      // Tamper with the proof
      const tamperedProof = {
        ...proof,
        rootHash: 'invalid_root',
      };

      expect(MerkleTree.verifyProof(tamperedProof)).toBe(false);
    });

    it('should throw for invalid index', () => {
      const tree = new MerkleTree();
      tree.append('data1');

      expect(() => tree.generateProof(-1)).toThrow();
      expect(() => tree.generateProof(1)).toThrow();
    });

    it('should verify data exists in tree', () => {
      const tree = new MerkleTree();
      tree.append('secret data');

      const proof = tree.generateProof(0);

      expect(tree.verifyData('secret data', proof)).toBe(true);
      expect(tree.verifyData('different data', proof)).toBe(false);
    });
  });

  describe('serialization', () => {
    it('should serialize and deserialize', () => {
      const tree = new MerkleTree('test-tree-id');
      tree.append('data1');
      tree.append('data2');

      const json = tree.toJSON();
      const restored = MerkleTree.fromJSON(json);

      expect(restored.getId()).toBe('test-tree-id');
      expect(restored.size).toBe(2);
      expect(restored.getRoot()).toBe(tree.getRoot());
    });

    it('should preserve state through serialization', () => {
      const tree = new MerkleTree();
      tree.append('a');
      tree.append('b');
      tree.append('c');

      const state = tree.getState();
      const restored = MerkleTree.fromState(state);

      // Generate proofs on both and verify they match
      const originalProof = tree.generateProof(1);
      const restoredProof = restored.generateProof(1);

      expect(restoredProof.rootHash).toBe(originalProof.rootHash);
      expect(MerkleTree.verifyProof(restoredProof)).toBe(true);
    });
  });

  describe('edge cases', () => {
    it('should handle single element', () => {
      const tree = new MerkleTree();
      tree.append('single');

      const proof = tree.generateProof(0);
      expect(MerkleTree.verifyProof(proof)).toBe(true);
    });

    it('should handle odd number of elements', () => {
      const tree = new MerkleTree();
      tree.append('a');
      tree.append('b');
      tree.append('c');

      // All proofs should be valid
      for (let i = 0; i < 3; i++) {
        const proof = tree.generateProof(i);
        expect(MerkleTree.verifyProof(proof)).toBe(true);
      }
    });

    it('should handle large trees', () => {
      const tree = new MerkleTree();

      for (let i = 0; i < 100; i++) {
        tree.append(`data-${i}`);
      }

      expect(tree.size).toBe(100);

      // Verify random proofs
      const indices = [0, 25, 50, 75, 99];
      for (const idx of indices) {
        const proof = tree.generateProof(idx);
        expect(MerkleTree.verifyProof(proof)).toBe(true);
      }
    });
  });
});

describe('AuditLog', () => {
  describe('basic operations', () => {
    it('should create an empty log', () => {
      const log = new AuditLog();
      expect(log.size).toBe(0);
      expect(log.getEntries()).toHaveLength(0);
    });

    it('should add entries', () => {
      const log = new AuditLog();

      const entry = log.addEntry('test_action', 'actor_1', { key: 'value' });

      expect(entry.action).toBe('test_action');
      expect(entry.actor).toBe('actor_1');
      expect(entry.data).toEqual({ key: 'value' });
      expect(entry.previousHash).toBe('genesis');
      expect(log.size).toBe(1);
    });

    it('should chain entries with hashes', () => {
      const log = new AuditLog();

      const entry1 = log.addEntry('action1', 'actor1', {});
      const entry2 = log.addEntry('action2', 'actor2', {});

      expect(entry2.previousHash).toBe(entry1.entryHash);
    });
  });

  describe('integrity verification', () => {
    it('should verify intact log', () => {
      const log = new AuditLog();

      log.addEntry('action1', 'actor1', {});
      log.addEntry('action2', 'actor2', {});
      log.addEntry('action3', 'actor3', {});

      expect(log.verifyIntegrity()).toBe(true);
    });

    it('should generate valid Merkle proofs for entries', () => {
      const log = new AuditLog();

      const entry = log.addEntry('test', 'actor', { data: 'value' });
      log.addEntry('test2', 'actor', {});

      const proof = log.generateProof(entry.id);

      expect(MerkleTree.verifyProof(proof)).toBe(true);
    });
  });

  describe('queries', () => {
    it('should retrieve entry by ID', () => {
      const log = new AuditLog();

      const entry = log.addEntry('find_me', 'actor', { secret: true });
      log.addEntry('other', 'actor', {});

      const found = log.getEntry(entry.id);
      expect(found).toBeDefined();
      expect(found?.action).toBe('find_me');
    });

    it('should return undefined for unknown ID', () => {
      const log = new AuditLog();
      log.addEntry('test', 'actor', {});

      expect(log.getEntry('unknown-id')).toBeUndefined();
    });

    it('should return all entries in order', () => {
      const log = new AuditLog();

      log.addEntry('first', 'actor', {});
      log.addEntry('second', 'actor', {});
      log.addEntry('third', 'actor', {});

      const entries = log.getEntries();
      expect(entries).toHaveLength(3);
      expect(entries[0]?.action).toBe('first');
      expect(entries[1]?.action).toBe('second');
      expect(entries[2]?.action).toBe('third');
    });
  });
});
