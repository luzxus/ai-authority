/**
 * Merkle Tree Implementation
 *
 * Provides an append-only Merkle tree for immutable audit logs.
 * All case histories and votes are stored in this structure for
 * cryptographic verification and tamper detection.
 */

import { createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';

// ============================================================================
// Types
// ============================================================================

export interface MerkleNode {
  /** Hash of this node */
  readonly hash: string;

  /** Left child hash (for internal nodes) */
  readonly left?: string;

  /** Right child hash (for internal nodes) */
  readonly right?: string;

  /** Data hash (for leaf nodes) */
  readonly dataHash?: string;

  /** Index in the tree */
  readonly index: number;

  /** Level in the tree (0 = leaves) */
  readonly level: number;
}

export interface MerkleProof {
  /** Leaf data hash being proven */
  readonly leafHash: string;

  /** Index of the leaf */
  readonly leafIndex: number;

  /** Proof path (sibling hashes from leaf to root) */
  readonly path: ProofStep[];

  /** Root hash at time of proof generation */
  readonly rootHash: string;

  /** Tree size at time of proof */
  readonly treeSize: number;
}

export interface ProofStep {
  /** Sibling hash */
  readonly hash: string;

  /** Position of sibling ('left' or 'right') */
  readonly position: 'left' | 'right';

  /** Level in the tree */
  readonly level: number;
}

export interface MerkleTreeState {
  /** Current root hash */
  readonly rootHash: string;

  /** Number of leaves */
  readonly size: number;

  /** All leaf hashes in order */
  readonly leaves: string[];

  /** Tree creation timestamp */
  readonly createdAt: Date;

  /** Last modification timestamp */
  readonly lastModifiedAt: Date;

  /** Tree ID */
  readonly id: string;
}

// ============================================================================
// Merkle Tree Implementation
// ============================================================================

/**
 * Append-only Merkle tree for audit logs.
 *
 * Properties:
 * - Append-only: New entries can only be added, never modified or removed
 * - Verifiable: Any entry can be proven to exist via Merkle proof
 * - Tamper-evident: Any modification invalidates the root hash
 */
export class MerkleTree {
  private readonly id: string;
  private readonly leaves: string[] = [];
  private readonly createdAt: Date;
  private lastModifiedAt: Date;

  constructor(id?: string) {
    this.id = id ?? uuidv4();
    this.createdAt = new Date();
    this.lastModifiedAt = this.createdAt;
  }

  /**
   * Hash function using SHA-256.
   */
  private static hash(data: string): string {
    return createHash('sha256').update(data).digest('hex');
  }

  /**
   * Combine two hashes into a parent hash.
   */
  private static combineHashes(left: string, right: string): string {
    return MerkleTree.hash(left + right);
  }

  /**
   * Append new data to the tree.
   * Returns the leaf hash.
   */
  append(data: string): string {
    const leafHash = MerkleTree.hash(data);
    this.leaves.push(leafHash);
    this.lastModifiedAt = new Date();
    return leafHash;
  }

  /**
   * Append pre-hashed data to the tree.
   */
  appendHash(hash: string): void {
    this.leaves.push(hash);
    this.lastModifiedAt = new Date();
  }

  /**
   * Get the current root hash.
   */
  getRoot(): string {
    if (this.leaves.length === 0) {
      return MerkleTree.hash('empty');
    }

    return this.computeRoot(this.leaves);
  }

  /**
   * Compute root from a list of leaf hashes.
   */
  private computeRoot(hashes: string[]): string {
    if (hashes.length === 0) {
      return MerkleTree.hash('empty');
    }

    if (hashes.length === 1) {
      return hashes[0]!;
    }

    const nextLevel: string[] = [];

    for (let i = 0; i < hashes.length; i += 2) {
      const left = hashes[i]!;
      const right = hashes[i + 1] ?? left; // Duplicate last if odd
      nextLevel.push(MerkleTree.combineHashes(left, right));
    }

    return this.computeRoot(nextLevel);
  }

  /**
   * Generate a Merkle proof for a leaf at the given index.
   */
  generateProof(index: number): MerkleProof {
    if (index < 0 || index >= this.leaves.length) {
      throw new Error(`Invalid leaf index: ${index}`);
    }

    const leafHash = this.leaves[index]!;
    const path: ProofStep[] = [];

    let currentLevel = [...this.leaves];
    let currentIndex = index;
    let level = 0;

    while (currentLevel.length > 1) {
      const isRightNode = currentIndex % 2 === 1;
      const siblingIndex = isRightNode ? currentIndex - 1 : currentIndex + 1;

      // Handle odd number of nodes (last node has no sibling)
      const siblingHash =
        siblingIndex < currentLevel.length
          ? currentLevel[siblingIndex]!
          : currentLevel[currentIndex]!;

      path.push({
        hash: siblingHash,
        position: isRightNode ? 'left' : 'right',
        level,
      });

      // Move to next level
      const nextLevel: string[] = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i]!;
        const right = currentLevel[i + 1] ?? left;
        nextLevel.push(MerkleTree.combineHashes(left, right));
      }

      currentLevel = nextLevel;
      currentIndex = Math.floor(currentIndex / 2);
      level++;
    }

    return {
      leafHash,
      leafIndex: index,
      path,
      rootHash: this.getRoot(),
      treeSize: this.leaves.length,
    };
  }

  /**
   * Verify a Merkle proof.
   */
  static verifyProof(proof: MerkleProof): boolean {
    let currentHash = proof.leafHash;

    for (const step of proof.path) {
      if (step.position === 'left') {
        currentHash = MerkleTree.combineHashes(step.hash, currentHash);
      } else {
        currentHash = MerkleTree.combineHashes(currentHash, step.hash);
      }
    }

    return currentHash === proof.rootHash;
  }

  /**
   * Verify that data exists in the tree.
   */
  verifyData(data: string, proof: MerkleProof): boolean {
    const dataHash = MerkleTree.hash(data);
    if (dataHash !== proof.leafHash) {
      return false;
    }
    return MerkleTree.verifyProof(proof);
  }

  /**
   * Get the current state of the tree.
   */
  getState(): MerkleTreeState {
    return {
      rootHash: this.getRoot(),
      size: this.leaves.length,
      leaves: [...this.leaves],
      createdAt: this.createdAt,
      lastModifiedAt: this.lastModifiedAt,
      id: this.id,
    };
  }

  /**
   * Get the number of leaves.
   */
  get size(): number {
    return this.leaves.length;
  }

  /**
   * Get the tree ID.
   */
  getId(): string {
    return this.id;
  }

  /**
   * Restore a tree from state.
   */
  static fromState(state: MerkleTreeState): MerkleTree {
    const tree = new MerkleTree(state.id);
    for (const leaf of state.leaves) {
      tree.appendHash(leaf);
    }
    return tree;
  }

  /**
   * Export tree for persistence.
   */
  toJSON(): string {
    return JSON.stringify(this.getState());
  }

  /**
   * Import tree from JSON.
   */
  static fromJSON(json: string): MerkleTree {
    const state = JSON.parse(json) as MerkleTreeState;
    return MerkleTree.fromState(state);
  }
}

// ============================================================================
// Audit Log Implementation
// ============================================================================

export interface AuditLogEntry {
  /** Unique entry ID */
  readonly id: string;

  /** Timestamp */
  readonly timestamp: Date;

  /** Action type */
  readonly action: string;

  /** Actor performing the action */
  readonly actor: string;

  /** Target of the action */
  readonly target?: string;

  /** Additional data */
  readonly data: Record<string, unknown>;

  /** Hash of this entry */
  readonly entryHash: string;

  /** Hash of previous entry */
  readonly previousHash: string;
}

/**
 * Immutable audit log backed by a Merkle tree.
 */
export class AuditLog {
  private readonly tree: MerkleTree;
  private readonly entries: AuditLogEntry[] = [];
  private previousHash = 'genesis';

  constructor(treeId?: string) {
    this.tree = new MerkleTree(treeId);
  }

  /**
   * Add an entry to the audit log.
   */
  addEntry(
    action: string,
    actor: string,
    data: Record<string, unknown>,
    target?: string
  ): AuditLogEntry {
    const id = uuidv4();
    const timestamp = new Date();

    // Create entry content for hashing
    const content = JSON.stringify({
      id,
      timestamp: timestamp.toISOString(),
      action,
      actor,
      target,
      data,
      previousHash: this.previousHash,
    });

    const entryHash = this.tree.append(content);

    const entry: AuditLogEntry = {
      id,
      timestamp,
      action,
      actor,
      ...(target !== undefined && { target }),
      data,
      entryHash,
      previousHash: this.previousHash,
    };

    this.entries.push(entry);
    this.previousHash = entryHash;

    return entry;
  }

  /**
   * Get all entries.
   */
  getEntries(): readonly AuditLogEntry[] {
    return this.entries;
  }

  /**
   * Get entry by ID.
   */
  getEntry(id: string): AuditLogEntry | undefined {
    return this.entries.find((e) => e.id === id);
  }

  /**
   * Generate proof for an entry.
   */
  generateProof(entryId: string): MerkleProof {
    const index = this.entries.findIndex((e) => e.id === entryId);
    if (index === -1) {
      throw new Error(`Entry not found: ${entryId}`);
    }
    return this.tree.generateProof(index);
  }

  /**
   * Verify the integrity of the entire log.
   */
  verifyIntegrity(): boolean {
    let expectedPreviousHash = 'genesis';

    for (const entry of this.entries) {
      if (entry.previousHash !== expectedPreviousHash) {
        return false;
      }
      expectedPreviousHash = entry.entryHash;
    }

    return true;
  }

  /**
   * Get the current root hash.
   */
  getRootHash(): string {
    return this.tree.getRoot();
  }

  /**
   * Get the number of entries.
   */
  get size(): number {
    return this.entries.length;
  }

  /**
   * Get the underlying Merkle tree state.
   */
  getTreeState(): MerkleTreeState {
    return this.tree.getState();
  }
}
