/**
 * Federation Protocol
 *
 * Implements the P2P federation protocol per blueprint §5 and §11:
 * - Zero-knowledge proofs for sharing alerts
 * - Federated architecture with nodes per region
 * - Byzantine fault-tolerant consensus
 */

import type {
  FederationNode,
  FederationMessage,
  FederationMessageType,
  ThreatSignal,
  Permission,
} from '@ai-authority/core';
import { sha256, sign, verify, generateRSAKeyPair } from '@ai-authority/core';
import * as crypto from 'crypto';

// Simple UUID v4 generator
function uuidv4(): string {
  return crypto.randomUUID();
}

// ============================================================================
// Types
// ============================================================================

export interface FederationConfig {
  /** This node's ID */
  readonly nodeId: string;

  /** This node's region */
  readonly region: string;

  /** Node capabilities */
  readonly capabilities: Permission[];

  /** Consensus threshold (fraction of nodes required) */
  readonly consensusThreshold: number;

  /** Message timeout in ms */
  readonly messageTimeoutMs: number;

  /** Heartbeat interval in ms */
  readonly heartbeatIntervalMs: number;
}

export interface PeerConnection {
  /** Peer node info */
  readonly node: FederationNode;

  /** Connection status */
  status: 'connected' | 'connecting' | 'disconnected';

  /** Last message received */
  lastMessageAt?: Date;

  /** Pending messages */
  pendingMessages: FederationMessage[];
}

export interface ConsensusProposal {
  /** Proposal ID */
  readonly id: string;

  /** Proposal type */
  readonly type: 'threat_alert' | 'intervention' | 'node_action';

  /** Proposal data */
  readonly data: unknown;

  /** Proposer node ID */
  readonly proposerId: string;

  /** Votes received */
  readonly votes: Map<string, 'approve' | 'reject'>;

  /** Proposal timestamp */
  readonly createdAt: Date;

  /** Proposal status */
  status: 'pending' | 'approved' | 'rejected' | 'expired';
}

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_FEDERATION_CONFIG: Omit<FederationConfig, 'nodeId' | 'region'> = {
  capabilities: ['read:signals', 'write:signals'],
  consensusThreshold: 2 / 3, // Per blueprint: >2/3 node agreement
  messageTimeoutMs: 30000,
  heartbeatIntervalMs: 10000,
};

// ============================================================================
// Federation Node Manager
// ============================================================================

/**
 * Manages a node in the federated network.
 */
export class FederationNodeManager {
  private readonly config: FederationConfig;
  private readonly privateKey: string;
  private readonly publicKey: string;
  private readonly peers: Map<string, PeerConnection> = new Map();
  private readonly proposals: Map<string, ConsensusProposal> = new Map();
  private readonly messageHandlers: Map<FederationMessageType, MessageHandler[]> = new Map();

  constructor(config: FederationConfig) {
    this.config = config;

    // Generate node keys
    const keyPair = generateRSAKeyPair();
    this.privateKey = keyPair.privateKey;
    this.publicKey = keyPair.publicKey;
  }

  /**
   * Get this node's info.
   */
  getNodeInfo(): FederationNode {
    return {
      id: this.config.nodeId,
      publicKey: this.publicKey,
      capabilities: this.config.capabilities,
      region: this.config.region,
      trustScore: 1.0, // Self-trust
      lastSeen: new Date(),
      status: 'active',
      metadata: {},
    };
  }

  /**
   * Register a peer node.
   */
  registerPeer(node: FederationNode): void {
    this.peers.set(node.id, {
      node,
      status: 'disconnected',
      pendingMessages: [],
    });
  }

  /**
   * Remove a peer node.
   */
  removePeer(nodeId: string): void {
    this.peers.delete(nodeId);
  }

  /**
   * Get all peer nodes.
   */
  getPeers(): FederationNode[] {
    return Array.from(this.peers.values()).map((p) => p.node);
  }

  /**
   * Get active peer count.
   */
  getActivePeerCount(): number {
    return Array.from(this.peers.values()).filter((p) => p.status === 'connected').length;
  }

  /**
   * Create a signed message.
   */
  createMessage<T>(
    type: FederationMessageType,
    payload: T,
    recipientId: string | 'broadcast'
  ): FederationMessage<T> {
    const messageData = {
      id: uuidv4(),
      type,
      senderId: this.config.nodeId,
      recipientId,
      payload,
      timestamp: new Date(),
    };

    const signature = sign(JSON.stringify(messageData), this.privateKey);

    return {
      ...messageData,
      signature,
    };
  }

  /**
   * Verify a message signature.
   */
  verifyMessage(message: FederationMessage): boolean {
    const peer = this.peers.get(message.senderId);
    if (!peer) {
      return false;
    }

    const messageData = {
      id: message.id,
      type: message.type,
      senderId: message.senderId,
      recipientId: message.recipientId,
      payload: message.payload,
      timestamp: message.timestamp,
    };

    return verify(JSON.stringify(messageData), message.signature, peer.node.publicKey);
  }

  /**
   * Handle incoming message.
   */
  handleMessage(message: FederationMessage): void {
    // Verify signature
    if (!this.verifyMessage(message)) {
      console.warn(`Invalid message signature from ${message.senderId}`);
      return;
    }

    // Update peer last seen
    const peer = this.peers.get(message.senderId);
    if (peer) {
      peer.lastMessageAt = new Date();
    }

    // Call registered handlers
    const handlers = this.messageHandlers.get(message.type) ?? [];
    for (const handler of handlers) {
      handler(message);
    }
  }

  /**
   * Register a message handler.
   */
  onMessage(type: FederationMessageType, handler: MessageHandler): void {
    const handlers = this.messageHandlers.get(type) ?? [];
    handlers.push(handler);
    this.messageHandlers.set(type, handlers);
  }

  /**
   * Broadcast a threat signal to all peers.
   */
  broadcastThreatSignal(signal: ThreatSignal): FederationMessage<ThreatSignal> {
    const message = this.createMessage('threat_alert', signal, 'broadcast');

    // Queue for all peers
    for (const peer of this.peers.values()) {
      if (peer.status === 'connected') {
        peer.pendingMessages.push(message as FederationMessage);
      }
    }

    return message;
  }

  /**
   * Start a consensus proposal.
   */
  proposeConsensus(
    type: ConsensusProposal['type'],
    data: unknown
  ): ConsensusProposal {
    const proposal: ConsensusProposal = {
      id: uuidv4(),
      type,
      data,
      proposerId: this.config.nodeId,
      votes: new Map(),
      createdAt: new Date(),
      status: 'pending',
    };

    // Vote for own proposal
    proposal.votes.set(this.config.nodeId, 'approve');

    this.proposals.set(proposal.id, proposal);

    // Broadcast proposal
    const message = this.createMessage('consensus_proposal', proposal, 'broadcast');
    for (const peer of this.peers.values()) {
      if (peer.status === 'connected') {
        peer.pendingMessages.push(message as FederationMessage);
      }
    }

    return proposal;
  }

  /**
   * Vote on a consensus proposal.
   */
  voteOnProposal(proposalId: string, vote: 'approve' | 'reject'): void {
    const proposal = this.proposals.get(proposalId);
    if (!proposal || proposal.status !== 'pending') {
      return;
    }

    proposal.votes.set(this.config.nodeId, vote);

    // Broadcast vote
    const message = this.createMessage(
      'consensus_vote',
      { proposalId, vote },
      'broadcast'
    );

    for (const peer of this.peers.values()) {
      if (peer.status === 'connected') {
        peer.pendingMessages.push(message as FederationMessage);
      }
    }

    // Check if consensus reached
    this.checkConsensus(proposalId);
  }

  /**
   * Check if consensus is reached on a proposal.
   */
  private checkConsensus(proposalId: string): void {
    const proposal = this.proposals.get(proposalId);
    if (!proposal || proposal.status !== 'pending') {
      return;
    }

    const totalNodes = this.peers.size + 1; // Including self
    const approveCount = Array.from(proposal.votes.values()).filter(
      (v) => v === 'approve'
    ).length;
    const rejectCount = Array.from(proposal.votes.values()).filter(
      (v) => v === 'reject'
    ).length;

    const approveRatio = approveCount / totalNodes;
    const rejectRatio = rejectCount / totalNodes;

    if (approveRatio >= this.config.consensusThreshold) {
      proposal.status = 'approved';
    } else if (rejectRatio > 1 - this.config.consensusThreshold) {
      proposal.status = 'rejected';
    }
  }

  /**
   * Get proposal status.
   */
  getProposal(proposalId: string): ConsensusProposal | undefined {
    return this.proposals.get(proposalId);
  }

  /**
   * Get pending proposals.
   */
  getPendingProposals(): ConsensusProposal[] {
    return Array.from(this.proposals.values()).filter((p) => p.status === 'pending');
  }

  /**
   * Drain pending messages for a peer.
   */
  drainMessages(peerId: string): FederationMessage[] {
    const peer = this.peers.get(peerId);
    if (!peer) {
      return [];
    }

    const messages = [...peer.pendingMessages];
    peer.pendingMessages = [];
    return messages;
  }
}

type MessageHandler = (message: FederationMessage) => void;

// ============================================================================
// Differential Privacy
// ============================================================================

/**
 * Applies differential privacy to numeric data.
 * Per blueprint §5: "Use differential privacy for sharing analytics"
 */
export class DifferentialPrivacy {
  private readonly epsilon: number;

  constructor(epsilon: number = 1.0) {
    this.epsilon = epsilon;
  }

  /**
   * Add Laplacian noise for differential privacy.
   */
  addNoise(value: number, sensitivity: number = 1): number {
    const scale = sensitivity / this.epsilon;
    const noise = this.laplacianNoise(scale);
    return value + noise;
  }

  /**
   * Generate Laplacian noise.
   */
  private laplacianNoise(scale: number): number {
    const u = Math.random() - 0.5;
    return -scale * Math.sign(u) * Math.log(1 - 2 * Math.abs(u));
  }

  /**
   * Privatize a count.
   */
  privatizeCount(count: number): number {
    return Math.round(this.addNoise(count, 1));
  }

  /**
   * Privatize a rate/ratio.
   */
  privatizeRate(rate: number): number {
    const noisy = this.addNoise(rate, 0.1);
    return Math.max(0, Math.min(1, noisy)); // Clamp to [0, 1]
  }

  /**
   * Get privacy budget (epsilon).
   */
  getEpsilon(): number {
    return this.epsilon;
  }
}

// ============================================================================
// Zero-Knowledge Proof Stub
// ============================================================================

/**
 * Placeholder for zero-knowledge proof generation.
 * Per blueprint §5: "Use zero-knowledge proofs for sharing alerts"
 *
 * Note: Full ZK implementation would require a ZK library like snarkjs.
 * This is a simplified commitment-based approach for the prototype.
 */
export interface ZKProof {
  /** Commitment to the secret */
  readonly commitment: string;

  /** Public statement being proven */
  readonly statement: string;

  /** Proof data */
  readonly proof: string;

  /** Verification key */
  readonly verificationKey: string;
}

/**
 * Simple commitment-based "proof" for prototype.
 */
export class ZKProofGenerator {
  /**
   * Generate a proof that a value exceeds a threshold without revealing the value.
   */
  proveThresholdExceeded(value: number, threshold: number, salt: string): ZKProof {
    // This is a simplified version - real ZK would be more complex
    const exceeds = value > threshold;
    const commitment = sha256(`${value}:${salt}`);
    const statement = `value > ${threshold}`;
    const proof = sha256(`${exceeds}:${commitment}:${salt}`);
    const verificationKey = sha256(`vk:${threshold}:${salt}`);

    return {
      commitment,
      statement,
      proof,
      verificationKey,
    };
  }

  /**
   * Verify a threshold proof.
   */
  verifyThresholdProof(
    zkProof: ZKProof,
    threshold: number,
    expectedResult: boolean,
    salt: string
  ): boolean {
    const expectedProof = sha256(`${expectedResult}:${zkProof.commitment}:${salt}`);
    const expectedVK = sha256(`vk:${threshold}:${salt}`);

    return zkProof.proof === expectedProof && zkProof.verificationKey === expectedVK;
  }
}
