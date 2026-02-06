/**
 * Peer Discovery
 *
 * Implements peer discovery mechanisms for the federation network:
 * - Bootstrap nodes for initial connection
 * - Peer exchange protocol for discovering new peers
 * - Simple DHT-like routing for scalable peer lookup
 */

import type { FederationNode } from '@ai-authority/core';
import { sha256 } from '@ai-authority/core';

// ============================================================================
// Types
// ============================================================================

export interface DiscoveryConfig {
  /** Bootstrap nodes to connect to initially */
  readonly bootstrapNodes: BootstrapNode[];

  /** Maximum peers to discover */
  readonly maxDiscoveredPeers: number;

  /** Discovery refresh interval in ms */
  readonly refreshIntervalMs: number;

  /** Peer exchange enabled */
  readonly enablePeerExchange: boolean;

  /** DHT bucket size (k-value) */
  readonly dhtBucketSize: number;
}

export interface BootstrapNode {
  /** Node address (host:port) */
  readonly address: string;

  /** Node public key (for verification) */
  readonly publicKey?: string;

  /** Region hint */
  readonly region?: string;
}

export interface DiscoveredPeer {
  /** Peer address */
  readonly address: string;

  /** Node info (if known) */
  nodeInfo?: FederationNode;

  /** How peer was discovered */
  readonly discoverySource: 'bootstrap' | 'peer_exchange' | 'dht';

  /** Discovery timestamp */
  readonly discoveredAt: Date;

  /** Last connection attempt */
  lastAttemptAt?: Date;

  /** Connection failures */
  failureCount: number;

  /** Is currently connected */
  isConnected: boolean;
}

export interface PeerExchangeMessage {
  /** Sender's known peers */
  readonly peers: Array<{
    address: string;
    nodeId?: string;
    region?: string;
    trustScore?: number;
  }>;

  /** Request more peers */
  readonly requestMore: boolean;
}

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_DISCOVERY_CONFIG: DiscoveryConfig = {
  bootstrapNodes: [],
  maxDiscoveredPeers: 200,
  refreshIntervalMs: 300000, // 5 minutes
  enablePeerExchange: true,
  dhtBucketSize: 20,
};

// ============================================================================
// Peer Discovery Manager
// ============================================================================

/**
 * Manages peer discovery for the federation network.
 */
export class PeerDiscovery {
  private readonly config: DiscoveryConfig;
  private readonly discoveredPeers: Map<string, DiscoveredPeer> = new Map();
  private readonly dht: SimpleDHT;
  private refreshInterval: ReturnType<typeof setInterval> | undefined;

  constructor(nodeId: string, config: DiscoveryConfig = DEFAULT_DISCOVERY_CONFIG) {
    this.config = config;
    this.dht = new SimpleDHT(nodeId, config.dhtBucketSize);

    // Add bootstrap nodes to discovered peers
    for (const bootstrap of config.bootstrapNodes) {
      this.addDiscoveredPeer(bootstrap.address, 'bootstrap');
    }
  }

  /**
   * Start discovery process.
   */
  start(): void {
    if (this.refreshInterval) return;

    this.refreshInterval = setInterval(() => {
      this.refreshPeers();
    }, this.config.refreshIntervalMs);
  }

  /**
   * Stop discovery process.
   */
  stop(): void {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = undefined;
    }
  }

  /**
   * Add a discovered peer.
   */
  addDiscoveredPeer(
    address: string,
    source: DiscoveredPeer['discoverySource'],
    nodeInfo?: FederationNode
  ): void {
    if (this.discoveredPeers.size >= this.config.maxDiscoveredPeers) {
      // Evict oldest non-connected peer
      this.evictOldestPeer();
    }

    const existing = this.discoveredPeers.get(address);
    if (existing) {
      // Update existing
      if (nodeInfo) {
        existing.nodeInfo = nodeInfo;
      }
      return;
    }

    const newPeer: DiscoveredPeer = {
      address,
      discoverySource: source,
      discoveredAt: new Date(),
      failureCount: 0,
      isConnected: false,
    };
    if (nodeInfo) {
      newPeer.nodeInfo = nodeInfo;
    }
    this.discoveredPeers.set(address, newPeer);

    // Add to DHT if we have node info
    if (nodeInfo) {
      this.dht.addNode(nodeInfo.id, address);
    }
  }

  /**
   * Mark peer as connected.
   */
  markConnected(address: string, nodeInfo: FederationNode): void {
    const peer = this.discoveredPeers.get(address);
    if (peer) {
      peer.isConnected = true;
      peer.nodeInfo = nodeInfo;
      peer.failureCount = 0;
      this.dht.addNode(nodeInfo.id, address);
    }
  }

  /**
   * Mark peer as disconnected.
   */
  markDisconnected(address: string): void {
    const peer = this.discoveredPeers.get(address);
    if (peer) {
      peer.isConnected = false;
    }
  }

  /**
   * Record connection failure.
   */
  recordFailure(address: string): void {
    const peer = this.discoveredPeers.get(address);
    if (peer) {
      peer.failureCount++;
      peer.lastAttemptAt = new Date();

      // Remove peer after too many failures
      if (peer.failureCount > 5 && peer.discoverySource !== 'bootstrap') {
        this.discoveredPeers.delete(address);
      }
    }
  }

  /**
   * Get peers to try connecting to.
   */
  getPeersToConnect(count: number): DiscoveredPeer[] {
    const candidates = Array.from(this.discoveredPeers.values())
      .filter((p) => !p.isConnected)
      .filter((p) => {
        // Skip recently failed peers
        if (p.lastAttemptAt) {
          const backoffMs = Math.min(p.failureCount * 30000, 300000);
          const elapsed = Date.now() - p.lastAttemptAt.getTime();
          if (elapsed < backoffMs) return false;
        }
        return true;
      })
      .sort((a, b) => {
        // Prioritize: bootstrap > fewer failures > older discovery
        if (a.discoverySource === 'bootstrap' && b.discoverySource !== 'bootstrap') return -1;
        if (b.discoverySource === 'bootstrap' && a.discoverySource !== 'bootstrap') return 1;
        if (a.failureCount !== b.failureCount) return a.failureCount - b.failureCount;
        return a.discoveredAt.getTime() - b.discoveredAt.getTime();
      });

    return candidates.slice(0, count);
  }

  /**
   * Get connected peers for exchange.
   */
  getConnectedPeers(): DiscoveredPeer[] {
    return Array.from(this.discoveredPeers.values()).filter((p) => p.isConnected);
  }

  /**
   * Handle peer exchange message.
   */
  handlePeerExchange(message: PeerExchangeMessage): PeerExchangeMessage | null {
    if (!this.config.enablePeerExchange) return null;

    // Add received peers
    for (const peer of message.peers) {
      this.addDiscoveredPeer(peer.address, 'peer_exchange');
    }

    // Respond with our peers if requested
    if (message.requestMore) {
      return this.createPeerExchangeMessage(false);
    }

    return null;
  }

  /**
   * Create peer exchange message.
   */
  createPeerExchangeMessage(requestMore: boolean): PeerExchangeMessage {
    const connectedPeers = this.getConnectedPeers().slice(0, 20);

    return {
      peers: connectedPeers
        .filter((p) => p.nodeInfo)
        .map((p) => {
          const peer: { address: string; nodeId?: string; region?: string; trustScore?: number } = {
            address: p.address,
          };
          if (p.nodeInfo?.id) peer.nodeId = p.nodeInfo.id;
          if (p.nodeInfo?.region) peer.region = p.nodeInfo.region;
          if (p.nodeInfo?.trustScore !== undefined) peer.trustScore = p.nodeInfo.trustScore;
          return peer;
        }),
      requestMore,
    };
  }

  /**
   * Find node by ID using DHT.
   */
  findNode(nodeId: string): string | undefined {
    return this.dht.findNode(nodeId);
  }

  /**
   * Get closest nodes to an ID.
   */
  findClosestNodes(targetId: string, count: number): Array<{ nodeId: string; address: string }> {
    return this.dht.findClosest(targetId, count);
  }

  /**
   * Get discovery statistics.
   */
  getStats(): {
    totalDiscovered: number;
    connected: number;
    bySource: Record<string, number>;
  } {
    const peers = Array.from(this.discoveredPeers.values());

    const bySource: Record<string, number> = {};
    for (const peer of peers) {
      bySource[peer.discoverySource] = (bySource[peer.discoverySource] ?? 0) + 1;
    }

    return {
      totalDiscovered: peers.length,
      connected: peers.filter((p) => p.isConnected).length,
      bySource,
    };
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  private refreshPeers(): void {
    // Remove stale non-connected peers
    const now = Date.now();
    const staleThreshold = 3600000; // 1 hour

    for (const [address, peer] of this.discoveredPeers.entries()) {
      if (!peer.isConnected && peer.discoverySource !== 'bootstrap') {
        const age = now - peer.discoveredAt.getTime();
        if (age > staleThreshold && peer.failureCount > 2) {
          this.discoveredPeers.delete(address);
        }
      }
    }
  }

  private evictOldestPeer(): void {
    let oldestPeer: DiscoveredPeer | undefined;
    let oldestAddress: string | undefined;

    for (const [address, peer] of this.discoveredPeers.entries()) {
      // Never evict bootstrap or connected peers
      if (peer.discoverySource === 'bootstrap' || peer.isConnected) continue;

      if (!oldestPeer || peer.discoveredAt < oldestPeer.discoveredAt) {
        oldestPeer = peer;
        oldestAddress = address;
      }
    }

    if (oldestAddress) {
      this.discoveredPeers.delete(oldestAddress);
    }
  }
}

// ============================================================================
// Simple DHT
// ============================================================================

/**
 * Simplified DHT for node lookup.
 * Uses XOR distance metric similar to Kademlia.
 */
export class SimpleDHT {
  private readonly bucketSize: number;
  private readonly routingTable: Map<string, { nodeId: string; address: string }[]> = new Map();

  constructor(_nodeId: string, bucketSize: number = 20) {
    this.bucketSize = bucketSize;
  }

  /**
   * Add a node to the routing table.
   */
  addNode(nodeId: string, address: string): void {
    const nodeHash = sha256(nodeId);
    const bucketIndex = this.getBucketIndex(nodeHash);

    let bucket = this.routingTable.get(bucketIndex);
    if (!bucket) {
      bucket = [];
      this.routingTable.set(bucketIndex, bucket);
    }

    // Check if already exists
    const existingIdx = bucket.findIndex((n) => n.nodeId === nodeId);
    if (existingIdx >= 0) {
      // Move to end (most recently seen)
      const existing = bucket.splice(existingIdx, 1)[0];
      if (existing) {
        bucket.push(existing);
      }
      return;
    }

    // Add to bucket
    if (bucket.length < this.bucketSize) {
      bucket.push({ nodeId, address });
    } else {
      // Bucket full - replace oldest if it's stale (simplified: always replace oldest)
      bucket.shift();
      bucket.push({ nodeId, address });
    }
  }

  /**
   * Remove a node from the routing table.
   */
  removeNode(nodeId: string): void {
    const nodeHash = sha256(nodeId);
    const bucketIndex = this.getBucketIndex(nodeHash);
    const bucket = this.routingTable.get(bucketIndex);

    if (bucket) {
      const idx = bucket.findIndex((n) => n.nodeId === nodeId);
      if (idx >= 0) {
        bucket.splice(idx, 1);
      }
    }
  }

  /**
   * Find a node's address by ID.
   */
  findNode(nodeId: string): string | undefined {
    const nodeHash = sha256(nodeId);
    const bucketIndex = this.getBucketIndex(nodeHash);
    const bucket = this.routingTable.get(bucketIndex);

    if (bucket) {
      const node = bucket.find((n) => n.nodeId === nodeId);
      if (node) return node.address;
    }

    return undefined;
  }

  /**
   * Find nodes closest to a target ID.
   */
  findClosest(targetId: string, count: number): Array<{ nodeId: string; address: string }> {
    const targetHash = sha256(targetId);
    const allNodes: Array<{ nodeId: string; address: string; distance: bigint }> = [];

    for (const bucket of this.routingTable.values()) {
      for (const node of bucket) {
        const nodeHash = sha256(node.nodeId);
        const distance = this.xorDistance(nodeHash, targetHash);
        allNodes.push({ ...node, distance });
      }
    }

    // Sort by distance and return closest
    allNodes.sort((a, b) => {
      if (a.distance < b.distance) return -1;
      if (a.distance > b.distance) return 1;
      return 0;
    });

    return allNodes.slice(0, count).map(({ nodeId, address }) => ({ nodeId, address }));
  }

  /**
   * Get routing table size.
   */
  getSize(): number {
    let total = 0;
    for (const bucket of this.routingTable.values()) {
      total += bucket.length;
    }
    return total;
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  private getBucketIndex(nodeHash: string): string {
    // Simplified: use first 2 hex chars as bucket index
    // In real Kademlia, would use bit-level XOR distance
    return nodeHash.substring(0, 2);
  }

  private xorDistance(hash1: string, hash2: string): bigint {
    // Convert hex hashes to bigint and XOR
    const h1 = BigInt('0x' + hash1);
    const h2 = BigInt('0x' + hash2);
    return h1 ^ h2;
  }
}

// ============================================================================
// Well-Known Bootstrap Nodes
// ============================================================================

/**
 * Default bootstrap nodes for the AI Authority network.
 * In production, these would be maintained infrastructure nodes.
 */
export const WELL_KNOWN_BOOTSTRAP_NODES: BootstrapNode[] = [
  {
    address: 'bootstrap-us.ai-authority.network:8765',
    region: 'us-east',
  },
  {
    address: 'bootstrap-eu.ai-authority.network:8765',
    region: 'eu-west',
  },
  {
    address: 'bootstrap-ap.ai-authority.network:8765',
    region: 'ap-southeast',
  },
];

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Create discovery config with default bootstrap nodes.
 */
export function createDiscoveryConfig(
  additionalBootstrap: BootstrapNode[] = []
): DiscoveryConfig {
  return {
    ...DEFAULT_DISCOVERY_CONFIG,
    bootstrapNodes: [...WELL_KNOWN_BOOTSTRAP_NODES, ...additionalBootstrap],
  };
}
