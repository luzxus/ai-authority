/**
 * P2P Network Layer
 *
 * Implements peer-to-peer networking for the federation protocol.
 * Uses WebSocket-based transport with gossip protocol for message propagation.
 */

import type { FederationNode, FederationMessage } from '@ai-authority/core';
import * as crypto from 'crypto';

// ============================================================================
// Types
// ============================================================================

export interface PeerNetworkConfig {
  /** This node's ID */
  readonly nodeId: string;

  /** Listen port for incoming connections */
  readonly listenPort: number;

  /** Maximum peers to maintain */
  readonly maxPeers: number;

  /** Connection timeout in ms */
  readonly connectionTimeoutMs: number;

  /** Heartbeat interval in ms */
  readonly heartbeatIntervalMs: number;

  /** Message TTL for gossip propagation */
  readonly messageTTL: number;

  /** Enable encryption for peer communication */
  readonly enableEncryption: boolean;
}

export interface PeerInfo {
  /** Peer ID (mutable - updated after handshake) */
  id: string;

  /** Connection address */
  readonly address: string;

  /** Connection state */
  state: 'connecting' | 'connected' | 'disconnected';

  /** Whether we initiated this connection */
  readonly isOutbound: boolean;

  /** Last message timestamp */
  lastMessageAt?: Date;

  /** Last heartbeat timestamp */
  lastHeartbeatAt?: Date;

  /** Connection latency (ms) */
  latencyMs?: number;

  /** Federation node info (after handshake) */
  nodeInfo?: FederationNode;
}

export interface NetworkEvent {
  type: 'peer_connected' | 'peer_disconnected' | 'message_received' | 'network_error';
  peer?: FederationNode;
  peerId?: string;
  message?: FederationMessage;
  error?: string;
}

export type NetworkEventHandler = (event: NetworkEvent) => void;

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_PEER_NETWORK_CONFIG: Omit<PeerNetworkConfig, 'nodeId'> = {
  listenPort: 8765,
  maxPeers: 50,
  connectionTimeoutMs: 10000,
  heartbeatIntervalMs: 30000,
  messageTTL: 5,
  enableEncryption: true,
};

// ============================================================================
// Peer Network
// ============================================================================

/**
 * Manages peer-to-peer network connections.
 *
 * In a production system, this would use actual WebSocket connections.
 * This implementation provides the interface and message handling logic
 * that can be backed by any transport layer.
 */
export class PeerNetwork {
  private readonly config: PeerNetworkConfig;
  private readonly peers: Map<string, PeerInfo> = new Map();
  private readonly eventHandlers: Map<string, NetworkEventHandler[]> = new Map();
  private readonly seenMessages: Set<string> = new Set();
  private heartbeatInterval?: ReturnType<typeof setInterval>;
  private cleanupInterval?: ReturnType<typeof setInterval>;
  private isRunning = false;

  // Transport abstraction - can be replaced with actual WebSocket
  private transport?: NetworkTransport;

  constructor(config: PeerNetworkConfig) {
    this.config = config;
  }

  /**
   * Start the network.
   */
  async start(): Promise<void> {
    if (this.isRunning) return;

    this.isRunning = true;

    // Initialize transport
    this.transport = new InMemoryTransport(this.config.nodeId);
    await this.transport.listen(this.config.listenPort);

    // Set up transport handlers
    this.transport.onConnection((peerId, address) => {
      this.handleNewConnection(peerId, address);
    });

    this.transport.onMessage((peerId, data) => {
      this.handleTransportMessage(peerId, data);
    });

    this.transport.onDisconnect((peerId) => {
      this.handleDisconnection(peerId);
    });

    // Start heartbeat
    this.heartbeatInterval = setInterval(() => {
      this.sendHeartbeats();
    }, this.config.heartbeatIntervalMs);

    // Start message cleanup
    this.cleanupInterval = setInterval(() => {
      this.cleanupSeenMessages();
    }, 60000);
  }

  /**
   * Stop the network.
   */
  async stop(): Promise<void> {
    if (!this.isRunning) return;

    this.isRunning = false;

    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }

    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }

    // Disconnect all peers
    for (const peerId of this.peers.keys()) {
      await this.disconnectPeer(peerId);
    }

    // Stop transport
    if (this.transport) {
      await this.transport.close();
    }
  }

  /**
   * Connect to a peer.
   */
  async connectToPeer(address: string): Promise<void> {
    if (!this.isRunning || !this.transport) {
      throw new Error('Network not started');
    }

    if (this.peers.size >= this.config.maxPeers) {
      throw new Error('Maximum peers reached');
    }

    // Connect via transport - returns the peer's ID
    const peerId = await this.transport.connect(address, this.config.connectionTimeoutMs);

    const peerInfo: PeerInfo = {
      id: peerId,
      address,
      state: 'connecting',
      isOutbound: true,
    };

    this.peers.set(peerId, peerInfo);

    try {
      // Send handshake
      await this.sendHandshake(peerId);
    } catch (error) {
      this.peers.delete(peerId);
      throw error;
    }
  }

  /**
   * Disconnect from a peer.
   */
  async disconnectPeer(peerId: string): Promise<void> {
    const peer = this.peers.get(peerId);
    if (!peer) return;

    peer.state = 'disconnected';

    if (this.transport) {
      await this.transport.disconnect(peerId);
    }

    this.peers.delete(peerId);

    if (peer.nodeInfo) {
      this.emit({
        type: 'peer_disconnected',
        peerId: peer.nodeInfo.id,
      });
    }
  }

  /**
   * Send a message to a specific peer.
   */
  async sendMessage(peerId: string, message: FederationMessage): Promise<void> {
    const peer = this.peers.get(peerId);
    if (!peer || peer.state !== 'connected' || !this.transport) {
      throw new Error(`Peer ${peerId} not connected`);
    }

    // Mark message as seen to prevent echo
    this.seenMessages.add(message.id);

    // Serialize and send
    const data = this.serializeMessage(message);
    await this.transport.send(peerId, data);
  }

  /**
   * Broadcast a message to all connected peers.
   */
  async broadcast(message: FederationMessage): Promise<void> {
    if (!this.transport) return;

    // Mark as seen
    this.seenMessages.add(message.id);

    const data = this.serializeMessage(message);

    // Send to all connected peers
    const sendPromises: Promise<void>[] = [];
    for (const [peerId, peer] of this.peers.entries()) {
      if (peer.state === 'connected') {
        sendPromises.push(
          this.transport.send(peerId, data).catch((err) => {
            console.error(`Failed to send to peer ${peerId}:`, err);
          })
        );
      }
    }

    await Promise.all(sendPromises);
  }

  /**
   * Register an event handler.
   */
  on(eventType: NetworkEvent['type'], handler: NetworkEventHandler): void {
    const handlers = this.eventHandlers.get(eventType) ?? [];
    handlers.push(handler);
    this.eventHandlers.set(eventType, handlers);
  }

  /**
   * Get connected peer count.
   */
  getConnectedPeerCount(): number {
    return Array.from(this.peers.values()).filter((p) => p.state === 'connected').length;
  }

  /**
   * Get peer info.
   */
  getPeer(peerId: string): PeerInfo | undefined {
    return this.peers.get(peerId);
  }

  /**
   * Get all peers.
   */
  getAllPeers(): PeerInfo[] {
    return Array.from(this.peers.values());
  }

  /**
   * Check if running.
   */
  isActive(): boolean {
    return this.isRunning;
  }

  // ============================================================================
  // Internal Methods
  // ============================================================================

  private handleNewConnection(peerId: string, address: string): void {
    if (this.peers.size >= this.config.maxPeers) {
      // Reject connection
      this.transport?.disconnect(peerId);
      return;
    }

    const peerInfo: PeerInfo = {
      id: peerId,
      address,
      state: 'connecting',
      isOutbound: false, // This is an incoming connection
    };

    this.peers.set(peerId, peerInfo);
  }

  private handleTransportMessage(peerId: string, data: string): void {
    try {
      const message = this.deserializeMessage(data);

      // Check if already seen (gossip dedup)
      if (this.seenMessages.has(message.id)) {
        return;
      }
      this.seenMessages.add(message.id);

      // Handle handshake
      if (message.type === 'node_heartbeat' && (message.payload as { isHandshake?: boolean }).isHandshake) {
        this.handleHandshake(peerId, message);
        return;
      }

      // Update peer last message time
      const peer = this.peers.get(peerId);
      if (peer) {
        peer.lastMessageAt = new Date();
      }

      // Emit message event
      this.emit({
        type: 'message_received',
        message,
        peerId,
      });

      // Gossip propagation (if TTL > 0)
      const ttl = (message as FederationMessage & { ttl?: number }).ttl ?? this.config.messageTTL;
      if (ttl > 0 && message.recipientId === 'broadcast') {
        this.propagateGossip(message, peerId, ttl - 1);
      }
    } catch (error) {
      this.emit({
        type: 'network_error',
        error: `Failed to parse message: ${error}`,
        peerId,
      });
    }
  }

  private handleDisconnection(peerId: string): void {
    const peer = this.peers.get(peerId);
    if (!peer) return;

    const nodeInfo = peer.nodeInfo;
    this.peers.delete(peerId);

    if (nodeInfo) {
      this.emit({
        type: 'peer_disconnected',
        peerId: nodeInfo.id,
      });
    }
  }

  private handleHandshake(peerId: string, message: FederationMessage): void {
    const payload = message.payload as {
      isHandshake: boolean;
      nodeInfo: FederationNode;
      timestamp: number;
    };

    const peer = this.peers.get(peerId);
    if (!peer) return;

    // Update peer info
    peer.state = 'connected';
    peer.nodeInfo = payload.nodeInfo;
    peer.lastHeartbeatAt = new Date();

    // Calculate latency if we have the timestamp
    if (payload.timestamp) {
      peer.latencyMs = Date.now() - payload.timestamp;
    }

    // Re-key the peer by actual node ID if different
    if (peerId !== payload.nodeInfo.id) {
      this.peers.delete(peerId);
      peer.id = payload.nodeInfo.id;
      this.peers.set(payload.nodeInfo.id, peer);
    }

    // Emit connected event
    this.emit({
      type: 'peer_connected',
      peer: payload.nodeInfo,
    });

    // Send handshake response if this was an incoming connection
    // (we didn't initiate it, so we need to respond)
    if (!peer.isOutbound) {
      this.sendHandshake(payload.nodeInfo.id);
    }
  }

  private async sendHandshake(peerId: string): Promise<void> {
    const handshake: FederationMessage<{
      isHandshake: boolean;
      nodeInfo: Partial<FederationNode>;
      timestamp: number;
    }> = {
      id: crypto.randomUUID(),
      type: 'node_heartbeat',
      senderId: this.config.nodeId,
      recipientId: peerId,
      payload: {
        isHandshake: true,
        nodeInfo: {
          id: this.config.nodeId,
          publicKey: '', // Would be set from actual config
          capabilities: [],
          region: 'unknown',
          trustScore: 1.0,
          lastSeen: new Date(),
          status: 'active',
          metadata: {},
        },
        timestamp: Date.now(),
      },
      timestamp: new Date(),
      signature: '', // Would be signed
    };

    const data = this.serializeMessage(handshake);
    await this.transport?.send(peerId, data);
  }

  private sendHeartbeats(): void {
    const now = Date.now();
    const staleThreshold = this.config.heartbeatIntervalMs * 3;

    for (const [peerId, peer] of this.peers.entries()) {
      if (peer.state !== 'connected') continue;

      // Check if peer is stale
      if (peer.lastHeartbeatAt) {
        const lastHeartbeat = peer.lastHeartbeatAt.getTime();
        if (now - lastHeartbeat > staleThreshold) {
          // Peer appears dead
          this.disconnectPeer(peerId);
          continue;
        }
      }

      // Send heartbeat
      const heartbeat: FederationMessage<{ timestamp: number }> = {
        id: crypto.randomUUID(),
        type: 'node_heartbeat',
        senderId: this.config.nodeId,
        recipientId: peerId,
        payload: { timestamp: now },
        timestamp: new Date(),
        signature: '',
      };

      this.transport?.send(peerId, this.serializeMessage(heartbeat)).catch((err) => {
        console.error(`Heartbeat failed for peer ${peerId}:`, err);
      });
    }
  }

  private async propagateGossip(
    message: FederationMessage,
    sourcePeerId: string,
    ttl: number
  ): Promise<void> {
    const gossipMessage = { ...message, ttl } as FederationMessage & { ttl: number };
    const data = this.serializeMessage(gossipMessage);

    // Send to all connected peers except source
    for (const [peerId, peer] of this.peers.entries()) {
      if (peer.state === 'connected' && peerId !== sourcePeerId) {
        this.transport?.send(peerId, data).catch(() => {
          // Ignore gossip failures
        });
      }
    }
  }

  private cleanupSeenMessages(): void {
    // Keep seen messages set from growing unbounded
    // In production, would use a bloom filter or time-based eviction
    if (this.seenMessages.size > 10000) {
      const toKeep = Array.from(this.seenMessages).slice(-5000);
      this.seenMessages.clear();
      for (const id of toKeep) {
        this.seenMessages.add(id);
      }
    }
  }

  private serializeMessage(message: FederationMessage): string {
    return JSON.stringify(message, (_, value) => {
      if (value instanceof Date) {
        return { __type: 'Date', value: value.toISOString() };
      }
      return value;
    });
  }

  private deserializeMessage(data: string): FederationMessage {
    return JSON.parse(data, (_, value) => {
      if (value && typeof value === 'object' && value.__type === 'Date') {
        return new Date(value.value);
      }
      return value;
    });
  }

  private emit(event: NetworkEvent): void {
    const handlers = this.eventHandlers.get(event.type) ?? [];
    for (const handler of handlers) {
      try {
        handler(event);
      } catch (error) {
        console.error(`Error in event handler for ${event.type}:`, error);
      }
    }
  }
}

// ============================================================================
// Transport Abstraction
// ============================================================================

/**
 * Abstract transport interface.
 * Can be implemented with WebSocket, TCP, or other transports.
 */
export interface NetworkTransport {
  listen(port: number): Promise<void>;
  connect(address: string, timeoutMs: number): Promise<string>;
  send(peerId: string, data: string): Promise<void>;
  disconnect(peerId: string): Promise<void>;
  close(): Promise<void>;
  onConnection(handler: (peerId: string, address: string) => void): void;
  onMessage(handler: (peerId: string, data: string) => void): void;
  onDisconnect(handler: (peerId: string) => void): void;
}

/**
 * In-memory transport for testing and single-node scenarios.
 * In production, replace with WebSocketTransport.
 */
export class InMemoryTransport implements NetworkTransport {
  private static instances: Map<string, InMemoryTransport> = new Map();
  private static portMapping: Map<number, string> = new Map();

  private readonly nodeId: string;
  private connectionHandler?: (peerId: string, address: string) => void;
  private messageHandler?: (peerId: string, data: string) => void;
  private disconnectHandler?: (peerId: string) => void;
  private listeningPort?: number;
  private connections: Map<string, string> = new Map(); // peerId -> nodeId

  constructor(nodeId: string) {
    this.nodeId = nodeId;
    InMemoryTransport.instances.set(nodeId, this);
  }

  async listen(port: number): Promise<void> {
    this.listeningPort = port;
    InMemoryTransport.portMapping.set(port, this.nodeId);
  }

  async connect(address: string, _timeoutMs: number): Promise<string> {
    // Parse address (format: "localhost:port" or just "port")
    const port = parseInt(address.split(':').pop() ?? address, 10);
    const targetNodeId = InMemoryTransport.portMapping.get(port);

    if (!targetNodeId) {
      throw new Error(`No node listening on port ${port}`);
    }

    const targetTransport = InMemoryTransport.instances.get(targetNodeId);
    if (!targetTransport) {
      throw new Error(`Target node ${targetNodeId} not found`);
    }

    // Create bidirectional connection
    const peerId = targetNodeId;
    this.connections.set(peerId, targetNodeId);
    targetTransport.connections.set(this.nodeId, this.nodeId);

    // Notify target of new connection
    targetTransport.connectionHandler?.(this.nodeId, `localhost:${this.listeningPort}`);

    return peerId;
  }

  async send(peerId: string, data: string): Promise<void> {
    const targetNodeId = this.connections.get(peerId) ?? peerId;
    const targetTransport = InMemoryTransport.instances.get(targetNodeId);

    if (!targetTransport) {
      throw new Error(`Peer ${peerId} not found`);
    }

    // Simulate async network delivery
    setImmediate(() => {
      targetTransport.messageHandler?.(this.nodeId, data);
    });
  }

  async disconnect(peerId: string): Promise<void> {
    const targetNodeId = this.connections.get(peerId);
    this.connections.delete(peerId);

    if (targetNodeId) {
      const targetTransport = InMemoryTransport.instances.get(targetNodeId);
      if (targetTransport) {
        targetTransport.connections.delete(this.nodeId);
        targetTransport.disconnectHandler?.(this.nodeId);
      }
    }
  }

  async close(): Promise<void> {
    // Disconnect all peers
    for (const peerId of this.connections.keys()) {
      await this.disconnect(peerId);
    }

    // Remove from registry
    if (this.listeningPort) {
      InMemoryTransport.portMapping.delete(this.listeningPort);
    }
    InMemoryTransport.instances.delete(this.nodeId);
  }

  onConnection(handler: (peerId: string, address: string) => void): void {
    this.connectionHandler = handler;
  }

  onMessage(handler: (peerId: string, data: string) => void): void {
    this.messageHandler = handler;
  }

  onDisconnect(handler: (peerId: string) => void): void {
    this.disconnectHandler = handler;
  }

  /**
   * Clear all instances (for testing).
   */
  static clearAll(): void {
    InMemoryTransport.instances.clear();
    InMemoryTransport.portMapping.clear();
  }
}

// ============================================================================
// WebSocket Transport (Production - Stub)
// ============================================================================

/**
 * WebSocket-based transport for production use.
 * This is a stub - actual implementation would use ws library.
 */
export class WebSocketTransport implements NetworkTransport {
  constructor(_nodeId: string) {
    // nodeId would be used in production implementation
  }

  async listen(_port: number): Promise<void> {
    // In production: Create WebSocket server
    // const wss = new WebSocket.Server({ port });
    throw new Error('WebSocketTransport.listen() not implemented - use InMemoryTransport for testing');
  }

  async connect(_address: string, _timeoutMs: number): Promise<string> {
    // In production: Create WebSocket client connection
    // const ws = new WebSocket(`ws://${address}`);
    throw new Error('WebSocketTransport.connect() not implemented - use InMemoryTransport for testing');
  }

  async send(_peerId: string, _data: string): Promise<void> {
    throw new Error('WebSocketTransport.send() not implemented');
  }

  async disconnect(_peerId: string): Promise<void> {
    throw new Error('WebSocketTransport.disconnect() not implemented');
  }

  async close(): Promise<void> {
    throw new Error('WebSocketTransport.close() not implemented');
  }

  onConnection(_handler: (peerId: string, address: string) => void): void {
    // Would store handler in production implementation
  }

  onMessage(_handler: (peerId: string, data: string) => void): void {
    // Would store handler in production implementation
  }

  onDisconnect(_handler: (peerId: string) => void): void {
    // Would store handler in production implementation
  }
}
