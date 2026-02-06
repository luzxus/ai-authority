/**
 * Liaison Agent
 *
 * Federation agent that manages P2P communication and knowledge sharing
 * between nodes in the federated network. Per blueprint §5:
 * - Query external nodes for shared insights
 * - Aggregate anomaly patterns from cloud providers
 * - Privacy-preserving model updates
 * - Zero-knowledge proofs for alerts
 */

import type { ThreatSignal, FederationMessage, FederationNode } from '@ai-authority/core';
import { generateSecureId, MerkleTree } from '@ai-authority/core';
import {
  FederationNodeManager,
  type FederationConfig,
  type ConsensusProposal,
  DEFAULT_FEDERATION_CONFIG,
  ZKProofGenerator,
} from './protocol.js';
import { SignalSharer, type SharedSignal, type SignalSharingConfig, DEFAULT_SHARING_CONFIG } from './sharing.js';
import { PeerNetwork, type PeerNetworkConfig, type NetworkEvent, DEFAULT_PEER_NETWORK_CONFIG } from './network.js';

// ============================================================================
// Types
// ============================================================================

export interface LiaisonConfig {
  /** This node's ID */
  readonly nodeId: string;

  /** This node's region */
  readonly region: string;

  /** Node's public key */
  readonly publicKey: string;

  /** Federation configuration */
  readonly federation: FederationConfig;

  /** Signal sharing configuration */
  readonly sharing?: SignalSharingConfig;

  /** Network configuration */
  readonly network?: PeerNetworkConfig;

  /** Bootstrap peers to connect to on startup */
  readonly bootstrapPeers?: string[];

  /** Max concurrent tasks */
  readonly maxConcurrentTasks?: number;

  /** Task timeout in ms */
  readonly taskTimeoutMs?: number;
}

export interface FederationState {
  /** Connected peer count */
  readonly connectedPeers: number;

  /** Total known peers */
  readonly knownPeers: number;

  /** Pending consensus proposals */
  readonly pendingProposals: number;

  /** Signals shared this session */
  readonly signalsShared: number;

  /** Signals received this session */
  readonly signalsReceived: number;

  /** Last sync timestamp */
  readonly lastSyncAt?: Date;

  /** Network status */
  readonly networkStatus: 'connected' | 'connecting' | 'disconnected';
}

export interface LiaisonTask {
  id: string;
  type: LiaisonTaskType['type'];
  payload: LiaisonTaskType;
  createdAt: Date;
}

export interface TaskResult {
  taskId: string;
  agentId: string;
  status: 'completed' | 'failed';
  output?: unknown;
  error?: string;
  startedAt: Date;
  completedAt: Date;
}

export interface SignalShareTask {
  type: 'share_signal';
  signal: ThreatSignal;
  targetPeers?: string[]; // Specific peers or broadcast
}

export interface ProposeConsensusTask {
  type: 'propose_consensus';
  proposalType: ConsensusProposal['type'];
  data: unknown;
}

export interface QueryPeersTask {
  type: 'query_peers';
  query: {
    type?: ThreatSignal['type'];
    severity?: ThreatSignal['severity'];
    since?: Date;
  };
}

export interface SyncKnowledgeTask {
  type: 'sync_knowledge';
  domain: string;
}

export type LiaisonTaskType =
  | SignalShareTask
  | ProposeConsensusTask
  | QueryPeersTask
  | SyncKnowledgeTask;

// Simple event emitter for liaison events
interface LiaisonEventEmitter {
  on(event: string, listener: (...args: unknown[]) => void): void;
  emit(event: string, ...args: unknown[]): void;
}

class SimpleLiaisonEventEmitter implements LiaisonEventEmitter {
  private listeners: Map<string, Array<(...args: unknown[]) => void>> = new Map();

  on(event: string, listener: (...args: unknown[]) => void): void {
    const existing = this.listeners.get(event) ?? [];
    existing.push(listener);
    this.listeners.set(event, existing);
  }

  emit(event: string, ...args: unknown[]): void {
    const listeners = this.listeners.get(event) ?? [];
    for (const listener of listeners) {
      try {
        listener(...args);
      } catch (e) {
        console.error(`Error in event listener for ${event}:`, e);
      }
    }
  }
}

// ============================================================================
// Liaison Agent
// ============================================================================

/**
 * Liaison agent that manages federation communication.
 */
export class LiaisonAgent {
  private readonly id: string;
  private readonly federationManager: FederationNodeManager;
  private readonly signalSharer: SignalSharer;
  private readonly zkGenerator: ZKProofGenerator;
  private readonly network: PeerNetwork;
  private readonly receivedSignals: Map<string, SharedSignal> = new Map();
  private readonly events: LiaisonEventEmitter;
  private readonly auditLog: MerkleTree;
  private federationState: FederationState;
  private bootstrapPeers: string[];
  private isRunning = false;

  constructor(config: LiaisonConfig) {
    this.id = generateSecureId();
    this.events = new SimpleLiaisonEventEmitter();
    this.auditLog = new MerkleTree();

    this.federationManager = new FederationNodeManager(config.federation);
    this.signalSharer = new SignalSharer(
      config.federation.nodeId,
      config.sharing ?? DEFAULT_SHARING_CONFIG
    );
    this.zkGenerator = new ZKProofGenerator();
    this.network = new PeerNetwork({
      ...DEFAULT_PEER_NETWORK_CONFIG,
      ...config.network,
      nodeId: config.federation.nodeId,
    });
    this.bootstrapPeers = config.bootstrapPeers ?? [];

    this.federationState = {
      connectedPeers: 0,
      knownPeers: 0,
      pendingProposals: 0,
      signalsShared: 0,
      signalsReceived: 0,
      networkStatus: 'disconnected',
    };

    this.setupNetworkHandlers();
    this.setupMessageHandlers();
  }

  /**
   * Set up network event handlers.
   */
  private setupNetworkHandlers(): void {
    this.network.on('peer_connected', (event: NetworkEvent) => {
      if (event.type === 'peer_connected' && event.peer) {
        this.handlePeerConnected(event.peer);
      }
    });

    this.network.on('peer_disconnected', (event: NetworkEvent) => {
      if (event.type === 'peer_disconnected' && event.peerId) {
        this.handlePeerDisconnected(event.peerId);
      }
    });

    this.network.on('message_received', (event: NetworkEvent) => {
      if (event.type === 'message_received' && event.message) {
        this.handleIncomingMessage(event.message);
      }
    });

    this.network.on('network_error', (event: NetworkEvent) => {
      if (event.type === 'network_error') {
        this.logAudit('network_error', { error: event.error });
      }
    });
  }

  /**
   * Set up federation message handlers.
   */
  private setupMessageHandlers(): void {
    this.federationManager.onMessage('threat_alert', (msg) => {
      this.handleThreatAlert(msg as FederationMessage<ThreatSignal>);
    });

    this.federationManager.onMessage('signal_share', (msg) => {
      this.handleSignalShare(msg as FederationMessage<SharedSignal>);
    });

    this.federationManager.onMessage('consensus_proposal', (msg) => {
      this.handleConsensusProposal(msg as FederationMessage<ConsensusProposal>);
    });

    this.federationManager.onMessage('consensus_vote', (msg) => {
      this.handleConsensusVote(msg as FederationMessage<{ proposalId: string; vote: 'approve' | 'reject' }>);
    });
  }

  /**
   * Start the liaison agent.
   */
  async start(): Promise<void> {
    if (this.isRunning) return;

    this.logAudit('liaison_starting', { nodeId: this.federationManager.getNodeInfo().id });

    // Start network
    await this.network.start();
    this.updateFederationState({ networkStatus: 'connecting' });
    this.isRunning = true;

    // Connect to bootstrap peers
    for (const peerAddress of this.bootstrapPeers) {
      try {
        await this.network.connectToPeer(peerAddress);
      } catch (error) {
        this.logAudit('bootstrap_peer_failed', { address: peerAddress, error: String(error) });
      }
    }
  }

  /**
   * Stop the liaison agent.
   */
  async stop(): Promise<void> {
    if (!this.isRunning) return;

    this.logAudit('liaison_stopping', { nodeId: this.federationManager.getNodeInfo().id });
    await this.network.stop();
    this.updateFederationState({ networkStatus: 'disconnected' });
    this.isRunning = false;
  }

  /**
   * Register an event handler.
   */
  on(event: string, handler: (...args: unknown[]) => void): void {
    this.events.on(event, handler);
  }

  /**
   * Process a task.
   */
  async processTask(task: LiaisonTask): Promise<TaskResult> {
    const taskData = task.payload;

    switch (taskData.type) {
      case 'share_signal':
        return this.handleShareSignalTask(task.id, taskData);

      case 'propose_consensus':
        return this.handleProposeConsensusTask(task.id, taskData);

      case 'query_peers':
        return this.handleQueryPeersTask(task.id, taskData);

      case 'sync_knowledge':
        return this.handleSyncKnowledgeTask(task.id, taskData);

      default:
        return {
          taskId: task.id,
          agentId: this.id,
          status: 'failed',
          error: `Unknown task type: ${(taskData as { type: string }).type}`,
          startedAt: new Date(),
          completedAt: new Date(),
        };
    }
  }

  // ============================================================================
  // Task Handlers
  // ============================================================================

  private async handleShareSignalTask(
    taskId: string,
    task: SignalShareTask
  ): Promise<TaskResult> {
    const startedAt = new Date();

    try {
      // Prepare signal for privacy-preserving sharing
      const sharedSignal = this.signalSharer.prepareForSharing(
        task.signal,
        this.federationManager.getNodeInfo().region
      );

      if (!sharedSignal) {
        return {
          taskId,
          agentId: this.id,
          status: 'completed',
          output: { shared: false, reason: 'Below confidence threshold' },
          startedAt,
          completedAt: new Date(),
        };
      }

      // Create message with ZK proof for high-severity signals
      let zkProof: string | undefined;
      if (task.signal.severity === 'critical' || task.signal.severity === 'high') {
        const proof = this.zkGenerator.proveThresholdExceeded(
          task.signal.confidence,
          0.8,
          task.signal.id
        );
        zkProof = JSON.stringify(proof);
      }

      // Broadcast or send to specific peers
      if (task.targetPeers && task.targetPeers.length > 0) {
        for (const peerId of task.targetPeers) {
          const message = this.federationManager.createMessage('signal_share', sharedSignal, peerId);
          if (zkProof) {
            (message as FederationMessage & { zkProof: string }).zkProof = zkProof;
          }
          await this.network.sendMessage(peerId, message);
        }
      } else {
        const message = this.federationManager.createMessage('signal_share', sharedSignal, 'broadcast');
        if (zkProof) {
          (message as FederationMessage & { zkProof: string }).zkProof = zkProof;
        }
        await this.network.broadcast(message);
      }

      this.updateFederationState({
        signalsShared: this.federationState.signalsShared + 1,
      });

      this.logAudit('signal_shared', {
        signalId: task.signal.id,
        type: task.signal.type,
        severity: task.signal.severity,
        targetPeers: task.targetPeers ?? 'broadcast',
      });

      return {
        taskId,
        agentId: this.id,
        status: 'completed',
        output: { shared: true, signalIdHash: sharedSignal.signalIdHash },
        startedAt,
        completedAt: new Date(),
      };
    } catch (error) {
      return {
        taskId,
        agentId: this.id,
        status: 'failed',
        error: String(error),
        startedAt,
        completedAt: new Date(),
      };
    }
  }

  private async handleProposeConsensusTask(
    taskId: string,
    task: ProposeConsensusTask
  ): Promise<TaskResult> {
    const startedAt = new Date();

    try {
      const proposal = this.federationManager.proposeConsensus(task.proposalType, task.data);

      // Broadcast proposal to network
      const message = this.federationManager.createMessage('consensus_proposal', proposal, 'broadcast');
      await this.network.broadcast(message);

      this.updateFederationState({
        pendingProposals: this.federationManager.getPendingProposals().length,
      });

      this.logAudit('consensus_proposed', {
        proposalId: proposal.id,
        type: proposal.type,
      });

      return {
        taskId,
        agentId: this.id,
        status: 'completed',
        output: { proposalId: proposal.id, status: proposal.status },
        startedAt,
        completedAt: new Date(),
      };
    } catch (error) {
      return {
        taskId,
        agentId: this.id,
        status: 'failed',
        error: String(error),
        startedAt,
        completedAt: new Date(),
      };
    }
  }

  private async handleQueryPeersTask(
    taskId: string,
    task: QueryPeersTask
  ): Promise<TaskResult> {
    const startedAt = new Date();

    try {
      // Filter received signals based on query
      const matchingSignals = Array.from(this.receivedSignals.values()).filter((signal) => {
        if (task.query.type && signal.type !== task.query.type) return false;
        if (task.query.severity && signal.severity !== task.query.severity) return false;
        if (task.query.since && signal.sharedAt < task.query.since) return false;
        return true;
      });

      // Aggregate results
      const aggregation = this.signalSharer.aggregateSignals(matchingSignals);

      return {
        taskId,
        agentId: this.id,
        status: 'completed',
        output: {
          signals: matchingSignals,
          aggregation: {
            totalSignals: aggregation.totalSignals,
            byType: Object.fromEntries(aggregation.byType),
            bySeverity: Object.fromEntries(aggregation.bySeverity),
            byRegion: Object.fromEntries(aggregation.byRegion),
            avgConfidence: aggregation.avgConfidence,
          },
        },
        startedAt,
        completedAt: new Date(),
      };
    } catch (error) {
      return {
        taskId,
        agentId: this.id,
        status: 'failed',
        error: String(error),
        startedAt,
        completedAt: new Date(),
      };
    }
  }

  private async handleSyncKnowledgeTask(
    taskId: string,
    task: SyncKnowledgeTask
  ): Promise<TaskResult> {
    const startedAt = new Date();

    try {
      // Request knowledge sync from all connected peers
      const message = this.federationManager.createMessage(
        'signal_share',
        { syncRequest: true, domain: task.domain },
        'broadcast'
      );
      await this.network.broadcast(message);

      this.updateFederationState({
        lastSyncAt: new Date(),
      });

      this.logAudit('knowledge_sync_requested', { domain: task.domain });

      return {
        taskId,
        agentId: this.id,
        status: 'completed',
        output: { domain: task.domain, requested: true },
        startedAt,
        completedAt: new Date(),
      };
    } catch (error) {
      return {
        taskId,
        agentId: this.id,
        status: 'failed',
        error: String(error),
        startedAt,
        completedAt: new Date(),
      };
    }
  }

  // ============================================================================
  // Network Event Handlers
  // ============================================================================

  private handlePeerConnected(peer: FederationNode): void {
    this.federationManager.registerPeer(peer);

    this.updateFederationState({
      connectedPeers: this.federationManager.getActivePeerCount(),
      knownPeers: this.federationManager.getPeers().length,
      networkStatus: 'connected',
    });

    this.logAudit('peer_connected', {
      peerId: peer.id,
      region: peer.region,
    });

    // Emit event for orchestrator
    this.events.emit('peer_connected', { peer });
  }

  private handlePeerDisconnected(peerId: string): void {
    this.federationManager.removePeer(peerId);

    const activePeers = this.federationManager.getActivePeerCount();
    this.updateFederationState({
      connectedPeers: activePeers,
      networkStatus: activePeers > 0 ? 'connected' : 'disconnected',
    });

    this.logAudit('peer_disconnected', { peerId });

    // Emit event
    this.events.emit('peer_disconnected', { peerId });
  }

  private handleIncomingMessage(message: FederationMessage): void {
    this.federationManager.handleMessage(message);
  }

  // ============================================================================
  // Message Handlers
  // ============================================================================

  private handleThreatAlert(message: FederationMessage<ThreatSignal>): void {
    this.logAudit('threat_alert_received', {
      from: message.senderId,
      signalId: message.payload.id,
      type: message.payload.type,
      severity: message.payload.severity,
    });

    // Emit for other agents to process
    this.events.emit('threat_alert', { signal: message.payload, from: message.senderId });
  }

  private handleSignalShare(message: FederationMessage<SharedSignal>): void {
    const signal = message.payload;

    // Store received signal
    this.receivedSignals.set(signal.signalIdHash, signal);

    this.updateFederationState({
      signalsReceived: this.federationState.signalsReceived + 1,
    });

    this.logAudit('signal_received', {
      from: message.senderId,
      signalIdHash: signal.signalIdHash,
      type: signal.type,
      severity: signal.severity,
    });

    // Emit for correlation
    this.events.emit('signal_received', { signal, from: message.senderId });
  }

  private handleConsensusProposal(message: FederationMessage<ConsensusProposal>): void {
    const proposal = message.payload;

    this.logAudit('consensus_proposal_received', {
      from: message.senderId,
      proposalId: proposal.id,
      type: proposal.type,
    });

    // Emit for decision
    this.events.emit('consensus_proposal', { proposal, from: message.senderId });
  }

  private handleConsensusVote(
    message: FederationMessage<{ proposalId: string; vote: 'approve' | 'reject' }>
  ): void {
    const { proposalId, vote } = message.payload;

    this.logAudit('consensus_vote_received', {
      from: message.senderId,
      proposalId,
      vote,
    });

    // Emit for tracking
    this.events.emit('consensus_vote', { proposalId, vote, from: message.senderId });
  }

  // ============================================================================
  // Public API
  // ============================================================================

  /**
   * Get agent ID.
   */
  getId(): string {
    return this.id;
  }

  /**
   * Check if agent is running.
   */
  isActive(): boolean {
    return this.isRunning;
  }

  /**
   * Get current federation state.
   */
  getFederationState(): FederationState {
    return { ...this.federationState };
  }

  /**
   * Get this node's info.
   */
  getNodeInfo(): FederationNode {
    return this.federationManager.getNodeInfo();
  }

  /**
   * Get list of connected peers.
   */
  getConnectedPeers(): FederationNode[] {
    return this.federationManager.getPeers();
  }

  /**
   * Get pending consensus proposals.
   */
  getPendingProposals(): ConsensusProposal[] {
    return this.federationManager.getPendingProposals();
  }

  /**
   * Vote on a proposal.
   */
  async voteOnProposal(proposalId: string, vote: 'approve' | 'reject'): Promise<void> {
    this.federationManager.voteOnProposal(proposalId, vote);

    // Broadcast vote
    const message = this.federationManager.createMessage(
      'consensus_vote',
      { proposalId, vote },
      'broadcast'
    );
    await this.network.broadcast(message);

    this.logAudit('consensus_voted', { proposalId, vote });
  }

  /**
   * Get received signals.
   */
  getReceivedSignals(): SharedSignal[] {
    return Array.from(this.receivedSignals.values());
  }

  /**
   * Connect to a new peer.
   */
  async connectToPeer(address: string): Promise<void> {
    await this.network.connectToPeer(address);
  }

  // ============================================================================
  // Helpers
  // ============================================================================

  private updateFederationState(updates: Partial<FederationState>): void {
    this.federationState = { ...this.federationState, ...updates };
  }

  private logAudit(action: string, data: Record<string, unknown>): void {
    this.auditLog.append(JSON.stringify({
      timestamp: new Date().toISOString(),
      agentId: this.id,
      action,
      ...data,
    }));
  }
}

// ============================================================================
// Default Configuration
// ============================================================================

export function createDefaultLiaisonConfig(
  nodeId: string,
  region: string,
  publicKey: string
): LiaisonConfig {
  return {
    nodeId,
    region,
    publicKey,
    federation: {
      nodeId,
      region,
      ...DEFAULT_FEDERATION_CONFIG,
    },
    sharing: DEFAULT_SHARING_CONFIG,
  };
}
