/**
 * Agent Types and Interfaces
 * 
 * Defines the core types for the autonomous agent system.
 */

import type { SignedData } from '@ai-authority/core';

/** Agent layers in the system architecture */
export type AgentLayer = 
  | 'sensing'      // Scout, Sensor, Learner
  | 'analysis'     // Analyzer, Forensic, Reflector
  | 'decision'     // Enforcer, Watchdog, Auditor
  | 'governance';  // Proposer, Approver, Curator

/** Agent role types */
export type AgentRole =
  // Sensing layer
  | 'scout'       // Explore networks, discover anomalies
  | 'sensor'      // Monitor signals, collect telemetry
  | 'learner'     // Bootstrap knowledge, RL updates
  // Analysis layer
  | 'analyzer'    // Behavioral probing, self-play
  | 'forensic'    // Attribution, obfuscation reversal
  | 'reflector'   // Evaluate efficacy, propose updates
  // Decision layer
  | 'enforcer'    // Execute interventions
  | 'watchdog'    // Monitor bias, trigger corrections
  | 'auditor'     // Compliance checks, verify actions
  // Governance layer
  | 'proposer'    // Suggest knowledge/architecture changes
  | 'approver'    // Validate proposals via simulation
  | 'curator';    // Synthesize knowledge, encode rules

/** Agent lifecycle states */
export type AgentState =
  | 'initializing'
  | 'ready'
  | 'running'
  | 'paused'
  | 'error'
  | 'terminated';

/** Agent identity */
export interface AgentIdentity {
  readonly id: string;
  readonly role: AgentRole;
  readonly layer: AgentLayer;
  readonly publicKey: string;
  readonly nodeId: string;
  readonly createdAt: number;
}

/** Agent capabilities by role */
export interface AgentCapabilities {
  canRead: string[];      // Knowledge domains readable
  canWrite: string[];     // Knowledge domains writable
  canExecute: string[];   // Actions executable
  canPropose: boolean;    // Can propose changes
  canApprove: boolean;    // Can approve changes
  canIntervene: boolean;  // Can execute interventions
  maxInterventionTier: number; // Maximum intervention tier allowed
}

/** Message types for inter-agent communication */
export type MessageType =
  | 'signal'           // Anomaly signal from sensors
  | 'analysis'         // Analysis result
  | 'attribution'      // Attribution finding
  | 'intervention'     // Intervention request/result
  | 'proposal'         // Knowledge/architecture proposal
  | 'vote'             // Consensus vote
  | 'audit'            // Audit trail entry
  | 'heartbeat'        // Health check
  | 'knowledge_update' // Knowledge base update
  | 'command';         // Control command

/** Inter-agent message */
export interface AgentMessage<T = unknown> {
  id: string;
  type: MessageType;
  from: string;          // Agent ID
  to: string | 'broadcast';
  payload: T;
  timestamp: number;
  signature: string;
  correlationId?: string | undefined;
  replyTo?: string | undefined;
}

/** Signed agent message envelope */
export type SignedAgentMessage<T = unknown> = SignedData<AgentMessage<T>>;

/** Agent configuration */
export interface AgentConfig {
  role: AgentRole;
  nodeId: string;
  privateKey: string;
  publicKey: string;
  capabilities: AgentCapabilities;
  knowledgeEndpoints: string[];
  peerAgents: string[];
  heartbeatIntervalMs: number;
  maxConcurrentTasks: number;
}

/** Agent metrics */
export interface AgentMetrics {
  agentId: string;
  uptime: number;
  tasksProcessed: number;
  tasksFailed: number;
  messagesReceived: number;
  messagesSent: number;
  lastHeartbeat: number;
  averageLatencyMs: number;
  knowledgeQueriesPerSec: number;
  detectionAccuracy?: number | undefined;
  falsePositiveRate?: number | undefined;
}

/** Task definition for agent processing */
export interface AgentTask<T = unknown> {
  id: string;
  type: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  payload: T;
  createdAt: number;
  deadline?: number | undefined;
  retries: number;
  maxRetries: number;
  correlationId?: string | undefined;
}

/** Task result */
export interface TaskResult<T = unknown> {
  taskId: string;
  success: boolean;
  result?: T | undefined;
  error?: string | undefined;
  duration: number;
  timestamp: number;
}

/** Consensus request for high-impact decisions */
export interface ConsensusRequest {
  id: string;
  type: 'intervention' | 'knowledge_update' | 'architecture_change';
  proposer: string;
  proposal: unknown;
  requiredApprovals: number;
  deadline: number;
  votes: ConsensusVote[];
}

/** Consensus vote */
export interface ConsensusVote {
  voterId: string;
  approve: boolean;
  reason?: string | undefined;
  timestamp: number;
  signature: string;
}

/** Knowledge query */
export interface KnowledgeQuery {
  type: 'embedding' | 'rule' | 'fingerprint' | 'pattern';
  query: string | number[];
  threshold?: number | undefined;
  maxResults?: number | undefined;
  filters?: Record<string, unknown> | undefined;
}

/** Knowledge query result */
export interface KnowledgeResult {
  matches: KnowledgeMatch[];
  queryTime: number;
  totalSearched: number;
}

/** Knowledge match */
export interface KnowledgeMatch {
  id: string;
  type: string;
  score: number;
  data: unknown;
  metadata: Record<string, unknown>;
}

/** Get layer for a role */
export function getLayerForRole(role: AgentRole): AgentLayer {
  switch (role) {
    case 'scout':
    case 'sensor':
    case 'learner':
      return 'sensing';
    case 'analyzer':
    case 'forensic':
    case 'reflector':
      return 'analysis';
    case 'enforcer':
    case 'watchdog':
    case 'auditor':
      return 'decision';
    case 'proposer':
    case 'approver':
    case 'curator':
      return 'governance';
  }
}

/** Get default capabilities for a role */
export function getDefaultCapabilities(role: AgentRole): AgentCapabilities {
  const base: AgentCapabilities = {
    canRead: ['public'],
    canWrite: [],
    canExecute: [],
    canPropose: false,
    canApprove: false,
    canIntervene: false,
    maxInterventionTier: 0,
  };

  switch (role) {
    case 'scout':
      return { ...base, canRead: ['public', 'network'], canExecute: ['explore', 'probe'] };
    case 'sensor':
      return { ...base, canRead: ['public', 'signals'], canWrite: ['signals'], canExecute: ['monitor'] };
    case 'learner':
      return { ...base, canRead: ['public', 'knowledge'], canWrite: ['knowledge_draft'], canExecute: ['train'] };
    case 'analyzer':
      return { ...base, canRead: ['public', 'signals', 'knowledge'], canExecute: ['analyze', 'simulate'] };
    case 'forensic':
      return { ...base, canRead: ['public', 'signals', 'knowledge', 'audit'], canExecute: ['attribute', 'trace'] };
    case 'reflector':
      return { ...base, canRead: ['public', 'knowledge', 'metrics'], canPropose: true };
    case 'enforcer':
      return { ...base, canRead: ['public', 'analysis'], canIntervene: true, maxInterventionTier: 3 };
    case 'watchdog':
      return { ...base, canRead: ['public', 'knowledge', 'metrics', 'audit'], canExecute: ['correct'] };
    case 'auditor':
      return { ...base, canRead: ['public', 'audit', 'actions'] };
    case 'proposer':
      return { ...base, canRead: ['public', 'knowledge'], canPropose: true };
    case 'approver':
      return { ...base, canRead: ['public', 'knowledge', 'proposals'], canApprove: true, canExecute: ['simulate'] };
    case 'curator':
      return { ...base, canRead: ['public', 'knowledge'], canWrite: ['knowledge'], canExecute: ['encode'] };
  }
}
