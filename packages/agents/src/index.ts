/**
 * AI Authority - Agents Package
 * 
 * Core agent infrastructure for autonomous AI Authority network.
 */

// Types
export * from './types.js';

// Base agent
export { BaseAgent } from './base.js';

// Messaging
export { MessageBus, createMessageBus } from './messaging.js';
export type { MessageHandler, MessageBusConfig } from './messaging.js';

// Orchestrator
export { AgentOrchestrator, createOrchestrator } from './orchestrator.js';
export type { OrchestratorConfig, AgentFactory, OrchestratorState } from './orchestrator.js';
