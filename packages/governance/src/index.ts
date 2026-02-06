/**
 * AI Authority - Governance Package
 * 
 * Governance agents for autonomous knowledge evolution.
 */

// Proposer agent
export { ProposerAgent } from './proposer.js';
export type { Proposal, ProposalType, SimulationResult } from './proposer.js';

// Approver agent
export { ApproverAgent } from './approver.js';
export type { ProposalVote, SimulationConfig } from './approver.js';

// Curator agent
export { CuratorAgent } from './curator.js';
export type { SynthesisResult, SynthesizedItem } from './curator.js';
