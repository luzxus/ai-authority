/**
 * @ai-authority/adjudication
 *
 * Human-in-the-loop case management and voting system.
 */

export {
  // Case types
  type CaseStatus,
  type CaseDecision,
  type CaseSummary,
  type CaseEvidence,
  type CaseConfig,
  // Classes
  CaseManager,
  // Constants
  DEFAULT_CASE_CONFIG,
} from './cases.js';

export {
  // Voting types
  type SignedVote,
  type VotingSession,
  type VotingConfig,
  type VoteTally,
  // Classes
  VotingManager,
  VoteAggregator,
  // Constants
  DEFAULT_VOTING_CONFIG,
} from './voting.js';

export {
  // Reviewer types
  type ReviewerStatus,
  type ReviewerRole,
  type ReviewerProfile,
  type ReviewerQualifications,
  type ConflictOfInterest,
  // Classes
  ReviewerManager,
} from './reviewers.js';

export { WatchdogAgent } from './watchdog.js';
export type {
  BiasCategory,
  BiasMetric,
  BiasAlert,
  CorrectionAction,
  FairnessAudit,
  FairnessMetrics,
  FairnessViolation,
  DecisionRecord,
  WatchdogConfig,
} from './watchdog.js';

export { AuditorAgent } from './auditor.js';
export type {
  CompliancePolicy,
  ComplianceRule,
  RuleCondition,
  AuditableAction,
  ActionResult,
  AuditRecord,
  ComplianceCheck,
  AuditVerdict,
  Violation,
  AuditReport,
  AuditSummary,
  AuditorConfig,
} from './auditor.js';
