/**
 * Case Management System
 *
 * Manages cases for human review with full audit trail.
 */

import type { ThreatSignal, RiskScore } from '@ai-authority/core';
import { MerkleTree, sha256 } from '@ai-authority/core';

// ============================================================================
// Types
// ============================================================================

export type CaseStatus =
  | 'pending_review'
  | 'under_review'
  | 'voting'
  | 'decided'
  | 'appealed'
  | 'closed';

export type CaseDecision =
  | 'no_action'
  | 'advisory'
  | 'throttle'
  | 'revoke'
  | 'escalate';

export interface CaseSummary {
  /** Case ID */
  readonly id: string;

  /** Subject agent */
  readonly agentId: string;

  /** Triggering threat signal */
  readonly signalId: string;

  /** Risk score that triggered escalation */
  readonly riskScore: RiskScore;

  /** Current status */
  status: CaseStatus;

  /** Assigned reviewers */
  assignedReviewers: string[];

  /** Created timestamp */
  readonly createdAt: Date;

  /** Last updated */
  updatedAt: Date;

  /** Final decision (if decided) */
  decision?: CaseDecision;

  /** Appeal deadline (if applicable) */
  appealDeadline?: Date;
}

export interface CaseEvidence {
  /** Evidence ID */
  readonly id: string;

  /** Case ID */
  readonly caseId: string;

  /** Evidence type */
  readonly type: 'threat_signal' | 'behavior_log' | 'external_report' | 'reviewer_note';

  /** Evidence content (serialized) */
  readonly content: string;

  /** Content hash for integrity */
  readonly contentHash: string;

  /** Submitted by */
  readonly submittedBy: string;

  /** Submission timestamp */
  readonly submittedAt: Date;
}

export interface CaseConfig {
  /** Minimum reviewers required */
  readonly minReviewers: number;

  /** Quorum for decision (e.g., 3 of 5) */
  readonly quorumSize: number;

  /** Review timeout in hours */
  readonly reviewTimeoutHours: number;

  /** Appeal window in hours */
  readonly appealWindowHours: number;

  /** Auto-escalate after timeout */
  readonly autoEscalateOnTimeout: boolean;
}

/** Audit entry for case actions */
export interface CaseAuditEntry {
  /** Entry ID */
  readonly id: string;

  /** Action performed */
  readonly action: string;

  /** Actor who performed the action */
  readonly actorId: string;

  /** Target case ID */
  readonly caseId: string;

  /** Timestamp */
  readonly timestamp: Date;

  /** Additional details */
  readonly details: Record<string, unknown>;
}

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_CASE_CONFIG: CaseConfig = {
  minReviewers: 5,
  quorumSize: 3,
  reviewTimeoutHours: 72,
  appealWindowHours: 24,
  autoEscalateOnTimeout: true,
};

// ============================================================================
// Case Manager
// ============================================================================

/**
 * Manages the lifecycle of adjudication cases.
 */
export class CaseManager {
  private readonly cases: Map<string, CaseSummary> = new Map();
  private readonly evidence: Map<string, CaseEvidence[]> = new Map();
  private readonly auditTree: MerkleTree;
  private readonly auditEntries: CaseAuditEntry[] = [];
  private readonly config: CaseConfig;
  private readonly reviewerPool: Set<string> = new Set();

  constructor(config: CaseConfig = DEFAULT_CASE_CONFIG) {
    this.config = config;
    this.auditTree = new MerkleTree('case-audit-log');
  }

  /**
   * Create a new case for review.
   */
  async createCase(
    agentId: string,
    signal: ThreatSignal,
    riskScore: RiskScore,
    creatorId: string
  ): Promise<CaseSummary> {
    const id = `CASE-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;

    const caseSummary: CaseSummary = {
      id,
      agentId,
      signalId: signal.id,
      riskScore,
      status: 'pending_review',
      assignedReviewers: [],
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.cases.set(id, caseSummary);
    this.evidence.set(id, []);

    // Add initial evidence
    await this.addEvidence(id, 'threat_signal', JSON.stringify(signal), creatorId);

    // Log creation
    this.logAuditEntry(id, 'case_created', creatorId, {
      agentId,
      signalId: signal.id,
      riskTier: riskScore.tier,
    });

    return caseSummary;
  }

  /**
   * Add a reviewer to the pool.
   */
  addReviewer(reviewerId: string): void {
    this.reviewerPool.add(reviewerId);
  }

  /**
   * Remove a reviewer from the pool.
   */
  removeReviewer(reviewerId: string): void {
    this.reviewerPool.delete(reviewerId);
  }

  /**
   * Assign reviewers to a case.
   */
  async assignReviewers(caseId: string, assignerId: string): Promise<string[]> {
    const caseSummary = this.cases.get(caseId);
    if (!caseSummary) {
      throw new Error(`Case not found: ${caseId}`);
    }

    if (this.reviewerPool.size < this.config.minReviewers) {
      throw new Error(
        `Insufficient reviewers in pool: ${this.reviewerPool.size}/${this.config.minReviewers}`
      );
    }

    // Randomly select reviewers
    const available = Array.from(this.reviewerPool);
    const selected: string[] = [];
    const used = new Set<number>();

    while (selected.length < this.config.minReviewers) {
      const idx = Math.floor(Math.random() * available.length);
      if (!used.has(idx)) {
        used.add(idx);
        const reviewer = available[idx];
        if (reviewer !== undefined) {
          selected.push(reviewer);
        }
      }
    }

    caseSummary.assignedReviewers = selected;
    caseSummary.status = 'under_review';
    caseSummary.updatedAt = new Date();

    this.logAuditEntry(caseId, 'reviewers_assigned', assignerId, {
      reviewers: selected,
    });

    return selected;
  }

  /**
   * Add evidence to a case.
   */
  async addEvidence(
    caseId: string,
    type: CaseEvidence['type'],
    content: string,
    submitterId: string
  ): Promise<CaseEvidence> {
    const caseSummary = this.cases.get(caseId);
    if (!caseSummary) {
      throw new Error(`Case not found: ${caseId}`);
    }

    const evidenceId = `EV-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;

    const evidence: CaseEvidence = {
      id: evidenceId,
      caseId,
      type,
      content,
      contentHash: sha256(content),
      submittedBy: submitterId,
      submittedAt: new Date(),
    };

    const caseEvidence = this.evidence.get(caseId) ?? [];
    caseEvidence.push(evidence);
    this.evidence.set(caseId, caseEvidence);

    caseSummary.updatedAt = new Date();

    this.logAuditEntry(caseId, 'evidence_added', submitterId, {
      evidenceId,
      type,
      contentHash: evidence.contentHash,
    });

    return evidence;
  }

  /**
   * Start voting phase.
   */
  async startVoting(caseId: string, initiatorId: string): Promise<void> {
    const caseSummary = this.cases.get(caseId);
    if (!caseSummary) {
      throw new Error(`Case not found: ${caseId}`);
    }

    if (caseSummary.status !== 'under_review') {
      throw new Error(`Case not in review status: ${caseSummary.status}`);
    }

    if (caseSummary.assignedReviewers.length < this.config.minReviewers) {
      throw new Error('Insufficient reviewers assigned');
    }

    caseSummary.status = 'voting';
    caseSummary.updatedAt = new Date();

    this.logAuditEntry(caseId, 'voting_started', initiatorId, {});
  }

  /**
   * Get case by ID.
   */
  getCase(caseId: string): CaseSummary | undefined {
    return this.cases.get(caseId);
  }

  /**
   * Get all evidence for a case.
   */
  getCaseEvidence(caseId: string): CaseEvidence[] {
    return this.evidence.get(caseId) ?? [];
  }

  /**
   * Get all cases by status.
   */
  getCasesByStatus(status: CaseStatus): CaseSummary[] {
    return Array.from(this.cases.values()).filter((c) => c.status === status);
  }

  /**
   * Get cases assigned to a reviewer.
   */
  getCasesForReviewer(reviewerId: string): CaseSummary[] {
    return Array.from(this.cases.values()).filter((c) =>
      c.assignedReviewers.includes(reviewerId)
    );
  }

  /**
   * Record final decision.
   */
  async recordDecision(
    caseId: string,
    decision: CaseDecision,
    deciderId: string
  ): Promise<void> {
    const caseSummary = this.cases.get(caseId);
    if (!caseSummary) {
      throw new Error(`Case not found: ${caseId}`);
    }

    caseSummary.status = 'decided';
    caseSummary.decision = decision;
    caseSummary.updatedAt = new Date();

    // Set appeal deadline
    caseSummary.appealDeadline = new Date(
      Date.now() + this.config.appealWindowHours * 60 * 60 * 1000
    );

    this.logAuditEntry(caseId, 'decision_recorded', deciderId, {
      decision,
      appealDeadline: caseSummary.appealDeadline.toISOString(),
    });
  }

  /**
   * File an appeal.
   */
  async fileAppeal(caseId: string, reason: string, appellantId: string): Promise<void> {
    const caseSummary = this.cases.get(caseId);
    if (!caseSummary) {
      throw new Error(`Case not found: ${caseId}`);
    }

    if (caseSummary.status !== 'decided') {
      throw new Error(`Case not in decided status: ${caseSummary.status}`);
    }

    if (caseSummary.appealDeadline && new Date() > caseSummary.appealDeadline) {
      throw new Error('Appeal deadline has passed');
    }

    caseSummary.status = 'appealed';
    caseSummary.updatedAt = new Date();

    await this.addEvidence(caseId, 'reviewer_note', `APPEAL: ${reason}`, appellantId);

    this.logAuditEntry(caseId, 'appeal_filed', appellantId, { reason });
  }

  /**
   * Close a case.
   */
  async closeCase(caseId: string, closerId: string, reason: string): Promise<void> {
    const caseSummary = this.cases.get(caseId);
    if (!caseSummary) {
      throw new Error(`Case not found: ${caseId}`);
    }

    caseSummary.status = 'closed';
    caseSummary.updatedAt = new Date();

    this.logAuditEntry(caseId, 'case_closed', closerId, { reason });
  }

  /**
   * Get audit trail.
   */
  getAuditTrail(): readonly CaseAuditEntry[] {
    return this.auditEntries;
  }

  /**
   * Get audit tree root for verification.
   */
  getAuditRoot(): string {
    return this.auditTree.getRoot();
  }

  /**
   * Get configuration.
   */
  getConfig(): CaseConfig {
    return this.config;
  }

  /**
   * Log an audit entry.
   */
  private logAuditEntry(
    caseId: string,
    action: string,
    actorId: string,
    details: Record<string, unknown>
  ): void {
    const entry: CaseAuditEntry = {
      id: `AUDIT-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date(),
      action,
      actorId,
      caseId,
      details,
    };

    this.auditEntries.push(entry);
    this.auditTree.append(JSON.stringify(entry));
  }
}
