/**
 * Appeal Management
 *
 * Handles appeals against interventions with time-limited windows.
 */

import { MerkleTree, sha256 } from '@ai-authority/core';
import type { InterventionRecord } from './actions.js';

// ============================================================================
// Types
// ============================================================================

export type AppealStatus =
  | 'pending'
  | 'under_review'
  | 'granted'
  | 'denied'
  | 'partial'
  | 'withdrawn'
  | 'expired';

export type AppealGrounds =
  | 'factual_error'
  | 'procedural_violation'
  | 'new_evidence'
  | 'proportionality'
  | 'mistaken_identity'
  | 'other';

export interface Appeal {
  /** Appeal ID */
  readonly id: string;

  /** Intervention being appealed */
  readonly interventionId: string;

  /** Appellant ID (agent owner or representative) */
  readonly appellantId: string;

  /** Appeal grounds */
  readonly grounds: AppealGrounds;

  /** Detailed argument */
  readonly argument: string;

  /** Supporting evidence references */
  readonly evidenceRefs: string[];

  /** Current status */
  status: AppealStatus;

  /** Created timestamp */
  readonly createdAt: Date;

  /** Review deadline */
  readonly reviewDeadline: Date;

  /** Assigned reviewers */
  assignedReviewers: string[];

  /** Decision (if decided) */
  decision?: AppealDecision;
}

export interface AppealDecision {
  /** Outcome */
  readonly outcome: 'grant' | 'deny' | 'partial';

  /** Decider ID */
  readonly decidedBy: string;

  /** Decision timestamp */
  readonly decidedAt: Date;

  /** Rationale */
  readonly rationale: string;

  /** Modifications (for partial grants) */
  modifications?: string[];
}

export interface AppealConfig {
  /** Window for filing appeals (hours) */
  readonly appealWindowHours: number;

  /** Deadline for review (hours after filing) */
  readonly reviewDeadlineHours: number;

  /** Minimum reviewers for appeal */
  readonly minReviewers: number;

  /** Auto-grant if deadline passes without decision */
  readonly autoGrantOnExpiry: boolean;
}

/** Audit entry for appeal actions */
export interface AppealAuditEntry {
  /** Entry ID */
  readonly id: string;

  /** Action performed */
  readonly action: string;

  /** Actor who performed the action */
  readonly actorId: string;

  /** Target appeal ID */
  readonly appealId: string;

  /** Timestamp */
  readonly timestamp: Date;

  /** Additional details */
  readonly details: Record<string, unknown>;
}

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_APPEAL_CONFIG: AppealConfig = {
  appealWindowHours: 24,
  reviewDeadlineHours: 72,
  minReviewers: 3,
  autoGrantOnExpiry: false,
};

// ============================================================================
// Appeal Manager
// ============================================================================

/**
 * Manages the appeal process for interventions.
 */
export class AppealManager {
  private readonly appeals: Map<string, Appeal> = new Map();
  private readonly auditTree: MerkleTree;
  private readonly auditEntries: AppealAuditEntry[] = [];
  private readonly config: AppealConfig;

  constructor(config: AppealConfig = DEFAULT_APPEAL_CONFIG) {
    this.config = config;
    this.auditTree = new MerkleTree('appeal-audit-log');
  }

  /**
   * File an appeal against an intervention.
   */
  async fileAppeal(
    intervention: InterventionRecord,
    appellantId: string,
    grounds: AppealGrounds,
    argument: string,
    evidenceRefs: string[] = []
  ): Promise<Appeal> {
    // Check if appeal window is still open
    const now = new Date();
    if (now > intervention.appealDeadline) {
      throw new Error('Appeal window has closed');
    }

    // Check for existing appeal
    const existingAppeal = this.getAppealForIntervention(intervention.id);
    if (existingAppeal) {
      throw new Error(`Appeal already exists: ${existingAppeal.id}`);
    }

    // Validate argument
    if (!argument || argument.length < 100) {
      throw new Error('Appeal argument must be at least 100 characters');
    }

    const id = `APPEAL-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;

    const appeal: Appeal = {
      id,
      interventionId: intervention.id,
      appellantId,
      grounds,
      argument,
      evidenceRefs,
      status: 'pending',
      createdAt: now,
      reviewDeadline: new Date(now.getTime() + this.config.reviewDeadlineHours * 60 * 60 * 1000),
      assignedReviewers: [],
    };

    this.appeals.set(id, appeal);

    this.logAuditEntry(id, 'appeal_filed', appellantId, {
      interventionId: intervention.id,
      grounds,
    });

    return appeal;
  }

  /**
   * Assign reviewers to an appeal.
   */
  async assignReviewers(appealId: string, reviewerIds: string[], assignerId: string): Promise<void> {
    const appeal = this.appeals.get(appealId);
    if (!appeal) {
      throw new Error(`Appeal not found: ${appealId}`);
    }

    if (appeal.status !== 'pending') {
      throw new Error(`Appeal not pending: ${appeal.status}`);
    }

    if (reviewerIds.length < this.config.minReviewers) {
      throw new Error(
        `Insufficient reviewers: ${reviewerIds.length}/${this.config.minReviewers}`
      );
    }

    appeal.assignedReviewers = reviewerIds;
    appeal.status = 'under_review';

    this.logAuditEntry(appealId, 'reviewers_assigned', assignerId, {
      reviewers: reviewerIds,
    });
  }

  /**
   * Record an appeal decision.
   */
  async recordDecision(
    appealId: string,
    outcome: AppealDecision['outcome'],
    rationale: string,
    deciderId: string,
    modifications?: string[]
  ): Promise<AppealDecision> {
    const appeal = this.appeals.get(appealId);
    if (!appeal) {
      throw new Error(`Appeal not found: ${appealId}`);
    }

    if (appeal.status !== 'under_review') {
      throw new Error(`Appeal not under review: ${appeal.status}`);
    }

    const decision: AppealDecision = {
      outcome,
      decidedBy: deciderId,
      decidedAt: new Date(),
      rationale,
    };

    // Only add modifications if provided
    if (modifications && modifications.length > 0) {
      (decision as { modifications: string[] }).modifications = modifications;
    }

    appeal.decision = decision;
    appeal.status = outcome === 'grant' ? 'granted' : outcome === 'deny' ? 'denied' : 'partial';

    this.logAuditEntry(appealId, 'decision_recorded', deciderId, {
      outcome,
      rationale: rationale.substring(0, 100), // Truncate for audit
    });

    return decision;
  }

  /**
   * Withdraw an appeal.
   */
  async withdrawAppeal(appealId: string, appellantId: string, reason: string): Promise<void> {
    const appeal = this.appeals.get(appealId);
    if (!appeal) {
      throw new Error(`Appeal not found: ${appealId}`);
    }

    if (appeal.appellantId !== appellantId) {
      throw new Error('Only appellant can withdraw appeal');
    }

    if (appeal.status === 'granted' || appeal.status === 'denied' || appeal.status === 'partial') {
      throw new Error(`Cannot withdraw decided appeal: ${appeal.status}`);
    }

    appeal.status = 'withdrawn';

    this.logAuditEntry(appealId, 'appeal_withdrawn', appellantId, { reason });
  }

  /**
   * Get appeal by ID.
   */
  getAppeal(appealId: string): Appeal | undefined {
    return this.appeals.get(appealId);
  }

  /**
   * Get appeal for an intervention.
   */
  getAppealForIntervention(interventionId: string): Appeal | undefined {
    return Array.from(this.appeals.values()).find(
      (a) => a.interventionId === interventionId
    );
  }

  /**
   * Get appeals by status.
   */
  getAppealsByStatus(status: AppealStatus): Appeal[] {
    return Array.from(this.appeals.values()).filter((a) => a.status === status);
  }

  /**
   * Get appeals assigned to a reviewer.
   */
  getAppealsForReviewer(reviewerId: string): Appeal[] {
    return Array.from(this.appeals.values()).filter(
      (a) => a.assignedReviewers.includes(reviewerId)
    );
  }

  /**
   * Check for expired appeals and handle accordingly.
   */
  checkExpiredAppeals(): Appeal[] {
    const expired: Appeal[] = [];
    const now = new Date();

    for (const appeal of this.appeals.values()) {
      if (
        (appeal.status === 'pending' || appeal.status === 'under_review') &&
        now > appeal.reviewDeadline
      ) {
        if (this.config.autoGrantOnExpiry) {
          appeal.status = 'granted';
          appeal.decision = {
            outcome: 'grant',
            decidedBy: 'system',
            decidedAt: now,
            rationale: 'Appeal granted due to review deadline expiry',
          };
        } else {
          appeal.status = 'expired';
        }

        expired.push(appeal);

        this.logAuditEntry(appeal.id, 'appeal_expired', 'system', {
          autoGrant: this.config.autoGrantOnExpiry,
        });
      }
    }

    return expired;
  }

  /**
   * Get audit trail.
   */
  getAuditTrail(): readonly AppealAuditEntry[] {
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
  getConfig(): AppealConfig {
    return this.config;
  }

  /**
   * Get appeal hash for integrity verification.
   */
  getAppealHash(appealId: string): string {
    const appeal = this.appeals.get(appealId);
    if (!appeal) {
      throw new Error(`Appeal not found: ${appealId}`);
    }
    return sha256(JSON.stringify(appeal));
  }

  /**
   * Log an audit entry.
   */
  private logAuditEntry(
    appealId: string,
    action: string,
    actorId: string,
    details: Record<string, unknown>
  ): void {
    const entry: AppealAuditEntry = {
      id: `AUDIT-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date(),
      action,
      actorId,
      appealId,
      details,
    };

    this.auditEntries.push(entry);
    this.auditTree.append(JSON.stringify(entry));
  }
}
