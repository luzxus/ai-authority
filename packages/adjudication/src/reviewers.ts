/**
 * Reviewer Management
 *
 * Manages human reviewers with qualifications and conflict-of-interest checks.
 */

// ============================================================================
// Types
// ============================================================================

export type ReviewerStatus = 'active' | 'inactive' | 'suspended' | 'pending_approval';

export type ReviewerRole = 'reviewer' | 'senior_reviewer' | 'lead' | 'admin';

export interface ReviewerProfile {
  /** Reviewer ID */
  readonly id: string;

  /** Public key for vote signing */
  publicKey: string;

  /** Reviewer status */
  status: ReviewerStatus;

  /** Role */
  role: ReviewerRole;

  /** Organization affiliations (for conflict checks) */
  affiliations: string[];

  /** Cases reviewed */
  casesReviewed: number;

  /** Joined date */
  joinedAt: Date;

  /** Last active */
  lastActiveAt: Date;

  /** Qualification scores */
  qualifications: ReviewerQualifications;
}

export interface ReviewerQualifications {
  /** Accuracy score (0-1) based on agreement with final decisions */
  accuracy: number;

  /** Consistency score (0-1) based on rationale quality */
  consistency: number;

  /** Timeliness score (0-1) based on response times */
  timeliness: number;

  /** Total cases for calculating scores */
  totalCases: number;
}

export interface ConflictOfInterest {
  /** COI ID */
  readonly id: string;

  /** Reviewer ID */
  readonly reviewerId: string;

  /** Organization or entity */
  readonly entity: string;

  /** COI type */
  readonly type: 'employer' | 'investor' | 'collaborator' | 'personal' | 'other';

  /** Start date */
  readonly startDate: Date;

  /** End date (if applicable) */
  endDate?: Date;

  /** Declaration date */
  readonly declaredAt: Date;
}

export interface ReviewerConfig {
  /** Minimum qualifications for active status */
  readonly minAccuracy: number;

  /** Minimum cases before qualifications count */
  readonly minCasesForQualification: number;

  /** COI cooldown period in days */
  readonly coiCooldownDays: number;
}

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_REVIEWER_CONFIG: ReviewerConfig = {
  minAccuracy: 0.7,
  minCasesForQualification: 10,
  coiCooldownDays: 365, // 1 year
};

// ============================================================================
// Reviewer Manager
// ============================================================================

/**
 * Manages reviewer profiles and conflict of interest declarations.
 */
export class ReviewerManager {
  private readonly reviewers: Map<string, ReviewerProfile> = new Map();
  private readonly conflicts: Map<string, ConflictOfInterest[]> = new Map();
  private readonly config: ReviewerConfig;

  constructor(config: ReviewerConfig = DEFAULT_REVIEWER_CONFIG) {
    this.config = config;
  }

  /**
   * Register a new reviewer.
   */
  registerReviewer(
    id: string,
    publicKey: string,
    role: ReviewerRole = 'reviewer',
    affiliations: string[] = []
  ): ReviewerProfile {
    if (this.reviewers.has(id)) {
      throw new Error(`Reviewer already exists: ${id}`);
    }

    const profile: ReviewerProfile = {
      id,
      publicKey,
      status: 'pending_approval',
      role,
      affiliations,
      casesReviewed: 0,
      joinedAt: new Date(),
      lastActiveAt: new Date(),
      qualifications: {
        accuracy: 0,
        consistency: 0,
        timeliness: 0,
        totalCases: 0,
      },
    };

    this.reviewers.set(id, profile);
    this.conflicts.set(id, []);

    return profile;
  }

  /**
   * Approve a pending reviewer.
   */
  approveReviewer(reviewerId: string): void {
    const profile = this.reviewers.get(reviewerId);
    if (!profile) {
      throw new Error(`Reviewer not found: ${reviewerId}`);
    }

    if (profile.status !== 'pending_approval') {
      throw new Error(`Reviewer not pending approval: ${profile.status}`);
    }

    profile.status = 'active';
  }

  /**
   * Suspend a reviewer.
   */
  suspendReviewer(reviewerId: string, _reason: string): void {
    const profile = this.reviewers.get(reviewerId);
    if (!profile) {
      throw new Error(`Reviewer not found: ${reviewerId}`);
    }

    profile.status = 'suspended';
  }

  /**
   * Reactivate a reviewer.
   */
  reactivateReviewer(reviewerId: string): void {
    const profile = this.reviewers.get(reviewerId);
    if (!profile) {
      throw new Error(`Reviewer not found: ${reviewerId}`);
    }

    if (profile.status !== 'suspended' && profile.status !== 'inactive') {
      throw new Error(`Reviewer not suspended or inactive: ${profile.status}`);
    }

    profile.status = 'active';
  }

  /**
   * Declare a conflict of interest.
   */
  declareConflict(
    reviewerId: string,
    entity: string,
    type: ConflictOfInterest['type'],
    startDate: Date,
    endDate?: Date
  ): ConflictOfInterest {
    const profile = this.reviewers.get(reviewerId);
    if (!profile) {
      throw new Error(`Reviewer not found: ${reviewerId}`);
    }

    const conflict: ConflictOfInterest = {
      id: `COI-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      reviewerId,
      entity,
      type,
      startDate,
      declaredAt: new Date(),
    };

    // Only add endDate if it's defined
    if (endDate !== undefined) {
      (conflict as { endDate: Date }).endDate = endDate;
    }

    const reviewerConflicts = this.conflicts.get(reviewerId) ?? [];
    reviewerConflicts.push(conflict);
    this.conflicts.set(reviewerId, reviewerConflicts);

    return conflict;
  }

  /**
   * Check if a reviewer has a conflict with an agent's organization.
   */
  hasConflict(reviewerId: string, agentOrganization: string): boolean {
    const conflicts = this.conflicts.get(reviewerId) ?? [];
    const now = new Date();
    const cooldownDate = new Date(
      now.getTime() - this.config.coiCooldownDays * 24 * 60 * 60 * 1000
    );

    for (const conflict of conflicts) {
      // Check if organization matches
      if (conflict.entity.toLowerCase() !== agentOrganization.toLowerCase()) {
        continue;
      }

      // Check if conflict is current or within cooldown
      if (!conflict.endDate || conflict.endDate > cooldownDate) {
        return true;
      }
    }

    return false;
  }

  /**
   * Get eligible reviewers for a case (no conflicts).
   */
  getEligibleReviewers(agentOrganization: string): ReviewerProfile[] {
    return Array.from(this.reviewers.values()).filter(
      (r) => r.status === 'active' && !this.hasConflict(r.id, agentOrganization)
    );
  }

  /**
   * Update reviewer qualifications after a case.
   */
  updateQualifications(
    reviewerId: string,
    agreedWithDecision: boolean,
    responseTimeHours: number
  ): void {
    const profile = this.reviewers.get(reviewerId);
    if (!profile) {
      throw new Error(`Reviewer not found: ${reviewerId}`);
    }

    const qual = profile.qualifications;
    const totalCases = qual.totalCases + 1;

    // Update accuracy (moving average)
    const newAccuracy =
      (qual.accuracy * qual.totalCases + (agreedWithDecision ? 1 : 0)) / totalCases;

    // Update timeliness (inverse of response time, normalized)
    // Assume 48 hours is "on time" = 1.0 score
    const timelinessScore = Math.max(0, Math.min(1, 1 - (responseTimeHours - 48) / 48));
    const newTimeliness = (qual.timeliness * qual.totalCases + timelinessScore) / totalCases;

    // Consistency is harder to measure - for now, use agreement as proxy
    const newConsistency =
      (qual.consistency * qual.totalCases + (agreedWithDecision ? 1 : 0.5)) / totalCases;

    profile.qualifications = {
      accuracy: newAccuracy,
      consistency: newConsistency,
      timeliness: newTimeliness,
      totalCases,
    };

    profile.casesReviewed++;
    profile.lastActiveAt = new Date();

    // Check if qualifications drop below threshold
    if (
      totalCases >= this.config.minCasesForQualification &&
      newAccuracy < this.config.minAccuracy
    ) {
      // Mark for review (don't auto-suspend, just flag)
      console.warn(`Reviewer ${reviewerId} accuracy below threshold: ${newAccuracy}`);
    }
  }

  /**
   * Get reviewer by ID.
   */
  getReviewer(reviewerId: string): ReviewerProfile | undefined {
    return this.reviewers.get(reviewerId);
  }

  /**
   * Get all reviewers.
   */
  getAllReviewers(): ReviewerProfile[] {
    return Array.from(this.reviewers.values());
  }

  /**
   * Get conflicts for a reviewer.
   */
  getConflicts(reviewerId: string): ConflictOfInterest[] {
    return this.conflicts.get(reviewerId) ?? [];
  }

  /**
   * Get configuration.
   */
  getConfig(): ReviewerConfig {
    return this.config;
  }

  /**
   * Get reviewer statistics.
   */
  getStatistics(): {
    total: number;
    active: number;
    pending: number;
    suspended: number;
    inactive: number;
    averageAccuracy: number;
    averageCases: number;
  } {
    const reviewers = Array.from(this.reviewers.values());
    const active = reviewers.filter((r) => r.status === 'active');

    const totalAccuracy = active.reduce(
      (sum, r) => sum + r.qualifications.accuracy,
      0
    );
    const totalCases = reviewers.reduce((sum, r) => sum + r.casesReviewed, 0);

    return {
      total: reviewers.length,
      active: active.length,
      pending: reviewers.filter((r) => r.status === 'pending_approval').length,
      suspended: reviewers.filter((r) => r.status === 'suspended').length,
      inactive: reviewers.filter((r) => r.status === 'inactive').length,
      averageAccuracy: active.length > 0 ? totalAccuracy / active.length : 0,
      averageCases: reviewers.length > 0 ? totalCases / reviewers.length : 0,
    };
  }
}
