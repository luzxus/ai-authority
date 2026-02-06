/**
 * Voting System
 *
 * Implements 3-of-5 quorum voting with cryptographic signatures.
 * All votes and rationales are cryptographically signed per blueprint requirements.
 */

import { sign, verify } from '@ai-authority/core';
import type { CaseDecision, CaseSummary } from './cases.js';

// ============================================================================
// Types
// ============================================================================

/** A vote cast by a reviewer */
export interface Vote {
  /** Vote ID */
  readonly id: string;

  /** Case being voted on */
  readonly caseId: string;

  /** Reviewer who cast the vote */
  readonly reviewerId: string;

  /** Decision */
  readonly decision: CaseDecision;

  /** Rationale for the vote */
  readonly rationale: string;

  /** Timestamp */
  readonly timestamp: Date;
}

export interface SignedVote extends Vote {
  /** Cryptographic signature of the vote */
  readonly signature: string;

  /** Public key used for signing */
  readonly publicKey: string;
}

export interface VotingSession {
  /** Session ID */
  readonly id: string;

  /** Case being voted on */
  readonly caseId: string;

  /** Eligible voters */
  readonly eligibleVoters: string[];

  /** Votes cast */
  readonly votes: Map<string, SignedVote>;

  /** Session status */
  status: 'open' | 'closed' | 'quorum_reached' | 'expired';

  /** Created timestamp */
  readonly createdAt: Date;

  /** Deadline */
  readonly deadline: Date;

  /** Final decision (if quorum reached) */
  decision?: CaseDecision;

  /** Quorum threshold */
  readonly quorumSize: number;
}

export interface VotingConfig {
  /** Quorum size for decisions */
  readonly quorumSize: number;

  /** Voting deadline in hours */
  readonly votingDeadlineHours: number;

  /** Allow abstentions */
  readonly allowAbstain: boolean;

  /** Require rationale */
  readonly requireRationale: boolean;

  /** Minimum rationale length */
  readonly minRationaleLength: number;
}

export interface VoteTally {
  noAction: number;
  advisory: number;
  throttle: number;
  revoke: number;
  escalate: number;
  abstain: number;
  total: number;
}

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_VOTING_CONFIG: VotingConfig = {
  quorumSize: 3,
  votingDeadlineHours: 48,
  allowAbstain: true,
  requireRationale: true,
  minRationaleLength: 50,
};

// ============================================================================
// Voting Manager
// ============================================================================

/**
 * Manages voting sessions with cryptographic integrity.
 */
export class VotingManager {
  private readonly sessions: Map<string, VotingSession> = new Map();
  private readonly voterKeys: Map<string, { publicKey: string; privateKey: string }> =
    new Map();
  private readonly config: VotingConfig;

  constructor(config: VotingConfig = DEFAULT_VOTING_CONFIG) {
    this.config = config;
  }

  /**
   * Register a voter with their key pair.
   */
  registerVoter(voterId: string, publicKey: string, privateKey: string): void {
    this.voterKeys.set(voterId, { publicKey, privateKey });
  }

  /**
   * Create a voting session for a case.
   */
  createSession(caseSummary: CaseSummary): VotingSession {
    const id = `VOTE-${caseSummary.id}-${Date.now()}`;

    const session: VotingSession = {
      id,
      caseId: caseSummary.id,
      eligibleVoters: [...caseSummary.assignedReviewers],
      votes: new Map(),
      status: 'open',
      createdAt: new Date(),
      deadline: new Date(
        Date.now() + this.config.votingDeadlineHours * 60 * 60 * 1000
      ),
      quorumSize: this.config.quorumSize,
    };

    this.sessions.set(id, session);
    return session;
  }

  /**
   * Cast a vote with cryptographic signature.
   */
  async castVote(
    sessionId: string,
    voterId: string,
    decision: CaseDecision | 'abstain',
    rationale: string
  ): Promise<SignedVote> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Voting session not found: ${sessionId}`);
    }

    // Validate session status
    if (session.status !== 'open') {
      throw new Error(`Voting session is ${session.status}`);
    }

    // Check deadline
    if (new Date() > session.deadline) {
      session.status = 'expired';
      throw new Error('Voting deadline has passed');
    }

    // Validate voter eligibility
    if (!session.eligibleVoters.includes(voterId)) {
      throw new Error(`Voter not eligible: ${voterId}`);
    }

    // Check for duplicate vote
    if (session.votes.has(voterId)) {
      throw new Error(`Voter has already cast a vote: ${voterId}`);
    }

    // Validate abstain
    if (decision === 'abstain' && !this.config.allowAbstain) {
      throw new Error('Abstentions are not allowed');
    }

    // Validate rationale
    if (this.config.requireRationale) {
      if (!rationale || rationale.length < this.config.minRationaleLength) {
        throw new Error(
          `Rationale must be at least ${this.config.minRationaleLength} characters`
        );
      }
    }

    // Get voter keys
    const keys = this.voterKeys.get(voterId);
    if (!keys) {
      throw new Error(`Voter keys not registered: ${voterId}`);
    }

    // Determine actual decision (abstain maps to no_action with ABSTAIN prefix)
    const actualDecision: CaseDecision = decision === 'abstain' ? 'no_action' : decision;
    const actualRationale = decision === 'abstain' ? `ABSTAIN: ${rationale}` : rationale;

    // Create vote payload
    const votePayload = {
      sessionId,
      caseId: session.caseId,
      voterId,
      decision: actualDecision,
      rationale: actualRationale,
      timestamp: new Date().toISOString(),
    };

    // Sign the vote
    const payloadString = JSON.stringify(votePayload);
    const signature = sign(payloadString, keys.privateKey);

    const signedVote: SignedVote = {
      id: `V-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      caseId: session.caseId,
      reviewerId: voterId,
      decision: actualDecision,
      rationale: actualRationale,
      timestamp: new Date(),
      signature,
      publicKey: keys.publicKey,
    };

    // Store the vote
    session.votes.set(voterId, signedVote);

    // Check for quorum
    this.checkQuorum(session);

    return signedVote;
  }

  /**
   * Verify a signed vote.
   */
  verifyVote(vote: SignedVote): boolean {
    const session = this.findSessionForVote(vote);
    const payload = {
      sessionId: session?.id,
      caseId: vote.caseId,
      voterId: vote.reviewerId,
      decision: vote.decision,
      rationale: vote.rationale,
      timestamp: vote.timestamp.toISOString(),
    };

    return verify(JSON.stringify(payload), vote.signature, vote.publicKey);
  }

  /**
   * Get voting session by ID.
   */
  getSession(sessionId: string): VotingSession | undefined {
    return this.sessions.get(sessionId);
  }

  /**
   * Get session for a case.
   */
  getSessionForCase(caseId: string): VotingSession | undefined {
    return Array.from(this.sessions.values()).find((s) => s.caseId === caseId);
  }

  /**
   * Get vote tally for a session.
   */
  getTally(sessionId: string): VoteTally {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Voting session not found: ${sessionId}`);
    }

    const tally: VoteTally = {
      noAction: 0,
      advisory: 0,
      throttle: 0,
      revoke: 0,
      escalate: 0,
      abstain: 0,
      total: session.votes.size,
    };

    for (const vote of session.votes.values()) {
      switch (vote.decision) {
        case 'no_action':
          // Check if this was an abstention by looking at rationale
          if (vote.rationale.startsWith('ABSTAIN:')) {
            tally.abstain++;
          } else {
            tally.noAction++;
          }
          break;
        case 'advisory':
          tally.advisory++;
          break;
        case 'throttle':
          tally.throttle++;
          break;
        case 'revoke':
          tally.revoke++;
          break;
        case 'escalate':
          tally.escalate++;
          break;
      }
    }

    return tally;
  }

  /**
   * Get votes for a session.
   */
  getVotes(sessionId: string): SignedVote[] {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Voting session not found: ${sessionId}`);
    }
    return Array.from(session.votes.values());
  }

  /**
   * Close a voting session manually.
   */
  closeSession(sessionId: string): VotingSession {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Voting session not found: ${sessionId}`);
    }

    if (session.status === 'open') {
      session.status = 'closed';
    }

    return session;
  }

  /**
   * Get all open sessions.
   */
  getOpenSessions(): VotingSession[] {
    return Array.from(this.sessions.values()).filter((s) => s.status === 'open');
  }

  /**
   * Check for expired sessions and update status.
   */
  checkExpiredSessions(): VotingSession[] {
    const expired: VotingSession[] = [];
    const now = new Date();

    for (const session of this.sessions.values()) {
      if (session.status === 'open' && now > session.deadline) {
        session.status = 'expired';
        expired.push(session);
      }
    }

    return expired;
  }

  /**
   * Get configuration.
   */
  getConfig(): VotingConfig {
    return this.config;
  }

  /**
   * Check if quorum has been reached.
   */
  private checkQuorum(session: VotingSession): void {
    const tally = this.getTally(session.id);

    // Determine winning decision
    const decisions: { decision: CaseDecision; count: number }[] = [
      { decision: 'no_action', count: tally.noAction },
      { decision: 'advisory', count: tally.advisory },
      { decision: 'throttle', count: tally.throttle },
      { decision: 'revoke', count: tally.revoke },
      { decision: 'escalate', count: tally.escalate },
    ];

    // Sort by count descending
    decisions.sort((a, b) => b.count - a.count);

    // Check if top decision has quorum
    const topDecision = decisions[0];
    if (topDecision && topDecision.count >= session.quorumSize) {
      session.status = 'quorum_reached';
      session.decision = topDecision.decision;
    }
  }

  /**
   * Find session containing a vote.
   */
  private findSessionForVote(vote: SignedVote): VotingSession | undefined {
    return Array.from(this.sessions.values()).find((s) => s.caseId === vote.caseId);
  }
}

// ============================================================================
// Vote Aggregator
// ============================================================================

/**
 * Aggregates votes across multiple sessions for analytics.
 */
export class VoteAggregator {
  /**
   * Aggregate statistics from multiple sessions.
   */
  aggregate(sessions: VotingSession[]): {
    totalSessions: number;
    completed: number;
    expired: number;
    averageVotes: number;
    decisionDistribution: Record<CaseDecision, number>;
    averageTimeToQuorum: number;
  } {
    let completed = 0;
    let expired = 0;
    let totalVotes = 0;
    let totalTimeToQuorum = 0;
    let quorumCount = 0;
    const decisions: Record<CaseDecision, number> = {
      no_action: 0,
      advisory: 0,
      throttle: 0,
      revoke: 0,
      escalate: 0,
    };

    for (const session of sessions) {
      if (session.status === 'quorum_reached' || session.status === 'closed') {
        completed++;
        if (session.decision) {
          decisions[session.decision]++;
        }
      } else if (session.status === 'expired') {
        expired++;
      }

      totalVotes += session.votes.size;

      // Calculate time to quorum
      if (session.status === 'quorum_reached' && session.votes.size >= session.quorumSize) {
        const votes = Array.from(session.votes.values());
        const lastVoteTime = Math.max(...votes.map((v) => v.timestamp.getTime()));
        const timeToQuorum = lastVoteTime - session.createdAt.getTime();
        totalTimeToQuorum += timeToQuorum;
        quorumCount++;
      }
    }

    return {
      totalSessions: sessions.length,
      completed,
      expired,
      averageVotes: sessions.length > 0 ? totalVotes / sessions.length : 0,
      decisionDistribution: decisions,
      averageTimeToQuorum:
        quorumCount > 0 ? totalTimeToQuorum / quorumCount / (1000 * 60 * 60) : 0, // In hours
    };
  }
}
