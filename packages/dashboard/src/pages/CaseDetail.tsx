import React, { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import './CaseDetail.css';

// Mock case data
const mockCase = {
  id: 'CASE-001',
  agentId: 'agent-abc123',
  signalId: 'SIG-789',
  status: 'voting',
  createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
  assignedReviewers: ['reviewer-1', 'reviewer-2', 'reviewer-3', 'reviewer-4', 'reviewer-5'],
  riskScore: {
    overall: 0.78,
    tier: 2,
    dimensions: {
      harm: 0.65,
      persistence: 0.82,
      autonomy: 0.91,
      deception: 0.72,
      evasion: 0.60,
    },
  },
  evidence: [
    {
      id: 'EV-001',
      type: 'threat_signal',
      description: 'Initial detection signal with anomaly details',
      submittedAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
    },
    {
      id: 'EV-002',
      type: 'behavior_log',
      description: 'Behavioral analysis logs showing chained tool calls',
      submittedAt: new Date(Date.now() - 1.5 * 60 * 60 * 1000),
    },
    {
      id: 'EV-003',
      type: 'reviewer_note',
      description: 'Pattern matches known deceptive agent behavior',
      submittedAt: new Date(Date.now() - 1 * 60 * 60 * 1000),
    },
  ],
  votes: [
    { reviewerId: 'reviewer-1', decision: 'throttle', rationale: 'Clear pattern of autonomous behavior exceeding thresholds.' },
    { reviewerId: 'reviewer-2', decision: 'throttle', rationale: 'Agent shows persistent behavior across multiple sessions.' },
    { reviewerId: 'reviewer-3', decision: 'advisory', rationale: 'Concerning but may be within acceptable bounds for this use case.' },
  ],
};

export const CaseDetail: React.FC = () => {
  const { caseId } = useParams<{ caseId: string }>();
  const [voteDecision, setVoteDecision] = useState('');
  const [voteRationale, setVoteRationale] = useState('');

  const handleVote = () => {
    if (!voteDecision || !voteRationale) {
      alert('Please select a decision and provide a rationale');
      return;
    }
    alert(`Vote submitted: ${voteDecision}\nRationale: ${voteRationale}`);
  };

  return (
    <div className="case-detail">
      <header className="page-header">
        <div className="header-nav">
          <Link to="/cases" className="back-link">← Back to Cases</Link>
        </div>
        <div className="header-main">
          <h1>{caseId}</h1>
          <span className={`badge tier-${mockCase.riskScore.tier}`}>
            TIER {mockCase.riskScore.tier}
          </span>
        </div>
        <p className="page-subtitle">Agent: {mockCase.agentId}</p>
      </header>

      <div className="case-content">
        <div className="main-column">
          {/* Risk Score Card */}
          <section className="card">
            <h2>Risk Assessment</h2>
            <div className="risk-overview">
              <div className="overall-score">
                <div className="score-value">{(mockCase.riskScore.overall * 100).toFixed(0)}%</div>
                <div className="score-label">Overall Risk</div>
              </div>
              <div className="dimension-scores">
                {Object.entries(mockCase.riskScore.dimensions).map(([key, value]) => (
                  <div key={key} className="dimension">
                    <div className="dimension-label">{key}</div>
                    <div className="dimension-bar">
                      <div
                        className="dimension-fill"
                        style={{ width: `${value * 100}%`, backgroundColor: getScoreColor(value) }}
                      />
                    </div>
                    <div className="dimension-value">{(value * 100).toFixed(0)}%</div>
                  </div>
                ))}
              </div>
            </div>
          </section>

          {/* Evidence Card */}
          <section className="card">
            <h2>Evidence ({mockCase.evidence.length})</h2>
            <div className="evidence-list">
              {mockCase.evidence.map((ev) => (
                <div key={ev.id} className="evidence-item">
                  <div className="evidence-header">
                    <span className="evidence-id">{ev.id}</span>
                    <span className={`badge evidence-type-${ev.type.replace('_', '-')}`}>
                      {ev.type.replace('_', ' ')}
                    </span>
                  </div>
                  <p className="evidence-description">{ev.description}</p>
                  <span className="evidence-time">
                    {ev.submittedAt.toLocaleTimeString()}
                  </span>
                </div>
              ))}
            </div>
          </section>

          {/* Voting Card */}
          <section className="card voting-card">
            <h2>Cast Your Vote</h2>
            <div className="vote-form">
              <div className="vote-options">
                {['no_action', 'advisory', 'throttle', 'revoke', 'escalate'].map((option) => (
                  <label key={option} className={`vote-option ${voteDecision === option ? 'selected' : ''}`}>
                    <input
                      type="radio"
                      name="decision"
                      value={option}
                      checked={voteDecision === option}
                      onChange={(e) => setVoteDecision(e.target.value)}
                    />
                    {option.replace('_', ' ')}
                  </label>
                ))}
              </div>
              <div className="rationale-input">
                <label>Rationale (min 50 characters)</label>
                <textarea
                  value={voteRationale}
                  onChange={(e) => setVoteRationale(e.target.value)}
                  placeholder="Provide detailed reasoning for your decision..."
                  rows={4}
                />
                <span className="char-count">{voteRationale.length} / 50</span>
              </div>
              <button className="primary vote-btn" onClick={handleVote}>
                Submit Vote
              </button>
            </div>
          </section>
        </div>

        <div className="side-column">
          {/* Status Card */}
          <section className="card status-card">
            <h3>Status</h3>
            <span className={`badge status-${mockCase.status.replace('_', '-')}`}>
              {mockCase.status.replace('_', ' ')}
            </span>
            <div className="status-info">
              <div className="info-row">
                <span className="info-label">Created</span>
                <span className="info-value">{mockCase.createdAt.toLocaleString()}</span>
              </div>
              <div className="info-row">
                <span className="info-label">Signal ID</span>
                <span className="info-value">{mockCase.signalId}</span>
              </div>
            </div>
          </section>

          {/* Reviewers Card */}
          <section className="card reviewers-card">
            <h3>Assigned Reviewers</h3>
            <div className="reviewer-list">
              {mockCase.assignedReviewers.map((r) => {
                const vote = mockCase.votes.find((v) => v.reviewerId === r);
                return (
                  <div key={r} className="reviewer-item">
                    <span className="reviewer-name">{r}</span>
                    {vote ? (
                      <span className={`badge vote-${vote.decision}`}>{vote.decision}</span>
                    ) : (
                      <span className="badge pending">pending</span>
                    )}
                  </div>
                );
              })}
            </div>
            <div className="vote-tally">
              <h4>Vote Tally</h4>
              <div className="tally-row">
                <span>Votes cast:</span>
                <span>{mockCase.votes.length} / 5</span>
              </div>
              <div className="tally-row">
                <span>Quorum needed:</span>
                <span>3</span>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
};

function getScoreColor(score: number): string {
  if (score >= 0.8) return '#ef4444';
  if (score >= 0.6) return '#f59e0b';
  if (score >= 0.4) return '#eab308';
  return '#22c55e';
}
