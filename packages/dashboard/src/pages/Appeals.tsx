import React from 'react';
import './Appeals.css';

const mockAppeals = [
  {
    id: 'APPEAL-001',
    interventionId: 'INT-003',
    agentId: 'agent-def456',
    status: 'under_review',
    grounds: ['factual_error', 'proportionality'],
    statement: 'The agent behavior was misclassified. The autonomous actions were part of a legitimate workflow authorized by the user. The severity of intervention is disproportionate to the actual risk.',
    filedAt: new Date(Date.now() - 12 * 60 * 60 * 1000),
    decisionDeadline: new Date(Date.now() + 36 * 60 * 60 * 1000),
  },
  {
    id: 'APPEAL-002',
    interventionId: 'INT-007',
    agentId: 'agent-mno345',
    status: 'pending',
    grounds: ['identity_confusion'],
    statement: 'The flagged behavior originated from a different agent instance. Our agent shares the same model fingerprint but operates in a completely different context with different permissions.',
    filedAt: new Date(Date.now() - 4 * 60 * 60 * 1000),
    decisionDeadline: new Date(Date.now() + 44 * 60 * 60 * 1000),
  },
  {
    id: 'APPEAL-003',
    interventionId: 'INT-005',
    agentId: 'agent-pqr678',
    status: 'granted',
    grounds: ['changed_circumstances'],
    statement: 'The behavioral patterns that triggered the intervention have been corrected through an update. The agent now operates within all specified thresholds.',
    filedAt: new Date(Date.now() - 48 * 60 * 60 * 1000),
    decisionDeadline: new Date(Date.now() - 12 * 60 * 60 * 1000),
    decision: {
      outcome: 'grant',
      rationale: 'Evidence shows behavioral corrections have been implemented. Intervention reversed.',
      decidedAt: new Date(Date.now() - 6 * 60 * 60 * 1000),
    },
  },
];

export const Appeals: React.FC = () => {
  return (
    <div className="appeals-page">
      <header className="page-header">
        <h1>Appeals</h1>
        <p className="page-subtitle">Review intervention appeals with 24-hour response window</p>
      </header>

      <div className="appeals-stats">
        <div className="stat-item">
          <span className="stat-value">
            {mockAppeals.filter((a) => a.status === 'pending').length}
          </span>
          <span className="stat-label">Pending</span>
        </div>
        <div className="stat-item">
          <span className="stat-value">
            {mockAppeals.filter((a) => a.status === 'under_review').length}
          </span>
          <span className="stat-label">Under Review</span>
        </div>
        <div className="stat-item">
          <span className="stat-value">
            {mockAppeals.filter((a) => a.status === 'granted').length}
          </span>
          <span className="stat-label">Granted</span>
        </div>
        <div className="stat-item">
          <span className="stat-value">
            {mockAppeals.filter((a) => a.status === 'denied').length}
          </span>
          <span className="stat-label">Denied</span>
        </div>
      </div>

      <div className="appeals-list">
        {mockAppeals.map((appeal) => (
          <div key={appeal.id} className="appeal-card card">
            <div className="appeal-header">
              <div>
                <div className="appeal-id">{appeal.id}</div>
                <div className="appeal-meta">
                  Intervention: {appeal.interventionId} • Agent: {appeal.agentId}
                </div>
              </div>
              <span className={`badge status-${appeal.status.replace('_', '-')}`}>
                {appeal.status.replace('_', ' ')}
              </span>
            </div>

            <div className="appeal-body">
              <div className="grounds-section">
                <h4>Grounds for Appeal</h4>
                <div className="grounds-list">
                  {appeal.grounds.map((ground) => (
                    <span key={ground} className="ground-badge">
                      {ground.replace('_', ' ')}
                    </span>
                  ))}
                </div>
              </div>

              <div className="statement-section">
                <h4>Statement</h4>
                <p className="statement-text">{appeal.statement}</p>
              </div>

              <div className="timeline-section">
                <div className="timeline-item">
                  <span className="timeline-label">Filed</span>
                  <span className="timeline-value">{formatDateTime(appeal.filedAt)}</span>
                </div>
                <div className="timeline-item">
                  <span className="timeline-label">Decision Deadline</span>
                  <span className={`timeline-value ${isUrgent(appeal.decisionDeadline) ? 'urgent' : ''}`}>
                    {formatDateTime(appeal.decisionDeadline)}
                    {isUrgent(appeal.decisionDeadline) && appeal.status !== 'granted' && appeal.status !== 'denied' && (
                      <span className="urgent-badge">URGENT</span>
                    )}
                  </span>
                </div>
              </div>

              {appeal.decision && (
                <div className="decision-section">
                  <h4>Decision</h4>
                  <div className={`decision-outcome outcome-${appeal.decision.outcome}`}>
                    {appeal.decision.outcome.toUpperCase()}
                  </div>
                  <p className="decision-rationale">{appeal.decision.rationale}</p>
                  <span className="decision-time">
                    Decided: {formatDateTime(appeal.decision.decidedAt)}
                  </span>
                </div>
              )}
            </div>

            {(appeal.status === 'pending' || appeal.status === 'under_review') && (
              <div className="appeal-actions">
                {appeal.status === 'pending' && (
                  <button className="primary">Begin Review</button>
                )}
                {appeal.status === 'under_review' && (
                  <>
                    <button className="success">Grant Appeal</button>
                    <button className="danger">Deny Appeal</button>
                    <button className="secondary">Request More Info</button>
                  </>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

function formatDateTime(date: Date): string {
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function isUrgent(deadline: Date): boolean {
  const hoursRemaining = (deadline.getTime() - Date.now()) / (1000 * 60 * 60);
  return hoursRemaining > 0 && hoursRemaining < 12;
}
