import React from 'react';
import './Interventions.css';

const mockInterventions = [
  {
    id: 'INT-001',
    agentId: 'agent-xyz789',
    tier: 1,
    type: 'advisory',
    status: 'active',
    issuedAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000),
    expiresAt: new Date(Date.now() + 85 * 24 * 60 * 60 * 1000),
    caseId: 'CASE-055',
  },
  {
    id: 'INT-002',
    agentId: 'agent-abc123',
    tier: 2,
    type: 'throttle',
    status: 'pending',
    issuedAt: new Date(Date.now() - 12 * 60 * 60 * 1000),
    expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
    appealDeadline: new Date(Date.now() + 12 * 60 * 60 * 1000),
    caseId: 'CASE-078',
  },
  {
    id: 'INT-003',
    agentId: 'agent-def456',
    tier: 3,
    type: 'revoke',
    status: 'appealed',
    issuedAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
    expiresAt: new Date(Date.now() + 89 * 24 * 60 * 60 * 1000),
    caseId: 'CASE-092',
  },
];

export const Interventions: React.FC = () => {
  return (
    <div className="interventions-page">
      <header className="page-header">
        <h1>Interventions</h1>
        <p className="page-subtitle">Active and pending intervention actions</p>
      </header>

      <div className="interventions-summary">
        <div className="summary-card tier-1-summary">
          <div className="summary-value">3</div>
          <div className="summary-label">Tier 1 (Advisory)</div>
        </div>
        <div className="summary-card tier-2-summary">
          <div className="summary-value">2</div>
          <div className="summary-label">Tier 2 (Throttle)</div>
        </div>
        <div className="summary-card tier-3-summary">
          <div className="summary-value">1</div>
          <div className="summary-label">Tier 3 (Revoke)</div>
        </div>
      </div>

      <div className="interventions-list">
        {mockInterventions.map((intervention) => (
          <div key={intervention.id} className="intervention-card card">
            <div className="intervention-header">
              <div className="intervention-id">{intervention.id}</div>
              <span className={`badge tier-${intervention.tier}`}>
                TIER {intervention.tier}
              </span>
            </div>

            <div className="intervention-body">
              <div className="info-grid">
                <div className="info-item">
                  <span className="info-label">Agent</span>
                  <span className="info-value agent-id">{intervention.agentId}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Type</span>
                  <span className="info-value">{intervention.type}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Status</span>
                  <span className={`badge status-${intervention.status}`}>
                    {intervention.status}
                  </span>
                </div>
                <div className="info-item">
                  <span className="info-label">Case</span>
                  <span className="info-value">{intervention.caseId}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Issued</span>
                  <span className="info-value">{formatDate(intervention.issuedAt)}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Expires</span>
                  <span className="info-value">{formatDate(intervention.expiresAt)}</span>
                </div>
              </div>

              {intervention.appealDeadline && intervention.status === 'pending' && (
                <div className="appeal-warning">
                  ⏰ Appeal deadline: {formatDate(intervention.appealDeadline)}
                </div>
              )}
            </div>

            <div className="intervention-actions">
              {intervention.status === 'pending' && (
                <button className="primary">Activate</button>
              )}
              {intervention.status === 'active' && (
                <>
                  <button className="secondary">Suspend</button>
                  <button className="danger">Reverse</button>
                </>
              )}
              {intervention.status === 'appealed' && (
                <button className="primary">Review Appeal</button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

function formatDate(date: Date): string {
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}
