import React, { useState } from 'react';
import './Audits.css';

// Mock data for audit records
const mockAudits = [
  {
    id: 'audit-001',
    timestamp: Date.now() - 3600000,
    agentId: 'enforcer-001',
    actionType: 'intervention',
    actionId: 'intervention-456',
    policyId: 'policy-tier-3',
    result: 'compliant',
    details: {
      requiredConsensus: 3,
      actualConsensus: 4,
      signatures: ['watchdog-001', 'auditor-001', 'analyzer-001', 'approver-001'],
      cryptoVerified: true,
    },
    severity: 'high',
  },
  {
    id: 'audit-002',
    timestamp: Date.now() - 7200000,
    agentId: 'proposer-001',
    actionType: 'governance',
    actionId: 'proposal-789',
    policyId: 'policy-knowledge-update',
    result: 'compliant',
    details: {
      requiredApprovals: 2,
      actualApprovals: 2,
      signatures: ['approver-001', 'curator-001'],
      cryptoVerified: true,
    },
    severity: 'medium',
  },
  {
    id: 'audit-003',
    timestamp: Date.now() - 14400000,
    agentId: 'enforcer-002',
    actionType: 'intervention',
    actionId: 'intervention-123',
    policyId: 'policy-tier-2',
    result: 'violation',
    details: {
      requiredConsensus: 2,
      actualConsensus: 1,
      signatures: ['enforcer-002'],
      cryptoVerified: true,
      violationReason: 'Insufficient consensus for Tier-2 intervention',
    },
    severity: 'high',
  },
  {
    id: 'audit-004',
    timestamp: Date.now() - 28800000,
    agentId: 'sensor-001',
    actionType: 'detection',
    actionId: 'detection-999',
    policyId: 'policy-data-collection',
    result: 'compliant',
    details: {
      differentialPrivacy: true,
      epsilonValue: 0.1,
      signatures: ['sensor-001'],
      cryptoVerified: true,
    },
    severity: 'low',
  },
  {
    id: 'audit-005',
    timestamp: Date.now() - 43200000,
    agentId: 'liaison-001',
    actionType: 'federation',
    actionId: 'share-555',
    policyId: 'policy-knowledge-sharing',
    result: 'violation',
    details: {
      requiredZKProof: true,
      providedZKProof: false,
      signatures: ['liaison-001'],
      cryptoVerified: true,
      violationReason: 'Missing zero-knowledge proof for threat alert',
    },
    severity: 'critical',
  },
  {
    id: 'audit-006',
    timestamp: Date.now() - 86400000,
    agentId: 'analyzer-001',
    actionType: 'scoring',
    actionId: 'score-777',
    policyId: 'policy-risk-assessment',
    result: 'compliant',
    details: {
      modelVersion: '2.3.1',
      ensembleUsed: true,
      signatures: ['analyzer-001'],
      cryptoVerified: true,
    },
    severity: 'medium',
  },
];

const mockPolicies = [
  {
    id: 'policy-tier-1',
    name: 'Tier-1 Intervention',
    description: 'Public advisory - requires single agent authorization',
    consensusRequired: 1,
    complianceRate: 0.98,
  },
  {
    id: 'policy-tier-2',
    name: 'Tier-2 Intervention',
    description: 'Voluntary throttling - requires 2-agent agreement',
    consensusRequired: 2,
    complianceRate: 0.89,
  },
  {
    id: 'policy-tier-3',
    name: 'Tier-3 Intervention',
    description: 'Credential shadow-ban - requires Byzantine consensus',
    consensusRequired: 3,
    complianceRate: 0.95,
  },
  {
    id: 'policy-tier-4',
    name: 'Tier-4 Intervention',
    description: 'Model isolation - requires supermajority + audit',
    consensusRequired: 5,
    complianceRate: 1.0,
  },
  {
    id: 'policy-knowledge-update',
    name: 'Knowledge Base Update',
    description: 'Updates to shared knowledge require dual approval',
    consensusRequired: 2,
    complianceRate: 0.97,
  },
  {
    id: 'policy-data-collection',
    name: 'Data Collection',
    description: 'All data collection must use differential privacy',
    consensusRequired: 1,
    complianceRate: 0.99,
  },
];

type ResultFilter = 'all' | 'compliant' | 'violation';
type SeverityFilter = 'all' | 'low' | 'medium' | 'high' | 'critical';

export const Audits: React.FC = () => {
  const [resultFilter, setResultFilter] = useState<ResultFilter>('all');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');

  const filteredAudits = mockAudits.filter((audit) => {
    if (resultFilter !== 'all' && audit.result !== resultFilter) return false;
    if (severityFilter !== 'all' && audit.severity !== severityFilter) return false;
    return true;
  });

  const stats = {
    total: mockAudits.length,
    compliant: mockAudits.filter((a) => a.result === 'compliant').length,
    violations: mockAudits.filter((a) => a.result === 'violation').length,
    complianceRate:
      (mockAudits.filter((a) => a.result === 'compliant').length / mockAudits.length) * 100,
    cryptoVerified: mockAudits.filter((a) => a.details.cryptoVerified).length,
  };

  return (
    <div className="audits-page">
      <header className="page-header">
        <h1>Compliance Audits</h1>
        <p className="page-subtitle">
          Audit trails and policy compliance verification for all agent actions
        </p>
      </header>

      <div className="audits-summary">
        <div className="summary-card">
          <div className="summary-value">{stats.total}</div>
          <div className="summary-label">Total Audits</div>
        </div>
        <div className="summary-card compliant">
          <div className="summary-value">{stats.compliant}</div>
          <div className="summary-label">Compliant</div>
        </div>
        <div className="summary-card violations">
          <div className="summary-value">{stats.violations}</div>
          <div className="summary-label">Violations</div>
        </div>
        <div className="summary-card rate">
          <div className="summary-value">{stats.complianceRate.toFixed(1)}%</div>
          <div className="summary-label">Compliance Rate</div>
        </div>
      </div>

      <div className="policies-section">
        <h2>Policy Compliance Overview</h2>
        <div className="policies-grid">
          {mockPolicies.map((policy) => (
            <div key={policy.id} className="policy-card">
              <div className="policy-header">
                <span className="policy-name">{policy.name}</span>
                <span
                  className={`policy-rate ${policy.complianceRate >= 0.95 ? 'good' : policy.complianceRate >= 0.85 ? 'warning' : 'bad'}`}
                >
                  {(policy.complianceRate * 100).toFixed(0)}%
                </span>
              </div>
              <p className="policy-desc">{policy.description}</p>
              <div className="policy-meta">
                <span className="consensus-badge">
                  Consensus: {policy.consensusRequired}
                </span>
              </div>
              <div className="compliance-bar">
                <div
                  className={`compliance-fill ${policy.complianceRate >= 0.95 ? 'good' : policy.complianceRate >= 0.85 ? 'warning' : 'bad'}`}
                  style={{ width: `${policy.complianceRate * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="audits-filters">
        <div className="filter-group">
          <label>Result:</label>
          <select
            value={resultFilter}
            onChange={(e) => setResultFilter(e.target.value as ResultFilter)}
          >
            <option value="all">All Results</option>
            <option value="compliant">Compliant</option>
            <option value="violation">Violations</option>
          </select>
        </div>
        <div className="filter-group">
          <label>Severity:</label>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as SeverityFilter)}
          >
            <option value="all">All Severities</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </div>
      </div>

      <div className="audits-list">
        {filteredAudits.map((audit) => (
          <div key={audit.id} className={`audit-card result-${audit.result}`}>
            <div className="audit-header">
              <div className="audit-identity">
                <span className="audit-id">{audit.id}</span>
                <span className={`result-badge ${audit.result}`}>
                  {audit.result === 'compliant' ? '✓ Compliant' : '✗ Violation'}
                </span>
                <span className={`severity-badge severity-${audit.severity}`}>
                  {audit.severity}
                </span>
              </div>
              <span className="audit-time">{formatTimeAgo(audit.timestamp)}</span>
            </div>

            <div className="audit-details">
              <div className="detail-row">
                <span className="detail-label">Agent:</span>
                <span className="detail-value mono">{audit.agentId}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Action Type:</span>
                <span className="detail-value">{audit.actionType}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Action ID:</span>
                <span className="detail-value mono">{audit.actionId}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Policy:</span>
                <span className="detail-value">{audit.policyId}</span>
              </div>
            </div>

            <div className="audit-verification">
              <div className="verification-item">
                <span className="verification-label">Crypto Verified:</span>
                <span className={`verification-value ${audit.details.cryptoVerified ? 'verified' : 'failed'}`}>
                  {audit.details.cryptoVerified ? '✓ Yes' : '✗ No'}
                </span>
              </div>
              {audit.details.requiredConsensus !== undefined && (
                <div className="verification-item">
                  <span className="verification-label">Consensus:</span>
                  <span className={`verification-value ${audit.details.actualConsensus >= audit.details.requiredConsensus ? 'verified' : 'failed'}`}>
                    {audit.details.actualConsensus}/{audit.details.requiredConsensus} required
                  </span>
                </div>
              )}
              <div className="signatures">
                <span className="signatures-label">Signatures:</span>
                {audit.details.signatures.map((sig) => (
                  <span key={sig} className="signature-badge">
                    {sig}
                  </span>
                ))}
              </div>
            </div>

            {audit.details.violationReason && (
              <div className="violation-reason">
                <span className="violation-icon">⚠️</span>
                {audit.details.violationReason}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

function formatTimeAgo(timestamp: number): string {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}
