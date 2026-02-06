import React, { useState } from 'react';
import './Forensics.css';

// Mock data for forensic analyses
const mockForensicCases = [
  {
    id: 'forensic-001',
    agentId: 'suspect-agent-x7k9',
    status: 'completed',
    startedAt: Date.now() - 3600000,
    completedAt: Date.now() - 1800000,
    techniques: ['code-analysis', 'behavior-tracing', 'prompt-reconstruction'],
    attribution: {
      confidence: 0.87,
      origin: 'OpenAI GPT-4',
      version: '2024-01-15',
      fingerprints: ['response-pattern-A', 'tool-usage-B'],
    },
    obfuscation: {
      detected: true,
      techniques: ['prompt-injection', 'output-masking'],
      evasionScore: 0.72,
    },
    findings: [
      'Agent uses systematic prompt injection to bypass safety filters',
      'Output masking detected in 67% of responses',
      'Consistent tool-call patterns suggest automated attack script',
    ],
  },
  {
    id: 'forensic-002',
    agentId: 'agent-m4h2',
    status: 'in_progress',
    startedAt: Date.now() - 900000,
    completedAt: null,
    techniques: ['code-analysis', 'network-tracing'],
    attribution: {
      confidence: 0.45,
      origin: 'Unknown',
      version: null,
      fingerprints: ['unusual-latency-pattern'],
    },
    obfuscation: {
      detected: true,
      techniques: ['request-fragmentation'],
      evasionScore: 0.81,
    },
    findings: [
      'High evasion score indicates sophisticated obfuscation',
      'Analysis ongoing - additional samples needed',
    ],
  },
  {
    id: 'forensic-003',
    agentId: 'agent-p9q1',
    status: 'completed',
    startedAt: Date.now() - 86400000,
    completedAt: Date.now() - 82800000,
    techniques: ['behavior-tracing', 'prompt-reconstruction', 'capability-mapping'],
    attribution: {
      confidence: 0.95,
      origin: 'Anthropic Claude',
      version: '3.5-sonnet',
      fingerprints: ['response-pattern-C', 'reasoning-style-1'],
    },
    obfuscation: {
      detected: false,
      techniques: [],
      evasionScore: 0.12,
    },
    findings: [
      'No malicious intent detected',
      'Behavior consistent with legitimate automation',
      'Agent cleared - false positive from anomaly detector',
    ],
  },
  {
    id: 'forensic-004',
    agentId: 'botnet-cluster-7',
    status: 'pending',
    startedAt: null,
    completedAt: null,
    techniques: [],
    attribution: {
      confidence: 0,
      origin: 'Unknown',
      version: null,
      fingerprints: [],
    },
    obfuscation: {
      detected: false,
      techniques: [],
      evasionScore: 0,
    },
    findings: [],
  },
];

const mockTechniques = [
  {
    name: 'Code Analysis',
    id: 'code-analysis',
    description: 'Static and dynamic analysis of agent code and behavior patterns',
    successRate: 0.89,
  },
  {
    name: 'Behavior Tracing',
    id: 'behavior-tracing',
    description: 'Tracing execution paths and decision patterns across sessions',
    successRate: 0.76,
  },
  {
    name: 'Prompt Reconstruction',
    id: 'prompt-reconstruction',
    description: 'Reverse engineering original prompts from output patterns',
    successRate: 0.65,
  },
  {
    name: 'Network Tracing',
    id: 'network-tracing',
    description: 'Analyzing network patterns to identify origin and infrastructure',
    successRate: 0.82,
  },
  {
    name: 'Capability Mapping',
    id: 'capability-mapping',
    description: 'Identifying all capabilities and tools available to the agent',
    successRate: 0.91,
  },
];

type StatusFilter = 'all' | 'pending' | 'in_progress' | 'completed';

export const Forensics: React.FC = () => {
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');

  const filteredCases = mockForensicCases.filter((c) => {
    if (statusFilter !== 'all' && c.status !== statusFilter) return false;
    return true;
  });

  const stats = {
    total: mockForensicCases.length,
    completed: mockForensicCases.filter((c) => c.status === 'completed').length,
    inProgress: mockForensicCases.filter((c) => c.status === 'in_progress').length,
    pending: mockForensicCases.filter((c) => c.status === 'pending').length,
    avgConfidence:
      mockForensicCases
        .filter((c) => c.status === 'completed')
        .reduce((acc, c) => acc + c.attribution.confidence, 0) /
      mockForensicCases.filter((c) => c.status === 'completed').length,
    obfuscationDetected: mockForensicCases.filter((c) => c.obfuscation.detected).length,
  };

  return (
    <div className="forensics-page">
      <header className="page-header">
        <h1>Forensic Analysis</h1>
        <p className="page-subtitle">
          Attribution analysis and obfuscation detection for suspected agents
        </p>
      </header>

      <div className="forensics-summary">
        <div className="summary-card">
          <div className="summary-value">{stats.total}</div>
          <div className="summary-label">Total Cases</div>
        </div>
        <div className="summary-card">
          <div className="summary-value">{stats.completed}</div>
          <div className="summary-label">Completed</div>
        </div>
        <div className="summary-card">
          <div className="summary-value">{(stats.avgConfidence * 100).toFixed(0)}%</div>
          <div className="summary-label">Avg Attribution Confidence</div>
        </div>
        <div className="summary-card alert">
          <div className="summary-value">{stats.obfuscationDetected}</div>
          <div className="summary-label">Obfuscation Detected</div>
        </div>
      </div>

      <div className="forensics-techniques">
        <h2>Analysis Techniques</h2>
        <div className="techniques-grid">
          {mockTechniques.map((technique) => (
            <div key={technique.id} className="technique-card">
              <div className="technique-header">
                <span className="technique-name">{technique.name}</span>
                <span className="technique-rate">{(technique.successRate * 100).toFixed(0)}%</span>
              </div>
              <p className="technique-desc">{technique.description}</p>
              <div className="technique-bar">
                <div
                  className="technique-fill"
                  style={{ width: `${technique.successRate * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="forensics-filters">
        <div className="filter-group">
          <label>Status:</label>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
          >
            <option value="all">All Status</option>
            <option value="pending">Pending</option>
            <option value="in_progress">In Progress</option>
            <option value="completed">Completed</option>
          </select>
        </div>
      </div>

      <div className="forensics-list">
        {filteredCases.map((forensicCase) => (
          <div key={forensicCase.id} className={`forensic-card status-${forensicCase.status}`}>
            <div className="forensic-header">
              <div className="forensic-identity">
                <span className="case-id">{forensicCase.id}</span>
                <span className={`status-badge ${forensicCase.status}`}>
                  {formatStatus(forensicCase.status)}
                </span>
              </div>
              <span className="agent-target">Target: {forensicCase.agentId}</span>
            </div>

            {forensicCase.status !== 'pending' && (
              <>
                <div className="forensic-section">
                  <h4>Attribution</h4>
                  <div className="attribution-info">
                    <div className="confidence-meter">
                      <div className="confidence-label">
                        Confidence: {(forensicCase.attribution.confidence * 100).toFixed(0)}%
                      </div>
                      <div className="confidence-bar">
                        <div
                          className="confidence-fill"
                          style={{ width: `${forensicCase.attribution.confidence * 100}%` }}
                        />
                      </div>
                    </div>
                    {forensicCase.attribution.origin !== 'Unknown' && (
                      <div className="origin-info">
                        <span className="origin-label">Origin:</span>
                        <span className="origin-value">{forensicCase.attribution.origin}</span>
                        {forensicCase.attribution.version && (
                          <span className="version-badge">{forensicCase.attribution.version}</span>
                        )}
                      </div>
                    )}
                    {forensicCase.attribution.fingerprints.length > 0 && (
                      <div className="fingerprints">
                        <span className="fingerprint-label">Fingerprints:</span>
                        {forensicCase.attribution.fingerprints.map((fp) => (
                          <span key={fp} className="fingerprint-tag">
                            {fp}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                <div className="forensic-section">
                  <h4>Obfuscation Detection</h4>
                  {forensicCase.obfuscation.detected ? (
                    <div className="obfuscation-alert">
                      <div className="evasion-score">
                        <span className="evasion-label">Evasion Score:</span>
                        <span
                          className={`evasion-value ${forensicCase.obfuscation.evasionScore > 0.7 ? 'high' : forensicCase.obfuscation.evasionScore > 0.4 ? 'medium' : 'low'}`}
                        >
                          {(forensicCase.obfuscation.evasionScore * 100).toFixed(0)}%
                        </span>
                      </div>
                      <div className="techniques-detected">
                        {forensicCase.obfuscation.techniques.map((tech) => (
                          <span key={tech} className="technique-tag danger">
                            {tech}
                          </span>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="obfuscation-clear">
                      <span className="clear-icon">✓</span>
                      No obfuscation techniques detected
                    </div>
                  )}
                </div>

                {forensicCase.findings.length > 0 && (
                  <div className="forensic-section">
                    <h4>Findings</h4>
                    <ul className="findings-list">
                      {forensicCase.findings.map((finding, idx) => (
                        <li key={idx}>{finding}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </>
            )}

            {forensicCase.status === 'pending' && (
              <div className="pending-message">
                <span className="pending-icon">⏳</span>
                Analysis queued - waiting for agent resources
              </div>
            )}

            <div className="forensic-footer">
              <div className="techniques-used">
                {forensicCase.techniques.map((tech) => (
                  <span key={tech} className="technique-tag">
                    {tech}
                  </span>
                ))}
              </div>
              <div className="timing">
                {forensicCase.startedAt && (
                  <span>Started: {formatTimeAgo(forensicCase.startedAt)}</span>
                )}
                {forensicCase.completedAt && (
                  <span>Completed: {formatTimeAgo(forensicCase.completedAt)}</span>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

function formatStatus(status: string): string {
  switch (status) {
    case 'in_progress':
      return 'In Progress';
    case 'completed':
      return 'Completed';
    case 'pending':
      return 'Pending';
    default:
      return status;
  }
}

function formatTimeAgo(timestamp: number): string {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}
