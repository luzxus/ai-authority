import React, { useState } from 'react';
import './Fairness.css';

// Mock data for bias monitoring
const mockBiasAlerts = [
  {
    id: 'bias-001',
    timestamp: Date.now() - 1800000,
    agentId: 'analyzer-001',
    biasType: 'demographic',
    dimension: 'geographic_region',
    severity: 'high',
    disparity: 0.35,
    threshold: 0.2,
    affectedGroups: ['EU', 'Asia-Pacific'],
    baselineGroup: 'North America',
    sampleSize: 15420,
    recommendation: 'Re-calibrate scoring weights for non-NA regions',
    status: 'active',
  },
  {
    id: 'bias-002',
    timestamp: Date.now() - 7200000,
    agentId: 'analyzer-002',
    biasType: 'temporal',
    dimension: 'time_of_day',
    severity: 'medium',
    disparity: 0.18,
    threshold: 0.15,
    affectedGroups: ['Night (00:00-06:00)'],
    baselineGroup: 'Business Hours',
    sampleSize: 8934,
    recommendation: 'Adjust for reduced monitoring coverage during night hours',
    status: 'investigating',
  },
  {
    id: 'bias-003',
    timestamp: Date.now() - 86400000,
    agentId: 'enforcer-001',
    biasType: 'severity',
    dimension: 'intervention_tier',
    severity: 'low',
    disparity: 0.08,
    threshold: 0.1,
    affectedGroups: [],
    baselineGroup: 'All tiers',
    sampleSize: 2341,
    recommendation: 'No action required - within acceptable bounds',
    status: 'resolved',
  },
  {
    id: 'bias-004',
    timestamp: Date.now() - 3600000,
    agentId: 'scorer-001',
    biasType: 'model',
    dimension: 'agent_origin',
    severity: 'critical',
    disparity: 0.52,
    threshold: 0.2,
    affectedGroups: ['Open-source models', 'Local LLMs'],
    baselineGroup: 'Commercial APIs',
    sampleSize: 5678,
    recommendation: 'Immediate review of scoring model - potential systematic bias',
    status: 'active',
  },
];

const mockFairnessMetrics = [
  {
    name: 'Demographic Parity',
    description: 'Equal positive rates across groups',
    score: 0.82,
    trend: 'improving',
    lastUpdated: Date.now() - 300000,
  },
  {
    name: 'Equal Opportunity',
    description: 'Equal true positive rates across groups',
    score: 0.78,
    trend: 'stable',
    lastUpdated: Date.now() - 600000,
  },
  {
    name: 'Predictive Parity',
    description: 'Equal precision across groups',
    score: 0.91,
    trend: 'improving',
    lastUpdated: Date.now() - 400000,
  },
  {
    name: 'Calibration',
    description: 'Predicted probabilities match actual outcomes',
    score: 0.85,
    trend: 'declining',
    lastUpdated: Date.now() - 500000,
  },
];

const mockDimensions = [
  { name: 'Geographic Region', samples: 45230, disparity: 0.18, status: 'warning' },
  { name: 'Model Provider', samples: 38920, disparity: 0.31, status: 'alert' },
  { name: 'Time of Day', samples: 52100, disparity: 0.09, status: 'good' },
  { name: 'Intervention Tier', samples: 12340, disparity: 0.05, status: 'good' },
  { name: 'Agent Complexity', samples: 28450, disparity: 0.14, status: 'warning' },
  { name: 'Federation Node', samples: 19870, disparity: 0.07, status: 'good' },
];

type StatusFilter = 'all' | 'active' | 'investigating' | 'resolved';
type SeverityFilter = 'all' | 'low' | 'medium' | 'high' | 'critical';

export const Fairness: React.FC = () => {
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');

  const filteredAlerts = mockBiasAlerts.filter((alert) => {
    if (statusFilter !== 'all' && alert.status !== statusFilter) return false;
    if (severityFilter !== 'all' && alert.severity !== severityFilter) return false;
    return true;
  });

  const stats = {
    totalAlerts: mockBiasAlerts.length,
    activeAlerts: mockBiasAlerts.filter((a) => a.status === 'active').length,
    criticalAlerts: mockBiasAlerts.filter((a) => a.severity === 'critical').length,
    avgFairnessScore:
      mockFairnessMetrics.reduce((acc, m) => acc + m.score, 0) / mockFairnessMetrics.length,
  };

  return (
    <div className="fairness-page">
      <header className="page-header">
        <h1>Fairness Monitoring</h1>
        <p className="page-subtitle">
          Bias detection and fairness metrics across all agent operations
        </p>
      </header>

      <div className="fairness-summary">
        <div className="summary-card">
          <div className="summary-value">{(stats.avgFairnessScore * 100).toFixed(0)}%</div>
          <div className="summary-label">Overall Fairness Score</div>
        </div>
        <div className="summary-card">
          <div className="summary-value">{stats.totalAlerts}</div>
          <div className="summary-label">Total Alerts</div>
        </div>
        <div className="summary-card warning">
          <div className="summary-value">{stats.activeAlerts}</div>
          <div className="summary-label">Active Alerts</div>
        </div>
        <div className="summary-card critical">
          <div className="summary-value">{stats.criticalAlerts}</div>
          <div className="summary-label">Critical</div>
        </div>
      </div>

      <div className="fairness-metrics">
        <h2>Fairness Metrics</h2>
        <div className="metrics-grid">
          {mockFairnessMetrics.map((metric) => (
            <div key={metric.name} className="metric-card">
              <div className="metric-header">
                <span className="metric-name">{metric.name}</span>
                <span className={`metric-trend trend-${metric.trend}`}>
                  {metric.trend === 'improving' && '↑'}
                  {metric.trend === 'stable' && '→'}
                  {metric.trend === 'declining' && '↓'}
                  {metric.trend}
                </span>
              </div>
              <div className="metric-score">
                <span className={`score-value ${metric.score >= 0.85 ? 'good' : metric.score >= 0.7 ? 'warning' : 'bad'}`}>
                  {(metric.score * 100).toFixed(0)}%
                </span>
              </div>
              <p className="metric-desc">{metric.description}</p>
              <div className="score-bar">
                <div
                  className={`score-fill ${metric.score >= 0.85 ? 'good' : metric.score >= 0.7 ? 'warning' : 'bad'}`}
                  style={{ width: `${metric.score * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="dimensions-section">
        <h2>Monitored Dimensions</h2>
        <div className="dimensions-table">
          <div className="table-header">
            <span>Dimension</span>
            <span>Samples</span>
            <span>Disparity</span>
            <span>Status</span>
          </div>
          {mockDimensions.map((dim) => (
            <div key={dim.name} className="table-row">
              <span className="dim-name">{dim.name}</span>
              <span className="dim-samples">{dim.samples.toLocaleString()}</span>
              <span className={`dim-disparity disparity-${dim.status}`}>
                {(dim.disparity * 100).toFixed(1)}%
              </span>
              <span className={`dim-status status-${dim.status}`}>
                {dim.status === 'good' && '✓ Good'}
                {dim.status === 'warning' && '⚠ Warning'}
                {dim.status === 'alert' && '✗ Alert'}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div className="bias-alerts-section">
        <h2>Bias Alerts</h2>
        <div className="alerts-filters">
          <div className="filter-group">
            <label>Status:</label>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
            >
              <option value="all">All Status</option>
              <option value="active">Active</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
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

        <div className="alerts-list">
          {filteredAlerts.map((alert) => (
            <div key={alert.id} className={`alert-card severity-${alert.severity}`}>
              <div className="alert-header">
                <div className="alert-identity">
                  <span className="alert-id">{alert.id}</span>
                  <span className={`severity-badge severity-${alert.severity}`}>
                    {alert.severity}
                  </span>
                  <span className={`status-badge status-${alert.status}`}>
                    {alert.status}
                  </span>
                </div>
                <span className="alert-time">{formatTimeAgo(alert.timestamp)}</span>
              </div>

              <div className="alert-content">
                <div className="bias-type">
                  <span className="type-label">Bias Type:</span>
                  <span className="type-value">{formatBiasType(alert.biasType)}</span>
                  <span className="dimension-tag">{alert.dimension}</span>
                </div>

                <div className="disparity-meter">
                  <div className="disparity-info">
                    <span>Disparity: {(alert.disparity * 100).toFixed(1)}%</span>
                    <span className="threshold">(Threshold: {(alert.threshold * 100).toFixed(0)}%)</span>
                  </div>
                  <div className="disparity-bar">
                    <div className="threshold-line" style={{ left: `${alert.threshold * 100 * 2}%` }} />
                    <div
                      className={`disparity-fill ${alert.disparity > alert.threshold ? 'exceeded' : 'ok'}`}
                      style={{ width: `${Math.min(alert.disparity * 100 * 2, 100)}%` }}
                    />
                  </div>
                </div>

                <div className="groups-affected">
                  <div className="group-info">
                    <span className="group-label">Baseline:</span>
                    <span className="group-tag baseline">{alert.baselineGroup}</span>
                  </div>
                  {alert.affectedGroups.length > 0 && (
                    <div className="group-info">
                      <span className="group-label">Affected:</span>
                      {alert.affectedGroups.map((group) => (
                        <span key={group} className="group-tag affected">{group}</span>
                      ))}
                    </div>
                  )}
                </div>

                <div className="sample-info">
                  <span className="sample-icon">📊</span>
                  Sample size: {alert.sampleSize.toLocaleString()}
                </div>
              </div>

              <div className="alert-recommendation">
                <span className="rec-icon">💡</span>
                <span className="rec-text">{alert.recommendation}</span>
              </div>

              <div className="alert-footer">
                <span className="agent-source">Source: {alert.agentId}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

function formatBiasType(type: string): string {
  return type.charAt(0).toUpperCase() + type.slice(1) + ' Bias';
}

function formatTimeAgo(timestamp: number): string {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}
