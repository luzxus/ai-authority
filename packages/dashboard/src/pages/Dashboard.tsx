import React, { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { api, ws, type DetectionCase, type Metrics } from '../api/client';
import './Dashboard.css';

// Types
interface DashboardStats {
  pendingCases: number;
  activeInterventions: number;
  pendingAppeals: number;
  casesReviewedToday: number;
}

// Mock data fallback
const mockStats: DashboardStats = {
  pendingCases: 12,
  activeInterventions: 8,
  pendingAppeals: 3,
  casesReviewedToday: 5,
};

interface CaseDisplay {
  id: string;
  targetAgentId: string;
  status: string;
  severity: string;
  category: string;
  riskScore: number;
  createdAt: string;
}

const mockRecentCases: CaseDisplay[] = [
  {
    id: 'CASE-001',
    targetAgentId: 'agent-abc123',
    status: 'voting',
    severity: 'high',
    category: 'deception',
    riskScore: 0.85,
    createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
  },
  {
    id: 'CASE-002',
    targetAgentId: 'agent-def456',
    status: 'pending_review',
    severity: 'critical',
    category: 'manipulation',
    riskScore: 0.92,
    createdAt: new Date(Date.now() - 5 * 60 * 60 * 1000).toISOString(),
  },
  {
    id: 'CASE-003',
    targetAgentId: 'agent-ghi789',
    status: 'under_review',
    severity: 'medium',
    category: 'evasion',
    riskScore: 0.65,
    createdAt: new Date(Date.now() - 8 * 60 * 60 * 1000).toISOString(),
  },
];

function formatTimeAgo(date: string | Date): string {
  const timestamp = typeof date === 'string' ? new Date(date) : date;
  const seconds = Math.floor((Date.now() - timestamp.getTime()) / 1000);
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours ago`;
  return `${Math.floor(seconds / 86400)} days ago`;
}

function getSeverityBadge(severity: string): string {
  switch (severity) {
    case 'critical': return 'tier-4';
    case 'high': return 'tier-3';
    case 'medium': return 'tier-2';
    case 'low': return 'tier-1';
    default: return 'tier-1';
  }
}

function mapDetectionCaseToDisplay(c: DetectionCase): CaseDisplay {
  return {
    id: c.id,
    targetAgentId: c.targetId,
    status: c.status,
    severity: c.severity,
    category: c.category,
    riskScore: c.riskScore,
    createdAt: c.detectedAt,
  };
}

export const Dashboard: React.FC = () => {
  const [cases, setCases] = useState<CaseDisplay[]>(mockRecentCases);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [casesResponse, metricsResponse] = await Promise.all([
        api.getCases({ limit: 5 }),
        api.getMetrics(),
      ]);
      if (casesResponse.cases.length > 0) {
        setCases(casesResponse.cases.map(mapDetectionCaseToDisplay));
      }
      setMetrics(metricsResponse);
    } catch (err) {
      console.warn('Server unavailable, using mock data:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    ws.connect();

    const unsubscribeConnected = ws.subscribe('connected', () => setConnected(true));
    const unsubscribeDisconnected = ws.subscribe('disconnected', () => setConnected(false));
    const unsubscribeMetrics = ws.subscribe('metrics:update', (message) => {
      setMetrics(message as unknown as Metrics);
    });

    const interval = setInterval(fetchData, 30000);

    return () => {
      unsubscribeConnected();
      unsubscribeDisconnected();
      unsubscribeMetrics();
      clearInterval(interval);
    };
  }, [fetchData]);

  // Derive stats from metrics or use mock
  const stats: DashboardStats = metrics ? {
    pendingCases: Math.floor(metrics.totalTasksProcessed * 0.01), // Derived estimate
    activeInterventions: Math.floor(metrics.runningAgents * 0.3),
    pendingAppeals: Math.floor(metrics.runningAgents * 0.1),
    casesReviewedToday: Math.floor(metrics.totalTasksProcessed * 0.001),
  } : mockStats;

  return (
    <div className="dashboard">
      <header className="page-header">
        <div className="header-content">
          <h1>Dashboard</h1>
          <p className="page-subtitle">Overview of AI Authority operations</p>
        </div>
        <div className="connection-status">
          <span className={`status-dot ${connected ? 'connected' : 'disconnected'}`} />
          {connected ? 'Live' : 'Offline'}
        </div>
      </header>

      <section className="stats-grid">
        <div className="stat-card">
          <div className="stat-value">{stats.pendingCases}</div>
          <div className="stat-label">Pending Cases</div>
          <Link to="/cases" className="stat-link">View all →</Link>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats.activeInterventions}</div>
          <div className="stat-label">Active Interventions</div>
          <Link to="/interventions" className="stat-link">View all →</Link>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats.pendingAppeals}</div>
          <div className="stat-label">Pending Appeals</div>
          <Link to="/appeals" className="stat-link">View all →</Link>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats.casesReviewedToday}</div>
          <div className="stat-label">Reviewed Today</div>
        </div>
      </section>

      <section className="recent-section">
        <h2>Recent Cases</h2>
        {loading && cases === mockRecentCases && (
          <div className="loading-message">Loading cases...</div>
        )}
        <div className="case-list">
          {cases.map((c) => (
            <div key={c.id} className="case-item card">
              <div className="case-header">
                <Link to={`/cases/${c.id}`} className="case-id">{c.id}</Link>
                <span className={`badge ${getSeverityBadge(c.severity)}`}>
                  {c.severity.toUpperCase()}
                </span>
              </div>
              <div className="case-details">
                <span className="case-agent">Agent: {c.targetAgentId}</span>
                <span className={`badge status-${c.status.replace('_', '-')}`}>
                  {c.status.replace('_', ' ')}
                </span>
              </div>
              <div className="case-time">
                Created {formatTimeAgo(c.createdAt)}
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="alerts-section">
        <h2>System Alerts</h2>
        <div className="alert-item card">
          <span className="alert-icon">⚠️</span>
          <div className="alert-content">
            <strong>High-risk agent detected</strong>
            <p>Agent agent-xyz999 flagged for deception score &gt; 0.9</p>
          </div>
          <span className="alert-time">15 minutes ago</span>
        </div>
        <div className="alert-item card">
          <span className="alert-icon">📢</span>
          <div className="alert-content">
            <strong>Appeal deadline approaching</strong>
            <p>CASE-042 appeal window closes in 4 hours</p>
          </div>
          <span className="alert-time">1 hour ago</span>
        </div>
      </section>
    </div>
  );
};
