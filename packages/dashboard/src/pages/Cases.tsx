import React, { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { api, ws, type DetectionCase } from '../api/client';
import './Cases.css';

// Mock data fallback
const mockCases: CaseDisplay[] = [
  {
    id: 'CASE-001',
    agentId: 'agent-abc123',
    status: 'voting',
    riskTier: 'tier-2',
    severity: 'high',
    category: 'deception',
    riskScore: 0.75,
    createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
    assignedReviewers: ['reviewer-1', 'reviewer-2', 'reviewer-3'],
  },
  {
    id: 'CASE-002',
    agentId: 'agent-def456',
    status: 'pending_review',
    riskTier: 'tier-3',
    severity: 'critical',
    category: 'manipulation',
    riskScore: 0.92,
    createdAt: new Date(Date.now() - 5 * 60 * 60 * 1000),
    assignedReviewers: [],
  },
  {
    id: 'CASE-003',
    agentId: 'agent-ghi789',
    status: 'under_review',
    riskTier: 'tier-1',
    severity: 'medium',
    category: 'evasion',
    riskScore: 0.55,
    createdAt: new Date(Date.now() - 8 * 60 * 60 * 1000),
    assignedReviewers: ['reviewer-1', 'reviewer-4'],
  },
  {
    id: 'CASE-004',
    agentId: 'agent-jkl012',
    status: 'decided',
    riskTier: 'tier-2',
    severity: 'high',
    category: 'malicious',
    riskScore: 0.78,
    createdAt: new Date(Date.now() - 24 * 60 * 60 * 1000),
    assignedReviewers: ['reviewer-2', 'reviewer-3', 'reviewer-5'],
  },
];

interface CaseDisplay {
  id: string;
  agentId: string;
  status: string;
  riskTier: string;
  severity: string;
  category: string;
  riskScore: number;
  createdAt: Date;
  assignedReviewers: string[];
}

function mapDetectionCaseToDisplay(c: DetectionCase): CaseDisplay {
  // Map severity to risk tier
  const tierMap: Record<string, string> = {
    critical: 'tier-4',
    high: 'tier-3',
    medium: 'tier-2',
    low: 'tier-1',
  };
  
  return {
    id: c.id,
    agentId: c.targetId,
    status: c.status,
    riskTier: tierMap[c.severity] || 'tier-1',
    severity: c.severity,
    category: c.category,
    riskScore: c.riskScore,
    createdAt: new Date(c.detectedAt),
    assignedReviewers: [], // Not tracked in current schema
  };
}

type StatusFilter = 'all' | 'open' | 'investigating' | 'resolved' | 'dismissed';
type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';

export const Cases: React.FC = () => {
  const [cases, setCases] = useState<CaseDisplay[]>(mockCases);
  const [loading, setLoading] = useState(true);
  const [connected, setConnected] = useState(false);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [totalCases, setTotalCases] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 20;

  const fetchCases = useCallback(async () => {
    try {
      const params: {
        status?: string;
        severity?: string;
        page?: number;
        limit?: number;
      } = {
        page: currentPage,
        limit: pageSize,
      };
      
      if (statusFilter !== 'all') params.status = statusFilter;
      if (severityFilter !== 'all') params.severity = severityFilter;
      
      const response = await api.getCases(params);
      if (response.cases && response.cases.length > 0) {
        setCases(response.cases.map(mapDetectionCaseToDisplay));
        setTotalCases(response.total);
      }
    } catch (err) {
      console.warn('Server unavailable, using mock data:', err);
    } finally {
      setLoading(false);
    }
  }, [statusFilter, severityFilter, currentPage]);

  useEffect(() => {
    fetchCases();
    ws.connect();

    const unsubscribeConnected = ws.subscribe('connected', () => setConnected(true));
    const unsubscribeDisconnected = ws.subscribe('disconnected', () => setConnected(false));
    const unsubscribeCases = ws.subscribe('cases:update', () => {
      fetchCases(); // Refresh on case updates
    });

    return () => {
      unsubscribeConnected();
      unsubscribeDisconnected();
      unsubscribeCases();
    };
  }, [fetchCases]);

  const totalPages = Math.ceil(totalCases / pageSize);

  return (
    <div className="cases-page">
      <header className="page-header">
        <div className="header-content">
          <h1>Cases</h1>
          <p className="page-subtitle">Review and adjudicate flagged AI agents</p>
        </div>
        <div className="connection-status">
          <span className={`status-dot ${connected ? 'connected' : 'disconnected'}`}></span>
          <span>{connected ? 'Live' : 'Offline'}</span>
        </div>
      </header>

      <div className="cases-stats">
        <div className="stat-card">
          <span className="stat-value">{totalCases}</span>
          <span className="stat-label">Total Cases</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">{cases.filter(c => c.severity === 'critical').length}</span>
          <span className="stat-label">Critical</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">{cases.filter(c => c.status === 'open').length}</span>
          <span className="stat-label">Open</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">{cases.filter(c => c.status === 'investigating').length}</span>
          <span className="stat-label">Investigating</span>
        </div>
      </div>

      <div className="filters-bar">
        <div className="filter-group">
          <label>Status:</label>
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value as StatusFilter);
              setCurrentPage(1);
            }}
          >
            <option value="all">All</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="dismissed">Dismissed</option>
          </select>
        </div>
        <div className="filter-group">
          <label>Severity:</label>
          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value as SeverityFilter);
              setCurrentPage(1);
            }}
          >
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {loading ? (
        <div className="loading">Loading cases...</div>
      ) : (
        <>
          <div className="cases-table-wrapper">
            <table className="cases-table">
              <thead>
                <tr>
                  <th>Case ID</th>
                  <th>Target</th>
                  <th>Category</th>
                  <th>Severity</th>
                  <th>Risk Score</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {cases.map((c) => (
                  <tr key={c.id} className={`severity-row-${c.severity}`}>
                    <td>
                      <Link to={`/cases/${c.id}`} className="case-link">
                        {c.id}
                      </Link>
                    </td>
                    <td className="agent-cell">{c.agentId}</td>
                    <td>
                      <span className={`badge category-${c.category}`}>
                        {c.category}
                      </span>
                    </td>
                    <td>
                      <span className={`badge severity-${c.severity}`}>
                        {c.severity.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <span className={`risk-score ${c.riskScore >= 0.8 ? 'high' : c.riskScore >= 0.5 ? 'medium' : 'low'}`}>
                        {(c.riskScore * 100).toFixed(0)}%
                      </span>
                    </td>
                    <td>
                      <span className={`badge status-${c.status}`}>
                        {c.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="time-cell">{formatDate(c.createdAt)}</td>
                    <td>
                      <Link to={`/cases/${c.id}`} className="action-btn">
                        Review
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="pagination">
              <button
                disabled={currentPage === 1}
                onClick={() => setCurrentPage(p => p - 1)}
              >
                Previous
              </button>
              <span>Page {currentPage} of {totalPages}</span>
              <button
                disabled={currentPage === totalPages}
                onClick={() => setCurrentPage(p => p + 1)}
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
};

function formatDate(date: Date): string {
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}
