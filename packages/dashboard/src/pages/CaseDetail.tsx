import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api, type CaseDetail as CaseDetailData } from '../api/client';
import './CaseDetail.css';

interface Evidence {
  id: string;
  type: string;
  description: string;
  data?: {
    summary?: string;
    riskAssessment?: string;
    recommendation?: string;
    evidenceCited?: string[];
    [key: string]: unknown;
  };
  collectedAt: string;
  collectedBy: string;
}

interface TimelineEvent {
  id: string;
  timestamp: string;
  type: string;
  description: string;
  actor: string;
}

export const CaseDetail: React.FC = () => {
  const { caseId } = useParams<{ caseId: string }>();
  const [caseData, setCaseData] = useState<CaseDetailData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [voteDecision, setVoteDecision] = useState('');
  const [voteRationale, setVoteRationale] = useState('');

  useEffect(() => {
    if (!caseId) return;

    const fetchCase = async () => {
      try {
        setLoading(true);
        setError(null);
        const data = await api.getCase(caseId);
        setCaseData(data);
      } catch (err) {
        console.error('Failed to fetch case:', err);
        setError(err instanceof Error ? err.message : 'Failed to load case');
      } finally {
        setLoading(false);
      }
    };

    fetchCase();
  }, [caseId]);

  const handleVote = () => {
    if (!voteDecision || !voteRationale) {
      alert('Please select a decision and provide a rationale');
      return;
    }
    alert(`Vote submitted: ${voteDecision}\nRationale: ${voteRationale}`);
  };

  // Map severity to tier
  const getTier = (severity: string): number => {
    const tierMap: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
    return tierMap[severity] || 1;
  };

  if (loading) {
    return (
      <div className="case-detail">
        <header className="page-header">
          <div className="header-nav">
            <Link to="/cases" className="back-link">← Back to Cases</Link>
          </div>
        </header>
        <div className="loading-state">Loading case details...</div>
      </div>
    );
  }

  if (error || !caseData) {
    return (
      <div className="case-detail">
        <header className="page-header">
          <div className="header-nav">
            <Link to="/cases" className="back-link">← Back to Cases</Link>
          </div>
        </header>
        <div className="error-state">
          <h2>Error Loading Case</h2>
          <p>{error || 'Case not found'}</p>
        </div>
      </div>
    );
  }

  const tier = getTier(caseData.severity);
  const evidence = (caseData.evidence || []) as Evidence[];
  const timeline = (caseData.timeline || []) as TimelineEvent[];

  // Find analysis report in evidence
  const analysisReport = evidence.find(e => e.type === 'analysis_report');
  const otherEvidence = evidence.filter(e => e.type !== 'analysis_report');

  return (
    <div className="case-detail">
      <header className="page-header">
        <div className="header-nav">
          <Link to="/cases" className="back-link">← Back to Cases</Link>
        </div>
        <div className="header-main">
          <h1>{caseData.title || caseId}</h1>
          <span className={`badge tier-${tier}`}>
            TIER {tier}
          </span>
        </div>
        <p className="page-subtitle">Target: {caseData.targetId} ({caseData.targetType})</p>
      </header>

      <div className="case-content">
        <div className="main-column">
          {/* Summary Card */}
          <section className="card summary-card">
            <h2>Summary</h2>
            <p className="case-description">{caseData.description}</p>
            {caseData.threatTypes && caseData.threatTypes.length > 0 && (
              <div className="threat-types">
                <strong>Threat Types: </strong>
                {caseData.threatTypes.map((t: string) => (
                  <span key={t} className="badge threat-type">{t.replace(/_/g, ' ')}</span>
                ))}
              </div>
            )}
          </section>

          {/* Analysis Report Card */}
          {analysisReport && (
            <section className="card analysis-card">
              <h2>🔍 Analysis Report</h2>
              <div className="analysis-content">
                <div 
                  className="analysis-description" 
                  dangerouslySetInnerHTML={{ __html: formatMarkdown(analysisReport.description) }} 
                />
                
                {analysisReport.data && (
                  <>
                    {analysisReport.data.riskAssessment && (
                      <div className="analysis-section">
                        <h3>Risk Assessment</h3>
                        <p>{analysisReport.data.riskAssessment}</p>
                      </div>
                    )}
                    
                    {analysisReport.data.recommendation && (
                      <div className="analysis-section recommendation">
                        <h3>Recommendation</h3>
                        <p>{analysisReport.data.recommendation}</p>
                      </div>
                    )}

                    {analysisReport.data.evidenceCited && analysisReport.data.evidenceCited.length > 0 && (
                      <div className="analysis-section">
                        <h3>Evidence Cited</h3>
                        <ul className="evidence-cited-list">
                          {analysisReport.data.evidenceCited.map((e, i) => (
                            <li key={i} dangerouslySetInnerHTML={{ __html: formatMarkdown(e) }} />
                          ))}
                        </ul>
                      </div>
                    )}
                  </>
                )}
              </div>
              <div className="analysis-meta">
                <span>Generated by: {analysisReport.collectedBy}</span>
                <span>{new Date(analysisReport.collectedAt).toLocaleString()}</span>
              </div>
            </section>
          )}

          {/* Risk Score Card */}
          <section className="card">
            <h2>Risk Assessment</h2>
            <div className="risk-overview">
              <div className="overall-score">
                <div className="score-value">{(caseData.riskScore * 100).toFixed(0)}%</div>
                <div className="score-label">Confidence Score</div>
              </div>
              <div className="risk-details">
                <div className="risk-item">
                  <span className="risk-label">Severity</span>
                  <span className={`badge severity-${caseData.severity}`}>
                    {caseData.severity.toUpperCase()}
                  </span>
                </div>
                <div className="risk-item">
                  <span className="risk-label">Category</span>
                  <span className={`badge category-${caseData.category}`}>
                    {caseData.category}
                  </span>
                </div>
              </div>
            </div>
          </section>

          {/* Raw Evidence Card */}
          <section className="card">
            <h2>Raw Evidence ({otherEvidence.length})</h2>
            <div className="evidence-list">
              {otherEvidence.map((ev) => (
                <div key={ev.id} className="evidence-item">
                  <div className="evidence-header">
                    <span className="evidence-id">{ev.id}</span>
                    <span className={`badge evidence-type-${ev.type.replace(/_/g, '-')}`}>
                      {ev.type.replace(/_/g, ' ')}
                    </span>
                  </div>
                  <p className="evidence-description">{ev.description}</p>
                  <span className="evidence-time">
                    {new Date(ev.collectedAt).toLocaleString()} • {ev.collectedBy}
                  </span>
                </div>
              ))}
              {otherEvidence.length === 0 && (
                <p className="no-evidence">No additional evidence collected</p>
              )}
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
            <span className={`badge status-${caseData.status.replace('_', '-')}`}>
              {caseData.status.replace('_', ' ')}
            </span>
            <div className="status-info">
              <div className="info-row">
                <span className="info-label">Detected</span>
                <span className="info-value">{new Date(caseData.detectedAt).toLocaleString()}</span>
              </div>
              <div className="info-row">
                <span className="info-label">Detected By</span>
                <span className="info-value">{caseData.detectedBy}</span>
              </div>
              {caseData.moltbookUsername && (
                <div className="info-row">
                  <span className="info-label">Moltbook User</span>
                  <span className="info-value">
                    <a 
                      href={`https://www.moltbook.com/@${caseData.moltbookUsername}`} 
                      target="_blank" 
                      rel="noopener noreferrer"
                    >
                      @{caseData.moltbookUsername}
                    </a>
                  </span>
                </div>
              )}
            </div>
          </section>

          {/* Timeline Card */}
          <section className="card timeline-card">
            <h3>Timeline</h3>
            <div className="timeline-list">
              {timeline.map((event) => (
                <div key={event.id} className="timeline-item">
                  <div className="timeline-marker" />
                  <div className="timeline-content">
                    <span className={`badge timeline-type-${event.type}`}>{event.type}</span>
                    <p>{event.description}</p>
                    <span className="timeline-meta">
                      {new Date(event.timestamp).toLocaleString()} • {event.actor}
                    </span>
                  </div>
                </div>
              ))}
              {timeline.length === 0 && (
                <p className="no-timeline">No timeline events</p>
              )}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
};

// Simple markdown-like formatting
function formatMarkdown(text: string): string {
  return text
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\n/g, '<br/>');
}

function getScoreColor(score: number): string {
  if (score >= 0.8) return '#ef4444';
  if (score >= 0.6) return '#f59e0b';
  if (score >= 0.4) return '#eab308';
  return '#22c55e';
}
