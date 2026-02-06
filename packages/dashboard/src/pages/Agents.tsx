import React, { useState, useEffect, useCallback } from 'react';
import { api, ws, type Agent } from '../api/client';
import './Agents.css';

// Mock data fallback when server is unavailable
const mockAgents: Agent[] = [
  {
    id: 'scout-001',
    role: 'scout',
    layer: 'sensing',
    status: 'running',
    tasksProcessed: 1523,
    tasksFailed: 12,
    lastHeartbeat: new Date(Date.now() - 5000).toISOString(),
  },
  {
    id: 'sensor-001',
    role: 'sensor',
    layer: 'sensing',
    status: 'running',
    tasksProcessed: 8942,
    tasksFailed: 45,
    lastHeartbeat: new Date(Date.now() - 3000).toISOString(),
  },
  {
    id: 'learner-001',
    role: 'learner',
    layer: 'sensing',
    status: 'running',
    tasksProcessed: 2156,
    tasksFailed: 8,
    lastHeartbeat: new Date(Date.now() - 2000).toISOString(),
  },
  {
    id: 'analyzer-001',
    role: 'analyzer',
    layer: 'analysis',
    status: 'running',
    tasksProcessed: 4521,
    tasksFailed: 23,
    lastHeartbeat: new Date(Date.now() - 8000).toISOString(),
  },
  {
    id: 'forensic-001',
    role: 'forensic',
    layer: 'analysis',
    status: 'running',
    tasksProcessed: 892,
    tasksFailed: 5,
    lastHeartbeat: new Date(Date.now() - 4000).toISOString(),
  },
  {
    id: 'watchdog-001',
    role: 'watchdog',
    layer: 'decision',
    status: 'running',
    tasksProcessed: 12453,
    tasksFailed: 67,
    lastHeartbeat: new Date(Date.now() - 1000).toISOString(),
  },
  {
    id: 'auditor-001',
    role: 'auditor',
    layer: 'decision',
    status: 'running',
    tasksProcessed: 5621,
    tasksFailed: 28,
    lastHeartbeat: new Date(Date.now() - 6000).toISOString(),
  },
  {
    id: 'enforcer-001',
    role: 'enforcer',
    layer: 'decision',
    status: 'stopped',
    tasksProcessed: 234,
    tasksFailed: 2,
    lastHeartbeat: new Date(Date.now() - 120000).toISOString(),
  },
  {
    id: 'proposer-001',
    role: 'proposer',
    layer: 'governance',
    status: 'running',
    tasksProcessed: 156,
    tasksFailed: 3,
    lastHeartbeat: new Date(Date.now() - 10000).toISOString(),
  },
  {
    id: 'approver-001',
    role: 'approver',
    layer: 'governance',
    status: 'running',
    tasksProcessed: 89,
    tasksFailed: 1,
    lastHeartbeat: new Date(Date.now() - 7000).toISOString(),
  },
];

type LayerFilter = 'all' | 'sensing' | 'analysis' | 'decision' | 'governance';
type StatusFilter = 'all' | 'running' | 'stopped' | 'error';

// Helper functions
function formatTimeAgo(timestamp: string | undefined): string {
  if (!timestamp) return 'never';
  const seconds = Math.floor((Date.now() - new Date(timestamp).getTime()) / 1000);
  if (seconds < 10) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
}

export const Agents: React.FC = () => {
  const [agents, setAgents] = useState<Agent[]>(mockAgents);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
  const [layerFilter, setLayerFilter] = useState<LayerFilter>('all');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');

  // Fetch agents from API
  const fetchAgents = useCallback(async () => {
    try {
      const response = await api.getAgents();
      if (response.agents && response.agents.length > 0) {
        setAgents(response.agents);
        setError(null);
      }
      // If no agents from server, keep mock data
    } catch (err) {
      console.warn('Server unavailable, using mock data:', err);
      // Keep mock data on error
    } finally {
      setLoading(false);
    }
  }, []);

  // Initial fetch and WebSocket connection
  useEffect(() => {
    fetchAgents();

    // Connect WebSocket for real-time updates
    ws.connect();
    
    const unsubscribeConnected = ws.subscribe('connected', () => {
      setConnected(true);
    });

    const unsubscribeDisconnected = ws.subscribe('disconnected', () => {
      setConnected(false);
    });

    const unsubscribeAgentUpdate = ws.subscribe('agent:update', (message) => {
      const agent = message as unknown as Agent;
      setAgents(prev => prev.map(a => a.id === agent.id ? agent : a));
    });

    const unsubscribeAgentStarted = ws.subscribe('agent:started', (message) => {
      const agent = message as unknown as Agent;
      setAgents(prev => {
        const exists = prev.find(a => a.id === agent.id);
        if (exists) {
          return prev.map(a => a.id === agent.id ? agent : a);
        }
        return [...prev, agent];
      });
    });

    const unsubscribeAgentStopped = ws.subscribe('agent:stopped', (message) => {
      const data = message as unknown as { agentId: string };
      setAgents(prev => prev.map(a => 
        a.id === data.agentId ? { ...a, status: 'stopped' as const } : a
      ));
    });

    // Periodic refresh as backup
    const interval = setInterval(fetchAgents, 30000);

    return () => {
      unsubscribeConnected();
      unsubscribeDisconnected();
      unsubscribeAgentUpdate();
      unsubscribeAgentStarted();
      unsubscribeAgentStopped();
      clearInterval(interval);
    };
  }, [fetchAgents]);

  const filteredAgents = agents.filter((agent) => {
    if (layerFilter !== 'all' && agent.layer !== layerFilter) return false;
    if (statusFilter !== 'all' && agent.status !== statusFilter) return false;
    return true;
  });

  const layerCounts = {
    sensing: agents.filter((a) => a.layer === 'sensing').length,
    analysis: agents.filter((a) => a.layer === 'analysis').length,
    decision: agents.filter((a) => a.layer === 'decision').length,
    governance: agents.filter((a) => a.layer === 'governance').length,
  };

  const statusCounts = {
    running: agents.filter((a) => a.status === 'running').length,
    stopped: agents.filter((a) => a.status === 'stopped').length,
    error: agents.filter((a) => a.status === 'error').length,
  };

  return (
    <div className="agents-page">
      <header className="page-header">
        <div className="header-content">
          <h1>Active Agents</h1>
          <p className="page-subtitle">Monitor and manage AI Authority agents across all layers</p>
        </div>
        <div className="connection-status">
          <span className={`status-dot ${connected ? 'connected' : 'disconnected'}`} />
          {connected ? 'Live' : 'Offline'}
        </div>
      </header>

      {error && (
        <div className="error-banner">
          ⚠️ {error}
        </div>
      )}

      <div className="agents-summary">
        <div className="summary-card">
          <div className="summary-value">{agents.length}</div>
          <div className="summary-label">Total Agents</div>
        </div>
        <div className="summary-card status-running">
          <div className="summary-value">{statusCounts.running}</div>
          <div className="summary-label">Running</div>
        </div>
        <div className="summary-card status-paused">
          <div className="summary-value">{statusCounts.stopped}</div>
          <div className="summary-label">Stopped</div>
        </div>
        <div className="summary-card status-error">
          <div className="summary-value">{statusCounts.error}</div>
          <div className="summary-label">Error</div>
        </div>
      </div>

      <div className="layer-breakdown">
        <div className="layer-card sensing">
          <div className="layer-icon">🔍</div>
          <div className="layer-info">
            <div className="layer-name">Sensing Layer</div>
            <div className="layer-count">{layerCounts.sensing} agents</div>
          </div>
          <div className="layer-roles">Scout, Sensor, Learner</div>
        </div>
        <div className="layer-card analysis">
          <div className="layer-icon">🧠</div>
          <div className="layer-info">
            <div className="layer-name">Analysis Layer</div>
            <div className="layer-count">{layerCounts.analysis} agents</div>
          </div>
          <div className="layer-roles">Analyzer, Forensic, Reflector</div>
        </div>
        <div className="layer-card decision">
          <div className="layer-icon">⚖️</div>
          <div className="layer-info">
            <div className="layer-name">Decision Layer</div>
            <div className="layer-count">{layerCounts.decision} agents</div>
          </div>
          <div className="layer-roles">Enforcer, Watchdog, Auditor</div>
        </div>
        <div className="layer-card governance">
          <div className="layer-icon">🏛️</div>
          <div className="layer-info">
            <div className="layer-name">Governance Layer</div>
            <div className="layer-count">{layerCounts.governance} agents</div>
          </div>
          <div className="layer-roles">Proposer, Approver, Curator</div>
        </div>
      </div>

      <div className="agents-filters">
        <div className="filter-group">
          <label>Layer:</label>
          <select
            value={layerFilter}
            onChange={(e) => setLayerFilter(e.target.value as LayerFilter)}
          >
            <option value="all">All Layers</option>
            <option value="sensing">Sensing</option>
            <option value="analysis">Analysis</option>
            <option value="decision">Decision</option>
            <option value="governance">Governance</option>
          </select>
        </div>
        <div className="filter-group">
          <label>Status:</label>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
          >
            <option value="all">All Status</option>
            <option value="running">Running</option>
            <option value="stopped">Stopped</option>
            <option value="error">Error</option>
          </select>
        </div>
      </div>

      <div className="agents-list">
        {loading && agents === mockAgents && (
          <div className="loading-state">Loading agents...</div>
        )}
        {filteredAgents.map((agent) => (
          <div key={agent.id} className={`agent-card card layer-${agent.layer}`}>
            <div className="agent-header">
              <div className="agent-identity">
                <span className="agent-id">{agent.id}</span>
                <span className={`badge role-${agent.role}`}>{agent.role}</span>
              </div>
              <span className={`status-indicator status-${agent.status}`}>
                {agent.status}
              </span>
            </div>

            <div className="agent-metrics">
              <div className="metric">
                <span className="metric-value">{agent.tasksProcessed.toLocaleString()}</span>
                <span className="metric-label">Tasks Processed</span>
              </div>
              <div className="metric">
                <span className="metric-value">{agent.tasksFailed}</span>
                <span className="metric-label">Failed</span>
              </div>
              <div className="metric">
                <span className="metric-value">
                  {agent.tasksProcessed > 0 
                    ? ((1 - agent.tasksFailed / agent.tasksProcessed) * 100).toFixed(1) 
                    : '100.0'}%
                </span>
                <span className="metric-label">Success Rate</span>
              </div>
            </div>

            <div className="agent-footer">
              <span className="heartbeat">
                💓 {formatTimeAgo(agent.lastHeartbeat)}
              </span>
              <div className="agent-actions">
                <button 
                  className="action-btn"
                  onClick={() => handleRestartAgent(agent.id)}
                  disabled={agent.status === 'running'}
                  title="Restart agent"
                >
                  🔄
                </button>
                <button 
                  className="action-btn"
                  onClick={() => handleStopAgent(agent.id)}
                  disabled={agent.status === 'stopped'}
                  title="Stop agent"
                >
                  ⏹️
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

async function handleRestartAgent(agentId: string) {
  try {
    await api.restartAgent(agentId);
  } catch (err) {
    console.error('Failed to restart agent:', err);
  }
}

async function handleStopAgent(agentId: string) {
  try {
    await api.stopAgent(agentId);
  } catch (err) {
    console.error('Failed to stop agent:', err);
  }
}
