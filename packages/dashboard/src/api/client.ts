/**
 * API Client
 *
 * HTTP and WebSocket client for communicating with the AI Authority backend.
 */

// ============================================================================
// Configuration
// ============================================================================

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001';
const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:3001';

// ============================================================================
// Types
// ============================================================================

export interface Agent {
  id: string;
  role: string;
  layer: 'sensing' | 'analysis' | 'decision' | 'governance';
  status: 'initializing' | 'running' | 'stopped' | 'error';
  startedAt?: string;
  stoppedAt?: string;
  tasksProcessed: number;
  tasksFailed: number;
  lastHeartbeat?: string;
  errorMessage?: string;
}

export interface DetectionCase {
  id: string;
  title: string;
  description?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'investigating' | 'resolved' | 'dismissed';
  category: 'malicious' | 'negligent' | 'suspicious' | 'unknown';
  targetId: string;
  targetType: string;
  detectedAt: string;
  riskScore: number;
}

export interface Metrics {
  nodeId: string;
  region: string;
  uptime: number;
  totalAgents: number;
  runningAgents: number;
  totalTasksProcessed: number;
  totalTasksFailed: number;
  memoryMB?: {
    heapUsed: number;
    heapTotal: number;
    rss: number;
  };
}

export interface WSMessage {
  type: string;
  payload: unknown;
  timestamp: number;
}

// ============================================================================
// Federation Types (Data Fetching & Distribution Plan)
// ============================================================================

export type AccessTier = 'public' | 'restricted' | 'confidential' | 'classified';
export type DataCategory =
  | 'threat_signals'
  | 'incident_reports'
  | 'compliance_audits'
  | 'model_performance_metrics'
  | 'bias_assessments'
  | 'risk_scores'
  | 'behavioral_patterns'
  | 'anonymized_indicators'
  | 'aggregated_statistics';

export interface RegulatoryAuthority {
  id: string;
  name: string;
  type: 'government_agency' | 'international_body' | 'national_entity' | 'regional_authority' | 'industry_consortium' | 'research_institution';
  jurisdiction: 'global' | 'continental' | 'national' | 'regional' | 'sector_specific';
  regions: string[];
  domains: string[];
  accessTier: AccessTier;
  trustScore: number;
  status: 'active' | 'suspended' | 'pending_verification' | 'inactive';
  joinedAt: string;
  lastActiveAt: string;
}

export interface DataSource {
  id: string;
  name: string;
  type: 'internal_audit' | 'industry_submission' | 'public_dataset' | 'private_partnership' | 'peer_authority' | 'api_feed' | 'manual_upload';
  dataCategories: DataCategory[];
  requiredTier: AccessTier;
  trustLevel: number;
  status: 'active' | 'inactive' | 'error' | 'rate_limited';
  lastFetchAt?: string;
}

export interface FetchRequest {
  id: string;
  requesterId: string;
  method: 'active' | 'passive' | 'collaborative';
  categories: DataCategory[];
  status: 'pending' | 'processing' | 'completed' | 'failed' | 'expired';
  priority: 'low' | 'normal' | 'high' | 'critical';
  requestedAt: string;
}

export interface DistributionChannel {
  id: string;
  name: string;
  model: 'push' | 'pull' | 'hybrid';
  supportedCategories: DataCategory[];
  requiredTier: AccessTier;
  subscriptionCount: number;
  status: 'active' | 'inactive' | 'maintenance';
}

export interface DistributionSubscription {
  id: string;
  subscriberId: string;
  channelId: string;
  categories: DataCategory[];
  status: 'active' | 'paused' | 'cancelled';
  itemsDelivered: number;
  lastDeliveryAt?: string;
}

export interface MonitoringAlert {
  id: string;
  type: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  message: string;
  triggeredBy: string;
  timestamp: string;
  status: 'active' | 'acknowledged' | 'resolved';
}

export interface Incident {
  id: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  affectedAuthorities: string[];
  timestamp: string;
  status: 'open' | 'investigating' | 'contained' | 'resolved' | 'closed';
}

export interface FederationStats {
  authorities: {
    total: number;
    active: number;
    byType: Record<string, number>;
    byTier: Record<AccessTier, number>;
  };
  fetching: {
    totalSources: number;
    activeSources: number;
    totalRequests: number;
    pendingRequests: number;
    completedRequests: number;
  };
  distribution: {
    totalChannels: number;
    activeChannels: number;
    totalSubscriptions: number;
    totalPackages: number;
  };
  monitoring: {
    activeAlerts: number;
    activeIncidents: number;
    healthStatus: 'healthy' | 'degraded' | 'unhealthy';
  };
}

// ============================================================================
// HTTP Client
// ============================================================================

class ApiClient {
  private baseUrl: string;

  constructor(baseUrl: string = API_BASE_URL) {
    this.baseUrl = baseUrl;
  }

  private async request<T>(
    path: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;

    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Unknown error' }));
      throw new Error(error.error || `HTTP ${response.status}`);
    }

    return response.json();
  }

  // Health check
  async getHealth(): Promise<{ status: string; nodeId: string; uptime: number }> {
    return this.request('/health');
  }

  // =========================================================================
  // Agents
  // =========================================================================

  async getAgents(): Promise<{ count: number; agents: Agent[] }> {
    return this.request('/api/agents');
  }

  async getAgent(id: string): Promise<Agent> {
    return this.request(`/api/agents/${id}`);
  }

  async getAgentsByLayer(layer: string): Promise<{ layer: string; count: number; agents: Agent[] }> {
    return this.request(`/api/agents/layer/${layer}`);
  }

  async submitTask(agentId: string, task: { type: string; payload?: unknown }): Promise<{ success: boolean; result: unknown }> {
    return this.request(`/api/agents/${agentId}/task`, {
      method: 'POST',
      body: JSON.stringify(task),
    });
  }

  async restartAgent(agentId: string): Promise<{ success: boolean }> {
    return this.request(`/api/agents/${agentId}/restart`, { method: 'POST' });
  }

  async stopAgent(agentId: string): Promise<{ success: boolean }> {
    return this.request(`/api/agents/${agentId}/stop`, { method: 'POST' });
  }

  async createAgent(role: string, layer: string): Promise<{ success: boolean; agent: Agent }> {
    return this.request('/api/agents', {
      method: 'POST',
      body: JSON.stringify({ role, layer }),
    });
  }

  // =========================================================================
  // Metrics
  // =========================================================================

  async getMetrics(): Promise<Metrics> {
    return this.request('/api/metrics');
  }

  async getMetricsHistory(limit?: number): Promise<{ count: number; history: unknown[] }> {
    const query = limit ? `?limit=${limit}` : '';
    return this.request(`/api/metrics/history${query}`);
  }

  async getAgentMetrics(): Promise<{ totalAgents: number; runningAgents: number; byLayer: Record<string, unknown>; byRole: Record<string, unknown> }> {
    return this.request('/api/metrics/agents');
  }

  async getHealthStatus(): Promise<{ status: string; checks: Record<string, unknown> }> {
    return this.request('/api/metrics/health');
  }

  // =========================================================================
  // Cases
  // =========================================================================

  async getCases(params?: {
    status?: string;
    severity?: string;
    category?: string;
    page?: number;
    limit?: number;
  }): Promise<{ total: number; page: number; limit: number; cases: DetectionCase[] }> {
    const searchParams = new URLSearchParams();
    if (params?.status) searchParams.set('status', params.status);
    if (params?.severity) searchParams.set('severity', params.severity);
    if (params?.category) searchParams.set('category', params.category);
    if (params?.page) searchParams.set('page', String(params.page));
    if (params?.limit) searchParams.set('limit', String(params.limit));

    const query = searchParams.toString();
    return this.request(`/api/cases${query ? `?${query}` : ''}`);
  }

  async getCase(id: string): Promise<DetectionCase & { evidence: unknown[]; timeline: unknown[] }> {
    return this.request(`/api/cases/${id}`);
  }

  async getCaseStats(): Promise<{
    total: number;
    bySeverity: Record<string, number>;
    byStatus: Record<string, number>;
    byCategory: Record<string, number>;
    avgRiskScore: number;
  }> {
    return this.request('/api/cases/stats/summary');
  }

  async updateCaseStatus(
    id: string,
    status: string,
    resolution?: string
  ): Promise<{ success: boolean }> {
    return this.request(`/api/cases/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, resolution }),
    });
  }

  async addCaseEvidence(
    id: string,
    evidence: { type: string; description: string; data?: unknown }
  ): Promise<{ success: boolean; evidence: unknown }> {
    return this.request(`/api/cases/${id}/evidence`, {
      method: 'POST',
      body: JSON.stringify(evidence),
    });
  }

  // =========================================================================
  // Federation - Authorities
  // =========================================================================

  async getAuthorities(): Promise<{ count: number; authorities: RegulatoryAuthority[] }> {
    return this.request('/api/federation/authorities');
  }

  async getAuthority(id: string): Promise<RegulatoryAuthority> {
    return this.request(`/api/federation/authorities/${id}`);
  }

  async getAuthoritiesByType(type: string): Promise<{ type: string; count: number; authorities: RegulatoryAuthority[] }> {
    return this.request(`/api/federation/authorities/type/${type}`);
  }

  async getAuthoritiesByTier(tier: AccessTier): Promise<{ tier: AccessTier; count: number; authorities: RegulatoryAuthority[] }> {
    return this.request(`/api/federation/authorities/tier/${tier}`);
  }

  async registerAuthority(authority: Omit<RegulatoryAuthority, 'id' | 'trustScore' | 'joinedAt' | 'lastActiveAt' | 'status'>): Promise<{ success: boolean; authority: RegulatoryAuthority }> {
    return this.request('/api/federation/authorities', {
      method: 'POST',
      body: JSON.stringify(authority),
    });
  }

  async updateAuthorityStatus(id: string, status: RegulatoryAuthority['status']): Promise<{ success: boolean }> {
    return this.request(`/api/federation/authorities/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    });
  }

  // =========================================================================
  // Federation - Data Sources
  // =========================================================================

  async getDataSources(): Promise<{ count: number; sources: DataSource[] }> {
    return this.request('/api/federation/sources');
  }

  async getDataSource(id: string): Promise<DataSource> {
    return this.request(`/api/federation/sources/${id}`);
  }

  async getSourcesByCategory(category: DataCategory): Promise<{ category: DataCategory; count: number; sources: DataSource[] }> {
    return this.request(`/api/federation/sources/category/${category}`);
  }

  async registerDataSource(source: Omit<DataSource, 'id' | 'status'>): Promise<{ success: boolean; source: DataSource }> {
    return this.request('/api/federation/sources', {
      method: 'POST',
      body: JSON.stringify(source),
    });
  }

  // =========================================================================
  // Federation - Fetching
  // =========================================================================

  async createFetchRequest(request: {
    sourceIds: string[];
    categories: DataCategory[];
    criteria: Record<string, unknown>;
    priority?: 'low' | 'normal' | 'high' | 'critical';
  }): Promise<{ success: boolean; request: FetchRequest }> {
    return this.request('/api/federation/fetch/requests', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async getFetchRequests(params?: {
    status?: string;
    page?: number;
    limit?: number;
  }): Promise<{ total: number; page: number; limit: number; requests: FetchRequest[] }> {
    const searchParams = new URLSearchParams();
    if (params?.status) searchParams.set('status', params.status);
    if (params?.page) searchParams.set('page', String(params.page));
    if (params?.limit) searchParams.set('limit', String(params.limit));

    const query = searchParams.toString();
    return this.request(`/api/federation/fetch/requests${query ? `?${query}` : ''}`);
  }

  async executeFetchRequest(requestId: string): Promise<{ success: boolean; results: unknown[] }> {
    return this.request(`/api/federation/fetch/requests/${requestId}/execute`, {
      method: 'POST',
    });
  }

  // =========================================================================
  // Federation - Distribution
  // =========================================================================

  async getDistributionChannels(): Promise<{ count: number; channels: DistributionChannel[] }> {
    return this.request('/api/federation/distribution/channels');
  }

  async createDistributionChannel(channel: Omit<DistributionChannel, 'id' | 'subscriptionCount' | 'status'>): Promise<{ success: boolean; channel: DistributionChannel }> {
    return this.request('/api/federation/distribution/channels', {
      method: 'POST',
      body: JSON.stringify(channel),
    });
  }

  async subscribe(channelId: string, subscription: {
    categories: DataCategory[];
    filters?: Record<string, unknown>;
    preferences?: Record<string, unknown>;
  }): Promise<{ success: boolean; subscription: DistributionSubscription }> {
    return this.request(`/api/federation/distribution/channels/${channelId}/subscribe`, {
      method: 'POST',
      body: JSON.stringify(subscription),
    });
  }

  async unsubscribe(subscriptionId: string): Promise<{ success: boolean }> {
    return this.request(`/api/federation/distribution/subscriptions/${subscriptionId}`, {
      method: 'DELETE',
    });
  }

  async getSubscriptions(): Promise<{ count: number; subscriptions: DistributionSubscription[] }> {
    return this.request('/api/federation/distribution/subscriptions');
  }

  async createPullRequest(request: {
    categories: DataCategory[];
    criteria: Record<string, unknown>;
    pagination?: { page: number; limit: number };
  }): Promise<{ success: boolean; requestId: string }> {
    return this.request('/api/federation/distribution/pull', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // =========================================================================
  // Federation - Monitoring
  // =========================================================================

  async getFederationStats(): Promise<FederationStats> {
    return this.request('/api/federation/stats');
  }

  async getMonitoringAlerts(params?: {
    status?: string;
    severity?: string;
    page?: number;
    limit?: number;
  }): Promise<{ total: number; alerts: MonitoringAlert[] }> {
    const searchParams = new URLSearchParams();
    if (params?.status) searchParams.set('status', params.status);
    if (params?.severity) searchParams.set('severity', params.severity);
    if (params?.page) searchParams.set('page', String(params.page));
    if (params?.limit) searchParams.set('limit', String(params.limit));

    const query = searchParams.toString();
    return this.request(`/api/federation/monitoring/alerts${query ? `?${query}` : ''}`);
  }

  async acknowledgeAlert(alertId: string): Promise<{ success: boolean }> {
    return this.request(`/api/federation/monitoring/alerts/${alertId}/acknowledge`, {
      method: 'POST',
    });
  }

  async resolveAlert(alertId: string): Promise<{ success: boolean }> {
    return this.request(`/api/federation/monitoring/alerts/${alertId}/resolve`, {
      method: 'POST',
    });
  }

  async getIncidents(params?: {
    status?: string;
    severity?: string;
    page?: number;
    limit?: number;
  }): Promise<{ total: number; incidents: Incident[] }> {
    const searchParams = new URLSearchParams();
    if (params?.status) searchParams.set('status', params.status);
    if (params?.severity) searchParams.set('severity', params.severity);
    if (params?.page) searchParams.set('page', String(params.page));
    if (params?.limit) searchParams.set('limit', String(params.limit));

    const query = searchParams.toString();
    return this.request(`/api/federation/monitoring/incidents${query ? `?${query}` : ''}`);
  }

  async createIncident(incident: {
    type: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    affectedAuthorities?: string[];
  }): Promise<{ success: boolean; incident: Incident }> {
    return this.request('/api/federation/monitoring/incidents', {
      method: 'POST',
      body: JSON.stringify(incident),
    });
  }

  async updateIncidentStatus(incidentId: string, status: Incident['status'], notes?: string): Promise<{ success: boolean }> {
    return this.request(`/api/federation/monitoring/incidents/${incidentId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, notes }),
    });
  }

  async getMonitoringDashboard(): Promise<{
    currentMetrics: Record<string, number>;
    alerts: MonitoringAlert[];
    incidents: Incident[];
    healthStatus: { status: string; components: unknown[] };
  }> {
    return this.request('/api/federation/monitoring/dashboard');
  }

  async submitFeedback(feedback: {
    type: string;
    subject: string;
    details: string;
    importance?: 'low' | 'medium' | 'high';
  }): Promise<{ success: boolean; feedbackId: string }> {
    return this.request('/api/federation/monitoring/feedback', {
      method: 'POST',
      body: JSON.stringify(feedback),
    });
  }
}

// ============================================================================
// WebSocket Client
// ============================================================================

type MessageHandler = (message: WSMessage) => void;

class WebSocketClient {
  private ws: WebSocket | null = null;
  private url: string;
  private handlers: Map<string, Set<MessageHandler>> = new Map();
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private isConnecting = false;

  constructor(url: string = WS_URL) {
    this.url = url;
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        resolve();
        return;
      }

      if (this.isConnecting) {
        // Wait for existing connection attempt
        const checkInterval = setInterval(() => {
          if (this.ws?.readyState === WebSocket.OPEN) {
            clearInterval(checkInterval);
            resolve();
          }
        }, 100);
        return;
      }

      this.isConnecting = true;

      try {
        this.ws = new WebSocket(this.url);

        this.ws.onopen = () => {
          console.log('WebSocket connected');
          this.reconnectAttempts = 0;
          this.isConnecting = false;
          resolve();
        };

        this.ws.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data) as WSMessage;
            this.dispatchMessage(message);
          } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
          }
        };

        this.ws.onclose = () => {
          console.log('WebSocket disconnected');
          this.isConnecting = false;
          this.attemptReconnect();
        };

        this.ws.onerror = (error) => {
          console.error('WebSocket error:', error);
          this.isConnecting = false;
          reject(error);
        };
      } catch (error) {
        this.isConnecting = false;
        reject(error);
      }
    });
  }

  private attemptReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.log('Max reconnection attempts reached');
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

    console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
    setTimeout(() => {
      this.connect().catch(console.error);
    }, delay);
  }

  disconnect(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  send(message: { type: string; payload?: unknown }): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ ...message, timestamp: Date.now() }));
    }
  }

  subscribe(topic: string, handler: MessageHandler): () => void {
    if (!this.handlers.has(topic)) {
      this.handlers.set(topic, new Set());
    }
    this.handlers.get(topic)!.add(handler);

    // Return unsubscribe function
    return () => {
      this.handlers.get(topic)?.delete(handler);
    };
  }

  on(messageType: string, handler: MessageHandler): () => void {
    return this.subscribe(messageType, handler);
  }

  private dispatchMessage(message: WSMessage): void {
    // Dispatch to specific type handlers
    const typeHandlers = this.handlers.get(message.type);
    if (typeHandlers) {
      typeHandlers.forEach((handler) => handler(message));
    }

    // Dispatch to wildcard handlers
    const wildcardHandlers = this.handlers.get('*');
    if (wildcardHandlers) {
      wildcardHandlers.forEach((handler) => handler(message));
    }
  }

  isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }
}

// ============================================================================
// Singleton Instances
// ============================================================================

export const api = new ApiClient();
export const ws = new WebSocketClient();

// ============================================================================
// React Hooks
// ============================================================================

import { useState, useEffect, useCallback } from 'react';

export function useAgents() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAgents = useCallback(async () => {
    try {
      const data = await api.getAgents();
      setAgents(data.agents);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch agents');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAgents();

    // Subscribe to WebSocket updates
    ws.connect().then(() => {
      const unsubscribe = ws.on('agents', (message) => {
        setAgents(message.payload as Agent[]);
      });

      return () => {
        unsubscribe();
      };
    }).catch(console.error);
  }, [fetchAgents]);

  return { agents, loading, error, refetch: fetchAgents };
}

export function useMetrics() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        const data = await api.getMetrics();
        setMetrics(data);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch metrics');
      } finally {
        setLoading(false);
      }
    };

    fetchMetrics();

    // Subscribe to WebSocket updates
    ws.connect().then(() => {
      const unsubscribe = ws.on('metrics', (message) => {
        setMetrics(message.payload as Metrics);
      });

      return () => {
        unsubscribe();
      };
    }).catch(console.error);
  }, []);

  return { metrics, loading, error };
}

export function useCases(params?: {
  status?: string;
  severity?: string;
  category?: string;
}) {
  const [cases, setCases] = useState<DetectionCase[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchCases = useCallback(async () => {
    try {
      const data = await api.getCases(params);
      setCases(data.cases);
      setTotal(data.total);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch cases');
    } finally {
      setLoading(false);
    }
  }, [params?.status, params?.severity, params?.category]);

  useEffect(() => {
    fetchCases();
  }, [fetchCases]);

  return { cases, total, loading, error, refetch: fetchCases };
}

// ============================================================================
// Federation Hooks
// ============================================================================

export function useAuthorities() {
  const [authorities, setAuthorities] = useState<RegulatoryAuthority[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAuthorities = useCallback(async () => {
    try {
      const data = await api.getAuthorities();
      setAuthorities(data.authorities);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch authorities');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAuthorities();

    // Subscribe to WebSocket updates
    ws.connect().then(() => {
      const unsubscribe = ws.on('authorities', (message) => {
        setAuthorities(message.payload as RegulatoryAuthority[]);
      });

      return () => {
        unsubscribe();
      };
    }).catch(console.error);
  }, [fetchAuthorities]);

  return { authorities, loading, error, refetch: fetchAuthorities };
}

export function useDataSources() {
  const [sources, setSources] = useState<DataSource[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchSources = useCallback(async () => {
    try {
      const data = await api.getDataSources();
      setSources(data.sources);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch data sources');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSources();
  }, [fetchSources]);

  return { sources, loading, error, refetch: fetchSources };
}

export function useDistributionChannels() {
  const [channels, setChannels] = useState<DistributionChannel[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchChannels = useCallback(async () => {
    try {
      const data = await api.getDistributionChannels();
      setChannels(data.channels);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch channels');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchChannels();

    ws.connect().then(() => {
      const unsubscribe = ws.on('distribution_channels', (message) => {
        setChannels(message.payload as DistributionChannel[]);
      });

      return () => {
        unsubscribe();
      };
    }).catch(console.error);
  }, [fetchChannels]);

  return { channels, loading, error, refetch: fetchChannels };
}

export function useFederationStats() {
  const [stats, setStats] = useState<FederationStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const data = await api.getFederationStats();
        setStats(data);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch federation stats');
      } finally {
        setLoading(false);
      }
    };

    fetchStats();

    // Subscribe to WebSocket updates
    ws.connect().then(() => {
      const unsubscribe = ws.on('federation_stats', (message) => {
        setStats(message.payload as FederationStats);
      });

      return () => {
        unsubscribe();
      };
    }).catch(console.error);
  }, []);

  return { stats, loading, error };
}

export function useMonitoringAlerts(params?: { status?: string; severity?: string }) {
  const [alerts, setAlerts] = useState<MonitoringAlert[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAlerts = useCallback(async () => {
    try {
      const data = await api.getMonitoringAlerts(params);
      setAlerts(data.alerts);
      setTotal(data.total);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch alerts');
    } finally {
      setLoading(false);
    }
  }, [params?.status, params?.severity]);

  useEffect(() => {
    fetchAlerts();

    ws.connect().then(() => {
      const unsubscribe = ws.on('monitoring_alerts', (message) => {
        setAlerts(message.payload as MonitoringAlert[]);
      });

      return () => {
        unsubscribe();
      };
    }).catch(console.error);
  }, [fetchAlerts]);

  return { alerts, total, loading, error, refetch: fetchAlerts };
}

export function useIncidents(params?: { status?: string; severity?: string }) {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchIncidents = useCallback(async () => {
    try {
      const data = await api.getIncidents(params);
      setIncidents(data.incidents);
      setTotal(data.total);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch incidents');
    } finally {
      setLoading(false);
    }
  }, [params?.status, params?.severity]);

  useEffect(() => {
    fetchIncidents();

    ws.connect().then(() => {
      const unsubscribe = ws.on('incidents', (message) => {
        setIncidents(message.payload as Incident[]);
      });

      return () => {
        unsubscribe();
      };
    }).catch(console.error);
  }, [fetchIncidents]);

  return { incidents, total, loading, error, refetch: fetchIncidents };
}

export function useMonitoringDashboard() {
  const [dashboard, setDashboard] = useState<{
    currentMetrics: Record<string, number>;
    alerts: MonitoringAlert[];
    incidents: Incident[];
    healthStatus: { status: string; components: unknown[] };
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchDashboard = async () => {
      try {
        const data = await api.getMonitoringDashboard();
        setDashboard(data);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch dashboard');
      } finally {
        setLoading(false);
      }
    };

    fetchDashboard();

    // Subscribe to WebSocket updates for real-time dashboard
    ws.connect().then(() => {
      const unsubscribe = ws.on('monitoring_dashboard', (message) => {
        setDashboard(message.payload as typeof dashboard);
      });

      return () => {
        unsubscribe();
      };
    }).catch(console.error);

    // Refresh periodically
    const interval = setInterval(fetchDashboard, 30000);
    return () => clearInterval(interval);
  }, []);

  return { dashboard, loading, error };
}
