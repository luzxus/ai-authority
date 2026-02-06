/**
 * WebSocket Manager
 *
 * Handles real-time communication with dashboard clients.
 * Broadcasts agent status, metrics, and events.
 */

import { WebSocketServer, WebSocket } from 'ws';
import type { AgentOrchestrator, OrchestratorEvent } from './orchestrator.js';

// ============================================================================
// Types
// ============================================================================

export interface WSMessage {
  type: string;
  payload: unknown;
  timestamp: number;
}

export interface WSClient {
  id: string;
  ws: WebSocket;
  subscriptions: Set<string>;
  connectedAt: Date;
}

// ============================================================================
// WebSocket Manager
// ============================================================================

export class WebSocketManager {
  private readonly wss: WebSocketServer;
  private readonly orchestrator: AgentOrchestrator;
  private readonly clients: Map<string, WSClient> = new Map();
  private broadcastInterval?: ReturnType<typeof setInterval>;
  private clientIdCounter = 0;

  constructor(wss: WebSocketServer, orchestrator: AgentOrchestrator) {
    this.wss = wss;
    this.orchestrator = orchestrator;
  }

  // ==========================================================================
  // Lifecycle
  // ==========================================================================

  start(): void {
    // Handle new connections
    this.wss.on('connection', (ws) => {
      this.handleConnection(ws);
    });

    // Subscribe to orchestrator events
    this.orchestrator.onEvent((event) => {
      this.handleOrchestratorEvent(event);
    });

    // Periodic broadcast of agent status
    this.broadcastInterval = setInterval(() => {
      this.broadcastAgentStatus();
    }, 1000);

    console.log('WebSocket manager started');
  }

  stop(): void {
    if (this.broadcastInterval) {
      clearInterval(this.broadcastInterval);
    }

    // Close all client connections
    for (const client of this.clients.values()) {
      client.ws.close();
    }
    this.clients.clear();

    console.log('WebSocket manager stopped');
  }

  // ==========================================================================
  // Connection Handling
  // ==========================================================================

  private handleConnection(ws: WebSocket): void {
    const clientId = `client-${++this.clientIdCounter}`;

    const client: WSClient = {
      id: clientId,
      ws,
      subscriptions: new Set(['agents', 'metrics']), // Default subscriptions
      connectedAt: new Date(),
    };

    this.clients.set(clientId, client);
    console.log(`WebSocket client connected: ${clientId}`);

    // Send initial state
    this.sendToClient(client, {
      type: 'connected',
      payload: {
        clientId,
        nodeId: this.orchestrator.getMetrics().nodeId,
      },
      timestamp: Date.now(),
    });

    // Send current agent list
    this.sendToClient(client, {
      type: 'agents',
      payload: this.getAgentSummaries(),
      timestamp: Date.now(),
    });

    // Send current metrics
    this.sendToClient(client, {
      type: 'metrics',
      payload: this.orchestrator.getMetrics(),
      timestamp: Date.now(),
    });

    // Handle messages from client
    ws.on('message', (data) => {
      this.handleClientMessage(client, data.toString());
    });

    // Handle disconnection
    ws.on('close', () => {
      this.clients.delete(clientId);
      console.log(`WebSocket client disconnected: ${clientId}`);
    });

    // Handle errors
    ws.on('error', (error) => {
      console.error(`WebSocket error for ${clientId}:`, error);
      this.clients.delete(clientId);
    });
  }

  private handleClientMessage(client: WSClient, data: string): void {
    try {
      const message = JSON.parse(data) as WSMessage;

      switch (message.type) {
        case 'subscribe':
          this.handleSubscribe(client, message.payload as string[]);
          break;

        case 'unsubscribe':
          this.handleUnsubscribe(client, message.payload as string[]);
          break;

        case 'ping':
          this.sendToClient(client, {
            type: 'pong',
            payload: null,
            timestamp: Date.now(),
          });
          break;

        case 'get_agents':
          this.sendToClient(client, {
            type: 'agents',
            payload: this.getAgentSummaries(),
            timestamp: Date.now(),
          });
          break;

        case 'get_metrics':
          this.sendToClient(client, {
            type: 'metrics',
            payload: this.orchestrator.getMetrics(),
            timestamp: Date.now(),
          });
          break;

        default:
          console.warn(`Unknown WebSocket message type: ${message.type}`);
      }
    } catch (error) {
      console.error('Failed to parse WebSocket message:', error);
    }
  }

  private handleSubscribe(client: WSClient, topics: string[]): void {
    for (const topic of topics) {
      client.subscriptions.add(topic);
    }
  }

  private handleUnsubscribe(client: WSClient, topics: string[]): void {
    for (const topic of topics) {
      client.subscriptions.delete(topic);
    }
  }

  // ==========================================================================
  // Broadcasting
  // ==========================================================================

  private handleOrchestratorEvent(event: OrchestratorEvent): void {
    const message: WSMessage = {
      type: `event:${event.type}`,
      payload: {
        agentId: event.agentId,
        data: event.data,
      },
      timestamp: event.timestamp.getTime(),
    };

    this.broadcastToTopic(message, 'events');
  }

  private broadcastAgentStatus(): void {
    const message: WSMessage = {
      type: 'agents',
      payload: this.getAgentSummaries(),
      timestamp: Date.now(),
    };

    this.broadcastToTopic(message, 'agents');
  }

  private broadcastToTopic(message: WSMessage, topic: string): void {
    const data = JSON.stringify(message);

    for (const client of this.clients.values()) {
      if (client.subscriptions.has(topic) && client.ws.readyState === WebSocket.OPEN) {
        client.ws.send(data);
      }
    }
  }

  /**
   * Broadcast a message to all connected clients (public API for external callers).
   */
  broadcastEvent(event: { type: string; data: unknown; timestamp: string }): void {
    const message: WSMessage = {
      type: event.type,
      payload: event.data,
      timestamp: new Date(event.timestamp).getTime(),
    };
    // Broadcast to all topics (events subscription)
    const data = JSON.stringify(message);
    for (const client of this.clients.values()) {
      if (client.ws.readyState === WebSocket.OPEN) {
        client.ws.send(data);
      }
    }
  }

  private sendToClient(client: WSClient, message: WSMessage): void {
    if (client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(JSON.stringify(message));
    }
  }

  // ==========================================================================
  // Helpers
  // ==========================================================================

  private getAgentSummaries(): object[] {
    return this.orchestrator.getAllAgents().map((agent) => ({
      id: agent.id,
      role: agent.role,
      layer: agent.layer,
      status: agent.status,
      startedAt: agent.startedAt?.toISOString(),
      tasksProcessed: agent.tasksProcessed,
      tasksFailed: agent.tasksFailed,
      lastHeartbeat: agent.lastHeartbeat?.toISOString(),
      errorMessage: agent.errorMessage,
    }));
  }

  getClientCount(): number {
    return this.clients.size;
  }
}
