/**
 * AI Authority Backend Server
 *
 * Main entry point for the API server that orchestrates agents
 * and serves real-time data to the dashboard.
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { WebSocketServer } from 'ws';
import http from 'http';

import { AgentOrchestrator, type OrchestratorConfig } from './orchestrator.js';
import { createApiRouter } from './api/index.js';
import { WebSocketManager } from './websocket.js';
import { ScanScheduler, getScheduler, type SchedulerConfig, DEFAULT_SCHEDULER_CONFIG } from './scheduler.js';

// ============================================================================
// Configuration
// ============================================================================

export interface ServerConfig {
  /** HTTP port */
  port: number;

  /** WebSocket port (same as HTTP if not specified) */
  wsPort?: number;

  /** CORS origins */
  corsOrigins: string[];

  /** Enable development mode */
  isDevelopment: boolean;

  /** Orchestrator configuration */
  orchestrator: OrchestratorConfig;

  /** Scheduler configuration */
  scheduler: SchedulerConfig;
}

export const DEFAULT_SERVER_CONFIG: ServerConfig = {
  port: 3001,
  corsOrigins: ['http://localhost:5173', 'http://localhost:3000'],
  isDevelopment: process.env.NODE_ENV !== 'production',
  orchestrator: {
    nodeId: 'node-local-001',
    region: 'local',
    autoStartAgents: true,
    enableFederation: false,
  },
  scheduler: DEFAULT_SCHEDULER_CONFIG,
};

// ============================================================================
// Server Class
// ============================================================================

export class AIAuthorityServer {
  private readonly config: ServerConfig;
  private readonly app: express.Application;
  private readonly server: http.Server;
  private readonly wss: WebSocketServer;
  private readonly orchestrator: AgentOrchestrator;
  private readonly wsManager: WebSocketManager;
  private readonly scheduler: ScanScheduler;
  private isRunning = false;

  constructor(config: Partial<ServerConfig> = {}) {
    this.config = { ...DEFAULT_SERVER_CONFIG, ...config };

    // Create Express app
    this.app = express();
    this.setupMiddleware();

    // Create HTTP server
    this.server = http.createServer(this.app);

    // Create WebSocket server
    this.wss = new WebSocketServer({ server: this.server });

    // Create orchestrator
    this.orchestrator = new AgentOrchestrator(this.config.orchestrator);

    // Create WebSocket manager
    this.wsManager = new WebSocketManager(this.wss, this.orchestrator);

    // Create scheduler and connect to WebSocket manager and orchestrator
    this.scheduler = getScheduler(this.config.scheduler);
    this.scheduler.setWebSocketManager(this.wsManager);
    this.scheduler.setOrchestrator(this.orchestrator);

    // Setup routes
    this.setupRoutes();
  }

  // ==========================================================================
  // Setup
  // ==========================================================================

  private setupMiddleware(): void {
    // Security
    if (this.config.isDevelopment) {
      this.app.use(helmet({ contentSecurityPolicy: false }));
    } else {
      this.app.use(helmet());
    }

    // CORS
    this.app.use(cors({
      origin: this.config.corsOrigins,
      credentials: true,
    }));

    // Compression
    this.app.use(compression());

    // JSON parsing
    this.app.use(express.json({ limit: '10mb' }));

    // Request logging in development
    if (this.config.isDevelopment) {
      this.app.use((req, _res, next) => {
        console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
        next();
      });
    }
  }

  private setupRoutes(): void {
    // Health check
    this.app.get('/health', (_req, res) => {
      res.json({
        status: 'healthy',
        timestamp: Date.now(),
        uptime: process.uptime(),
        nodeId: this.config.orchestrator.nodeId,
      });
    });

    // API routes
    this.app.use('/api', createApiRouter(this.orchestrator));

    // Error handler
    this.app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      console.error('Server error:', err);
      res.status(500).json({
        error: 'Internal server error',
        message: this.config.isDevelopment ? err.message : undefined,
      });
    });
  }

  // ==========================================================================
  // Lifecycle
  // ==========================================================================

  async start(): Promise<void> {
    if (this.isRunning) {
      throw new Error('Server is already running');
    }

    // Start orchestrator
    await this.orchestrator.start();

    // Start WebSocket manager
    this.wsManager.start();

    // Start scheduler for automated scanning
    this.scheduler.start();

    // Start HTTP server
    await new Promise<void>((resolve) => {
      this.server.listen(this.config.port, () => {
        console.log(`🚀 AI Authority Server running on port ${this.config.port}`);
        console.log(`   Node ID: ${this.config.orchestrator.nodeId}`);
        console.log(`   WebSocket: ws://localhost:${this.config.port}`);
        console.log(`   API: http://localhost:${this.config.port}/api`);
        console.log(`   Scheduler: ${this.config.scheduler.enabled ? 'enabled' : 'disabled'} (${this.config.scheduler.cronExpression})`);
        resolve();
      });
    });

    this.isRunning = true;
  }

  async stop(): Promise<void> {
    if (!this.isRunning) return;

    console.log('Shutting down server...');

    // Stop scheduler
    this.scheduler.stop();

    // Stop WebSocket manager
    this.wsManager.stop();

    // Stop orchestrator
    await this.orchestrator.stop();

    // Close HTTP server
    await new Promise<void>((resolve, reject) => {
      this.server.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    this.isRunning = false;
    console.log('Server stopped');
  }

  // ==========================================================================
  // Accessors
  // ==========================================================================

  getOrchestrator(): AgentOrchestrator {
    return this.orchestrator;
  }

  getWebSocketManager(): WebSocketManager {
    return this.wsManager;
  }

  getScheduler(): ScanScheduler {
    return this.scheduler;
  }

  isActive(): boolean {
    return this.isRunning;
  }
}

// ============================================================================
// Main Entry Point
// ============================================================================

async function main(): Promise<void> {
  const server = new AIAuthorityServer();

  // Graceful shutdown
  const shutdown = async (signal: string) => {
    console.log(`\nReceived ${signal}, shutting down gracefully...`);
    await server.stop();
    process.exit(0);
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  await server.start();
}

// Run if this is the main module
main().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});

export { AgentOrchestrator } from './orchestrator.js';
export { WebSocketManager } from './websocket.js';
export * from './database.js';
export * from './workflows.js';
export * from './scheduler.js';
