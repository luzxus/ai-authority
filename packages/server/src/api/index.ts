/**
 * API Routes Index
 *
 * Central router that combines all API endpoints.
 */

import { Router } from 'express';
import type { AgentOrchestrator } from '../orchestrator.js';
import { createAgentsRouter } from './agents.js';
import { createMetricsRouter } from './metrics.js';
import { createCasesRouter } from './cases.js';
import { createSchedulerRouter } from './scheduler.js';
import { getDispatcher } from '../dispatcher.js';

export function createApiRouter(orchestrator: AgentOrchestrator): Router {
  const router = Router();

  // Agent management
  router.use('/agents', createAgentsRouter(orchestrator));

  // System metrics
  router.use('/metrics', createMetricsRouter(orchestrator));

  // Cases and detections
  router.use('/cases', createCasesRouter(orchestrator));

  // Scheduler management
  router.use('/scheduler', createSchedulerRouter());

  // Dispatcher stats
  router.get('/dispatcher/stats', (_req, res) => {
    const dispatcher = getDispatcher();
    res.json(dispatcher.getStats());
  });

  // API info
  router.get('/', (_req, res) => {
    res.json({
      name: 'AI Authority API',
      version: '0.1.0',
      endpoints: [
        'GET /api/agents',
        'GET /api/agents/:id',
        'POST /api/agents/:id/task',
        'POST /api/agents/:id/restart',
        'GET /api/metrics',
        'GET /api/metrics/history',
        'GET /api/cases',
        'GET /api/cases/:id',
        'GET /api/scheduler/status',
        'POST /api/scheduler/scan',
        'POST /api/scheduler/start',
        'POST /api/scheduler/stop',
        'GET /api/dispatcher/stats',
      ],
    });
  });

  return router;
}
