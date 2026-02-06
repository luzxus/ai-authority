/**
 * Metrics API
 *
 * REST endpoints for system metrics and monitoring.
 */

import { Router, type Request, type Response } from 'express';
import type { AgentOrchestrator } from '../orchestrator.js';

interface MetricsSnapshot {
  timestamp: number;
  metrics: ReturnType<AgentOrchestrator['getMetrics']>;
}

export function createMetricsRouter(orchestrator: AgentOrchestrator): Router {
  const router = Router();
  const history: MetricsSnapshot[] = [];
  const MAX_HISTORY = 360; // 30 minutes at 5-second intervals

  // Collect metrics periodically
  setInterval(() => {
    history.push({
      timestamp: Date.now(),
      metrics: orchestrator.getMetrics(),
    });

    // Trim old entries
    while (history.length > MAX_HISTORY) {
      history.shift();
    }
  }, 5000);

  // Get current metrics
  router.get('/', (_req: Request, res: Response) => {
    const metrics = orchestrator.getMetrics();

    res.json({
      ...metrics,
      timestamp: Date.now(),
      memoryMB: {
        heapUsed: Math.round(metrics.memoryUsage.heapUsed / 1024 / 1024),
        heapTotal: Math.round(metrics.memoryUsage.heapTotal / 1024 / 1024),
        rss: Math.round(metrics.memoryUsage.rss / 1024 / 1024),
        external: Math.round(metrics.memoryUsage.external / 1024 / 1024),
      },
    });
  });

  // Get metrics history
  router.get('/history', (req: Request, res: Response) => {
    const limit = Math.min(parseInt(req.query.limit as string) || 60, MAX_HISTORY);
    const recent = history.slice(-limit);

    res.json({
      count: recent.length,
      intervalMs: 5000,
      history: recent.map((h) => ({
        timestamp: h.timestamp,
        runningAgents: h.metrics.runningAgents,
        tasksProcessed: h.metrics.totalTasksProcessed,
        tasksFailed: h.metrics.totalTasksFailed,
        heapUsedMB: Math.round(h.metrics.memoryUsage.heapUsed / 1024 / 1024),
      })),
    });
  });

  // Get agent-specific metrics
  router.get('/agents', (_req: Request, res: Response) => {
    const agents = orchestrator.getAllAgents();

    const byLayer: Record<string, { count: number; running: number; tasks: number; failed: number }> = {};
    const byRole: Record<string, { count: number; running: number; tasks: number; failed: number }> = {};

    for (const agent of agents) {
      // By layer
      if (!byLayer[agent.layer]) {
        byLayer[agent.layer] = { count: 0, running: 0, tasks: 0, failed: 0 };
      }
      const layerStats = byLayer[agent.layer];
      if (layerStats) {
        layerStats.count++;
        if (agent.status === 'running') layerStats.running++;
        layerStats.tasks += agent.tasksProcessed;
        layerStats.failed += agent.tasksFailed;
      }

      // By role
      if (!byRole[agent.role]) {
        byRole[agent.role] = { count: 0, running: 0, tasks: 0, failed: 0 };
      }
      const roleStats = byRole[agent.role];
      if (roleStats) {
        roleStats.count++;
        if (agent.status === 'running') roleStats.running++;
        roleStats.tasks += agent.tasksProcessed;
        roleStats.failed += agent.tasksFailed;
      }
    }

    res.json({
      totalAgents: agents.length,
      runningAgents: agents.filter((a) => a.status === 'running').length,
      byLayer,
      byRole,
    });
  });

  // Get health summary
  router.get('/health', (_req: Request, res: Response) => {
    const metrics = orchestrator.getMetrics();
    const agents = orchestrator.getAllAgents();

    const unhealthyAgents = agents.filter((a) => {
      if (a.status === 'error') return true;
      if (a.status === 'running' && a.lastHeartbeat) {
        const staleMs = Date.now() - a.lastHeartbeat.getTime();
        return staleMs > 30000; // 30 seconds without heartbeat
      }
      return false;
    });

    const memoryUsagePercent = (metrics.memoryUsage.heapUsed / metrics.memoryUsage.heapTotal) * 100;

    const status = unhealthyAgents.length > 0 || memoryUsagePercent > 90 ? 'degraded' : 'healthy';

    res.json({
      status,
      checks: {
        agents: {
          status: unhealthyAgents.length === 0 ? 'pass' : 'fail',
          total: agents.length,
          unhealthy: unhealthyAgents.length,
          unhealthyIds: unhealthyAgents.map((a) => a.id),
        },
        memory: {
          status: memoryUsagePercent < 90 ? 'pass' : 'warn',
          usedPercent: Math.round(memoryUsagePercent),
          heapUsedMB: Math.round(metrics.memoryUsage.heapUsed / 1024 / 1024),
        },
        uptime: {
          status: 'pass',
          seconds: Math.round(metrics.uptime / 1000),
        },
      },
    });
  });

  return router;
}
