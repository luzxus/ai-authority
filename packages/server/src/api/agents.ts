/**
 * Agents API
 *
 * REST endpoints for agent management.
 */

import { Router, type Request, type Response } from 'express';
import type { AgentOrchestrator } from '../orchestrator.js';

export function createAgentsRouter(orchestrator: AgentOrchestrator): Router {
  const router = Router();

  // List all agents
  router.get('/', (_req: Request, res: Response) => {
    const agents = orchestrator.getAllAgents().map((agent) => ({
      id: agent.id,
      role: agent.role,
      layer: agent.layer,
      status: agent.status,
      startedAt: agent.startedAt?.toISOString(),
      stoppedAt: agent.stoppedAt?.toISOString(),
      tasksProcessed: agent.tasksProcessed,
      tasksFailed: agent.tasksFailed,
      lastHeartbeat: agent.lastHeartbeat?.toISOString(),
      errorMessage: agent.errorMessage,
    }));

    res.json({
      count: agents.length,
      agents,
    });
  });

  // Get agent by ID
  router.get('/:id', (req: Request, res: Response) => {
    const agentId = req.params.id;
    if (!agentId) {
      res.status(400).json({ error: 'Agent ID is required' });
      return;
    }
    const agent = orchestrator.getAgent(agentId);

    if (!agent) {
      res.status(404).json({ error: 'Agent not found' });
      return;
    }

    res.json({
      id: agent.id,
      role: agent.role,
      layer: agent.layer,
      status: agent.status,
      startedAt: agent.startedAt?.toISOString(),
      stoppedAt: agent.stoppedAt?.toISOString(),
      tasksProcessed: agent.tasksProcessed,
      tasksFailed: agent.tasksFailed,
      lastHeartbeat: agent.lastHeartbeat?.toISOString(),
      errorMessage: agent.errorMessage,
    });
  });

  // Get agents by layer
  router.get('/layer/:layer', (req: Request, res: Response) => {
    const layer = req.params.layer;
    if (!layer) {
      res.status(400).json({ error: 'Layer is required' });
      return;
    }
    const agents = orchestrator.getAgentsByLayer(layer).map((agent) => ({
      id: agent.id,
      role: agent.role,
      layer: agent.layer,
      status: agent.status,
      tasksProcessed: agent.tasksProcessed,
      tasksFailed: agent.tasksFailed,
      lastHeartbeat: agent.lastHeartbeat?.toISOString(),
    }));

    res.json({
      layer: req.params.layer,
      count: agents.length,
      agents,
    });
  });

  // Submit a task to an agent
  router.post('/:id/task', async (req: Request, res: Response) => {
    const agentId = req.params.id;
    if (!agentId) {
      res.status(400).json({ error: 'Agent ID is required' });
      return;
    }
    const { type, payload } = req.body;

    if (!type) {
      res.status(400).json({ error: 'Task type is required' });
      return;
    }

    try {
      const result = await orchestrator.submitTask(agentId, { type, payload });
      res.json({
        success: true,
        agentId: req.params.id,
        taskType: type,
        result,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Task failed',
      });
    }
  });

  // Restart an agent
  router.post('/:id/restart', async (req: Request, res: Response) => {
    const agentId = req.params.id;
    if (!agentId) {
      res.status(400).json({ error: 'Agent ID is required' });
      return;
    }
    try {
      await orchestrator.restartAgent(agentId);
      res.json({
        success: true,
        message: `Agent ${agentId} restarted`,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Restart failed',
      });
    }
  });

  // Stop an agent
  router.post('/:id/stop', async (req: Request, res: Response) => {
    const agentId = req.params.id;
    if (!agentId) {
      res.status(400).json({ error: 'Agent ID is required' });
      return;
    }
    try {
      await orchestrator.stopAgent(agentId);
      res.json({
        success: true,
        message: `Agent ${req.params.id} stopped`,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Stop failed',
      });
    }
  });

  // Create a new agent
  router.post('/', async (req: Request, res: Response) => {
    const { role, layer } = req.body;

    if (!role || !layer) {
      res.status(400).json({ error: 'Role and layer are required' });
      return;
    }

    const validLayers = ['sensing', 'analysis', 'decision', 'governance'];
    if (!validLayers.includes(layer)) {
      res.status(400).json({ error: `Layer must be one of: ${validLayers.join(', ')}` });
      return;
    }

    try {
      const agentId = await orchestrator.createAgent(role, layer);
      const agent = orchestrator.getAgent(agentId);

      res.status(201).json({
        success: true,
        agent: {
          id: agentId,
          role: agent?.role,
          layer: agent?.layer,
          status: agent?.status,
        },
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to create agent',
      });
    }
  });

  return router;
}
