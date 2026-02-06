/**
 * Scheduler API
 *
 * REST endpoints for monitoring and controlling the scan scheduler.
 */

import { Router, type Request, type Response } from 'express';
import { getScheduler } from '../scheduler.js';

export function createSchedulerRouter(): Router {
  const router = Router();
  const scheduler = getScheduler();

  // Get scheduler status
  router.get('/status', (_req: Request, res: Response) => {
    const state = scheduler.getState();
    res.json({
      success: true,
      scheduler: {
        running: state.running,
        startedAt: state.startedAt?.toISOString(),
        nextScanAt: state.nextScanAt?.toISOString(),
        totalScans: state.totalScans,
        totalThreatsFound: state.totalThreatsFound,
        totalCasesCreated: state.totalCasesCreated,
      },
      lastScan: state.lastScan ? {
        scanId: state.lastScan.scanId,
        startedAt: state.lastScan.startedAt.toISOString(),
        completedAt: state.lastScan.completedAt.toISOString(),
        durationMs: state.lastScan.durationMs,
        pagesScanned: state.lastScan.pagesScanned,
        postsAnalyzed: state.lastScan.postsAnalyzed,
        agentsAnalyzed: state.lastScan.agentsAnalyzed,
        threatsDetected: state.lastScan.threatsDetected,
        casesCreated: state.lastScan.casesCreated,
        signalsBySeverity: state.lastScan.signalsBySeverity,
        errors: state.lastScan.errors,
        hasMoreContent: state.lastScan.hasMoreContent,
      } : null,
    });
  });

  // Trigger a manual scan
  router.post('/scan', async (_req: Request, res: Response) => {
    try {
      const result = await scheduler.triggerManualScan();
      res.json({
        success: true,
        scan: {
          scanId: result.scanId,
          startedAt: result.startedAt.toISOString(),
          completedAt: result.completedAt.toISOString(),
          durationMs: result.durationMs,
          pagesScanned: result.pagesScanned,
          postsAnalyzed: result.postsAnalyzed,
          agentsAnalyzed: result.agentsAnalyzed,
          threatsDetected: result.threatsDetected,
          casesCreated: result.casesCreated,
          signalsBySeverity: result.signalsBySeverity,
          errors: result.errors,
          hasMoreContent: result.hasMoreContent,
        },
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Scan failed',
      });
    }
  });

  // Start the scheduler (if not already running)
  router.post('/start', (_req: Request, res: Response) => {
    const state = scheduler.getState();
    if (state.running) {
      res.json({ success: true, message: 'Scheduler already running' });
      return;
    }
    
    scheduler.start();
    res.json({ success: true, message: 'Scheduler started' });
  });

  // Stop the scheduler
  router.post('/stop', (_req: Request, res: Response) => {
    const state = scheduler.getState();
    if (!state.running) {
      res.json({ success: true, message: 'Scheduler not running' });
      return;
    }
    
    scheduler.stop();
    res.json({ success: true, message: 'Scheduler stopped' });
  });

  return router;
}
