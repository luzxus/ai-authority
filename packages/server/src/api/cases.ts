/**
 * Cases API
 *
 * REST endpoints for detection cases and incidents.
 * Integrates with MoltbookClient for real threat detection.
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import { generateSecureId } from '@ai-authority/core';
import type { AgentOrchestrator } from '../orchestrator.js';
import {
  MoltbookClient,
  type MoltbookThreatSignal,
  type ThreatEvidence,
} from '@ai-authority/federation';
import {
  createCase as dbCreateCase,
  getCaseById as dbGetCaseById,
  caseExists as dbCaseExists,
  listCases as dbListCases,
  updateCaseStatus as dbUpdateCaseStatus,
  addEvidence as dbAddEvidence,
  getCaseStats as dbGetCaseStats,
  type CaseInput,
  type EvidenceInput,
  type TimelineEventInput,
} from '../database.js';

// ============================================================================
// Types
// ============================================================================

interface DetectionCase {
  id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'investigating' | 'resolved' | 'dismissed';
  category: 'malicious' | 'negligent' | 'suspicious' | 'unknown';
  targetId: string;
  targetType: 'agent' | 'api' | 'endpoint' | 'unknown' | 'moltbook_agent';
  detectedAt: Date;
  detectedBy: string;
  riskScore: number;
  evidence: CaseEvidence[];
  timeline: CaseEvent[];
  assignedTo?: string | undefined;
  resolvedAt?: Date | undefined;
  resolution?: string | undefined;
  /** Moltbook-specific fields */
  moltbookUsername?: string | undefined;
  threatTypes?: string[] | undefined;
}

interface CaseEvidence {
  id: string;
  type: string;
  description: string;
  data: unknown;
  collectedAt: Date;
  collectedBy: string;
}

interface CaseEvent {
  id: string;
  timestamp: Date;
  type: string;
  description: string;
  actor: string;
}

// ============================================================================
// Moltbook Integration
// ============================================================================

let moltbookClient: MoltbookClient | null = null;

/**
 * Initialize or get the Moltbook Client instance.
 */
function getMoltbookClient(): MoltbookClient {
  if (!moltbookClient) {
    moltbookClient = new MoltbookClient({
      baseUrl: 'https://www.moltbook.com/api/v1',
      timeoutMs: 30000,
    });
  }
  return moltbookClient;
}

/**
 * Map threat type to case category.
 */
function threatTypeToCategory(threatType: string): DetectionCase['category'] {
  const maliciousTypes = [
    'credential_theft',
    'scam',
    'malware_distribution',
    'phishing',
    'data_harvesting',
  ];
  const negligentTypes = ['prompt_injection', 'manipulation'];
  
  if (maliciousTypes.includes(threatType)) return 'malicious';
  if (negligentTypes.includes(threatType)) return 'negligent';
  return 'suspicious';
}

/**
 * Convert a Moltbook threat signal to a DetectionCase.
 */
function signalToCase(signal: MoltbookThreatSignal): DetectionCase {
  return {
    id: `case-${signal.id.slice(0, 8)}`,
    title: `Moltbook: ${signal.agentUsername} - ${signal.type.replace(/_/g, ' ')}`,
    description: signal.evidence
      .map((e: ThreatEvidence) => `${e.type}: ${e.description}`)
      .join('\n') || `Suspicious activity detected for @${signal.agentUsername}`,
    severity: signal.severity,
    status: signal.severity === 'critical' ? 'investigating' : 'open',
    category: threatTypeToCategory(signal.type),
    targetId: signal.agentUsername,
    targetType: 'moltbook_agent',
    detectedAt: signal.detectedAt,
    detectedBy: 'moltbook-client',
    riskScore: signal.confidence,
    evidence: [{
      id: generateSecureId().slice(0, 8),
      type: signal.type,
      description: signal.evidence
        .map((e: ThreatEvidence) => `${e.type}: ${e.description}`)
        .join('; '),
      data: {
        confidence: signal.confidence,
        evidence: signal.evidence,
        sourceId: signal.sourceId,
        relatedAgents: signal.relatedAgents,
      },
      collectedAt: signal.detectedAt,
      collectedBy: 'moltbook-client',
    }],
    timeline: [
      {
        id: generateSecureId().slice(0, 8),
        timestamp: signal.detectedAt,
        type: 'created',
        description: `Threat detected: ${signal.type}`,
        actor: 'moltbook-client',
      },
    ],
    moltbookUsername: signal.agentUsername,
    threatTypes: [signal.type],
  };
}

/**
 * Sync cases from Moltbook signals to the database.
 */
function syncCasesFromMoltbook(): void {
  const client = getMoltbookClient();
  const signals = client.getSignals();
  
  for (const signal of signals) {
    const caseId = `case-${signal.id.slice(0, 8)}`;
    // Only add if not already tracked in database
    if (!dbCaseExists(caseId)) {
      const detectionCase = signalToCase(signal);
      const caseInput: CaseInput = {
        id: detectionCase.id,
        title: detectionCase.title,
        description: detectionCase.description,
        severity: detectionCase.severity,
        status: detectionCase.status,
        category: detectionCase.category,
        targetId: detectionCase.targetId,
        targetType: detectionCase.targetType,
        detectedAt: detectionCase.detectedAt,
        detectedBy: detectionCase.detectedBy,
        riskScore: detectionCase.riskScore,
        moltbookUsername: detectionCase.moltbookUsername,
        threatTypes: detectionCase.threatTypes,
      };
      const evidence: EvidenceInput[] = detectionCase.evidence.map((e) => ({
        id: e.id,
        type: e.type,
        description: e.description,
        data: e.data,
        collectedAt: e.collectedAt,
        collectedBy: e.collectedBy,
      }));
      const timeline: TimelineEventInput[] = detectionCase.timeline.map((t) => ({
        id: t.id,
        timestamp: t.timestamp,
        type: t.type,
        description: t.description,
        actor: t.actor,
      }));
      try {
        dbCreateCase(caseInput, evidence, timeline);
      } catch (error) {
        console.warn(`Failed to persist case ${caseId}:`, error);
      }
    }
  }
}

// ============================================================================
// Router
// ============================================================================

export function createCasesRouter(_orchestrator: AgentOrchestrator): Router {
  const router = Router();

  // Sync from Moltbook on each request (in production, this would be event-driven)
  router.use((_req: Request, _res: Response, next: NextFunction) => {
    syncCasesFromMoltbook();
    next();
  });

  // Moltbook-specific endpoints
  // -------------------------------------------------------------------------

  // Trigger a manual scan of recent Moltbook activity
  router.post('/moltbook/scan', async (_req: Request, res: Response) => {
    try {
      const client = getMoltbookClient();
      const startTime = Date.now();
      
      const signals = await client.scanRecentActivity({
        postLimit: 100,
        analyzeAgents: true,
      });
      
      // Sync new cases
      syncCasesFromMoltbook();
      
      res.json({
        success: true,
        scan: {
          timestamp: new Date().toISOString(),
          signalsFound: signals.length,
          criticalCount: signals.filter((s: MoltbookThreatSignal) => s.severity === 'critical').length,
          highCount: signals.filter((s: MoltbookThreatSignal) => s.severity === 'high').length,
          durationMs: Date.now() - startTime,
        },
      });
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Scan failed',
      });
    }
  });

  // Get Moltbook stats
  router.get('/moltbook/stats', (_req: Request, res: Response) => {
    const client = getMoltbookClient();
    const signals = client.getSignals();
    
    const bySeverity: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 };
    const byType: Record<string, number> = {};
    
    for (const signal of signals) {
      const currentCount = bySeverity[signal.severity];
      if (currentCount !== undefined) {
        bySeverity[signal.severity] = currentCount + 1;
      }
      byType[signal.type] = (byType[signal.type] ?? 0) + 1;
    }
    
    res.json({
      totalSignals: signals.length,
      bySeverity,
      byType,
      uniqueAgents: new Set(signals.map((s: MoltbookThreatSignal) => s.agentUsername)).size,
    });
  });

  // Investigate a specific Moltbook agent
  router.post('/moltbook/investigate', async (req: Request, res: Response) => {
    const { username } = req.body;
    
    if (!username) {
      res.status(400).json({ error: 'Username is required' });
      return;
    }
    
    try {
      const client = getMoltbookClient();
      const signals = await client.analyzeAgent(username);
      
      // Sync to create cases if needed
      syncCasesFromMoltbook();
      
      const riskScore = signals.length > 0
        ? Math.min(1, signals.reduce((sum, s) => sum + s.confidence, 0) / signals.length)
        : 0;
      
      res.json({
        success: true,
        investigation: {
          username,
          riskScore,
          signalCount: signals.length,
          threatTypes: [...new Set(signals.map((s) => s.type))],
          signals: signals.map((s) => ({
            id: s.id,
            type: s.type,
            severity: s.severity,
            confidence: s.confidence,
            detectedAt: s.detectedAt.toISOString(),
          })),
        },
      });
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Investigation failed',
      });
    }
  });

  // Get all Moltbook threat signals
  router.get('/moltbook/signals', (req: Request, res: Response) => {
    const client = getMoltbookClient();
    let signals = client.getSignals();
    
    // Filter by severity
    const severity = req.query.severity as string;
    if (severity && ['low', 'medium', 'high', 'critical'].includes(severity)) {
      signals = signals.filter((s: MoltbookThreatSignal) => s.severity === severity);
    }
    
    // Filter by type
    const type = req.query.type as string;
    if (type) {
      signals = signals.filter((s: MoltbookThreatSignal) => s.type === type);
    }
    
    res.json({
      total: signals.length,
      signals: signals.map((s: MoltbookThreatSignal) => ({
        id: s.id,
        type: s.type,
        severity: s.severity,
        confidence: s.confidence,
        agentUsername: s.agentUsername,
        detectedAt: s.detectedAt.toISOString(),
        evidenceCount: s.evidence.length,
        sourceId: s.sourceId,
      })),
    });
  });

  // Get agents with threats (targets)
  router.get('/moltbook/targets', (req: Request, res: Response) => {
    const client = getMoltbookClient();
    const signals = client.getSignals();
    
    // Group signals by agent
    const agentSignals = new Map<string, MoltbookThreatSignal[]>();
    for (const signal of signals) {
      const existing = agentSignals.get(signal.agentUsername) ?? [];
      existing.push(signal);
      agentSignals.set(signal.agentUsername, existing);
    }
    
    // Build targets from grouped signals
    let targets = Array.from(agentSignals.entries()).map(([username, agentSigs]) => {
      const maxSeverity = agentSigs.reduce((max, s) => {
        const order = { low: 0, medium: 1, high: 2, critical: 3 };
        return order[s.severity] > order[max.severity] ? s : max;
      }, agentSigs[0]!);
      
      return {
        username,
        riskScore: agentSigs.reduce((sum, s) => sum + s.confidence, 0) / agentSigs.length,
        priority: maxSeverity.severity,
        threatTypes: [...new Set(agentSigs.map((s) => s.type))],
        signalCount: agentSigs.length,
        firstSeen: new Date(Math.min(...agentSigs.map((s) => s.detectedAt.getTime()))),
        lastSeen: new Date(Math.max(...agentSigs.map((s) => s.detectedAt.getTime()))),
      };
    });
    
    // Filter by priority
    const priority = req.query.priority as string;
    if (priority) {
      targets = targets.filter((t) => t.priority === priority);
    }
    
    res.json({
      total: targets.length,
      targets: targets.map((t) => ({
        ...t,
        firstSeen: t.firstSeen.toISOString(),
        lastSeen: t.lastSeen.toISOString(),
      })),
    });
  });

  // Standard case endpoints
  // -------------------------------------------------------------------------

  // List all cases (using SQLite)
  router.get('/', (req: Request, res: Response) => {
    const status = req.query.status as string | undefined;
    const severity = req.query.severity as string | undefined;
    const category = req.query.category as string | undefined;
    const page = parseInt(req.query.page as string) || 1;
    const pageSize = Math.min(parseInt(req.query.limit as string) || 20, 100);

    const result = dbListCases({
      status,
      severity,
      category,
      page,
      pageSize,
      sortBy: 'detected_at',
      sortOrder: 'desc',
    });

    res.json({
      total: result.total,
      page: result.page,
      limit: result.pageSize,
      totalPages: result.totalPages,
      cases: result.cases.map((c) => ({
        id: c.id,
        title: c.title,
        severity: c.severity,
        status: c.status,
        category: c.category,
        targetId: c.targetId,
        targetType: c.targetType,
        detectedAt: c.detectedAt.toISOString(),
        riskScore: c.riskScore,
      })),
    });
  });

  // Get case by ID (using SQLite)
  router.get('/:id', (req: Request, res: Response) => {
    const caseId = req.params.id;
    if (!caseId) {
      res.status(400).json({ error: 'Case ID is required' });
      return;
    }
    const caseData = dbGetCaseById(caseId);

    if (!caseData) {
      res.status(404).json({ error: 'Case not found' });
      return;
    }

    res.json({
      id: caseData.id,
      title: caseData.title,
      description: caseData.description,
      severity: caseData.severity,
      status: caseData.status,
      category: caseData.category,
      targetId: caseData.targetId,
      targetType: caseData.targetType,
      riskScore: caseData.riskScore,
      moltbookUsername: caseData.moltbookUsername,
      threatTypes: caseData.threatTypes,
      detectedAt: caseData.detectedAt.toISOString(),
      detectedBy: caseData.detectedBy,
      resolvedAt: caseData.resolvedAt?.toISOString(),
      resolution: caseData.resolution,
      createdAt: caseData.createdAt.toISOString(),
      updatedAt: caseData.updatedAt.toISOString(),
      timeline: caseData.timeline.map((e) => ({
        ...e,
        timestamp: e.timestamp.toISOString(),
      })),
      evidence: caseData.evidence.map((e) => ({
        ...e,
        collectedAt: e.collectedAt.toISOString(),
      })),
    });
  });

  // Get case statistics (using SQLite)
  router.get('/stats/summary', (_req: Request, res: Response) => {
    const stats = dbGetCaseStats();
    res.json(stats);
  });

  // Update case status (using SQLite)
  router.patch('/:id/status', (req: Request, res: Response) => {
    const caseId = req.params.id;
    if (!caseId) {
      res.status(400).json({ error: 'Case ID is required' });
      return;
    }

    const { status, resolution, actor } = req.body;
    const validStatuses = ['open', 'investigating', 'resolved', 'dismissed'];

    if (!validStatuses.includes(status)) {
      res.status(400).json({ error: `Status must be one of: ${validStatuses.join(', ')}` });
      return;
    }

    const updatedCase = dbUpdateCaseStatus(caseId, status, actor || 'api', resolution);

    if (!updatedCase) {
      res.status(404).json({ error: 'Case not found' });
      return;
    }

    res.json({
      success: true,
      case: {
        id: updatedCase.id,
        status: updatedCase.status,
        resolvedAt: updatedCase.resolvedAt?.toISOString(),
        resolution: updatedCase.resolution,
      },
    });
  });

  // Add evidence to a case (using SQLite)
  router.post('/:id/evidence', (req: Request, res: Response) => {
    const caseId = req.params.id;
    if (!caseId) {
      res.status(400).json({ error: 'Case ID is required' });
      return;
    }

    const { type, description, data, collectedBy } = req.body;

    if (!type || !description) {
      res.status(400).json({ error: 'Type and description are required' });
      return;
    }

    const evidence: EvidenceInput = {
      id: generateSecureId().slice(0, 8),
      type,
      description,
      data: data ?? null,
      collectedAt: new Date(),
      collectedBy: collectedBy ?? 'api',
    };

    const updatedCase = dbAddEvidence(caseId, evidence, collectedBy ?? 'api');

    if (!updatedCase) {
      res.status(404).json({ error: 'Case not found' });
      return;
    }

    res.status(201).json({
      success: true,
      evidence: {
        ...evidence,
        collectedAt: evidence.collectedAt.toISOString(),
      },
    });
  });

  // Create a new case (using SQLite)
  router.post('/', (req: Request, res: Response) => {
    const { title, description, severity, category, targetId, targetType, riskScore, detectedBy } = req.body;

    if (!title) {
      res.status(400).json({ error: 'Title is required' });
      return;
    }

    const id = `case-${generateSecureId().slice(0, 8)}`;
    const now = new Date();

    const caseInput: CaseInput = {
      id,
      title,
      description: description ?? '',
      severity: severity ?? 'medium',
      status: 'open',
      category: category ?? 'unknown',
      targetId: targetId ?? 'unknown',
      targetType: targetType ?? 'unknown',
      detectedAt: now,
      detectedBy: detectedBy ?? 'api',
      riskScore: riskScore ?? 0.5,
    };

    const timeline: TimelineEventInput[] = [{
      id: generateSecureId().slice(0, 8),
      timestamp: now,
      type: 'created',
      description: 'Case created',
      actor: detectedBy ?? 'api',
    }];

    try {
      const newCase = dbCreateCase(caseInput, [], timeline);

      res.status(201).json({
        success: true,
        case: {
          id: newCase.id,
          title: newCase.title,
          severity: newCase.severity,
          status: newCase.status,
          detectedAt: newCase.detectedAt.toISOString(),
        },
      });
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Failed to create case',
      });
    }
  });

  return router;
}
