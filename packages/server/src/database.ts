/**
 * Database Module
 *
 * SQLite persistence layer for the AI Authority server.
 * Handles cases, evidence, timeline events, and audit logs.
 */

import Database from 'better-sqlite3';
import { join, dirname } from 'path';
import { mkdirSync, existsSync } from 'fs';

// ============================================================================
// Types
// ============================================================================

export interface DbCase {
  id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'investigating' | 'resolved' | 'dismissed';
  category: 'malicious' | 'negligent' | 'suspicious' | 'unknown';
  target_id: string;
  target_type: string;
  detected_at: string;
  detected_by: string;
  risk_score: number;
  assigned_to: string | null;
  resolved_at: string | null;
  resolution: string | null;
  moltbook_username: string | null;
  threat_types: string | null;  // JSON array
  created_at: string;
  updated_at: string;
}

export interface DbEvidence {
  id: string;
  case_id: string;
  type: string;
  description: string;
  data: string;  // JSON
  collected_at: string;
  collected_by: string;
}

export interface DbTimelineEvent {
  id: string;
  case_id: string;
  timestamp: string;
  type: string;
  description: string;
  actor: string;
}

export interface DbAuditLog {
  id: string;
  timestamp: string;
  action: string;
  entity_type: string;
  entity_id: string;
  actor: string;
  data: string | null;  // JSON
}

// ============================================================================
// Database Manager
// ============================================================================

let db: Database.Database | null = null;

/**
 * Get or create database connection.
 */
export function getDatabase(dbPath?: string): Database.Database {
  if (db) return db;

  const path = dbPath ?? join(process.cwd(), 'data', 'ai-authority.db');
  
  // Ensure directory exists
  const dir = dirname(path);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  db = new Database(path);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  initializeSchema(db);
  return db;
}

/**
 * Close database connection.
 */
export function closeDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

/**
 * Initialize database schema.
 */
function initializeSchema(database: Database.Database): void {
  database.exec(`
    -- Cases table
    CREATE TABLE IF NOT EXISTS cases (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
      status TEXT NOT NULL CHECK (status IN ('open', 'investigating', 'resolved', 'dismissed')),
      category TEXT NOT NULL CHECK (category IN ('malicious', 'negligent', 'suspicious', 'unknown')),
      target_id TEXT NOT NULL,
      target_type TEXT NOT NULL,
      detected_at TEXT NOT NULL,
      detected_by TEXT NOT NULL,
      risk_score REAL NOT NULL DEFAULT 0,
      assigned_to TEXT,
      resolved_at TEXT,
      resolution TEXT,
      moltbook_username TEXT,
      threat_types TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Evidence table
    CREATE TABLE IF NOT EXISTS evidence (
      id TEXT PRIMARY KEY,
      case_id TEXT NOT NULL,
      type TEXT NOT NULL,
      description TEXT NOT NULL,
      data TEXT,
      collected_at TEXT NOT NULL,
      collected_by TEXT NOT NULL,
      FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    -- Timeline events table
    CREATE TABLE IF NOT EXISTS timeline_events (
      id TEXT PRIMARY KEY,
      case_id TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      type TEXT NOT NULL,
      description TEXT NOT NULL,
      actor TEXT NOT NULL,
      FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    -- Audit log table (append-only)
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL DEFAULT (datetime('now')),
      action TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      entity_id TEXT NOT NULL,
      actor TEXT NOT NULL,
      data TEXT
    );

    -- Indexes for common queries
    CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
    CREATE INDEX IF NOT EXISTS idx_cases_severity ON cases(severity);
    CREATE INDEX IF NOT EXISTS idx_cases_detected_at ON cases(detected_at);
    CREATE INDEX IF NOT EXISTS idx_cases_target_id ON cases(target_id);
    CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id);
    CREATE INDEX IF NOT EXISTS idx_timeline_case_id ON timeline_events(case_id);
    CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_id);
  `);
}

// ============================================================================
// Case Operations
// ============================================================================

export interface CaseInput {
  id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'investigating' | 'resolved' | 'dismissed';
  category: 'malicious' | 'negligent' | 'suspicious' | 'unknown';
  targetId: string;
  targetType: string;
  detectedAt: Date;
  detectedBy: string;
  riskScore: number;
  assignedTo?: string | undefined;
  resolvedAt?: Date | undefined;
  resolution?: string | undefined;
  moltbookUsername?: string | undefined;
  threatTypes?: string[] | undefined;
}

export interface CaseWithRelations extends Omit<CaseInput, 'assignedTo' | 'resolvedAt' | 'resolution' | 'moltbookUsername' | 'threatTypes'> {
  assignedTo?: string | undefined;
  resolvedAt?: Date | undefined;
  resolution?: string | undefined;
  moltbookUsername?: string | undefined;
  threatTypes?: string[] | undefined;
  evidence: EvidenceInput[];
  timeline: TimelineEventInput[];
  createdAt: Date;
  updatedAt: Date;
}

export interface EvidenceInput {
  id: string;
  type: string;
  description: string;
  data: unknown;
  collectedAt: Date;
  collectedBy: string;
}

export interface TimelineEventInput {
  id: string;
  timestamp: Date;
  type: string;
  description: string;
  actor: string;
}

/**
 * Create a new case with evidence and timeline events.
 */
export function createCase(
  input: CaseInput,
  evidence: EvidenceInput[] = [],
  timeline: TimelineEventInput[] = []
): CaseWithRelations {
  const database = getDatabase();
  
  const insertCase = database.prepare(`
    INSERT INTO cases (
      id, title, description, severity, status, category,
      target_id, target_type, detected_at, detected_by, risk_score,
      assigned_to, resolved_at, resolution, moltbook_username, threat_types
    ) VALUES (
      @id, @title, @description, @severity, @status, @category,
      @targetId, @targetType, @detectedAt, @detectedBy, @riskScore,
      @assignedTo, @resolvedAt, @resolution, @moltbookUsername, @threatTypes
    )
  `);

  const insertEvidence = database.prepare(`
    INSERT INTO evidence (id, case_id, type, description, data, collected_at, collected_by)
    VALUES (@id, @caseId, @type, @description, @data, @collectedAt, @collectedBy)
  `);

  const insertTimeline = database.prepare(`
    INSERT INTO timeline_events (id, case_id, timestamp, type, description, actor)
    VALUES (@id, @caseId, @timestamp, @type, @description, @actor)
  `);

  const insertAudit = database.prepare(`
    INSERT INTO audit_log (action, entity_type, entity_id, actor, data)
    VALUES (@action, @entityType, @entityId, @actor, @data)
  `);

  const transaction = database.transaction(() => {
    // Insert case
    insertCase.run({
      id: input.id,
      title: input.title,
      description: input.description,
      severity: input.severity,
      status: input.status,
      category: input.category,
      targetId: input.targetId,
      targetType: input.targetType,
      detectedAt: input.detectedAt.toISOString(),
      detectedBy: input.detectedBy,
      riskScore: input.riskScore,
      assignedTo: input.assignedTo ?? null,
      resolvedAt: input.resolvedAt?.toISOString() ?? null,
      resolution: input.resolution ?? null,
      moltbookUsername: input.moltbookUsername ?? null,
      threatTypes: input.threatTypes ? JSON.stringify(input.threatTypes) : null,
    });

    // Insert evidence
    for (const ev of evidence) {
      insertEvidence.run({
        id: ev.id,
        caseId: input.id,
        type: ev.type,
        description: ev.description,
        data: JSON.stringify(ev.data),
        collectedAt: ev.collectedAt.toISOString(),
        collectedBy: ev.collectedBy,
      });
    }

    // Insert timeline events
    for (const event of timeline) {
      insertTimeline.run({
        id: event.id,
        caseId: input.id,
        timestamp: event.timestamp.toISOString(),
        type: event.type,
        description: event.description,
        actor: event.actor,
      });
    }

    // Audit log
    insertAudit.run({
      action: 'case_created',
      entityType: 'case',
      entityId: input.id,
      actor: input.detectedBy,
      data: JSON.stringify({ severity: input.severity, category: input.category }),
    });
  });

  transaction();

  return getCaseById(input.id)!;
}

/**
 * Get case by ID with all relations.
 */
export function getCaseById(id: string): CaseWithRelations | null {
  const database = getDatabase();

  const caseRow = database.prepare(`
    SELECT * FROM cases WHERE id = ?
  `).get(id) as DbCase | undefined;

  if (!caseRow) return null;

  const evidenceRows = database.prepare(`
    SELECT * FROM evidence WHERE case_id = ?
  `).all(id) as DbEvidence[];

  const timelineRows = database.prepare(`
    SELECT * FROM timeline_events WHERE case_id = ? ORDER BY timestamp ASC
  `).all(id) as DbTimelineEvent[];

  return {
    id: caseRow.id,
    title: caseRow.title,
    description: caseRow.description,
    severity: caseRow.severity,
    status: caseRow.status,
    category: caseRow.category,
    targetId: caseRow.target_id,
    targetType: caseRow.target_type,
    detectedAt: new Date(caseRow.detected_at),
    detectedBy: caseRow.detected_by,
    riskScore: caseRow.risk_score,
    assignedTo: caseRow.assigned_to ?? undefined,
    resolvedAt: caseRow.resolved_at ? new Date(caseRow.resolved_at) : undefined,
    resolution: caseRow.resolution ?? undefined,
    moltbookUsername: caseRow.moltbook_username ?? undefined,
    threatTypes: caseRow.threat_types ? JSON.parse(caseRow.threat_types) : undefined,
    createdAt: new Date(caseRow.created_at),
    updatedAt: new Date(caseRow.updated_at),
    evidence: evidenceRows.map((ev) => ({
      id: ev.id,
      type: ev.type,
      description: ev.description,
      data: ev.data ? JSON.parse(ev.data) : null,
      collectedAt: new Date(ev.collected_at),
      collectedBy: ev.collected_by,
    })),
    timeline: timelineRows.map((event) => ({
      id: event.id,
      timestamp: new Date(event.timestamp),
      type: event.type,
      description: event.description,
      actor: event.actor,
    })),
  };
}

/**
 * Check if a case exists.
 */
export function caseExists(id: string): boolean {
  const database = getDatabase();
  const row = database.prepare(`SELECT 1 FROM cases WHERE id = ?`).get(id);
  return row !== undefined;
}

/**
 * List cases with filtering and pagination.
 */
export interface ListCasesOptions {
  status?: string | undefined;
  severity?: string | undefined;
  category?: string | undefined;
  targetId?: string | undefined;
  page?: number | undefined;
  pageSize?: number | undefined;
  sortBy?: 'detected_at' | 'risk_score' | 'severity' | undefined;
  sortOrder?: 'asc' | 'desc' | undefined;
}

export interface ListCasesResult {
  cases: CaseWithRelations[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

export function listCases(options: ListCasesOptions = {}): ListCasesResult {
  const database = getDatabase();
  const {
    status,
    severity,
    category,
    targetId,
    page = 1,
    pageSize = 20,
    sortBy = 'detected_at',
    sortOrder = 'desc',
  } = options;

  // Build WHERE clause
  const conditions: string[] = [];
  const params: Record<string, string> = {};

  if (status) {
    conditions.push('status = @status');
    params.status = status;
  }
  if (severity) {
    conditions.push('severity = @severity');
    params.severity = severity;
  }
  if (category) {
    conditions.push('category = @category');
    params.category = category;
  }
  if (targetId) {
    conditions.push('target_id = @targetId');
    params.targetId = targetId;
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  // Count total
  const countStmt = database.prepare(`SELECT COUNT(*) as count FROM cases ${whereClause}`);
  const countRow = countStmt.get(params) as { count: number };
  const total = countRow.count;

  // Get paginated results
  const offset = (page - 1) * pageSize;
  const sortColumn = sortBy === 'severity' ? 
    `CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END` :
    sortBy;
  
  const selectStmt = database.prepare(`
    SELECT id FROM cases ${whereClause}
    ORDER BY ${sortColumn} ${sortOrder.toUpperCase()}
    LIMIT @limit OFFSET @offset
  `);

  const rows = selectStmt.all({ ...params, limit: pageSize, offset }) as { id: string }[];
  const cases = rows.map((row) => getCaseById(row.id)!).filter(Boolean);

  return {
    cases,
    total,
    page,
    pageSize,
    totalPages: Math.ceil(total / pageSize),
  };
}

/**
 * Update case status.
 */
export function updateCaseStatus(
  id: string,
  status: 'open' | 'investigating' | 'resolved' | 'dismissed',
  actor: string,
  resolution?: string
): CaseWithRelations | null {
  const database = getDatabase();

  const resolvedAt = (status === 'resolved' || status === 'dismissed')
    ? new Date().toISOString()
    : null;

  const updateCase = database.prepare(`
    UPDATE cases SET
      status = @status,
      resolved_at = COALESCE(@resolvedAt, resolved_at),
      resolution = COALESCE(@resolution, resolution),
      updated_at = datetime('now')
    WHERE id = @id
  `);

  const insertTimeline = database.prepare(`
    INSERT INTO timeline_events (id, case_id, timestamp, type, description, actor)
    VALUES (@eventId, @caseId, @timestamp, @type, @description, @actor)
  `);

  const insertAudit = database.prepare(`
    INSERT INTO audit_log (action, entity_type, entity_id, actor, data)
    VALUES (@action, @entityType, @entityId, @actor, @data)
  `);

  const transaction = database.transaction(() => {
    const result = updateCase.run({
      id,
      status,
      resolvedAt,
      resolution: resolution ?? null,
    });

    if (result.changes === 0) return null;

    // Add timeline event
    insertTimeline.run({
      eventId: `evt-${Date.now().toString(36)}`,
      caseId: id,
      timestamp: new Date().toISOString(),
      type: 'status_changed',
      description: `Status changed to ${status}${resolution ? `: ${resolution}` : ''}`,
      actor,
    });

    // Audit log
    insertAudit.run({
      action: 'case_status_updated',
      entityType: 'case',
      entityId: id,
      actor,
      data: JSON.stringify({ status, resolution }),
    });

    return getCaseById(id);
  });

  return transaction();
}

/**
 * Add evidence to a case.
 */
export function addEvidence(
  caseId: string,
  evidence: EvidenceInput,
  actor: string
): CaseWithRelations | null {
  const database = getDatabase();

  const insertEvidence = database.prepare(`
    INSERT INTO evidence (id, case_id, type, description, data, collected_at, collected_by)
    VALUES (@id, @caseId, @type, @description, @data, @collectedAt, @collectedBy)
  `);

  const insertTimeline = database.prepare(`
    INSERT INTO timeline_events (id, case_id, timestamp, type, description, actor)
    VALUES (@eventId, @caseId, @timestamp, @type, @description, @actor)
  `);

  const updateCase = database.prepare(`
    UPDATE cases SET updated_at = datetime('now') WHERE id = @caseId
  `);

  const transaction = database.transaction(() => {
    insertEvidence.run({
      id: evidence.id,
      caseId,
      type: evidence.type,
      description: evidence.description,
      data: JSON.stringify(evidence.data),
      collectedAt: evidence.collectedAt.toISOString(),
      collectedBy: evidence.collectedBy,
    });

    insertTimeline.run({
      eventId: `evt-${Date.now().toString(36)}`,
      caseId,
      timestamp: new Date().toISOString(),
      type: 'evidence_added',
      description: `Evidence added: ${evidence.type}`,
      actor,
    });

    updateCase.run({ caseId });

    return getCaseById(caseId);
  });

  return transaction();
}

/**
 * Get case statistics.
 */
export interface CaseStats {
  total: number;
  bySeverity: Record<string, number>;
  byStatus: Record<string, number>;
  byCategory: Record<string, number>;
  avgRiskScore: number;
}

export function getCaseStats(): CaseStats {
  const database = getDatabase();

  const totalRow = database.prepare(`SELECT COUNT(*) as count FROM cases`).get() as { count: number };
  
  const severityRows = database.prepare(`
    SELECT severity, COUNT(*) as count FROM cases GROUP BY severity
  `).all() as { severity: string; count: number }[];

  const statusRows = database.prepare(`
    SELECT status, COUNT(*) as count FROM cases GROUP BY status
  `).all() as { status: string; count: number }[];

  const categoryRows = database.prepare(`
    SELECT category, COUNT(*) as count FROM cases GROUP BY category
  `).all() as { category: string; count: number }[];

  const avgRow = database.prepare(`
    SELECT AVG(risk_score) as avg FROM cases
  `).get() as { avg: number | null };

  const bySeverity: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 };
  const byStatus: Record<string, number> = { open: 0, investigating: 0, resolved: 0, dismissed: 0 };
  const byCategory: Record<string, number> = { malicious: 0, negligent: 0, suspicious: 0, unknown: 0 };

  for (const row of severityRows) {
    bySeverity[row.severity] = row.count;
  }
  for (const row of statusRows) {
    byStatus[row.status] = row.count;
  }
  for (const row of categoryRows) {
    byCategory[row.category] = row.count;
  }

  return {
    total: totalRow.count,
    bySeverity,
    byStatus,
    byCategory,
    avgRiskScore: avgRow.avg !== null ? Math.round(avgRow.avg * 100) / 100 : 0,
  };
}

/**
 * Get audit logs.
 */
export function getAuditLogs(
  entityType?: string,
  entityId?: string,
  limit = 100
): DbAuditLog[] {
  const database = getDatabase();

  let query = `SELECT * FROM audit_log`;
  const params: Record<string, string | number> = { limit };

  if (entityType && entityId) {
    query += ` WHERE entity_type = @entityType AND entity_id = @entityId`;
    params.entityType = entityType;
    params.entityId = entityId;
  } else if (entityType) {
    query += ` WHERE entity_type = @entityType`;
    params.entityType = entityType;
  }

  query += ` ORDER BY timestamp DESC LIMIT @limit`;

  return database.prepare(query).all(params) as DbAuditLog[];
}

// ============================================================================
// Agent Behavior Tracking
// ============================================================================

export interface DbAgentBehavior {
  id: number;
  agent_username: string;
  recorded_at: string;
  post_count: number;
  comment_count: number;
  upvotes_received: number;
  downvotes_received: number;
  threat_signals: number;
  avg_semantic_risk: number;
  manipulation_score: number;
  deception_score: number;
  coordination_score: number;
  activity_hours: string;  // JSON array of hours active
  metadata: string | null;  // JSON
}

export interface DbAgentRiskHistory {
  id: number;
  agent_username: string;
  recorded_at: string;
  risk_score: number;
  risk_level: string;
  contributing_factors: string;  // JSON
  trend: string;  // 'increasing' | 'decreasing' | 'stable'
}

export interface DbAgentAlert {
  id: string;
  agent_username: string;
  alert_type: string;
  severity: string;
  title: string;
  description: string;
  triggered_at: string;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  resolved_at: string | null;
  metadata: string | null;  // JSON
}

/**
 * Initialize behavior tracking tables.
 * Called separately from main schema to allow gradual migration.
 */
export function initializeBehaviorTracking(): void {
  const database = getDatabase();

  database.exec(`
    -- Agent behavior snapshots (periodic recordings)
    CREATE TABLE IF NOT EXISTS agent_behavior (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_username TEXT NOT NULL,
      recorded_at TEXT NOT NULL DEFAULT (datetime('now')),
      post_count INTEGER NOT NULL DEFAULT 0,
      comment_count INTEGER NOT NULL DEFAULT 0,
      upvotes_received INTEGER NOT NULL DEFAULT 0,
      downvotes_received INTEGER NOT NULL DEFAULT 0,
      threat_signals INTEGER NOT NULL DEFAULT 0,
      avg_semantic_risk REAL NOT NULL DEFAULT 0,
      manipulation_score REAL NOT NULL DEFAULT 0,
      deception_score REAL NOT NULL DEFAULT 0,
      coordination_score REAL NOT NULL DEFAULT 0,
      activity_hours TEXT,
      metadata TEXT
    );

    -- Agent risk score history
    CREATE TABLE IF NOT EXISTS agent_risk_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent_username TEXT NOT NULL,
      recorded_at TEXT NOT NULL DEFAULT (datetime('now')),
      risk_score REAL NOT NULL,
      risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
      contributing_factors TEXT,
      trend TEXT NOT NULL CHECK (trend IN ('increasing', 'decreasing', 'stable'))
    );

    -- Agent alerts (threshold breaches, anomalies)
    CREATE TABLE IF NOT EXISTS agent_alerts (
      id TEXT PRIMARY KEY,
      agent_username TEXT NOT NULL,
      alert_type TEXT NOT NULL,
      severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      triggered_at TEXT NOT NULL DEFAULT (datetime('now')),
      acknowledged_at TEXT,
      acknowledged_by TEXT,
      resolved_at TEXT,
      metadata TEXT
    );

    -- Indexes for behavior tracking
    CREATE INDEX IF NOT EXISTS idx_agent_behavior_username ON agent_behavior(agent_username);
    CREATE INDEX IF NOT EXISTS idx_agent_behavior_recorded_at ON agent_behavior(recorded_at);
    CREATE INDEX IF NOT EXISTS idx_agent_risk_history_username ON agent_risk_history(agent_username);
    CREATE INDEX IF NOT EXISTS idx_agent_risk_history_recorded_at ON agent_risk_history(recorded_at);
    CREATE INDEX IF NOT EXISTS idx_agent_alerts_username ON agent_alerts(agent_username);
    CREATE INDEX IF NOT EXISTS idx_agent_alerts_triggered_at ON agent_alerts(triggered_at);
    CREATE INDEX IF NOT EXISTS idx_agent_alerts_severity ON agent_alerts(severity);
  `);
}

// ============================================================================
// Behavior Recording Functions
// ============================================================================

export interface AgentBehaviorInput {
  agentUsername: string;
  postCount: number;
  commentCount: number;
  upvotesReceived: number;
  downvotesReceived: number;
  threatSignals: number;
  avgSemanticRisk: number;
  manipulationScore: number;
  deceptionScore: number;
  coordinationScore: number;
  activityHours?: number[];
  metadata?: Record<string, unknown>;
}

/**
 * Record a behavior snapshot for an agent.
 */
export function recordAgentBehavior(input: AgentBehaviorInput): number {
  const database = getDatabase();
  initializeBehaviorTracking();

  const result = database.prepare(`
    INSERT INTO agent_behavior (
      agent_username, post_count, comment_count, upvotes_received, downvotes_received,
      threat_signals, avg_semantic_risk, manipulation_score, deception_score,
      coordination_score, activity_hours, metadata
    ) VALUES (
      @agentUsername, @postCount, @commentCount, @upvotesReceived, @downvotesReceived,
      @threatSignals, @avgSemanticRisk, @manipulationScore, @deceptionScore,
      @coordinationScore, @activityHours, @metadata
    )
  `).run({
    agentUsername: input.agentUsername,
    postCount: input.postCount,
    commentCount: input.commentCount,
    upvotesReceived: input.upvotesReceived,
    downvotesReceived: input.downvotesReceived,
    threatSignals: input.threatSignals,
    avgSemanticRisk: input.avgSemanticRisk,
    manipulationScore: input.manipulationScore,
    deceptionScore: input.deceptionScore,
    coordinationScore: input.coordinationScore,
    activityHours: input.activityHours ? JSON.stringify(input.activityHours) : null,
    metadata: input.metadata ? JSON.stringify(input.metadata) : null,
  });

  return result.lastInsertRowid as number;
}

/**
 * Get behavior history for an agent.
 */
export function getAgentBehaviorHistory(
  agentUsername: string,
  limit = 30
): DbAgentBehavior[] {
  const database = getDatabase();
  initializeBehaviorTracking();

  return database.prepare(`
    SELECT * FROM agent_behavior
    WHERE agent_username = @agentUsername
    ORDER BY recorded_at DESC
    LIMIT @limit
  `).all({ agentUsername, limit }) as DbAgentBehavior[];
}

/**
 * Record risk score history.
 */
export interface RiskHistoryInput {
  agentUsername: string;
  riskScore: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  contributingFactors?: Record<string, number>;
  trend: 'increasing' | 'decreasing' | 'stable';
}

export function recordRiskHistory(input: RiskHistoryInput): number {
  const database = getDatabase();
  initializeBehaviorTracking();

  const result = database.prepare(`
    INSERT INTO agent_risk_history (
      agent_username, risk_score, risk_level, contributing_factors, trend
    ) VALUES (
      @agentUsername, @riskScore, @riskLevel, @contributingFactors, @trend
    )
  `).run({
    agentUsername: input.agentUsername,
    riskScore: input.riskScore,
    riskLevel: input.riskLevel,
    contributingFactors: input.contributingFactors ? JSON.stringify(input.contributingFactors) : null,
    trend: input.trend,
  });

  return result.lastInsertRowid as number;
}

/**
 * Get risk history for an agent.
 */
export function getAgentRiskHistory(
  agentUsername: string,
  limit = 30
): DbAgentRiskHistory[] {
  const database = getDatabase();
  initializeBehaviorTracking();

  return database.prepare(`
    SELECT * FROM agent_risk_history
    WHERE agent_username = @agentUsername
    ORDER BY recorded_at DESC
    LIMIT @limit
  `).all({ agentUsername, limit }) as DbAgentRiskHistory[];
}

/**
 * Calculate risk trend based on recent history.
 */
export function calculateRiskTrend(agentUsername: string): 'increasing' | 'decreasing' | 'stable' {
  const history = getAgentRiskHistory(agentUsername, 10);
  
  if (history.length < 2) return 'stable';
  
  // Calculate average of first half vs second half
  const midpoint = Math.floor(history.length / 2);
  const recentAvg = history.slice(0, midpoint).reduce((sum, h) => sum + h.risk_score, 0) / midpoint;
  const olderAvg = history.slice(midpoint).reduce((sum, h) => sum + h.risk_score, 0) / (history.length - midpoint);
  
  const diff = recentAvg - olderAvg;
  if (diff > 0.1) return 'increasing';
  if (diff < -0.1) return 'decreasing';
  return 'stable';
}

// ============================================================================
// Alert Functions
// ============================================================================

export interface AlertInput {
  id: string;
  agentUsername: string;
  alertType: 'threshold_breach' | 'anomaly' | 'pattern_change' | 'coordination' | 'escalation';
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  metadata?: Record<string, unknown>;
}

/**
 * Create an agent alert.
 */
export function createAgentAlert(input: AlertInput): void {
  const database = getDatabase();
  initializeBehaviorTracking();

  database.prepare(`
    INSERT INTO agent_alerts (
      id, agent_username, alert_type, severity, title, description, metadata
    ) VALUES (
      @id, @agentUsername, @alertType, @severity, @title, @description, @metadata
    )
  `).run({
    id: input.id,
    agentUsername: input.agentUsername,
    alertType: input.alertType,
    severity: input.severity,
    title: input.title,
    description: input.description,
    metadata: input.metadata ? JSON.stringify(input.metadata) : null,
  });
}

/**
 * Get active alerts for an agent.
 */
export function getActiveAlerts(agentUsername?: string): DbAgentAlert[] {
  const database = getDatabase();
  initializeBehaviorTracking();

  if (agentUsername) {
    return database.prepare(`
      SELECT * FROM agent_alerts
      WHERE agent_username = @agentUsername AND resolved_at IS NULL
      ORDER BY triggered_at DESC
    `).all({ agentUsername }) as DbAgentAlert[];
  }

  return database.prepare(`
    SELECT * FROM agent_alerts
    WHERE resolved_at IS NULL
    ORDER BY triggered_at DESC
    LIMIT 100
  `).all() as DbAgentAlert[];
}

/**
 * Acknowledge an alert.
 */
export function acknowledgeAlert(alertId: string, acknowledgedBy: string): boolean {
  const database = getDatabase();
  initializeBehaviorTracking();

  const result = database.prepare(`
    UPDATE agent_alerts
    SET acknowledged_at = datetime('now'), acknowledged_by = @acknowledgedBy
    WHERE id = @alertId AND acknowledged_at IS NULL
  `).run({ alertId, acknowledgedBy });

  return result.changes > 0;
}

/**
 * Resolve an alert.
 */
export function resolveAlert(alertId: string): boolean {
  const database = getDatabase();
  initializeBehaviorTracking();

  const result = database.prepare(`
    UPDATE agent_alerts
    SET resolved_at = datetime('now')
    WHERE id = @alertId AND resolved_at IS NULL
  `).run({ alertId });

  return result.changes > 0;
}

// ============================================================================
// Behavior Analysis Functions
// ============================================================================

/**
 * Detect anomalies in agent behavior compared to historical baseline.
 */
export interface BehaviorAnomaly {
  field: string;
  currentValue: number;
  baselineValue: number;
  deviation: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export function detectBehaviorAnomalies(
  agentUsername: string,
  currentBehavior: AgentBehaviorInput
): BehaviorAnomaly[] {
  const history = getAgentBehaviorHistory(agentUsername, 30);
  const anomalies: BehaviorAnomaly[] = [];

  if (history.length < 5) {
    // Not enough history for meaningful comparison
    return anomalies;
  }

  // Calculate baseline averages and standard deviations
  const calculateStats = (values: number[]): { avg: number; stdDev: number } => {
    const avg = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((sum, v) => sum + Math.pow(v - avg, 2), 0) / values.length;
    return { avg, stdDev: Math.sqrt(variance) };
  };

  // Check various metrics for anomalies
  const fieldsToCheck: Array<{ field: keyof AgentBehaviorInput; dbField: keyof DbAgentBehavior }> = [
    { field: 'threatSignals', dbField: 'threat_signals' },
    { field: 'avgSemanticRisk', dbField: 'avg_semantic_risk' },
    { field: 'manipulationScore', dbField: 'manipulation_score' },
    { field: 'deceptionScore', dbField: 'deception_score' },
    { field: 'coordinationScore', dbField: 'coordination_score' },
  ];

  for (const { field, dbField } of fieldsToCheck) {
    const historicalValues = history.map(h => h[dbField] as number);
    const stats = calculateStats(historicalValues);
    const currentValue = currentBehavior[field] as number;
    
    // Calculate z-score (number of standard deviations from mean)
    const zScore = stats.stdDev > 0 
      ? (currentValue - stats.avg) / stats.stdDev 
      : 0;
    
    // Flag if more than 2 standard deviations above baseline
    if (zScore > 2) {
      let severity: BehaviorAnomaly['severity'] = 'low';
      if (zScore > 4) severity = 'critical';
      else if (zScore > 3) severity = 'high';
      else if (zScore > 2.5) severity = 'medium';
      
      anomalies.push({
        field,
        currentValue,
        baselineValue: Math.round(stats.avg * 100) / 100,
        deviation: Math.round(zScore * 100) / 100,
        severity,
      });
    }
  }

  return anomalies;
}

/**
 * Get agents with highest risk scores.
 */
export function getHighRiskAgents(limit = 20): Array<{
  agentUsername: string;
  latestRiskScore: number;
  riskLevel: string;
  trend: string;
  alertCount: number;
}> {
  const database = getDatabase();
  initializeBehaviorTracking();

  return database.prepare(`
    WITH latest_risk AS (
      SELECT 
        agent_username,
        risk_score,
        risk_level,
        trend,
        ROW_NUMBER() OVER (PARTITION BY agent_username ORDER BY recorded_at DESC) as rn
      FROM agent_risk_history
    ),
    alert_counts AS (
      SELECT agent_username, COUNT(*) as alert_count
      FROM agent_alerts
      WHERE resolved_at IS NULL
      GROUP BY agent_username
    )
    SELECT 
      lr.agent_username as agentUsername,
      lr.risk_score as latestRiskScore,
      lr.risk_level as riskLevel,
      lr.trend,
      COALESCE(ac.alert_count, 0) as alertCount
    FROM latest_risk lr
    LEFT JOIN alert_counts ac ON lr.agent_username = ac.agent_username
    WHERE lr.rn = 1
    ORDER BY lr.risk_score DESC
    LIMIT @limit
  `).all({ limit }) as Array<{
    agentUsername: string;
    latestRiskScore: number;
    riskLevel: string;
    trend: string;
    alertCount: number;
  }>;
}
