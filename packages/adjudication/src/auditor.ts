/**
 * Auditor Agent
 * 
 * Performs compliance checks, verifies actions, and maintains audit trails.
 * Ensures all system operations adhere to policies and regulations.
 */

import { BaseAgent, type AgentConfig, type AgentTask, type TaskResult } from '@ai-authority/agents';
import { generateSecureId, sha256, verify as verifySignature } from '@ai-authority/core';

/** Compliance policy */
export interface CompliancePolicy {
  id: string;
  name: string;
  version: string;
  rules: ComplianceRule[];
  effectiveFrom: number;
  effectiveTo?: number;
  severity: 'advisory' | 'mandatory' | 'critical';
}

/** Compliance rule */
export interface ComplianceRule {
  id: string;
  name: string;
  description: string;
  condition: RuleCondition;
  action: 'allow' | 'deny' | 'flag' | 'require_approval';
  metadata: Record<string, unknown>;
}

/** Rule condition */
export interface RuleCondition {
  type: 'threshold' | 'pattern' | 'temporal' | 'composite';
  field?: string;
  operator?: 'gt' | 'lt' | 'eq' | 'contains' | 'matches';
  value?: unknown;
  children?: RuleCondition[];
  combinator?: 'and' | 'or' | 'not';
}

/** Action record to audit */
export interface AuditableAction {
  id: string;
  type: string;
  agentId: string;
  timestamp: number;
  payload: Record<string, unknown>;
  signature: string;
  result?: ActionResult;
}

/** Action result */
export interface ActionResult {
  success: boolean;
  outcome: unknown;
  duration: number;
  error?: string;
}

/** Audit record */
export interface AuditRecord {
  id: string;
  actionId: string;
  timestamp: number;
  auditorId: string;
  checks: ComplianceCheck[];
  verdict: AuditVerdict;
  hash: string;
  previousHash: string;  // Chain link
  signature: string;
}

/** Compliance check result */
export interface ComplianceCheck {
  policyId: string;
  ruleId: string;
  passed: boolean;
  details: string;
  timestamp: number;
}

/** Audit verdict */
export interface AuditVerdict {
  status: 'compliant' | 'non_compliant' | 'requires_review' | 'exempted';
  score: number;  // 0-1 compliance score
  violations: Violation[];
  recommendations: string[];
}

/** Compliance violation */
export interface Violation {
  policyId: string;
  ruleId: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  remediation: string;
  evidence: unknown;
}

/** Audit report */
export interface AuditReport {
  id: string;
  generatedAt: number;
  period: { start: number; end: number };
  summary: AuditSummary;
  records: AuditRecord[];
  violations: Violation[];
  complianceScore: number;
  recommendations: string[];
}

/** Audit summary */
export interface AuditSummary {
  totalActions: number;
  audited: number;
  compliant: number;
  nonCompliant: number;
  requiresReview: number;
  exempted: number;
}

/** Auditor configuration */
export interface AuditorConfig {
  auditBatchSize: number;
  retentionDays: number;
  autoAuditEnabled: boolean;
  requireSignatureVerification: boolean;
}

const defaultAuditorConfig: AuditorConfig = {
  auditBatchSize: 100,
  retentionDays: 365,
  autoAuditEnabled: true,
  requireSignatureVerification: true,
};

/**
 * Auditor Agent
 * 
 * Maintains compliance and audit trails for the AI Authority system.
 * Creates immutable, chained audit records for all significant actions.
 */
export class AuditorAgent extends BaseAgent {
  private readonly auditorConfig: AuditorConfig;
  private policies: Map<string, CompliancePolicy> = new Map();
  private actionQueue: AuditableAction[] = [];
  private auditRecords: AuditRecord[] = [];
  private lastHash = '0'.repeat(64); // Genesis hash

  constructor(config: AgentConfig, auditorConfig: Partial<AuditorConfig> = {}) {
    super(config);
    this.auditorConfig = { ...defaultAuditorConfig, ...auditorConfig };
  }

  protected async onInitialize(): Promise<void> {
    // Load default policies
    this.loadDefaultPolicies();
  }

  protected async onMessage(message: { type: string; payload: unknown }): Promise<void> {
    if (message.type === 'audit') {
      // Queue action for auditing
      const action = message.payload as AuditableAction;
      this.queueAction(action);
    }
  }

  protected async processTask<T, R>(task: AgentTask<T>): Promise<TaskResult<R>> {
    const startTime = Date.now();

    try {
      switch (task.type) {
        case 'audit_action': {
          const action = task.payload as AuditableAction;
          const result = await this.auditAction(action);
          return {
            taskId: task.id,
            success: true,
            result: result as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        case 'verify_action': {
          const action = task.payload as AuditableAction;
          const result = await this.verifyAction(action);
          return {
            taskId: task.id,
            success: true,
            result: result as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        case 'check_compliance': {
          const { action, policyId } = task.payload as { action: AuditableAction; policyId?: string };
          const result = await this.checkCompliance(action, policyId);
          return {
            taskId: task.id,
            success: true,
            result: result as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        case 'register_policy': {
          const policy = task.payload as CompliancePolicy;
          this.registerPolicy(policy);
          return {
            taskId: task.id,
            success: true,
            result: { registered: true, policyId: policy.id } as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        case 'generate_report': {
          const { startTime: reportStart, endTime: reportEnd } = task.payload as { startTime?: number; endTime?: number };
          const result = await this.generateReport(reportStart, reportEnd);
          return {
            taskId: task.id,
            success: true,
            result: result as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        case 'verify_chain': {
          const result = await this.verifyAuditChain();
          return {
            taskId: task.id,
            success: true,
            result: result as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        case 'get_audit_record': {
          const { actionId } = task.payload as { actionId: string };
          const result = this.getAuditRecord(actionId);
          return {
            taskId: task.id,
            success: true,
            result: result as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        default:
          return {
            taskId: task.id,
            success: false,
            error: `Unknown task type: ${task.type}`,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
      }
    } catch (error) {
      return {
        taskId: task.id,
        success: false,
        error: String(error),
        duration: Date.now() - startTime,
        timestamp: Date.now(),
      };
    }
  }

  /** Audit an action and create audit record */
  async auditAction(action: AuditableAction): Promise<AuditRecord> {
    // Verify action signature if required
    if (this.auditorConfig.requireSignatureVerification) {
      const verification = await this.verifyAction(action);
      if (!verification.valid) {
        throw new Error(`Action signature verification failed: ${verification.reason}`);
      }
    }

    // Run compliance checks
    const checks = await this.runComplianceChecks(action);

    // Determine verdict
    const verdict = this.determineVerdict(checks);

    // Create audit record
    const record = this.createAuditRecord(action, checks, verdict);

    // Store record
    this.auditRecords.push(record);
    this.lastHash = record.hash;

    // Broadcast audit result if non-compliant
    if (verdict.status === 'non_compliant') {
      await this.sendMessage('broadcast', 'audit', {
        type: 'compliance_violation',
        record,
      });
    }

    this.logAudit('action_audited', {
      actionId: action.id,
      recordId: record.id,
      verdict: verdict.status,
      complianceScore: verdict.score,
    });

    return record;
  }

  /** Verify action signature and integrity */
  async verifyAction(action: AuditableAction): Promise<{ valid: boolean; reason?: string }> {
    // Verify signature
    const actionCopy = { ...action, signature: '' };
    const dataToVerify = JSON.stringify(actionCopy);

    try {
      const isValid = verifySignature(dataToVerify, action.signature, action.agentId);
      if (!isValid) {
        return { valid: false, reason: 'Invalid signature' };
      }
    } catch {
      // If verification fails due to invalid key format, check hash instead
      const expectedHash = sha256(JSON.stringify({ ...action, signature: '' }));
      if (action.signature !== expectedHash) {
        return { valid: false, reason: 'Signature verification unavailable, hash mismatch' };
      }
    }

    // Verify timestamp is reasonable
    const now = Date.now();
    if (action.timestamp > now + 60000) {
      return { valid: false, reason: 'Timestamp is in the future' };
    }

    if (action.timestamp < now - 86400000 * 30) {
      return { valid: false, reason: 'Timestamp is too old (>30 days)' };
    }

    return { valid: true };
  }

  /** Check compliance against policies */
  async checkCompliance(action: AuditableAction, policyId?: string): Promise<ComplianceCheck[]> {
    const checks: ComplianceCheck[] = [];
    const now = Date.now();

    // Get applicable policies
    const policies = policyId 
      ? [this.policies.get(policyId)].filter(Boolean) as CompliancePolicy[]
      : this.getActivePolicies(now);

    for (const policy of policies) {
      for (const rule of policy.rules) {
        const passed = this.evaluateRule(rule, action);
        
        checks.push({
          policyId: policy.id,
          ruleId: rule.id,
          passed,
          details: passed 
            ? `Rule "${rule.name}" passed` 
            : `Rule "${rule.name}" failed: ${rule.description}`,
          timestamp: now,
        });
      }
    }

    return checks;
  }

  /** Register a compliance policy */
  registerPolicy(policy: CompliancePolicy): void {
    this.policies.set(policy.id, policy);

    this.logAudit('policy_registered', {
      policyId: policy.id,
      name: policy.name,
      ruleCount: policy.rules.length,
    });
  }

  /** Generate audit report */
  async generateReport(startTime?: number, endTime?: number): Promise<AuditReport> {
    const now = Date.now();
    const start = startTime ?? now - 86400000 * 7; // Default: last 7 days
    const end = endTime ?? now;

    // Filter records in time range
    const records = this.auditRecords.filter(
      r => r.timestamp >= start && r.timestamp <= end
    );

    // Calculate summary
    const summary = this.calculateSummary(records);

    // Collect violations
    const violations = records.flatMap(r => r.verdict.violations);

    // Calculate overall compliance score
    const complianceScore = summary.audited > 0
      ? summary.compliant / summary.audited
      : 1;

    // Generate recommendations
    const recommendations = this.generateRecommendations(violations, complianceScore);

    const report: AuditReport = {
      id: generateSecureId(),
      generatedAt: now,
      period: { start, end },
      summary,
      records,
      violations,
      complianceScore,
      recommendations,
    };

    this.logAudit('report_generated', {
      reportId: report.id,
      period: report.period,
      complianceScore,
    });

    return report;
  }

  /** Verify audit chain integrity */
  async verifyAuditChain(): Promise<{ valid: boolean; errors: string[] }> {
    const errors: string[] = [];

    if (this.auditRecords.length === 0) {
      return { valid: true, errors: [] };
    }

    // Check genesis record
    const genesis = this.auditRecords[0]!;
    if (genesis.previousHash !== '0'.repeat(64)) {
      errors.push('Genesis record has invalid previous hash');
    }

    // Verify chain
    for (let i = 0; i < this.auditRecords.length; i++) {
      const record = this.auditRecords[i]!;
      
      // Verify hash
      const expectedHash = this.calculateRecordHash(record);
      if (record.hash !== expectedHash) {
        errors.push(`Record ${record.id} has invalid hash`);
      }

      // Verify chain link
      if (i > 0) {
        const prevRecord = this.auditRecords[i - 1]!;
        if (record.previousHash !== prevRecord.hash) {
          errors.push(`Record ${record.id} has broken chain link`);
        }
      }

      // Note: In production, would verify signature against auditor's public key
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  // ============================================================================
  // Private Helpers
  // ============================================================================

  private loadDefaultPolicies(): void {
    // Intervention policy
    this.registerPolicy({
      id: 'policy-intervention-001',
      name: 'Intervention Policy',
      version: '1.0.0',
      effectiveFrom: Date.now(),
      severity: 'mandatory',
      rules: [
        {
          id: 'rule-001',
          name: 'Tier 1 intervention limit',
          description: 'Tier 1 interventions require single agent approval',
          condition: {
            type: 'composite',
            combinator: 'and',
            children: [
              { type: 'pattern', field: 'type', operator: 'contains', value: 'intervention' },
              { type: 'threshold', field: 'payload.tier', operator: 'eq', value: 1 },
            ],
          },
          action: 'allow',
          metadata: { tier: 1 },
        },
        {
          id: 'rule-002',
          name: 'Tier 3+ intervention consensus',
          description: 'Tier 3+ interventions require Byzantine consensus',
          condition: {
            type: 'composite',
            combinator: 'and',
            children: [
              { type: 'pattern', field: 'type', operator: 'contains', value: 'intervention' },
              { type: 'threshold', field: 'payload.tier', operator: 'gt', value: 2 },
              { type: 'threshold', field: 'payload.approvals', operator: 'lt', value: 3 },
            ],
          },
          action: 'deny',
          metadata: { tier: 3 },
        },
      ],
    });

    // Data access policy
    this.registerPolicy({
      id: 'policy-data-001',
      name: 'Data Access Policy',
      version: '1.0.0',
      effectiveFrom: Date.now(),
      severity: 'critical',
      rules: [
        {
          id: 'rule-010',
          name: 'No raw user data without warrant',
          description: 'Raw user data collection requires warrant-equivalent authorization',
          condition: {
            type: 'composite',
            combinator: 'and',
            children: [
              { type: 'pattern', field: 'type', operator: 'contains', value: 'data_access' },
              { type: 'pattern', field: 'payload.dataType', operator: 'eq', value: 'user_data' },
              { type: 'pattern', field: 'payload.hasWarrant', operator: 'eq', value: false },
            ],
          },
          action: 'deny',
          metadata: { category: 'privacy' },
        },
      ],
    });

    // Knowledge update policy
    this.registerPolicy({
      id: 'policy-knowledge-001',
      name: 'Knowledge Update Policy',
      version: '1.0.0',
      effectiveFrom: Date.now(),
      severity: 'mandatory',
      rules: [
        {
          id: 'rule-020',
          name: 'Knowledge updates require adversarial validation',
          description: 'All knowledge updates must pass adversarial validation',
          condition: {
            type: 'composite',
            combinator: 'and',
            children: [
              { type: 'pattern', field: 'type', operator: 'eq', value: 'knowledge_update' },
              { type: 'pattern', field: 'payload.adversarialValidated', operator: 'eq', value: false },
            ],
          },
          action: 'flag',
          metadata: { category: 'security' },
        },
      ],
    });
  }

  private getActivePolicies(timestamp: number): CompliancePolicy[] {
    return Array.from(this.policies.values()).filter(p => 
      p.effectiveFrom <= timestamp && 
      (!p.effectiveTo || p.effectiveTo > timestamp)
    );
  }

  private evaluateRule(rule: ComplianceRule, action: AuditableAction): boolean {
    const result = this.evaluateCondition(rule.condition, action);
    
    // If condition matches, check if action is allowed
    if (result) {
      return rule.action === 'allow';
    }
    
    // Condition doesn't match - rule doesn't apply
    return true;
  }

  private evaluateCondition(condition: RuleCondition, action: AuditableAction): boolean {
    switch (condition.type) {
      case 'threshold':
        return this.evaluateThreshold(condition, action);
      case 'pattern':
        return this.evaluatePattern(condition, action);
      case 'temporal':
        return this.evaluateTemporal(condition, action);
      case 'composite':
        return this.evaluateComposite(condition, action);
      default:
        return false;
    }
  }

  private evaluateThreshold(condition: RuleCondition, action: AuditableAction): boolean {
    const value = this.getFieldValue(action, condition.field ?? '');
    const threshold = condition.value as number;

    switch (condition.operator) {
      case 'gt': return (value as number) > threshold;
      case 'lt': return (value as number) < threshold;
      case 'eq': return value === threshold;
      default: return false;
    }
  }

  private evaluatePattern(condition: RuleCondition, action: AuditableAction): boolean {
    const value = this.getFieldValue(action, condition.field ?? '');
    const pattern = condition.value;

    switch (condition.operator) {
      case 'eq': return value === pattern;
      case 'contains': return String(value).includes(String(pattern));
      case 'matches': return new RegExp(String(pattern)).test(String(value));
      default: return false;
    }
  }

  private evaluateTemporal(condition: RuleCondition, action: AuditableAction): boolean {
    const timestamp = action.timestamp;
    const value = condition.value as number;

    switch (condition.operator) {
      case 'gt': return timestamp > value;
      case 'lt': return timestamp < value;
      default: return false;
    }
  }

  private evaluateComposite(condition: RuleCondition, action: AuditableAction): boolean {
    const children = condition.children ?? [];
    
    switch (condition.combinator) {
      case 'and':
        return children.every(c => this.evaluateCondition(c, action));
      case 'or':
        return children.some(c => this.evaluateCondition(c, action));
      case 'not':
        return children.length > 0 && !this.evaluateCondition(children[0]!, action);
      default:
        return false;
    }
  }

  private getFieldValue(action: AuditableAction, field: string): unknown {
    const parts = field.split('.');
    let value: unknown = action;

    for (const part of parts) {
      if (value && typeof value === 'object') {
        value = (value as Record<string, unknown>)[part];
      } else {
        return undefined;
      }
    }

    return value;
  }

  private async runComplianceChecks(action: AuditableAction): Promise<ComplianceCheck[]> {
    return this.checkCompliance(action);
  }

  private determineVerdict(checks: ComplianceCheck[]): AuditVerdict {
    const violations: Violation[] = [];
    let totalScore = 0;
    let checkCount = 0;

    for (const check of checks) {
      checkCount++;
      if (check.passed) {
        totalScore += 1;
      } else {
        const policy = this.policies.get(check.policyId);
        const rule = policy?.rules.find(r => r.id === check.ruleId);

        violations.push({
          policyId: check.policyId,
          ruleId: check.ruleId,
          severity: this.mapPolicySeverity(policy?.severity),
          description: check.details,
          remediation: rule ? `Ensure ${rule.description}` : 'Review action against policy',
          evidence: check,
        });
      }
    }

    const score = checkCount > 0 ? totalScore / checkCount : 1;
    const hasViolations = violations.length > 0;
    const hasCritical = violations.some(v => v.severity === 'critical');

    let status: AuditVerdict['status'];
    if (hasCritical) {
      status = 'non_compliant';
    } else if (hasViolations) {
      status = 'requires_review';
    } else {
      status = 'compliant';
    }

    return {
      status,
      score,
      violations,
      recommendations: this.generateVerdictRecommendations(violations),
    };
  }

  private mapPolicySeverity(severity?: CompliancePolicy['severity']): Violation['severity'] {
    switch (severity) {
      case 'critical': return 'critical';
      case 'mandatory': return 'high';
      case 'advisory': return 'low';
      default: return 'medium';
    }
  }

  private generateVerdictRecommendations(violations: Violation[]): string[] {
    const recs: string[] = [];

    for (const v of violations) {
      recs.push(v.remediation);
    }

    return [...new Set(recs)];
  }

  private createAuditRecord(
    action: AuditableAction,
    checks: ComplianceCheck[],
    verdict: AuditVerdict
  ): AuditRecord {
    const record: AuditRecord = {
      id: generateSecureId(),
      actionId: action.id,
      timestamp: Date.now(),
      auditorId: this.id,
      checks,
      verdict,
      hash: '',
      previousHash: this.lastHash,
      signature: '',
    };

    // Calculate hash
    record.hash = this.calculateRecordHash(record);

    // Sign record (in production, would use actual signing)
    record.signature = sha256(record.hash + this.id);

    return record;
  }

  private calculateRecordHash(record: AuditRecord): string {
    const data = {
      actionId: record.actionId,
      timestamp: record.timestamp,
      auditorId: record.auditorId,
      checks: record.checks,
      verdict: record.verdict,
      previousHash: record.previousHash,
    };

    return sha256(JSON.stringify(data));
  }

  private calculateSummary(records: AuditRecord[]): AuditSummary {
    const summary: AuditSummary = {
      totalActions: records.length,
      audited: records.length,
      compliant: 0,
      nonCompliant: 0,
      requiresReview: 0,
      exempted: 0,
    };

    for (const r of records) {
      switch (r.verdict.status) {
        case 'compliant': summary.compliant++; break;
        case 'non_compliant': summary.nonCompliant++; break;
        case 'requires_review': summary.requiresReview++; break;
        case 'exempted': summary.exempted++; break;
      }
    }

    return summary;
  }

  private generateRecommendations(violations: Violation[], complianceScore: number): string[] {
    const recommendations: string[] = [];

    if (complianceScore < 0.9) {
      recommendations.push('Review and update compliance training for agents');
    }

    if (complianceScore < 0.7) {
      recommendations.push('Consider pausing automated actions pending investigation');
    }

    // Group violations by type
    const violationsByPolicy = new Map<string, Violation[]>();
    for (const v of violations) {
      const existing = violationsByPolicy.get(v.policyId) ?? [];
      existing.push(v);
      violationsByPolicy.set(v.policyId, existing);
    }

    for (const [policyId, policyViolations] of violationsByPolicy) {
      if (policyViolations.length > 5) {
        const policy = this.policies.get(policyId);
        recommendations.push(`High violation rate for policy "${policy?.name ?? policyId}": review policy rules or agent behavior`);
      }
    }

    return [...new Set(recommendations)];
  }

  private queueAction(action: AuditableAction): void {
    this.actionQueue.push(action);

    if (this.auditorConfig.autoAuditEnabled && this.actionQueue.length >= this.auditorConfig.auditBatchSize) {
      this.processActionQueue();
    }
  }

  private async processActionQueue(): Promise<void> {
    const batch = this.actionQueue.splice(0, this.auditorConfig.auditBatchSize);
    
    for (const action of batch) {
      try {
        await this.auditAction(action);
      } catch (error) {
        this.logAudit('audit_failed', {
          actionId: action.id,
          error: String(error),
        });
      }
    }
  }

  // ============================================================================
  // Query Methods
  // ============================================================================

  /** Get audit record by action ID */
  getAuditRecord(actionId: string): AuditRecord | undefined {
    return this.auditRecords.find(r => r.actionId === actionId);
  }

  /** Get all audit records */
  getAuditRecords(): AuditRecord[] {
    return [...this.auditRecords];
  }

  /** Get policy by ID */
  getPolicy(policyId: string): CompliancePolicy | undefined {
    return this.policies.get(policyId);
  }

  /** Get all policies */
  getPolicies(): CompliancePolicy[] {
    return Array.from(this.policies.values());
  }

  /** Get chain length */
  getChainLength(): number {
    return this.auditRecords.length;
  }

  /** Get last hash in chain */
  getLastHash(): string {
    return this.lastHash;
  }
}
