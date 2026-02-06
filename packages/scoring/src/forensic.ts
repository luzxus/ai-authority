/**
 * Forensic Agent
 * 
 * Performs attribution analysis, obfuscation reversal, and chain-of-custody tracking.
 * Traces malicious behavior back to source models and operators.
 */

import { BaseAgent, type AgentConfig, type AgentTask, type TaskResult } from '@ai-authority/agents';
import { generateSecureId, sha256 } from '@ai-authority/core';

/** Attribution target - entity being investigated */
export interface AttributionTarget {
  id: string;
  type: 'model' | 'agent' | 'operator' | 'deployment';
  identifier: string;
  metadata: Record<string, unknown>;
  firstSeen: number;
  lastSeen: number;
}

/** Evidence item for attribution */
export interface ForensicEvidence {
  id: string;
  type: 'behavioral' | 'textual' | 'structural' | 'temporal' | 'network';
  source: string;
  timestamp: number;
  data: unknown;
  hash: string;  // Integrity hash
  confidence: number;
  chainOfCustody: CustodyRecord[];
}

/** Chain of custody record */
export interface CustodyRecord {
  timestamp: number;
  agentId: string;
  action: 'collected' | 'analyzed' | 'transferred' | 'stored';
  location: string;
  signature: string;
}

/** Attribution result */
export interface AttributionResult {
  id: string;
  targetId: string;
  timestamp: number;
  confidence: number;
  
  // Attribution findings
  likelySource: AttributionCandidate[];
  obfuscationDetected: ObfuscationFinding[];
  behavioralFingerprint: string;
  
  // Evidence chain
  evidence: ForensicEvidence[];
  reasoning: ReasoningStep[];
}

/** Attribution candidate - potential source */
export interface AttributionCandidate {
  targetId: string;
  targetType: AttributionTarget['type'];
  identifier: string;
  probability: number;
  matchingFeatures: string[];
  confidence: number;
}

/** Detected obfuscation technique */
export interface ObfuscationFinding {
  technique: string;
  description: string;
  severity: 'low' | 'medium' | 'high';
  reversed: boolean;
  originalBehavior?: string;
}

/** Reasoning step in attribution */
export interface ReasoningStep {
  step: number;
  description: string;
  inputs: string[];
  conclusion: string;
  confidence: number;
}

/** Known obfuscation techniques */
export type ObfuscationTechnique = 
  | 'prompt_injection'
  | 'output_encoding'
  | 'behavioral_mimicry'
  | 'timing_manipulation'
  | 'identity_spoofing'
  | 'capability_hiding'
  | 'goal_obfuscation';

/**
 * Forensic Agent
 * 
 * Specializes in tracing malicious AI behavior back to its source.
 * Uses behavioral analysis, fingerprinting, and obfuscation detection.
 */
export class ForensicAgent extends BaseAgent {
  private targets: Map<string, AttributionTarget> = new Map();
  private evidence: Map<string, ForensicEvidence> = new Map();
  private attributions: Map<string, AttributionResult> = new Map();
  private knownFingerprints: Map<string, string> = new Map(); // fingerprint -> identifier

  constructor(config: AgentConfig) {
    super(config);
  }

  protected async onInitialize(): Promise<void> {
    // Subscribe to attribution requests
  }

  protected async onMessage(message: { type: string; payload: unknown }): Promise<void> {
    if (message.type === 'attribution') {
      // Handle attribution request
      const request = message.payload as { targetId: string };
      this.submitTask({
        type: 'attribute',
        priority: 'high',
        payload: { targetId: request.targetId },
        maxRetries: 2,
      });
    }
  }

  protected async processTask<T, R>(task: AgentTask<T>): Promise<TaskResult<R>> {
    const startTime = Date.now();

    try {
      switch (task.type) {
        case 'attribute': {
          const { targetId } = task.payload as { targetId: string };
          const result = await this.performAttribution(targetId);
          return {
            taskId: task.id,
            success: true,
            result: result as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        case 'collect_evidence': {
          const evidenceInput = task.payload as Omit<ForensicEvidence, 'id' | 'hash' | 'chainOfCustody'>;
          const result = await this.collectEvidence(evidenceInput);
          return {
            taskId: task.id,
            success: true,
            result: result as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        case 'detect_obfuscation': {
          const { behavior, context } = task.payload as { behavior: unknown; context: Record<string, unknown> };
          const result = await this.detectObfuscation(behavior, context);
          return {
            taskId: task.id,
            success: true,
            result: result as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        case 'fingerprint': {
          const { behavior } = task.payload as { behavior: unknown };
          const result = await this.generateFingerprint(behavior);
          return {
            taskId: task.id,
            success: true,
            result: result as R,
            duration: Date.now() - startTime,
            timestamp: Date.now(),
          };
        }

        case 'register_target': {
          const target = task.payload as Omit<AttributionTarget, 'id' | 'firstSeen' | 'lastSeen'>;
          const result = this.registerTarget(target);
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

  /** Perform full attribution analysis */
  async performAttribution(targetId: string): Promise<AttributionResult> {
    const target = this.targets.get(targetId);
    if (!target) {
      throw new Error(`Target not found: ${targetId}`);
    }

    // Gather evidence for target
    const targetEvidence = this.gatherEvidence(targetId);

    // Detect obfuscation in behavior
    const obfuscation = await this.detectObfuscation(
      targetEvidence.map(e => e.data),
      { targetId }
    );

    // Generate behavioral fingerprint
    const fingerprint = await this.generateFingerprint(targetEvidence);

    // Find matching candidates
    const candidates = this.findMatchingCandidates(fingerprint, targetEvidence);

    // Build reasoning chain
    const reasoning = this.buildReasoningChain(target, targetEvidence, obfuscation, candidates);

    // Calculate overall confidence
    const confidence = this.calculateAttributionConfidence(candidates, obfuscation, reasoning);

    const result: AttributionResult = {
      id: generateSecureId(),
      targetId,
      timestamp: Date.now(),
      confidence,
      likelySource: candidates,
      obfuscationDetected: obfuscation,
      behavioralFingerprint: fingerprint,
      evidence: targetEvidence,
      reasoning,
    };

    this.attributions.set(result.id, result);

    // Broadcast attribution result
    await this.sendMessage('broadcast', 'attribution', result);

    this.logAudit('attribution_completed', {
      attributionId: result.id,
      targetId,
      confidence,
      candidateCount: candidates.length,
      obfuscationCount: obfuscation.length,
    });

    return result;
  }

  /** Collect and secure evidence */
  async collectEvidence(
    input: Omit<ForensicEvidence, 'id' | 'hash' | 'chainOfCustody'>
  ): Promise<ForensicEvidence> {
    const evidence: ForensicEvidence = {
      ...input,
      id: generateSecureId(),
      hash: sha256(JSON.stringify(input.data)),
      chainOfCustody: [{
        timestamp: Date.now(),
        agentId: this.id,
        action: 'collected',
        location: 'forensic_agent',
        signature: '', // Would be signed in production
      }],
    };

    this.evidence.set(evidence.id, evidence);

    this.logAudit('evidence_collected', {
      evidenceId: evidence.id,
      type: evidence.type,
      source: evidence.source,
    });

    return evidence;
  }

  /** Detect obfuscation techniques */
  async detectObfuscation(
    behavior: unknown,
    context: Record<string, unknown>
  ): Promise<ObfuscationFinding[]> {
    const findings: ObfuscationFinding[] = [];
    const behaviorStr = JSON.stringify(behavior);

    // Check for prompt injection patterns
    if (this.detectPromptInjection(behaviorStr)) {
      findings.push({
        technique: 'prompt_injection',
        description: 'Detected embedded prompt injection patterns',
        severity: 'high',
        reversed: false,
      });
    }

    // Check for output encoding (base64, etc.)
    const encodingResult = this.detectOutputEncoding(behaviorStr);
    if (encodingResult.detected) {
      const finding: ObfuscationFinding = {
        technique: 'output_encoding',
        description: `Detected ${encodingResult.encoding} encoding`,
        severity: 'medium',
        reversed: true,
      };
      if (encodingResult.decoded) {
        finding.originalBehavior = encodingResult.decoded;
      }
      findings.push(finding);
    }

    // Check for behavioral mimicry
    if (this.detectBehavioralMimicry(behavior, context)) {
      findings.push({
        technique: 'behavioral_mimicry',
        description: 'Behavior appears to mimic another known model',
        severity: 'medium',
        reversed: false,
      });
    }

    // Check for timing manipulation
    if (this.detectTimingManipulation(behavior, context)) {
      findings.push({
        technique: 'timing_manipulation',
        description: 'Suspicious timing patterns detected',
        severity: 'low',
        reversed: false,
      });
    }

    // Check for identity spoofing
    if (this.detectIdentitySpoofing(behavior, context)) {
      findings.push({
        technique: 'identity_spoofing',
        description: 'Identity claims inconsistent with behavior',
        severity: 'high',
        reversed: false,
      });
    }

    return findings;
  }

  /** Generate behavioral fingerprint */
  async generateFingerprint(behavior: unknown): Promise<string> {
    // Extract features from behavior
    const features = this.extractBehavioralFeatures(behavior);
    
    // Create deterministic fingerprint
    const fingerprint = sha256(JSON.stringify(features));
    
    return fingerprint;
  }

  /** Register a target for tracking */
  registerTarget(input: Omit<AttributionTarget, 'id' | 'firstSeen' | 'lastSeen'>): AttributionTarget {
    const now = Date.now();
    const target: AttributionTarget = {
      ...input,
      id: generateSecureId(),
      firstSeen: now,
      lastSeen: now,
    };

    this.targets.set(target.id, target);

    this.logAudit('target_registered', {
      targetId: target.id,
      type: target.type,
      identifier: target.identifier,
    });

    return target;
  }

  // ============================================================================
  // Detection Helpers
  // ============================================================================

  private detectPromptInjection(text: string): boolean {
    const patterns = [
      /ignore\s+(previous|above)\s+instructions?/i,
      /disregard\s+(all|previous)/i,
      /you\s+are\s+now\s+in\s+developer\s+mode/i,
      /system\s*:\s*you\s+are/i,
      /###\s*(system|instruction|prompt)/i,
    ];

    return patterns.some(pattern => pattern.test(text));
  }

  private detectOutputEncoding(text: string): { detected: boolean; encoding?: string; decoded?: string } {
    // Check for base64
    const base64Pattern = /^[A-Za-z0-9+/]+={0,2}$/;
    if (text.length > 20 && base64Pattern.test(text.replace(/\s/g, ''))) {
      try {
        const decoded = Buffer.from(text, 'base64').toString('utf8');
        if (decoded.length > 0 && !/[\x00-\x08\x0E-\x1F]/.test(decoded)) {
          return { detected: true, encoding: 'base64', decoded };
        }
      } catch {
        // Not valid base64
      }
    }

    // Check for hex encoding
    const hexPattern = /^[0-9a-fA-F]+$/;
    if (text.length > 20 && text.length % 2 === 0 && hexPattern.test(text)) {
      try {
        const decoded = Buffer.from(text, 'hex').toString('utf8');
        if (decoded.length > 0 && !/[\x00-\x08\x0E-\x1F]/.test(decoded)) {
          return { detected: true, encoding: 'hex', decoded };
        }
      } catch {
        // Not valid hex
      }
    }

    return { detected: false };
  }

  private detectBehavioralMimicry(behavior: unknown, _context: Record<string, unknown>): boolean {
    // Check if behavior matches known model signatures but claims different identity
    const fingerprint = sha256(JSON.stringify(behavior));
    const knownIdentifier = this.knownFingerprints.get(fingerprint);
    
    return knownIdentifier !== undefined;
  }

  private detectTimingManipulation(_behavior: unknown, context: Record<string, unknown>): boolean {
    // Check for suspicious timing patterns
    const timestamps = context['timestamps'] as number[] | undefined;
    if (!timestamps || timestamps.length < 3) return false;

    // Check for unnaturally regular intervals
    const intervals = [];
    for (let i = 1; i < timestamps.length; i++) {
      intervals.push(timestamps[i]! - timestamps[i - 1]!);
    }

    const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((sum, i) => sum + Math.pow(i - avgInterval, 2), 0) / intervals.length;
    
    // Very low variance suggests artificial timing
    return variance < avgInterval * 0.01;
  }

  private detectIdentitySpoofing(behavior: unknown, context: Record<string, unknown>): boolean {
    const claimedIdentity = context['claimedIdentity'] as string | undefined;
    if (!claimedIdentity) return false;

    // Check if behavioral fingerprint matches claimed identity
    const fingerprint = sha256(JSON.stringify(behavior));
    const expectedIdentifier = this.knownFingerprints.get(fingerprint);

    return expectedIdentifier !== undefined && expectedIdentifier !== claimedIdentity;
  }

  // ============================================================================
  // Attribution Helpers
  // ============================================================================

  private gatherEvidence(targetId: string): ForensicEvidence[] {
    return Array.from(this.evidence.values()).filter(e => 
      e.source === targetId || 
      (e.data as Record<string, unknown>)?.targetId === targetId
    );
  }

  private extractBehavioralFeatures(behavior: unknown): Record<string, unknown> {
    const behaviorStr = JSON.stringify(behavior);
    
    return {
      length: behaviorStr.length,
      wordCount: behaviorStr.split(/\s+/).length,
      uniqueTokens: new Set(behaviorStr.toLowerCase().split(/\s+/)).size,
      avgWordLength: behaviorStr.split(/\s+/).reduce((sum, w) => sum + w.length, 0) / 
                     Math.max(1, behaviorStr.split(/\s+/).length),
      punctuationRatio: (behaviorStr.match(/[.,!?;:]/g) || []).length / behaviorStr.length,
      uppercaseRatio: (behaviorStr.match(/[A-Z]/g) || []).length / behaviorStr.length,
      digitRatio: (behaviorStr.match(/\d/g) || []).length / behaviorStr.length,
      specialCharRatio: (behaviorStr.match(/[^a-zA-Z0-9\s]/g) || []).length / behaviorStr.length,
    };
  }

  private findMatchingCandidates(
    fingerprint: string,
    evidence: ForensicEvidence[]
  ): AttributionCandidate[] {
    const candidates: AttributionCandidate[] = [];

    // Check against known fingerprints
    const knownMatch = this.knownFingerprints.get(fingerprint);
    if (knownMatch) {
      candidates.push({
        targetId: knownMatch,
        targetType: 'model',
        identifier: knownMatch,
        probability: 0.9,
        matchingFeatures: ['behavioral_fingerprint'],
        confidence: 0.85,
      });
    }

    // Analyze evidence for attribution clues
    for (const e of evidence) {
      if (e.type === 'network' && e.confidence > 0.7) {
        const networkData = e.data as { sourceIp?: string; sourceModel?: string };
        if (networkData.sourceModel) {
          candidates.push({
            targetId: generateSecureId(),
            targetType: 'model',
            identifier: networkData.sourceModel,
            probability: e.confidence * 0.8,
            matchingFeatures: ['network_trace'],
            confidence: e.confidence,
          });
        }
      }
    }

    // Sort by probability
    return candidates.sort((a, b) => b.probability - a.probability);
  }

  private buildReasoningChain(
    target: AttributionTarget,
    evidence: ForensicEvidence[],
    obfuscation: ObfuscationFinding[],
    candidates: AttributionCandidate[]
  ): ReasoningStep[] {
    const steps: ReasoningStep[] = [];

    steps.push({
      step: 1,
      description: 'Identified attribution target',
      inputs: [target.identifier, target.type],
      conclusion: `Target ${target.identifier} of type ${target.type} identified for analysis`,
      confidence: 1.0,
    });

    steps.push({
      step: 2,
      description: 'Gathered forensic evidence',
      inputs: evidence.map(e => e.id),
      conclusion: `Collected ${evidence.length} evidence items across ${new Set(evidence.map(e => e.type)).size} categories`,
      confidence: evidence.length > 0 ? 0.9 : 0.3,
    });

    if (obfuscation.length > 0) {
      steps.push({
        step: 3,
        description: 'Detected obfuscation techniques',
        inputs: obfuscation.map(o => o.technique),
        conclusion: `Found ${obfuscation.length} obfuscation techniques: ${obfuscation.map(o => o.technique).join(', ')}`,
        confidence: 0.8,
      });
    }

    steps.push({
      step: obfuscation.length > 0 ? 4 : 3,
      description: 'Identified attribution candidates',
      inputs: candidates.map(c => c.identifier),
      conclusion: candidates.length > 0 
        ? `Most likely source: ${candidates[0]?.identifier} (${(candidates[0]?.probability ?? 0 * 100).toFixed(1)}% probability)`
        : 'No matching candidates found',
      confidence: candidates.length > 0 ? candidates[0]!.confidence : 0.2,
    });

    return steps;
  }

  private calculateAttributionConfidence(
    candidates: AttributionCandidate[],
    obfuscation: ObfuscationFinding[],
    reasoning: ReasoningStep[]
  ): number {
    if (candidates.length === 0) return 0.1;

    const topCandidate = candidates[0]!;
    let confidence = topCandidate.confidence;

    // Reduce confidence if obfuscation detected and not reversed
    const unreversedObfuscation = obfuscation.filter(o => !o.reversed);
    confidence *= Math.pow(0.9, unreversedObfuscation.length);

    // Factor in reasoning chain confidence
    const avgReasoningConfidence = reasoning.reduce((sum, r) => sum + r.confidence, 0) / reasoning.length;
    confidence = (confidence + avgReasoningConfidence) / 2;

    return Math.max(0.1, Math.min(1.0, confidence));
  }

  // ============================================================================
  // Query Methods
  // ============================================================================

  /** Get attribution result by ID */
  getAttribution(id: string): AttributionResult | undefined {
    return this.attributions.get(id);
  }

  /** Get all attributions for a target */
  getAttributionsForTarget(targetId: string): AttributionResult[] {
    return Array.from(this.attributions.values()).filter(a => a.targetId === targetId);
  }

  /** Register known fingerprint */
  registerFingerprint(fingerprint: string, identifier: string): void {
    this.knownFingerprints.set(fingerprint, identifier);
  }

  /** Get evidence by ID */
  getEvidence(id: string): ForensicEvidence | undefined {
    return this.evidence.get(id);
  }
}
