/**
 * OpenTelemetry Tracing Configuration
 *
 * Provides distributed tracing for all AI Authority operations.
 * Per blueprint: "comprehensive audit logging via OpenTelemetry"
 */

import { trace, context, SpanKind, SpanStatusCode } from '@opentelemetry/api';
import type { Span, Tracer, Context, SpanOptions, Attributes } from '@opentelemetry/api';

// ============================================================================
// Tracer Configuration
// ============================================================================

const TRACER_NAME = 'ai-authority';
const TRACER_VERSION = '0.1.0';

/**
 * Get the AI Authority tracer.
 */
export function getTracer(): Tracer {
  return trace.getTracer(TRACER_NAME, TRACER_VERSION);
}

// ============================================================================
// Span Helpers
// ============================================================================

export interface SpanConfig {
  name: string;
  kind?: SpanKind;
  attributes?: Attributes;
  parentContext?: Context;
}

/**
 * Create and start a new span.
 */
export function startSpan(config: SpanConfig): Span {
  const tracer = getTracer();
  const options: SpanOptions = {
    kind: config.kind ?? SpanKind.INTERNAL,
    ...(config.attributes !== undefined && { attributes: config.attributes }),
  };

  const ctx = config.parentContext ?? context.active();
  return tracer.startSpan(config.name, options, ctx);
}

/**
 * Execute a function within a span context.
 */
export async function withSpan<T>(
  config: SpanConfig,
  fn: (span: Span) => Promise<T>
): Promise<T> {
  const span = startSpan(config);

  try {
    const result = await context.with(trace.setSpan(context.active(), span), () => fn(span));
    span.setStatus({ code: SpanStatusCode.OK });
    return result;
  } catch (error) {
    span.setStatus({
      code: SpanStatusCode.ERROR,
      message: error instanceof Error ? error.message : 'Unknown error',
    });
    if (error instanceof Error) {
      span.recordException(error);
    }
    throw error;
  } finally {
    span.end();
  }
}

/**
 * Execute a synchronous function within a span context.
 */
export function withSpanSync<T>(config: SpanConfig, fn: (span: Span) => T): T {
  const span = startSpan(config);

  try {
    const result = fn(span);
    span.setStatus({ code: SpanStatusCode.OK });
    return result;
  } catch (error) {
    span.setStatus({
      code: SpanStatusCode.ERROR,
      message: error instanceof Error ? error.message : 'Unknown error',
    });
    if (error instanceof Error) {
      span.recordException(error);
    }
    throw error;
  } finally {
    span.end();
  }
}

// ============================================================================
// Standard Attributes
// ============================================================================

/**
 * Standard attribute names for AI Authority spans.
 */
export const SpanAttributes = {
  // Agent identification
  AGENT_ID: 'ai_authority.agent.id',
  AGENT_FINGERPRINT: 'ai_authority.agent.fingerprint',

  // Threat signals
  SIGNAL_ID: 'ai_authority.signal.id',
  SIGNAL_TYPE: 'ai_authority.signal.type',
  SIGNAL_SEVERITY: 'ai_authority.signal.severity',

  // Risk scoring
  RISK_SCORE: 'ai_authority.risk.score',
  RISK_TIER: 'ai_authority.risk.tier',
  RISK_CLASSIFICATION: 'ai_authority.risk.classification',

  // Cases
  CASE_ID: 'ai_authority.case.id',
  CASE_STATUS: 'ai_authority.case.status',

  // Interventions
  INTERVENTION_ID: 'ai_authority.intervention.id',
  INTERVENTION_TIER: 'ai_authority.intervention.tier',
  INTERVENTION_ACTION: 'ai_authority.intervention.action',

  // Federation
  NODE_ID: 'ai_authority.node.id',
  NODE_REGION: 'ai_authority.node.region',
  MESSAGE_TYPE: 'ai_authority.message.type',

  // Capabilities
  CAPABILITY_ID: 'ai_authority.capability.id',
  PERMISSION: 'ai_authority.permission',

  // Audit
  AUDIT_ACTION: 'ai_authority.audit.action',
  AUDIT_ACTOR: 'ai_authority.audit.actor',
} as const;

// ============================================================================
// Span Decorators
// ============================================================================

/**
 * Decorator to trace a method.
 */
export function Traced(spanName?: string) {
  return function <T extends (...args: unknown[]) => unknown>(
    _target: object,
    propertyKey: string,
    descriptor: TypedPropertyDescriptor<T>
  ): TypedPropertyDescriptor<T> {
    const originalMethod = descriptor.value;

    if (!originalMethod) {
      return descriptor;
    }

    const name = spanName ?? propertyKey;

    descriptor.value = function (this: unknown, ...args: unknown[]) {
      const span = startSpan({ name });

      try {
        const result = originalMethod.apply(this, args);

        // Handle promises
        if (result instanceof Promise) {
          return result
            .then((value) => {
              span.setStatus({ code: SpanStatusCode.OK });
              span.end();
              return value;
            })
            .catch((error: unknown) => {
              span.setStatus({
                code: SpanStatusCode.ERROR,
                message: error instanceof Error ? error.message : 'Unknown error',
              });
              if (error instanceof Error) {
                span.recordException(error);
              }
              span.end();
              throw error;
            });
        }

        span.setStatus({ code: SpanStatusCode.OK });
        span.end();
        return result;
      } catch (error) {
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: error instanceof Error ? error.message : 'Unknown error',
        });
        if (error instanceof Error) {
          span.recordException(error);
        }
        span.end();
        throw error;
      }
    } as T;

    return descriptor;
  };
}

// ============================================================================
// Event Recording
// ============================================================================

/**
 * Record an event on the current span.
 */
export function recordEvent(name: string, attributes?: Attributes): void {
  const span = trace.getActiveSpan();
  if (span) {
    span.addEvent(name, attributes);
  }
}

/**
 * Record a security event.
 */
export function recordSecurityEvent(
  eventType: string,
  details: Record<string, unknown>
): void {
  recordEvent(`security.${eventType}`, {
    'security.event_type': eventType,
    ...Object.fromEntries(
      Object.entries(details).map(([k, v]) => [`security.${k}`, String(v)])
    ),
  });
}

/**
 * Record an audit event.
 */
export function recordAuditEvent(
  action: string,
  actor: string,
  target?: string,
  details?: Record<string, unknown>
): void {
  recordEvent('audit', {
    [SpanAttributes.AUDIT_ACTION]: action,
    [SpanAttributes.AUDIT_ACTOR]: actor,
    ...(target ? { 'ai_authority.audit.target': target } : {}),
    ...(details ?? {}),
  });
}
