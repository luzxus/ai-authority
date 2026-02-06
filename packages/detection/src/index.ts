/**
 * AI Authority Detection Package
 *
 * Anomaly detection, behavioral analysis, model fingerprinting, and autonomous agents.
 */

// Core detection utilities
export * from './anomaly.js';
export * from './fingerprint.js';
export * from './behavioral.js';

// Autonomous agents
export { ScoutAgent } from './scout.js';
export type { DiscoveryTarget, DiscoveryResult, Finding, ExplorationStrategy } from './scout.js';

export { SensorAgent } from './sensor.js';
export type { SignalSource, TelemetryRecord, TelemetryEvent, SensorOutput } from './sensor.js';

export { LearnerAgent } from './learner.js';
export type {
  LearningEpisode,
  Observation,
  LearningAction,
  ModelUpdate,
  ModelMetrics,
  ParameterChange,
  LearningConfig,
} from './learner.js';

// Moltbook Scout (Primary Data Source Integration)
export { MoltbookScoutAgent, DEFAULT_SCOUT_CONFIG } from './moltbook-scout.js';
export type {
  InvestigationTarget,
  HuntResult,
  MoltbookScoutConfig,
} from './moltbook-scout.js';
