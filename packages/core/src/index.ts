/**
 * AI Authority Core Package
 *
 * Shared types, interfaces, and utilities for the federated
 * detection and early-warning network for malicious AI agent behavior.
 */

// Types
export * from './types.js';
export * from './scoring.js';

// Result utilities - explicit exports to avoid naming conflicts with validation
export {
  type Result,
  type Success,
  type Failure,
  type AppError,
  type ErrorCode,
  ok,
  err,
  isOk,
  isErr,
  unwrap,
  unwrapOr,
  unwrapOrElse,
  map,
  flatMap,
  mapErr,
  all as resultAll,
  any as resultAny,
  toPromise,
  createError,
  Errors,
} from './result.js';

// Validation utilities - explicit exports to avoid naming conflicts with result
export {
  type ValidationResult,
  type ValidationError,
  type Validator,
  isNonEmptyString,
  isInRange,
  matchesPattern,
  isOneOf,
  isValidDate,
  isWithinLengthLimit,
  isWithinArrayLimit,
  isWithinDepthLimit,
  sanitizeString,
  sanitizeObject,
  combineValidations,
  all as validationAll,
  any as validationAny,
  isValidUUID,
  isValidHex,
  isValidAgentId,
} from './validation.js';

// Cryptography
export * from './crypto.js';
export * from './merkle.js';

// Capabilities - uses types from types.js so export the manager
export { CapabilityManager } from './capabilities.js';

// Tracing
export * from './tracing.js';
