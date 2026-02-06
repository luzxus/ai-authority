/**
 * Result Type
 *
 * A type-safe way to handle operations that can fail,
 * without throwing exceptions.
 */

// ============================================================================
// Result Type Definition
// ============================================================================

export type Result<T, E = Error> = Success<T> | Failure<E>;

export interface Success<T> {
  readonly ok: true;
  readonly value: T;
}

export interface Failure<E> {
  readonly ok: false;
  readonly error: E;
}

// ============================================================================
// Constructors
// ============================================================================

/**
 * Create a success result.
 */
export function ok<T>(value: T): Success<T> {
  return { ok: true, value };
}

/**
 * Create a failure result.
 */
export function err<E>(error: E): Failure<E> {
  return { ok: false, error };
}

// ============================================================================
// Type Guards
// ============================================================================

/**
 * Check if a result is a success.
 */
export function isOk<T, E>(result: Result<T, E>): result is Success<T> {
  return result.ok;
}

/**
 * Check if a result is a failure.
 */
export function isErr<T, E>(result: Result<T, E>): result is Failure<E> {
  return !result.ok;
}

// ============================================================================
// Transformations
// ============================================================================

/**
 * Map over a successful result.
 */
export function map<T, U, E>(result: Result<T, E>, fn: (value: T) => U): Result<U, E> {
  if (result.ok) {
    return ok(fn(result.value));
  }
  return result;
}

/**
 * Map over a failed result.
 */
export function mapErr<T, E, F>(result: Result<T, E>, fn: (error: E) => F): Result<T, F> {
  if (!result.ok) {
    return err(fn(result.error));
  }
  return result;
}

/**
 * Chain results (flatMap).
 */
export function flatMap<T, U, E>(
  result: Result<T, E>,
  fn: (value: T) => Result<U, E>
): Result<U, E> {
  if (result.ok) {
    return fn(result.value);
  }
  return result;
}

/**
 * Unwrap a result, throwing if it's a failure.
 */
export function unwrap<T, E>(result: Result<T, E>): T {
  if (result.ok) {
    return result.value;
  }
  throw result.error;
}

/**
 * Unwrap a result with a default value.
 */
export function unwrapOr<T, E>(result: Result<T, E>, defaultValue: T): T {
  if (result.ok) {
    return result.value;
  }
  return defaultValue;
}

/**
 * Unwrap a result with a lazy default.
 */
export function unwrapOrElse<T, E>(result: Result<T, E>, fn: (error: E) => T): T {
  if (result.ok) {
    return result.value;
  }
  return fn(result.error);
}

// ============================================================================
// Combining Results
// ============================================================================

/**
 * Combine multiple results into one.
 * Returns the first error encountered, or all values if all succeed.
 */
export function all<T extends readonly Result<unknown, unknown>[]>(
  ...results: T
): Result<{ [K in keyof T]: T[K] extends Result<infer V, unknown> ? V : never }, unknown> {
  const values: unknown[] = [];

  for (const result of results) {
    if (!result.ok) {
      return result;
    }
    values.push(result.value);
  }

  return ok(values as { [K in keyof T]: T[K] extends Result<infer V, unknown> ? V : never });
}

/**
 * Return the first successful result, or all errors if all fail.
 */
export function any<T, E>(results: Result<T, E>[]): Result<T, E[]> {
  const errors: E[] = [];

  for (const result of results) {
    if (result.ok) {
      return result;
    }
    errors.push(result.error);
  }

  return err(errors);
}

// ============================================================================
// Async Support
// ============================================================================

/**
 * Wrap a promise in a Result.
 */
export async function fromPromise<T, E = Error>(
  promise: Promise<T>,
  errorMapper?: (e: unknown) => E
): Promise<Result<T, E>> {
  try {
    const value = await promise;
    return ok(value);
  } catch (e) {
    if (errorMapper) {
      return err(errorMapper(e));
    }
    return err(e as E);
  }
}

/**
 * Convert a Result to a Promise.
 */
export function toPromise<T, E>(result: Result<T, E>): Promise<T> {
  if (result.ok) {
    return Promise.resolve(result.value);
  }
  return Promise.reject(result.error);
}

/**
 * Async map.
 */
export async function mapAsync<T, U, E>(
  result: Result<T, E>,
  fn: (value: T) => Promise<U>
): Promise<Result<U, E>> {
  if (result.ok) {
    const value = await fn(result.value);
    return ok(value);
  }
  return result;
}

/**
 * Async flatMap.
 */
export async function flatMapAsync<T, U, E>(
  result: Result<T, E>,
  fn: (value: T) => Promise<Result<U, E>>
): Promise<Result<U, E>> {
  if (result.ok) {
    return fn(result.value);
  }
  return result;
}

// ============================================================================
// Error Types
// ============================================================================

/**
 * Standard error codes for the AI Authority system.
 */
export type ErrorCode =
  | 'VALIDATION_ERROR'
  | 'AUTHENTICATION_ERROR'
  | 'AUTHORIZATION_ERROR'
  | 'NOT_FOUND'
  | 'CONFLICT'
  | 'RATE_LIMITED'
  | 'INTERNAL_ERROR'
  | 'NETWORK_ERROR'
  | 'TIMEOUT'
  | 'UNAVAILABLE';

/**
 * Structured error for the AI Authority system.
 */
export interface AppError {
  readonly code: ErrorCode;
  readonly message: string;
  readonly details?: Record<string, unknown>;
  readonly cause?: Error;
}

/**
 * Create an AppError.
 */
export function createError(
  code: ErrorCode,
  message: string,
  details?: Record<string, unknown>,
  cause?: Error
): AppError {
  const error: AppError = { code, message };
  if (details !== undefined) {
    (error as { details: Record<string, unknown> }).details = details;
  }
  if (cause !== undefined) {
    (error as { cause: Error }).cause = cause;
  }
  return error;
}

/**
 * Create common errors.
 */
export const Errors = {
  validation: (message: string, details?: Record<string, unknown>) =>
    createError('VALIDATION_ERROR', message, details),

  notFound: (resource: string, id: string) =>
    createError('NOT_FOUND', `${resource} not found: ${id}`, { resource, id }),

  unauthorized: (message: string = 'Unauthorized') =>
    createError('AUTHENTICATION_ERROR', message),

  forbidden: (message: string = 'Forbidden') =>
    createError('AUTHORIZATION_ERROR', message),

  rateLimited: (retryAfter?: number) =>
    createError('RATE_LIMITED', 'Rate limit exceeded', { retryAfter }),

  internal: (message: string = 'Internal error', cause?: Error) =>
    createError('INTERNAL_ERROR', message, undefined, cause),
} as const;
