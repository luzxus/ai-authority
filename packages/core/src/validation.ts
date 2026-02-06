/**
 * Validation Utilities
 *
 * Input validation and sanitization to prevent poisoning attacks.
 * Per blueprint §13: "Input sanitization against poisoning attacks"
 */

// ============================================================================
// Types
// ============================================================================

export interface ValidationResult {
  readonly valid: boolean;
  readonly errors: ValidationError[];
}

export interface ValidationError {
  readonly field: string;
  readonly message: string;
  readonly code: string;
}

export type Validator<T> = (value: unknown) => ValidationResult & { value?: T };

// ============================================================================
// Basic Validators
// ============================================================================

/**
 * Validate that a value is a non-empty string.
 */
export function isNonEmptyString(value: unknown, field: string): ValidationResult {
  if (typeof value !== 'string') {
    return {
      valid: false,
      errors: [{ field, message: 'Must be a string', code: 'INVALID_TYPE' }],
    };
  }

  if (value.trim().length === 0) {
    return {
      valid: false,
      errors: [{ field, message: 'Must not be empty', code: 'EMPTY_STRING' }],
    };
  }

  return { valid: true, errors: [] };
}

/**
 * Validate that a value is within a numeric range.
 */
export function isInRange(
  value: unknown,
  field: string,
  min: number,
  max: number
): ValidationResult {
  if (typeof value !== 'number' || isNaN(value)) {
    return {
      valid: false,
      errors: [{ field, message: 'Must be a number', code: 'INVALID_TYPE' }],
    };
  }

  if (value < min || value > max) {
    return {
      valid: false,
      errors: [
        {
          field,
          message: `Must be between ${min} and ${max}`,
          code: 'OUT_OF_RANGE',
        },
      ],
    };
  }

  return { valid: true, errors: [] };
}

/**
 * Validate that a value matches a pattern.
 */
export function matchesPattern(
  value: unknown,
  field: string,
  pattern: RegExp,
  patternDescription: string
): ValidationResult {
  if (typeof value !== 'string') {
    return {
      valid: false,
      errors: [{ field, message: 'Must be a string', code: 'INVALID_TYPE' }],
    };
  }

  if (!pattern.test(value)) {
    return {
      valid: false,
      errors: [
        {
          field,
          message: `Must match pattern: ${patternDescription}`,
          code: 'PATTERN_MISMATCH',
        },
      ],
    };
  }

  return { valid: true, errors: [] };
}

/**
 * Validate that a value is one of allowed values.
 */
export function isOneOf<T extends string>(
  value: unknown,
  field: string,
  allowedValues: readonly T[]
): ValidationResult {
  if (!allowedValues.includes(value as T)) {
    return {
      valid: false,
      errors: [
        {
          field,
          message: `Must be one of: ${allowedValues.join(', ')}`,
          code: 'INVALID_VALUE',
        },
      ],
    };
  }

  return { valid: true, errors: [] };
}

/**
 * Validate that a value is a valid date.
 */
export function isValidDate(value: unknown, field: string): ValidationResult {
  if (value instanceof Date) {
    if (isNaN(value.getTime())) {
      return {
        valid: false,
        errors: [{ field, message: 'Invalid date', code: 'INVALID_DATE' }],
      };
    }
    return { valid: true, errors: [] };
  }

  if (typeof value === 'string') {
    const date = new Date(value);
    if (isNaN(date.getTime())) {
      return {
        valid: false,
        errors: [{ field, message: 'Invalid date string', code: 'INVALID_DATE' }],
      };
    }
    return { valid: true, errors: [] };
  }

  return {
    valid: false,
    errors: [{ field, message: 'Must be a date', code: 'INVALID_TYPE' }],
  };
}

// ============================================================================
// Security Validators
// ============================================================================

/**
 * Maximum allowed string length to prevent DoS.
 */
const MAX_STRING_LENGTH = 100000;

/**
 * Maximum allowed array length.
 */
const MAX_ARRAY_LENGTH = 10000;

/**
 * Maximum object depth for nested structures.
 */
const MAX_OBJECT_DEPTH = 10;

/**
 * Validate string doesn't exceed maximum length.
 */
export function isWithinLengthLimit(
  value: unknown,
  field: string,
  maxLength: number = MAX_STRING_LENGTH
): ValidationResult {
  if (typeof value !== 'string') {
    return {
      valid: false,
      errors: [{ field, message: 'Must be a string', code: 'INVALID_TYPE' }],
    };
  }

  if (value.length > maxLength) {
    return {
      valid: false,
      errors: [
        {
          field,
          message: `Exceeds maximum length of ${maxLength}`,
          code: 'LENGTH_EXCEEDED',
        },
      ],
    };
  }

  return { valid: true, errors: [] };
}

/**
 * Validate array doesn't exceed maximum length.
 */
export function isWithinArrayLimit(
  value: unknown,
  field: string,
  maxLength: number = MAX_ARRAY_LENGTH
): ValidationResult {
  if (!Array.isArray(value)) {
    return {
      valid: false,
      errors: [{ field, message: 'Must be an array', code: 'INVALID_TYPE' }],
    };
  }

  if (value.length > maxLength) {
    return {
      valid: false,
      errors: [
        {
          field,
          message: `Array exceeds maximum length of ${maxLength}`,
          code: 'ARRAY_LENGTH_EXCEEDED',
        },
      ],
    };
  }

  return { valid: true, errors: [] };
}

/**
 * Validate object depth doesn't exceed limit.
 */
export function isWithinDepthLimit(
  value: unknown,
  field: string,
  maxDepth: number = MAX_OBJECT_DEPTH,
  currentDepth: number = 0
): ValidationResult {
  if (currentDepth > maxDepth) {
    return {
      valid: false,
      errors: [
        {
          field,
          message: `Object depth exceeds maximum of ${maxDepth}`,
          code: 'DEPTH_EXCEEDED',
        },
      ],
    };
  }

  if (typeof value === 'object' && value !== null) {
    for (const [key, val] of Object.entries(value)) {
      const result = isWithinDepthLimit(
        val,
        `${field}.${key}`,
        maxDepth,
        currentDepth + 1
      );
      if (!result.valid) {
        return result;
      }
    }
  }

  return { valid: true, errors: [] };
}

// ============================================================================
// Sanitization
// ============================================================================

/**
 * Sanitize a string by removing control characters.
 */
export function sanitizeString(value: string): string {
  // Remove control characters except newline, tab, carriage return
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
}

/**
 * Sanitize an object by limiting depth and removing dangerous keys.
 */
export function sanitizeObject<T extends object>(
  obj: T,
  maxDepth: number = MAX_OBJECT_DEPTH
): T {
  const dangerousKeys = ['__proto__', 'constructor', 'prototype'];

  function sanitize(value: unknown, depth: number): unknown {
    if (depth > maxDepth) {
      return '[depth exceeded]';
    }

    if (typeof value === 'string') {
      return sanitizeString(value);
    }

    if (Array.isArray(value)) {
      return value.slice(0, MAX_ARRAY_LENGTH).map((v) => sanitize(v, depth + 1));
    }

    if (typeof value === 'object' && value !== null) {
      const result: Record<string, unknown> = {};
      for (const [key, val] of Object.entries(value)) {
        if (!dangerousKeys.includes(key)) {
          result[key] = sanitize(val, depth + 1);
        }
      }
      return result;
    }

    return value;
  }

  return sanitize(obj, 0) as T;
}

// ============================================================================
// Composite Validators
// ============================================================================

/**
 * Combine multiple validation results.
 */
export function combineValidations(...results: ValidationResult[]): ValidationResult {
  const errors = results.flatMap((r) => r.errors);
  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Create a validator that requires all conditions.
 */
export function all(...validators: (() => ValidationResult)[]): ValidationResult {
  const results = validators.map((v) => v());
  return combineValidations(...results);
}

/**
 * Create a validator that requires at least one condition.
 */
export function any(...validators: (() => ValidationResult)[]): ValidationResult {
  const results = validators.map((v) => v());

  if (results.some((r) => r.valid)) {
    return { valid: true, errors: [] };
  }

  return combineValidations(...results);
}

// ============================================================================
// ID Validators
// ============================================================================

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX_PATTERN = /^[0-9a-f]+$/i;
const AGENT_ID_PATTERN = /^[a-z0-9-]+:[a-z0-9-]+:[a-z0-9]+:[a-f0-9]+$/i;

/**
 * Validate UUID format.
 */
export function isValidUUID(value: unknown, field: string): ValidationResult {
  return matchesPattern(value, field, UUID_PATTERN, 'UUID');
}

/**
 * Validate hex string format.
 */
export function isValidHex(value: unknown, field: string): ValidationResult {
  return matchesPattern(value, field, HEX_PATTERN, 'hexadecimal');
}

/**
 * Validate agent ID format.
 */
export function isValidAgentId(value: unknown, field: string): ValidationResult {
  return matchesPattern(
    value,
    field,
    AGENT_ID_PATTERN,
    '{namespace}:{type}:{algorithm}:{hash}'
  );
}
