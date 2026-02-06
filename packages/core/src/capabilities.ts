/**
 * Capability-Based Access Control
 *
 * Implements capability tokens for fine-grained, least-privilege access control.
 * Per blueprint §10: "Tokens grant specific permissions"
 */

import { createHash, createSign, createVerify, generateKeyPairSync } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import type { CapabilityToken, Permission, CapabilityConstraint } from './types.js';

// ============================================================================
// Types
// ============================================================================

export interface KeyPair {
  readonly publicKey: string;
  readonly privateKey: string;
}

export interface CapabilityRequest {
  /** Requested permissions */
  readonly permissions: Permission[];

  /** Subject requesting the capability */
  readonly subject: string;

  /** Justification for the request */
  readonly justification: string;

  /** Requested duration in seconds */
  readonly durationSeconds: number;

  /** Requested constraints */
  readonly constraints?: CapabilityConstraint[];
}

export interface CapabilityValidationResult {
  readonly valid: boolean;
  readonly reason?: string;
  readonly expiredAt?: Date;
  readonly missingPermissions?: Permission[];
}

// ============================================================================
// Capability Manager
// ============================================================================

/**
 * Manages capability tokens for access control.
 */
export class CapabilityManager {
  private readonly issuerId: string;
  private readonly privateKey: string;
  private readonly publicKey: string;
  private readonly trustedIssuers: Map<string, string> = new Map();
  private readonly revokedTokens: Set<string> = new Set();

  constructor(issuerId: string, keyPair?: KeyPair) {
    this.issuerId = issuerId;

    if (keyPair) {
      this.privateKey = keyPair.privateKey;
      this.publicKey = keyPair.publicKey;
    } else {
      const generated = CapabilityManager.generateKeyPair();
      this.privateKey = generated.privateKey;
      this.publicKey = generated.publicKey;
    }

    // Trust self
    this.trustedIssuers.set(issuerId, this.publicKey);
  }

  /**
   * Generate a new key pair.
   */
  static generateKeyPair(): KeyPair {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { publicKey, privateKey };
  }

  /**
   * Get this issuer's public key.
   */
  getPublicKey(): string {
    return this.publicKey;
  }

  /**
   * Get this issuer's ID.
   */
  getIssuerId(): string {
    return this.issuerId;
  }

  /**
   * Add a trusted issuer.
   */
  addTrustedIssuer(issuerId: string, publicKey: string): void {
    this.trustedIssuers.set(issuerId, publicKey);
  }

  /**
   * Remove a trusted issuer.
   */
  removeTrustedIssuer(issuerId: string): void {
    if (issuerId !== this.issuerId) {
      this.trustedIssuers.delete(issuerId);
    }
  }

  /**
   * Issue a new capability token.
   */
  issueToken(request: CapabilityRequest): CapabilityToken {
    const id = uuidv4();
    const issuedAt = new Date();
    const expiresAt = new Date(issuedAt.getTime() + request.durationSeconds * 1000);

    const tokenData = {
      id,
      permissions: request.permissions,
      subject: request.subject,
      issuer: this.issuerId,
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
      constraints: request.constraints ?? [],
    };

    const signature = this.sign(JSON.stringify(tokenData));

    return {
      ...tokenData,
      issuedAt,
      expiresAt,
      signature,
    };
  }

  /**
   * Validate a capability token.
   */
  validateToken(
    token: CapabilityToken,
    requiredPermissions?: Permission[]
  ): CapabilityValidationResult {
    // Check if revoked
    if (this.revokedTokens.has(token.id)) {
      return { valid: false, reason: 'Token has been revoked' };
    }

    // Check expiration
    const now = new Date();
    if (token.expiresAt < now) {
      return {
        valid: false,
        reason: 'Token has expired',
        expiredAt: token.expiresAt,
      };
    }

    // Check issuer trust
    const issuerPublicKey = this.trustedIssuers.get(token.issuer);
    if (!issuerPublicKey) {
      return { valid: false, reason: `Untrusted issuer: ${token.issuer}` };
    }

    // Verify signature
    const tokenData = {
      id: token.id,
      permissions: token.permissions,
      subject: token.subject,
      issuer: token.issuer,
      issuedAt: token.issuedAt.toISOString(),
      expiresAt: token.expiresAt.toISOString(),
      constraints: token.constraints,
    };

    if (!this.verify(JSON.stringify(tokenData), token.signature, issuerPublicKey)) {
      return { valid: false, reason: 'Invalid signature' };
    }

    // Check required permissions
    if (requiredPermissions && requiredPermissions.length > 0) {
      const missingPermissions = requiredPermissions.filter(
        (p) => !token.permissions.includes(p)
      );

      if (missingPermissions.length > 0) {
        return {
          valid: false,
          reason: 'Missing required permissions',
          missingPermissions,
        };
      }
    }

    // Check constraints
    for (const constraint of token.constraints) {
      const constraintResult = this.checkConstraint(constraint);
      if (!constraintResult.valid) {
        return constraintResult;
      }
    }

    return { valid: true };
  }

  /**
   * Check a single constraint.
   */
  private checkConstraint(constraint: CapabilityConstraint): CapabilityValidationResult {
    switch (constraint.type) {
      case 'time_window': {
        const now = new Date();
        const start = new Date(constraint.parameters['start'] as string);
        const end = new Date(constraint.parameters['end'] as string);
        if (now < start || now > end) {
          return { valid: false, reason: 'Outside allowed time window' };
        }
        break;
      }

      case 'rate_limit': {
        // Rate limiting would be checked by a separate rate limiter
        // This is a placeholder for the constraint structure
        break;
      }

      case 'geography': {
        // Geographic constraints would be checked against request origin
        // This is a placeholder for the constraint structure
        break;
      }

      case 'scope': {
        // Scope constraints limit what resources can be accessed
        // This is a placeholder for the constraint structure
        break;
      }
    }

    return { valid: true };
  }

  /**
   * Revoke a token.
   */
  revokeToken(tokenId: string): void {
    this.revokedTokens.add(tokenId);
  }

  /**
   * Check if a token is revoked.
   */
  isRevoked(tokenId: string): boolean {
    return this.revokedTokens.has(tokenId);
  }

  /**
   * Delegate a subset of permissions to a new token.
   */
  delegateToken(
    parentToken: CapabilityToken,
    delegatedPermissions: Permission[],
    newSubject: string,
    durationSeconds: number
  ): CapabilityToken | null {
    // Validate parent token
    const validation = this.validateToken(parentToken, delegatedPermissions);
    if (!validation.valid) {
      return null;
    }

    // Ensure delegated permissions are subset of parent
    const invalidPermissions = delegatedPermissions.filter(
      (p) => !parentToken.permissions.includes(p)
    );
    if (invalidPermissions.length > 0) {
      return null;
    }

    // Ensure duration doesn't exceed parent
    const maxDuration = Math.floor(
      (parentToken.expiresAt.getTime() - Date.now()) / 1000
    );
    const actualDuration = Math.min(durationSeconds, maxDuration);

    return this.issueToken({
      permissions: delegatedPermissions,
      subject: newSubject,
      justification: `Delegated from ${parentToken.subject}`,
      durationSeconds: actualDuration,
      constraints: parentToken.constraints,
    });
  }

  /**
   * Sign data with the private key.
   */
  private sign(data: string): string {
    const sign = createSign('SHA256');
    sign.update(data);
    return sign.sign(this.privateKey, 'base64');
  }

  /**
   * Verify a signature.
   */
  private verify(data: string, signature: string, publicKey: string): boolean {
    try {
      const verify = createVerify('SHA256');
      verify.update(data);
      return verify.verify(publicKey, signature, 'base64');
    } catch {
      return false;
    }
  }

  /**
   * Hash data for integrity checks.
   */
  static hash(data: string): string {
    return createHash('sha256').update(data).digest('hex');
  }
}

// ============================================================================
// Permission Helpers
// ============================================================================

/**
 * Check if a permission allows an action.
 */
export function permissionAllows(permission: Permission, action: string): boolean {
  const [permType, permResource] = permission.split(':');
  const [actionType, actionResource] = action.split(':');

  // Exact match
  if (permission === action) {
    return true;
  }

  // Wildcard resource match
  if (permType === actionType && permResource === '*') {
    return true;
  }

  // Admin permissions grant all actions on that resource
  if (permType === 'admin' && permResource === actionResource) {
    return true;
  }

  return false;
}

/**
 * Get the minimum required tier for a permission.
 */
export function getPermissionTier(permission: Permission): 'tier1' | 'tier2' | 'tier3' | null {
  if (permission.startsWith('execute:tier3')) {
    return 'tier3';
  }
  if (permission.startsWith('execute:tier2')) {
    return 'tier2';
  }
  if (permission.startsWith('execute:tier1')) {
    return 'tier1';
  }
  return null;
}
