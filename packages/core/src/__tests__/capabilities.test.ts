/**
 * Capability Manager Tests
 */

import { CapabilityManager, permissionAllows, getPermissionTier } from '../capabilities.js';
import type { Permission } from '../types.js';

describe('CapabilityManager', () => {
  let manager: CapabilityManager;

  beforeEach(() => {
    manager = new CapabilityManager('test-issuer');
  });

  describe('key management', () => {
    it('should generate key pair on construction', () => {
      expect(manager.getPublicKey()).toBeDefined();
      expect(manager.getPublicKey()).toContain('-----BEGIN PUBLIC KEY-----');
    });

    it('should use provided key pair', () => {
      const keyPair = CapabilityManager.generateKeyPair();
      const customManager = new CapabilityManager('custom-issuer', keyPair);

      expect(customManager.getPublicKey()).toBe(keyPair.publicKey);
    });
  });

  describe('token issuance', () => {
    it('should issue valid token', () => {
      const token = manager.issueToken({
        permissions: ['read:signals', 'write:signals'],
        subject: 'test-subject',
        justification: 'Testing',
        durationSeconds: 3600,
      });

      expect(token.id).toBeDefined();
      expect(token.permissions).toContain('read:signals');
      expect(token.subject).toBe('test-subject');
      expect(token.issuer).toBe('test-issuer');
      expect(token.signature).toBeDefined();
    });

    it('should set correct expiration', () => {
      const before = Date.now();

      const token = manager.issueToken({
        permissions: ['read:signals'],
        subject: 'test',
        justification: 'Test',
        durationSeconds: 3600,
      });

      const after = Date.now();

      const expectedMin = before + 3600 * 1000;
      const expectedMax = after + 3600 * 1000;

      expect(token.expiresAt.getTime()).toBeGreaterThanOrEqual(expectedMin);
      expect(token.expiresAt.getTime()).toBeLessThanOrEqual(expectedMax);
    });
  });

  describe('token validation', () => {
    it('should validate own tokens', () => {
      const token = manager.issueToken({
        permissions: ['read:signals'],
        subject: 'test',
        justification: 'Test',
        durationSeconds: 3600,
      });

      const result = manager.validateToken(token);
      expect(result.valid).toBe(true);
    });

    it('should reject expired tokens', () => {
      const token = manager.issueToken({
        permissions: ['read:signals'],
        subject: 'test',
        justification: 'Test',
        durationSeconds: -1, // Already expired
      });

      const result = manager.validateToken(token);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('expired');
    });

    it('should reject revoked tokens', () => {
      const token = manager.issueToken({
        permissions: ['read:signals'],
        subject: 'test',
        justification: 'Test',
        durationSeconds: 3600,
      });

      manager.revokeToken(token.id);

      const result = manager.validateToken(token);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('revoked');
    });

    it('should reject tokens from untrusted issuers', () => {
      const otherManager = new CapabilityManager('other-issuer');
      const token = otherManager.issueToken({
        permissions: ['read:signals'],
        subject: 'test',
        justification: 'Test',
        durationSeconds: 3600,
      });

      // Don't add other-issuer as trusted
      const result = manager.validateToken(token);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Untrusted issuer');
    });

    it('should validate tokens from trusted issuers', () => {
      const otherManager = new CapabilityManager('other-issuer');
      const token = otherManager.issueToken({
        permissions: ['read:signals'],
        subject: 'test',
        justification: 'Test',
        durationSeconds: 3600,
      });

      // Add other-issuer as trusted
      manager.addTrustedIssuer('other-issuer', otherManager.getPublicKey());

      const result = manager.validateToken(token);
      expect(result.valid).toBe(true);
    });

    it('should check required permissions', () => {
      const token = manager.issueToken({
        permissions: ['read:signals'],
        subject: 'test',
        justification: 'Test',
        durationSeconds: 3600,
      });

      const validResult = manager.validateToken(token, ['read:signals']);
      expect(validResult.valid).toBe(true);

      const invalidResult = manager.validateToken(token, ['write:signals']);
      expect(invalidResult.valid).toBe(false);
      expect(invalidResult.missingPermissions).toContain('write:signals');
    });
  });

  describe('token delegation', () => {
    it('should delegate subset of permissions', () => {
      const parentToken = manager.issueToken({
        permissions: ['read:signals', 'write:signals', 'read:cases'],
        subject: 'parent',
        justification: 'Parent token',
        durationSeconds: 3600,
      });

      const delegatedToken = manager.delegateToken(
        parentToken,
        ['read:signals'],
        'child',
        1800
      );

      expect(delegatedToken).not.toBeNull();
      expect(delegatedToken?.permissions).toEqual(['read:signals']);
      expect(delegatedToken?.subject).toBe('child');
    });

    it('should not delegate permissions not in parent', () => {
      const parentToken = manager.issueToken({
        permissions: ['read:signals'],
        subject: 'parent',
        justification: 'Parent token',
        durationSeconds: 3600,
      });

      const delegatedToken = manager.delegateToken(
        parentToken,
        ['write:signals'], // Not in parent
        'child',
        1800
      );

      expect(delegatedToken).toBeNull();
    });

    it('should not exceed parent duration', () => {
      const parentToken = manager.issueToken({
        permissions: ['read:signals'],
        subject: 'parent',
        justification: 'Parent token',
        durationSeconds: 1000,
      });

      const delegatedToken = manager.delegateToken(
        parentToken,
        ['read:signals'],
        'child',
        5000 // Longer than parent
      );

      expect(delegatedToken).not.toBeNull();
      expect(delegatedToken!.expiresAt.getTime()).toBeLessThanOrEqual(
        parentToken.expiresAt.getTime()
      );
    });
  });

  describe('issuer management', () => {
    it('should track trusted issuers', () => {
      const other = new CapabilityManager('other');

      manager.addTrustedIssuer('other', other.getPublicKey());

      const token = other.issueToken({
        permissions: ['read:signals'],
        subject: 'test',
        justification: 'Test',
        durationSeconds: 3600,
      });

      expect(manager.validateToken(token).valid).toBe(true);
    });

    it('should remove trusted issuers', () => {
      const other = new CapabilityManager('other');

      manager.addTrustedIssuer('other', other.getPublicKey());
      manager.removeTrustedIssuer('other');

      const token = other.issueToken({
        permissions: ['read:signals'],
        subject: 'test',
        justification: 'Test',
        durationSeconds: 3600,
      });

      expect(manager.validateToken(token).valid).toBe(false);
    });

    it('should not remove self from trusted issuers', () => {
      manager.removeTrustedIssuer('test-issuer');

      const token = manager.issueToken({
        permissions: ['read:signals'],
        subject: 'test',
        justification: 'Test',
        durationSeconds: 3600,
      });

      // Should still validate own tokens
      expect(manager.validateToken(token).valid).toBe(true);
    });
  });
});

describe('Permission helpers', () => {
  describe('permissionAllows', () => {
    it('should allow exact matches', () => {
      expect(permissionAllows('read:signals', 'read:signals')).toBe(true);
      expect(permissionAllows('write:cases', 'write:cases')).toBe(true);
    });

    it('should reject non-matches', () => {
      expect(permissionAllows('read:signals', 'write:signals')).toBe(false);
      expect(permissionAllows('read:signals', 'read:cases')).toBe(false);
    });
  });

  describe('getPermissionTier', () => {
    it('should identify execution tiers', () => {
      expect(getPermissionTier('execute:tier1' as Permission)).toBe('tier1');
      expect(getPermissionTier('execute:tier2' as Permission)).toBe('tier2');
      expect(getPermissionTier('execute:tier3' as Permission)).toBe('tier3');
    });

    it('should return null for non-execution permissions', () => {
      expect(getPermissionTier('read:signals')).toBeNull();
      expect(getPermissionTier('admin:nodes')).toBeNull();
    });
  });
});
