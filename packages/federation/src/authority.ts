/**
 * Regulatory Authority Types & Management
 *
 * Defines types and classes for managing AI regulatory authorities
 * in the federated data sharing network. Per the Data Fetching and
 * Distribution Plan for AI Regulatory Authorities.
 */

import { generateSecureId } from '@ai-authority/core';

// ============================================================================
// Types
// ============================================================================

/**
 * Classification of regulatory authority types.
 */
export type AuthorityType =
  | 'government_agency' // e.g., NIST, FDA
  | 'international_body' // e.g., EU AI Office
  | 'national_entity' // e.g., UK AI Safety Institute
  | 'regional_authority' // e.g., State-level regulators
  | 'industry_consortium' // e.g., AI-ISAC
  | 'research_institution'; // e.g., Academic partners

/**
 * Jurisdiction scope for an authority.
 */
export type JurisdictionScope =
  | 'global'
  | 'continental'
  | 'national'
  | 'regional'
  | 'sector_specific';

/**
 * Access tier for data distribution.
 * Per the distribution plan's multi-tier access model.
 */
export type AccessTier =
  | 'public' // Anonymized aggregates
  | 'restricted' // Detailed data with authentication
  | 'confidential' // Sensitive investigations
  | 'classified'; // Critical infrastructure threats

/**
 * Regulatory authority participating in the federation.
 */
export interface RegulatoryAuthority {
  /** Unique authority ID */
  readonly id: string;

  /** Display name */
  readonly name: string;

  /** Authority type */
  readonly type: AuthorityType;

  /** Jurisdiction scope */
  readonly jurisdiction: JurisdictionScope;

  /** Geographic region(s) covered */
  readonly regions: string[];

  /** Regulatory domains (e.g., healthcare, finance) */
  readonly domains: string[];

  /** Access tier granted */
  readonly accessTier: AccessTier;

  /** Permissions for data operations */
  readonly permissions: AuthorityPermission[];

  /** Associated federation node */
  readonly nodeId: string;

  /** Public key for secure communication */
  readonly publicKey: string;

  /** Contact information (for incident response) */
  readonly contactInfo: AuthorityContact;

  /** Data sharing agreements (MOU IDs) */
  readonly agreements: string[];

  /** Compliance certifications */
  readonly certifications: string[];

  /** Trust score (0-1) based on participation history */
  trustScore: number;

  /** When authority joined the network */
  readonly joinedAt: Date;

  /** Last activity timestamp */
  lastActiveAt: Date;

  /** Authority status */
  status: 'active' | 'suspended' | 'pending_verification' | 'inactive';
}

/**
 * Permissions specific to regulatory authorities.
 */
export type AuthorityPermission =
  | 'fetch:public_data'
  | 'fetch:restricted_data'
  | 'fetch:confidential_data'
  | 'fetch:classified_data'
  | 'distribute:public_data'
  | 'distribute:restricted_data'
  | 'distribute:confidential_data'
  | 'distribute:classified_data'
  | 'process:anonymize'
  | 'process:enrich'
  | 'process:aggregate'
  | 'admin:approve_authorities'
  | 'admin:manage_agreements'
  | 'admin:audit_access';

/**
 * Contact information for an authority.
 */
export interface AuthorityContact {
  /** Primary contact name */
  readonly primaryContact: string;

  /** Contact email */
  readonly email: string;

  /** Emergency contact (for incident response) */
  readonly emergencyContact?: string;

  /** Secure communication channel (e.g., encrypted email) */
  readonly secureChannel?: string;
}

/**
 * Data sharing agreement (Memorandum of Understanding).
 */
export interface DataSharingAgreement {
  /** Agreement ID */
  readonly id: string;

  /** Participating authorities */
  readonly parties: string[];

  /** Agreement type */
  readonly type: 'bilateral' | 'multilateral' | 'consortium';

  /** Data types covered */
  readonly coveredDataTypes: DataCategory[];

  /** Sharing restrictions */
  readonly restrictions: SharingRestriction[];

  /** Effective date */
  readonly effectiveDate: Date;

  /** Expiration date */
  readonly expirationDate: Date;

  /** Liability clauses (hashed for reference) */
  readonly liabilityClausesHash: string;

  /** Digital signatures from all parties */
  readonly signatures: AgreementSignature[];

  /** Agreement status */
  status: 'draft' | 'pending_signatures' | 'active' | 'expired' | 'terminated';
}

/**
 * Categories of data that can be shared.
 */
export type DataCategory =
  | 'threat_signals'
  | 'incident_reports'
  | 'compliance_audits'
  | 'model_performance_metrics'
  | 'bias_assessments'
  | 'risk_scores'
  | 'behavioral_patterns'
  | 'anonymized_indicators'
  | 'aggregated_statistics';

/**
 * Restrictions on data sharing.
 */
export interface SharingRestriction {
  /** Restriction type */
  readonly type: 'geographic' | 'temporal' | 'usage' | 'retention' | 'onward_sharing';

  /** Restriction details */
  readonly details: string;

  /** Enforcement mechanism */
  readonly enforcement: 'technical' | 'legal' | 'audit';
}

/**
 * Digital signature for agreements.
 */
export interface AgreementSignature {
  /** Signing authority ID */
  readonly authorityId: string;

  /** Signature timestamp */
  readonly signedAt: Date;

  /** Cryptographic signature */
  readonly signature: string;

  /** Signing authority's public key */
  readonly publicKey: string;
}

// ============================================================================
// Default Configurations
// ============================================================================

export const DEFAULT_AUTHORITY_PERMISSIONS: Record<AccessTier, AuthorityPermission[]> = {
  public: ['fetch:public_data', 'distribute:public_data', 'process:aggregate'],
  restricted: [
    'fetch:public_data',
    'fetch:restricted_data',
    'distribute:public_data',
    'distribute:restricted_data',
    'process:aggregate',
    'process:anonymize',
  ],
  confidential: [
    'fetch:public_data',
    'fetch:restricted_data',
    'fetch:confidential_data',
    'distribute:public_data',
    'distribute:restricted_data',
    'distribute:confidential_data',
    'process:aggregate',
    'process:anonymize',
    'process:enrich',
  ],
  classified: [
    'fetch:public_data',
    'fetch:restricted_data',
    'fetch:confidential_data',
    'fetch:classified_data',
    'distribute:public_data',
    'distribute:restricted_data',
    'distribute:confidential_data',
    'distribute:classified_data',
    'process:aggregate',
    'process:anonymize',
    'process:enrich',
    'admin:audit_access',
  ],
};

// ============================================================================
// Authority Registry
// ============================================================================

/**
 * Manages regulatory authorities in the federation.
 */
export class AuthorityRegistry {
  private readonly authorities: Map<string, RegulatoryAuthority> = new Map();
  private readonly agreements: Map<string, DataSharingAgreement> = new Map();
  private readonly authorityByNode: Map<string, string> = new Map();

  /**
   * Register a new regulatory authority.
   */
  registerAuthority(
    config: Omit<RegulatoryAuthority, 'id' | 'trustScore' | 'joinedAt' | 'lastActiveAt' | 'status'>
  ): RegulatoryAuthority {
    const id = generateSecureId();
    const authority: RegulatoryAuthority = {
      ...config,
      id,
      trustScore: 0.5, // Initial neutral trust score
      joinedAt: new Date(),
      lastActiveAt: new Date(),
      status: 'pending_verification',
    };

    this.authorities.set(id, authority);
    this.authorityByNode.set(config.nodeId, id);

    return authority;
  }

  /**
   * Get authority by ID.
   */
  getAuthority(id: string): RegulatoryAuthority | undefined {
    return this.authorities.get(id);
  }

  /**
   * Get authority by federation node ID.
   */
  getAuthorityByNode(nodeId: string): RegulatoryAuthority | undefined {
    const authorityId = this.authorityByNode.get(nodeId);
    return authorityId ? this.authorities.get(authorityId) : undefined;
  }

  /**
   * Get all authorities.
   */
  getAllAuthorities(): RegulatoryAuthority[] {
    return Array.from(this.authorities.values());
  }

  /**
   * Get authorities by type.
   */
  getAuthoritiesByType(type: AuthorityType): RegulatoryAuthority[] {
    return Array.from(this.authorities.values()).filter((a) => a.type === type);
  }

  /**
   * Get authorities by access tier.
   */
  getAuthoritiesByTier(tier: AccessTier): RegulatoryAuthority[] {
    return Array.from(this.authorities.values()).filter((a) => a.accessTier === tier);
  }

  /**
   * Get authorities with specific permission.
   */
  getAuthoritiesWithPermission(permission: AuthorityPermission): RegulatoryAuthority[] {
    return Array.from(this.authorities.values()).filter((a) =>
      a.permissions.includes(permission)
    );
  }

  /**
   * Update authority status.
   */
  updateAuthorityStatus(
    id: string,
    status: RegulatoryAuthority['status']
  ): boolean {
    const authority = this.authorities.get(id);
    if (!authority) return false;

    authority.status = status;
    authority.lastActiveAt = new Date();
    return true;
  }

  /**
   * Update authority trust score.
   */
  updateTrustScore(id: string, delta: number): boolean {
    const authority = this.authorities.get(id);
    if (!authority) return false;

    authority.trustScore = Math.max(0, Math.min(1, authority.trustScore + delta));
    authority.lastActiveAt = new Date();
    return true;
  }

  /**
   * Check if authority has permission.
   */
  hasPermission(authorityId: string, permission: AuthorityPermission): boolean {
    const authority = this.authorities.get(authorityId);
    if (!authority) return false;
    if (authority.status !== 'active') return false;
    return authority.permissions.includes(permission);
  }

  /**
   * Check if authority can access data tier.
   */
  canAccessTier(authorityId: string, tier: AccessTier): boolean {
    const authority = this.authorities.get(authorityId);
    if (!authority) return false;
    if (authority.status !== 'active') return false;

    const tierHierarchy: AccessTier[] = ['public', 'restricted', 'confidential', 'classified'];
    const authorityTierIndex = tierHierarchy.indexOf(authority.accessTier);
    const requestedTierIndex = tierHierarchy.indexOf(tier);

    return authorityTierIndex >= requestedTierIndex;
  }

  /**
   * Register a data sharing agreement.
   */
  registerAgreement(
    config: Omit<DataSharingAgreement, 'id' | 'status'>
  ): DataSharingAgreement {
    const id = generateSecureId();
    const agreement: DataSharingAgreement = {
      ...config,
      id,
      status: 'draft',
    };

    this.agreements.set(id, agreement);

    // Update participating authorities
    for (const partyId of config.parties) {
      const authority = this.authorities.get(partyId);
      if (authority && !authority.agreements.includes(id)) {
        (authority.agreements as string[]).push(id);
      }
    }

    return agreement;
  }

  /**
   * Get agreement by ID.
   */
  getAgreement(id: string): DataSharingAgreement | undefined {
    return this.agreements.get(id);
  }

  /**
   * Get agreements between two authorities.
   */
  getAgreementsBetween(authorityId1: string, authorityId2: string): DataSharingAgreement[] {
    return Array.from(this.agreements.values()).filter(
      (a) =>
        a.status === 'active' &&
        a.parties.includes(authorityId1) &&
        a.parties.includes(authorityId2)
    );
  }

  /**
   * Check if sharing is allowed between authorities for a data category.
   */
  isSharingAllowed(
    fromAuthorityId: string,
    toAuthorityId: string,
    dataCategory: DataCategory
  ): { allowed: boolean; agreementId?: string; restrictions?: SharingRestriction[] } {
    const agreements = this.getAgreementsBetween(fromAuthorityId, toAuthorityId);

    for (const agreement of agreements) {
      if (agreement.coveredDataTypes.includes(dataCategory)) {
        return {
          allowed: true,
          agreementId: agreement.id,
          restrictions: agreement.restrictions,
        };
      }
    }

    return { allowed: false };
  }

  /**
   * Sign an agreement.
   */
  signAgreement(
    agreementId: string,
    authorityId: string,
    signature: string,
    publicKey: string
  ): boolean {
    const agreement = this.agreements.get(agreementId);
    if (!agreement) return false;
    if (!agreement.parties.includes(authorityId)) return false;

    // Check if already signed
    const existingSignature = agreement.signatures.find((s) => s.authorityId === authorityId);
    if (existingSignature) return false;

    (agreement.signatures as AgreementSignature[]).push({
      authorityId,
      signedAt: new Date(),
      signature,
      publicKey,
    });

    // Check if all parties have signed
    if (agreement.signatures.length === agreement.parties.length) {
      agreement.status = 'active';
    } else {
      agreement.status = 'pending_signatures';
    }

    return true;
  }

  /**
   * Get registry statistics.
   */
  getStats(): {
    totalAuthorities: number;
    activeAuthorities: number;
    byType: Record<AuthorityType, number>;
    byTier: Record<AccessTier, number>;
    totalAgreements: number;
    activeAgreements: number;
  } {
    const authorities = Array.from(this.authorities.values());
    const agreements = Array.from(this.agreements.values());

    const byType: Record<AuthorityType, number> = {
      government_agency: 0,
      international_body: 0,
      national_entity: 0,
      regional_authority: 0,
      industry_consortium: 0,
      research_institution: 0,
    };

    const byTier: Record<AccessTier, number> = {
      public: 0,
      restricted: 0,
      confidential: 0,
      classified: 0,
    };

    for (const authority of authorities) {
      byType[authority.type]++;
      byTier[authority.accessTier]++;
    }

    return {
      totalAuthorities: authorities.length,
      activeAuthorities: authorities.filter((a) => a.status === 'active').length,
      byType,
      byTier,
      totalAgreements: agreements.length,
      activeAgreements: agreements.filter((a) => a.status === 'active').length,
    };
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Create default permissions for an access tier.
 */
export function getDefaultPermissions(tier: AccessTier): AuthorityPermission[] {
  return [...DEFAULT_AUTHORITY_PERMISSIONS[tier]];
}

/**
 * Validate authority configuration.
 */
export function validateAuthorityConfig(
  config: Partial<RegulatoryAuthority>
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!config.name || config.name.trim().length < 3) {
    errors.push('Authority name must be at least 3 characters');
  }

  if (!config.type) {
    errors.push('Authority type is required');
  }

  if (!config.jurisdiction) {
    errors.push('Jurisdiction scope is required');
  }

  if (!config.regions || config.regions.length === 0) {
    errors.push('At least one region must be specified');
  }

  if (!config.nodeId) {
    errors.push('Federation node ID is required');
  }

  if (!config.publicKey) {
    errors.push('Public key is required for secure communication');
  }

  if (!config.contactInfo?.email) {
    errors.push('Contact email is required');
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}
