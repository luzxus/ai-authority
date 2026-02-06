/**
 * Cryptographic Utilities
 *
 * Provides cryptographic primitives for signing, verification,
 * and integrity checking throughout the AI Authority system.
 */

import {
  createHash,
  createSign,
  createVerify,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  generateKeyPairSync,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  scryptSync,
} from 'crypto';

// ============================================================================
// Types
// ============================================================================

export interface SignedData<T> {
  readonly data: T;
  readonly signature: string;
  readonly signedBy: string;
  readonly signedAt: Date;
  readonly algorithm: string;
}

export interface EncryptedData {
  readonly ciphertext: string;
  readonly iv: string;
  readonly salt: string;
  readonly algorithm: string;
}

export interface HashResult {
  readonly hash: string;
  readonly algorithm: string;
  readonly inputLength: number;
}

// ============================================================================
// Hashing
// ============================================================================

/**
 * Hash data using SHA-256.
 */
export function sha256(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Hash data using SHA-512.
 */
export function sha512(data: string | Buffer): string {
  return createHash('sha512').update(data).digest('hex');
}

/**
 * Hash with result metadata.
 */
export function hashWithMetadata(
  data: string | Buffer,
  algorithm: 'sha256' | 'sha512' = 'sha256'
): HashResult {
  const hash = createHash(algorithm).update(data).digest('hex');
  return {
    hash,
    algorithm,
    inputLength: typeof data === 'string' ? data.length : data.length,
  };
}

/**
 * Hash an object deterministically (sorted keys).
 */
export function hashObject(obj: unknown): string {
  const normalized = JSON.stringify(obj, Object.keys(obj as object).sort());
  return sha256(normalized);
}

// ============================================================================
// Digital Signatures
// ============================================================================

export interface KeyPair {
  readonly publicKey: string;
  readonly privateKey: string;
}

/**
 * Generate an RSA key pair.
 */
export function generateRSAKeyPair(modulusLength: 2048 | 4096 = 2048): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKey, privateKey };
}

/**
 * Generate an Ed25519 key pair (faster, smaller keys).
 */
export function generateEd25519KeyPair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKey, privateKey };
}

/**
 * Sign data with a private key.
 * Supports both RSA and Ed25519 keys.
 */
export function sign(data: string, privateKey: string): string {
  // Detect key type from PEM format
  const isEd25519 = privateKey.includes('PRIVATE KEY') && 
    (privateKey.includes('ed25519') || privateKey.length < 300);
  
  if (isEd25519) {
    // Ed25519 uses direct signing without explicit algorithm
    const key = createPrivateKey(privateKey);
    const signature = cryptoSign(null, Buffer.from(data), key);
    return signature.toString('base64');
  } else {
    // RSA keys use SHA256
    const signer = createSign('SHA256');
    signer.update(data);
    return signer.sign(privateKey, 'base64');
  }
}

/**
 * Verify a signature.
 * Supports both RSA and Ed25519 keys.
 */
export function verify(data: string, signature: string, publicKey: string): boolean {
  try {
    // Detect key type from PEM format
    const isEd25519 = publicKey.includes('PUBLIC KEY') && 
      (publicKey.includes('ed25519') || publicKey.length < 200);
    
    if (isEd25519) {
      // Ed25519 uses direct verification
      const key = createPublicKey(publicKey);
      return cryptoVerify(null, Buffer.from(data), key, Buffer.from(signature, 'base64'));
    } else {
      // RSA keys use SHA256
      const verifier = createVerify('SHA256');
      verifier.update(data);
      return verifier.verify(publicKey, signature, 'base64');
    }
  } catch {
    return false;
  }
}

/**
 * Sign data and wrap in SignedData structure.
 */
export function signData<T>(data: T, privateKey: string, signerId: string): SignedData<T> {
  const serialized = JSON.stringify(data);
  const signature = sign(serialized, privateKey);
  
  // Detect algorithm from key
  const isEd25519 = privateKey.includes('PRIVATE KEY') && 
    (privateKey.includes('ed25519') || privateKey.length < 300);

  return {
    data,
    signature,
    signedBy: signerId,
    signedAt: new Date(),
    algorithm: isEd25519 ? 'Ed25519' : 'RSA-SHA256',
  };
}

/**
 * Verify SignedData structure.
 */
export function verifySignedData<T>(signedData: SignedData<T>, publicKey: string): boolean {
  const serialized = JSON.stringify(signedData.data);
  return verify(serialized, signedData.signature, publicKey);
}

// ============================================================================
// Symmetric Encryption
// ============================================================================

const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const SALT_LENGTH = 32;
const KEY_LENGTH = 32;

/**
 * Encrypt data with a password.
 */
export function encrypt(plaintext: string, password: string): EncryptedData {
  const salt = randomBytes(SALT_LENGTH);
  const key = scryptSync(password, salt, KEY_LENGTH);
  const iv = randomBytes(IV_LENGTH);

  const cipher = createCipheriv(ENCRYPTION_ALGORITHM, key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'base64');
  encrypted += cipher.final('base64');

  // Get auth tag for GCM mode
  const authTag = cipher.getAuthTag();

  return {
    ciphertext: encrypted + ':' + authTag.toString('base64'),
    iv: iv.toString('base64'),
    salt: salt.toString('base64'),
    algorithm: ENCRYPTION_ALGORITHM,
  };
}

/**
 * Decrypt data with a password.
 */
export function decrypt(encryptedData: EncryptedData, password: string): string {
  const salt = Buffer.from(encryptedData.salt, 'base64');
  const iv = Buffer.from(encryptedData.iv, 'base64');
  const key = scryptSync(password, salt, KEY_LENGTH);

  const [ciphertext, authTagStr] = encryptedData.ciphertext.split(':');
  if (!ciphertext || !authTagStr) {
    throw new Error('Invalid encrypted data format');
  }

  const authTag = Buffer.from(authTagStr, 'base64');

  const decipher = createDecipheriv(ENCRYPTION_ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(ciphertext, 'base64', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

// ============================================================================
// Random Generation
// ============================================================================

/**
 * Generate a secure random string.
 */
export function generateRandomString(length: number): string {
  return randomBytes(Math.ceil(length / 2))
    .toString('hex')
    .slice(0, length);
}

/**
 * Generate a secure random ID.
 */
export function generateSecureId(): string {
  return randomBytes(16).toString('hex');
}

/**
 * Generate a nonce.
 */
export function generateNonce(): string {
  return randomBytes(32).toString('base64');
}

// ============================================================================
// Commitment Schemes
// ============================================================================

/**
 * Create a cryptographic commitment.
 * Used for "commit-reveal" schemes where you want to commit to a value
 * without revealing it, then reveal it later.
 */
export interface Commitment {
  readonly commitment: string;
  readonly nonce: string;
}

/**
 * Create a commitment to a value.
 */
export function commit(value: string): Commitment {
  const nonce = generateNonce();
  const commitment = sha256(value + nonce);
  return { commitment, nonce };
}

/**
 * Verify a commitment.
 */
export function verifyCommitment(
  value: string,
  commitment: string,
  nonce: string
): boolean {
  const computed = sha256(value + nonce);
  return computed === commitment;
}

// ============================================================================
// Integrity Checking
// ============================================================================

/**
 * Create a message authentication code (MAC).
 */
export function createMAC(data: string, secret: string): string {
  return createHash('sha256')
    .update(data + secret)
    .digest('hex');
}

/**
 * Verify a MAC.
 */
export function verifyMAC(data: string, mac: string, secret: string): boolean {
  const computed = createMAC(data, secret);
  // Constant-time comparison to prevent timing attacks
  if (computed.length !== mac.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < computed.length; i++) {
    result |= computed.charCodeAt(i) ^ mac.charCodeAt(i);
  }
  return result === 0;
}
