/**
 * Solid Sidecar TypeScript SDK - DPoP Key Store
 * Phase: 27 - SDK/Client Compatibility Layer
 * Version: v1.0.0
 * Created: 2026-07-07
 * Author: Mistral Vibe
 * License: MIT
 *
 * This file contains the DPoP key store implementation for generating,
 * storing, and managing DPoP key pairs.
 *
 * Security Level: CRITICAL - This handles cryptographic key material
 */

import type { DpopKeyPair, JsonWebKey, DpopProof, DpopProofOptions } from '../types';
import { generateUuid, sha256Base64UrlSync, base64UrlEncode } from '../utils';
import { environment } from '../utils';

// ============================================================================
// DPoP Key Store Configuration
// ============================================================================

/**
 * Configuration for DPoP key store
 */
export interface DpopKeyStoreConfig {
  /** Key storage backend (default: InMemoryKeyStore) */
  storage?: DpopKeyStorage;
  
  /** Default key algorithm (default: ES256) */
  defaultAlgorithm?: 'ES256' | 'ES384' | 'ES512' | 'RS256' | 'RS384' | 'RS512' | 'EdDSA';
  
  /** Key size for EC keys (default: 256 for ES256) */
  ecKeySize?: 256 | 384 | 521;
  
  /** RSA key size (default: 2048) */
  rsaKeySize?: 2048 | 4096;
  
  /** Whether to rotate keys automatically */
  autoRotate?: boolean;
  
  /** Key rotation interval in milliseconds (default: 7 days) */
  rotationInterval?: number;
  
  /** Maximum number of keys to keep */
  maxKeys?: number;
}

/**
 * Default DPoP key store configuration
 */
export const DEFAULT_DPOP_KEYSTORE_CONFIG: Required<DpopKeyStoreConfig> = {
  storage: undefined,
  defaultAlgorithm: 'ES256',
  ecKeySize: 256,
  rsaKeySize: 2048,
  autoRotate: false,
  rotationInterval: 7 * 24 * 60 * 60 * 1000, // 7 days
  maxKeys: 10,
};

// ============================================================================
// Key Storage Interface
// ============================================================================

/**
 * Interface for DPoP key storage backends
 */
export interface DpopKeyStorage {
  /**
   * Retrieves a key pair by ID
   */
  getKey(kid: string): Promise<DpopKeyPair | null>;

  /**
   * Stores a key pair
   */
  setKey(kid: string, keyPair: DpopKeyPair): Promise<void>;

  /**
   * Deletes a key pair
   */
  deleteKey(kid: string): Promise<void>;

  /**
   * Lists all key IDs
   */
  listKeys(): Promise<string[]>;

  /**
   * Gets the active key (most recently used or created)
   */
  getActiveKey(): Promise<DpopKeyPair | null>;

  /**
   * Sets the active key
   */
  setActiveKey(kid: string): Promise<void>;
}

// ============================================================================
// In-Memory Key Storage
// ============================================================================

/**
 * In-memory key storage implementation
 * 
 * Note: This is suitable for testing but NOT for production.
 * In production, use SecureKeyStore or BrowserKeyStore.
 */
export class InMemoryKeyStore implements DpopKeyStorage {
  private readonly keys: Map<string, DpopKeyPair> = new Map();
  private activeKeyId: string | null = null;

  public async getKey(kid: string): Promise<DpopKeyPair | null> {
    return this.keys.get(kid) || null;
  }

  public async setKey(kid: string, keyPair: DpopKeyPair): Promise<void> {
    this.keys.set(kid, keyPair);
    // Set as active if it's the first key
    if (this.keys.size === 1) {
      this.activeKeyId = kid;
    }
  }

  public async deleteKey(kid: string): Promise<void> {
    this.keys.delete(kid);
    if (this.activeKeyId === kid) {
      this.activeKeyId = this.keys.keys().next().value || null;
    }
  }

  public async listKeys(): Promise<string[]> {
    return Array.from(this.keys.keys());
  }

  public async getActiveKey(): Promise<DpopKeyPair | null> {
    if (!this.activeKeyId) {
      return null;
    }
    return this.keys.get(this.activeKeyId) || null;
  }

  public async setActiveKey(kid: string): Promise<void> {
    if (!this.keys.has(kid)) {
      throw new Error(`Key ${kid} not found`);
    }
    this.activeKeyId = kid;
  }

  public async clear(): Promise<void> {
    this.keys.clear();
    this.activeKeyId = null;
  }
}

// ============================================================================
// Secure Key Storage (Node.js)
// ============================================================================

/**
 * Secure key storage using Node.js crypto and secure storage
 * 
 * This implementation encrypts private keys before storing them.
 * In production, consider using a dedicated key management service.
 */
export class SecureKeyStore implements DpopKeyStorage {
  private readonly storage: Map<string, { publicKey: JsonWebKey; encryptedPrivateKey: string }> = new Map();
  private readonly encryptionKey: Uint8Array;
  private activeKeyId: string | null = null;

  constructor(encryptionKey?: string) {
    if (!environment.isNode) {
      throw new Error('SecureKeyStore requires Node.js environment');
    }

    // Generate or use provided encryption key
    if (encryptionKey) {
      this.encryptionKey = new TextEncoder().encode(encryptionKey);
    } else {
      this.encryptionKey = require('crypto').randomBytes(32);
    }
  }

  private async encrypt(data: string): Promise<string> {
    const crypto = require('crypto');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    const encrypted = Buffer.concat([
      cipher.update(data, 'utf8'),
      cipher.final(),
      cipher.getAuthTag(),
    ]);
    return Buffer.concat([iv, encrypted]).toString('base64');
  }

  private async decrypt(encryptedData: string): Promise<string> {
    const crypto = require('crypto');
    const data = Buffer.from(encryptedData, 'base64');
    const iv = data.subarray(0, 16);
    const encrypted = data.subarray(16, data.length - 16);
    const authTag = data.subarray(data.length - 16);
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]).toString('utf8');
  }

  public async getKey(kid: string): Promise<DpopKeyPair | null> {
    const stored = this.storage.get(kid);
    if (!stored) {
      return null;
    }

    const privateKey = await this.decrypt(stored.encryptedPrivateKey);
    return {
      ...stored,
      privateKey: JSON.parse(privateKey),
    };
  }

  public async setKey(kid: string, keyPair: DpopKeyPair): Promise<void> {
    const encryptedPrivateKey = await this.encrypt(JSON.stringify(keyPair.privateKey));
    this.storage.set(kid, {
      publicKey: keyPair.publicKey,
      encryptedPrivateKey,
    });
    if (this.storage.size === 1) {
      this.activeKeyId = kid;
    }
  }

  public async deleteKey(kid: string): Promise<void> {
    this.storage.delete(kid);
    if (this.activeKeyId === kid) {
      this.activeKeyId = this.storage.keys().next().value || null;
    }
  }

  public async listKeys(): Promise<string[]> {
    return Array.from(this.storage.keys());
  }

  public async getActiveKey(): Promise<DpopKeyPair | null> {
    if (!this.activeKeyId) {
      return null;
    }
    return this.getKey(this.activeKeyId);
  }

  public async setActiveKey(kid: string): Promise<void> {
    if (!this.storage.has(kid)) {
      throw new Error(`Key ${kid} not found`);
    }
    this.activeKeyId = kid;
  }
}

// ============================================================================
// DPoP Key Store
// ============================================================================

/**
 * DPoP Key Store for managing DPoP key pairs
 * 
 * Features:
 * - Key generation (EC and RSA)
 * - Key storage (in-memory, secure, or custom)
 * - Key rotation
 * - DPoP proof generation
 * - Key identification and lookup
 */
export class DpopKeyStore {
  private readonly config: Required<DpopKeyStoreConfig>;
  private readonly storage: DpopKeyStorage;
  private readonly logger: Console;

  constructor(config: DpopKeyStoreConfig = {}) {
    this.config = {
      ...DEFAULT_DPOP_KEYSTORE_CONFIG,
      ...config,
    };

    // Initialize storage
    this.storage = this.config.storage || new InMemoryKeyStore();
    this.logger = console;

    // Log initialization
    this.logger.debug('DpopKeyStore initialized', {
      defaultAlgorithm: this.config.defaultAlgorithm,
      ecKeySize: this.config.ecKeySize,
    });
  }

  // ==========================================================================
  // Key Generation
  // ==========================================================================

  /**
   * Generates a new EC key pair
   */
  private async generateEcKeyPair(kid?: string): Promise<DpopKeyPair> {
    const crypto = require('crypto');
    const { ecKeySize, defaultAlgorithm } = this.config;

    const curveMap: Record<number, string> = {
      256: 'P-256',
      384: 'P-384',
      521: 'P-521',
    };

    const algorithmMap: Record<number, 'ES256' | 'ES384' | 'ES512'> = {
      256: 'ES256',
      384: 'ES384',
      521: 'ES512',
    };

    const curve = curveMap[ecKeySize] || 'P-256';
    const algorithm = algorithmMap[ecKeySize] || defaultAlgorithm;

    // Generate key pair
    const keyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: curve,
      publicKeyEncoding: { type: 'spki', format: 'jwk' },
      privateKeyEncoding: { type: 'pkcs8', format: 'jwk' },
    });

    const now = Date.now();
    const generatedKid = kid || generateUuid();

    return {
      privateKey: keyPair.privateKey as JsonWebKey,
      publicKey: keyPair.publicKey as JsonWebKey,
      kid: generatedKid,
      createdAt: now,
    };
  }

  /**
   * Generates a new RSA key pair
   */
  private async generateRsaKeyPair(kid?: string): Promise<DpopKeyPair> {
    const crypto = require('crypto');
    const { rsaKeySize, defaultAlgorithm } = this.config;

    const algorithmMap: Record<number, 'RS256' | 'RS384' | 'RS512'> = {
      2048: 'RS256',
      4096: 'RS384',
    };

    const algorithm = algorithmMap[rsaKeySize] || defaultAlgorithm;

    // Generate key pair
    const keyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: rsaKeySize,
      publicExponent: 65537,
      publicKeyEncoding: { type: 'spki', format: 'jwk' },
      privateKeyEncoding: { type: 'pkcs8', format: 'jwk' },
    });

    const now = Date.now();
    const generatedKid = kid || generateUuid();

    return {
      privateKey: keyPair.privateKey as JsonWebKey,
      publicKey: keyPair.publicKey as JsonWebKey,
      kid: generatedKid,
      createdAt: now,
    };
  }

  /**
   * Generates a new Ed25519 key pair
   */
  private async generateEd25519KeyPair(kid?: string): Promise<DpopKeyPair> {
    const crypto = require('crypto');
    const { defaultAlgorithm } = this.config;

    // Generate key pair
    const keyPair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'jwk' },
      privateKeyEncoding: { type: 'pkcs8', format: 'jwk' },
    });

    const now = Date.now();
    const generatedKid = kid || generateUuid();

    return {
      privateKey: keyPair.privateKey as JsonWebKey,
      publicKey: keyPair.publicKey as JsonWebKey,
      kid: generatedKid,
      createdAt: now,
    };
  }

  // ==========================================================================
  // Key Management
  // ==========================================================================

  /**
   * Generates a new DPoP key pair
   */
  public async generateKeyPair(
    algorithm?: 'ES256' | 'ES384' | 'ES512' | 'RS256' | 'RS384' | 'RS512' | 'EdDSA'
  ): Promise<DpopKeyPair> {
    const alg = algorithm || this.config.defaultAlgorithm;

    let keyPair: DpopKeyPair;

    switch (alg) {
      case 'ES256':
      case 'ES384':
      case 'ES512':
        keyPair = await this.generateEcKeyPair();
        break;
      case 'RS256':
      case 'RS384':
      case 'RS512':
        keyPair = await this.generateRsaKeyPair();
        break;
      case 'EdDSA':
        keyPair = await this.generateEd25519KeyPair();
        break;
      default:
        throw new Error(`Unsupported algorithm: ${alg}`);
    }

    // Store the key
    if (!keyPair.kid) {
      keyPair.kid = generateUuid();
    }
    await this.storage.setKey(keyPair.kid, keyPair);
    await this.storage.setActiveKey(keyPair.kid);

    this.logger.debug('Generated new DPoP key pair', {
      kid: keyPair.kid,
      algorithm: alg,
    });

    return keyPair;
  }

  /**
   * Gets a key pair by ID
   */
  public async getKeyPair(kid: string): Promise<DpopKeyPair | null> {
    return this.storage.getKey(kid);
  }

  /**
   * Gets the active key pair (most recently used)
   */
  public async getActiveKeyPair(): Promise<DpopKeyPair | null> {
    return this.storage.getActiveKey();
  }

  /**
   * Sets the active key pair
   */
  public async setActiveKeyPair(kid: string): Promise<void> {
    await this.storage.setActiveKey(kid);
  }

  /**
   * Lists all key pair IDs
   */
  public async listKeyPairs(): Promise<string[]> {
    return this.storage.listKeys();
  }

  /**
   * Deletes a key pair
   */
  public async deleteKeyPair(kid: string): Promise<void> {
    await this.storage.deleteKey(kid);
    this.logger.debug('Deleted DPoP key pair', { kid });
  }

  /**
   * Rotates the active key pair
   */
  public async rotateKeyPair(): Promise<DpopKeyPair> {
    // Generate new key
    const newKeyPair = await this.generateKeyPair(this.config.defaultAlgorithm);

    // Delete old keys if we exceed maxKeys
    const keyIds = await this.listKeyPairs();
    if (keyIds.length > this.config.maxKeys) {
      // Delete oldest keys (skip the new one and active one)
      const keysToDelete = keyIds
        .filter(kid => kid !== newKeyPair.kid)
        .sort()
        .slice(0, keyIds.length - this.config.maxKeys);

      for (const kid of keysToDelete) {
        await this.deleteKeyPair(kid);
      }
    }

    return newKeyPair;
  }

  // ==========================================================================
  // DPoP Proof Generation
  // ==========================================================================

  /**
   * Generates a DPoP proof JWT
   */
  public async generateDpopProof(
    options: DpopProofOptions
  ): Promise<DpopProof> {
    // Get active key pair
    const keyPair = await this.getActiveKeyPair();
    if (!keyPair) {
      throw new Error('No active DPoP key pair available. Generate a key pair first.');
    }

    const { method, url, jti, iat, accessToken } = options;

    // Generate unique JTI if not provided
    const nonce = jti || generateUuid();

    // Use current timestamp if not provided
    const issuedAt = iat || Math.floor(Date.now() / 1000);

    // Normalize URL (remove query parameters and fragment)
    const normalizedUrl = url.split('?')[0].split('#')[0];

    // Create JWT header
    const header = {
      typ: 'dpop+jwt',
      alg: this.getAlgorithmFromKey(keyPair.publicKey),
      jwk: this.normalizeJwk(keyPair.publicKey),
    };

    // Create JWT claims
    const claims: Record<string, unknown> = {
      htm: method.toUpperCase(),
      htu: normalizedUrl,
      jti: nonce,
      iat: issuedAt,
    };

    // Add ath claim if access token is provided
    if (accessToken) {
      claims.ath = sha256Base64UrlSync(accessToken);
    }

    // Encode header and claims
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedClaims = base64UrlEncode(JSON.stringify(claims));

    // Create signing input
    const signingInput = `${encodedHeader}.${encodedClaims}`;

    // Sign with private key
    const signature = await this.sign(signingInput, keyPair.privateKey);
    const encodedSignature = base64UrlEncode(signature);

    // Create final JWT
    const jwt = `${signingInput}.${encodedSignature}`;

    return {
      jwt,
      header,
      claims,
      signature: encodedSignature,
    };
  }

  /**
   * Gets the algorithm from a JWK
   */
  private getAlgorithmFromKey(jwk: JsonWebKey): string {
    if (jwk.kty === 'EC') {
      switch (jwk.crv) {
        case 'P-256': return 'ES256';
        case 'P-384': return 'ES384';
        case 'P-521': return 'ES512';
        default: return 'ES256';
      }
    } else if (jwk.kty === 'RSA') {
      return 'RS256';
    } else if (jwk.kty === 'OKP') {
      return 'EdDSA';
    }
    return 'ES256';
  }

  /**
   * Normalizes a JWK to remove unnecessary fields for DPoP
   */
  private normalizeJwk(jwk: JsonWebKey): JsonWebKey {
    return {
      kty: jwk.kty,
      use: 'sig',
      ...(jwk.crv && { crv: jwk.crv }),
      ...(jwk.x && { x: jwk.x }),
      ...(jwk.y && { y: jwk.y }),
      ...(jwk.n && { n: jwk.n }),
      ...(jwk.e && { e: jwk.e }),
      ...(jwk.d && { d: jwk.d }),
    };
  }

  /**
   * Signs data with a private key
   */
  private async sign(data: string, privateKey: JsonWebKey): Promise<Uint8Array> {
    if (environment.isNode) {
      const crypto = require('crypto');
      const keyObject = crypto.createPrivateKey({ key: privateKey, format: 'jwk' });
      
      const algorithm = this.getAlgorithmFromKey(privateKey as JsonWebKey);
      const signature = crypto.sign(
        algorithm.replace('ES', '').replace('RS', '').replace('Ed', ''),
        Buffer.from(data, 'utf8'),
        keyObject
      );
      
      return signature;
    } else {
      // Browser implementation using Web Crypto
      const keyObject = await crypto.subtle.importKey(
        'jwk',
        privateKey,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign']
      );
      
      const signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        keyObject,
        new TextEncoder().encode(data)
      );
      
      return new Uint8Array(signature);
    }
  }

  // ==========================================================================
  // Storage Access
  // ==========================================================================

  /**
   * Gets the underlying storage
   */
  public getStorage(): DpopKeyStorage {
    return this.storage;
  }

  /**
   * Clears all keys from storage
   */
  public async clear(): Promise<void> {
    const keyIds = await this.listKeyPairs();
    for (const kid of keyIds) {
      await this.deleteKeyPair(kid);
    }
    this.activeKeyId = null;
  }
}

// ============================================================================
// Exports
// ============================================================================

export { InMemoryKeyStore, SecureKeyStore };
export type { DpopKeyStorage };
