import type {
  DpopClaims,
  DpopHeader,
  DpopKeyPair,
  DpopProof,
  DpopProofOptions,
  JsonWebKey,
  SolidSidecarLogger,
} from '../types';
import {
  base64UrlEncode,
  environment,
  generateUuid,
  nullLogger,
  sha256Base64UrlSync,
} from '../utils';

export type DpopAlgorithm =
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'EdDSA';

export interface DpopKeyStoreConfig {
  storage?: DpopKeyStorage;
  defaultAlgorithm?: DpopAlgorithm;
  ecKeySize?: 256 | 384 | 521;
  rsaKeySize?: 2048 | 4096;
  autoRotate?: boolean;
  rotationInterval?: number;
  maxKeys?: number;
  logger?: SolidSidecarLogger;
}

type ResolvedDpopKeyStoreConfig = Omit<
  Required<DpopKeyStoreConfig>,
  'storage'
> & {
  storage: DpopKeyStorage | undefined;
};

export const DEFAULT_DPOP_KEYSTORE_CONFIG: Omit<
  ResolvedDpopKeyStoreConfig,
  'storage'
> = {
  defaultAlgorithm: 'ES256',
  ecKeySize: 256,
  rsaKeySize: 2048,
  autoRotate: false,
  rotationInterval: 7 * 24 * 60 * 60 * 1000,
  maxKeys: 10,
  logger: nullLogger,
};

export interface DpopKeyStorage {
  getKey(kid: string): Promise<DpopKeyPair | null>;
  setKey(kid: string, keyPair: DpopKeyPair): Promise<void>;
  deleteKey(kid: string): Promise<void>;
  listKeys(): Promise<string[]>;
  getActiveKey(): Promise<DpopKeyPair | null>;
  setActiveKey(kid: string): Promise<void>;
}

export class InMemoryKeyStore implements DpopKeyStorage {
  private readonly keys = new Map<string, DpopKeyPair>();
  private activeKeyId: string | null = null;

  public async getKey(kid: string): Promise<DpopKeyPair | null> {
    return this.keys.get(kid) ?? null;
  }

  public async setKey(kid: string, keyPair: DpopKeyPair): Promise<void> {
    this.keys.set(kid, keyPair);
    if (this.activeKeyId === null) {
      this.activeKeyId = kid;
    }
  }

  public async deleteKey(kid: string): Promise<void> {
    this.keys.delete(kid);
    if (this.activeKeyId === kid) {
      this.activeKeyId = this.keys.keys().next().value ?? null;
    }
  }

  public async listKeys(): Promise<string[]> {
    return [...this.keys.keys()];
  }

  public async getActiveKey(): Promise<DpopKeyPair | null> {
    return this.activeKeyId === null
      ? null
      : (this.keys.get(this.activeKeyId) ?? null);
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

interface EncryptedKeyRecord {
  publicKey: JsonWebKey;
  encryptedPrivateKey: string;
  kid?: string;
  createdAt: number;
}

export class SecureKeyStore implements DpopKeyStorage {
  private readonly storage = new Map<string, EncryptedKeyRecord>();
  private readonly encryptionKey: Uint8Array;
  private activeKeyId: string | null = null;

  constructor(encryptionKey?: string) {
    if (!environment.isNode) {
      throw new Error('SecureKeyStore requires Node.js environment');
    }
    const crypto = require('crypto');
    this.encryptionKey = encryptionKey
      ? crypto.createHash('sha256').update(encryptionKey, 'utf8').digest()
      : crypto.randomBytes(32);
  }

  private encrypt(data: string): string {
    const crypto = require('crypto');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(
      'aes-256-gcm',
      this.encryptionKey,
      iv
    );
    const ciphertext = Buffer.concat([
      cipher.update(data, 'utf8'),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([iv, authTag, ciphertext]).toString('base64');
  }

  private decrypt(encoded: string): string {
    const crypto = require('crypto');
    const data = Buffer.from(encoded, 'base64');
    if (data.length < 29) {
      throw new Error('Encrypted DPoP key record is malformed');
    }
    const iv = data.subarray(0, 12);
    const authTag = data.subarray(12, 28);
    const ciphertext = data.subarray(28);
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      this.encryptionKey,
      iv
    );
    decipher.setAuthTag(authTag);
    return Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]).toString('utf8');
  }

  public async getKey(kid: string): Promise<DpopKeyPair | null> {
    const stored = this.storage.get(kid);
    if (!stored) {
      return null;
    }
    return {
      publicKey: stored.publicKey,
      privateKey: JSON.parse(
        this.decrypt(stored.encryptedPrivateKey)
      ) as JsonWebKey,
      ...(stored.kid && { kid: stored.kid }),
      createdAt: stored.createdAt,
    };
  }

  public async setKey(kid: string, keyPair: DpopKeyPair): Promise<void> {
    this.storage.set(kid, {
      publicKey: keyPair.publicKey,
      encryptedPrivateKey: this.encrypt(JSON.stringify(keyPair.privateKey)),
      ...(keyPair.kid && { kid: keyPair.kid }),
      createdAt: keyPair.createdAt,
    });
    if (this.activeKeyId === null) {
      this.activeKeyId = kid;
    }
  }

  public async deleteKey(kid: string): Promise<void> {
    this.storage.delete(kid);
    if (this.activeKeyId === kid) {
      this.activeKeyId = this.storage.keys().next().value ?? null;
    }
  }

  public async listKeys(): Promise<string[]> {
    return [...this.storage.keys()];
  }

  public async getActiveKey(): Promise<DpopKeyPair | null> {
    return this.activeKeyId === null
      ? null
      : this.getKey(this.activeKeyId);
  }

  public async setActiveKey(kid: string): Promise<void> {
    if (!this.storage.has(kid)) {
      throw new Error(`Key ${kid} not found`);
    }
    this.activeKeyId = kid;
  }
}

export class DpopKeyStore {
  private readonly config: ResolvedDpopKeyStoreConfig;
  private readonly storage: DpopKeyStorage;
  private readonly logger: SolidSidecarLogger;

  constructor(config: DpopKeyStoreConfig = {}) {
    this.config = {
      ...DEFAULT_DPOP_KEYSTORE_CONFIG,
      ...config,
      storage: config.storage,
      defaultAlgorithm:
        config.defaultAlgorithm ??
        DEFAULT_DPOP_KEYSTORE_CONFIG.defaultAlgorithm,
      ecKeySize:
        config.ecKeySize ?? DEFAULT_DPOP_KEYSTORE_CONFIG.ecKeySize,
      rsaKeySize:
        config.rsaKeySize ?? DEFAULT_DPOP_KEYSTORE_CONFIG.rsaKeySize,
      autoRotate:
        config.autoRotate ?? DEFAULT_DPOP_KEYSTORE_CONFIG.autoRotate,
      rotationInterval:
        config.rotationInterval ??
        DEFAULT_DPOP_KEYSTORE_CONFIG.rotationInterval,
      maxKeys: config.maxKeys ?? DEFAULT_DPOP_KEYSTORE_CONFIG.maxKeys,
      logger: config.logger ?? DEFAULT_DPOP_KEYSTORE_CONFIG.logger,
    };
    this.storage = this.config.storage ?? new InMemoryKeyStore();
    this.logger = this.config.logger;
  }

  private async generateNodeKeyPair(
    algorithm: DpopAlgorithm
  ): Promise<DpopKeyPair> {
    const crypto = require('crypto');
    let generated: { publicKey: JsonWebKey; privateKey: JsonWebKey };

    if (algorithm.startsWith('ES')) {
      const curves: Record<string, string> = {
        ES256: 'P-256',
        ES384: 'P-384',
        ES512: 'P-521',
      };
      generated = crypto.generateKeyPairSync('ec', {
        namedCurve: curves[algorithm],
        publicKeyEncoding: { type: 'spki', format: 'jwk' },
        privateKeyEncoding: { type: 'pkcs8', format: 'jwk' },
      });
    } else if (algorithm.startsWith('RS')) {
      generated = crypto.generateKeyPairSync('rsa', {
        modulusLength: this.config.rsaKeySize,
        publicExponent: 65537,
        publicKeyEncoding: { type: 'spki', format: 'jwk' },
        privateKeyEncoding: { type: 'pkcs8', format: 'jwk' },
      });
    } else {
      generated = crypto.generateKeyPairSync('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'jwk' },
        privateKeyEncoding: { type: 'pkcs8', format: 'jwk' },
      });
    }

    generated.publicKey.alg = algorithm;
    generated.privateKey.alg = algorithm;
    return {
      publicKey: generated.publicKey,
      privateKey: generated.privateKey,
      kid: generateUuid(),
      createdAt: Date.now(),
    };
  }

  public async generateKeyPair(
    algorithm: DpopAlgorithm = this.config.defaultAlgorithm
  ): Promise<DpopKeyPair> {
    if (!environment.isNode) {
      throw new Error(
        'DPoP key generation currently requires the Node.js crypto runtime'
      );
    }
    const keyPair = await this.generateNodeKeyPair(algorithm);
    const kid = keyPair.kid ?? generateUuid();
    keyPair.kid = kid;
    await this.storage.setKey(kid, keyPair);
    await this.storage.setActiveKey(kid);
    this.logger.debug('Generated new DPoP key pair', {
      kid,
      algorithm,
    });
    return keyPair;
  }

  public async getKeyPair(kid: string): Promise<DpopKeyPair | null> {
    return this.storage.getKey(kid);
  }

  public async getActiveKeyPair(): Promise<DpopKeyPair | null> {
    return this.storage.getActiveKey();
  }

  public async setActiveKeyPair(kid: string): Promise<void> {
    await this.storage.setActiveKey(kid);
  }

  public async listKeyPairs(): Promise<string[]> {
    return this.storage.listKeys();
  }

  public async deleteKeyPair(kid: string): Promise<void> {
    await this.storage.deleteKey(kid);
  }

  public async rotateKeyPair(): Promise<DpopKeyPair> {
    const newKeyPair = await this.generateKeyPair(
      this.config.defaultAlgorithm
    );
    const keys = await Promise.all(
      (await this.storage.listKeys()).map(async kid => ({
        kid,
        pair: await this.storage.getKey(kid),
      }))
    );
    const removable = keys
      .filter(
        item =>
          item.kid !== newKeyPair.kid && item.pair !== null
      )
      .sort(
        (left, right) =>
          (left.pair?.createdAt ?? 0) - (right.pair?.createdAt ?? 0)
      );
    while ((await this.storage.listKeys()).length > this.config.maxKeys) {
      const oldest = removable.shift();
      if (!oldest) {
        break;
      }
      await this.storage.deleteKey(oldest.kid);
    }
    return newKeyPair;
  }

  public async generateDpopProof(
    options: DpopProofOptions
  ): Promise<DpopProof> {
    const keyPair = await this.storage.getActiveKey();
    if (!keyPair) {
      throw new Error(
        'No active DPoP key pair available. Generate a key pair first.'
      );
    }

    const algorithm = this.getAlgorithmFromKey(keyPair.publicKey);
    const header: DpopHeader = {
      typ: 'dpop+jwt',
      alg: algorithm,
      jwk: this.toPublicJwk(keyPair.publicKey),
    };
    const normalizedUrl = new URL(options.url);
    normalizedUrl.search = '';
    normalizedUrl.hash = '';
    const claims: DpopClaims = {
      htm: options.method.toUpperCase() as DpopClaims['htm'],
      htu: normalizedUrl.toString(),
      jti: options.jti ?? generateUuid(),
      iat: options.iat ?? Math.floor(Date.now() / 1000),
      ...(options.accessToken && {
        ath: sha256Base64UrlSync(options.accessToken),
      }),
    };

    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedClaims = base64UrlEncode(JSON.stringify(claims));
    const signingInput = `${encodedHeader}.${encodedClaims}`;
    const signature = await this.sign(
      signingInput,
      keyPair.privateKey,
      algorithm
    );
    const encodedSignature = base64UrlEncode(signature);
    return {
      jwt: `${signingInput}.${encodedSignature}`,
      header,
      claims,
      signature: encodedSignature,
    };
  }

  private getAlgorithmFromKey(jwk: JsonWebKey): DpopAlgorithm {
    const supported = new Set<DpopAlgorithm>([
      'ES256',
      'ES384',
      'ES512',
      'RS256',
      'RS384',
      'RS512',
      'EdDSA',
    ]);
    if (jwk.alg && supported.has(jwk.alg as DpopAlgorithm)) {
      return jwk.alg as DpopAlgorithm;
    }
    if (jwk.kty === 'EC') {
      if (jwk.crv === 'P-384') return 'ES384';
      if (jwk.crv === 'P-521') return 'ES512';
      return 'ES256';
    }
    if (jwk.kty === 'RSA') return 'RS256';
    if (jwk.kty === 'OKP') return 'EdDSA';
    throw new Error(`Unsupported DPoP key type: ${jwk.kty ?? 'unknown'}`);
  }

  private toPublicJwk(jwk: JsonWebKey): JsonWebKey {
    return {
      kty: jwk.kty,
      use: 'sig',
      ...(jwk.crv && { crv: jwk.crv }),
      ...(jwk.x && { x: jwk.x }),
      ...(jwk.y && { y: jwk.y }),
      ...(jwk.n && { n: jwk.n }),
      ...(jwk.e && { e: jwk.e }),
    };
  }

  private async sign(
    data: string,
    privateKey: JsonWebKey,
    algorithm: DpopAlgorithm
  ): Promise<Uint8Array> {
    if (!environment.isNode) {
      throw new Error('DPoP signing currently requires Node.js crypto');
    }
    const crypto = require('crypto');
    const keyObject = crypto.createPrivateKey({
      key: privateKey,
      format: 'jwk',
    });
    const digest =
      algorithm === 'EdDSA' ? null : `sha${algorithm.slice(2)}`;
    return crypto.sign(digest, Buffer.from(data, 'utf8'), {
      key: keyObject,
      ...(algorithm.startsWith('ES') && {
        dsaEncoding: 'ieee-p1363',
      }),
    });
  }

  public getStorage(): DpopKeyStorage {
    return this.storage;
  }

  public async clear(): Promise<void> {
    for (const kid of await this.storage.listKeys()) {
      await this.storage.deleteKey(kid);
    }
  }
}
