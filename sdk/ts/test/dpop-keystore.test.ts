/**
 * Solid Sidecar TypeScript SDK - DPoP Key Store Tests
 * Phase: 27 - SDK/Client Compatibility Layer
 * Version: v1.0.0
 * Created: 2026-07-07
 * Author: Mistral Vibe
 * License: MIT
 */

import {
  DpopKeyStore,
  InMemoryKeyStore,
  SecureKeyStore,
  DEFAULT_DPOP_KEYSTORE_CONFIG,
} from '../src/auth/dpop-keystore';

describe('DpopKeyStore', () => {
  describe('Initialization', () => {
    it('should initialize with default configuration', () => {
      const keyStore = new DpopKeyStore();
      expect(keyStore).toBeInstanceOf(DpopKeyStore);
    });

    it('should initialize with custom configuration', () => {
      const customConfig = {
        defaultAlgorithm: 'ES384',
        ecKeySize: 384,
        autoRotate: true,
      };
      
      const keyStore = new DpopKeyStore(customConfig);
      expect(keyStore).toBeInstanceOf(DpopKeyStore);
    });

    it('should accept custom storage', () => {
      const storage = new InMemoryKeyStore();
      const keyStore = new DpopKeyStore({ storage });
      expect(keyStore.getStorage()).toBe(storage);
    });
  });

  describe('Key Generation', () => {
    it('should generate EC256 key pair by default', async () => {
      const keyStore = new DpopKeyStore();
      const keyPair = await keyStore.generateKeyPair();
      
      expect(keyPair).toHaveProperty('privateKey');
      expect(keyPair).toHaveProperty('publicKey');
      expect(keyPair).toHaveProperty('kid');
      expect(keyPair).toHaveProperty('createdAt');
      expect(keyPair.publicKey.kty).toBe('EC');
      expect(keyPair.publicKey.crv).toBe('P-256');
    });

    it('should generate ES256 key pair', async () => {
      const keyStore = new DpopKeyStore({ defaultAlgorithm: 'ES256' });
      const keyPair = await keyStore.generateKeyPair();
      
      expect(keyPair.publicKey.kty).toBe('EC');
      expect(keyPair.publicKey.crv).toBe('P-256');
    });

    it('should generate ES384 key pair', async () => {
      const keyStore = new DpopKeyStore({ defaultAlgorithm: 'ES384', ecKeySize: 384 });
      const keyPair = await keyStore.generateKeyPair();
      
      expect(keyPair.publicKey.kty).toBe('EC');
      expect(keyPair.publicKey.crv).toBe('P-384');
    });

    it('should generate RSA key pair', async () => {
      const keyStore = new DpopKeyStore({ defaultAlgorithm: 'RS256' });
      const keyPair = await keyStore.generateKeyPair();
      
      expect(keyPair.publicKey.kty).toBe('RSA');
    });

    it('should generate Ed25519 key pair', async () => {
      const keyStore = new DpopKeyStore({ defaultAlgorithm: 'EdDSA' });
      const keyPair = await keyStore.generateKeyPair();
      
      expect(keyPair.publicKey.kty).toBe('OKP');
    });

    it('should store generated key pair', async () => {
      const keyStore = new DpopKeyStore();
      const keyPair = await keyStore.generateKeyPair();
      
      const activeKey = await keyStore.getActiveKeyPair();
      expect(activeKey).not.toBeNull();
      expect(activeKey?.kid).toBe(keyPair.kid);
    });
  });

  describe('Key Management', () => {
    it('should get key pair by ID', async () => {
      const keyStore = new DpopKeyStore();
      const keyPair = await keyStore.generateKeyPair();
      
      const retrieved = await keyStore.getKeyPair(keyPair.kid!);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.kid).toBe(keyPair.kid);
    });

    it('should return null for non-existent key', async () => {
      const keyStore = new DpopKeyStore();
      const result = await keyStore.getKeyPair('non-existent');
      expect(result).toBeNull();
    });

    it('should get active key pair', async () => {
      const keyStore = new DpopKeyStore();
      await keyStore.generateKeyPair();
      
      const activeKey = await keyStore.getActiveKeyPair();
      expect(activeKey).not.toBeNull();
    });

    it('should list all key pairs', async () => {
      const keyStore = new DpopKeyStore();
      await keyStore.generateKeyPair();
      await keyStore.generateKeyPair();
      await keyStore.generateKeyPair();
      
      const keyIds = await keyStore.listKeyPairs();
      expect(keyIds.length).toBe(3);
    });

    it('should set active key pair', async () => {
      const keyStore = new DpopKeyStore();
      const key1 = await keyStore.generateKeyPair();
      const key2 = await keyStore.generateKeyPair();
      
      await keyStore.setActiveKeyPair(key1.kid!);
      const active = await keyStore.getActiveKeyPair();
      
      expect(active?.kid).toBe(key1.kid);
    });

    it('should delete key pair', async () => {
      const keyStore = new DpopKeyStore();
      const keyPair = await keyStore.generateKeyPair();
      
      await keyStore.deleteKeyPair(keyPair.kid!);
      const deleted = await keyStore.getKeyPair(keyPair.kid!);
      
      expect(deleted).toBeNull();
    });

    it('should rotate key pair', async () => {
      const keyStore = new DpopKeyStore({ maxKeys: 2 });
      const oldKey = await keyStore.generateKeyPair();
      
      const newKey = await keyStore.rotateKeyPair();
      
      expect(newKey.kid).not.toBe(oldKey.kid);
      
      const active = await keyStore.getActiveKeyPair();
      expect(active?.kid).toBe(newKey.kid);
    });

    it('should limit number of keys on rotation', async () => {
      const keyStore = new DpopKeyStore({ maxKeys: 2 });
      await keyStore.generateKeyPair();
      await keyStore.generateKeyPair();
      
      // This should trigger cleanup of old keys
      await keyStore.rotateKeyPair();
      
      const keyIds = await keyStore.listKeyPairs();
      expect(keyIds.length).toBeLessThanOrEqual(2);
    });

    it('should clear all keys', async () => {
      const keyStore = new DpopKeyStore();
      await keyStore.generateKeyPair();
      await keyStore.generateKeyPair();
      
      await keyStore.clear();
      
      const keyIds = await keyStore.listKeyPairs();
      expect(keyIds.length).toBe(0);
    });
  });

  describe('DPoP Proof Generation', () => {
    it('should generate DPoP proof', async () => {
      const keyStore = new DpopKeyStore();
      await keyStore.generateKeyPair();
      
      const proof = await keyStore.generateDpopProof({
        method: 'GET',
        url: 'https://example.com/resource',
      });
      
      expect(proof).toHaveProperty('jwt');
      expect(proof).toHaveProperty('header');
      expect(proof).toHaveProperty('claims');
      expect(proof).toHaveProperty('signature');
      
      expect(proof.header.typ).toBe('dpop+jwt');
      expect(proof.header.alg).toBe('ES256');
      expect(proof.header.jwk).toBeDefined();
      
      expect(proof.claims.htm).toBe('GET');
      expect(proof.claims.htu).toBe('https://example.com/resource');
      expect(proof.claims.jti).toBeDefined();
      expect(proof.claims.iat).toBeDefined();
    });

    it('should include ath claim when access token is provided', async () => {
      const keyStore = new DpopKeyStore();
      await keyStore.generateKeyPair();
      
      const accessToken = 'test-access-token';
      const proof = await keyStore.generateDpopProof({
        method: 'GET',
        url: 'https://example.com/resource',
        accessToken,
      });
      
      expect(proof.claims.ath).toBeDefined();
    });

    it('should normalize URL by removing query parameters and fragments', async () => {
      const keyStore = new DpopKeyStore();
      await keyStore.generateKeyPair();
      
      const proof = await keyStore.generateDpopProof({
        method: 'GET',
        url: 'https://example.com/resource?query=1#fragment',
      });
      
      expect(proof.claims.htu).toBe('https://example.com/resource');
    });

    it('should use custom jti if provided', async () => {
      const keyStore = new DpopKeyStore();
      await keyStore.generateKeyPair();
      
      const customJti = 'custom-nonce-123';
      const proof = await keyStore.generateDpopProof({
        method: 'GET',
        url: 'https://example.com/resource',
        jti: customJti,
      });
      
      expect(proof.claims.jti).toBe(customJti);
    });

    it('should use custom iat if provided', async () => {
      const keyStore = new DpopKeyStore();
      await keyStore.generateKeyPair();
      
      const customIat = Math.floor(Date.now() / 1000) - 1000;
      const proof = await keyStore.generateDpopProof({
        method: 'GET',
        url: 'https://example.com/resource',
        iat: customIat,
      });
      
      expect(proof.claims.iat).toBe(customIat);
    });

    it('should use active key pair by default', async () => {
      const keyStore = new DpopKeyStore();
      const key1 = await keyStore.generateKeyPair();
      const key2 = await keyStore.generateKeyPair();
      
      await keyStore.setActiveKeyPair(key1.kid!);
      
      const proof = await keyStore.generateDpopProof({
        method: 'GET',
        url: 'https://example.com/resource',
      });
      
      // The proof should use the active key
      expect(proof.header.jwk).toEqual(key1.publicKey);
    });
  });

  describe('Key Algorithm Support', () => {
    it('should get algorithm from EC key', () => {
      const keyStore = new DpopKeyStore();
      const getAlgorithmFromKey = (keyStore as any).getAlgorithmFromKey;
      
      expect(getAlgorithmFromKey({ kty: 'EC', crv: 'P-256' })).toBe('ES256');
      expect(getAlgorithmFromKey({ kty: 'EC', crv: 'P-384' })).toBe('ES384');
      expect(getAlgorithmFromKey({ kty: 'EC', crv: 'P-521' })).toBe('ES512');
    });

    it('should get algorithm from RSA key', () => {
      const keyStore = new DpopKeyStore();
      const getAlgorithmFromKey = (keyStore as any).getAlgorithmFromKey;
      
      expect(getAlgorithmFromKey({ kty: 'RSA' })).toBe('RS256');
    });

    it('should get algorithm from OKP (Ed25519) key', () => {
      const keyStore = new DpopKeyStore();
      const getAlgorithmFromKey = (keyStore as any).getAlgorithmFromKey;
      
      expect(getAlgorithmFromKey({ kty: 'OKP' })).toBe('EdDSA');
    });
  });

  describe('Key Normalization', () => {
    it('should normalize JWK for DPoP', () => {
      const keyStore = new DpopKeyStore();
      const normalizeJwk = (keyStore as any).normalizeJwk;
      
      const jwk = {
        kty: 'EC',
        crv: 'P-256',
        x: 'abc',
        y: 'def',
        d: 'private',
        kid: 'key-123',
        alg: 'ES256',
        use: 'sig',
      };
      
      const normalized = normalizeJwk(jwk);
      
      expect(normalized.kty).toBe('EC');
      expect(normalized.use).toBe('sig');
      expect(normalized.crv).toBe('P-256');
      expect(normalized.x).toBe('abc');
      expect(normalized.y).toBe('def');
      // Private key should be preserved for DPoP
      expect(normalized.d).toBe('private');
    });
  });
});

describe('InMemoryKeyStore', () => {
  it('should store and retrieve key pairs', async () => {
    const storage = new InMemoryKeyStore();
    
    const keyPair = {
      privateKey: { kty: 'EC', crv: 'P-256', x: 'a', y: 'b', d: 'c' } as any,
      publicKey: { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' } as any,
      kid: 'test-key',
      createdAt: Date.now(),
    };
    
    await storage.setKey('test-key', keyPair);
    const retrieved = await storage.getKey('test-key');
    
    expect(retrieved).toEqual(keyPair);
  });

  it('should delete key pairs', async () => {
    const storage = new InMemoryKeyStore();
    const keyPair = {
      privateKey: {} as any,
      publicKey: {} as any,
      kid: 'test-key',
      createdAt: Date.now(),
    };
    
    await storage.setKey('test-key', keyPair);
    await storage.deleteKey('test-key');
    
    const retrieved = await storage.getKey('test-key');
    expect(retrieved).toBeNull();
  });

  it('should list all keys', async () => {
    const storage = new InMemoryKeyStore();
    
    await storage.setKey('key1', { kid: 'key1' } as any);
    await storage.setKey('key2', { kid: 'key2' } as any);
    await storage.setKey('key3', { kid: 'key3' } as any);
    
    const keys = await storage.listKeys();
    expect(keys.sort()).toEqual(['key1', 'key2', 'key3']);
  });

  it('should get and set active key', async () => {
    const storage = new InMemoryKeyStore();
    
    await storage.setKey('key1', { kid: 'key1' } as any);
    await storage.setKey('key2', { kid: 'key2' } as any);
    
    await storage.setActiveKey('key2');
    const active = await storage.getActiveKey();
    
    expect(active?.kid).toBe('key2');
  });

  it('should return first key as active if none set', async () => {
    const storage = new InMemoryKeyStore();
    
    await storage.setKey('key1', { kid: 'key1' } as any);
    const active = await storage.getActiveKey();
    
    expect(active?.kid).toBe('key1');
  });
});
