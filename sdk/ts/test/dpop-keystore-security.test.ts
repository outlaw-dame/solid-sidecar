import { createPublicKey, verify } from 'crypto';
import {
  DpopKeyStore,
  InMemoryKeyStore,
  SecureKeyStore,
  type DpopKeyStoreConfig,
} from '../src/auth/dpop-keystore';

function decodeJwtPart<T>(part: string): T {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as T;
}

describe('DPoP key-store security baseline', () => {
  it('generates a verifiable ES256 proof without private JWK material', async () => {
    const store = new DpopKeyStore({
      storage: new InMemoryKeyStore(),
      defaultAlgorithm: 'ES256',
    });
    const keyPair = await store.generateKeyPair();
    const proof = await store.generateDpopProof({
      method: 'GET',
      url: 'https://pod.example/resource?ignored=true#fragment',
      jti: 'test-jti',
      iat: 1234,
      accessToken: 'access-token',
    });

    expect(proof.header.alg).toBe('ES256');
    expect(proof.header.jwk).not.toHaveProperty('d');
    expect(proof.header.jwk).not.toHaveProperty('p');
    expect(proof.header.jwk).not.toHaveProperty('q');
    expect(proof.claims).toMatchObject({
      htm: 'GET',
      htu: 'https://pod.example/resource',
      jti: 'test-jti',
      iat: 1234,
    });

    const parts = proof.jwt.split('.');
    expect(parts).toHaveLength(3);
    const encodedHeader = parts[0]!;
    const encodedClaims = parts[1]!;
    const encodedSignature = parts[2]!;
    expect(decodeJwtPart(encodedHeader)).toEqual(proof.header);
    expect(decodeJwtPart(encodedClaims)).toEqual(proof.claims);
    expect(Buffer.from(encodedSignature, 'base64url')).toHaveLength(64);

    const publicKey = createPublicKey({
      key: keyPair.publicKey as globalThis.JsonWebKey,
      format: 'jwk',
    });
    expect(
      verify(
        'sha256',
        Buffer.from(`${encodedHeader}.${encodedClaims}`, 'utf8'),
        { key: publicKey, dsaEncoding: 'ieee-p1363' },
        Buffer.from(encodedSignature, 'base64url')
      )
    ).toBe(true);
  });

  it('preserves metadata through secure storage encryption', async () => {
    const storage = new SecureKeyStore();
    const keyStore = new DpopKeyStore({ storage });
    const generated = await keyStore.generateKeyPair('ES256');
    const restored = await storage.getKey(generated.kid!);

    expect(restored?.kid).toBe(generated.kid);
    expect(restored?.createdAt).toBe(generated.createdAt);
    expect(restored?.publicKey).toEqual(generated.publicKey);
    expect(restored?.privateKey).toEqual(generated.privateKey);
  });

  it('retains defaults when optional values are explicitly undefined', async () => {
    const explicitUndefinedConfig = {
      defaultAlgorithm: undefined,
      ecKeySize: undefined,
      rsaKeySize: undefined,
      autoRotate: undefined,
      rotationInterval: undefined,
      maxKeys: undefined,
      logger: undefined,
    } as unknown as DpopKeyStoreConfig;
    const store = new DpopKeyStore(explicitUndefinedConfig);
    const generated = await store.generateKeyPair();
    expect(generated.publicKey.alg).toBe('ES256');
  });

  it('rotates by creation time and retains the configured maximum', async () => {
    const store = new DpopKeyStore({ maxKeys: 2 });
    const first = await store.generateKeyPair('ES256');
    await new Promise(resolve => setTimeout(resolve, 2));
    const second = await store.generateKeyPair('ES256');
    await new Promise(resolve => setTimeout(resolve, 2));
    const third = await store.rotateKeyPair();

    expect(await store.listKeyPairs()).toHaveLength(2);
    expect(await store.getKeyPair(first.kid!)).toBeNull();
    expect(await store.getKeyPair(second.kid!)).not.toBeNull();
    expect(await store.getKeyPair(third.kid!)).not.toBeNull();
  });
});
