/**
 * Solid Sidecar TypeScript SDK - Authentication Manager
 * Phase: 27 - SDK/Client Compatibility Layer
 * License: MIT
 */

import type {
  DpopProof,
  DpopProofOptions,
  PkcePair,
  SolidSidecarLogger,
  TokenResponse,
  TokenSet,
} from '../types';
import { AuthenticationError, ValidationError } from '../types';
import {
  DEFAULT_DPOP_KEYSTORE_CONFIG,
  DpopKeyStore,
  type DpopKeyStoreConfig,
} from './dpop-keystore';
import {
  base64UrlEncode,
  generateUuid,
  nullLogger,
  sha256Base64UrlSync,
} from '../utils';

export interface AuthManagerConfig {
  issuerUrl: string;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  scopes?: string[];
  dpopKeyStoreConfig?: DpopKeyStoreConfig;
  useDpop?: boolean;
  logger?: SolidSidecarLogger;
}

type ResolvedAuthManagerConfig = Omit<
  Required<AuthManagerConfig>,
  'clientSecret'
> & {
  clientSecret?: string;
};

export const DEFAULT_AUTH_MANAGER_CONFIG: Pick<
  ResolvedAuthManagerConfig,
  'scopes' | 'useDpop' | 'dpopKeyStoreConfig' | 'logger'
> = {
  scopes: ['openid', 'profile', 'webid'],
  useDpop: true,
  dpopKeyStoreConfig: DEFAULT_DPOP_KEYSTORE_CONFIG,
  logger: nullLogger,
};

export interface TokenStorage {
  getTokenSet(): Promise<TokenSet | null>;
  setTokenSet(tokenSet: TokenSet): Promise<void>;
  deleteTokenSet(): Promise<void>;
  getAccessToken(): Promise<string | null>;
  getRefreshToken(): Promise<string | null>;
  getTokenExpiration(): Promise<number | null>;
}

export class InMemoryTokenStorage implements TokenStorage {
  private tokenSet: TokenSet | null = null;

  public async getTokenSet(): Promise<TokenSet | null> {
    return this.tokenSet;
  }

  public async setTokenSet(tokenSet: TokenSet): Promise<void> {
    this.tokenSet = tokenSet;
  }

  public async deleteTokenSet(): Promise<void> {
    this.tokenSet = null;
  }

  public async getAccessToken(): Promise<string | null> {
    return this.tokenSet?.access_token || null;
  }

  public async getRefreshToken(): Promise<string | null> {
    return this.tokenSet?.refresh_token || null;
  }

  public async getTokenExpiration(): Promise<number | null> {
    return this.tokenSet?.expires_at || null;
  }
}

/**
 * In-memory encrypted token storage for Node.js processes.
 *
 * This protects token material from accidental plaintext exposure inside this
 * storage object, but it is not durable storage and is not a replacement for
 * an operating-system or hardware-backed secret store.
 */
export class SecureTokenStorage implements TokenStorage {
  private readonly storage = new InMemoryTokenStorage();
  private readonly encryptionKey: Uint8Array;

  constructor(encryptionKey?: string) {
    if (encryptionKey) {
      this.encryptionKey = new TextEncoder().encode(encryptionKey);
    } else {
      this.encryptionKey = require('crypto').randomBytes(32);
    }
  }

  private async encrypt(data: TokenSet): Promise<TokenSet> {
    const crypto = require('crypto');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(
      'aes-256-gcm',
      this.encryptionKey,
      iv
    );
    const encrypted = Buffer.concat([
      cipher.update(JSON.stringify(data), 'utf8'),
      cipher.final(),
      cipher.getAuthTag(),
    ]);

    return {
      ...data,
      access_token: Buffer.concat([iv, encrypted]).toString('base64'),
      refresh_token: '',
    };
  }

  private async decrypt(encrypted: TokenSet): Promise<TokenSet> {
    const crypto = require('crypto');
    const data = Buffer.from(encrypted.access_token || '', 'base64');
    const iv = data.subarray(0, 16);
    const ciphertext = data.subarray(16, data.length - 16);
    const authTag = data.subarray(data.length - 16);
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      this.encryptionKey,
      iv
    );
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]).toString('utf8');

    return JSON.parse(decrypted) as TokenSet;
  }

  public async getTokenSet(): Promise<TokenSet | null> {
    const encrypted = await this.storage.getTokenSet();
    return encrypted ? this.decrypt(encrypted) : null;
  }

  public async setTokenSet(tokenSet: TokenSet): Promise<void> {
    await this.storage.setTokenSet(await this.encrypt(tokenSet));
  }

  public async deleteTokenSet(): Promise<void> {
    await this.storage.deleteTokenSet();
  }

  public async getAccessToken(): Promise<string | null> {
    return (await this.getTokenSet())?.access_token || null;
  }

  public async getRefreshToken(): Promise<string | null> {
    return (await this.getTokenSet())?.refresh_token || null;
  }

  public async getTokenExpiration(): Promise<number | null> {
    return (await this.getTokenSet())?.expires_at || null;
  }
}

export function generatePkcePair(): PkcePair {
  const codeVerifier = base64UrlEncode(require('crypto').randomBytes(32));
  return {
    codeVerifier,
    codeChallenge: sha256Base64UrlSync(codeVerifier),
    codeChallengeMethod: 'S256',
  };
}

export class AuthManager {
  private readonly config: ResolvedAuthManagerConfig;
  private readonly dpopKeyStore: DpopKeyStore;
  private readonly tokenStorage: TokenStorage;
  private readonly logger: SolidSidecarLogger;

  constructor(config: AuthManagerConfig) {
    if (!config.issuerUrl) {
      throw new ValidationError('OIDC issuer URL is required', 'issuerUrl');
    }
    if (!config.clientId) {
      throw new ValidationError('Client ID is required', 'clientId');
    }
    if (!config.redirectUri) {
      throw new ValidationError('Redirect URI is required', 'redirectUri');
    }

    this.config = {
      ...DEFAULT_AUTH_MANAGER_CONFIG,
      ...config,
      scopes: config.scopes ?? DEFAULT_AUTH_MANAGER_CONFIG.scopes,
      useDpop: config.useDpop ?? DEFAULT_AUTH_MANAGER_CONFIG.useDpop,
      dpopKeyStoreConfig:
        config.dpopKeyStoreConfig ??
        DEFAULT_AUTH_MANAGER_CONFIG.dpopKeyStoreConfig,
      logger: config.logger ?? DEFAULT_AUTH_MANAGER_CONFIG.logger,
    };

    this.dpopKeyStore = new DpopKeyStore(this.config.dpopKeyStoreConfig);
    this.tokenStorage = new InMemoryTokenStorage();
    this.logger = this.config.logger;

    this.logger.debug('AuthManager initialized', {
      issuerUrl: this.config.issuerUrl,
      clientId: this.config.clientId,
      redirectUri: this.config.redirectUri,
      useDpop: this.config.useDpop,
    });
  }

  public generatePkce(): PkcePair {
    return generatePkcePair();
  }

  public buildAuthorizationUrl(
    pkce: PkcePair,
    state?: string,
    nonce?: string
  ): string {
    const { issuerUrl, clientId, redirectUri, scopes } = this.config;
    const url = new URL(issuerUrl);
    url.pathname = `${url.pathname.replace(/\/$/, '')}/auth`;
    url.search = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: pkce.codeChallenge,
      code_challenge_method: pkce.codeChallengeMethod,
      scope: scopes.join(' '),
      state: state || generateUuid(),
      nonce: nonce || generateUuid(),
    }).toString();
    return url.toString();
  }

  public async exchangeCode(
    code: string,
    codeVerifier: string
  ): Promise<TokenSet> {
    if (!code) {
      throw new AuthenticationError('Authorization code is required');
    }
    if (!codeVerifier) {
      throw new AuthenticationError('PKCE code verifier is required');
    }

    const { issuerUrl, clientId, redirectUri, clientSecret } = this.config;
    const url = new URL(issuerUrl);
    url.pathname = `${url.pathname.replace(/\/$/, '')}/token`;
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: codeVerifier,
    });
    if (clientSecret) {
      params.set('client_secret', clientSecret);
    }

    const response = await this.fetchWithRetry(url.toString(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
    if (!response.ok) {
      const error = await response.text();
      this.logger.error('Token exchange failed', {
        status: response.status,
        error,
      });
      throw new AuthenticationError(
        `Token exchange failed: ${response.status}`,
        { statusCode: response.status }
      );
    }

    const tokenResponse: TokenResponse = await response.json();
    const now = Date.now();
    const tokenSet: TokenSet = {
      ...tokenResponse,
      expires_at: now + tokenResponse.expires_in * 1000,
      issued_at: tokenResponse.issued_at
        ? tokenResponse.issued_at * 1000
        : now,
    };
    await this.tokenStorage.setTokenSet(tokenSet);

    if (this.config.useDpop) {
      await this.dpopKeyStore.generateKeyPair(
        this.config.dpopKeyStoreConfig.defaultAlgorithm
      );
    }

    this.logger.info('Token exchange successful', {
      expires_at: tokenSet.expires_at,
      scopes: tokenResponse.scope,
    });
    return tokenSet;
  }

  public async refreshToken(): Promise<TokenSet> {
    const existingRefreshToken = await this.tokenStorage.getRefreshToken();
    if (!existingRefreshToken) {
      throw new AuthenticationError('No refresh token available');
    }

    const { issuerUrl, clientId, clientSecret } = this.config;
    const url = new URL(issuerUrl);
    url.pathname = `${url.pathname.replace(/\/$/, '')}/token`;
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: existingRefreshToken,
      client_id: clientId,
    });
    if (clientSecret) {
      params.set('client_secret', clientSecret);
    }

    const response = await this.fetchWithRetry(url.toString(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
    if (!response.ok) {
      const error = await response.text();
      this.logger.error('Token refresh failed', {
        status: response.status,
        error,
      });
      await this.tokenStorage.deleteTokenSet();
      throw new AuthenticationError(
        `Token refresh failed: ${response.status}`,
        { statusCode: response.status }
      );
    }

    const tokenResponse: TokenResponse = await response.json();
    const now = Date.now();
    const tokenSet: TokenSet = {
      ...tokenResponse,
      refresh_token: tokenResponse.refresh_token || existingRefreshToken,
      expires_at: now + tokenResponse.expires_in * 1000,
      issued_at: tokenResponse.issued_at
        ? tokenResponse.issued_at * 1000
        : now,
    };
    await this.tokenStorage.setTokenSet(tokenSet);
    this.logger.info('Token refresh successful', {
      expires_at: tokenSet.expires_at,
    });
    return tokenSet;
  }

  public async getAccessToken(): Promise<string | null> {
    const tokenSet = await this.tokenStorage.getTokenSet();
    if (!tokenSet) {
      return null;
    }

    const expiresAt = tokenSet.expires_at || 0;
    if (Date.now() >= expiresAt - 5 * 60 * 1000) {
      try {
        await this.refreshToken();
        return this.getAccessToken();
      } catch (error) {
        this.logger.error('Auto-refresh failed', { error });
        return null;
      }
    }
    return tokenSet.access_token;
  }

  public async getRefreshToken(): Promise<string | null> {
    return this.tokenStorage.getRefreshToken();
  }

  public async getTokenExpiration(): Promise<number | null> {
    return this.tokenStorage.getTokenExpiration();
  }

  public async clearTokens(): Promise<void> {
    await this.tokenStorage.deleteTokenSet();
    this.logger.info('Tokens cleared');
  }

  public async generateDpopProof(
    options: DpopProofOptions
  ): Promise<DpopProof> {
    if (!this.config.useDpop) {
      throw new Error(
        'DPoP is disabled. Enable DPoP in AuthManager configuration.'
      );
    }
    const accessToken = await this.getAccessToken();
    if (!accessToken) {
      throw new AuthenticationError('No access token available');
    }
    return this.dpopKeyStore.generateDpopProof({
      ...options,
      accessToken,
    });
  }

  public async signRequest(
    method: string,
    url: string
  ): Promise<{ accessToken: string; dpopProof: string }> {
    const accessToken = await this.getAccessToken();
    if (!accessToken) {
      throw new AuthenticationError('No access token available');
    }
    const dpopProof = await this.generateDpopProof({
      method: method as any,
      url,
      accessToken,
    });
    return { accessToken, dpopProof: dpopProof.jwt };
  }

  private async fetchWithRetry(
    url: string,
    options: RequestInit,
    retries = 3
  ): Promise<Response> {
    try {
      const fetchImpl =
        typeof fetch === 'undefined' ? require('cross-fetch') : fetch;
      return await fetchImpl(url, options);
    } catch (error) {
      if (retries <= 0) {
        throw error;
      }
      const delay = Math.pow(2, 3 - retries) * 1000;
      await new Promise(resolve => setTimeout(resolve, delay));
      return this.fetchWithRetry(url, options, retries - 1);
    }
  }

  public getDpopKeyStore(): DpopKeyStore {
    return this.dpopKeyStore;
  }

  public getTokenStorage(): TokenStorage {
    return this.tokenStorage;
  }

  public async isAuthenticated(): Promise<boolean> {
    return !!(await this.getAccessToken());
  }

  public async getSessionInfo(): Promise<{
    isAuthenticated: boolean;
    accessToken: string | null;
    expiresAt: number | null;
    clientId: string;
    issuerUrl: string;
    useDpop: boolean;
  }> {
    const [accessToken, expiresAt] = await Promise.all([
      this.getAccessToken(),
      this.getTokenExpiration(),
    ]);
    return {
      isAuthenticated: !!accessToken,
      accessToken: accessToken ? '[REDACTED]' : null,
      expiresAt,
      clientId: this.config.clientId,
      issuerUrl: this.config.issuerUrl,
      useDpop: this.config.useDpop,
    };
  }
}
