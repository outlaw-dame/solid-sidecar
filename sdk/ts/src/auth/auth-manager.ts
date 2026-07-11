/**
 * Solid Sidecar TypeScript SDK - Authentication Manager
 * Phase: 27 - SDK/Client Compatibility Layer
 * Version: v1.0.0
 * Created: 2026-07-07
 * Author: Mistral Vibe
 * License: MIT
 *
 * This file contains the authentication manager for handling OIDC token
 * exchange, token refresh, and DPoP proof generation.
 *
 * Security Level: CRITICAL
 */

import type {
  TokenResponse,
  TokenSet,
  PkcePair,
  DpopProofOptions,
  DpopProof,
  SolidSidecarLogger,
} from '../types';
import { AuthenticationError, ValidationError } from '../types';
import { DpopKeyStore, DEFAULT_DPOP_KEYSTORE_CONFIG, type DpopKeyStoreConfig } from './dpop-keystore';
import { generateUuid, base64UrlEncode, sha256Base64UrlSync } from '../utils';

// ============================================================================
// Authentication Configuration
// ============================================================================

/**
 * Configuration for authentication manager
 */
export interface AuthManagerConfig {
  /** OIDC issuer URL */
  issuerUrl: string;
  
  /** Client ID */
  clientId: string;
  
  /** Client secret (optional, for confidential clients) */
  clientSecret?: string;
  
  /** Redirect URI */
  redirectUri: string;
  
  /** Scopes to request */
  scopes?: string[];
  
  /** DPoP key store configuration */
  dpopKeyStoreConfig?: DpopKeyStoreConfig;
  
  /** Whether to use DPoP (default: true) */
  useDpop?: boolean;
  
  /** Custom logger */
  logger?: SolidSidecarLogger;
}

/**
 * Default authentication configuration
 */
export const DEFAULT_AUTH_MANAGER_CONFIG: Partial<AuthManagerConfig> = {
  scopes: ['openid', 'profile', 'webid'],
  useDpop: true,
  dpopKeyStoreConfig: DEFAULT_DPOP_KEYSTORE_CONFIG,
};

// ============================================================================
// Token Storage Interface
// ============================================================================

/**
 * Interface for token storage
 */
export interface TokenStorage {
  /**
   * Gets the token set
   */
  getTokenSet(): Promise<TokenSet | null>;

  /**
   * Stores the token set
   */
  setTokenSet(tokenSet: TokenSet): Promise<void>;

  /**
   * Deletes the token set
   */
  deleteTokenSet(): Promise<void>;

  /**
   * Gets the current access token
   */
  getAccessToken(): Promise<string | null>;

  /**
   * Gets the current refresh token
   */
  getRefreshToken(): Promise<string | null>;

  /**
   * Gets the token expiration
   */
  getTokenExpiration(): Promise<number | null>;
}

// ============================================================================
// In-Memory Token Storage
// ============================================================================

/**
 * In-memory token storage
 * 
 * Note: This is suitable for testing but NOT for production.
 * In production, use SecureTokenStorage.
 */
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

// ============================================================================
// Secure Token Storage (Node.js)
// ============================================================================

/**
 * Secure token storage using encryption
 */
export class SecureTokenStorage implements TokenStorage {
  private readonly storage: InMemoryTokenStorage;
  private readonly encryptionKey: Uint8Array;

  constructor(encryptionKey?: string) {
    this.storage = new InMemoryTokenStorage();
    
    if (encryptionKey) {
      this.encryptionKey = new TextEncoder().encode(encryptionKey);
    } else {
      this.encryptionKey = require('crypto').randomBytes(32);
    }
  }

  private async encrypt(data: TokenSet): Promise<TokenSet> {
    const crypto = require('crypto');
    const json = JSON.stringify(data);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    const encrypted = Buffer.concat([
      cipher.update(json, 'utf8'),
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
    const encryptedData = data.subarray(16, data.length - 16);
    const authTag = data.subarray(data.length - 16);
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([
      decipher.update(encryptedData),
      decipher.final(),
    ]).toString('utf8');
    
    return JSON.parse(decrypted) as TokenSet;
  }

  public async getTokenSet(): Promise<TokenSet | null> {
    const encrypted = await this.storage.getTokenSet();
    if (!encrypted) {
      return null;
    }
    return this.decrypt(encrypted);
  }

  public async setTokenSet(tokenSet: TokenSet): Promise<void> {
    const encrypted = await this.encrypt(tokenSet);
    await this.storage.setTokenSet(encrypted);
  }

  public async deleteTokenSet(): Promise<void> {
    await this.storage.deleteTokenSet();
  }

  public async getAccessToken(): Promise<string | null> {
    const tokenSet = await this.getTokenSet();
    return tokenSet?.access_token || null;
  }

  public async getRefreshToken(): Promise<string | null> {
    const tokenSet = await this.getTokenSet();
    return tokenSet?.refresh_token || null;
  }

  public async getTokenExpiration(): Promise<number | null> {
    const tokenSet = await this.getTokenSet();
    return tokenSet?.expires_at || null;
  }
}

// ============================================================================
// PKCE Utilities
// ============================================================================

/**
 * Generates a PKCE code verifier and challenge
 */
export function generatePkcePair(): PkcePair {
  // Generate code verifier (43-128 characters)
  const codeVerifier = base64UrlEncode(require('crypto').randomBytes(32));
  
  // Generate code challenge (SHA-256 hash of code verifier)
  const codeChallenge = sha256Base64UrlSync(codeVerifier);

  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: 'S256',
  };
}

// ============================================================================
// Authentication Manager
// ============================================================================

/**
 * Authentication Manager for Solid Sidecar
 * 
 * Features:
 * - OIDC token exchange with PKCE
 * - Token refresh
 * - DPoP proof generation
 * - Token storage
 * - Automatic token refresh
 * - Session management
 */
export class AuthManager {
  private readonly config: Required<AuthManagerConfig>;
  private readonly dpopKeyStore: DpopKeyStore;
  private readonly tokenStorage: TokenStorage;
  private readonly logger: SolidSidecarLogger;

  constructor(config: AuthManagerConfig) {
    // Validate required configuration
    if (!config.issuerUrl) {
      throw new ValidationError('OIDC issuer URL is required', 'issuerUrl');
    }
    if (!config.clientId) {
      throw new ValidationError('Client ID is required', 'clientId');
    }
    if (!config.redirectUri) {
      throw new ValidationError('Redirect URI is required', 'redirectUri');
    }

    // Merge with defaults
    this.config = {
      ...DEFAULT_AUTH_MANAGER_CONFIG,
      ...config,
      logger: config.logger || console,
    };

    // Initialize DPoP key store
    this.dpopKeyStore = new DpopKeyStore(
      this.config.dpopKeyStoreConfig
    );

    // Initialize token storage
    this.tokenStorage = new InMemoryTokenStorage();
    this.logger = this.config.logger;

    this.logger.debug('AuthManager initialized', {
      issuerUrl: this.config.issuerUrl,
      clientId: this.config.clientId,
      redirectUri: this.config.redirectUri,
      useDpop: this.config.useDpop,
    });
  }

  // ==========================================================================
  // PKCE Flow
  // ==========================================================================

  /**
   * Generates PKCE code verifier and challenge for authorization request
   */
  public generatePkce(): PkcePair {
    return generatePkcePair();
  }

  /**
   * Builds the authorization URL for the OIDC issuer
   */
  public buildAuthorizationUrl(pkce: PkcePair, state?: string, nonce?: string): string {
    const { issuerUrl, clientId, redirectUri, scopes } = this.config;

    const url = new URL(issuerUrl);
    url.pathname = url.pathname.replace(/\/$/, '') + '/auth';

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: pkce.codeChallenge,
      code_challenge_method: pkce.codeChallengeMethod,
      scope: scopes.join(' '),
      state: state || generateUuid(),
      nonce: nonce || generateUuid(),
    });

    url.search = params.toString();
    return url.toString();
  }

  // ==========================================================================
  // Token Exchange
  // ==========================================================================

  /**
   * Exchanges authorization code for tokens
   * 
   * @param code - The authorization code
   * @param codeVerifier - The PKCE code verifier
   * @returns Token set with access token, refresh token, etc.
   */
  public async exchangeCode(
    code: string,
    codeVerifier: string
  ): Promise<TokenSet> {
    const { issuerUrl, clientId, redirectUri, clientSecret } = this.config;

    if (!code) {
      throw new AuthenticationError('Authorization code is required');
    }
    if (!codeVerifier) {
      throw new AuthenticationError('PKCE code verifier is required');
    }

    const url = new URL(issuerUrl);
    url.pathname = url.pathname.replace(/\/$/, '') + '/token';

    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: codeVerifier,
    });

    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    // Add client secret if available
    if (clientSecret) {
      // For confidential clients, use basic auth or client_secret in body
      params.set('client_secret', clientSecret);
    }

    const response = await this.fetchWithRetry(url.toString(), {
      method: 'POST',
      headers,
      body: params.toString(),
    });

    if (!response.ok) {
      const error = await response.text();
      this.logger.error('Token exchange failed', { status: response.status, error });
      throw new AuthenticationError(`Token exchange failed: ${response.status}`, {
        statusCode: response.status,
      });
    }

    const tokenResponse: TokenResponse = await response.json();

    // Create token set with metadata
    const now = Date.now();
    const tokenSet: TokenSet = {
      ...tokenResponse,
      expires_at: now + (tokenResponse.expires_in * 1000),
      issued_at: tokenResponse.issued_at ? tokenResponse.issued_at * 1000 : now,
    };

    // Store token set
    await this.tokenStorage.setTokenSet(tokenSet);

    // Generate DPoP key pair if DPoP is enabled
    if (this.config.useDpop) {
      await this.dpopKeyStore.generateKeyPair(this.config.dpopKeyStoreConfig?.defaultAlgorithm);
    }

    this.logger.info('Token exchange successful', {
      expires_at: tokenSet.expires_at,
      scopes: tokenResponse.scope,
    });

    return tokenSet;
  }

  // ==========================================================================
  // Token Refresh
  // ==========================================================================

  /**
   * Refreshes the access token using the refresh token
   */
  public async refreshToken(): Promise<TokenSet> {
    const { issuerUrl, clientId, clientSecret } = this.config;

    const refreshToken = await this.tokenStorage.getRefreshToken();
    if (!refreshToken) {
      throw new AuthenticationError('No refresh token available');
    }

    const url = new URL(issuerUrl);
    url.pathname = url.pathname.replace(/\/$/, '') + '/token';

    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: clientId,
    });

    // Add client secret if available
    if (clientSecret) {
      params.set('client_secret', clientSecret);
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    const response = await this.fetchWithRetry(url.toString(), {
      method: 'POST',
      headers,
      body: params.toString(),
    });

    if (!response.ok) {
      const error = await response.text();
      this.logger.error('Token refresh failed', { status: response.status, error });
      
      // Clear tokens on auth failure
      await this.tokenStorage.deleteTokenSet();
      
      throw new AuthenticationError(`Token refresh failed: ${response.status}`, {
        statusCode: response.status,
      });
    }

    const tokenResponse: TokenResponse = await response.json();

    // Create token set with metadata
    const now = Date.now();
    const tokenSet: TokenSet = {
      ...tokenResponse,
      // Use existing refresh token if not provided
      refresh_token: tokenResponse.refresh_token || (await this.tokenStorage.getRefreshToken()) || '',
      expires_at: now + (tokenResponse.expires_in * 1000),
      issued_at: tokenResponse.issued_at ? tokenResponse.issued_at * 1000 : now,
    };

    // Store token set
    await this.tokenStorage.setTokenSet(tokenSet);

    this.logger.info('Token refresh successful', {
      expires_at: tokenSet.expires_at,
    });

    return tokenSet;
  }

  // ==========================================================================
  // Token Management
  // ==========================================================================

  /**
   * Gets the current access token
   */
  public async getAccessToken(): Promise<string | null> {
    // Check if token is expired or about to expire
    const tokenSet = await this.tokenStorage.getTokenSet();
    
    if (!tokenSet) {
      return null;
    }

    // Auto-refresh if token is expired or about to expire (within 5 minutes)
    const now = Date.now();
    const expiresAt = tokenSet.expires_at || 0;
    
    if (now >= expiresAt - 5 * 60 * 1000) {
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

  /**
   * Gets the current refresh token
   */
  public async getRefreshToken(): Promise<string | null> {
    return this.tokenStorage.getRefreshToken();
  }

  /**
   * Gets the token expiration timestamp
   */
  public async getTokenExpiration(): Promise<number | null> {
    return this.tokenStorage.getTokenExpiration();
  }

  /**
   * Clears the token set
   */
  public async clearTokens(): Promise<void> {
    await this.tokenStorage.deleteTokenSet();
    this.logger.info('Tokens cleared');
  }

  // ==========================================================================
  // DPoP Proof Generation
  // ==========================================================================

  /**
   * Generates a DPoP proof for a request
   */
  public async generateDpopProof(
    options: DpopProofOptions
  ): Promise<DpopProof> {
    if (!this.config.useDpop) {
      throw new Error('DPoP is disabled. Enable DPoP in AuthManager configuration.');
    }

    // Get access token
    const accessToken = await this.getAccessToken();
    if (!accessToken) {
      throw new AuthenticationError('No access token available');
    }

    return this.dpopKeyStore.generateDpopProof({
      ...options,
      accessToken,
    });
  }

  // ==========================================================================
  // HTTP Request Signing
  // ==========================================================================

  /**
   * Signs an HTTP request with DPoP proof
   */
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

    return {
      accessToken,
      dpopProof: dpopProof.jwt,
    };
  }

  // ==========================================================================
  // Internal HTTP Fetch with Retry
  // ==========================================================================

  /**
   * Makes an HTTP fetch request with retry logic
   */
  private async fetchWithRetry(
    url: string,
    options: RequestInit,
    retries: number = 3
  ): Promise<Response> {
    try {
      // Use global fetch or node-fetch
      const fetchImpl = typeof fetch === 'undefined' ? require('cross-fetch') : fetch;
      return await fetchImpl(url, options);
    } catch (error) {
      if (retries <= 0) {
        throw error;
      }
      
      // Wait and retry
      const delay = Math.pow(2, 3 - retries) * 1000;
      await new Promise(resolve => setTimeout(resolve, delay));
      return this.fetchWithRetry(url, options, retries - 1);
    }
  }

  // ==========================================================================
  // DPoP Key Store Access
  // ==========================================================================

  /**
   * Gets the DPoP key store
   */
  public getDpopKeyStore(): DpopKeyStore {
    return this.dpopKeyStore;
  }

  /**
   * Gets the token storage
   */
  public getTokenStorage(): TokenStorage {
    return this.tokenStorage;
  }

  // ==========================================================================
  // Session Management
  // ==========================================================================

  /**
   * Checks if the user is authenticated
   */
  public async isAuthenticated(): Promise<boolean> {
    const accessToken = await this.getAccessToken();
    return !!accessToken;
  }

  /**
   * Gets the current session information
   */
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

// ============================================================================
// Exports
// ============================================================================

export { InMemoryTokenStorage, SecureTokenStorage, generatePkcePair };
export type { TokenStorage };
