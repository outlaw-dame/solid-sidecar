/**
 * Solid Sidecar TypeScript SDK - Main Export
 * Phase: 27 - SDK/Client Compatibility Layer
 * Version: v1.0.0
 * Created: 2026-07-07
 * Author: Mistral Vibe
 * License: MIT
 *
 * This file exports all SDK components for easy importing.
 */

// ============================================================================
// Core Types and Utilities
// ============================================================================

export * from './types';
export * from './utils';
export * from './http-client';

// ============================================================================
// Authentication
// ============================================================================

export * as AuthManager from './auth/auth-manager';
export * as DpopKeyStore from './auth/dpop-keystore';

// Re-export main classes
export { AuthManager, DEFAULT_AUTH_MANAGER_CONFIG, type AuthManagerConfig } from './auth/auth-manager';
export {
  DpopKeyStore,
  DEFAULT_DPOP_KEYSTORE_CONFIG,
  InMemoryKeyStore,
  SecureKeyStore,
  type DpopKeyStoreConfig,
  type DpopKeyStorage,
} from './auth/dpop-keystore';

// ============================================================================
// Clients
// ============================================================================

export * as ResourceClient from './clients/resource-client';
export * as PolicyClient from './clients/policy-client';
export * as NotificationClient from './clients/notification-client';
export * as WebIdClient from './clients/webid-client';
export * as RdfCodec from './clients/rdf-codec';
export * as SyncClient from './clients/sync-client';

// Re-export main classes
export {
  ResourceClient,
  DEFAULT_RESOURCE_CLIENT_CONFIG,
  type ResourceClientConfig,
} from './clients/resource-client';

export {
  PolicyClient,
  DEFAULT_POLICY_CLIENT_CONFIG,
  type PolicyClientConfig,
} from './clients/policy-client';

export {
  NotificationClient,
  DEFAULT_NOTIFICATION_CLIENT_CONFIG,
  type NotificationClientConfig,
  SolidSidecarEventSource,
} from './clients/notification-client';

export {
  WebIdClient,
  DEFAULT_WEBID_CLIENT_CONFIG,
  type WebIdClientConfig,
  type WebIdProfile,
  type WebIdDiscoveryOptions,
  type WebIdValidationResult,
} from './clients/webid-client';

export {
  RdfCodec,
  DEFAULT_RDF_CODEC_CONFIG,
  NAMESPACES,
  PREFIXES,
  type RdfCodecConfig,
  type RdfLiteral,
  type RdfTerm,
} from './clients/rdf-codec';

export {
  SyncClient,
  DEFAULT_SYNC_CLIENT_CONFIG,
  type SyncClientConfig,
  type SyncStatus,
  type ChangeType,
  type LocalChange,
  type RemoteChange,
  type SyncResult,
  type SyncSummary,
  type ConflictResolutionStrategy,
  type SyncConfig,
  type SyncProgressCallback,
  type ConflictCallback,
} from './clients/sync-client';

// ============================================================================
// Pre-built Solid Sidecar Client (Convenience)
// ============================================================================

/**
 * Pre-configured Solid Sidecar client with all components
 * 
 * This provides a convenient way to get started with the SDK without
 * having to import and configure each component separately.
 * 
 * @example
 * ```typescript
 * import { SolidSidecarClient } from '@solid-sidecar/sdk';
 * 
 * const client = new SolidSidecarClient({
 *   baseUrl: 'https://localhost:8443',
 * });
 * 
 * // Use the resource client
 * const resource = await client.resource.get('https://example.org/profile/card');
 * 
 * // Use the auth manager
 * const authManager = client.createAuthManager({
 *   issuerUrl: 'https://oidc-issuer.com',
 *   clientId: 'my-app',
 *   redirectUri: 'my-app://callback',
 * });
 * ```
 */
export interface SolidSidecarClientConfig {
  baseUrl: string;
  timeout?: number;
  maxRetries?: number;
  logger?: import('./types').SolidSidecarLogger;
}

export class SolidSidecarClient {
  public readonly resource: ResourceClient;
  public readonly policy: PolicyClient;
  public readonly notification: NotificationClient;
  public readonly webId: WebIdClient;
  public readonly rdf: RdfCodec;
  public readonly sync: SyncClient;
  public readonly http: import('./http-client').SolidSidecarHttpClient;

  private readonly config: Required<SolidSidecarClientConfig>;
  private authManagerInstance: AuthManager | null = null;

  constructor(config: SolidSidecarClientConfig) {
    this.config = {
      baseUrl: config.baseUrl,
      timeout: config.timeout || 30000,
      maxRetries: config.maxRetries || 3,
      logger: config.logger || console,
    };

    // Initialize all clients with consistent configuration
    this.http = new import('./http-client').SolidSidecarHttpClient({
      baseUrl: this.config.baseUrl,
      timeout: this.config.timeout,
      maxRetries: this.config.maxRetries,
      logger: this.config.logger,
    });

    this.resource = new ResourceClient({
      httpClientConfig: this.http.getConfig(),
      logger: this.config.logger,
    });

    this.policy = new PolicyClient({
      httpClientConfig: this.http.getConfig(),
      logger: this.config.logger,
    });

    this.notification = new NotificationClient({
      httpClientConfig: this.http.getConfig(),
      logger: this.config.logger,
    });

    this.webId = new WebIdClient({
      httpClientConfig: this.http.getConfig(),
      logger: this.config.logger,
    });

    this.rdf = new RdfCodec({
      logger: this.config.logger,
    });

    this.sync = new SyncClient({
      httpClientConfig: this.http.getConfig(),
      logger: this.config.logger,
    });
  }

  /**
   * Creates an authentication manager with the configured base URL
   */
  public createAuthManager(config: Omit<import('./auth/auth-manager').AuthManagerConfig, 'redirectUri'> & {
    redirectUri: string;
  }): AuthManager {
    this.authManagerInstance = new AuthManager({
      ...config,
      // Ensure baseUrl is used for issuer discovery
      issuerUrl: config.issuerUrl || this.config.baseUrl,
    });
    
    // Update clients to use this auth manager
    this.resource = new ResourceClient({
      httpClientConfig: this.http.getConfig(),
      authManager: this.authManagerInstance,
      logger: this.config.logger,
    });

    this.policy = new PolicyClient({
      httpClientConfig: this.http.getConfig(),
      authManager: this.authManagerInstance,
      logger: this.config.logger,
    });

    this.webId = new WebIdClient({
      httpClientConfig: this.http.getConfig(),
      authManager: this.authManagerInstance,
      logger: this.config.logger,
    });

    return this.authManagerInstance;
  }

  /**
   * Gets the current authentication manager (if created)
   */
  public getAuthManager(): AuthManager | null {
    return this.authManagerInstance;
  }

  /**
   * Gets the configuration
   */
  public getConfig(): Required<SolidSidecarClientConfig> {
    return { ...this.config };
  }

  /**
   * Closes all connections and cleans up resources
   */
  public async close(): Promise<void> {
    // Close any open connections
    // For now, just clear caches
    this.webId.clearCache();
    this.sync.clearQueue();
  }
}

// ============================================================================
// Default Exports
// ============================================================================

/**
 * Default export for convenience
 */
export default {
  // Clients
  ResourceClient,
  PolicyClient,
  NotificationClient,
  WebIdClient,
  RdfCodec,
  SyncClient,
  
  // Auth
  AuthManager,
  DpopKeyStore,
  InMemoryKeyStore,
  SecureKeyStore,
  
  // Utilities
  SolidSidecarHttpClient: import('./http-client').SolidSidecarHttpClient,
  getDefaultHttpClient: import('./http-client').getDefaultHttpClient,
  resetDefaultHttpClient: import('./http-client').resetDefaultHttpClient,
  configureDefaultHttpClient: import('./http-client').configureDefaultHttpClient,
  
  // Main convenience client
  SolidSidecarClient,
  
  // Constants
  NAMESPACES,
  PREFIXES,
  DEFAULT_RETRY_OPTIONS: import('./types').DEFAULT_RETRY_OPTIONS,
};
