/**
 * Solid Sidecar TypeScript SDK - public entry point.
 *
 * Phase 27: SDK/client compatibility layer.
 * Status: beta API; compatibility guarantees are documented separately.
 */

import { SolidSidecarHttpClient, configureDefaultHttpClient, getDefaultHttpClient, resetDefaultHttpClient } from './http-client';
import { DEFAULT_RETRY_OPTIONS, type SolidSidecarLogger } from './types';
import { nullLogger } from './utils';
import { AuthManager, DEFAULT_AUTH_MANAGER_CONFIG, type AuthManagerConfig } from './auth/auth-manager';
import {
  DpopKeyStore,
  DEFAULT_DPOP_KEYSTORE_CONFIG,
  InMemoryKeyStore,
  SecureKeyStore,
  type DpopKeyStoreConfig,
  type DpopKeyStorage,
} from './auth/dpop-keystore';
import {
  ResourceClient,
  DEFAULT_RESOURCE_CLIENT_CONFIG,
  type ResourceClientConfig,
} from './clients/resource-client';
import {
  PolicyClient,
  DEFAULT_POLICY_CLIENT_CONFIG,
  type PolicyClientConfig,
} from './clients/policy-client';
import {
  NotificationClient,
  DEFAULT_NOTIFICATION_CLIENT_CONFIG,
  SolidSidecarEventSource,
  type NotificationClientConfig,
} from './clients/notification-client';
import {
  WebIdClient,
  DEFAULT_WEBID_CLIENT_CONFIG,
  type WebIdClientConfig,
  type WebIdProfile,
  type WebIdDiscoveryOptions,
  type WebIdValidationResult,
} from './clients/webid-client';
import {
  RdfCodec,
  DEFAULT_RDF_CODEC_CONFIG,
  NAMESPACES,
  PREFIXES,
  type RdfCodecConfig,
  type RdfLiteral,
  type RdfTerm,
} from './clients/rdf-codec';
import {
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

export * from './types';
export * from './utils';
export * from './http-client';

export {
  AuthManager,
  DEFAULT_AUTH_MANAGER_CONFIG,
  type AuthManagerConfig,
  DpopKeyStore,
  DEFAULT_DPOP_KEYSTORE_CONFIG,
  InMemoryKeyStore,
  SecureKeyStore,
  type DpopKeyStoreConfig,
  type DpopKeyStorage,
  ResourceClient,
  DEFAULT_RESOURCE_CLIENT_CONFIG,
  type ResourceClientConfig,
  PolicyClient,
  DEFAULT_POLICY_CLIENT_CONFIG,
  type PolicyClientConfig,
  NotificationClient,
  DEFAULT_NOTIFICATION_CLIENT_CONFIG,
  SolidSidecarEventSource,
  type NotificationClientConfig,
  WebIdClient,
  DEFAULT_WEBID_CLIENT_CONFIG,
  type WebIdClientConfig,
  type WebIdProfile,
  type WebIdDiscoveryOptions,
  type WebIdValidationResult,
  RdfCodec,
  DEFAULT_RDF_CODEC_CONFIG,
  NAMESPACES,
  PREFIXES,
  type RdfCodecConfig,
  type RdfLiteral,
  type RdfTerm,
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
};

export interface SolidSidecarClientConfig {
  baseUrl: string;
  timeout?: number;
  maxRetries?: number;
  logger?: SolidSidecarLogger;
}

/**
 * Convenience facade that keeps one HTTP configuration across the SDK clients.
 *
 * Authentication-aware client instances are replaced atomically when an
 * AuthManager is created. Consumers should not retain references to an older
 * ResourceClient, PolicyClient, or WebIdClient across that transition.
 */
export class SolidSidecarClient {
  public resource: ResourceClient;
  public policy: PolicyClient;
  public readonly notification: NotificationClient;
  public webId: WebIdClient;
  public readonly rdf: RdfCodec;
  public readonly sync: SyncClient;
  public readonly http: SolidSidecarHttpClient;

  private readonly config: Required<SolidSidecarClientConfig>;
  private authManagerInstance: AuthManager | null = null;

  constructor(config: SolidSidecarClientConfig) {
    this.config = {
      baseUrl: config.baseUrl,
      timeout: config.timeout ?? 30000,
      maxRetries: config.maxRetries ?? 3,
      logger: config.logger ?? nullLogger,
    };

    this.http = new SolidSidecarHttpClient({
      baseUrl: this.config.baseUrl,
      timeout: this.config.timeout,
      defaultTimeout: this.config.timeout,
      maxRetries: this.config.maxRetries,
      logger: this.config.logger,
    });

    const httpClientConfig = this.http.getConfig();
    this.resource = new ResourceClient({ httpClientConfig, logger: this.config.logger });
    this.policy = new PolicyClient({ httpClientConfig, logger: this.config.logger });
    this.notification = new NotificationClient({ httpClientConfig, logger: this.config.logger });
    this.webId = new WebIdClient({ httpClientConfig, logger: this.config.logger });
    this.rdf = new RdfCodec({ logger: this.config.logger });
    this.sync = new SyncClient({ httpClientConfig, logger: this.config.logger });
  }

  public createAuthManager(
    config: Omit<AuthManagerConfig, 'redirectUri'> & { redirectUri: string }
  ): AuthManager {
    this.authManagerInstance = new AuthManager({
      ...config,
      issuerUrl: config.issuerUrl ?? this.config.baseUrl,
    });

    const httpClientConfig = this.http.getConfig();
    this.resource = new ResourceClient({
      httpClientConfig,
      authManager: this.authManagerInstance,
      logger: this.config.logger,
    });
    this.policy = new PolicyClient({
      httpClientConfig,
      authManager: this.authManagerInstance,
      logger: this.config.logger,
    });
    this.webId = new WebIdClient({
      httpClientConfig,
      authManager: this.authManagerInstance,
      logger: this.config.logger,
    });

    return this.authManagerInstance;
  }

  public getAuthManager(): AuthManager | null {
    return this.authManagerInstance;
  }

  public getConfig(): Required<SolidSidecarClientConfig> {
    return { ...this.config };
  }

  public async close(): Promise<void> {
    this.webId.clearCache();
    this.sync.clearQueue();
  }
}

export default {
  ResourceClient,
  PolicyClient,
  NotificationClient,
  WebIdClient,
  RdfCodec,
  SyncClient,
  AuthManager,
  DpopKeyStore,
  InMemoryKeyStore,
  SecureKeyStore,
  SolidSidecarHttpClient,
  getDefaultHttpClient,
  resetDefaultHttpClient,
  configureDefaultHttpClient,
  SolidSidecarClient,
  NAMESPACES,
  PREFIXES,
  DEFAULT_RETRY_OPTIONS,
};
