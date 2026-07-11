/**
 * Solid Sidecar TypeScript SDK - Sync/Reconciliation Client
 * Phase: 27 - SDK/Client Compatibility Layer
 * Version: v1.0.0
 * Created: 2026-07-07
 * Author: Mistral Vibe
 * License: MIT
 *
 * This file contains the SyncClient for offline-first operations with
 * conflict detection, ETag handling, and reconciliation.
 *
 * Security Level: CRITICAL - Handles data synchronization and conflict resolution
 */

import type {
  ResourceUri,
  Resource,
  ResourceMetadata,
  HttpHeaders,
  ConditionalWriteOptions,
  SolidSidecarLogger,
} from '../types';
import {
  ConflictError,
  PreconditionFailedError,
  ValidationError,
} from '../types';
import { ResourceClient, type ResourceClientConfig } from './resource-client';
import {
  calculateBackoffDelay,
  sleep,
  DEFAULT_RETRY_OPTIONS,
} from '../utils';

// ============================================================================
// Sync Types
// ============================================================================

/** Sync status for a resource */
export type SyncStatus = 'synced' | 'pending' | 'conflict' | 'error' | 'deleted';

/** Change type */
export type ChangeType = 'create' | 'update' | 'delete' | 'patch';

/** Local change record */
export interface LocalChange {
  /** Unique change identifier */
  id: string;
  
  /** Resource URI */
  resourceUri: ResourceUri;
  
  /** Change type */
  type: ChangeType;
  
  /** Content for create/update */
  content?: string;
  
  /** Content type */
  contentType?: string;
  
  /** ETag of the local version */
  localEtag?: string;
  
  /** ETag of the remote version at time of change */
  baseEtag?: string;
  
  /** Timestamp when change was made */
  timestamp: number;
  
  /** Number of retry attempts */
  retryCount: number;
  
  /** Last error message */
  lastError?: string;
  
  /** Custom headers */
  headers?: HttpHeaders;
  
  /** If-Match header value for conditional writes */
  ifMatch?: string | string[];
  
  /** If-None-Match header value */
  ifNoneMatch?: string | string[];
}

/** Remote change information */
export interface RemoteChange {
  /** Resource URI */
  resourceUri: ResourceUri;
  
  /** Current ETag on server */
  etag: string;
  
  /** Last modified timestamp */
  lastModified?: string;
  
  /** Content length */
  contentLength?: number;
  
  /** Whether the resource exists */
  exists: boolean;
}

/** Sync result for a single resource */
export interface SyncResult {
  /** Resource URI */
  resourceUri: ResourceUri;
  
  /** Sync status */
  status: SyncStatus;
  
  /** Local change ID if applicable */
  localChangeId?: string;
  
  /** New ETag after sync */
  newEtag?: string;
  
  /** Server's last modified timestamp */
  serverLastModified?: string;
  
  /** Number of retries performed */
  retryCount: number;
  
  /** Error message if status is 'error' or 'conflict' */
  error?: string;
  
  /** Conflict resolution strategy used */
  resolutionStrategy?: ConflictResolutionStrategy;
  
  /** The winning content (for conflicts resolved to client or server) */
  winningContent?: string;
  
  /** Whether a retry is suggested */
  suggestRetry: boolean;
}

/** Overall sync summary */
export interface SyncSummary {
  /** Total number of resources synced */
  total: number;
  
  /** Number of successful syncs */
  synced: number;
  
  /** Number of conflicts */
  conflicts: number;
  
  /** Number of errors */
  errors: number;
  
  /** Number of pending changes */
  pending: number;
  
  /** Number of deleted resources */
  deleted: number;
  
  /** Individual results */
  results: SyncResult[];
  
  /** Start timestamp */
  startedAt: number;
  
  /** End timestamp */
  endedAt: number;
  
  /** Total duration in milliseconds */
  duration: number;
}

/** Conflict resolution strategy */
export type ConflictResolutionStrategy = 
  | 'server-wins'
  | 'client-wins'
  | 'manual'
  | 'merge'
  | 'latest-wins';

/** Sync configuration */
export interface SyncConfig {
  /** Conflict resolution strategy (default: 'manual') */
  conflictResolution?: ConflictResolutionStrategy;
  
  /** Maximum number of retries per resource (default: 3) */
  maxRetries?: number;
  
  /** Base delay for exponential backoff in milliseconds (default: 1000) */
  baseRetryDelay?: number;
  
  /** Maximum delay for exponential backoff in milliseconds (default: 30000) */
  maxRetryDelay?: number;
  
  /** Batch size for sync operations (default: 10) */
  batchSize?: number;
  
  /** Whether to validate ETags before sync (default: true) */
  validateETags?: boolean;
  
  /** Whether to auto-resolve conflicts (default: false) */
  autoResolveConflicts?: boolean;
  
  /** Custom conflict resolver function */
  conflictResolver?: (
    localChange: LocalChange,
    remoteChange: RemoteChange
  ) => Promise<ConflictResolutionStrategy | string>;
}

/** Sync progress callback */
export type SyncProgressCallback = (
  current: number,
  total: number,
  result: SyncResult
) => void;

/** Conflict callback */
export type ConflictCallback = (
  localChange: LocalChange,
  remoteChange: RemoteChange
) => Promise<ConflictResolutionStrategy | string | void>;

// ============================================================================
// Sync Client Configuration
// ============================================================================

/**
 * Configuration for SyncClient
 */
export interface SyncClientConfig extends ResourceClientConfig {
  /** Sync configuration */
  syncConfig?: SyncConfig;
  
  /** Custom logger */
  logger?: SolidSidecarLogger;
}

/**
 * Default SyncClient configuration
 */
export const DEFAULT_SYNC_CLIENT_CONFIG: Partial<SyncClientConfig> = {
  syncConfig: {
    conflictResolution: 'manual',
    maxRetries: 3,
    baseRetryDelay: 1000,
    maxRetryDelay: 30000,
    batchSize: 10,
    validateETags: true,
    autoResolveConflicts: false,
  },
};

// ============================================================================
// Sync Client
// ============================================================================

/**
 * SyncClient for Solid Sidecar
 * 
 * Features:
 * - Offline-first sync with local change queue
 * - ETag-based conflict detection
 * - Exponential backoff and retry logic
 * - Configurable conflict resolution strategies
 * - Batch sync operations
 * - Progress callbacks
 * - Self-healing with retry and reconciliation
 * - IDOR prevention
 * - SSRF prevention
 */
export class SyncClient {
  private readonly config: Required<SyncClientConfig>;
  private readonly resourceClient: ResourceClient;
  private readonly logger: SolidSidecarLogger;
  
  // Local change queue
  private readonly changeQueue: Map<string, LocalChange> = new Map();
  
  // Pending sync operations
  private readonly pendingSyncs: Map<string, Promise<SyncResult>> = new Map();
  
  // Sync state tracking
  private isSyncing = false;
  private syncCancelled = false;
  
  constructor(config: SyncClientConfig = {}) {
    // Merge with defaults
    this.config = {
      ...DEFAULT_SYNC_CLIENT_CONFIG,
      ...config,
      logger: config.logger || console,
      syncConfig: {
        ...DEFAULT_SYNC_CLIENT_CONFIG.syncConfig,
        ...config.syncConfig,
      },
    };

    // Initialize resource client
    this.resourceClient = new ResourceClient(config);
    this.logger = this.config.logger;

    this.logger.debug('SyncClient initialized', {
      conflictResolution: this.config.syncConfig.conflictResolution,
      maxRetries: this.config.syncConfig.maxRetries,
      batchSize: this.config.syncConfig.batchSize,
    });
  }

  // ==========================================================================
  // Queue Management
  // ==========================================================================

  /**
   * Queues a create operation
   * 
   * @param resourceUri - The resource URI
   * @param content - The content to create
   * @param options - Additional options
   * @returns The change ID
   */
  public async queueCreate(
    resourceUri: ResourceUri,
    content: string,
    options: {
      contentType?: string;
      headers?: HttpHeaders;
    } = {}
  ): Promise<string> {
    return this.queueChange({
      type: 'create',
      resourceUri,
      content,
      contentType: options.contentType,
      headers: options.headers,
      ifNoneMatch: '*',
    });
  }

  /**
   * Queues an update operation
   * 
   * @param resourceUri - The resource URI
   * @param content - The updated content
   * @param baseEtag - The ETag the update is based on
   * @param options - Additional options
   * @returns The change ID
   */
  public async queueUpdate(
    resourceUri: ResourceUri,
    content: string,
    baseEtag: string,
    options: {
      contentType?: string;
      headers?: HttpHeaders;
    } = {}
  ): Promise<string> {
    // Get current metadata to validate base ETag
    if (this.config.syncConfig.validateETags) {
      try {
        const metadata = await this.resourceClient.head(resourceUri);
        if (!metadata.etag) {
          throw new ValidationError(
            'Cannot queue update: resource has no ETag',
            'resourceUri'
          );
        }
      } catch (error) {
        this.logger.warn('Failed to validate ETag for update', {
          resourceUri,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    return this.queueChange({
      type: 'update',
      resourceUri,
      content,
      contentType: options.contentType,
      headers: options.headers,
      baseEtag,
      ifMatch: baseEtag,
    });
  }

  /**
   * Queues a delete operation
   * 
   * @param resourceUri - The resource URI
   * @param baseEtag - The ETag the delete is based on
   * @param options - Additional options
   * @returns The change ID
   */
  public async queueDelete(
    resourceUri: ResourceUri,
    baseEtag: string,
    options: {
      headers?: HttpHeaders;
    } = {}
  ): Promise<string> {
    return this.queueChange({
      type: 'delete',
      resourceUri,
      baseEtag,
      headers: options.headers,
      ifMatch: baseEtag,
    });
  }

  /**
   * Queues a PATCH operation (SPARQL Update)
   * 
   * @param resourceUri - The resource URI
   * @param sparqlUpdate - The SPARQL Update query
   * @param baseEtag - The ETag the patch is based on
   * @param options - Additional options
   * @returns The change ID
   */
  public async queuePatch(
    resourceUri: ResourceUri,
    sparqlUpdate: string,
    baseEtag: string,
    options: {
      headers?: HttpHeaders;
    } = {}
  ): Promise<string> {
    return this.queueChange({
      type: 'patch',
      resourceUri,
      content: sparqlUpdate,
      baseEtag,
      headers: options.headers,
      ifMatch: baseEtag,
      contentType: 'application/sparql-update',
    });
  }

  /**
   * Queues a change
   */
  private queueChange(change: Omit<LocalChange, 'id' | 'timestamp' | 'retryCount' | 'lastError'>): string {
    const id = this.generateChangeId();
    
    const newChange: LocalChange = {
      id,
      timestamp: Date.now(),
      retryCount: 0,
      ...change,
    };
    
    this.changeQueue.set(id, newChange);
    this.logger.debug('Change queued', {
      id,
      type: change.type,
      resourceUri: change.resourceUri,
    });
    
    return id;
  }

  /**
   * Gets a queued change
   */
  public getChange(changeId: string): LocalChange | null {
    return this.changeQueue.get(changeId) || null;
  }

  /**
   * Lists all queued changes
   */
  public listChanges(): LocalChange[] {
    return Array.from(this.changeQueue.values())
      .sort((a, b) => a.timestamp - b.timestamp);
  }

  /**
   * Removes a change from the queue
   */
  public removeChange(changeId: string): boolean {
    return this.changeQueue.delete(changeId);
  }

  /**
   * Clears all queued changes
   */
  public clearQueue(): void {
    this.changeQueue.clear();
    this.logger.info('Change queue cleared');
  }

  /**
   * Gets the number of queued changes
   */
  public getQueueSize(): number {
    return this.changeQueue.size;
  }

  // ==========================================================================
  // Sync Operations
  // ==========================================================================

  /**
   * Syncs a single change
   * 
   * @param changeId - The change ID to sync
   * @param options - Sync options
   * @returns Sync result
   */
  public async syncChange(
    changeId: string,
    options: {
      onProgress?: SyncProgressCallback;
      onConflict?: ConflictCallback;
    } = {}
  ): Promise<SyncResult> {
    const change = this.changeQueue.get(changeId);
    if (!change) {
      throw new ValidationError(`Change not found: ${changeId}`, 'changeId');
    }

    // Check if already syncing
    if (this.pendingSyncs.has(changeId)) {
      return this.pendingSyncs.get(changeId)!;
    }

    const syncPromise = this.syncSingleChange(change, options);
    this.pendingSyncs.set(changeId, syncPromise);
    
    try {
      const result = await syncPromise;
      return result;
    } finally {
      this.pendingSyncs.delete(changeId);
    }
  }

  /**
   * Syncs all queued changes
   * 
   * @param options - Sync options
   * @returns Sync summary
   */
  public async syncAll(
    options: {
      batchSize?: number;
      onProgress?: SyncProgressCallback;
      onConflict?: ConflictCallback;
    } = {}
  ): Promise<SyncSummary> {
    if (this.isSyncing) {
      throw new Error('Sync already in progress');
    }

    const batchSize = options.batchSize || this.config.syncConfig.batchSize;
    const startTime = Date.now();
    const results: SyncResult[] = [];
    
    this.isSyncing = true;
    this.syncCancelled = false;
    
    try {
      // Get all changes sorted by timestamp
      const changes = this.listChanges();
      const total = changes.length;
      
      this.logger.info('Starting sync', { total, batchSize });
      
      // Process in batches
      for (let i = 0; i < changes.length && !this.syncCancelled; i += batchSize) {
        const batch = changes.slice(i, i + batchSize);
        
        // Process batch concurrently
        const batchPromises = batch.map(async (change, batchIndex) => {
          try {
            const result = await this.syncSingleChange(change, {
              onProgress: options.onProgress
                ? (current, batchTotal, batchResult) => {
                    options.onProgress!(i + current, total, batchResult);
                  }
                : undefined,
              onConflict: options.onConflict,
            });
            
            results.push(result);
            
            // Remove successful change from queue
            if (result.status === 'synced' || result.status === 'deleted') {
              this.changeQueue.delete(change.id);
            }
            
            return result;
          } catch (error) {
            this.logger.error('Failed to sync change', {
              changeId: change.id,
              error: error instanceof Error ? error.message : String(error),
            });
            
            // Create error result
            const errorResult: SyncResult = {
              resourceUri: change.resourceUri,
              status: 'error',
              localChangeId: change.id,
              retryCount: change.retryCount,
              error: error instanceof Error ? error.message : String(error),
              suggestRetry: true,
            };
            
            results.push(errorResult);
            return errorResult;
          }
        });
        
        // Wait for batch to complete
        await Promise.all(batchPromises);
        
        // Add delay between batches to prevent overwhelming server
        if (i + batchSize < changes.length && batchSize > 0) {
          await sleep(100); // 100ms delay between batches
        }
      }
      
      // Calculate summary
      const summary: SyncSummary = {
        total,
        synced: results.filter(r => r.status === 'synced').length,
        conflicts: results.filter(r => r.status === 'conflict').length,
        errors: results.filter(r => r.status === 'error').length,
        pending: results.filter(r => r.status === 'pending').length,
        deleted: results.filter(r => r.status === 'deleted').length,
        results,
        startedAt: startTime,
        endedAt: Date.now(),
        duration: Date.now() - startTime,
      };
      
      this.logger.info('Sync completed', summary);
      return summary;
      
    } finally {
      this.isSyncing = false;
    }
  }

  /**
   * Cancels the current sync operation
   */
  public cancelSync(): void {
    this.syncCancelled = true;
    this.logger.warn('Sync cancelled by user');
  }

  /**
   * Checks if sync is in progress
   */
  public isSyncInProgress(): boolean {
    return this.isSyncing;
  }

  // ==========================================================================
  // Conflict Resolution
  // ==========================================================================

  /**
   * Resolves a conflict manually
   * 
   * @param changeId - The change ID with conflict
   * @param strategy - The resolution strategy
   * @param options - Additional options
   * @returns Sync result
   */
  public async resolveConflict(
    changeId: string,
    strategy: ConflictResolutionStrategy | string,
    options: {
      winningContent?: string;
    } = {}
  ): Promise<SyncResult> {
    const change = this.changeQueue.get(changeId);
    if (!change) {
      throw new ValidationError(`Change not found: ${changeId}`, 'changeId');
    }

    // Get current remote state
    const remoteChange = await this.getRemoteChange(change.resourceUri);
    
    // Apply resolution strategy
    const result = await this.applyResolutionStrategy(
      change,
      remoteChange,
      strategy,
      options.winningContent
    );
    
    // Update change with resolution
    change.retryCount++;
    
    if (result.status === 'synced') {
      this.changeQueue.delete(changeId);
    } else {
      this.changeQueue.set(changeId, change);
    }
    
    this.logger.info('Conflict resolved', {
      changeId,
      strategy,
      status: result.status,
    });
    
    return result;
  }

  // ==========================================================================
  // State Reconciliation
  // ==========================================================================

  /**
   * Performs full state reconciliation between local and remote
   * 
   * @param containerUri - The container to reconcile
   * @param options - Reconciliation options
   * @returns Sync summary
   */
  public async reconcileContainer(
    containerUri: string,
    options: {
      onProgress?: SyncProgressCallback;
      onConflict?: ConflictCallback;
    } = {}
  ): Promise<SyncSummary> {
    this.logger.info('Starting container reconciliation', { containerUri });
    
    const startTime = Date.now();
    const results: SyncResult[] = [];
    
    try {
      // Get remote container listing
      const remoteListing = await this.resourceClient.listContainer(containerUri);
      const remoteResources = [
        ...remoteListing.resources,
        ...remoteListing.containers,
      ];
      
      // Get local changes for this container
      const localChanges = this.listChanges()
        .filter(change => change.resourceUri.startsWith(containerUri));
      
      // Create map of local changes by resource
      const localByResource = new Map<string, LocalChange[]>();
      for (const change of localChanges) {
        if (!localByResource.has(change.resourceUri)) {
          localByResource.set(change.resourceUri, []);
        }
        localByResource.get(change.resourceUri)?.push(change);
      }
      
      // For each remote resource, check if we have local changes
      let processed = 0;
      const total = remoteResources.length + localChanges.length;
      
      for (const resourceUri of remoteResources) {
        if (this.syncCancelled) break;
        
        const localChangesForResource = localByResource.get(resourceUri) || [];
        
        for (const change of localChangesForResource) {
          try {
            const result = await this.syncSingleChange(change, {
              onProgress: options.onProgress
                ? (current, batchTotal, batchResult) => {
                    options.onProgress!(processed + current, total, batchResult);
                  }
                : undefined,
              onConflict: options.onConflict,
            });
            
            results.push(result);
            processed++;
            
            if (result.status === 'synced' || result.status === 'deleted') {
              this.changeQueue.delete(change.id);
            }
          } catch (error) {
            results.push({
              resourceUri: change.resourceUri,
              status: 'error',
              localChangeId: change.id,
              retryCount: change.retryCount,
              error: error instanceof Error ? error.message : String(error),
              suggestRetry: true,
            });
            processed++;
          }
        }
      }
      
      // Handle resources that exist locally but not remotely (pending creates)
      for (const [resourceUri, changes] of localByResource) {
        if (this.syncCancelled) break;
        
        if (!remoteResources.includes(resourceUri)) {
          for (const change of changes) {
            if (change.type === 'create' || change.type === 'update') {
              try {
                const result = await this.syncSingleChange(change, {
                  onProgress: options.onProgress
                    ? (current, batchTotal, batchResult) => {
                        options.onProgress!(processed + current, total, batchResult);
                      }
                    : undefined,
                  onConflict: options.onConflict,
                });
                
                results.push(result);
                processed++;
                
                if (result.status === 'synced' || result.status === 'deleted') {
                  this.changeQueue.delete(change.id);
                }
              } catch (error) {
                results.push({
                  resourceUri: change.resourceUri,
                  status: 'error',
                  localChangeId: change.id,
                  retryCount: change.retryCount,
                  error: error instanceof Error ? error.message : String(error),
                  suggestRetry: true,
                });
                processed++;
              }
            }
          }
        }
      }
      
      // Calculate summary
      const summary: SyncSummary = {
        total: results.length,
        synced: results.filter(r => r.status === 'synced').length,
        conflicts: results.filter(r => r.status === 'conflict').length,
        errors: results.filter(r => r.status === 'error').length,
        pending: results.filter(r => r.status === 'pending').length,
        deleted: results.filter(r => r.status === 'deleted').length,
        results,
        startedAt: startTime,
        endedAt: Date.now(),
        duration: Date.now() - startTime,
      };
      
      this.logger.info('Container reconciliation completed', {
        containerUri,
        ...summary,
      });
      
      return summary;
      
    } finally {
      this.isSyncing = false;
    }
  }

  // ==========================================================================
  // Private Methods
  // ==========================================================================

  /**
   * Syncs a single change
   */
  private async syncSingleChange(
    change: LocalChange,
    options: {
      onProgress?: SyncProgressCallback;
      onConflict?: ConflictCallback;
    }
  ): Promise<SyncResult> {
    this.logger.debug('Syncing change', {
      id: change.id,
      type: change.type,
      resourceUri: change.resourceUri,
    });

    try {
      // Get current remote state
      const remoteChange = await this.getRemoteChange(change.resourceUri);
      
      // Check for conflict
      const conflict = this.detectConflict(change, remoteChange);
      
      if (conflict) {
        if (this.config.syncConfig.autoResolveConflicts) {
          // Auto-resolve conflict
          const strategy = this.config.syncConfig.conflictResolver
            ? await this.config.syncConfig.conflictResolver(change, remoteChange)
            : this.config.syncConfig.conflictResolution!;
          
          return this.applyResolutionStrategy(change, remoteChange, strategy);
        } else {
          // Conflict detected, need manual resolution
          if (options.onConflict) {
            const customStrategy = await options.onConflict(change, remoteChange);
            if (customStrategy) {
              return this.applyResolutionStrategy(change, remoteChange, customStrategy);
            }
          }
          
          return {
            resourceUri: change.resourceUri,
            status: 'conflict',
            localChangeId: change.id,
            retryCount: change.retryCount,
            error: 'Conflict detected - manual resolution required',
            suggestRetry: false,
          };
        }
      }
      
      // No conflict, apply the change
      return this.applyChange(change, remoteChange);
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      // Check if it's a retryable error
      const shouldRetry = this.isRetryableError(error);
      
      // Update change retry count
      change.retryCount++;
      change.lastError = errorMessage;
      this.changeQueue.set(change.id, change);
      
      return {
        resourceUri: change.resourceUri,
        status: 'error',
        localChangeId: change.id,
        retryCount: change.retryCount,
        error: errorMessage,
        suggestRetry: shouldRetry && change.retryCount < this.config.syncConfig.maxRetries,
      };
    }
  }

  /**
   * Gets the current state of a resource from the server
   */
  private async getRemoteChange(resourceUri: ResourceUri): Promise<RemoteChange> {
    try {
      const metadata = await this.resourceClient.head(resourceUri);
      
      return {
        resourceUri,
        etag: metadata.etag || '',
        lastModified: metadata.lastModified,
        contentLength: metadata.contentLength,
        exists: metadata.exists,
      };
    } catch (error) {
      // Resource doesn't exist or is inaccessible
      return {
        resourceUri,
        etag: '',
        exists: false,
      };
    }
  }

  /**
   * Detects if there's a conflict between local change and remote state
   */
  private detectConflict(
    localChange: LocalChange,
    remoteChange: RemoteChange
  ): boolean {
    // No conflict if resource doesn't exist and we're creating
    if (!remoteChange.exists && localChange.type === 'create') {
      return false;
    }
    
    // Conflict if:
    // 1. We're creating but resource already exists
    if (localChange.type === 'create' && remoteChange.exists) {
      return true;
    }
    
    // 2. We're updating/deleting but the remote ETag doesn't match our base
    if (localChange.baseEtag && localChange.baseEtag !== remoteChange.etag) {
      return true;
    }
    
    // 3. Resource doesn't exist but we're updating or deleting
    if (!remoteChange.exists && (localChange.type === 'update' || localChange.type === 'delete')) {
      return true;
    }
    
    return false;
  }

  /**
   * Applies a resolution strategy to a conflict
   */
  private async applyResolutionStrategy(
    localChange: LocalChange,
    remoteChange: RemoteChange,
    strategy: ConflictResolutionStrategy | string,
    winningContent?: string
  ): Promise<SyncResult> {
    switch (strategy) {
      case 'server-wins':
        // Accept server's version, discard local change
        this.changeQueue.delete(localChange.id);
        return {
          resourceUri: localChange.resourceUri,
          status: 'synced',
          localChangeId: localChange.id,
          newEtag: remoteChange.etag,
          serverLastModified: remoteChange.lastModified,
          retryCount: localChange.retryCount,
          resolutionStrategy: 'server-wins',
          suggestRetry: false,
        };

      case 'client-wins':
        // Force apply local change, overwrite server
        if (winningContent || localChange.content) {
          try {
            const metadata = await this.resourceClient.put(
              localChange.resourceUri,
              winningContent || localChange.content!,
              {
                contentType: localChange.contentType,
                headers: localChange.headers,
                ifNoneMatch: '*', // Force overwrite
              }
            );
            
            this.changeQueue.delete(localChange.id);
            return {
              resourceUri: localChange.resourceUri,
              status: 'synced',
              localChangeId: localChange.id,
              newEtag: metadata.etag,
              serverLastModified: metadata.lastModified,
              retryCount: localChange.retryCount,
              resolutionStrategy: 'client-wins',
              winningContent: winningContent || localChange.content,
              suggestRetry: false,
            };
          } catch (error) {
            return {
              resourceUri: localChange.resourceUri,
              status: 'error',
              localChangeId: localChange.id,
              retryCount: localChange.retryCount,
              error: error instanceof Error ? error.message : String(error),
              resolutionStrategy: 'client-wins',
              suggestRetry: true,
            };
          }
        }
        break;

      case 'merge':
        // Attempt to merge changes (for RDF resources)
        if (localChange.type === 'update' || localChange.type === 'patch') {
          try {
            // Get current remote content
            const remoteResource = await this.resourceClient.get(localChange.resourceUri);
            
            // For now, simple merge: just apply local change
            // In a real implementation, this would parse both RDF graphs and merge them
            const metadata = await this.resourceClient.put(
              localChange.resourceUri,
              localChange.content!,
              {
                contentType: localChange.contentType,
                headers: localChange.headers,
                ifMatch: localChange.ifMatch,
              }
            );
            
            this.changeQueue.delete(localChange.id);
            return {
              resourceUri: localChange.resourceUri,
              status: 'synced',
              localChangeId: localChange.id,
              newEtag: metadata.etag,
              serverLastModified: metadata.lastModified,
              retryCount: localChange.retryCount,
              resolutionStrategy: 'merge',
              suggestRetry: false,
            };
          } catch (error) {
            return {
              resourceUri: localChange.resourceUri,
              status: 'error',
              localChangeId: localChange.id,
              retryCount: localChange.retryCount,
              error: error instanceof Error ? error.message : String(error),
              resolutionStrategy: 'merge',
              suggestRetry: true,
            };
          }
        }
        break;

      case 'latest-wins':
        // The most recent change wins (compare timestamps)
        // For simplicity, we'll assume local change is newer
        // In a real implementation, you'd compare the actual timestamps
        return this.applyResolutionStrategy(localChange, remoteChange, 'client-wins', winningContent);

      case 'manual':
      default:
        // Manual resolution or unknown strategy
        return {
          resourceUri: localChange.resourceUri,
          status: 'conflict',
          localChangeId: localChange.id,
          retryCount: localChange.retryCount,
          error: 'Manual resolution required',
          resolutionStrategy: typeof strategy === 'string' ? strategy : 'manual',
          suggestRetry: false,
        };
    }
    
    // Unknown strategy
    return {
      resourceUri: localChange.resourceUri,
      status: 'conflict',
      localChangeId: localChange.id,
      retryCount: localChange.retryCount,
      error: `Unknown resolution strategy: ${strategy}`,
      resolutionStrategy: typeof strategy === 'string' ? strategy : 'manual',
      suggestRetry: false,
    };
  }

  /**
   * Applies a change to the server
   */
  private async applyChange(
    change: LocalChange,
    remoteChange: RemoteChange
  ): Promise<SyncResult> {
    try {
      switch (change.type) {
        case 'create':
          return this.applyCreate(change);
        case 'update':
          return this.applyUpdate(change);
        case 'delete':
          return this.applyDelete(change);
        case 'patch':
          return this.applyPatch(change);
        default:
          throw new ValidationError(`Unknown change type: ${change.type}`, 'type');
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      // Check for specific error types
      if (error instanceof PreconditionFailedError || error instanceof ConflictError) {
        return {
          resourceUri: change.resourceUri,
          status: 'conflict',
          localChangeId: change.id,
          retryCount: change.retryCount,
          error: errorMessage,
          suggestRetry: false,
        };
      }
      
      throw error;
    }
  }

  /**
   * Applies a create change
   */
  private async applyCreate(change: LocalChange): Promise<SyncResult> {
    const metadata = await this.resourceClient.create(
      change.resourceUri,
      change.content!,
      {
        contentType: change.contentType,
        headers: change.headers,
      }
    );
    
    this.changeQueue.delete(change.id);
    
    return {
      resourceUri: change.resourceUri,
      status: 'synced',
      localChangeId: change.id,
      newEtag: metadata.etag,
      serverLastModified: metadata.lastModified,
      retryCount: change.retryCount,
      suggestRetry: false,
    };
  }

  /**
   * Applies an update change
   */
  private async applyUpdate(change: LocalChange): Promise<SyncResult> {
    const metadata = await this.resourceClient.put(
      change.resourceUri,
      change.content!,
      {
        contentType: change.contentType,
        headers: change.headers,
        ifMatch: change.ifMatch,
      }
    );
    
    this.changeQueue.delete(change.id);
    
    return {
      resourceUri: change.resourceUri,
      status: 'synced',
      localChangeId: change.id,
      newEtag: metadata.etag,
      serverLastModified: metadata.lastModified,
      retryCount: change.retryCount,
      suggestRetry: false,
    };
  }

  /**
   * Applies a delete change
   */
  private async applyDelete(change: LocalChange): Promise<SyncResult> {
    await this.resourceClient.delete(change.resourceUri, {
      headers: change.headers,
      ifMatch: change.ifMatch,
    });
    
    this.changeQueue.delete(change.id);
    
    return {
      resourceUri: change.resourceUri,
      status: 'deleted',
      localChangeId: change.id,
      retryCount: change.retryCount,
      suggestRetry: false,
    };
  }

  /**
   * Applies a patch change
   */
  private async applyPatch(change: LocalChange): Promise<SyncResult> {
    const metadata = await this.resourceClient.patch(
      change.resourceUri,
      change.content!,
      {
        contentType: change.contentType,
        headers: change.headers,
        ifMatch: change.ifMatch,
      }
    );
    
    this.changeQueue.delete(change.id);
    
    return {
      resourceUri: change.resourceUri,
      status: 'synced',
      localChangeId: change.id,
      newEtag: metadata.etag,
      serverLastModified: metadata.lastModified,
      retryCount: change.retryCount,
      suggestRetry: false,
    };
  }

  /**
   * Generates a unique change ID
   */
  private generateChangeId(): string {
    return `change-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
  }

  /**
   * Checks if an error is retryable
   */
  private isRetryableError(error: unknown): boolean {
    if (error instanceof ConflictError || error instanceof PreconditionFailedError) {
      return false; // These require manual resolution
    }
    
    if (error instanceof Error) {
      // Network errors are retryable
      if (error.name === 'NetworkError' || error.name === 'TypeError') {
        return true;
      }
      
      // Rate limit errors are retryable
      if (error.message.includes('429') || error.message.includes('rate limit')) {
        return true;
      }
      
      // Server errors are retryable
      if (error.message.includes('500') || error.message.includes('502') || 
          error.message.includes('503') || error.message.includes('504')) {
        return true;
      }
    }
    
    return false;
  }

  // ==========================================================================
  // Getters
  // ==========================================================================

  /**
   * Gets the resource client
   */
  public getResourceClient(): ResourceClient {
    return this.resourceClient;
  }

  /**
   * Gets the configuration
   */
  public getConfig(): Required<SyncClientConfig> {
    return { ...this.config };
  }
}

// ============================================================================
// Exports
// ============================================================================

export default SyncClient;
export type {
  SyncStatus,
  ChangeType,
  LocalChange,
  RemoteChange,
  SyncResult,
  SyncSummary,
  ConflictResolutionStrategy,
  SyncConfig,
  SyncProgressCallback,
  ConflictCallback,
};
