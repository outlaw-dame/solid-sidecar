/**
 * Solid Sidecar TypeScript SDK - Sync/Reconciliation Client
 * Fail-closed queueing, synchronization, and reconciliation.
 */

import type { HttpHeaders, ResourceUri, SolidSidecarLogger } from '../types';
import { ConflictError, PreconditionFailedError, ValidationError } from '../types';
import { nullLogger, sleep } from '../utils';
import { ResourceClient, type ResourceClientConfig } from './resource-client';

export type SyncStatus = 'synced' | 'pending' | 'conflict' | 'error' | 'deleted';
export type ChangeType = 'create' | 'update' | 'delete' | 'patch';

export interface LocalChange {
  id: string;
  resourceUri: ResourceUri;
  type: ChangeType;
  content?: string;
  contentType?: string;
  localEtag?: string;
  baseEtag?: string;
  timestamp: number;
  retryCount: number;
  lastError?: string;
  headers?: HttpHeaders;
  ifMatch?: string | string[];
  ifNoneMatch?: string | string[];
}

export interface RemoteChange {
  resourceUri: ResourceUri;
  etag: string;
  lastModified?: string;
  contentLength?: number;
  exists: boolean;
}

export interface SyncResult {
  resourceUri: ResourceUri;
  status: SyncStatus;
  localChangeId?: string;
  newEtag?: string;
  serverLastModified?: string;
  retryCount: number;
  error?: string;
  resolutionStrategy?: ConflictResolutionStrategy;
  winningContent?: string;
  suggestRetry: boolean;
}

export interface SyncSummary {
  total: number;
  synced: number;
  conflicts: number;
  errors: number;
  pending: number;
  deleted: number;
  results: SyncResult[];
  startedAt: number;
  endedAt: number;
  duration: number;
}

export type ConflictResolutionStrategy =
  | 'server-wins'
  | 'client-wins'
  | 'manual'
  | 'merge'
  | 'latest-wins';

export interface SyncConfig {
  conflictResolution?: ConflictResolutionStrategy;
  maxRetries?: number;
  baseRetryDelay?: number;
  maxRetryDelay?: number;
  batchSize?: number;
  validateETags?: boolean;
  autoResolveConflicts?: boolean;
  conflictResolver?: (
    localChange: LocalChange,
    remoteChange: RemoteChange
  ) => Promise<ConflictResolutionStrategy | string>;
}

export type SyncProgressCallback = (
  current: number,
  total: number,
  result: SyncResult
) => void;

export type ConflictCallback = (
  localChange: LocalChange,
  remoteChange: RemoteChange
) => Promise<ConflictResolutionStrategy | string | void>;

export interface SyncClientConfig extends ResourceClientConfig {
  syncConfig?: SyncConfig;
  logger?: SolidSidecarLogger;
}

interface ResolvedSyncConfig {
  conflictResolution: ConflictResolutionStrategy;
  maxRetries: number;
  baseRetryDelay: number;
  maxRetryDelay: number;
  batchSize: number;
  validateETags: boolean;
  autoResolveConflicts: boolean;
  conflictResolver?: SyncConfig['conflictResolver'];
}

interface ResolvedSyncClientConfig {
  syncConfig: ResolvedSyncConfig;
  logger: SolidSidecarLogger;
}

export const DEFAULT_SYNC_CLIENT_CONFIG = {
  syncConfig: {
    conflictResolution: 'manual',
    maxRetries: 3,
    baseRetryDelay: 1000,
    maxRetryDelay: 30000,
    batchSize: 10,
    validateETags: true,
    autoResolveConflicts: false,
  },
  logger: nullLogger,
} satisfies ResolvedSyncClientConfig;

function cloneChange(change: LocalChange): LocalChange {
  return {
    ...change,
    ...(change.headers !== undefined && { headers: { ...change.headers } }),
    ...(Array.isArray(change.ifMatch) && { ifMatch: [...change.ifMatch] }),
    ...(Array.isArray(change.ifNoneMatch) && {
      ifNoneMatch: [...change.ifNoneMatch],
    }),
  };
}

function validateInteger(name: string, value: number, minimum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new ValidationError(`${name} must be an integer >= ${minimum}`, name);
  }
  return value;
}

function isStrategy(value: string): value is ConflictResolutionStrategy {
  return (
    value === 'server-wins' ||
    value === 'client-wins' ||
    value === 'manual' ||
    value === 'merge' ||
    value === 'latest-wins'
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export class SyncClient {
  private readonly config: ResolvedSyncClientConfig;
  private readonly resourceClient: ResourceClient;
  private readonly logger: SolidSidecarLogger;
  private readonly changeQueue = new Map<string, LocalChange>();
  private readonly pendingSyncs = new Map<string, Promise<SyncResult>>();
  private isSyncing = false;
  private syncCancelled = false;
  private changeSequence = 0;

  constructor(config: SyncClientConfig = {}) {
    const requested = config.syncConfig ?? {};
    const maxRetries = validateInteger(
      'maxRetries',
      requested.maxRetries ?? DEFAULT_SYNC_CLIENT_CONFIG.syncConfig.maxRetries,
      0
    );
    const baseRetryDelay = validateInteger(
      'baseRetryDelay',
      requested.baseRetryDelay ??
        DEFAULT_SYNC_CLIENT_CONFIG.syncConfig.baseRetryDelay,
      0
    );
    const maxRetryDelay = validateInteger(
      'maxRetryDelay',
      requested.maxRetryDelay ?? DEFAULT_SYNC_CLIENT_CONFIG.syncConfig.maxRetryDelay,
      0
    );
    if (maxRetryDelay < baseRetryDelay) {
      throw new ValidationError(
        'maxRetryDelay must be greater than or equal to baseRetryDelay',
        'maxRetryDelay'
      );
    }

    this.config = {
      logger: config.logger ?? nullLogger,
      syncConfig: {
        conflictResolution:
          requested.conflictResolution ??
          DEFAULT_SYNC_CLIENT_CONFIG.syncConfig.conflictResolution,
        maxRetries,
        baseRetryDelay,
        maxRetryDelay,
        batchSize: validateInteger(
          'batchSize',
          requested.batchSize ?? DEFAULT_SYNC_CLIENT_CONFIG.syncConfig.batchSize,
          1
        ),
        validateETags:
          requested.validateETags ??
          DEFAULT_SYNC_CLIENT_CONFIG.syncConfig.validateETags,
        autoResolveConflicts:
          requested.autoResolveConflicts ??
          DEFAULT_SYNC_CLIENT_CONFIG.syncConfig.autoResolveConflicts,
        ...(requested.conflictResolver !== undefined && {
          conflictResolver: requested.conflictResolver,
        }),
      },
    };
    this.resourceClient = new ResourceClient({
      ...config,
      logger: config.logger ?? nullLogger,
    });
    this.logger = this.config.logger;
  }

  public async queueCreate(
    resourceUri: ResourceUri,
    content: string,
    options: { contentType?: string; headers?: HttpHeaders } = {}
  ): Promise<string> {
    return this.queueChange({
      type: 'create',
      resourceUri,
      content,
      ...(options.contentType !== undefined && {
        contentType: options.contentType,
      }),
      ...(options.headers !== undefined && { headers: { ...options.headers } }),
      ifNoneMatch: '*',
    });
  }

  public async queueUpdate(
    resourceUri: ResourceUri,
    content: string,
    baseEtag: string,
    options: { contentType?: string; headers?: HttpHeaders } = {}
  ): Promise<string> {
    this.requireEtag(baseEtag);
    if (this.config.syncConfig.validateETags) {
      const metadata = await this.resourceClient.head(resourceUri);
      if (!metadata.etag) {
        throw new ValidationError(
          'Cannot queue update: resource has no ETag',
          'resourceUri'
        );
      }
      if (metadata.etag !== baseEtag) {
        throw new PreconditionFailedError('Cannot queue update: base ETag is stale');
      }
    }
    return this.queueChange({
      type: 'update',
      resourceUri,
      content,
      baseEtag,
      ifMatch: baseEtag,
      ...(options.contentType !== undefined && {
        contentType: options.contentType,
      }),
      ...(options.headers !== undefined && { headers: { ...options.headers } }),
    });
  }

  public async queueDelete(
    resourceUri: ResourceUri,
    baseEtag: string,
    options: { headers?: HttpHeaders } = {}
  ): Promise<string> {
    this.requireEtag(baseEtag);
    return this.queueChange({
      type: 'delete',
      resourceUri,
      baseEtag,
      ifMatch: baseEtag,
      ...(options.headers !== undefined && { headers: { ...options.headers } }),
    });
  }

  public async queuePatch(
    resourceUri: ResourceUri,
    sparqlUpdate: string,
    baseEtag: string,
    options: { headers?: HttpHeaders } = {}
  ): Promise<string> {
    this.requireEtag(baseEtag);
    return this.queueChange({
      type: 'patch',
      resourceUri,
      content: sparqlUpdate,
      contentType: 'application/sparql-update',
      baseEtag,
      ifMatch: baseEtag,
      ...(options.headers !== undefined && { headers: { ...options.headers } }),
    });
  }

  public getChange(changeId: string): LocalChange | null {
    const change = this.changeQueue.get(changeId);
    return change === undefined ? null : cloneChange(change);
  }

  public listChanges(): LocalChange[] {
    return [...this.changeQueue.values()]
      .sort(
        (left, right) =>
          left.timestamp - right.timestamp || left.id.localeCompare(right.id)
      )
      .map(cloneChange);
  }

  public removeChange(changeId: string): boolean {
    if (this.pendingSyncs.has(changeId)) return false;
    return this.changeQueue.delete(changeId);
  }

  public clearQueue(): void {
    if (this.pendingSyncs.size > 0) {
      throw new ConflictError('Cannot clear queue while changes are syncing');
    }
    this.changeQueue.clear();
  }

  public getQueueSize(): number {
    return this.changeQueue.size;
  }

  public async syncChange(
    changeId: string,
    options: {
      onProgress?: SyncProgressCallback;
      onConflict?: ConflictCallback;
    } = {}
  ): Promise<SyncResult> {
    const existing = this.pendingSyncs.get(changeId);
    if (existing !== undefined) return existing;

    const stored = this.changeQueue.get(changeId);
    if (stored === undefined) {
      throw new ValidationError(`Change not found: ${changeId}`, 'changeId');
    }
    const promise = this.syncSingleChange(stored, options);
    this.pendingSyncs.set(changeId, promise);
    try {
      const result = await promise;
      if (result.status === 'synced' || result.status === 'deleted') {
        this.changeQueue.delete(changeId);
      }
      return result;
    } finally {
      this.pendingSyncs.delete(changeId);
    }
  }

  public async syncAll(
    options: {
      batchSize?: number;
      onProgress?: SyncProgressCallback;
      onConflict?: ConflictCallback;
    } = {}
  ): Promise<SyncSummary> {
    if (this.isSyncing) {
      throw new ConflictError('Sync already in progress');
    }
    const batchSize = validateInteger(
      'batchSize',
      options.batchSize ?? this.config.syncConfig.batchSize,
      1
    );
    const startedAt = Date.now();
    const changes = this.listChanges();
    const results: Array<SyncResult | undefined> = new Array(changes.length);
    this.isSyncing = true;
    this.syncCancelled = false;

    try {
      for (
        let offset = 0;
        offset < changes.length && !this.syncCancelled;
        offset += batchSize
      ) {
        const batch = changes.slice(offset, offset + batchSize);
        const settled = await Promise.all(
          batch.map(async (change, index) => {
            try {
              const result = await this.syncChange(change.id, {
                onConflict: options.onConflict,
              });
              return { index: offset + index, result };
            } catch (error) {
              return {
                index: offset + index,
                result: this.errorResult(change, error),
              };
            }
          })
        );
        for (const entry of settled) {
          results[entry.index] = entry.result;
          options.onProgress?.(entry.index + 1, changes.length, entry.result);
        }
        if (offset + batchSize < changes.length && !this.syncCancelled) {
          await sleep(100);
        }
      }

      const completed = results.filter(
        (result): result is SyncResult => result !== undefined
      );
      return this.summarize(changes.length, completed, startedAt);
    } finally {
      this.isSyncing = false;
    }
  }

  public cancelSync(): void {
    this.syncCancelled = true;
  }

  public isSyncInProgress(): boolean {
    return this.isSyncing;
  }

  public async resolveConflict(
    changeId: string,
    strategy: ConflictResolutionStrategy | string,
    options: { winningContent?: string } = {}
  ): Promise<SyncResult> {
    const change = this.changeQueue.get(changeId);
    if (change === undefined) {
      throw new ValidationError(`Change not found: ${changeId}`, 'changeId');
    }
    const remote = await this.getRemoteChange(change.resourceUri);
    const result = await this.applyResolutionStrategy(
      change,
      remote,
      strategy,
      options.winningContent
    );
    if (result.status === 'synced' || result.status === 'deleted') {
      this.changeQueue.delete(changeId);
    }
    return result;
  }

  public async reconcileContainer(
    containerUri: string,
    options: {
      onProgress?: SyncProgressCallback;
      onConflict?: ConflictCallback;
    } = {}
  ): Promise<SyncSummary> {
    if (this.isSyncing) {
      throw new ConflictError('Sync already in progress');
    }
    const container = this.canonicalContainer(containerUri);
    const startedAt = Date.now();
    this.isSyncing = true;
    this.syncCancelled = false;
    try {
      await this.resourceClient.listContainer(container);
      const changes = this.listChanges().filter(change =>
        this.isWithinContainer(container, change.resourceUri)
      );
      const results: SyncResult[] = [];
      for (const change of changes) {
        if (this.syncCancelled) break;
        try {
          results.push(
            await this.syncChange(change.id, {
              onConflict: options.onConflict,
            })
          );
        } catch (error) {
          results.push(this.errorResult(change, error));
        }
        const latest = results[results.length - 1];
        if (latest !== undefined) {
          options.onProgress?.(results.length, changes.length, latest);
        }
      }
      return this.summarize(changes.length, results, startedAt);
    } finally {
      this.isSyncing = false;
    }
  }

  public getConfig(): ResolvedSyncClientConfig {
    return {
      logger: this.config.logger,
      syncConfig: { ...this.config.syncConfig },
    };
  }

  private queueChange(
    change: Omit<
      LocalChange,
      'id' | 'timestamp' | 'retryCount' | 'lastError'
    >
  ): string {
    const id = `${Date.now().toString(36)}-${(++this.changeSequence).toString(36)}`;
    this.changeQueue.set(id, {
      ...change,
      id,
      timestamp: Date.now(),
      retryCount: 0,
      ...(change.headers !== undefined && { headers: { ...change.headers } }),
    });
    return id;
  }

  private async syncSingleChange(
    change: LocalChange,
    options: {
      onProgress?: SyncProgressCallback;
      onConflict?: ConflictCallback;
    }
  ): Promise<SyncResult> {
    let current = this.changeQueue.get(change.id);
    if (current === undefined) {
      throw new ValidationError(`Change not found: ${change.id}`, 'changeId');
    }

    for (;;) {
      if (this.syncCancelled) {
        return {
          resourceUri: current.resourceUri,
          status: 'pending',
          localChangeId: current.id,
          retryCount: current.retryCount,
          error: 'Sync cancelled',
          suggestRetry: true,
        };
      }

      try {
        const remote = await this.getRemoteChange(current.resourceUri);
        if (this.detectConflict(current, remote)) {
          return await this.handleConflict(current, remote, options);
        }
        const result = await this.applyChange(current);
        options.onProgress?.(1, 1, result);
        return result;
      } catch (error) {
        if (
          error instanceof PreconditionFailedError ||
          error instanceof ConflictError
        ) {
          const remote = await this.getRemoteChange(current.resourceUri);
          return this.handleConflict(current, remote, options);
        }
        if (current.retryCount >= this.config.syncConfig.maxRetries) {
          const failed = {
            ...current,
            lastError: errorMessage(error),
          };
          this.changeQueue.set(current.id, failed);
          return this.errorResult(failed, error);
        }
        current = {
          ...current,
          retryCount: current.retryCount + 1,
          lastError: errorMessage(error),
        };
        this.changeQueue.set(current.id, current);
        await sleep(this.backoffDelay(current.retryCount));
      }
    }
  }

  private async applyChange(change: LocalChange): Promise<SyncResult> {
    if (change.type === 'delete') {
      await this.resourceClient.delete(change.resourceUri, {
        ...(change.headers !== undefined && { headers: change.headers }),
        ...(change.ifMatch !== undefined && { ifMatch: change.ifMatch }),
      });
      return {
        resourceUri: change.resourceUri,
        status: 'deleted',
        localChangeId: change.id,
        retryCount: change.retryCount,
        suggestRetry: false,
      };
    }

    if (change.content === undefined) {
      throw new ValidationError(
        `${change.type} change requires content`,
        'content'
      );
    }

    const metadata =
      change.type === 'patch'
        ? await this.resourceClient.patch(change.resourceUri, change.content, {
            ...(change.contentType !== undefined && {
              contentType: change.contentType,
            }),
            ...(change.headers !== undefined && { headers: change.headers }),
            ...(change.ifMatch !== undefined && { ifMatch: change.ifMatch }),
          })
        : await this.resourceClient.put(change.resourceUri, change.content, {
            ...(change.contentType !== undefined && {
              contentType: change.contentType,
            }),
            ...(change.headers !== undefined && { headers: change.headers }),
            ...(change.ifMatch !== undefined && { ifMatch: change.ifMatch }),
            ...(change.ifNoneMatch !== undefined && {
              ifNoneMatch: change.ifNoneMatch,
            }),
          });

    return {
      resourceUri: change.resourceUri,
      status: 'synced',
      localChangeId: change.id,
      ...(metadata.etag !== undefined && { newEtag: metadata.etag }),
      ...(metadata.lastModified !== undefined && {
        serverLastModified: metadata.lastModified,
      }),
      retryCount: change.retryCount,
      suggestRetry: false,
    };
  }

  private async handleConflict(
    change: LocalChange,
    remote: RemoteChange,
    options: { onConflict?: ConflictCallback }
  ): Promise<SyncResult> {
    const callbackChoice = await options.onConflict?.(
      cloneChange(change),
      { ...remote }
    );
    const configuredChoice = this.config.syncConfig.conflictResolver
      ? await this.config.syncConfig.conflictResolver(
          cloneChange(change),
          { ...remote }
        )
      : undefined;
    const requested =
      callbackChoice ??
      configuredChoice ??
      (this.config.syncConfig.autoResolveConflicts
        ? this.config.syncConfig.conflictResolution
        : 'manual');

    return this.applyResolutionStrategy(change, remote, requested);
  }

  private async applyResolutionStrategy(
    change: LocalChange,
    remote: RemoteChange,
    strategyOrContent: ConflictResolutionStrategy | string,
    winningContent?: string
  ): Promise<SyncResult> {
    const strategy = isStrategy(strategyOrContent)
      ? strategyOrContent
      : winningContent !== undefined
        ? 'merge'
        : 'manual';

    if (strategy === 'manual') {
      return {
        resourceUri: change.resourceUri,
        status: 'conflict',
        localChangeId: change.id,
        retryCount: change.retryCount,
        error: 'Manual conflict resolution required',
        resolutionStrategy: strategy,
        suggestRetry: false,
      };
    }

    if (strategy === 'server-wins') {
      return {
        resourceUri: change.resourceUri,
        status: 'synced',
        localChangeId: change.id,
        retryCount: change.retryCount,
        resolutionStrategy: strategy,
        suggestRetry: false,
      };
    }

    if (strategy === 'latest-wins') {
      const remoteTimestamp =
        remote.lastModified === undefined ? Number.NaN : Date.parse(remote.lastModified);
      const localIsLater =
        Number.isNaN(remoteTimestamp) || change.timestamp > remoteTimestamp;
      return this.applyResolutionStrategy(
        change,
        remote,
        localIsLater ? 'client-wins' : 'server-wins',
        winningContent
      );
    }

    const content =
      winningContent ??
      (isStrategy(strategyOrContent) ? change.content : strategyOrContent);
    if (content === undefined) {
      throw new ValidationError(
        `${strategy} resolution requires winning content`,
        'winningContent'
      );
    }
    const metadata = await this.resourceClient.put(change.resourceUri, content, {
      ...(change.contentType !== undefined && {
        contentType: change.contentType,
      }),
      ...(change.headers !== undefined && { headers: change.headers }),
      ...(remote.exists && remote.etag !== '' && { ifMatch: remote.etag }),
      ...(!remote.exists && { ifNoneMatch: '*' }),
    });
    return {
      resourceUri: change.resourceUri,
      status: 'synced',
      localChangeId: change.id,
      ...(metadata.etag !== undefined && { newEtag: metadata.etag }),
      retryCount: change.retryCount,
      resolutionStrategy: strategy,
      winningContent: content,
      suggestRetry: false,
    };
  }

  private async getRemoteChange(resourceUri: ResourceUri): Promise<RemoteChange> {
    try {
      const metadata = await this.resourceClient.head(resourceUri);
      return {
        resourceUri,
        etag: metadata.etag ?? '',
        ...(metadata.lastModified !== undefined && {
          lastModified: metadata.lastModified,
        }),
        ...(metadata.contentLength !== undefined && {
          contentLength: metadata.contentLength,
        }),
        exists: true,
      };
    } catch (error) {
      const statusCode =
        typeof error === 'object' &&
        error !== null &&
        'statusCode' in error &&
        typeof error.statusCode === 'number'
          ? error.statusCode
          : undefined;
      if (statusCode === 404) {
        return { resourceUri, etag: '', exists: false };
      }
      throw error;
    }
  }

  private detectConflict(change: LocalChange, remote: RemoteChange): boolean {
    if (change.type === 'create') return remote.exists;
    if (!remote.exists) return change.type !== 'delete';
    return (
      change.baseEtag !== undefined &&
      remote.etag !== '' &&
      change.baseEtag !== remote.etag
    );
  }

  private backoffDelay(attempt: number): number {
    const exponential =
      this.config.syncConfig.baseRetryDelay * 2 ** Math.max(0, attempt - 1);
    return Math.min(exponential, this.config.syncConfig.maxRetryDelay);
  }

  private errorResult(change: LocalChange, error: unknown): SyncResult {
    return {
      resourceUri: change.resourceUri,
      status: 'error',
      localChangeId: change.id,
      retryCount: change.retryCount,
      error: errorMessage(error),
      suggestRetry: change.retryCount < this.config.syncConfig.maxRetries,
    };
  }

  private summarize(
    total: number,
    results: SyncResult[],
    startedAt: number
  ): SyncSummary {
    const endedAt = Date.now();
    return {
      total,
      synced: results.filter(result => result.status === 'synced').length,
      conflicts: results.filter(result => result.status === 'conflict').length,
      errors: results.filter(result => result.status === 'error').length,
      pending: results.filter(result => result.status === 'pending').length,
      deleted: results.filter(result => result.status === 'deleted').length,
      results: [...results],
      startedAt,
      endedAt,
      duration: endedAt - startedAt,
    };
  }

  private canonicalContainer(containerUri: string): string {
    let url: URL;
    try {
      url = new URL(containerUri);
    } catch {
      throw new ValidationError(
        'Container URI must be an absolute URL',
        'containerUri'
      );
    }
    if (!['http:', 'https:'].includes(url.protocol)) {
      throw new ValidationError(
        'Container URI must use HTTP or HTTPS',
        'containerUri'
      );
    }
    if (url.username || url.password) {
      throw new ValidationError(
        'Container URI must not contain credentials',
        'containerUri'
      );
    }
    url.hash = '';
    if (!url.pathname.endsWith('/')) url.pathname += '/';
    return url.toString();
  }

  private isWithinContainer(containerUri: string, resourceUri: string): boolean {
    try {
      const container = new URL(containerUri);
      const resource = new URL(resourceUri);
      return (
        resource.origin === container.origin &&
        resource.pathname.startsWith(container.pathname)
      );
    } catch {
      return false;
    }
  }

  private requireEtag(etag: string): void {
    if (!etag.trim()) {
      throw new ValidationError('ETag is required', 'baseEtag');
    }
  }
}

export default SyncClient;
