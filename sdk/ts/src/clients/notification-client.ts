import type {
  ContainerUri,
  NotificationEvent,
  NotificationEventType,
  NotificationSubscription,
  NotificationSubscriptionOptions,
  ResourceUri,
  SolidSidecarLogger,
} from '../types';
import { ValidationError } from '../types';
import { ResourceClient, type ResourceClientConfig } from './resource-client';
import {
  calculateBackoffDelay,
  generateUuid,
  nullLogger,
  sleep,
} from '../utils';

export interface NotificationClientConfig extends ResourceClientConfig {
  notificationsPath?: string;
  maxReconnectAttempts?: number;
  reconnectBaseDelay?: number;
  reconnectMaxDelay?: number;
  heartbeatInterval?: number;
  enableHeartbeat?: boolean;
  logger?: SolidSidecarLogger;
}

type ResolvedNotificationConfig = {
  notificationsPath: string;
  maxReconnectAttempts: number;
  reconnectBaseDelay: number;
  reconnectMaxDelay: number;
  heartbeatInterval: number;
  enableHeartbeat: boolean;
  logger: SolidSidecarLogger;
};

export const DEFAULT_NOTIFICATION_CLIENT_CONFIG: ResolvedNotificationConfig = {
  notificationsPath: '/notifications',
  maxReconnectAttempts: 5,
  reconnectBaseDelay: 1000,
  reconnectMaxDelay: 30000,
  heartbeatInterval: 30000,
  enableHeartbeat: true,
  logger: nullLogger,
};

type EventSourceEventType = 'message' | 'error' | 'open' | 'close';
type MessageListener = (event: MessageEvent) => void;
type ErrorListener = (event: Event) => void;
type VoidListener = () => void;

export class SolidSidecarEventSource {
  private eventSource: EventSource | null = null;
  private readonly baseUrl: string;
  private readonly logger: SolidSidecarLogger;
  private readonly config: ResolvedNotificationConfig;
  private readonly messageListeners: MessageListener[] = [];
  private readonly errorListeners: ErrorListener[] = [];
  private readonly openListeners: VoidListener[] = [];
  private readonly closeListeners: VoidListener[] = [];
  private reconnectAttempts = 0;
  private explicitlyClosed = false;
  private closeDispatched = false;
  private reconnecting = false;
  private lastEventId: string | null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;

  constructor(
    url: string,
    options: NotificationSubscriptionOptions,
    config: ResolvedNotificationConfig,
    logger: SolidSidecarLogger
  ) {
    this.baseUrl = url;
    this.config = config;
    this.logger = logger;
    this.lastEventId = options.cursor ?? null;
  }

  private getConnectionUrl(): string {
    const url = new URL(this.baseUrl);
    if (this.lastEventId) url.searchParams.set('cursor', this.lastEventId);
    else url.searchParams.delete('cursor');
    return url.toString();
  }

  public connect(): void {
    if (this.explicitlyClosed) return;
    this.closeInternal();
    const connectionUrl = this.getConnectionUrl();
    this.eventSource = new EventSource(connectionUrl, { withCredentials: true });
    this.setupHandlers(this.eventSource);
    if (this.config.enableHeartbeat) this.startHeartbeat();
    this.logger.debug('SSE connection created');
  }

  private setupHandlers(source: EventSource): void {
    source.onopen = () => {
      if (source !== this.eventSource || this.explicitlyClosed) return;
      this.reconnectAttempts = 0;
      this.reconnecting = false;
      this.dispatchOpen();
    };

    source.onerror = (error: Event) => {
      if (source !== this.eventSource || this.explicitlyClosed) return;
      this.dispatchError(error);
      if (source.readyState === 2) void this.reconnect();
    };

    source.onmessage = (event: MessageEvent) => {
      if (source !== this.eventSource || this.explicitlyClosed) return;
      if (event.lastEventId) this.lastEventId = event.lastEventId;
      for (const listener of [...this.messageListeners]) {
        try {
          listener(event);
        } catch (error) {
          this.logger.error('Notification message listener failed', { error });
        }
      }
    };
  }

  private dispatchError(event: Event): void {
    for (const listener of [...this.errorListeners]) {
      try {
        listener(event);
      } catch (error) {
        this.logger.error('Notification error listener failed', { error });
      }
    }
  }

  private dispatchOpen(): void {
    for (const listener of [...this.openListeners]) {
      try {
        listener();
      } catch (error) {
        this.logger.error('Notification open listener failed', { error });
      }
    }
  }

  private dispatchCloseOnce(): void {
    if (this.closeDispatched) return;
    this.closeDispatched = true;
    for (const listener of [...this.closeListeners]) {
      try {
        listener();
      } catch (error) {
        this.logger.error('Notification close listener failed', { error });
      }
    }
  }

  public addEventListener(type: 'message', listener: MessageListener): void;
  public addEventListener(type: 'error', listener: ErrorListener): void;
  public addEventListener(type: 'open' | 'close', listener: VoidListener): void;
  public addEventListener(
    type: EventSourceEventType,
    listener: MessageListener | ErrorListener | VoidListener
  ): void {
    if (type === 'message') this.messageListeners.push(listener as MessageListener);
    else if (type === 'error') this.errorListeners.push(listener as ErrorListener);
    else if (type === 'open') this.openListeners.push(listener as VoidListener);
    else this.closeListeners.push(listener as VoidListener);
  }

  public removeEventListener(type: 'message', listener: MessageListener): void;
  public removeEventListener(type: 'error', listener: ErrorListener): void;
  public removeEventListener(type: 'open' | 'close', listener: VoidListener): void;
  public removeEventListener(
    type: EventSourceEventType,
    listener: MessageListener | ErrorListener | VoidListener
  ): void {
    const remove = <T>(items: T[], value: T): void => {
      const index = items.indexOf(value);
      if (index >= 0) items.splice(index, 1);
    };
    if (type === 'message') remove(this.messageListeners, listener as MessageListener);
    else if (type === 'error') remove(this.errorListeners, listener as ErrorListener);
    else if (type === 'open') remove(this.openListeners, listener as VoidListener);
    else remove(this.closeListeners, listener as VoidListener);
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (this.eventSource?.readyState === 1) {
        this.logger.debug('SSE heartbeat');
      }
    }, this.config.heartbeatInterval);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer !== null) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  private closeInternal(): void {
    this.eventSource?.close();
    this.eventSource = null;
    this.stopHeartbeat();
  }

  public close(): void {
    if (this.explicitlyClosed) return;
    this.explicitlyClosed = true;
    this.closeInternal();
    this.dispatchCloseOnce();
  }

  public async reconnect(): Promise<void> {
    if (this.explicitlyClosed || this.reconnecting) return;
    if (this.reconnectAttempts >= this.config.maxReconnectAttempts) {
      this.close();
      return;
    }
    this.reconnecting = true;
    this.closeInternal();
    const delay = calculateBackoffDelay(this.reconnectAttempts, {
      baseDelay: this.config.reconnectBaseDelay,
      maxDelay: this.config.reconnectMaxDelay,
      jitterFactor: 0.1,
    });
    this.reconnectAttempts += 1;
    await sleep(delay);
    this.reconnecting = false;
    if (!this.explicitlyClosed) this.connect();
  }

  public getLastEventId(): string | null {
    return this.lastEventId;
  }

  public async resume(cursor: string): Promise<void> {
    if (!cursor.trim()) throw new ValidationError('Cursor is required', 'cursor');
    this.lastEventId = cursor;
    await this.reconnect();
  }

  public get isClosed(): boolean {
    return this.explicitlyClosed;
  }

  public get isOpen(): boolean {
    return !this.explicitlyClosed && this.eventSource?.readyState === 1;
  }

  public get readyState(): number {
    return this.eventSource?.readyState ?? 2;
  }
}

const VALID_NOTIFICATION_TYPES = new Set<NotificationEventType>([
  'ResourceCreated',
  'ResourceUpdated',
  'ResourceDeleted',
  'ContainerCreated',
  'ContainerUpdated',
  'ContainerDeleted',
  'PolicyCreated',
  'PolicyUpdated',
  'PolicyDeleted',
]);

export class NotificationClient {
  private readonly config: ResolvedNotificationConfig;
  private readonly resourceClient: ResourceClient;
  private readonly logger: SolidSidecarLogger;

  constructor(config: NotificationClientConfig = {}) {
    this.config = {
      notificationsPath:
        config.notificationsPath ?? DEFAULT_NOTIFICATION_CLIENT_CONFIG.notificationsPath,
      maxReconnectAttempts:
        config.maxReconnectAttempts ??
        DEFAULT_NOTIFICATION_CLIENT_CONFIG.maxReconnectAttempts,
      reconnectBaseDelay:
        config.reconnectBaseDelay ??
        DEFAULT_NOTIFICATION_CLIENT_CONFIG.reconnectBaseDelay,
      reconnectMaxDelay:
        config.reconnectMaxDelay ??
        DEFAULT_NOTIFICATION_CLIENT_CONFIG.reconnectMaxDelay,
      heartbeatInterval:
        config.heartbeatInterval ??
        DEFAULT_NOTIFICATION_CLIENT_CONFIG.heartbeatInterval,
      enableHeartbeat:
        config.enableHeartbeat ?? DEFAULT_NOTIFICATION_CLIENT_CONFIG.enableHeartbeat,
      logger: config.logger ?? DEFAULT_NOTIFICATION_CLIENT_CONFIG.logger,
    };
    if (this.config.maxReconnectAttempts < 0) {
      throw new ValidationError(
        'Maximum reconnect attempts cannot be negative',
        'maxReconnectAttempts'
      );
    }
    if (this.config.reconnectBaseDelay < 0 || this.config.reconnectMaxDelay < 0) {
      throw new ValidationError('Reconnect delays cannot be negative', 'reconnectBaseDelay');
    }
    this.resourceClient = new ResourceClient(config);
    this.logger = this.config.logger;
  }

  public async subscribe(
    options: NotificationSubscriptionOptions
  ): Promise<NotificationSubscription> {
    const resourceUri = this.validateResourceUri(options.resourceUri);
    if (options.maxEvents !== undefined && options.maxEvents <= 0) {
      throw new ValidationError('maxEvents must be greater than zero', 'maxEvents');
    }
    if (options.timeout !== undefined && options.timeout <= 0) {
      throw new ValidationError('timeout must be greater than zero', 'timeout');
    }

    const eventSource = new SolidSidecarEventSource(
      this.buildNotificationsUrl(resourceUri),
      options,
      this.config,
      this.logger
    );
    let deliveredEvents = 0;
    let timeoutId: ReturnType<typeof setTimeout> | null = null;

    eventSource.addEventListener('message', event => {
      const parsed = this.parseEvent(event);
      if (!parsed) return;
      try {
        options.onEvent?.(parsed);
      } catch (error) {
        this.logger.error('Notification callback failed', { error });
      }
      deliveredEvents += 1;
      if (options.maxEvents !== undefined && deliveredEvents >= options.maxEvents) {
        eventSource.close();
      }
    });
    eventSource.addEventListener('error', error => {
      try {
        options.onError?.(new Error(`SSE connection error: ${error.type}`));
      } catch (callbackError) {
        this.logger.error('Notification error callback failed', { callbackError });
      }
    });
    eventSource.addEventListener('close', () => {
      if (timeoutId !== null) {
        clearTimeout(timeoutId);
        timeoutId = null;
      }
      try {
        options.onClose?.();
      } catch (error) {
        this.logger.error('Notification close callback failed', { error });
      }
    });

    eventSource.connect();
    if (options.timeout !== undefined) {
      timeoutId = setTimeout(() => eventSource.close(), options.timeout);
    }

    return {
      id: generateUuid(),
      resourceUri,
      get isActive(): boolean {
        return !eventSource.isClosed;
      },
      close: async (): Promise<void> => eventSource.close(),
      resume: async (cursor: string): Promise<void> => eventSource.resume(cursor),
    };
  }

  private buildNotificationsUrl(resourceUri: string): string {
    const baseUrl = this.resourceClient.getHttpClient().getConfig().baseUrl;
    const url = new URL(this.config.notificationsPath, baseUrl);
    url.searchParams.set('resource', resourceUri);
    return url.toString();
  }

  private validateResourceUri(resourceUri: ResourceUri | ContainerUri): string {
    if (!resourceUri?.trim()) {
      throw new ValidationError('Resource URI is required', 'resourceUri');
    }
    const base = new URL(this.resourceClient.getHttpClient().getConfig().baseUrl);
    let resource: URL;
    try {
      resource = new URL(resourceUri, base);
    } catch {
      throw new ValidationError('Resource URI is invalid', 'resourceUri');
    }
    if (!['http:', 'https:'].includes(resource.protocol)) {
      throw new ValidationError('Resource URI must use HTTP or HTTPS', 'resourceUri');
    }
    if (resource.username || resource.password) {
      throw new ValidationError('Resource URI must not contain credentials', 'resourceUri');
    }
    if (resource.origin !== base.origin) {
      throw new ValidationError('Resource URI is outside the configured origin', 'resourceUri');
    }
    const basePath = base.pathname.endsWith('/') ? base.pathname : `${base.pathname}/`;
    const resourcePath = resource.pathname.endsWith('/')
      ? resource.pathname
      : `${resource.pathname}/`;
    if (basePath !== '/' && resourcePath !== basePath && !resourcePath.startsWith(basePath)) {
      throw new ValidationError('Resource URI is outside the configured path scope', 'resourceUri');
    }
    resource.hash = '';
    return resource.toString();
  }

  private parseEvent(event: MessageEvent): NotificationEvent | null {
    if (typeof event.data !== 'string') return null;
    let data: unknown;
    try {
      data = JSON.parse(event.data) as unknown;
    } catch {
      return null;
    }
    if (!data || typeof data !== 'object') return null;
    const record = data as Record<string, unknown>;
    const type = record.type;
    const resource = record.resource ?? record.url;
    if (typeof type !== 'string' || !VALID_NOTIFICATION_TYPES.has(type as NotificationEventType)) {
      return null;
    }
    if (typeof resource !== 'string' || !resource) return null;
    const result: NotificationEvent = {
      id:
        event.lastEventId ||
        (typeof record.id === 'string' ? record.id : generateUuid()),
      type: type as NotificationEventType,
      resource,
      timestamp:
        typeof record.timestamp === 'string'
          ? record.timestamp
          : new Date().toISOString(),
    };
    if (typeof record.container === 'string') result.container = record.container;
    if (typeof record.agent === 'string') result.agent = record.agent;
    if (record.metadata && typeof record.metadata === 'object') {
      result.metadata = record.metadata as Record<string, unknown>;
    }
    if (typeof record.sequence === 'number' && Number.isFinite(record.sequence)) {
      result.sequence = record.sequence;
    }
    return result;
  }

  private static hasEventSource(): boolean {
    return typeof EventSource !== 'undefined';
  }

  public static polyfillEventSource(): void {
    if (NotificationClient.hasEventSource() || typeof window !== 'undefined') return;

    class NodeEventSource {
      public static readonly CONNECTING = 0;
      public static readonly OPEN = 1;
      public static readonly CLOSED = 2;
      public readonly CONNECTING = 0;
      public readonly OPEN = 1;
      public readonly CLOSED = 2;
      public readyState = NodeEventSource.CONNECTING;
      public readonly url: string;
      public withCredentials = false;
      public onopen: ((event: Event) => void) | null = null;
      public onerror: ((event: Event) => void) | null = null;
      public onmessage: ((event: MessageEvent) => void) | null = null;
      private controller: AbortController | null = null;
      private buffer = '';
      private lastEventId = '';

      constructor(url: string, options?: EventSourceInit) {
        this.url = url;
        this.withCredentials = options?.withCredentials ?? false;
        void this.connect();
      }

      private async connect(): Promise<void> {
        this.controller = new AbortController();
        try {
          const response = await fetch(this.url, {
            headers: {
              Accept: 'text/event-stream',
              ...(this.lastEventId ? { 'Last-Event-ID': this.lastEventId } : {}),
            },
            credentials: this.withCredentials ? 'include' : 'same-origin',
            signal: this.controller.signal,
          });
          if (!response.ok || !response.body) {
            throw new Error(`SSE request failed with HTTP ${response.status}`);
          }
          this.readyState = NodeEventSource.OPEN;
          this.onopen?.(new Event('open'));
          const reader = response.body.getReader();
          const decoder = new TextDecoder();
          while (this.readyState !== NodeEventSource.CLOSED) {
            const { done, value } = await reader.read();
            if (done) break;
            this.processText(decoder.decode(value, { stream: true }));
          }
          this.processText(decoder.decode());
          if (this.readyState !== NodeEventSource.CLOSED) {
            this.readyState = NodeEventSource.CLOSED;
            this.onerror?.(new Event('error'));
          }
        } catch (error) {
          if (this.readyState !== NodeEventSource.CLOSED) {
            this.readyState = NodeEventSource.CLOSED;
            this.onerror?.(new Event(error instanceof Error ? error.message : 'error'));
          }
        }
      }

      private processText(text: string): void {
        this.buffer += text.replace(/\r\n/g, '\n');
        let boundary = this.buffer.indexOf('\n\n');
        while (boundary >= 0) {
          const block = this.buffer.slice(0, boundary);
          this.buffer = this.buffer.slice(boundary + 2);
          this.processBlock(block);
          boundary = this.buffer.indexOf('\n\n');
        }
      }

      private processBlock(block: string): void {
        let eventType = 'message';
        let eventId = this.lastEventId;
        const dataLines: string[] = [];
        for (const line of block.split('\n')) {
          if (!line || line.startsWith(':')) continue;
          const separator = line.indexOf(':');
          const field = separator >= 0 ? line.slice(0, separator) : line;
          let value = separator >= 0 ? line.slice(separator + 1) : '';
          if (value.startsWith(' ')) value = value.slice(1);
          if (field === 'data') dataLines.push(value);
          else if (field === 'event') eventType = value || 'message';
          else if (field === 'id' && !value.includes('\0')) eventId = value;
        }
        if (dataLines.length === 0) return;
        this.lastEventId = eventId;
        this.onmessage?.(
          new MessageEvent(eventType, {
            data: dataLines.join('\n'),
            lastEventId: eventId,
            origin: new URL(this.url).origin,
          })
        );
      }

      public addEventListener(): void {}
      public removeEventListener(): void {}
      public dispatchEvent(): boolean {
        return true;
      }

      public close(): void {
        if (this.readyState === NodeEventSource.CLOSED) return;
        this.readyState = NodeEventSource.CLOSED;
        this.controller?.abort();
        this.controller = null;
      }
    }

    globalThis.EventSource = NodeEventSource as unknown as typeof EventSource;
  }
}

export default NotificationClient;
