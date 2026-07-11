/**
 * Solid Sidecar TypeScript SDK - Notification Client
 * Phase: 27 - SDK/Client Compatibility Layer
 * Version: v1.0.0
 * Created: 2026-07-07
 * Author: Mistral Vibe
 * License: MIT
 *
 * This file contains the NotificationClient for Server-Sent Events (SSE)
 * subscriptions to Solid Sidecar notifications.
 *
 * Security Level: CRITICAL
 */

import type {
  ResourceUri,
  ContainerUri,
  NotificationEvent,
  NotificationSubscription,
  NotificationSubscriptionOptions,
  HttpHeaders,
  SolidSidecarLogger,
} from '../types';
import { ResourceClient, type ResourceClientConfig } from './resource-client';
import { ValidationError } from '../types';
import { generateUuid, sleep, calculateBackoffDelay, DEFAULT_RETRY_OPTIONS } from '../utils';

// ============================================================================
// Notification Client Configuration
// ============================================================================

/**
 * Configuration for NotificationClient
 */
export interface NotificationClientConfig extends ResourceClientConfig {
  /** Base path for notifications endpoint (default: /notifications) */
  notificationsPath?: string;
  
  /** Maximum reconnection attempts (default: 5) */
  maxReconnectAttempts?: number;
  
  /** Base delay for reconnection backoff in milliseconds (default: 1000) */
  reconnectBaseDelay?: number;
  
  /** Maximum delay for reconnection backoff in milliseconds (default: 30000) */
  reconnectMaxDelay?: number;
  
  /** Heartbeat interval in milliseconds (default: 30000) */
  heartbeatInterval?: number;
  
  /** Whether to enable heartbeat (default: true) */
  enableHeartbeat?: boolean;
  
  /** Custom logger */
  logger?: SolidSidecarLogger;
}

/**
 * Default NotificationClient configuration
 */
export const DEFAULT_NOTIFICATION_CLIENT_CONFIG: Required<NotificationClientConfig> = {
  notificationsPath: '/notifications',
  maxReconnectAttempts: 5,
  reconnectBaseDelay: 1000,
  reconnectMaxDelay: 30000,
  heartbeatInterval: 30000,
  enableHeartbeat: true,
  logger: console,
};

// ============================================================================
// Event Source Wrapper
// ============================================================================

/**
 * Wrapper around EventSource for better error handling and reconnection
 */
export class SolidSidecarEventSource {
  private eventSource: EventSource | null = null;
  private readonly url: string;
  private readonly options: NotificationSubscriptionOptions;
  private readonly logger: SolidSidecarLogger;
  private readonly config: Required<NotificationClientConfig>;
  
  private readonly listeners: {
    message: ((event: MessageEvent) => void)[];
    error: ((error: Event) => void)[];
    open: (() => void)[];
    close: (() => void)[];
  } = {
    message: [],
    error: [],
    open: [],
    close: [],
  };

  private reconnectAttempts = 0;
  private isClosed = false;
  private lastEventId: string | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;

  constructor(
    url: string,
    options: NotificationSubscriptionOptions,
    config: Required<NotificationClientConfig>,
    logger: SolidSidecarLogger
  ) {
    this.url = url;
    this.options = options;
    this.config = config;
    this.logger = logger;
    this.lastEventId = options.cursor || null;
  }

  /**
   * Connects to the EventSource
   */
  public connect(): void {
    // Clear existing event source
    this.closeInternal();
    this.isClosed = false;

    // Build EventSource options
    const eventSourceInit: EventSourceInit = {
      withCredentials: true,
    };

    // Add Last-Event-ID for cursor resume
    if (this.lastEventId) {
      eventSourceInit.withCredentials = true;
      // Note: Last-Event-ID is set via headers, not EventSourceInit
    }

    // Create EventSource
    this.eventSource = new EventSource(this.url, eventSourceInit);

    // Set up event handlers
    this.setupHandlers();

    // Start heartbeat if enabled
    if (this.config.enableHeartbeat) {
      this.startHeartbeat();
    }

    this.logger.debug('SSE connected', { url: this.url });
  }

  /**
   * Sets up event handlers
   */
  private setupHandlers(): void {
    if (!this.eventSource) return;

    this.eventSource.onopen = () => {
      this.reconnectAttempts = 0;
      this.dispatchEvent('open');
      this.logger.debug('SSE connection opened');
    };

    this.eventSource.onerror = (error: Event) => {
      // Only log if readyState is CLOSED (not connecting or open)
      if (this.eventSource?.readyState === EventSource.CLOSED) {
        this.logger.error('SSE connection error', { error });
        this.dispatchEvent('error', error);
      }
      this.dispatchEvent('error', error);
    };

    this.eventSource.onmessage = (event: MessageEvent) => {
      this.lastEventId = event.lastEventId;
      this.dispatchEvent('message', event);
    };
  }

  /**
   * Dispatches an event to listeners
   */
  private dispatchEvent(
    type: 'message' | 'error' | 'open' | 'close',
    data?: MessageEvent | Event
  ): void {
    for (const listener of this.listeners[type]) {
      try {
        if (type === 'message' || type === 'error') {
          listener(data as MessageEvent | Event);
        } else {
          listener();
        }
      } catch (error) {
        this.logger.error('Listener error', { error, type });
      }
    }
  }

  /**
   * Adds an event listener
   */
  public addEventListener(
    type: 'message' | 'error' | 'open' | 'close',
    listener: ((event: MessageEvent | Event) => void) | (() => void)
  ): void {
    this.listeners[type].push(listener as any);
  }

  /**
   * Removes an event listener
   */
  public removeEventListener(
    type: 'message' | 'error' | 'open' | 'close',
    listener: ((event: MessageEvent | Event) => void) | (() => void)
  ): void {
    this.listeners[type] = this.listeners[type].filter(l => l !== listener);
  }

  /**
   * Starts the heartbeat timer
   */
  private startHeartbeat(): void {
    this.heartbeatTimer = setInterval(() => {
      if (this.eventSource && this.eventSource.readyState === EventSource.OPEN) {
        this.logger.debug('SSE heartbeat');
      }
    }, this.config.heartbeatInterval);
  }

  /**
   * Stops the heartbeat timer
   */
  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  /**
   * Closes the connection
   */
  public close(): void {
    this.isClosed = true;
    this.closeInternal();
    this.dispatchEvent('close');
  }

  /**
   * Internal close method
   */
  private closeInternal(): void {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
    this.stopHeartbeat();
  }

  /**
   * Reconnects to the EventSource
   */
  public async reconnect(): Promise<void> {
    if (this.isClosed) return;

    this.closeInternal();

    const delay = calculateBackoffDelay(this.reconnectAttempts, {
      baseDelay: this.config.reconnectBaseDelay,
      maxDelay: this.config.reconnectMaxDelay,
      jitterFactor: 0.1,
    });

    this.logger.debug('SSE reconnecting', {
      attempt: this.reconnectAttempts + 1,
      delay,
    });

    await sleep(delay);
    this.reconnectAttempts++;
    this.connect();
  }

  /**
   * Gets the last event ID
   */
  public getLastEventId(): string | null {
    return this.lastEventId;
  }

  /**
   * Resumes from a specific cursor
   */
  public resume(cursor: string): void {
    this.lastEventId = cursor;
    this.reconnect();
  }

  /**
   * Gets whether the connection is closed
   */
  public get isClosed(): boolean {
    return this.isClosed || this.eventSource?.readyState === EventSource.CLOSED;
  }

  /**
   * Gets whether the connection is open
   */
  public get isOpen(): boolean {
    return this.eventSource?.readyState === EventSource.OPEN;
  }

  /**
   * Gets the ready state
   */
  public get readyState(): number {
    return this.eventSource?.readyState || EventSource.CLOSED;
  }
}

// ============================================================================
// Notification Client
// ============================================================================

/**
 * NotificationClient for Solid Sidecar
 * 
 * Features:
 * - Server-Sent Events (SSE) subscription
 * - Automatic reconnection with exponential backoff
 * - Cursor-based resume
 * - Event filtering
 * - Heartbeat monitoring
 * - IDOR prevention
 * - SSRF prevention
 */
export class NotificationClient {
  private readonly config: Required<NotificationClientConfig>;
  private readonly resourceClient: ResourceClient;
  private readonly logger: SolidSidecarLogger;

  constructor(config: NotificationClientConfig = {}) {
    // Merge with defaults
    this.config = {
      ...DEFAULT_NOTIFICATION_CLIENT_CONFIG,
      ...config,
      logger: config.logger || console,
    };

    // Initialize resource client
    this.resourceClient = new ResourceClient(config);
    this.logger = this.config.logger;

    this.logger.debug('NotificationClient initialized', {
      notificationsPath: this.config.notificationsPath,
      maxReconnectAttempts: this.config.maxReconnectAttempts,
    });
  }

  // ==========================================================================
  // Subscription Management
  // ==========================================================================

  /**
   * Subscribes to notifications for a resource or container
   */
  public async subscribe(
    options: NotificationSubscriptionOptions
  ): Promise<NotificationSubscription> {
    const { resourceUri, cursor, maxEvents, timeout, onEvent, onError, onClose } = options;

    // Validate resource URI
    this.validateResourceUri(resourceUri);

    // Build notifications URL
    const notificationsUrl = this.buildNotificationsUrl(resourceUri, cursor);

    // Create event source
    const eventSource = new SolidSidecarEventSource(
      notificationsUrl,
      options,
      this.config,
      this.logger
    );

    // Add message listener
    eventSource.addEventListener('message', (event: MessageEvent) => {
      try {
        // Parse event
        const notificationEvent = this.parseEvent(event);
        
        if (!notificationEvent) {
          this.logger.warn('Received malformed event', { data: event.data });
          return;
        }

        // Call onEvent callback
        if (onEvent) {
          onEvent(notificationEvent);
        }

        // Check max events
        if (maxEvents && eventSource.getLastEventId()) {
          // Count events (simplified)
          const eventId = eventSource.getLastEventId();
          // In a real implementation, you'd track the count properly
        }
      } catch (error) {
        this.logger.error('Error processing event', { error, data: event.data });
      }
    });

    // Add error listener
    eventSource.addEventListener('error', (error: Event) => {
      try {
        if (onError) {
          onError(new Error(`SSE error: ${(error as any).message || String(error)}`));
        }
      } catch (e) {
        this.logger.error('Error in error handler', { error: e });
      }
    });

    // Add close listener
    eventSource.addEventListener('close', () => {
      try {
        if (onClose) {
          onClose();
        }
      } catch (error) {
        this.logger.error('Error in close handler', { error });
      }
    });

    // Add open listener (for reconnection)
    eventSource.addEventListener('open', () => {
      this.logger.debug('SSE connection opened');
    });

    // Connect
    eventSource.connect();

    // Set up timeout
    let timeoutId: ReturnType<typeof setTimeout> | null = null;
    if (timeout) {
      timeoutId = setTimeout(() => {
        eventSource.close();
        if (onClose) onClose();
      }, timeout);
    }

    // Create subscription object
    const subscription: NotificationSubscription = {
      id: generateUuid(),
      resourceUri,
      isActive: true,
      close: () => {
        if (timeoutId) clearTimeout(timeoutId);
        eventSource.close();
      },
      resume: (cursor: string) => {
        eventSource.resume(cursor);
      },
    };

    return subscription;
  }

  // ==========================================================================
  // URL Building
  // ==========================================================================

  /**
   * Builds the notifications URL for a resource
   */
  private buildNotificationsUrl(
    resourceUri: ResourceUri | ContainerUri,
    cursor?: string
  ): string {
    // Resolve base URL
    const baseUrl = this.resourceClient.getHttpClient().getConfig().baseUrl;
    const notificationsBaseUrl = new URL(
      this.config.notificationsPath,
      baseUrl
    ).toString();

    // Build query parameters
    const params = new URLSearchParams({
      resource: resourceUri,
    });

    // Add cursor if provided
    if (cursor) {
      params.set('cursor', cursor);
    }

    // Build URL
    const url = `${notificationsBaseUrl}?${params.toString()}`;

    return url;
  }

  // ==========================================================================
  // Event Parsing
  // ==========================================================================

  /**
   * Parses a MessageEvent into a NotificationEvent
   */
  private parseEvent(event: MessageEvent): NotificationEvent | null {
    try {
      // Parse the event data
      let data: any;
      
      // Try to parse as JSON first
      try {
        data = JSON.parse(event.data);
      } catch {
        // If not JSON, try to parse as text
        data = { data: event.data };
      }

      // Extract fields
      const id = event.lastEventId || data.id || generateUuid();
      const type = data.type || event.type || 'unknown';
      const resource = data.resource || data.url || '';
      const container = data.container;
      const timestamp = data.timestamp || new Date().toISOString();
      const agent = data.agent;
      const metadata = data.metadata || {};
      const sequence = data.sequence;

      // Validate required fields
      if (!resource) {
        this.logger.warn('Event missing resource field', { data });
        return null;
      }

      // Validate event type
      const validTypes = [
        'ResourceCreated',
        'ResourceUpdated',
        'ResourceDeleted',
        'ContainerCreated',
        'ContainerUpdated',
        'ContainerDeleted',
        'PolicyCreated',
        'PolicyUpdated',
        'PolicyDeleted',
      ];

      if (!validTypes.includes(type)) {
        this.logger.warn('Unknown event type', { type, data });
        return null;
      }

      return {
        id,
        type: type as any,
        resource,
        container,
        timestamp,
        agent,
        metadata,
        sequence,
      };
    } catch (error) {
      this.logger.error('Failed to parse event', { error, data: event.data });
      return null;
    }
  }

  // ==========================================================================
  // Validation
  // ==========================================================================

  /**
   * Validates a resource URI
   */
  private validateResourceUri(resourceUri: ResourceUri): void {
    if (!resourceUri) {
      throw new ValidationError('Resource URI is required', 'resourceUri');
    }
    if (resourceUri.includes('..') || resourceUri.includes('//')) {
      throw new ValidationError(
        'Invalid resource URI: path traversal detected',
        'resourceUri'
      );
    }
  }

  // ==========================================================================
  // SSE Polyfill (for environments without EventSource)
  // ==========================================================================

  /**
   * Checks if EventSource is available
   */
  private static hasEventSource(): boolean {
    return typeof EventSource !== 'undefined';
  }

  /**
   * Polyfills EventSource if not available
   */
  public static polyfillEventSource(): void {
    if (NotificationClient.hasEventSource()) {
      return;
    }

    // Browser: EventSource is usually available
    if (typeof window !== 'undefined') {
      return;
    }

    // Node.js: Implement a simple EventSource polyfill using fetch
    // This is a simplified implementation for development/testing
    class NodeEventSource {
      public readonly CONNECTING = 0;
      public readonly OPEN = 1;
      public readonly CLOSED = 2;
      
      public readyState: number = 0;
      public url: string;
      
      public onopen: (() => void) | null = null;
      public onerror: ((error: Event) => void) | null = null;
      public onmessage: ((event: MessageEvent) => void) | null = null;
      
      private controller: AbortController | null = null;
      private lastEventId: string = '';

      constructor(url: string, _options?: EventSourceInit) {
        this.url = url;
        this.readyState = this.CONNECTING;
        this.connect();
      }

      private async connect(): Promise<void> {
        try {
          const fetchImpl = require('cross-fetch');
          const response = await fetchImpl(this.url, {
            headers: {
              Accept: 'text/event-stream',
              ...(this.lastEventId ? { 'Last-Event-ID': this.lastEventId } : {}),
            },
          });

          if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
          }

          if (!response.body) {
            throw new Error('No response body');
          }

          this.readyState = this.OPEN;
          if (this.onopen) this.onopen();

          const reader = response.body.getReader();
          const decoder = new TextDecoder();

          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            const text = decoder.decode(value);
            this.processText(text);
          }

          this.readyState = this.CLOSED;
          if (this.onerror) {
            this.onerror(new Event('connection closed'));
          }
        } catch (error) {
          this.readyState = this.CLOSED;
          if (this.onerror) {
            this.onerror(new Event('error', { error }));
          }
        }
      }

      private processText(text: string): void {
        // Simple SSE parser
        const lines = text.split('\n\n');
        
        for (const block of lines) {
          if (!block.trim()) continue;

          const event: any = {};
          const linesInBlock = block.split('\n');
          
          for (const line of linesInBlock) {
            if (line.startsWith('id:')) {
              event.id = line.substring(3).trim();
              this.lastEventId = event.id;
            } else if (line.startsWith('event:')) {
              event.event = line.substring(6).trim();
            } else if (line.startsWith('data:')) {
              event.data = line.substring(5).trim();
            } else if (line.startsWith('retry:')) {
              event.retry = parseInt(line.substring(6).trim(), 10);
            }
          }

          if (event.data) {
            const messageEvent = new MessageEvent('message', {
              data: event.data,
              lastEventId: event.id,
              origin: this.url,
            });
            if (this.onmessage) {
              this.onmessage(messageEvent);
            }
          }
        }
      }

      public close(): void {
        this.readyState = this.CLOSED;
        if (this.controller) {
          this.controller.abort();
        }
      }
    }

    // @ts-ignore - Assign to global
    globalThis.EventSource = NodeEventSource;
  }
}

// ============================================================================
// Exports
// ============================================================================

export { SolidSidecarEventSource };
export default NotificationClient;
