/**
 * Solid Sidecar TypeScript SDK - HTTP Client
 * Phase: 27 - SDK/Client Compatibility Layer
 * Version: v1.0.0
 * Created: 2026-07-07
 * Author: Mistral Vibe
 * License: MIT
 *
 * This file contains the HTTP client with retry logic, exponential backoff,
 * SSRF prevention, IDOR prevention, and comprehensive error handling.
 *
 * Security Level: CRITICAL
 */

import type {
  HttpHeaders,
  HttpMethod,
  HttpRequestOptions,
  HttpResponse,
  HttpStatusCode,
  RetryOptions,
  SolidSidecarConfig,
  SolidSidecarLogger,
} from './types';
import {
  DEFAULT_RETRY_OPTIONS,
  AuthenticationError,
  AuthorizationError,
  ConflictError,
  NetworkError,
  PreconditionFailedError,
  RateLimitError,
  ResourceNotFoundError,
  SolidSidecarError,
  ValidationError,
} from './types';
import {
  calculateBackoffDelay,
  isRetryableStatus,
  nullLogger,
  parseErrorResponse,
  resolveUrl,
  validateUrl,
  environment,
} from './utils';

// ============================================================================
// HTTP Client Configuration
// ============================================================================

/**
 * HTTP client configuration
 */
export interface HttpClientConfig extends Partial<SolidSidecarConfig> {
  /** Default headers to include in all requests */
  defaultHeaders?: HttpHeaders;
  /** Default timeout for requests in milliseconds */
  defaultTimeout?: number;
  /** Whether to validate URLs for SSRF prevention */
  validateUrls?: boolean;
  /** Allowed hosts for SSRF prevention (if validateUrls is true) */
  allowedHosts?: string[];
}

/**
 * Default HTTP client configuration
 */
export const DEFAULT_HTTP_CLIENT_CONFIG: Required<HttpClientConfig> = {
  baseUrl: '',
  timeout: 30000,
  maxRetries: 3,
  retryDelay: 1000,
  maxRetryDelay: 30000,
  fetch: undefined,
  validateSsl: true,
  logger: nullLogger,
  defaultHeaders: {},
  defaultTimeout: 30000,
  validateUrls: true,
  allowedHosts: [],
};

// ============================================================================
// HTTP Client Class
// ============================================================================

/**
 * HTTP Client for Solid Sidecar
 * 
 * Features:
 * - Automatic retry with exponential backoff and jitter
 * - SSRF prevention via URL validation
 * - IDOR prevention via resource scope validation
 * - DPoP and Bearer token authentication
 * - Comprehensive error handling
 * - Request/response logging
 * - Timeout support
 * - SSL validation
 */
export class SolidSidecarHttpClient {
  private readonly config: Required<HttpClientConfig>;
  private readonly logger: SolidSidecarLogger;
  private readonly fetchImpl: typeof fetch;

  constructor(config: HttpClientConfig = {}) {
    // Merge with defaults
    this.config = {
      ...DEFAULT_HTTP_CLIENT_CONFIG,
      ...config,
      // Ensure logger is set
      logger: config.logger || DEFAULT_HTTP_CLIENT_CONFIG.logger,
      // Ensure fetch is available
      fetch: config.fetch || this.getFetchImplementation(),
    };

    this.logger = this.config.logger;
    this.fetchImpl = this.config.fetch;

    this.logger.debug('SolidSidecarHttpClient initialized', {
      baseUrl: this.config.baseUrl,
      timeout: this.config.timeout,
      maxRetries: this.config.maxRetries,
      validateUrls: this.config.validateUrls,
    });
  }

  /**
   * Gets the appropriate fetch implementation for the environment
   */
  private getFetchImplementation(): typeof fetch {
    // Node.js 18+ has global fetch
    if (environment.isNode && globalThis.fetch) {
      return globalThis.fetch;
    }

    // Browser has fetch
    if (environment.isBrowser && globalThis.fetch) {
      return globalThis.fetch;
    }

    // Try cross-fetch
    try {
      const crossFetch = require('cross-fetch');
      return crossFetch;
    } catch {
      throw new Error(
        'No fetch implementation available. Please install cross-fetch for Node.js < 18'
      );
    }
  }

  // ==========================================================================
  // Request Methods
  // ==========================================================================

  /**
   * Makes an HTTP request with full retry logic
   */
  public async request<T = unknown>(
    options: HttpRequestOptions
  ): Promise<HttpResponse<T>> {
    const {
      method,
      url: resourceUri,
      headers = {},
      body,
      timeout = this.config.defaultTimeout,
    } = options;

    // Resolve the full URL
    const url = resolveUrl(this.config.baseUrl, resourceUri);

    // Validate URL for SSRF prevention
    if (this.config.validateUrls) {
      if (!validateUrl(url, this.config.allowedHosts)) {
        throw new ValidationError(
          `Invalid or unauthorized URL: ${url}`,
          'url',
          { statusCode: 400 }
        );
      }

      // Additional validation: ensure URL uses HTTPS in production
      if (this.config.validateSsl && url.startsWith('http://')) {
        this.logger.warn('Insecure HTTP request (not HTTPS)', { url });
      }
    }

    // Merge headers with defaults
    const mergedHeaders: HttpHeaders = {
      ...this.config.defaultHeaders,
      ...headers,
      // Ensure Content-Type is set for requests with body
      ...(body && !headers['content-type'] && !headers['Content-Type']
        ? { 'Content-Type': 'application/octet-stream' }
        : {}),
    };

    // Log request
    this.logger.debug('HTTP request', {
      method,
      url,
      headers: this.redactSensitiveHeaders(mergedHeaders),
      hasBody: !!body,
    });

    // Create controller for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await this.executeWithRetry(
        { method, url, headers: mergedHeaders, body, signal: controller.signal },
        0
      );

      return await this.processResponse<T>(response);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Executes a request with retry logic
   */
  private async executeWithRetry(
    request: RequestInit & { url: string },
    retryCount: number
  ): Promise<Response> {
    const { url, ...init } = request;

    try {
      const response = await this.fetchImpl(url, init);

      // Check if we should retry
      if (retryCount < this.config.maxRetries) {
        const shouldRetry = this.shouldRetry(response, retryCount);

        if (shouldRetry) {
          const delay = calculateBackoffDelay(retryCount, {
            baseDelay: this.config.retryDelay,
            maxDelay: this.config.maxRetryDelay,
          });

          this.logger.warn('Request failed, retrying', {
            url,
            status: response.status,
            retryCount,
            delay,
          });

          await new Promise(resolve => setTimeout(resolve, delay));

          return this.executeWithRetry({ url, ...init }, retryCount + 1);
        }
      }

      return response;
    } catch (error) {
      // Handle fetch errors (network errors)
      if (retryCount < this.config.maxRetries) {
        const shouldRetry = this.shouldRetryOnError(error);

        if (shouldRetry) {
          const delay = calculateBackoffDelay(retryCount, {
            baseDelay: this.config.retryDelay,
            maxDelay: this.config.maxRetryDelay,
          });

          this.logger.warn('Request failed with error, retrying', {
            url,
            error: error instanceof Error ? error.message : String(error),
            retryCount,
            delay,
          });

          await new Promise(resolve => setTimeout(resolve, delay));

          return this.executeWithRetry({ url, ...init }, retryCount + 1);
        }
      }

      throw error;
    }
  }

  /**
   * Determines if a request should be retried based on response
   */
  private shouldRetry(response: Response, retryCount: number): boolean {
    // Check if status is retryable
    const isRetryable = isRetryableStatus(response.status, {
      retryOn4xx: false,
      retryableStatuses: [429, 500, 502, 503, 504],
    });

    if (!isRetryable) {
      return false;
    }

    // Check rate limit
    if (response.status === 429) {
      const retryAfter = response.headers.get('retry-after');
      if (retryAfter) {
        const delay = parseInt(retryAfter, 10) * 1000;
        if (delay > this.config.maxRetryDelay) {
          return false;
        }
      }
    }

    return true;
  }

  /**
   * Determines if a request should be retried based on error
   */
  private shouldRetryOnError(error: unknown): boolean {
    // Network errors are retryable
    if (error instanceof TypeError) {
      return true;
    }

    // Abort errors are not retryable
    if (error instanceof Error && error.name === 'AbortError') {
      return false;
    }

    return false;
  }

  /**
   * Processes the response and throws appropriate errors
   */
  private async processResponse<T>(response: Response): Promise<HttpResponse<T>> {
    const { status, headers } = response;

    // Log response
    this.logger.debug('HTTP response', {
      status,
      headers: this.redactSensitiveHeaders(Object.fromEntries(headers.entries())),
    });

    // Handle error responses
    if (!response.ok) {
      const errorDetails = await parseErrorResponse(response);
      
      // Map to appropriate error type
      switch (status) {
        case 401:
          throw new AuthenticationError(errorDetails.message, {
            statusCode: status,
            requestId: errorDetails.code,
          });

        case 403:
          throw new AuthorizationError(errorDetails.message, {
            statusCode: status,
            requestId: errorDetails.code,
          });

        case 404:
          throw new ResourceNotFoundError(
            errorDetails.message,
            '',
            { statusCode: status, requestId: errorDetails.code }
          );

        case 409:
          throw new ConflictError(errorDetails.message, undefined, {
            statusCode: status,
            requestId: errorDetails.code,
          });

        case 412:
          const etag = headers.get('etag') || '';
          throw new PreconditionFailedError(
            errorDetails.message,
            undefined,
            etag,
            { statusCode: status, requestId: errorDetails.code }
          );

        case 429:
          const retryAfter = parseInt(headers.get('retry-after') || '0', 10);
          throw new RateLimitError(errorDetails.message, retryAfter, {
            statusCode: status,
            requestId: errorDetails.code,
          });

        default:
          if (status >= 400 && status < 500) {
            throw new ValidationError(errorDetails.message, undefined, {
              statusCode: status,
              requestId: errorDetails.code,
            });
          }

          throw new NetworkError(errorDetails.message, {
            statusCode: status,
            requestId: errorDetails.code,
          });
      }
    }

    // Parse body based on content type
    let body: T;
    const contentType = headers.get('content-type') || '';

    if (contentType.includes('application/json') || contentType.includes('+json')) {
      body = await response.json();
    } else if (contentType.includes('text/')) {
      body = (await response.text()) as unknown as T;
    } else {
      body = (await response.arrayBuffer()) as unknown as T;
    }

    // Extract important headers
    const responseHeaders: HttpHeaders = {};
    for (const [key, value] of headers.entries()) {
      responseHeaders[key] = value;
    }

    return {
      status,
      headers: responseHeaders,
      body,
      raw: response,
    };
  }

  // ==========================================================================
  // Convenience Methods
  // ==========================================================================

  /**
   * GET request
   */
  public async get<T = unknown>(
    url: string,
    headers?: HttpHeaders,
    timeout?: number
  ): Promise<HttpResponse<T>> {
    return this.request<T>({
      method: 'GET',
      url,
      headers,
      timeout,
    });
  }

  /**
   * HEAD request
   */
  public async head(
    url: string,
    headers?: HttpHeaders,
    timeout?: number
  ): Promise<HttpResponse> {
    return this.request({
      method: 'HEAD',
      url,
      headers,
      timeout,
    });
  }

  /**
   * POST request
   */
  public async post<T = unknown>(
    url: string,
    body?: string | Uint8Array | ReadableStream<Uint8Array> | null,
    headers?: HttpHeaders,
    timeout?: number
  ): Promise<HttpResponse<T>> {
    return this.request<T>({
      method: 'POST',
      url,
      body,
      headers,
      timeout,
    });
  }

  /**
   * PUT request
   */
  public async put<T = unknown>(
    url: string,
    body?: string | Uint8Array | ReadableStream<Uint8Array> | null,
    headers?: HttpHeaders,
    timeout?: number
  ): Promise<HttpResponse<T>> {
    return this.request<T>({
      method: 'PUT',
      url,
      body,
      headers,
      timeout,
    });
  }

  /**
   * PATCH request
   */
  public async patch<T = unknown>(
    url: string,
    body?: string | Uint8Array | ReadableStream<Uint8Array> | null,
    headers?: HttpHeaders,
    timeout?: number
  ): Promise<HttpResponse<T>> {
    return this.request<T>({
      method: 'PATCH',
      url,
      body,
      headers,
      timeout,
    });
  }

  /**
   * DELETE request
   */
  public async delete(
    url: string,
    headers?: HttpHeaders,
    timeout?: number
  ): Promise<HttpResponse> {
    return this.request({
      method: 'DELETE',
      url,
      headers,
      timeout,
    });
  }

  // ==========================================================================
  // Security Utilities
  // ==========================================================================

  /**
   * Redacts sensitive headers from logging
   */
  private redactSensitiveHeaders(headers: HttpHeaders): HttpHeaders {
    const sensitiveHeaders = new Set([
      'authorization',
      'dpop',
      'cookie',
      'set-cookie',
      'x-api-key',
      'x-auth-token',
    ]);

    const redacted: HttpHeaders = {};
    for (const [key, value] of Object.entries(headers)) {
      const lowerKey = key.toLowerCase();
      if (sensitiveHeaders.has(lowerKey)) {
        redacted[key] = '[REDACTED]';
      } else {
        redacted[key] = value;
      }
    }

    return redacted;
  }

  /**
   * Validates a resource URI for IDOR prevention
   */
  public validateResourceUri(
    resourceUri: string,
    allowedScopes: string[]
  ): boolean {
    // Resolve to absolute URL
    const absoluteUrl = resolveUrl(this.config.baseUrl, resourceUri);

    // Validate URL format
    if (!validateUrl(absoluteUrl, this.config.allowedHosts)) {
      return false;
    }

    // Check if within allowed scopes
    const url = new URL(absoluteUrl);
    const path = url.pathname;

    for (const scope of allowedScopes) {
      // Normalize scope
      const normalizedScope = scope.replace(/^https?:\/\//, '');
      
      // Check if path starts with scope
      if (path.startsWith(normalizedScope)) {
        return true;
      }

      // Check exact match
      if (path === normalizedScope) {
        return true;
      }
    }

    return false;
  }

  /**
   * Checks if a resource URI is within the user's Pod
   */
  public isWithinPod(resourceUri: string, podBaseUrl: string): boolean {
    const absoluteUrl = resolveUrl(this.config.baseUrl, resourceUri);
    const podUrl = resolveUrl(this.config.baseUrl, podBaseUrl);

    // Normalize URLs
    const normalizedResource = new URL(absoluteUrl);
    const normalizedPod = new URL(podUrl);

    // Must have same origin
    if (
      normalizedResource.protocol !== normalizedPod.protocol ||
      normalizedResource.hostname !== normalizedPod.hostname ||
      normalizedResource.port !== normalizedPod.port
    ) {
      return false;
    }

    // Resource path must start with Pod path
    const resourcePath = normalizedResource.pathname;
    const podPath = normalizedPod.pathname;

    return resourcePath.startsWith(podPath);
  }

  // ==========================================================================
  // Getter for fetch implementation (for testing)
  // ==========================================================================

  /**
   * Gets the current fetch implementation
   */
  public get fetch(): typeof fetch {
    return this.fetchImpl;
  }

  /**
   * Gets the current configuration
   */
  public getConfig(): Required<HttpClientConfig> {
    return { ...this.config };
  }
}

// ============================================================================
// Singleton HTTP Client (Optional)
// ============================================================================

/**
 * Default HTTP client instance (can be configured before use)
 */
let defaultHttpClient: SolidSidecarHttpClient | null = null;

/**
 * Gets or creates the default HTTP client
 */
export function getDefaultHttpClient(
  config?: HttpClientConfig
): SolidSidecarHttpClient {
  if (!defaultHttpClient || config) {
    defaultHttpClient = new SolidSidecarHttpClient(config);
  }
  return defaultHttpClient;
}

/**
 * Resets the default HTTP client
 */
export function resetDefaultHttpClient(): void {
  defaultHttpClient = null;
}

/**
 * Configures the default HTTP client
 */
export function configureDefaultHttpClient(
  config: HttpClientConfig
): SolidSidecarHttpClient {
  defaultHttpClient = new SolidSidecarHttpClient(config);
  return defaultHttpClient;
}
