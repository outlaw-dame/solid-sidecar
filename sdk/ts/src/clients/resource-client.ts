/**
 * Solid Sidecar TypeScript SDK - Resource Client
 * Phase: 27 - SDK/Client Compatibility Layer
 * Version: v1.0.0
 * Created: 2026-07-07
 * Author: Mistral Vibe
 * License: MIT
 *
 * This file contains the ResourceClient for CRUD operations on Solid resources.
 *
 * Security Level: CRITICAL
 */

import type {
  Resource,
  ResourceUri,
  ContainerUri,
  ResourceMetadata,
  ContainerListing,
  ConditionalWriteOptions,
  HttpHeaders,
  HttpResponse,
  RdfFormat,
  SolidSidecarLogger,
} from '../types';
import {
  ResourceNotFoundError,
  ConflictError,
  PreconditionFailedError,
  ValidationError,
} from '../types';
import { SolidSidecarHttpClient, type HttpClientConfig } from '../http-client';
import { AuthManager } from '../auth/auth-manager';
import type { DpopProofOptions } from '../types';
import {
  resolveUrl,
  validateUrl,
  parseETag,
  etagsMatch,
  getPreferredRdfContentType,
  isRdfContentType,
  parseLinkHeaders,
  RDF_CONTENT_TYPES,
} from '../utils';

// ============================================================================
// Resource Client Configuration
// ============================================================================

/**
 * Configuration for ResourceClient
 */
export interface ResourceClientConfig extends Partial<HttpClientConfig> {
  /** HTTP client configuration */
  httpClientConfig?: HttpClientConfig;
  
  /** Auth manager (optional, for DPoP authentication) */
  authManager?: AuthManager;
  
  /** Default content type for PUT/PATCH */
  defaultContentType?: string;
  
  /** Whether to use DPoP authentication (default: true if authManager is provided) */
  useDpop?: boolean;
  
  /** Custom logger */
  logger?: SolidSidecarLogger;
}

/**
 * Default ResourceClient configuration
 */
export const DEFAULT_RESOURCE_CLIENT_CONFIG: Partial<ResourceClientConfig> = {
  defaultContentType: 'text/turtle',
  useDpop: true,
};

// ============================================================================
// Resource Client
// ============================================================================

/**
 * ResourceClient for Solid Sidecar
 * 
 * Features:
 * - CRUD operations on resources
 * - Container operations
 * - Conditional writes (ETag/If-Match/If-None-Match)
 * - DPoP authentication
 * - Content-Type negotiation
 * - Automatic retry with exponential backoff
 * - IDOR prevention
 * - SSRF prevention
 */
export class ResourceClient {
  private readonly config: Required<ResourceClientConfig>;
  private readonly httpClient: SolidSidecarHttpClient;
  private readonly authManager: AuthManager | null;
  private readonly logger: SolidSidecarLogger;

  constructor(config: ResourceClientConfig = {}) {
    // Merge with defaults
    this.config = {
      ...DEFAULT_RESOURCE_CLIENT_CONFIG,
      ...config,
      logger: config.logger || console,
    };

    // Initialize HTTP client
    this.httpClient = config.httpClientConfig
      ? new SolidSidecarHttpClient(config.httpClientConfig)
      : new SolidSidecarHttpClient();

    // Store auth manager
    this.authManager = config.authManager || null;
    this.logger = this.config.logger;

    // Log initialization
    this.logger.debug('ResourceClient initialized', {
      baseUrl: this.httpClient.getConfig().baseUrl,
      useDpop: this.config.useDpop && !!this.authManager,
    });
  }

  // ==========================================================================
  // GET Operations
  // ==========================================================================

  /**
   * Gets a resource
   */
  public async get(
    resourceUri: ResourceUri,
    headers?: HttpHeaders,
    accept?: string
  ): Promise<Resource> {
    // Validate resource URI for IDOR prevention
    this.validateResourceUri(resourceUri);

    // Resolve URL
    const url = resolveUrl(this.httpClient.getConfig().baseUrl, resourceUri);

    // Add authentication headers
    const authHeaders = await this.getAuthHeaders('GET', url);

    // Merge headers
    const mergedHeaders = {
      ...authHeaders,
      ...headers,
      ...(accept && { Accept: accept }),
    };

    // Make request
    const response = await this.httpClient.get(url, mergedHeaders);

    // Parse response
    const metadata = this.parseResourceMetadata(response.headers, resourceUri);

    return {
      uri: resourceUri,
      metadata,
      content: response.body as string,
    };
  }

  /**
   * Gets resource metadata only (HEAD request)
   */
  public async head(
    resourceUri: ResourceUri,
    headers?: HttpHeaders
  ): Promise<ResourceMetadata> {
    // Validate resource URI
    this.validateResourceUri(resourceUri);

    // Resolve URL
    const url = resolveUrl(this.httpClient.getConfig().baseUrl, resourceUri);

    // Add authentication headers
    const authHeaders = await this.getAuthHeaders('HEAD', url);

    // Merge headers
    const mergedHeaders = {
      ...authHeaders,
      ...headers,
    };

    // Make request
    const response = await this.httpClient.head(url, mergedHeaders);

    // Parse metadata
    return this.parseResourceMetadata(response.headers, resourceUri);
  }

  // ==========================================================================
  // PUT Operations
  // ==========================================================================

  /**
   * Creates or replaces a resource
   */
  public async put(
    resourceUri: ResourceUri,
    content: string | Uint8Array,
    options: {
      contentType?: string;
      headers?: HttpHeaders;
      ifMatch?: string | string[];
      ifNoneMatch?: string | string[];
      link?: string;
    } = {}
  ): Promise<ResourceMetadata> {
    const {
      contentType = this.config.defaultContentType,
      headers = {},
      ifMatch,
      ifNoneMatch,
      link,
    } = options;

    // Validate resource URI
    this.validateResourceUri(resourceUri);

    // Resolve URL
    const url = resolveUrl(this.httpClient.getConfig().baseUrl, resourceUri);

    // Add authentication headers
    const authHeaders = await this.getAuthHeaders('PUT', url);

    // Merge headers
    const mergedHeaders = {
      ...authHeaders,
      ...headers,
      'Content-Type': contentType,
      ...(ifMatch && { 'If-Match': this.formatEtag(ifMatch) }),
      ...(ifNoneMatch && { 'If-None-Match': this.formatEtag(ifNoneMatch) }),
      ...(link && { Link: link }),
    };

    // Make request
    const response = await this.httpClient.put(url, content, mergedHeaders);

    // Parse metadata from response
    return this.parseResourceMetadata(response.headers, resourceUri);
  }

  // ==========================================================================
  // PATCH Operations
  // ==========================================================================

  /**
   * Partially updates a resource (SPARQL Update)
   */
  public async patch(
    resourceUri: ResourceUri,
    sparqlUpdate: string,
    options: {
      contentType?: string;
      headers?: HttpHeaders;
      ifMatch?: string | string[];
    } = {}
  ): Promise<ResourceMetadata> {
    const {
      contentType = 'application/sparql-update',
      headers = {},
      ifMatch,
    } = options;

    // Validate resource URI
    this.validateResourceUri(resourceUri);

    // Resolve URL
    const url = resolveUrl(this.httpClient.getConfig().baseUrl, resourceUri);

    // Add authentication headers
    const authHeaders = await this.getAuthHeaders('PATCH', url);

    // Merge headers
    const mergedHeaders = {
      ...authHeaders,
      ...headers,
      'Content-Type': contentType,
      ...(ifMatch && { 'If-Match': this.formatEtag(ifMatch) }),
    };

    // Make request
    const response = await this.httpClient.patch(url, sparqlUpdate, mergedHeaders);

    // Parse metadata from response
    return this.parseResourceMetadata(response.headers, resourceUri);
  }

  // ==========================================================================
  // DELETE Operations
  // ==========================================================================

  /**
   * Deletes a resource
   */
  public async delete(
    resourceUri: ResourceUri,
    options: {
      headers?: HttpHeaders;
      ifMatch?: string | string[];
    } = {}
  ): Promise<void> {
    const {
      headers = {},
      ifMatch,
    } = options;

    // Validate resource URI
    this.validateResourceUri(resourceUri);

    // Resolve URL
    const url = resolveUrl(this.httpClient.getConfig().baseUrl, resourceUri);

    // Add authentication headers
    const authHeaders = await this.getAuthHeaders('DELETE', url);

    // Merge headers
    const mergedHeaders = {
      ...authHeaders,
      ...headers,
      ...(ifMatch && { 'If-Match': this.formatEtag(ifMatch) }),
    };

    // Make request
    await this.httpClient.delete(url, mergedHeaders);
  }

  // ==========================================================================
  // Container Operations
  // ==========================================================================

  /**
   * Lists resources in a container
   */
  public async listContainer(
    containerUri: ContainerUri,
    headers?: HttpHeaders,
    accept?: string
  ): Promise<ContainerListing> {
    // Validate container URI
    this.validateResourceUri(containerUri);

    // Ensure container URI ends with slash
    const normalizedContainerUri = containerUri.endsWith('/')
      ? containerUri
      : `${containerUri}/`;

    // Resolve URL
    const url = resolveUrl(
      this.httpClient.getConfig().baseUrl,
      normalizedContainerUri
    );

    // Add authentication headers
    const authHeaders = await this.getAuthHeaders('GET', url);

    // Merge headers
    const mergedHeaders = {
      ...authHeaders,
      ...headers,
      ...(accept && { Accept: accept }),
    };

    // Make request
    const response = await this.httpClient.get(url, mergedHeaders);

    // Parse container listing
    const resources: ResourceUri[] = [];
    const containers: ContainerUri[] = [];

    // Parse the response body to extract resource URIs
    const body = response.body as string;
    if (body) {
      // Simple parsing for Turtle format
      const lines = body.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('@')) continue;

        // Match resource declarations
        const match = trimmed.match(/<([^>]+)>\s+/);
        if (match) {
          const resourceUri = match[1];
          // Check if it's a container (ends with /)
          if (resourceUri.endsWith('/')) {
            containers.push(resourceUri);
          } else {
            resources.push(resourceUri);
          }
        }
      }
    }

    // Parse metadata
    const metadata = this.parseResourceMetadata(response.headers, containerUri);

    return {
      containerUri: normalizedContainerUri,
      resources,
      containers,
      metadata,
    };
  }

  // ==========================================================================
  // Conditional Operations
  // ==========================================================================

  /**
   * Creates a resource with If-None-Match precondition
   */
  public async create(
    resourceUri: ResourceUri,
    content: string | Uint8Array,
    options: {
      contentType?: string;
      headers?: HttpHeaders;
    } = {}
  ): Promise<ResourceMetadata> {
    return this.put(resourceUri, content, {
      ...options,
      ifNoneMatch: '*',
    });
  }

  /**
   * Updates a resource with If-Match precondition
   */
  public async update(
    resourceUri: ResourceUri,
    content: string | Uint8Array,
    options: {
      contentType?: string;
      headers?: HttpHeaders;
      ifMatch: string | string[];
    } & ConditionalWriteOptions = {}
  ): Promise<ResourceMetadata> {
    if (!options.ifMatch) {
      // Get current ETag
      const metadata = await this.head(resourceUri);
      options.ifMatch = metadata.etag || '*';
    }

    return this.put(resourceUri, content, options);
  }

  // ==========================================================================
  // Metadata Parsing
  // ==========================================================================

  /**
   * Parses resource metadata from response headers
   */
  private parseResourceMetadata(
    headers: HttpHeaders,
    resourceUri: ResourceUri
  ): ResourceMetadata {
    const metadata: ResourceMetadata = {
      uri: resourceUri,
      exists: true,
    };

    // Content-Type
    if (headers['content-type']) {
      metadata.contentType = headers['content-type'];
    }

    // Content-Length
    if (headers['content-length']) {
      metadata.contentLength = parseInt(headers['content-length'], 10);
    }

    // ETag
    if (headers['etag']) {
      metadata.etag = parseETag(headers['etag']);
    }

    // Last-Modified
    if (headers['last-modified']) {
      metadata.lastModified = headers['last-modified'];
      metadata.lastModifiedAt = new Date(headers['last-modified']).getTime();
    }

    // Link headers
    metadata.links = parseLinkHeaders(headers);

    return metadata;
  }

  // ==========================================================================
  // Authentication Helpers
  // ==========================================================================

  /**
   * Gets authentication headers for a request
   */
  private async getAuthHeaders(
    method: string,
    url: string
  ): Promise<HttpHeaders> {
    const headers: HttpHeaders = {};

    // Add DPoP authentication if enabled
    if (this.config.useDpop && this.authManager) {
      try {
        const { accessToken, dpopProof } = await this.authManager.signRequest(
          method,
          url
        );
        headers.Authorization = `DPoP ${accessToken}`;
        headers.DPoP = dpopProof;
      } catch (error) {
        this.logger.warn('Failed to get DPoP authentication', { error });
      }
    }

    return headers;
  }

  // ==========================================================================
  // Validation Helpers
  // ==========================================================================

  /**
   * Validates a resource URI for IDOR prevention
   */
  private validateResourceUri(resourceUri: ResourceUri): void {
    // Basic URL validation
    if (!resourceUri) {
      throw new ValidationError('Resource URI is required', 'resourceUri');
    }

    // Check for path traversal
    if (resourceUri.includes('..') || resourceUri.includes('//')) {
      throw new ValidationError(
        'Invalid resource URI: path traversal detected',
        'resourceUri'
      );
    }

    // Resolve URL and validate
    const url = resolveUrl(this.httpClient.getConfig().baseUrl, resourceUri);
    if (!validateUrl(url)) {
      throw new ValidationError('Invalid resource URI', 'resourceUri');
    }
  }

  // ==========================================================================
  // ETag Formatting
  // ==========================================================================

  /**
   * Formats ETag(s) for If-Match/If-None-Match headers
   */
  private formatEtag(etag: string | string[]): string {
    if (Array.isArray(etag)) {
      return etag.map(e => `"${e}"`).join(', ');
    }
    return `"${etag}"`;
  }

  // ==========================================================================
  // Getters
  // ==========================================================================

  /**
   * Gets the HTTP client
   */
  public getHttpClient(): SolidSidecarHttpClient {
    return this.httpClient;
  }

  /**
   * Gets the auth manager
   */
  public getAuthManager(): AuthManager | null {
    return this.authManager;
  }

  /**
   * Gets the configuration
   */
  public getConfig(): Required<ResourceClientConfig> {
    return { ...this.config };
  }
}

// ============================================================================
// Exports
// ============================================================================

export default ResourceClient;
