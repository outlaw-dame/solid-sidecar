import type {
  ContainerListing,
  ContainerUri,
  ConditionalWriteOptions,
  HttpHeaders,
  Resource,
  ResourceMetadata,
  ResourceUri,
  SolidSidecarLogger,
} from '../types';
import { ValidationError } from '../types';
import {
  SolidSidecarHttpClient,
  type HttpClientConfig,
} from '../http-client';
import { AuthManager } from '../auth/auth-manager';
import { nullLogger, parseETag, parseLinkHeaders } from '../utils';

export interface ResourceClientConfig extends Partial<HttpClientConfig> {
  httpClientConfig?: HttpClientConfig;
  authManager?: AuthManager;
  defaultContentType?: string;
  useDpop?: boolean;
  logger?: SolidSidecarLogger;
}

interface ResolvedResourceClientConfig {
  httpClientConfig: HttpClientConfig;
  authManager: AuthManager | null;
  defaultContentType: string;
  useDpop: boolean;
  logger: SolidSidecarLogger;
}

export const DEFAULT_RESOURCE_CLIENT_CONFIG = {
  defaultContentType: 'text/turtle',
  useDpop: true,
  logger: nullLogger,
} satisfies Pick<
  ResolvedResourceClientConfig,
  'defaultContentType' | 'useDpop' | 'logger'
>;

const HTTP_CONFIG_KEYS = [
  'baseUrl',
  'timeout',
  'maxRetries',
  'retryDelay',
  'maxRetryDelay',
  'fetch',
  'validateSsl',
  'logger',
  'defaultHeaders',
  'defaultTimeout',
  'validateUrls',
  'allowedHosts',
] as const satisfies readonly (keyof HttpClientConfig)[];

type WriteOptions = {
  contentType?: string;
  headers?: HttpHeaders;
  ifMatch?: string | string[];
  ifNoneMatch?: string | string[];
  link?: string;
};

function getHeader(headers: HttpHeaders, name: string): string | undefined {
  const target = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === target) return value;
  }
  return undefined;
}

export class ResourceClient {
  private readonly config: ResolvedResourceClientConfig;
  private readonly httpClient: SolidSidecarHttpClient;
  private readonly authManager: AuthManager | null;
  private readonly logger: SolidSidecarLogger;
  private readonly baseUrl: URL;

  constructor(config: ResourceClientConfig = {}) {
    const topLevelHttpConfig: HttpClientConfig = {};
    for (const key of HTTP_CONFIG_KEYS) {
      const value = config[key];
      if (value !== undefined) {
        (topLevelHttpConfig as Record<string, unknown>)[key] = value;
      }
    }

    const nestedHttpConfig = config.httpClientConfig ?? {};
    const httpLogger =
      nestedHttpConfig.logger ??
      config.logger ??
      DEFAULT_RESOURCE_CLIENT_CONFIG.logger;
    const httpClientConfig: HttpClientConfig = {
      ...topLevelHttpConfig,
      ...nestedHttpConfig,
      logger: httpLogger,
    };

    this.config = {
      httpClientConfig,
      authManager: config.authManager ?? null,
      defaultContentType:
        config.defaultContentType ??
        DEFAULT_RESOURCE_CLIENT_CONFIG.defaultContentType,
      useDpop: config.useDpop ?? DEFAULT_RESOURCE_CLIENT_CONFIG.useDpop,
      logger: config.logger ?? nestedHttpConfig.logger ?? nullLogger,
    };
    this.httpClient = new SolidSidecarHttpClient(httpClientConfig);
    this.authManager = this.config.authManager;
    this.logger = this.config.logger;

    const configuredBaseUrl = this.httpClient.getConfig().baseUrl;
    try {
      this.baseUrl = new URL(configuredBaseUrl);
    } catch {
      throw new ValidationError(
        'ResourceClient requires an absolute HTTP(S) baseUrl',
        'baseUrl'
      );
    }
    if (!['http:', 'https:'].includes(this.baseUrl.protocol)) {
      throw new ValidationError('baseUrl must use HTTP or HTTPS', 'baseUrl');
    }
    if (this.baseUrl.username || this.baseUrl.password) {
      throw new ValidationError('baseUrl must not contain credentials', 'baseUrl');
    }
  }

  public async get(
    resourceUri: ResourceUri,
    headers: HttpHeaders = {},
    accept?: string
  ): Promise<Resource> {
    const url = this.resolveResourceUrl(resourceUri);
    const response = await this.httpClient.get<string>(
      url,
      await this.buildHeaders('GET', url, headers, {
        ...(accept !== undefined && { Accept: accept }),
      })
    );
    return {
      uri: url,
      metadata: this.parseResourceMetadata(response.headers, url),
      content: response.body,
    };
  }

  public async head(
    resourceUri: ResourceUri,
    headers: HttpHeaders = {}
  ): Promise<ResourceMetadata> {
    const url = this.resolveResourceUrl(resourceUri);
    const response = await this.httpClient.head(
      url,
      await this.buildHeaders('HEAD', url, headers)
    );
    return this.parseResourceMetadata(response.headers, url);
  }

  public async put(
    resourceUri: ResourceUri,
    content: string | Uint8Array,
    options: WriteOptions = {}
  ): Promise<ResourceMetadata> {
    const url = this.resolveResourceUrl(resourceUri);
    const enforcedHeaders: HttpHeaders = {
      'Content-Type': options.contentType ?? this.config.defaultContentType,
      ...(options.ifMatch !== undefined && {
        'If-Match': this.formatEtags(options.ifMatch),
      }),
      ...(options.ifNoneMatch !== undefined && {
        'If-None-Match': this.formatEtags(options.ifNoneMatch),
      }),
      ...(options.link !== undefined && { Link: options.link }),
    };
    const response = await this.httpClient.put(
      url,
      content,
      await this.buildHeaders('PUT', url, options.headers ?? {}, enforcedHeaders)
    );
    return this.parseResourceMetadata(response.headers, url);
  }

  public async patch(
    resourceUri: ResourceUri,
    sparqlUpdate: string,
    options: {
      contentType?: string;
      headers?: HttpHeaders;
      ifMatch?: string | string[];
    } = {}
  ): Promise<ResourceMetadata> {
    const url = this.resolveResourceUrl(resourceUri);
    const response = await this.httpClient.patch(
      url,
      sparqlUpdate,
      await this.buildHeaders('PATCH', url, options.headers ?? {}, {
        'Content-Type': options.contentType ?? 'application/sparql-update',
        ...(options.ifMatch !== undefined && {
          'If-Match': this.formatEtags(options.ifMatch),
        }),
      })
    );
    return this.parseResourceMetadata(response.headers, url);
  }

  public async delete(
    resourceUri: ResourceUri,
    options: { headers?: HttpHeaders; ifMatch?: string | string[] } = {}
  ): Promise<void> {
    const url = this.resolveResourceUrl(resourceUri);
    await this.httpClient.delete(
      url,
      await this.buildHeaders('DELETE', url, options.headers ?? {}, {
        ...(options.ifMatch !== undefined && {
          'If-Match': this.formatEtags(options.ifMatch),
        }),
      })
    );
  }

  public async listContainer(
    containerUri: ContainerUri,
    headers: HttpHeaders = {},
    accept?: string
  ): Promise<ContainerListing> {
    const resolved = new URL(this.resolveResourceUrl(containerUri));
    if (!resolved.pathname.endsWith('/')) resolved.pathname += '/';
    const url = resolved.toString();
    const response = await this.httpClient.get<string>(
      url,
      await this.buildHeaders('GET', url, headers, {
        ...(accept !== undefined && { Accept: accept }),
      })
    );
    const resources: ResourceUri[] = [];
    const containers: ContainerUri[] = [];
    for (const match of response.body.matchAll(/<([^>]+)>\s+/g)) {
      const candidate = match[1];
      if (!candidate) continue;
      const candidateUrl = new URL(candidate, url).toString();
      if (candidateUrl.endsWith('/')) containers.push(candidateUrl);
      else resources.push(candidateUrl);
    }
    return {
      containerUri: url,
      resources,
      containers,
      metadata: this.parseResourceMetadata(response.headers, url),
    };
  }

  public async create(
    resourceUri: ResourceUri,
    content: string | Uint8Array,
    options: { contentType?: string; headers?: HttpHeaders } = {}
  ): Promise<ResourceMetadata> {
    return this.put(resourceUri, content, { ...options, ifNoneMatch: '*' });
  }

  public async update(
    resourceUri: ResourceUri,
    content: string | Uint8Array,
    options: {
      contentType?: string;
      headers?: HttpHeaders;
      ifMatch?: string | string[];
    } & ConditionalWriteOptions = {}
  ): Promise<ResourceMetadata> {
    const ifMatch = options.ifMatch ?? (await this.head(resourceUri)).etag;
    if (!ifMatch) {
      throw new ValidationError(
        'Cannot safely update a resource without an ETag',
        'ifMatch'
      );
    }
    return this.put(resourceUri, content, { ...options, ifMatch });
  }

  private async buildHeaders(
    method: string,
    url: string,
    callerHeaders: HttpHeaders,
    enforcedHeaders: HttpHeaders = {}
  ): Promise<HttpHeaders> {
    const authHeaders = await this.getAuthHeaders(method, url);
    return {
      ...callerHeaders,
      ...enforcedHeaders,
      ...authHeaders,
    };
  }

  private async getAuthHeaders(method: string, url: string): Promise<HttpHeaders> {
    if (!this.config.useDpop) return {};
    if (!this.authManager) {
      throw new ValidationError(
        'DPoP is enabled but no AuthManager was configured',
        'authManager'
      );
    }
    const { accessToken, dpopProof } = await this.authManager.signRequest(
      method,
      url
    );
    return {
      Authorization: `DPoP ${accessToken}`,
      DPoP: dpopProof,
    };
  }

  private resolveResourceUrl(resourceUri: ResourceUri | ContainerUri): string {
    if (!resourceUri?.trim()) {
      throw new ValidationError('Resource URI is required', 'resourceUri');
    }
    let resource: URL;
    try {
      resource = new URL(resourceUri, this.baseUrl);
    } catch {
      throw new ValidationError('Resource URI is invalid', 'resourceUri');
    }
    if (!['http:', 'https:'].includes(resource.protocol)) {
      throw new ValidationError('Resource URI must use HTTP or HTTPS', 'resourceUri');
    }
    if (resource.username || resource.password) {
      throw new ValidationError(
        'Resource URI must not contain credentials',
        'resourceUri'
      );
    }
    if (resource.origin !== this.baseUrl.origin) {
      throw new ValidationError(
        'Resource URI is outside the configured origin',
        'resourceUri'
      );
    }
    const basePath = this.baseUrl.pathname.endsWith('/')
      ? this.baseUrl.pathname
      : `${this.baseUrl.pathname}/`;
    const resourcePath = resource.pathname.endsWith('/')
      ? resource.pathname
      : `${resource.pathname}/`;
    if (
      basePath !== '/' &&
      resourcePath !== basePath &&
      !resourcePath.startsWith(basePath)
    ) {
      throw new ValidationError(
        'Resource URI is outside the configured path scope',
        'resourceUri'
      );
    }
    resource.hash = '';
    return resource.toString();
  }

  private parseResourceMetadata(
    headers: HttpHeaders,
    resourceUri: ResourceUri
  ): ResourceMetadata {
    const metadata: ResourceMetadata = { uri: resourceUri, exists: true };
    const contentType = getHeader(headers, 'content-type');
    const contentLength = getHeader(headers, 'content-length');
    const etag = getHeader(headers, 'etag');
    const lastModified = getHeader(headers, 'last-modified');
    if (contentType !== undefined) metadata.contentType = contentType;
    if (contentLength !== undefined) {
      const parsed = Number.parseInt(contentLength, 10);
      if (Number.isFinite(parsed)) metadata.contentLength = parsed;
    }
    if (etag !== undefined) metadata.etag = parseETag(etag);
    if (lastModified !== undefined) {
      metadata.lastModified = lastModified;
      const timestamp = Date.parse(lastModified);
      if (!Number.isNaN(timestamp)) metadata.lastModifiedAt = timestamp;
    }
    metadata.links = parseLinkHeaders(headers);
    return metadata;
  }

  private formatEtags(etags: string | string[]): string {
    const values = Array.isArray(etags) ? etags : [etags];
    if (values.length === 0) {
      throw new ValidationError('At least one ETag is required', 'etag');
    }
    return values
      .map(value => {
        const trimmed = value.trim();
        if (trimmed === '*') return '*';
        if (/^(W\/)?".*"$/.test(trimmed)) return trimmed;
        return `"${trimmed.replaceAll('"', '')}"`;
      })
      .join(', ');
  }

  public getHttpClient(): SolidSidecarHttpClient {
    return this.httpClient;
  }

  public getAuthManager(): AuthManager | null {
    return this.authManager;
  }

  public getConfig(): ResolvedResourceClientConfig {
    return {
      ...this.config,
      httpClientConfig: { ...this.config.httpClientConfig },
    };
  }
}

export default ResourceClient;
