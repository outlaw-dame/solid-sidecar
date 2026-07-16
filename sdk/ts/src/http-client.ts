import type {
  HttpHeaders,
  HttpRequestOptions,
  HttpResponse,
  SolidSidecarConfig,
  SolidSidecarLogger,
} from './types';
import {
  AuthenticationError,
  AuthorizationError,
  ConflictError,
  NetworkError,
  PreconditionFailedError,
  RateLimitError,
  ResourceNotFoundError,
  ValidationError,
} from './types';
import {
  calculateBackoffDelay,
  isRetryableStatus,
  nullLogger,
  parseErrorResponse,
  resolveUrl,
  validateResourceScope,
  validateUrl,
} from './utils';

export interface HttpClientConfig extends Partial<SolidSidecarConfig> {
  defaultHeaders?: HttpHeaders;
  defaultTimeout?: number;
  validateUrls?: boolean;
  allowedHosts?: string[];
}

export interface ResolvedHttpClientConfig {
  baseUrl: string;
  timeout: number;
  maxRetries: number;
  retryDelay: number;
  maxRetryDelay: number;
  fetch: typeof fetch;
  validateSsl: boolean;
  logger: SolidSidecarLogger;
  defaultHeaders: HttpHeaders;
  defaultTimeout: number;
  validateUrls: boolean;
  allowedHosts: string[];
}

export const DEFAULT_HTTP_CLIENT_CONFIG = {
  baseUrl: '',
  timeout: 30_000,
  maxRetries: 3,
  retryDelay: 1_000,
  maxRetryDelay: 30_000,
  validateSsl: true,
  logger: nullLogger,
  defaultHeaders: {},
  defaultTimeout: 30_000,
  validateUrls: true,
  allowedHosts: [],
} satisfies Omit<ResolvedHttpClientConfig, 'fetch'>;

const IDEMPOTENT_METHODS = new Set(['GET', 'HEAD', 'PUT', 'DELETE', 'OPTIONS']);
const SENSITIVE_HEADERS = new Set([
  'authorization', 'dpop', 'cookie', 'set-cookie', 'x-api-key', 'x-auth-token', 'proxy-authorization',
]);

function requireFiniteNumber(name: string, value: number, minimum: number, integer = false): number {
  if (!Number.isFinite(value) || value < minimum || (integer && !Number.isInteger(value))) {
    throw new ValidationError(`${name} must be ${integer ? 'an integer ' : ''}>= ${minimum}`, name);
  }
  return value;
}

function headersToObject(headers: Headers): HttpHeaders {
  const result: HttpHeaders = {};
  headers.forEach((value, key) => { result[key] = value; });
  return result;
}

function parseRetryAfter(value: string | null, maximum: number): number | null {
  if (!value) return null;
  const seconds = Number(value);
  const delay = Number.isFinite(seconds)
    ? Math.max(0, seconds * 1000)
    : Math.max(0, Date.parse(value) - Date.now());
  return Number.isFinite(delay) && delay <= maximum ? Math.floor(delay) : null;
}

function abortableDelay(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.reject(new DOMException('The operation was aborted', 'AbortError'));
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new DOMException('The operation was aborted', 'AbortError'));
    };
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

export class SolidSidecarHttpClient {
  private readonly config: ResolvedHttpClientConfig;
  private readonly fetchImpl: typeof fetch;

  constructor(config: HttpClientConfig = {}) {
    const fetchImpl = config.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== 'function') {
      throw new ValidationError('No fetch implementation is available', 'fetch');
    }

    const baseUrl = config.baseUrl ?? DEFAULT_HTTP_CLIENT_CONFIG.baseUrl;
    let base: URL | null = null;
    if (baseUrl) {
      try { base = new URL(baseUrl); } catch { throw new ValidationError('baseUrl must be an absolute URL', 'baseUrl'); }
      if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password) {
        throw new ValidationError('baseUrl must be an HTTP(S) URL without credentials', 'baseUrl');
      }
    }

    const timeout = requireFiniteNumber('timeout', config.timeout ?? DEFAULT_HTTP_CLIENT_CONFIG.timeout, 1);
    const defaultTimeout = requireFiniteNumber('defaultTimeout', config.defaultTimeout ?? timeout, 1);
    const maxRetries = requireFiniteNumber('maxRetries', config.maxRetries ?? DEFAULT_HTTP_CLIENT_CONFIG.maxRetries, 0, true);
    const retryDelay = requireFiniteNumber('retryDelay', config.retryDelay ?? DEFAULT_HTTP_CLIENT_CONFIG.retryDelay, 0);
    const maxRetryDelay = requireFiniteNumber('maxRetryDelay', config.maxRetryDelay ?? DEFAULT_HTTP_CLIENT_CONFIG.maxRetryDelay, retryDelay);
    const allowedHosts = Array.from(new Set(
      (config.allowedHosts?.length ? config.allowedHosts : base ? [base.hostname] : [])
        .map(host => host.trim().toLowerCase())
        .filter(Boolean)
    ));

    this.config = {
      baseUrl,
      timeout,
      maxRetries,
      retryDelay,
      maxRetryDelay,
      fetch: fetchImpl,
      validateSsl: config.validateSsl ?? DEFAULT_HTTP_CLIENT_CONFIG.validateSsl,
      logger: config.logger ?? DEFAULT_HTTP_CLIENT_CONFIG.logger,
      defaultHeaders: { ...(config.defaultHeaders ?? {}) },
      defaultTimeout,
      validateUrls: config.validateUrls ?? DEFAULT_HTTP_CLIENT_CONFIG.validateUrls,
      allowedHosts,
    };
    this.fetchImpl = fetchImpl;
  }

  public async request<T = unknown>(options: HttpRequestOptions): Promise<HttpResponse<T>> {
    const timeout = requireFiniteNumber('timeout', options.timeout ?? this.config.defaultTimeout, 1);
    const url = resolveUrl(this.config.baseUrl, options.url);
    this.assertAllowedUrl(url);

    const headers: HttpHeaders = { ...this.config.defaultHeaders, ...(options.headers ?? {}) };
    const hasBody = options.body !== undefined && options.body !== null;
    if (hasBody && !Object.keys(headers).some(name => name.toLowerCase() === 'content-type')) {
      headers['Content-Type'] = 'application/octet-stream';
    }

    this.config.logger.debug('HTTP request', {
      method: options.method,
      url,
      headers: this.redactSensitiveHeaders(headers),
      hasBody,
    });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const response = await this.executeWithRetry({
        method: options.method,
        url,
        headers,
        body: options.body,
        signal: controller.signal,
      });
      this.assertAllowedUrl(response.url || url);
      return this.processResponse<T>(response);
    } finally {
      clearTimeout(timer);
    }
  }

  private assertAllowedUrl(url: string): void {
    if (!this.config.validateUrls) return;
    if (!validateUrl(url, this.config.allowedHosts)) {
      throw new ValidationError('Invalid or unauthorized request URL', 'url', { statusCode: 400 });
    }
    if (this.config.validateSsl && new URL(url).protocol !== 'https:') {
      throw new ValidationError('HTTPS is required by the current client policy', 'url', { statusCode: 400 });
    }
  }

  private async executeWithRetry(request: {
    method: string;
    url: string;
    headers: HttpHeaders;
    body?: HttpRequestOptions['body'];
    signal: AbortSignal;
  }): Promise<Response> {
    let attempt = 0;
    const retryableMethod = IDEMPOTENT_METHODS.has(request.method.toUpperCase());

    while (true) {
      try {
        const init: RequestInit = {
          method: request.method,
          headers: request.headers,
          signal: request.signal,
          redirect: 'error',
          ...(request.body !== undefined && request.body !== null && {
            body: request.body as unknown as BodyInit,
          }),
        };
        const response = await this.fetchImpl(request.url, init);
        if (!retryableMethod || attempt >= this.config.maxRetries || !isRetryableStatus(response.status, {
          retryOn4xx: false,
          retryableStatuses: [429, 500, 502, 503, 504],
        })) return response;

        const retryAfter = parseRetryAfter(response.headers.get('retry-after'), this.config.maxRetryDelay);
        const delay = retryAfter ?? calculateBackoffDelay(attempt, {
          baseDelay: this.config.retryDelay,
          maxDelay: this.config.maxRetryDelay,
        });
        await abortableDelay(delay, request.signal);
        attempt += 1;
      } catch (error) {
        if (error instanceof Error && error.name === 'AbortError') throw error;
        const retryableNetworkError = error instanceof TypeError;
        if (!retryableMethod || !retryableNetworkError || attempt >= this.config.maxRetries) throw error;
        const delay = calculateBackoffDelay(attempt, {
          baseDelay: this.config.retryDelay,
          maxDelay: this.config.maxRetryDelay,
        });
        await abortableDelay(delay, request.signal);
        attempt += 1;
      }
    }
  }

  private async processResponse<T>(response: Response): Promise<HttpResponse<T>> {
    const status = response.status;
    const responseHeaders = headersToObject(response.headers);
    this.config.logger.debug('HTTP response', {
      status,
      headers: this.redactSensitiveHeaders(responseHeaders),
    });

    if (!response.ok) {
      const error = await parseErrorResponse(response);
      const common = { statusCode: status, requestId: error.code };
      switch (status) {
        case 401: throw new AuthenticationError(error.message, common);
        case 403: throw new AuthorizationError(error.message, common);
        case 404: throw new ResourceNotFoundError(error.message, response.url, common);
        case 409: throw new ConflictError(error.message, undefined, common);
        case 412: throw new PreconditionFailedError(error.message, undefined, response.headers.get('etag') ?? '', common);
        case 429: throw new RateLimitError(error.message, Math.ceil((parseRetryAfter(response.headers.get('retry-after'), this.config.maxRetryDelay) ?? 0) / 1000), common);
        default:
          if (status >= 400 && status < 500) throw new ValidationError(error.message, undefined, common);
          throw new NetworkError(error.message, common);
      }
    }

    const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
    let body: T;
    if (status === 204 || status === 205 || response.headers.get('content-length') === '0') {
      body = undefined as T;
    } else if (contentType.includes('json')) {
      body = await response.json() as T;
    } else if (contentType.startsWith('text/') || contentType.includes('xml') || contentType.includes('turtle')) {
      body = await response.text() as unknown as T;
    } else {
      body = await response.arrayBuffer() as unknown as T;
    }
    return { status, headers: responseHeaders, body, raw: response };
  }

  public get<T = unknown>(url: string, headers?: HttpHeaders, timeout?: number): Promise<HttpResponse<T>> {
    return this.request<T>({ method: 'GET', url, headers, timeout });
  }
  public head(url: string, headers?: HttpHeaders, timeout?: number): Promise<HttpResponse> {
    return this.request({ method: 'HEAD', url, headers, timeout });
  }
  public post<T = unknown>(url: string, body?: HttpRequestOptions['body'], headers?: HttpHeaders, timeout?: number): Promise<HttpResponse<T>> {
    return this.request<T>({ method: 'POST', url, body, headers, timeout });
  }
  public put<T = unknown>(url: string, body?: HttpRequestOptions['body'], headers?: HttpHeaders, timeout?: number): Promise<HttpResponse<T>> {
    return this.request<T>({ method: 'PUT', url, body, headers, timeout });
  }
  public patch<T = unknown>(url: string, body?: HttpRequestOptions['body'], headers?: HttpHeaders, timeout?: number): Promise<HttpResponse<T>> {
    return this.request<T>({ method: 'PATCH', url, body, headers, timeout });
  }
  public delete(url: string, headers?: HttpHeaders, timeout?: number): Promise<HttpResponse> {
    return this.request({ method: 'DELETE', url, headers, timeout });
  }

  private redactSensitiveHeaders(headers: HttpHeaders): HttpHeaders {
    return Object.fromEntries(Object.entries(headers).map(([name, value]) => [
      name,
      SENSITIVE_HEADERS.has(name.toLowerCase()) ? '[REDACTED]' : value,
    ]));
  }

  public validateResourceUri(resourceUri: string, allowedScopes: string[]): boolean {
    try {
      const url = resolveUrl(this.config.baseUrl, resourceUri);
      return validateUrl(url, this.config.allowedHosts) && validateResourceScope(url, allowedScopes);
    } catch {
      return false;
    }
  }

  public isWithinPod(resourceUri: string, podBaseUrl: string): boolean {
    try {
      const resource = resolveUrl(this.config.baseUrl, resourceUri);
      const pod = resolveUrl(this.config.baseUrl, podBaseUrl);
      return validateResourceScope(resource, [pod]);
    } catch {
      return false;
    }
  }

  public get fetch(): typeof fetch { return this.fetchImpl; }
  public getConfig(): ResolvedHttpClientConfig {
    return {
      ...this.config,
      defaultHeaders: { ...this.config.defaultHeaders },
      allowedHosts: [...this.config.allowedHosts],
    };
  }
}

let defaultHttpClient: SolidSidecarHttpClient | null = null;
export function getDefaultHttpClient(config?: HttpClientConfig): SolidSidecarHttpClient {
  if (!defaultHttpClient || config) defaultHttpClient = new SolidSidecarHttpClient(config);
  return defaultHttpClient;
}
export function resetDefaultHttpClient(): void { defaultHttpClient = null; }
export function configureDefaultHttpClient(config: HttpClientConfig): SolidSidecarHttpClient {
  defaultHttpClient = new SolidSidecarHttpClient(config);
  return defaultHttpClient;
}
