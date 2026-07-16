import { createHash, randomBytes } from 'node:crypto';
import type { HttpStatusCode, RetryOptions, SolidSidecarLogger } from './types';
import { DEFAULT_RETRY_OPTIONS } from './types';

export function resolveUrl(baseUrl: string, resourceUri: string): string {
  if (!resourceUri?.trim()) throw new TypeError('resourceUri is required');
  try {
    if (/^https?:\/\//i.test(resourceUri)) return new URL(resourceUri).toString();
    if (!baseUrl?.trim()) throw new TypeError('baseUrl is required for relative URLs');
    return new URL(resourceUri, baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`).toString();
  } catch (error) {
    throw new TypeError(`Invalid URL: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export function normalizeUrl(url: string): string {
  const parsed = new URL(url);
  parsed.search = '';
  parsed.hash = '';
  return parsed.toString();
}

function isPrivateHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.localhost') || host === '::1') return true;
  if (/^127\./.test(host) || /^10\./.test(host) || /^169\.254\./.test(host) || /^192\.168\./.test(host)) return true;
  const match = host.match(/^172\.(\d{1,3})\./);
  if (match) {
    const second = Number(match[1]);
    if (second >= 16 && second <= 31) return true;
  }
  return host.startsWith('fc') || host.startsWith('fd') || host.startsWith('fe80:');
}

export function validateUrl(url: string, allowedHosts: string[] = []): boolean {
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) return false;
    if (parsed.username || parsed.password) return false;
    if (!parsed.hostname || /[\s\0]/.test(url)) return false;
    const normalizedAllowed = allowedHosts.map(host => host.trim().toLowerCase()).filter(Boolean);
    if (normalizedAllowed.length > 0 && !normalizedAllowed.includes(parsed.hostname.toLowerCase())) return false;
    if (normalizedAllowed.length === 0 && isPrivateHostname(parsed.hostname)) return false;
    return true;
  } catch {
    return false;
  }
}

export function isSameOrigin(baseUrl: string, url: string): boolean {
  try {
    return new URL(baseUrl).origin === new URL(url).origin;
  } catch {
    return false;
  }
}

function toBytes(input: string | Uint8Array | Buffer | ArrayBuffer): Uint8Array {
  if (typeof input === 'string') return new TextEncoder().encode(input);
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
}

export function base64UrlEncode(input: string | Uint8Array | Buffer | ArrayBuffer): string {
  return Buffer.from(toBytes(input)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64UrlDecode(input: string): string {
  if (!/^[A-Za-z0-9_-]*$/.test(input)) throw new TypeError('Invalid Base64URL input');
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  return Buffer.from(padded, 'base64').toString('utf8');
}

export async function sha256Base64Url(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const subtle = globalThis.crypto?.subtle;
  if (subtle) return base64UrlEncode(await subtle.digest('SHA-256', data));
  return sha256Base64UrlSync(input);
}

export function sha256Base64UrlSync(input: string): string {
  return base64UrlEncode(createHash('sha256').update(input, 'utf8').digest());
}

export function generateUuid(): string {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  const bytes = new Uint8Array(randomBytes(16));
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function sleep(ms: number): Promise<void> {
  if (!Number.isFinite(ms) || ms < 0) return Promise.reject(new RangeError('ms must be a non-negative finite number'));
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function calculateBackoffDelay(retryCount: number, options: Partial<RetryOptions> = {}): number {
  if (!Number.isInteger(retryCount) || retryCount < 0) throw new RangeError('retryCount must be a non-negative integer');
  const baseDelay = options.baseDelay ?? DEFAULT_RETRY_OPTIONS.baseDelay;
  const maxDelay = options.maxDelay ?? DEFAULT_RETRY_OPTIONS.maxDelay;
  const jitterFactor = options.jitterFactor ?? DEFAULT_RETRY_OPTIONS.jitterFactor;
  if (!Number.isFinite(baseDelay) || baseDelay < 0) throw new RangeError('baseDelay must be non-negative');
  if (!Number.isFinite(maxDelay) || maxDelay < baseDelay) throw new RangeError('maxDelay must be >= baseDelay');
  if (!Number.isFinite(jitterFactor) || jitterFactor < 0 || jitterFactor > 1) throw new RangeError('jitterFactor must be between 0 and 1');
  const capped = Math.min(maxDelay, baseDelay * 2 ** Math.min(retryCount, 52));
  return Math.min(maxDelay, Math.floor(capped + capped * jitterFactor * Math.random()));
}

export function isRetryableStatus(statusCode: HttpStatusCode, options: Partial<RetryOptions> = {}): boolean {
  if (!Number.isInteger(statusCode) || statusCode < 100 || statusCode > 599) return false;
  const retryOn4xx = options.retryOn4xx ?? DEFAULT_RETRY_OPTIONS.retryOn4xx;
  const retryableStatuses = options.retryableStatuses ?? DEFAULT_RETRY_OPTIONS.retryableStatuses;
  if (retryableStatuses.includes(statusCode)) return true;
  if (statusCode === 429 || (statusCode >= 500 && statusCode < 600)) return true;
  return retryOn4xx && statusCode >= 400 && statusCode < 500;
}

function safeString(value: unknown, fallback: string): string {
  return typeof value === 'string' && value.trim() ? value.slice(0, 4096) : fallback;
}

export async function parseErrorResponse(
  response: Response,
  defaultMessage = 'Request failed'
): Promise<{ message: string; code?: string; details?: unknown; statusCode: number }> {
  const statusCode = response.status;
  try {
    const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
    if (contentType.includes('json')) {
      const body: unknown = await response.json();
      if (body && typeof body === 'object' && !Array.isArray(body)) {
        const record = body as Record<string, unknown>;
        return {
          message: safeString(record.message ?? record.error, defaultMessage),
          ...(typeof record.code === 'string' && { code: record.code.slice(0, 256) }),
          ...(record.details !== undefined && { details: record.details }),
          statusCode,
        };
      }
    }
    const text = await response.text();
    return { message: safeString(text, defaultMessage), statusCode };
  } catch {
    return { message: defaultMessage, statusCode };
  }
}

function canonicalScope(scope: string, base?: URL): URL | null {
  try {
    const parsed = base ? new URL(scope, base) : new URL(scope);
    parsed.hash = '';
    parsed.search = '';
    return parsed;
  } catch {
    return null;
  }
}

export function validateResourceScope(resourceUri: string, allowedScopes: string[]): boolean {
  if (allowedScopes.length === 0) return false;
  const resource = canonicalScope(resourceUri);
  if (!resource) return false;
  return allowedScopes.some(scope => {
    const allowed = canonicalScope(scope, resource);
    if (!allowed || resource.origin !== allowed.origin) return false;
    const path = allowed.pathname.endsWith('/') ? allowed.pathname : `${allowed.pathname}/`;
    const resourcePath = resource.pathname.endsWith('/') ? resource.pathname : `${resource.pathname}/`;
    return resourcePath === path || resourcePath.startsWith(path);
  });
}

export function getContainerUri(resourceUri: string): string {
  try {
    const url = new URL(resourceUri);
    const pathname = url.pathname.replace(/\/+$/, '');
    url.pathname = pathname.slice(0, pathname.lastIndexOf('/') + 1) || '/';
    url.search = '';
    url.hash = '';
    return url.toString();
  } catch {
    const trimmed = resourceUri.replace(/\/+$/, '');
    const index = trimmed.lastIndexOf('/');
    return index < 0 ? '/' : trimmed.slice(0, index + 1) || '/';
  }
}

export function getResourceName(resourceUri: string): string {
  try {
    const path = new URL(resourceUri).pathname.replace(/\/+$/, '');
    return decodeURIComponent(path.slice(path.lastIndexOf('/') + 1));
  } catch {
    const trimmed = resourceUri.replace(/\/+$/, '');
    return trimmed.slice(trimmed.lastIndexOf('/') + 1);
  }
}

export const RDF_CONTENT_TYPES = {
  TURTLE: 'text/turtle',
  JSON_LD: 'application/ld+json',
  N_TRIPLES: 'application/n-triples',
  RDF_XML: 'application/rdf+xml',
} as const;

export const NON_RDF_CONTENT_TYPES = {
  PLAIN: 'text/plain',
  OCTET_STREAM: 'application/octet-stream',
  JSON: 'application/json',
} as const;

export const CONTENT_TYPES = { ...RDF_CONTENT_TYPES, ...NON_RDF_CONTENT_TYPES } as const;

export function isRdfContentType(contentType: string): boolean {
  const normalized = contentType.split(';', 1)[0]?.trim().toLowerCase();
  return Object.values(RDF_CONTENT_TYPES).some(value => value === normalized);
}

export function getPreferredRdfContentType(): string {
  return RDF_CONTENT_TYPES.TURTLE;
}

export const LINK_RELATIONS = {
  TYPE: 'type', ACL: 'acl', META: 'meta', ITEMS: 'items', CONTAINS: 'contains',
} as const;

export function parseLinkHeaders(headers: Headers | Record<string, string>): Array<{ uri: string; rel: string }> {
  const header = headers instanceof Headers ? headers.get('link') ?? '' : headers.link ?? headers.Link ?? '';
  const links: Array<{ uri: string; rel: string }> = [];
  for (const part of header.split(/,(?=\s*<)/)) {
    const uri = part.match(/<([^>]+)>/)?.[1];
    const rel = part.match(/(?:^|;)\s*rel\s*=\s*"?([^";]+)"?/i)?.[1];
    if (uri && rel) links.push({ uri, rel: rel.trim() });
  }
  return links;
}

export function parseETag(etag: string): string {
  return etag.trim().replace(/^W\//i, '');
}

export function etagsMatch(etag1: string, etag2: string): boolean {
  const clean = (value: string) => parseETag(value).replace(/^"|"$/g, '');
  return clean(etag1) === clean(etag2);
}

const runtime = globalThis as typeof globalThis & { Deno?: unknown; Bun?: unknown };
export const environment = {
  isNode: typeof process !== 'undefined' && Boolean(process.versions?.node),
  isBrowser: typeof window !== 'undefined' && typeof document !== 'undefined',
  isDeno: runtime.Deno !== undefined,
  isBun: runtime.Bun !== undefined,
};

export const defaultLogger: SolidSidecarLogger = {
  debug: (message, ...args) => console.debug(`[SOLID-SIDECAR:DEBUG] ${message}`, ...args),
  info: (message, ...args) => console.info(`[SOLID-SIDECAR:INFO] ${message}`, ...args),
  warn: (message, ...args) => console.warn(`[SOLID-SIDECAR:WARN] ${message}`, ...args),
  error: (message, ...args) => console.error(`[SOLID-SIDECAR:ERROR] ${message}`, ...args),
};

export const nullLogger: SolidSidecarLogger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};
