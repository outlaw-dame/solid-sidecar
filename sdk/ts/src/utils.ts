/**
 * Solid Sidecar TypeScript SDK - Utilities
 * Phase: 27 - SDK/Client Compatibility Layer
 * Version: v1.0.0
 * Created: 2026-07-07
 * Author: Mistral Vibe
 * License: MIT
 *
 * This file contains utility functions for the SDK.
 */

import { DEFAULT_RETRY_OPTIONS, HttpStatusCode, RetryOptions } from './types';

// ============================================================================
// URL Utilities
// ============================================================================

/**
 * Resolves a resource URI relative to a base URL
 * @param baseUrl - The base URL of the Solid Sidecar instance
 * @param resourceUri - The resource URI (can be absolute or relative)
 * @returns The resolved absolute URL
 */
export function resolveUrl(baseUrl: string, resourceUri: string): string {
  // If resourceUri is already an absolute URL, return it
  if (/^https?:\/\//i.test(resourceUri)) {
    return resourceUri;
  }

  // Remove trailing slash from base URL
  const base = baseUrl.replace(/\/+$/, '');

  // If resourceUri starts with a slash, concatenate directly
  if (resourceUri.startsWith('/')) {
    return `${base}${resourceUri}`;
  }

  // Otherwise, add a slash between
  return `${base}/${resourceUri}`;
}

/**
 * Normalizes a URL by removing query parameters and fragments
 * @param url - The URL to normalize
 * @returns The normalized URL (without query or fragment)
 */
export function normalizeUrl(url: string): string {
  return url.split('?')[0].split('#')[0];
}

/**
 * Validates a URL to prevent SSRF attacks
 * @param url - The URL to validate
 * @param allowedHosts - Optional list of allowed hosts
 * @returns true if the URL is valid and safe
 */
export function validateUrl(url: string, allowedHosts?: string[]): boolean {
  try {
    // Basic URL validation
    if (!/^https?:\/\/[a-zA-Z0-9.-]+(:[0-9]+)?(\/[^\s]*)?$/i.test(url)) {
      return false;
    }

    const parsed = new URL(url);

    // Only allow http and https schemes
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }

    // Check for credentials in URL (not allowed)
    if (parsed.username || parsed.password) {
      return false;
    }

    // If allowed hosts are specified, check against them
    if (allowedHosts && allowedHosts.length > 0) {
      const host = parsed.hostname.toLowerCase();
      if (!allowedHosts.some(h => h.toLowerCase() === host)) {
        return false;
      }
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Checks if a URL is within the same origin as the base URL
 * @param baseUrl - The base URL
 * @param url - The URL to check
 * @returns true if the URLs share the same origin
 */
export function isSameOrigin(baseUrl: string, url: string): boolean {
  try {
    const base = new URL(baseUrl);
    const target = new URL(url);
    
    return (
      base.protocol === target.protocol &&
      base.hostname === target.hostname &&
      base.port === target.port
    );
  } catch {
    return false;
  }
}

// ============================================================================
// Base64 URL Encoding
// ============================================================================

/**
 * Encodes a string or buffer to Base64Url without padding
 * @param input - The string or buffer to encode
 * @returns The Base64Url encoded string
 */
export function base64UrlEncode(input: string | Uint8Array | Buffer): string {
  const str = typeof input === 'string' ? input : Buffer.from(input).toString('utf8');
  const base64 = Buffer.from(str, 'utf8').toString('base64');
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Decodes a Base64Url string
 * @param input - The Base64Url string to decode
 * @returns The decoded string
 */
export function base64UrlDecode(input: string): string {
  // Add padding if needed
  const base64 = input
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  
  const padLength = (4 - (base64.length % 4)) % 4;
  const padded = base64 + '='.repeat(padLength);
  
  return Buffer.from(padded, 'base64').toString('utf8');
}

// ============================================================================
// SHA-256 Hashing
// ============================================================================

/**
 * Computes SHA-256 hash of a string and returns as Base64Url
 * @param input - The string to hash
 * @returns The SHA-256 hash as Base64Url string
 */
export async function sha256Base64Url(input: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(hashBuffer);
}

/**
 * Computes SHA-256 hash of a string synchronously (Node.js only)
 * @param input - The string to hash
 * @returns The SHA-256 hash as Base64Url string
 */
export function sha256Base64UrlSync(input: string): string {
  const hash = crypto
    .createHash('sha256')
    .update(input, 'utf8')
    .digest();
  return base64UrlEncode(hash);
}

// ============================================================================
// UUID Generation
// ============================================================================

/**
 * Generates a cryptographically secure UUID v4
 * @returns A UUID v4 string
 */
export function generateUuid(): string {
  // Use crypto.randomUUID if available
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }

  // Fallback for older environments
  const bytes = new Uint8Array(16);
  
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    // Node.js fallback
    require('crypto').randomBytes(16).copy(bytes);
  }

  // Set version (4) in the 7th byte (bits 6-7)
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  
  // Set variant (RFC 4122) in the 9th byte (bits 6-7)
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  // Convert to hex string
  const hex = Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

// ============================================================================
// Exponential Backoff
// ============================================================================

/**
 * Sleeps for a specified number of milliseconds
 * @param ms - Milliseconds to sleep
 * @returns Promise that resolves after the delay
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Calculates the delay for exponential backoff with jitter
 * @param retryCount - The current retry count (0-indexed)
 * @param options - Retry options
 * @returns The delay in milliseconds
 */
export function calculateBackoffDelay(
  retryCount: number,
  options: Partial<RetryOptions> = {}
): number {
  const {
    baseDelay = DEFAULT_RETRY_OPTIONS.baseDelay,
    maxDelay = DEFAULT_RETRY_OPTIONS.maxDelay,
    jitterFactor = DEFAULT_RETRY_OPTIONS.jitterFactor,
  } = options;

  // Calculate exponential delay
  const delay = baseDelay * Math.pow(2, retryCount);

  // Apply max delay cap
  const cappedDelay = Math.min(delay, maxDelay);

  // Apply jitter (random value between 0 and jitterFactor * cappedDelay)
  const jitter = cappedDelay * jitterFactor * Math.random();

  return Math.floor(cappedDelay + jitter);
}

/**
 * Checks if a status code is retryable
 * @param statusCode - The HTTP status code
 * @param options - Retry options
 * @returns true if the status code should be retried
 */
export function isRetryableStatus(
  statusCode: HttpStatusCode,
  options: Partial<RetryOptions> = {}
): boolean {
  const {
    retryOn4xx = DEFAULT_RETRY_OPTIONS.retryOn4xx,
    retryableStatuses = DEFAULT_RETRY_OPTIONS.retryableStatuses,
  } = options;

  // 5xx errors are generally retryable
  if (statusCode >= 500 && statusCode < 600) {
    return true;
  }

  // 429 Too Many Requests is always retryable
  if (statusCode === 429) {
    return true;
  }

  // Check if 4xx errors should be retried
  if (retryOn4xx && statusCode >= 400 && statusCode < 500) {
    return true;
  }

  // Check against specific retryable statuses
  if (retryableStatuses && retryableStatuses.includes(statusCode)) {
    return true;
  }

  return false;
}

// ============================================================================
// Error Handling
// ============================================================================

/**
 * Extracts error details from a response
 * @param response - The HTTP response
 * @param defaultMessage - Default error message
 * @returns Parsed error details
 */
export async function parseErrorResponse(
  response: Response,
  defaultMessage: string = 'Request failed'
): Promise<{ message: string; code?: string; details?: unknown; statusCode: number }> {
  const statusCode = response.status;
  
  try {
    const contentType = response.headers.get('content-type');
    
    if (contentType && contentType.includes('application/json')) {
      const body = await response.json();
      return {
        message: body.message || body.error || defaultMessage,
        code: body.code,
        details: body.details || body,
        statusCode,
      };
    } else {
      const text = await response.text();
      return {
        message: text || defaultMessage,
        statusCode,
      };
    }
  } catch {
    return {
      message: defaultMessage,
      statusCode,
    };
  }
}

// ============================================================================
// IDOR Prevention
// ============================================================================

/**
 * Validates that a resource URI is within the allowed scope
 * @param resourceUri - The resource URI to validate
 * @param allowedScopes - List of allowed scope patterns (e.g., 'https://example.com/', '/container/')
 * @returns true if the URI is within an allowed scope
 */
export function validateResourceScope(
  resourceUri: string,
  allowedScopes: string[]
): boolean {
  // Normalize the resource URI
  const normalizedUri = resourceUri.endsWith('/') 
    ? resourceUri 
    : `${resourceUri}/`;

  for (const scope of allowedScopes) {
    const normalizedScope = scope.endsWith('/') 
      ? scope 
      : `${scope}/`;
    
    // Check if the URI starts with the scope
    if (normalizedUri.startsWith(normalizedScope)) {
      return true;
    }
    
    // Check if the URI exactly matches the scope
    if (normalizedUri === normalizedScope) {
      return true;
    }
  }

  return false;
}

/**
 * Extracts the container from a resource URI
 * @param resourceUri - The resource URI
 * @returns The container URI
 */
export function getContainerUri(resourceUri: string): string {
  // Remove trailing slash
  const trimmed = resourceUri.replace(/\/+$/, '');
  
  // Find the last slash
  const lastSlash = trimmed.lastIndexOf('/');
  
  if (lastSlash === -1) {
    return '/';
  }
  
  // Extract container path
  const containerPath = trimmed.substring(0, lastSlash + 1);
  
  return containerPath || '/';
}

/**
 * Extracts the resource name from a resource URI
 * @param resourceUri - The resource URI
 * @returns The resource name (filename)
 */
export function getResourceName(resourceUri: string): string {
  const trimmed = resourceUri.replace(/\/+$/, '');
  const lastSlash = trimmed.lastIndexOf('/');
  return lastSlash === -1 ? trimmed : trimmed.substring(lastSlash + 1);
}

// ============================================================================
// Content-Type Utilities
// ============================================================================

/**
 * RDF content types
 */
export const RDF_CONTENT_TYPES = {
  TURTLE: 'text/turtle',
  JSON_LD: 'application/ld+json',
  N_TRIPLES: 'application/n-triples',
  RDF_XML: 'application/rdf+xml',
} as const;

/**
 * Non-RDF content types
 */
export const NON_RDF_CONTENT_TYPES = {
  PLAIN: 'text/plain',
  OCTET_STREAM: 'application/octet-stream',
  JSON: 'application/json',
} as const;

/**
 * All supported content types
 */
export const CONTENT_TYPES = {
  ...RDF_CONTENT_TYPES,
  ...NON_RDF_CONTENT_TYPES,
} as const;

/**
 * Checks if a content type is RDF
 * @param contentType - The content type to check
 * @returns true if the content type is an RDF format
 */
export function isRdfContentType(contentType: string): boolean {
  const normalized = contentType.toLowerCase();
  return Object.values(RDF_CONTENT_TYPES).some(
    ct => normalized === ct.toLowerCase()
  );
}

/**
 * Gets the preferred content type for RDF operations
 * @returns The preferred RDF content type
 */
export function getPreferredRdfContentType(): string {
  return RDF_CONTENT_TYPES.TURTLE;
}

// ============================================================================
// Link Header Parsing
// ============================================================================

/**
 * Link relation types
 */
export const LINK_RELATIONS = {
  TYPE: 'type',
  ACL: 'acl',
  META: 'meta',
  ITEMS: 'items',
  CONTAINS: 'contains',
} as const;

/**
 * Parses Link headers from response
 * @param headers - The response headers
 * @returns Array of link objects
 */
export function parseLinkHeaders(headers: Headers | Record<string, string>): Array<{
  uri: string;
  rel: string;
}> {
  const links: Array<{ uri: string; rel: string }> = [];
  
  // Get Link header
  let linkHeader = '';
  
  if (headers instanceof Headers) {
    linkHeader = headers.get('link') || '';
  } else {
    linkHeader = headers.link || headers.Link || '';
  }
  
  if (!linkHeader) {
    return links;
  }
  
  // Parse Link header
  // Format: <uri>; rel="type", <uri>; rel="type"
  const linkParts = linkHeader.split(',').map(p => p.trim());
  
  for (const part of linkParts) {
    if (!part) continue;
    
    const uriMatch = part.match(/<([^>]+)>/);
    const relMatch = part.match(/rel="([^"]+)"/i);
    
    if (uriMatch && relMatch) {
      links.push({
        uri: uriMatch[1],
        rel: relMatch[1],
      });
    }
  }
  
  return links;
}

// ============================================================================
// ETag Utilities
// ============================================================================

/**
 * Parses ETag header value
 * @param etag - The ETag header value
 * @returns The ETag value without weak indicator
 */
export function parseETag(etag: string): string {
  if (!etag) return '';
  
  // Remove weak indicator (W/)
  return etag.replace(/^W\//, '');
}

/**
 * Checks if two ETags match
 * @param etag1 - First ETag
 * @param etag2 - Second ETag
 * @returns true if the ETags match
 */
export function etagsMatch(etag1: string, etag2: string): boolean {
  const normalized1 = parseETag(etag1);
  const normalized2 = parseETag(etag2);
  
  // Weak comparison: strip quotes and compare
  const clean1 = normalized1.replace(/^["']|["']$/g, '');
  const clean2 = normalized2.replace(/^["']|["']$/g, '');
  
  return clean1 === clean2;
}

// ============================================================================
// Environment Detection
// ============================================================================

/**
 * Detects the runtime environment
 */
export const environment = ((): {
  isNode: boolean;
  isBrowser: boolean;
  isDeno: boolean;
  isBun: boolean;
} => {
  const isNode = typeof process !== 'undefined' && process.versions != null && process.versions.node != null;
  const isDeno = typeof Deno !== 'undefined';
  const isBun = typeof Bun !== 'undefined';
  const isBrowser = !isNode && !isDeno && !isBun && typeof window !== 'undefined';
  
  return {
    isNode,
    isBrowser,
    isDeno,
    isBun,
  };
})();

// ============================================================================
// Default Logger
// ============================================================================

/**
 * Default console-based logger
 */
export const defaultLogger: import('./types').SolidSidecarLogger = {
  debug: (message: string, ...args: unknown[]) => {
    console.debug(`[SOLID-SIDECAR:DEBUG] ${message}`, ...args);
  },
  info: (message: string, ...args: unknown[]) => {
    console.info(`[SOLID-SIDECAR:INFO] ${message}`, ...args);
  },
  warn: (message: string, ...args: unknown[]) => {
    console.warn(`[SOLID-SIDECAR:WARN] ${message}`, ...args);
  },
  error: (message: string, ...args: unknown[]) => {
    console.error(`[SOLID-SIDECAR:ERROR] ${message}`, ...args);
  },
};

/**
 * Null logger (no output)
 */
export const nullLogger: import('./types').SolidSidecarLogger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};
