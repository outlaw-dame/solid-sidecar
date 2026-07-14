export interface OutboundUrlPolicy {
  /** Permit plain HTTP. Intended only for explicit local development. */
  allowHttp?: boolean;
  /** Permit localhost, loopback, private, link-local, and single-label hosts. */
  allowPrivateHosts?: boolean;
  /** Exact hostnames permitted by policy. Ports are checked separately by URL origin. */
  allowedHosts?: readonly string[];
  /** Exact origins permitted by policy, for example https://pod.example:8443. */
  allowedOrigins?: readonly string[];
}

export type UrlPolicyFailure =
  | 'invalid_url'
  | 'unsupported_scheme'
  | 'credentials_forbidden'
  | 'private_host_forbidden'
  | 'host_not_allowed'
  | 'origin_not_allowed';

export interface UrlPolicyResult {
  ok: boolean;
  url?: URL;
  reason?: UrlPolicyFailure;
}

const FORBIDDEN_HOST_SUFFIXES = ['.localhost', '.local'];

function normalizeHostname(hostname: string): string {
  return hostname.toLowerCase().replace(/\.$/, '');
}

function parseIpv4(hostname: string): number[] | null {
  const parts = hostname.split('.');
  if (parts.length !== 4 || parts.some(part => !/^\d{1,3}$/.test(part))) {
    return null;
  }

  const octets = parts.map(Number);
  return octets.every(value => value >= 0 && value <= 255) ? octets : null;
}

function isForbiddenIpv4(octets: readonly number[]): boolean {
  const [a, b] = octets;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

function parseEmbeddedIpv4(host: string): number[] | null {
  const dottedMatch = host.match(/^::(?:ffff:)?(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (dottedMatch) {
    return parseIpv4(dottedMatch[1]);
  }

  // URL implementations commonly canonicalize mapped dotted forms such as
  // ::ffff:127.0.0.1 into ::ffff:7f00:1. Decode the final 32 bits so the
  // private IPv4 policy cannot be bypassed through that representation.
  const hexadecimalMatch = host.match(/^::(?:ffff:)?([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (!hexadecimalMatch) {
    return null;
  }

  const high = Number.parseInt(hexadecimalMatch[1], 16);
  const low = Number.parseInt(hexadecimalMatch[2], 16);
  return [high >> 8, high & 0xff, low >> 8, low & 0xff];
}

function isForbiddenIpv6(hostname: string): boolean {
  const host = hostname.replace(/^\[/, '').replace(/\]$/, '').toLowerCase();
  if (!host.includes(':')) {
    return false;
  }

  const embeddedIpv4 = parseEmbeddedIpv4(host);
  if (embeddedIpv4 && isForbiddenIpv4(embeddedIpv4)) {
    return true;
  }

  return (
    host === '::' ||
    host === '::1' ||
    host.startsWith('fc') ||
    host.startsWith('fd') ||
    /^fe[89ab]/.test(host) ||
    host.startsWith('ff') ||
    host.startsWith('2001:db8:')
  );
}

export function isPrivateOrLocalHostname(hostname: string): boolean {
  const host = normalizeHostname(hostname);
  if (
    host === 'localhost' ||
    FORBIDDEN_HOST_SUFFIXES.some(suffix => host.endsWith(suffix)) ||
    (!host.includes('.') && !host.includes(':'))
  ) {
    return true;
  }

  const ipv4 = parseIpv4(host);
  return ipv4 ? isForbiddenIpv4(ipv4) : isForbiddenIpv6(host);
}

function normalizeAllowedHosts(hosts: readonly string[] | undefined): Set<string> | null {
  if (!hosts || hosts.length === 0) {
    return null;
  }
  return new Set(hosts.map(normalizeHostname));
}

function normalizeAllowedOrigins(origins: readonly string[] | undefined): Set<string> | null {
  if (!origins || origins.length === 0) {
    return null;
  }

  const normalized = new Set<string>();
  for (const origin of origins) {
    try {
      normalized.add(new URL(origin).origin.toLowerCase());
    } catch {
      // Invalid policy entries are ignored, causing fail-closed matching.
    }
  }
  return normalized;
}

/**
 * Performs deterministic client-side URL checks.
 *
 * This deliberately does not claim DNS-rebinding protection: browsers do not
 * expose DNS resolution. Server-side callers must additionally validate every
 * resolved address at connection time and disable unsafe redirects.
 */
export function validateOutboundUrl(
  input: string,
  policy: OutboundUrlPolicy = {}
): UrlPolicyResult {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return { ok: false, reason: 'invalid_url' };
  }

  if (url.protocol !== 'https:' && !(policy.allowHttp && url.protocol === 'http:')) {
    return { ok: false, reason: 'unsupported_scheme' };
  }
  if (url.username || url.password) {
    return { ok: false, reason: 'credentials_forbidden' };
  }

  const host = normalizeHostname(url.hostname);
  if (!policy.allowPrivateHosts && isPrivateOrLocalHostname(host)) {
    return { ok: false, reason: 'private_host_forbidden' };
  }

  const allowedHosts = normalizeAllowedHosts(policy.allowedHosts);
  if (allowedHosts && !allowedHosts.has(host)) {
    return { ok: false, reason: 'host_not_allowed' };
  }

  const allowedOrigins = normalizeAllowedOrigins(policy.allowedOrigins);
  if (allowedOrigins && !allowedOrigins.has(url.origin.toLowerCase())) {
    return { ok: false, reason: 'origin_not_allowed' };
  }

  return { ok: true, url };
}

function canonicalScopeUrl(input: string): URL | null {
  try {
    const url = new URL(input, 'https://relative.invalid');
    if (url.username || url.password) {
      return null;
    }
    return url;
  } catch {
    return null;
  }
}

/**
 * Checks scope containment using canonical origin and path-segment boundaries.
 * Relative resources are resolved against the canonical scope URL. Query
 * strings and fragments never widen access.
 */
export function isResourceWithinScope(resource: string, scope: string): boolean {
  const scopeUrl = canonicalScopeUrl(scope);
  if (!scopeUrl) {
    return false;
  }

  let resourceUrl: URL;
  try {
    resourceUrl = new URL(resource, scopeUrl);
  } catch {
    return false;
  }

  if (
    resourceUrl.username ||
    resourceUrl.password ||
    resourceUrl.origin !== scopeUrl.origin
  ) {
    return false;
  }

  const scopePath = scopeUrl.pathname.endsWith('/')
    ? scopeUrl.pathname
    : `${scopeUrl.pathname}/`;
  const resourcePath = resourceUrl.pathname;

  return resourcePath === scopeUrl.pathname || resourcePath.startsWith(scopePath);
}
