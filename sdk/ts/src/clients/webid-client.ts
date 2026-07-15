import type { HttpHeaders, SolidSidecarLogger } from '../types';
import { ValidationError } from '../types';
import { ResourceClient, type ResourceClientConfig } from './resource-client';
import { nullLogger, validateUrl } from '../utils';

export interface WebIdProfile {
  id: string;
  type?: string | string[];
  name?: string;
  nickname?: string;
  email?: string;
  image?: string;
  storage?: string[];
  preferencesFile?: string;
  turtle?: string;
  raw?: string;
  profileUri: string;
  lastModified?: string;
  etag?: string;
}

export interface WebIdDiscoveryOptions {
  timeout?: number;
  headers?: HttpHeaders;
  /** @deprecated Redirect handling is enforced by the underlying HTTP client. */
  followRedirects?: boolean;
  /** @deprecated Redirect handling is enforced by the underlying HTTP client. */
  maxRedirects?: number;
}

export interface WebIdValidationResult {
  valid: boolean;
  webId: string;
  profileUri?: string;
  errors: string[];
  warnings: string[];
  profile?: WebIdProfile;
}

export interface WebIdClientConfig extends ResourceClientConfig {
  discoveryTimeout?: number;
  profileCacheSize?: number;
  profileCacheTtl?: number;
  enableSsrfProtection?: boolean;
  allowedHosts?: string[];
  logger?: SolidSidecarLogger;
}

interface ResolvedWebIdClientConfig {
  discoveryTimeout: number;
  profileCacheSize: number;
  profileCacheTtl: number;
  enableSsrfProtection: boolean;
  allowedHosts: string[];
  logger: SolidSidecarLogger;
}

interface ProfileCacheEntry {
  profile: WebIdProfile;
  timestamp: number;
}

const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const FOAF_NAME = 'http://xmlns.com/foaf/0.1/name';
const FOAF_NICK = 'http://xmlns.com/foaf/0.1/nick';
const FOAF_MBOX = 'http://xmlns.com/foaf/0.1/mbox';
const FOAF_IMAGE = 'http://xmlns.com/foaf/0.1/img';
const FOAF_DEPICTION = 'http://xmlns.com/foaf/0.1/depiction';
const FOAF_IMAGE_ALT = 'http://xmlns.com/foaf/0.1/image';
const PIM_STORAGE = 'http://www.w3.org/ns/pim/space#storage';
const PIM_PREFERENCES = 'http://www.w3.org/ns/pim/prefs#preferencesFile';

export const DEFAULT_WEBID_CLIENT_CONFIG = {
  discoveryTimeout: 10_000,
  profileCacheSize: 100,
  profileCacheTtl: 5 * 60 * 1_000,
  enableSsrfProtection: true,
  allowedHosts: [],
  logger: nullLogger,
} satisfies ResolvedWebIdClientConfig;

export class WebIdClient {
  private readonly config: ResolvedWebIdClientConfig;
  private readonly resourceClient: ResourceClient;
  private readonly logger: SolidSidecarLogger;
  private readonly profileCache = new Map<string, ProfileCacheEntry>();
  private readonly inFlightDiscoveries = new Map<string, Promise<WebIdProfile>>();
  private readonly hasImplicitAuthentication: boolean;

  public constructor(config: WebIdClientConfig = {}) {
    this.config = {
      discoveryTimeout:
        config.discoveryTimeout ?? DEFAULT_WEBID_CLIENT_CONFIG.discoveryTimeout,
      profileCacheSize:
        config.profileCacheSize ?? DEFAULT_WEBID_CLIENT_CONFIG.profileCacheSize,
      profileCacheTtl:
        config.profileCacheTtl ?? DEFAULT_WEBID_CLIENT_CONFIG.profileCacheTtl,
      enableSsrfProtection:
        config.enableSsrfProtection ??
        DEFAULT_WEBID_CLIENT_CONFIG.enableSsrfProtection,
      allowedHosts: [...(config.allowedHosts ?? DEFAULT_WEBID_CLIENT_CONFIG.allowedHosts)],
      logger: config.logger ?? DEFAULT_WEBID_CLIENT_CONFIG.logger,
    };

    if (!Number.isFinite(this.config.discoveryTimeout) || this.config.discoveryTimeout <= 0) {
      throw new ValidationError('discoveryTimeout must be a positive number', 'discoveryTimeout');
    }
    if (!Number.isInteger(this.config.profileCacheSize) || this.config.profileCacheSize < 0) {
      throw new ValidationError('profileCacheSize must be a non-negative integer', 'profileCacheSize');
    }
    if (!Number.isFinite(this.config.profileCacheTtl) || this.config.profileCacheTtl < 0) {
      throw new ValidationError('profileCacheTtl must be a non-negative number', 'profileCacheTtl');
    }

    this.resourceClient = new ResourceClient({ ...config, logger: this.config.logger });
    this.logger = this.config.logger;
    this.hasImplicitAuthentication = config.authManager !== undefined || config.useDpop === true;
  }

  public async discoverWebId(
    webId: string,
    options: WebIdDiscoveryOptions = {}
  ): Promise<WebIdProfile> {
    this.validateDiscoveryOptions(options);
    const canonicalWebId = this.canonicalizeWebId(webId);
    const usesSharedCache = this.canUseSharedCache(options);

    if (usesSharedCache) {
      const cached = this.getCachedProfile(canonicalWebId);
      if (cached) return cached;
    }

    const requestKey = this.discoveryRequestKey(canonicalWebId, options);
    const existing = this.inFlightDiscoveries.get(requestKey);
    if (existing) return this.cloneProfile(await existing);

    const discovery = this.loadWebId(canonicalWebId, options, usesSharedCache).finally(() => {
      this.inFlightDiscoveries.delete(requestKey);
    });
    this.inFlightDiscoveries.set(requestKey, discovery);
    return this.cloneProfile(await discovery);
  }

  public async validateWebId(
    webId: string,
    options: WebIdDiscoveryOptions = {}
  ): Promise<WebIdValidationResult> {
    const result: WebIdValidationResult = {
      valid: false,
      webId,
      errors: [],
      warnings: [],
    };

    try {
      const canonicalWebId = this.canonicalizeWebId(webId);
      const profile = await this.discoverWebId(canonicalWebId, options);
      result.profile = profile;
      result.profileUri = profile.profileUri;
      result.valid = profile.id === canonicalWebId;
      if (!result.valid) result.errors.push('Profile subject does not match the requested WebID');
      if (!profile.storage?.length) result.warnings.push('No storage locations found in profile');
    } catch (error) {
      result.errors.push(error instanceof Error ? error.message : 'WebID validation failed');
    }

    return result;
  }

  public async discoverStorageLocations(
    webId: string,
    options: WebIdDiscoveryOptions = {}
  ): Promise<string[]> {
    return [...((await this.discoverWebId(webId, options)).storage ?? [])];
  }

  public async discoverPrimaryStorage(
    webId: string,
    options: WebIdDiscoveryOptions = {}
  ): Promise<string | null> {
    return (await this.discoverStorageLocations(webId, options))[0] ?? null;
  }

  public async discoverPreferencesFile(
    webId: string,
    options: WebIdDiscoveryOptions = {}
  ): Promise<string | null> {
    return (await this.discoverWebId(webId, options)).preferencesFile ?? null;
  }

  public clearCache(): void {
    this.profileCache.clear();
  }

  public clearCachedProfile(webId: string): void {
    this.profileCache.delete(this.canonicalizeWebId(webId));
  }

  public isCached(webId: string): boolean {
    return this.getCachedProfile(this.canonicalizeWebId(webId)) !== null;
  }

  public getCacheSize(): number {
    this.pruneExpiredEntries();
    return this.profileCache.size;
  }

  public getResourceClient(): ResourceClient {
    return this.resourceClient;
  }

  public getConfig(): Readonly<ResolvedWebIdClientConfig> {
    return { ...this.config, allowedHosts: [...this.config.allowedHosts] };
  }

  private async loadWebId(
    canonicalWebId: string,
    options: WebIdDiscoveryOptions,
    cacheResult: boolean
  ): Promise<WebIdProfile> {
    const profileDocumentUri = this.profileDocumentUri(canonicalWebId);
    this.assertSafeUrl(profileDocumentUri);
    const profile = await this.fetchWebIdProfile(
      canonicalWebId,
      profileDocumentUri,
      options
    );
    if (cacheResult) this.cacheProfile(canonicalWebId, profile);
    this.logger.info('WebID profile discovered', {
      profileUri: profile.profileUri,
      hasStorage: (profile.storage?.length ?? 0) > 0,
    });
    return profile;
  }

  private validateDiscoveryOptions(options: WebIdDiscoveryOptions): void {
    if (options.timeout !== undefined && (!Number.isFinite(options.timeout) || options.timeout <= 0)) {
      throw new ValidationError('timeout must be a positive number', 'timeout');
    }
    if (options.followRedirects !== undefined || options.maxRedirects !== undefined) {
      throw new ValidationError(
        'Per-request redirect overrides are unsupported; redirect policy is enforced by the HTTP client',
        'followRedirects'
      );
    }
  }

  private canUseSharedCache(options: WebIdDiscoveryOptions): boolean {
    return (
      this.config.profileCacheTtl > 0 &&
      !this.hasImplicitAuthentication &&
      Object.keys(options.headers ?? {}).length === 0
    );
  }

  private discoveryRequestKey(webId: string, options: WebIdDiscoveryOptions): string {
    const headers = Object.entries(options.headers ?? {})
      .map(([name, value]) => [name.toLowerCase(), value.trim()] as const)
      .sort(([left], [right]) => left.localeCompare(right));
    return JSON.stringify({
      webId,
      timeout: options.timeout ?? null,
      headers,
      authenticated: this.hasImplicitAuthentication,
    });
  }

  private canonicalizeWebId(webId: string): string {
    if (typeof webId !== 'string' || webId.trim() === '') {
      throw new ValidationError('WebID must be a non-empty string', 'webId');
    }

    let parsed: URL;
    try {
      parsed = new URL(webId);
    } catch {
      throw new ValidationError('WebID must be a valid absolute URL', 'webId');
    }
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new ValidationError('WebID must use HTTP or HTTPS', 'webId');
    }
    if (parsed.username || parsed.password) {
      throw new ValidationError('WebID must not contain credentials', 'webId');
    }
    parsed.hostname = parsed.hostname.toLowerCase();
    return parsed.toString();
  }

  private profileDocumentUri(webId: string): string {
    const document = new URL(webId);
    document.hash = '';
    return document.toString();
  }

  private assertSafeUrl(value: string): void {
    if (!this.config.enableSsrfProtection) return;
    if (!validateUrl(value, this.config.allowedHosts)) {
      throw new ValidationError('WebID URI failed URL safety validation', 'webId');
    }

    const hostname = new URL(value).hostname.toLowerCase().replace(/^\[|\]$/gu, '');
    if (this.isForbiddenHostname(hostname)) {
      throw new ValidationError('WebID URI targets a private or special-use host', 'webId');
    }
  }

  private isForbiddenHostname(hostname: string): boolean {
    if (
      hostname === 'localhost' ||
      hostname.endsWith('.localhost') ||
      hostname.endsWith('.local') ||
      hostname.endsWith('.internal') ||
      hostname === 'metadata.google.internal'
    ) {
      return true;
    }

    if (this.isForbiddenIpv4(hostname)) return true;

    const normalizedIpv6 = hostname.toLowerCase();
    const mappedDotted = normalizedIpv6.match(
      /^(?:::ffff:(?:0:){0,1}|::)?(\d+\.\d+\.\d+\.\d+)$/u
    );
    if (mappedDotted?.[1] && this.isForbiddenIpv4(mappedDotted[1])) return true;

    const mappedHex = normalizedIpv6.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/u);
    if (mappedHex?.[1] && mappedHex[2]) {
      const high = Number.parseInt(mappedHex[1], 16);
      const low = Number.parseInt(mappedHex[2], 16);
      const mappedIpv4 = [high >> 8, high & 0xff, low >> 8, low & 0xff].join('.');
      if (this.isForbiddenIpv4(mappedIpv4)) return true;
    }

    return (
      normalizedIpv6 === '::' ||
      normalizedIpv6 === '::1' ||
      normalizedIpv6.startsWith('fc') ||
      normalizedIpv6.startsWith('fd') ||
      /^fe[89ab]/u.test(normalizedIpv6) ||
      normalizedIpv6.startsWith('ff')
    );
  }

  private isForbiddenIpv4(ip: string): boolean {
    const octets = ip.split('.').map(Number);
    if (
      octets.length !== 4 ||
      !octets.every(value => Number.isInteger(value) && value >= 0 && value <= 255)
    ) {
      return false;
    }

    const [a = 0, b = 0] = octets;
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

  private async fetchWebIdProfile(
    webId: string,
    profileDocumentUri: string,
    options: WebIdDiscoveryOptions
  ): Promise<WebIdProfile> {
    const response = await this.resourceClient.get(
      profileDocumentUri,
      options.headers ?? {},
      'text/turtle, application/ld+json;q=0.9'
    );
    const contentType = response.metadata.contentType?.split(';', 1)[0]?.trim().toLowerCase();
    const document = typeof response.content === 'string'
      ? response.content
      : JSON.stringify(response.content);
    const profile = this.parseWebIdProfile(
      document,
      webId,
      profileDocumentUri,
      contentType
    );
    profile.lastModified = response.metadata.lastModified;
    profile.etag = response.metadata.etag;
    profile.raw = document;
    if (contentType !== 'application/ld+json') profile.turtle = document;
    return profile;
  }

  private parseWebIdProfile(
    document: string,
    webId: string,
    profileDocumentUri: string,
    contentType?: string
  ): WebIdProfile {
    let profile: WebIdProfile;
    if (contentType === 'application/ld+json') {
      profile = this.parseJsonLdProfile(document, webId, profileDocumentUri);
    } else if (contentType === 'text/turtle' || contentType === 'application/n-triples') {
      profile = this.parseTurtleProfile(document, webId, profileDocumentUri);
    } else {
      const trimmed = document.trimStart();
      if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
        try {
          profile = this.parseJsonLdProfile(document, webId, profileDocumentUri);
        } catch (error) {
          if (error instanceof ValidationError && error.field === 'profile') {
            profile = this.parseTurtleProfile(document, webId, profileDocumentUri);
          } else {
            throw error;
          }
        }
      } else {
        profile = this.parseTurtleProfile(document, webId, profileDocumentUri);
      }
    }

    if (profile.id !== webId) {
      throw new ValidationError('Profile does not describe the requested WebID subject', 'webId');
    }
    return profile;
  }

  private parseTurtleProfile(
    turtle: string,
    webId: string,
    profileDocumentUri: string
  ): WebIdProfile {
    const prefixes = new Map<string, string>();
    for (const match of turtle.matchAll(/(?:@prefix|PREFIX)\s+([A-Za-z][\w-]*)?:\s*<([^>]+)>/giu)) {
      if (!match[2]) continue;
      try {
        prefixes.set(match[1] ?? '', new URL(match[2], profileDocumentUri).toString());
      } catch {
        throw new ValidationError('Profile contains an invalid Turtle prefix IRI', 'profile');
      }
    }

    const statements = this.collectTurtleStatements(turtle);
    const profile: WebIdProfile = { id: '', profileUri: profileDocumentUri };
    let foundSubject = false;

    for (const statement of statements) {
      const subjectToken = statement.match(/^([^\s]+)\s+/u)?.[1];
      if (!subjectToken) continue;
      const subject = this.resolveRdfTerm(subjectToken, prefixes, profileDocumentUri);
      if (subject !== webId) continue;
      foundSubject = true;
      profile.id = webId;
      const predicatesPart = statement.slice(subjectToken.length).trim();
      this.applyTurtlePredicates(profile, predicatesPart, prefixes, profileDocumentUri);
    }

    if (!foundSubject) {
      throw new ValidationError('Profile does not contain the requested WebID subject', 'webId');
    }
    return profile;
  }

  private collectTurtleStatements(turtle: string): string[] {
    const statements: string[] = [];
    let current = '';
    let inString = false;
    let escaped = false;
    let inIri = false;

    const source = turtle
      .split(/\r?\n/u)
      .map(rawLine => this.stripTurtleComment(rawLine).trim())
      .filter(line => line && !/^(?:@prefix|PREFIX|@base|BASE)\b/iu.test(line))
      .join(' ');

    for (let index = 0; index < source.length; index += 1) {
      const char = source[index] ?? '';
      current += char;
      if (escaped) {
        escaped = false;
        continue;
      }
      if (inString && char === '\\') {
        escaped = true;
        continue;
      }
      if (!inIri && char === '"') inString = !inString;
      else if (!inString && char === '<') inIri = true;
      else if (!inString && char === '>') inIri = false;
      else if (
        !inString &&
        !inIri &&
        char === '.' &&
        (index === source.length - 1 || /\s/u.test(source[index + 1] ?? ''))
      ) {
        if (current.trim()) statements.push(current.trim());
        current = '';
      }
    }
    if (current.trim()) statements.push(current.trim());
    return statements;
  }

  private stripTurtleComment(line: string): string {
    let clean = '';
    let inString = false;
    let escaped = false;
    let inIri = false;

    for (const char of line) {
      if (escaped) {
        clean += char;
        escaped = false;
        continue;
      }
      if (inString && char === '\\') {
        clean += char;
        escaped = true;
        continue;
      }
      if (!inIri && char === '"') inString = !inString;
      else if (!inString && char === '<') inIri = true;
      else if (!inString && char === '>') inIri = false;
      else if (!inString && !inIri && char === '#') break;
      clean += char;
    }
    return clean;
  }

  private applyTurtlePredicates(
    profile: WebIdProfile,
    statement: string,
    prefixes: Map<string, string>,
    base: string
  ): void {
    for (const pair of this.splitTurtlePredicatePairs(statement)) {
      const match = pair.match(/^(a|<[^>]+>|(?:[A-Za-z][\w-]*)?:[\w.-]*)\s+(.+)$/u);
      const predicateToken = match?.[1];
      const objectToken = match?.[2]?.trim();
      if (!predicateToken || !objectToken) continue;
      const predicate = predicateToken === 'a'
        ? RDF_TYPE
        : this.resolveRdfTerm(predicateToken, prefixes, base);
      if (!predicate) continue;
      this.applyProfileValue(profile, predicate, objectToken, prefixes, base);
    }
  }

  private splitTurtlePredicatePairs(statement: string): string[] {
    const pairs: string[] = [];
    let current = '';
    let inString = false;
    let escaped = false;
    let inIri = false;

    for (const char of statement.replace(/\.\s*$/u, '')) {
      if (escaped) {
        current += char;
        escaped = false;
        continue;
      }
      if (inString && char === '\\') {
        current += char;
        escaped = true;
        continue;
      }
      if (!inIri && char === '"') inString = !inString;
      else if (!inString && char === '<') inIri = true;
      else if (!inString && char === '>') inIri = false;
      if (!inString && !inIri && char === ';') {
        if (current.trim()) pairs.push(current.trim());
        current = '';
      } else {
        current += char;
      }
    }
    if (current.trim()) pairs.push(current.trim());
    return pairs;
  }

  private applyProfileValue(
    profile: WebIdProfile,
    predicate: string,
    objectToken: string,
    prefixes: Map<string, string>,
    base: string
  ): void {
    const literal = objectToken.match(/^"((?:\\.|[^"\\])*)"/u)?.[1]?.replace(/\\"/gu, '"');
    const iri = this.resolveRdfTerm(objectToken.split(/\s*,\s*/u)[0] ?? '', prefixes, base);

    if (predicate === RDF_TYPE && iri) profile.type = iri;
    else if (predicate === FOAF_NAME && literal !== undefined) profile.name = literal;
    else if (predicate === FOAF_NICK && literal !== undefined) profile.nickname = literal;
    else if (predicate === FOAF_MBOX && iri?.startsWith('mailto:')) profile.email = iri.slice(7);
    else if ([FOAF_IMAGE, FOAF_DEPICTION, FOAF_IMAGE_ALT].includes(predicate) && iri) {
      profile.image = this.requireSafeProfileUrl(iri, base);
    } else if (predicate === PIM_STORAGE && iri) {
      const storage = this.requireSafeProfileUrl(iri, base);
      profile.storage = [...new Set([...(profile.storage ?? []), storage])];
    } else if (predicate === PIM_PREFERENCES && iri) {
      profile.preferencesFile = this.requireSafeProfileUrl(iri, base);
    }
  }

  private parseJsonLdProfile(
    document: string,
    webId: string,
    profileDocumentUri: string
  ): WebIdProfile {
    let parsed: unknown;
    try {
      parsed = JSON.parse(document) as unknown;
    } catch {
      throw new ValidationError('Profile contains invalid JSON-LD', 'profile');
    }

    const root = this.asRecord(parsed);
    const graph = Array.isArray(parsed)
      ? parsed
      : root?.['@graph'] ?? [parsed];
    const nodes = (Array.isArray(graph) ? graph : [graph])
      .map(value => this.asRecord(value))
      .filter((value): value is Record<string, unknown> => value !== undefined);

    const node = nodes.find(value => this.jsonLdNodeMatches(value, webId, profileDocumentUri));
    if (!node) {
      throw new ValidationError('Profile does not contain the requested WebID subject', 'webId');
    }

    const context = this.buildJsonLdContext(
      [root?.['@context'], node['@context']],
      profileDocumentUri
    );
    const profile: WebIdProfile = { id: webId, profileUri: profileDocumentUri };

    const type = this.firstString(node['@type']);
    if (type) {
      try {
        profile.type = this.expandJsonLdTerm(type, context, profileDocumentUri);
      } catch {
        // Invalid non-authoritative type IRIs are ignored.
      }
    }

    profile.name = this.firstLiteral(
      this.jsonLdValue(node, FOAF_NAME, context, ['foaf:name', 'name'])
    );
    profile.nickname = this.firstLiteral(
      this.jsonLdValue(node, FOAF_NICK, context, ['foaf:nick'])
    );

    const email = this.firstIri(
      this.jsonLdValue(node, FOAF_MBOX, context, ['foaf:mbox'])
    );
    if (email?.startsWith('mailto:')) profile.email = email.slice(7);

    const image = this.firstIri(
      this.jsonLdValue(node, FOAF_IMAGE, context, ['foaf:img']) ??
      this.jsonLdValue(node, FOAF_DEPICTION, context, ['foaf:depiction']) ??
      this.jsonLdValue(node, FOAF_IMAGE_ALT, context, ['foaf:image'])
    );
    if (image) profile.image = this.requireSafeProfileUrl(image, profileDocumentUri);

    const storageValues = this.allIris(
      this.jsonLdValue(node, PIM_STORAGE, context, ['pim:storage'])
    );
    if (storageValues.length > 0) {
      profile.storage = [...new Set(
        storageValues.map(value => this.requireSafeProfileUrl(value, profileDocumentUri))
      )];
    }

    const preferences = this.firstIri(
      this.jsonLdValue(node, PIM_PREFERENCES, context, ['pim:preferencesFile'])
    );
    if (preferences) {
      profile.preferencesFile = this.requireSafeProfileUrl(preferences, profileDocumentUri);
    }
    return profile;
  }

  private jsonLdNodeMatches(
    node: Record<string, unknown>,
    webId: string,
    base: string
  ): boolean {
    const id = node['@id'];
    if (typeof id !== 'string') return false;
    try {
      return new URL(id, base).toString() === webId;
    } catch {
      return false;
    }
  }

  private buildJsonLdContext(values: unknown[], base: string): Map<string, string> {
    const context = new Map<string, string>();
    for (const value of values) this.applyJsonLdContextValue(context, value, base);
    return context;
  }

  private applyJsonLdContextValue(
    context: Map<string, string>,
    value: unknown,
    base: string
  ): void {
    if (Array.isArray(value)) {
      for (const item of value) this.applyJsonLdContextValue(context, item, base);
      return;
    }

    const record = this.asRecord(value);
    if (!record) return;

    const rawScope = new Map(context);
    const rawDefinitions = new Map<string, string>();
    for (const [term, definition] of Object.entries(record)) {
      if (term.startsWith('@')) continue;
      const id = typeof definition === 'string'
        ? definition
        : this.asRecord(definition)?.['@id'];
      if (typeof id !== 'string' || id.startsWith('@')) continue;
      rawDefinitions.set(term, id);
      rawScope.set(term, id);
    }

    const resolved = new Map<string, string>();
    for (const [term, raw] of rawDefinitions) {
      try {
        resolved.set(term, this.expandJsonLdTerm(raw, rawScope, base));
      } catch {
        // Ignore malformed or circular non-authoritative context entries.
      }
    }
    for (const [term, iri] of resolved) context.set(term, iri);
  }

  private jsonLdValue(
    node: Record<string, unknown>,
    iri: string,
    context: Map<string, string>,
    fallbacks: string[] = []
  ): unknown {
    if (node[iri] !== undefined) return node[iri];
    for (const fallback of fallbacks) {
      if (node[fallback] !== undefined) return node[fallback];
    }
    for (const [key, value] of Object.entries(node)) {
      if (key.startsWith('@')) continue;
      try {
        if (this.expandJsonLdTerm(key, context, '') === iri) return value;
      } catch {
        // Ignore malformed property aliases.
      }
    }
    return undefined;
  }

  private expandJsonLdTerm(
    term: string,
    context: Map<string, string>,
    base: string,
    seen: Set<string> = new Set()
  ): string {
    if (seen.has(term)) throw new Error('Circular JSON-LD context reference');
    const nextSeen = new Set(seen).add(term);

    const direct = context.get(term);
    if (direct) return this.expandJsonLdTerm(direct, context, base, nextSeen);

    const compact = term.match(/^([^:]+):(.*)$/u);
    if (compact?.[1] !== undefined && compact[2] !== undefined) {
      const prefix = context.get(compact[1]);
      if (prefix) {
        const expandedPrefix = this.expandJsonLdTerm(prefix, context, base, nextSeen);
        return `${expandedPrefix}${compact[2]}`;
      }
      if (/^[A-Za-z][A-Za-z0-9+.-]*:/u.test(term)) return term;
    }

    return new URL(term, base || undefined).toString();
  }

  private asRecord(value: unknown): Record<string, unknown> | undefined {
    return typeof value === 'object' && value !== null && !Array.isArray(value)
      ? value as Record<string, unknown>
      : undefined;
  }

  private firstString(value: unknown): string | undefined {
    if (typeof value === 'string') return value;
    if (Array.isArray(value)) {
      return value.find(item => typeof item === 'string') as string | undefined;
    }
    return undefined;
  }

  private firstLiteral(value: unknown): string | undefined {
    if (typeof value === 'string') return value;
    const values = Array.isArray(value) ? value : [value];
    for (const item of values) {
      const record = this.asRecord(item);
      if (typeof record?.['@value'] === 'string') return record['@value'];
    }
    return undefined;
  }

  private firstIri(value: unknown): string | undefined {
    return this.allIris(value)[0];
  }

  private allIris(value: unknown): string[] {
    const values = Array.isArray(value) ? value : [value];
    const result: string[] = [];
    for (const item of values) {
      if (typeof item === 'string') result.push(item);
      else {
        const id = this.asRecord(item)?.['@id'];
        if (typeof id === 'string') result.push(id);
      }
    }
    return result;
  }

  private resolveRdfTerm(
    token: string,
    prefixes: Map<string, string>,
    base: string
  ): string | undefined {
    const normalized = token.trim().replace(/[;,]$/u, '');
    if (normalized.startsWith('<') && normalized.endsWith('>')) {
      try {
        return new URL(normalized.slice(1, -1), base).toString();
      } catch {
        return undefined;
      }
    }

    const prefixed = normalized.match(/^([A-Za-z][\w-]*|):([\w.-]*)$/u);
    if (prefixed?.[1] !== undefined && prefixed[2] !== undefined) {
      const prefix = prefixes.get(prefixed[1]);
      if (prefix !== undefined) return `${prefix}${prefixed[2]}`;
    }

    if (/^[A-Za-z][A-Za-z0-9+.-]*:/u.test(normalized)) return normalized;
    return undefined;
  }

  private requireSafeProfileUrl(value: string, base: string): string {
    let resolved: string;
    try {
      resolved = new URL(value, base).toString();
    } catch {
      throw new ValidationError('Profile contains an invalid derived IRI', 'profile');
    }
    this.assertSafeUrl(resolved);
    return resolved;
  }

  private getCachedProfile(webId: string): WebIdProfile | null {
    const entry = this.profileCache.get(webId);
    if (!entry) return null;
    if (Date.now() - entry.timestamp >= this.config.profileCacheTtl) {
      this.profileCache.delete(webId);
      return null;
    }
    return this.cloneProfile(entry.profile);
  }

  private cacheProfile(webId: string, profile: WebIdProfile): void {
    if (this.config.profileCacheSize === 0 || this.config.profileCacheTtl === 0) return;
    this.profileCache.delete(webId);
    while (this.profileCache.size >= this.config.profileCacheSize) {
      const oldestKey = this.profileCache.keys().next().value as string | undefined;
      if (oldestKey === undefined) break;
      this.profileCache.delete(oldestKey);
    }
    this.profileCache.set(webId, {
      profile: this.cloneProfile(profile),
      timestamp: Date.now(),
    });
  }

  private pruneExpiredEntries(): void {
    if (this.config.profileCacheTtl === 0) {
      this.profileCache.clear();
      return;
    }
    const now = Date.now();
    for (const [key, entry] of this.profileCache) {
      if (now - entry.timestamp >= this.config.profileCacheTtl) {
        this.profileCache.delete(key);
      }
    }
  }

  private cloneProfile(profile: WebIdProfile): WebIdProfile {
    return {
      ...profile,
      ...(Array.isArray(profile.type) && { type: [...profile.type] }),
      ...(profile.storage && { storage: [...profile.storage] }),
    };
  }
}

export default WebIdClient;
