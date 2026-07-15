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
  followRedirects?: boolean;
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

export const DEFAULT_WEBID_CLIENT_CONFIG = {
  discoveryTimeout: 10_000,
  profileCacheSize: 100,
  profileCacheTtl: 5 * 60 * 1_000,
  enableSsrfProtection: true,
  allowedHosts: [],
  logger: nullLogger,
} satisfies ResolvedWebIdClientConfig;

interface ProfileCacheEntry {
  profile: WebIdProfile;
  timestamp: number;
  etag?: string;
}

export class WebIdClient {
  private readonly config: ResolvedWebIdClientConfig;
  private readonly resourceClient: ResourceClient;
  private readonly logger: SolidSidecarLogger;
  private readonly profileCache = new Map<string, ProfileCacheEntry>();

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
    this.logger.debug('WebIdClient initialized', {
      discoveryTimeout: this.config.discoveryTimeout,
      profileCacheSize: this.config.profileCacheSize,
      enableSsrfProtection: this.config.enableSsrfProtection,
    });
  }

  public async discoverWebId(
    webId: string,
    options: WebIdDiscoveryOptions = {}
  ): Promise<WebIdProfile> {
    const canonicalWebId = this.canonicalizeWebId(webId);
    const cached = this.getCachedProfile(canonicalWebId);
    if (cached) return cached;

    const profileDocumentUri = this.profileDocumentUri(canonicalWebId);
    this.assertSafeUrl(profileDocumentUri);

    const profile = await this.fetchWebIdProfile(
      canonicalWebId,
      profileDocumentUri,
      options
    );
    this.cacheProfile(canonicalWebId, profile);

    this.logger.info('WebID profile discovered', {
      profileUri: profile.profileUri,
      hasStorage: (profile.storage?.length ?? 0) > 0,
    });
    return profile;
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

      if (!result.valid) {
        result.errors.push('Profile subject does not match the requested WebID');
      }
      if (!profile.storage?.length) {
        result.warnings.push('No storage locations found in profile');
      }
    } catch (error) {
      result.errors.push(
        error instanceof Error ? error.message : 'WebID validation failed'
      );
    }

    return result;
  }

  public async discoverStorageLocations(
    webId: string,
    options: WebIdDiscoveryOptions = {}
  ): Promise<string[]> {
    const profile = await this.discoverWebId(webId, options);
    return [...(profile.storage ?? [])];
  }

  public async discoverPrimaryStorage(
    webId: string,
    options: WebIdDiscoveryOptions = {}
  ): Promise<string | null> {
    const storage = await this.discoverStorageLocations(webId, options);
    return storage[0] ?? null;
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
    return this.profileCache.size;
  }

  public getResourceClient(): ResourceClient {
    return this.resourceClient;
  }

  public getConfig(): Readonly<ResolvedWebIdClientConfig> {
    return {
      ...this.config,
      allowedHosts: [...this.config.allowedHosts],
    };
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
    parsed.hash = parsed.hash;
    return parsed.toString();
  }

  private profileDocumentUri(webId: string): string {
    const document = new URL(webId);
    document.hash = '';
    return document.toString();
  }

  private assertSafeUrl(url: string): void {
    if (
      this.config.enableSsrfProtection &&
      !validateUrl(url, this.config.allowedHosts)
    ) {
      throw new ValidationError('WebID URI failed URL safety validation', 'webId');
    }
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
    const profile = this.parseWebIdProfile(response.content, webId, profileDocumentUri);
    profile.lastModified = response.metadata.lastModified;
    profile.etag = response.metadata.etag;
    profile.raw = response.content;
    profile.turtle = response.content;
    return profile;
  }

  private parseWebIdProfile(
    turtle: string,
    webId: string,
    profileDocumentUri: string
  ): WebIdProfile {
    const profile: WebIdProfile = { id: webId, profileUri: profileDocumentUri };

    for (const rawLine of turtle.split(/\r?\n/u)) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#') || line.startsWith('@')) continue;

      const subjectMatch = line.match(/^<([^>]+)>/u);
      if (!subjectMatch) continue;

      let subject: string;
      try {
        subject = new URL(subjectMatch[1] ?? '', profileDocumentUri).toString();
      } catch {
        continue;
      }
      if (subject !== webId) continue;

      const typeMatch = line.match(/\ba\s+<([^>]+)>/iu);
      if (typeMatch?.[1]) profile.type = typeMatch[1];

      const nameMatch = line.match(/<http:\/\/xmlns\.com\/foaf\/0\.1\/name>\s+"([^"]+)"/u);
      if (nameMatch?.[1]) profile.name = nameMatch[1];

      const nicknameMatch = line.match(/<http:\/\/xmlns\.com\/foaf\/0\.1\/nick>\s+"([^"]+)"/u);
      if (nicknameMatch?.[1]) profile.nickname = nicknameMatch[1];

      const emailMatch = line.match(/<http:\/\/xmlns\.com\/foaf\/0\.1\/mbox>\s+<mailto:([^>]+)>/u);
      if (emailMatch?.[1]) profile.email = emailMatch[1];

      const imageMatch = line.match(/<http:\/\/xmlns\.com\/foaf\/0\.1\/(?:img|depiction|image)>\s+<([^>]+)>/u);
      if (imageMatch?.[1]) profile.image = this.safeProfileUrl(imageMatch[1], profileDocumentUri);

      const storageMatch = line.match(/<http:\/\/www\.w3\.org\/ns\/pim\/space#storage>\s+<([^>]+)>/u);
      if (storageMatch?.[1]) {
        const storage = this.safeProfileUrl(storageMatch[1], profileDocumentUri);
        if (storage) profile.storage = [...(profile.storage ?? []), storage];
      }

      const preferencesMatch = line.match(/<http:\/\/www\.w3\.org\/ns\/pim\/prefs#preferencesFile>\s+<([^>]+)>/u);
      if (preferencesMatch?.[1]) {
        profile.preferencesFile = this.safeProfileUrl(
          preferencesMatch[1],
          profileDocumentUri
        );
      }
    }

    return profile;
  }

  private safeProfileUrl(value: string, base: string): string | undefined {
    try {
      const resolved = new URL(value, base).toString();
      this.assertSafeUrl(resolved);
      return resolved;
    } catch {
      return undefined;
    }
  }

  private getCachedProfile(webId: string): WebIdProfile | null {
    const entry = this.profileCache.get(webId);
    if (!entry) return null;
    if (Date.now() - entry.timestamp >= this.config.profileCacheTtl) {
      this.profileCache.delete(webId);
      return null;
    }
    return entry.profile;
  }

  private cacheProfile(webId: string, profile: WebIdProfile): void {
    if (this.config.profileCacheSize === 0) return;

    this.profileCache.delete(webId);
    while (this.profileCache.size >= this.config.profileCacheSize) {
      const oldestKey = this.profileCache.keys().next().value as string | undefined;
      if (oldestKey === undefined) break;
      this.profileCache.delete(oldestKey);
    }

    this.profileCache.set(webId, {
      profile,
      timestamp: Date.now(),
      etag: profile.etag,
    });
  }
}

export default WebIdClient;
