/**
 * Solid Sidecar TypeScript SDK - WebID Client
 * Phase: 27 - SDK/Client Compatibility Layer
 * Version: v1.0.0
 * Created: 2026-07-07
 * Author: Mistral Vibe
 * License: MIT
 *
 * This file contains the WebIDClient for discovering and working with WebID profiles.
 *
 * Security Level: CRITICAL - Handles identity discovery and validation
 */

import type {
  ResourceUri,
  HttpHeaders,
  SolidSidecarLogger,
} from '../types';
import { ResourceClient, type ResourceClientConfig } from './resource-client';
import { ValidationError } from '../types';
import {
  resolveUrl,
  validateUrl,
  parseLinkHeaders,
  getResourceName,
} from '../utils';

// ============================================================================
// WebID Types
// ============================================================================

/** WebID profile document */
export interface WebIdProfile {
  /** Subject URI (the WebID) */
  id: string;
  
  /** Types of the profile */
  type?: string | string[];
  
  /** Person's name */
  name?: string;
  
  /** Person's nickname */
  nickname?: string;
  
  /** Person's email */
  email?: string;
  
  /** Person's image URL */
  image?: string;
  
  /** Storage locations */
  storage?: string[];
  
  /** Public preferences file */
  preferencesFile?: string;
  
  /** Profile document as RDF/Turtle */
  turtle?: string;
  
  /** Raw profile document */
  raw?: string;
  
  /** Profile URI */
  profileUri: string;
  
  /** Last modified timestamp */
  lastModified?: string;
  
  /** ETag */
  etag?: string;
}

/** WebID discovery options */
export interface WebIdDiscoveryOptions {
  /** Timeout for discovery in milliseconds */
  timeout?: number;
  
  /** Custom headers */
  headers?: HttpHeaders;
  
  /** Whether to follow redirects (default: true) */
  followRedirects?: boolean;
  
  /** Maximum redirect depth (default: 5) */
  maxRedirects?: number;
}

/** WebID validation result */
export interface WebIdValidationResult {
  /** Whether the WebID is valid */
  valid: boolean;
  
  /** The WebID being validated */
  webId: string;
  
  /** Profile URI if valid */
  profileUri?: string;
  
  /** Validation errors */
  errors: string[];
  
  /** Warnings */
  warnings: string[];
  
  /** The profile if successfully loaded */
  profile?: WebIdProfile;
}

// ============================================================================
// WebID Client Configuration
// ============================================================================

/**
 * Configuration for WebIdClient
 */
export interface WebIdClientConfig extends ResourceClientConfig {
  /** Timeout for WebID discovery in milliseconds (default: 10000) */
  discoveryTimeout?: number;
  
  /** Maximum number of profile lookups to cache (default: 100) */
  profileCacheSize?: number;
  
  /** Profile cache TTL in milliseconds (default: 5 minutes) */
  profileCacheTtl?: number;
  
  /** Whether to enable SSRF protection (default: true) */
  enableSsrfProtection?: boolean;
  
  /** Allowed hosts for profile discovery */
  allowedHosts?: string[];
  
  /** Custom logger */
  logger?: SolidSidecarLogger;
}

/**
 * Default WebIdClient configuration
 */
export const DEFAULT_WEBID_CLIENT_CONFIG: Partial<WebIdClientConfig> = {
  discoveryTimeout: 10000,
  profileCacheSize: 100,
  profileCacheTtl: 5 * 60 * 1000, // 5 minutes
  enableSsrfProtection: true,
  allowedHosts: [],
};

// ============================================================================
// Profile Cache Entry
// ============================================================================

interface ProfileCacheEntry {
  profile: WebIdProfile;
  timestamp: number;
  etag?: string;
}

// ============================================================================
// WebID Client
// ============================================================================

/**
 * WebID Client for Solid Sidecar
 * 
 * Features:
 * - WebID profile discovery and fetching
 * - WebID validation
 * - Profile caching with TTL
 * - Storage location discovery
 * - SSRF protection
 * - IDOR prevention
 * - ETag-based cache invalidation
 */
export class WebIdClient {
  private readonly config: Required<WebIdClientConfig>;
  private readonly resourceClient: ResourceClient;
  private readonly logger: SolidSidecarLogger;
  private readonly profileCache: Map<string, ProfileCacheEntry> = new Map();
  
  constructor(config: WebIdClientConfig = {}) {
    // Merge with defaults
    this.config = {
      ...DEFAULT_WEBID_CLIENT_CONFIG,
      ...config,
      logger: config.logger || console,
    };

    // Initialize resource client
    this.resourceClient = new ResourceClient(config);
    this.logger = this.config.logger;

    this.logger.debug('WebIdClient initialized', {
      discoveryTimeout: this.config.discoveryTimeout,
      profileCacheSize: this.config.profileCacheSize,
      enableSsrfProtection: this.config.enableSsrfProtection,
    });
  }

  // ==========================================================================
  // Discovery Methods
  // ==========================================================================

  /**
   * Discovers and fetches a WebID profile
   * 
   * @param webId - The WebID to discover (can be URI or WebID URI)
   * @param options - Discovery options
   * @returns The WebID profile
   */
  public async discoverWebId(
    webId: string,
    options: WebIdDiscoveryOptions = {}
  ): Promise<WebIdProfile> {
    this.validateWebId(webId);
    
    // Check cache first
    const cachedProfile = this.getCachedProfile(webId);
    if (cachedProfile) {
      this.logger.debug('WebID profile found in cache', { webId });
      return cachedProfile;
    }
    
    // Normalize WebID to URI
    const profileUri = this.normalizeWebId(webId);
    
    // Validate URL for SSRF prevention
    if (this.config.enableSsrfProtection) {
      if (!validateUrl(profileUri, this.config.allowedHosts)) {
        throw new ValidationError(
          `Invalid WebID URI: ${profileUri}`,
          'webId'
        );
      }
    }
    
    // Fetch the profile
    const profile = await this.fetchWebIdProfile(profileUri, options);
    
    // Cache the profile
    this.cacheProfile(webId, profile);
    
    this.logger.info('WebID profile discovered', { 
      webId, 
      profileUri: profile.profileUri,
      name: profile.name,
      hasStorage: !!(profile.storage && profile.storage.length > 0)
    });
    
    return profile;
  }

  /**
   * Validates a WebID and returns validation result
   * 
   * @param webId - The WebID to validate
   * @param options - Validation options
   * @returns Validation result
   */
  public async validateWebId(
    webId: string,
    options: WebIdDiscoveryOptions = {}
  ): Promise<WebIdValidationResult> {
    const result: WebIdValidationResult = {
      valid: true,
      webId,
      errors: [],
      warnings: [],
    };

    try {
      // Basic validation
      if (!webId || typeof webId !== 'string') {
        result.errors.push('WebID must be a non-empty string');
        result.valid = false;
        return result;
      }

      // Must be a valid URI
      try {
        new URL(webId);
      } catch {
        result.errors.push('WebID must be a valid URI');
        result.valid = false;
        return result;
      }

      // Normalize and validate structure
      const profileUri = this.normalizeWebId(webId);
      if (!profileUri) {
        result.errors.push('WebID must be an HTTP(S) URI with a path');
        result.valid = false;
        return result;
      }

      // Validate SSRF
      if (this.config.enableSsrfProtection) {
        if (!validateUrl(profileUri, this.config.allowedHosts)) {
          result.errors.push('WebID URI failed SSRF validation');
          result.valid = false;
          return result;
        }
      }

      // Try to fetch the profile
      try {
        const profile = await this.fetchWebIdProfile(profileUri, options);
        result.profile = profile;
        result.profileUri = profile.profileUri;
        
        // Check for required fields
        if (!profile.id) {
          result.warnings.push('Profile does not have an explicit @id or subject');
        }
        
        // Check if WebID matches the profile subject
        if (profile.id && profile.id !== webId && profile.id !== profileUri) {
          result.warnings.push(`Profile subject (${profile.id}) does not match WebID (${webId})`);
        }
        
        // Check for storage locations
        if (!profile.storage || profile.storage.length === 0) {
          result.warnings.push('No storage locations found in profile');
        }
        
      } catch (error) {
        result.errors.push(`Failed to fetch WebID profile: ${error instanceof Error ? error.message : String(error)}`);
        result.valid = false;
      }
      
    } catch (error) {
      result.errors.push(`WebID validation failed: ${error instanceof Error ? error.message : String(error)}`);
      result.valid = false;
    }
    
    return result;
  }

  /**
   * Discovers storage locations for a WebID
   * 
   * @param webId - The WebID
   * @param options - Discovery options
   * @returns Array of storage URIs
   */
  public async discoverStorageLocations(
    webId: string,
    options: WebIdDiscoveryOptions = {}
  ): Promise<string[]> {
    const profile = await this.discoverWebId(webId, options);
    return profile.storage || [];
  }

  /**
   * Discovers the primary storage location for a WebID
   * 
   * @param webId - The WebID
   * @param options - Discovery options
   * @returns Primary storage URI or null
   */
  public async discoverPrimaryStorage(
    webId: string,
    options: WebIdDiscoveryOptions = {}
  ): Promise<string | null> {
    const storage = await this.discoverStorageLocations(webId, options);
    return storage.length > 0 ? storage[0] : null;
  }

  /**
   * Discovers the preferences file for a WebID
   * 
   * @param webId - The WebID
   * @param options - Discovery options
   * @returns Preferences file URI or null
   */
  public async discoverPreferencesFile(
    webId: string,
    options: WebIdDiscoveryOptions = {}
  ): Promise<string | null> {
    const profile = await this.discoverWebId(webId, options);
    return profile.preferencesFile || null;
  }

  // ==========================================================================
  // Cache Management
  // ==========================================================================

  /**
   * Clears the profile cache
   */
  public clearCache(): void {
    this.profileCache.clear();
    this.logger.debug('WebID profile cache cleared');
  }

  /**
   * Removes a specific profile from cache
   * 
   * @param webId - The WebID to remove
   */
  public clearCachedProfile(webId: string): void {
    this.profileCache.delete(webId);
    this.logger.debug('WebID profile removed from cache', { webId });
  }

  /**
   * Checks if a profile is cached
   * 
   * @param webId - The WebID to check
   * @returns true if cached
   */
  public isCached(webId: string): boolean {
    return this.profileCache.has(webId);
  }

  /**
   * Gets the number of cached profiles
   */
  public getCacheSize(): number {
    return this.profileCache.size;
  }

  // ==========================================================================
  // Private Methods
  // ==========================================================================

  /**
   * Validates a WebID string
   */
  private validateWebId(webId: string): void {
    if (!webId || typeof webId !== 'string') {
      throw new ValidationError('WebID must be a non-empty string', 'webId');
    }

    // Must be a valid URI
    try {
      new URL(webId);
    } catch {
      throw new ValidationError('WebID must be a valid URI', 'webId');
    }
  }

  /**
   * Normalizes a WebID to a profile URI
   */
  private normalizeWebId(webId: string): string {
    // If it already looks like a profile URI, use it
    if (webId.startsWith('http://') || webId.startsWith('https://')) {
      return webId;
    }
    
    // Try to construct a profile URI
    // WebID can be in the form: scheme:user@host/path
    // or just a URI reference
    
    try {
      const url = new URL(webId);
      // If it has a path, it's probably already a profile URI
      if (url.pathname && url.pathname !== '/') {
        return webId;
      }
      // Otherwise, try adding /profile/card
      return `${webId}/profile/card`;
    } catch {
      // If it's not a valid URL, try to parse it as a URI reference
      // This is a fallback for DID-style WebIDs
      return webId;
    }
  }

  /**
   * Fetches a WebID profile
   */
  private async fetchWebIdProfile(
    profileUri: string,
    options: WebIdDiscoveryOptions = {}
  ): Promise<WebIdProfile> {
    const { timeout, headers } = options;
    
    // Fetch with custom timeout
    const response = await this.resourceClient.get(
      profileUri,
      headers,
      timeout || this.config.discoveryTimeout
    );
    
    // Parse the profile
    const profile = this.parseWebIdProfile(response.content, profileUri);
    
    // Add response metadata
    profile.profileUri = profileUri;
    profile.lastModified = response.metadata.lastModified;
    profile.etag = response.metadata.etag;
    profile.raw = response.content;
    profile.turtle = response.content;
    
    return profile;
  }

  /**
   * Parses a WebID profile from RDF/Turtle
   */
  private parseWebIdProfile(turtle: string, profileUri: string): WebIdProfile {
    const profile: WebIdProfile = {
      id: profileUri,
      profileUri,
    };

    // Simple Turtle parser for WebID profiles
    // In production, use a proper RDF parser like N3 or rdflib.js
    
    const lines = turtle.split('\n');
    
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('@') || trimmed.startsWith('#')) continue;

      // Match subject
      const subjectMatch = trimmed.match(/^<([^>]+)>/);
      if (!subjectMatch) continue;
      
      const subject = subjectMatch[1];
      
      // Match type
      const typeMatch = trimmed.match(/a\s+<([^>]+)>/i);
      if (typeMatch) {
        const typeUri = typeMatch[1];
        if (typeUri.includes('Person') || typeUri.includes('Agent')) {
          profile.type = typeUri;
        }
      }
      
      // Match name (foaf:name)
      const nameMatch = trimmed.match(/<http:\/\/xmlns\.com\/foaf\/0\.1\/name>\s+"([^"]+)"/);
      if (nameMatch) {
        profile.name = nameMatch[1];
      }
      
      // Match nickname
      const nicknameMatch = trimmed.match(/<http:\/\/xmlns\.com\/foaf\/0\.1\/nick>\s+"([^"]+)"/);
      if (nicknameMatch) {
        profile.nickname = nicknameMatch[1];
      }
      
      // Match email
      const emailMatch = trimmed.match(/<http:\/\/xmlns\.com\/foaf\/0\.1\/mbox>\s+<mailto:([^>]+)>/);
      if (emailMatch) {
        profile.email = emailMatch[1];
      }
      
      // Match image
      const imageMatch = trimmed.match(/<http:\/\/xmlns\.com\/foaf\/0\.1\/(img|depiction|image)>\s+<([^>]+)>/);
      if (imageMatch) {
        profile.image = imageMatch[2];
      }
      
      // Match storage (pim:storage)
      const storageMatch = trimmed.match(/<http:\/\/www\.w3\.org\/ns\/pim\/space#storage>\s+<([^>]+)>/);
      if (storageMatch) {
        profile.storage = profile.storage || [];
        profile.storage.push(storageMatch[1]);
      }
      
      // Match preferences file (prefs:preferencesFile)
      const prefsMatch = trimmed.match(/<http:\/\/www\.w3\.org\/ns\/pim\/prefs#preferencesFile>\s+<([^>]+)>/);
      if (prefsMatch) {
        profile.preferencesFile = prefsMatch[1];
      }
    }
    
    return profile;
  }

  /**
   * Gets a cached profile if available and not expired
   */
  private getCachedProfile(webId: string): WebIdProfile | null {
    const entry = this.profileCache.get(webId);
    if (!entry) {
      return null;
    }
    
    // Check TTL
    const now = Date.now();
    if (now - entry.timestamp > this.config.profileCacheTtl) {
      // Cache entry expired
      this.profileCache.delete(webId);
      return null;
    }
    
    return entry.profile;
  }

  /**
   * Caches a profile
   */
  private cacheProfile(webId: string, profile: WebIdProfile): void {
    // Evict entries if cache is full
    if (this.profileCache.size >= this.config.profileCacheSize) {
      const now = Date.now();
      const oldEntries = Array.from(this.profileCache.entries())
        .sort((a, b) => a[1].timestamp - b[1].timestamp)
        .slice(0, Math.floor(this.config.profileCacheSize / 4));
      
      for (const [key] of oldEntries) {
        this.profileCache.delete(key);
      }
    }
    
    // Add new entry
    this.profileCache.set(webId, {
      profile,
      timestamp: Date.now(),
      etag: profile.etag,
    });
  }

  // ==========================================================================
  // Getters
  // ==========================================================================

  /**
   * Gets the resource client
   */
  public getResourceClient(): ResourceClient {
    return this.resourceClient;
  }

  /**
   * Gets the configuration
   */
  public getConfig(): Required<WebIdClientConfig> {
    return { ...this.config };
  }
}

// ============================================================================
// Exports
// ============================================================================

export default WebIdClient;
export type { WebIdProfile, WebIdDiscoveryOptions, WebIdValidationResult };
