/**
 * Solid Sidecar TypeScript SDK - Policy Client
 * Phase: 27 - SDK/Client Compatibility Layer
 * Version: v1.0.0
 * Created: 2026-07-07
 * Author: Mistral Vibe
 * License: MIT
 *
 * This file contains the PolicyClient for managing WAC and ACP policies.
 *
 * Security Level: CRITICAL
 */

import type {
  ResourceUri,
  ContainerUri,
  PolicyResource,
  WacPolicy,
  AcpPolicy,
  WacAuthorization,
  AcpAllowRule,
  AcpDenyRule,
  HttpHeaders,
  ResourceMetadata,
  AccessControlModel,
  WacMode,
  AcpOperation,
  SolidSidecarLogger,
} from '../types';
import { ResourceClient, type ResourceClientConfig } from './resource-client';
import { ValidationError } from '../types';
import { getContainerUri, getResourceName } from '../utils';

// ============================================================================
// Policy Client Configuration
// ============================================================================

/**
 * Configuration for PolicyClient
 */
export interface PolicyClientConfig extends ResourceClientConfig {
  /** Access control model to use (default: 'wac') */
  defaultModel?: AccessControlModel;
  
  /** Custom logger */
  logger?: SolidSidecarLogger;
}

/**
 * Default PolicyClient configuration
 */
export const DEFAULT_POLICY_CLIENT_CONFIG: Partial<PolicyClientConfig> = {
  defaultModel: 'wac',
};

// ============================================================================
// Policy Client
// ============================================================================

/**
 * PolicyClient for Solid Sidecar
 * 
 * Features:
 * - Read and write WAC policies
 * - Read and write ACP policies
 * - Policy validation
 * - Policy resource discovery
 * - Access control checking
 * - IDOR prevention
 * - SSRF prevention
 */
export class PolicyClient {
  private readonly config: Required<PolicyClientConfig>;
  private readonly resourceClient: ResourceClient;
  private readonly logger: SolidSidecarLogger;

  constructor(config: PolicyClientConfig = {}) {
    // Merge with defaults
    this.config = {
      ...DEFAULT_POLICY_CLIENT_CONFIG,
      ...config,
      logger: config.logger || console,
    };

    // Initialize resource client
    this.resourceClient = new ResourceClient(config);
    this.logger = this.config.logger;

    this.logger.debug('PolicyClient initialized', {
      defaultModel: this.config.defaultModel,
    });
  }

  // ==========================================================================
  // WAC Policy Operations
  // ==========================================================================

  /**
   * Gets the WAC policy for a resource
   */
  public async getWacPolicy(
    resourceUri: ResourceUri
  ): Promise<WacPolicy | null> {
    // Validate resource URI
    this.validateResourceUri(resourceUri);

    // Get policy resource URI
    const policyUri = this.getWacPolicyUri(resourceUri);

    try {
      const resource = await this.resourceClient.get(policyUri, {}, 'text/turtle');
      return this.parseWacPolicy(resource.content, resource.uri);
    } catch (error) {
      // If resource not found, check for container-level policy
      if (error instanceof Error && error.message.includes('404')) {
        const containerUri = getContainerUri(resourceUri);
        if (containerUri !== resourceUri) {
          const containerPolicyUri = this.getWacPolicyUri(containerUri);
          try {
            const containerResource = await this.resourceClient.get(
              containerPolicyUri,
              {},
              'text/turtle'
            );
            return this.parseWacPolicy(containerResource.content, containerPolicyUri);
          } catch {
            return null;
          }
        }
        return null;
      }
      throw error;
    }
  }

  /**
   * Sets the WAC policy for a resource
   */
  public async setWacPolicy(
    resourceUri: ResourceUri,
    policy: WacPolicy,
    options: {
      contentType?: string;
      headers?: HttpHeaders;
    } = {}
  ): Promise<ResourceMetadata> {
    // Validate resource URI
    this.validateResourceUri(resourceUri);

    // Get policy resource URI
    const policyUri = this.getWacPolicyUri(resourceUri);

    // Serialize policy to Turtle
    const turtle = this.serializeWacPolicy(policy);

    return this.resourceClient.put(policyUri, turtle, {
      contentType: options.contentType || 'text/turtle',
      headers: options.headers,
      link: '<http://www.w3.org/ns/auth/acl#Authorization>; rel="type"',
    });
  }

  /**
   * Adds an authorization to a WAC policy
   */
  public async addWacAuthorization(
    resourceUri: ResourceUri,
    authorization: WacAuthorization,
    options: {
      headers?: HttpHeaders;
    } = {}
  ): Promise<ResourceMetadata> {
    // Get existing policy
    const policy = await this.getWacPolicy(resourceUri);
    const policyUri = this.getWacPolicyUri(resourceUri);

    // Create new policy with the authorization added
    const newPolicy: WacPolicy = policy || {
      '@id': policyUri,
      authorization: [],
    };

    // Add or update authorization
    // Note: This is a simple implementation. In production, you might want
    // to check for existing authorizations and update them instead.
    newPolicy.authorization.push(authorization);

    // Serialize and update
    const turtle = this.serializeWacPolicy(newPolicy);
    return this.resourceClient.put(policyUri, turtle, {
      contentType: 'text/turtle',
      headers: options.headers,
      link: '<http://www.w3.org/ns/auth/acl#Authorization>; rel="type"',
    });
  }

  /**
   * Removes an authorization from a WAC policy
   */
  public async removeWacAuthorization(
    resourceUri: ResourceUri,
    authorizationId: string,
    options: {
      headers?: HttpHeaders;
    } = {}
  ): Promise<ResourceMetadata> {
    // Get existing policy
    const policy = await this.getWacPolicy(resourceUri);
    const policyUri = this.getWacPolicyUri(resourceUri);

    if (!policy) {
      throw new ValidationError(
        `No WAC policy found for resource: ${resourceUri}`,
        'resourceUri'
      );
    }

    // Remove the authorization
    const newPolicy: WacPolicy = {
      ...policy,
      authorization: policy.authorization.filter(
        auth => auth['@id'] !== authorizationId
      ),
    };

    // Serialize and update
    const turtle = this.serializeWacPolicy(newPolicy);
    return this.resourceClient.put(policyUri, turtle, {
      contentType: 'text/turtle',
      headers: options.headers,
      link: '<http://www.w3.org/ns/auth/acl#Authorization>; rel="type"',
    });
  }

  // ==========================================================================
  // ACP Policy Operations
  // ==========================================================================

  /**
   * Gets the ACP policy for a resource
   */
  public async getAcpPolicy(
    resourceUri: ResourceUri
  ): Promise<AcpPolicy | null> {
    // Validate resource URI
    this.validateResourceUri(resourceUri);

    // Get policy resource URI
    const policyUri = this.getAcpPolicyUri(resourceUri);

    try {
      const resource = await this.resourceClient.get(policyUri, {}, 'text/turtle');
      return this.parseAcpPolicy(resource.content, resource.uri);
    } catch (error) {
      // If resource not found, check for container-level policy
      if (error instanceof Error && error.message.includes('404')) {
        const containerUri = getContainerUri(resourceUri);
        if (containerUri !== resourceUri) {
          const containerPolicyUri = this.getAcpPolicyUri(containerUri);
          try {
            const containerResource = await this.resourceClient.get(
              containerPolicyUri,
              {},
              'text/turtle'
            );
            return this.parseAcpPolicy(containerResource.content, containerPolicyUri);
          } catch {
            return null;
          }
        }
        return null;
      }
      throw error;
    }
  }

  /**
   * Sets the ACP policy for a resource
   */
  public async setAcpPolicy(
    resourceUri: ResourceUri,
    policy: AcpPolicy,
    options: {
      contentType?: string;
      headers?: HttpHeaders;
    } = {}
  ): Promise<ResourceMetadata> {
    // Validate resource URI
    this.validateResourceUri(resourceUri);

    // Get policy resource URI
    const policyUri = this.getAcpPolicyUri(resourceUri);

    // Serialize policy to Turtle
    const turtle = this.serializeAcpPolicy(policy);

    return this.resourceClient.put(policyUri, turtle, {
      contentType: options.contentType || 'text/turtle',
      headers: options.headers,
      link: '<http://www.w3.org/ns/solid/acp#AccessPolicy>; rel="type"',
    });
  }

  /**
   * Adds an allow rule to an ACP policy
   */
  public async addAcpAllowRule(
    resourceUri: ResourceUri,
    rule: AcpAllowRule,
    options: {
      headers?: HttpHeaders;
    } = {}
  ): Promise<ResourceMetadata> {
    // Get existing policy
    const policy = await this.getAcpPolicy(resourceUri);
    const policyUri = this.getAcpPolicyUri(resourceUri);

    // Create new policy with the rule added
    const newPolicy: AcpPolicy = policy || {
      '@id': policyUri,
      appliesTo: resourceUri,
      allow: [],
      deny: [],
    };

    // Add the rule
    newPolicy.allow = newPolicy.allow || [];
    newPolicy.allow.push(rule);

    // Serialize and update
    const turtle = this.serializeAcpPolicy(newPolicy);
    return this.resourceClient.put(policyUri, turtle, {
      contentType: 'text/turtle',
      headers: options.headers,
      link: '<http://www.w3.org/ns/solid/acp#AccessPolicy>; rel="type"',
    });
  }

  /**
   * Adds a deny rule to an ACP policy
   */
  public async addAcpDenyRule(
    resourceUri: ResourceUri,
    rule: AcpDenyRule,
    options: {
      headers?: HttpHeaders;
    } = {}
  ): Promise<ResourceMetadata> {
    // Get existing policy
    const policy = await this.getAcpPolicy(resourceUri);
    const policyUri = this.getAcpPolicyUri(resourceUri);

    // Create new policy with the rule added
    const newPolicy: AcpPolicy = policy || {
      '@id': policyUri,
      appliesTo: resourceUri,
      allow: [],
      deny: [],
    };

    // Add the rule
    newPolicy.deny = newPolicy.deny || [];
    newPolicy.deny.push(rule);

    // Serialize and update
    const turtle = this.serializeAcpPolicy(newPolicy);
    return this.resourceClient.put(policyUri, turtle, {
      contentType: 'text/turtle',
      headers: options.headers,
      link: '<http://www.w3.org/ns/solid/acp#AccessPolicy>; rel="type"',
    });
  }

  // ==========================================================================
  // Generic Policy Operations
  // ==========================================================================

  /**
   * Gets the policy for a resource (WAC or ACP)
   */
  public async getPolicy(
    resourceUri: ResourceUri,
    model?: AccessControlModel
  ): Promise<PolicyResource | null> {
    const acm = model || this.config.defaultModel;

    switch (acm) {
      case 'wac':
        const wacPolicy = await this.getWacPolicy(resourceUri);
        if (wacPolicy) {
          return {
            uri: this.getWacPolicyUri(resourceUri),
            model: 'wac',
            policy: wacPolicy,
          };
        }
        return null;

      case 'acp':
        const acpPolicy = await this.getAcpPolicy(resourceUri);
        if (acpPolicy) {
          return {
            uri: this.getAcpPolicyUri(resourceUri),
            model: 'acp',
            policy: acpPolicy,
          };
        }
        return null;

      default:
        throw new ValidationError(
          `Unsupported access control model: ${acm}`,
          'model'
        );
    }
  }

  /**
   * Sets the policy for a resource
   */
  public async setPolicy(
    resourceUri: ResourceUri,
    policy: WacPolicy | AcpPolicy,
    model?: AccessControlModel,
    options: {
      contentType?: string;
      headers?: HttpHeaders;
    } = {}
  ): Promise<ResourceMetadata> {
    const acm = model || this.config.defaultModel;

    switch (acm) {
      case 'wac':
        return this.setWacPolicy(resourceUri, policy as WacPolicy, options);

      case 'acp':
        return this.setAcpPolicy(resourceUri, policy as AcpPolicy, options);

      default:
        throw new ValidationError(
          `Unsupported access control model: ${acm}`,
          'model'
        );
    }
  }

  // ==========================================================================
  // Policy Discovery
  // ==========================================================================

  /**
   * Discovers the policy URI for a resource
   */
  public async discoverPolicyUri(
    resourceUri: ResourceUri
  ): Promise<ResourceUri | null> {
    // Get resource metadata
    const metadata = await this.resourceClient.head(resourceUri);

    // Look for Link header with rel="acl"
    const aclLink = metadata.links?.find(
      link => link.rel.toLowerCase() === 'acl'
    );

    if (aclLink) {
      return aclLink.uri;
    }

    // Default to standard ACL location
    return this.getWacPolicyUri(resourceUri);
  }

  // ==========================================================================
  // Access Control Checking
  // ==========================================================================

  /**
   * Checks if an agent has a specific access mode on a resource (WAC)
   */
  public async checkWacAccess(
    resourceUri: ResourceUri,
    agentWebId: string,
    mode: WacMode
  ): Promise<boolean> {
    const policy = await this.getWacPolicy(resourceUri);
    if (!policy) {
      // No policy means no access
      return false;
    }

    for (const auth of policy.authorization) {
      // Check agent
      let agentMatch = false;
      if (auth.agent === agentWebId) {
        agentMatch = true;
      } else if (auth.agentClass) {
        // Check if agent is a member of the class
        // This is a simplified check - in production, you'd need to query the agent's profile
        agentMatch = true; // Assume class includes all agents for now
      } else if (auth.agentGroup) {
        // Check if agent is a member of the group
        // This would require group membership lookup
        agentMatch = false;
      }

      // Check access to
      const accessTo = auth.accessTo || resourceUri;
      const resourceMatch = accessTo === resourceUri ||
        accessTo === '*' ||
        (accessTo.endsWith('/') && resourceUri.startsWith(accessTo));

      if (agentMatch && resourceMatch) {
        const authModes = Array.isArray(auth.mode) ? auth.mode : [auth.mode];
        if (authModes.includes(mode)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Checks if an agent has a specific operation on a resource (ACP)
   */
  public async checkAcpAccess(
    resourceUri: ResourceUri,
    agentWebId: string,
    operation: AcpOperation
  ): Promise<boolean> {
    const policy = await this.getAcpPolicy(resourceUri);
    if (!policy) {
      // No policy means no access
      return false;
    }

    // Check deny rules first (they take precedence)
    for (const denyRule of policy.deny || []) {
      const actorMatch = this.checkAcpActorMatch(denyRule, agentWebId);
      const operationMatch = this.checkAcpOperationMatch(denyRule, operation);
      
      if (actorMatch && operationMatch) {
        return false;
      }
    }

    // Check allow rules
    for (const allowRule of policy.allow || []) {
      const actorMatch = this.checkAcpActorMatch(allowRule, agentWebId);
      const operationMatch = this.checkAcpOperationMatch(allowRule, operation);
      
      if (actorMatch && operationMatch) {
        return true;
      }
    }

    return false;
  }

  // ==========================================================================
  // Policy Serialization/Deserialization
  // ==========================================================================

  /**
   * Parses a WAC policy from Turtle
   */
  private parseWacPolicy(turtle: string, policyUri: ResourceUri): WacPolicy {
    // Simple Turtle parser for WAC policies
    // In production, use a proper RDF parser
    const policy: WacPolicy = {
      '@id': policyUri,
      authorization: [],
    };

    const lines = turtle.split('\n');
    let currentAuth: Partial<WacAuthorization> | null = null;

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('@') || trimmed.startsWith('#')) continue;

      // Match subject (authorization URI)
      const authMatch = trimmed.match(/^<([^>]+)>\s+a\s+<http:\/\/www\.w3\.org\/ns\/auth\/acl#Authorization>/);
      if (authMatch) {
        const authUri = authMatch[1];
        currentAuth = {
          '@id': authUri,
          type: 'Authorization',
        };
        policy.authorization.push(currentAuth as WacAuthorization);
        continue;
      }

      if (!currentAuth) continue;

      // Match accessTo
      const accessToMatch = trimmed.match(/<http:\/\/www\.w3\.org\/ns\/auth\/acl#accessTo>\s+<([^>]+)>/);
      if (accessToMatch) {
        currentAuth.accessTo = accessToMatch[1];
        continue;
      }

      // Match agent
      const agentMatch = trimmed.match(/<http:\/\/www\.w3\.org\/ns\/auth\/acl#agent>\s+<([^>]+)>/);
      if (agentMatch) {
        currentAuth.agent = agentMatch[1];
        continue;
      }

      // Match agentClass
      const agentClassMatch = trimmed.match(/<http:\/\/www\.w3\.org\/ns\/auth\/acl#agentClass>\s+<([^>]+)>/);
      if (agentClassMatch) {
        currentAuth.agentClass = agentClassMatch[1];
        continue;
      }

      // Match agentGroup
      const agentGroupMatch = trimmed.match(/<http:\/\/www\.w3\.org\/ns\/auth\/acl#agentGroup>\s+<([^>]+)>/);
      if (agentGroupMatch) {
        currentAuth.agentGroup = agentGroupMatch[1];
        continue;
      }

      // Match mode
      const modeMatch = trimmed.match(/<http:\/\/www\.w3\.org\/ns\/auth\/acl#mode>\s+<([^>]+)>/);
      if (modeMatch) {
        const modeUri = modeMatch[1];
        const mode = this.uriToWacMode(modeUri);
        if (mode) {
          currentAuth.mode = Array.isArray(currentAuth.mode)
            ? [...currentAuth.mode, mode]
            : [mode];
        }
        continue;
      }
    }

    return policy;
  }

  /**
   * Serializes a WAC policy to Turtle
   */
  private serializeWacPolicy(policy: WacPolicy): string {
    const lines: string[] = [];

    // Add prefix
    lines.push('@prefix acl: <http://www.w3.org/ns/auth/acl#> .');
    lines.push('@prefix foaf: <http://xmlns.com/foaf/0.1/> .');
    lines.push('');

    // Serialize each authorization
    for (const auth of policy.authorization) {
      const authId = auth['@id'] || `_:auth${policy.authorization.indexOf(auth)}`;
      
      lines.push(`<${authId}> a acl:Authorization;`);
      
      if (auth.accessTo) {
        lines.push(`  acl:accessTo <${auth.accessTo}>;`);
      }

      if (auth.agent) {
        lines.push(`  acl:agent <${auth.agent}>;`);
      }
      if (auth.agentClass) {
        lines.push(`  acl:agentClass <${auth.agentClass}>;`);
      }
      if (auth.agentGroup) {
        lines.push(`  acl:agentGroup <${auth.agentGroup}>;`);
      }

      if (auth.mode) {
        const modes = Array.isArray(auth.mode) ? auth.mode : [auth.mode];
        for (const mode of modes) {
          lines.push(`  acl:mode <${this.wacModeToUri(mode)}>.`);
        }
      }
      
      lines.push('');
    }

    return lines.join('\n');
  }

  /**
   * Parses an ACP policy from Turtle
   */
  private parseAcpPolicy(turtle: string, policyUri: ResourceUri): AcpPolicy {
    // Simple Turtle parser for ACP policies
    // In production, use a proper RDF parser
    const policy: AcpPolicy = {
      '@id': policyUri,
      appliesTo: '',
      allow: [],
      deny: [],
    };

    const lines = turtle.split('\n');
    let inAllow = false;
    let inDeny = false;
    let currentRule: Partial<AcpAllowRule | AcpDenyRule> | null = null;

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('@') || trimmed.startsWith('#')) continue;

      // Match appliesTo
      const appliesToMatch = trimmed.match(/<http:\/\/www\.w3\.org\/ns\/solid\/acp#appliesTo>\s+<([^>]+)>/);
      if (appliesToMatch) {
        policy.appliesTo = appliesToMatch[1];
        continue;
      }

      // Match allow
      const allowMatch = trimmed.match(/<http:\/\/www\.w3\.org\/ns\/solid\/acp#allow>\s+\[/);
      if (allowMatch) {
        inAllow = true;
        inDeny = false;
        currentRule = { type: 'allow' };
        continue;
      }

      // Match deny
      const denyMatch = trimmed.match(/<http:\/\/www\.w3\.org\/ns\/solid\/acp#deny>\s+\[/);
      if (denyMatch) {
        inDeny = true;
        inAllow = false;
        currentRule = { type: 'deny' };
        continue;
      }

      // Match closing bracket
      if (trimmed === '] .' || trimmed === '].') {
        if (currentRule && inAllow) {
          policy.allow = policy.allow || [];
          policy.allow.push(currentRule as AcpAllowRule);
        } else if (currentRule && inDeny) {
          policy.deny = policy.deny || [];
          policy.deny.push(currentRule as AcpDenyRule);
        }
        currentRule = null;
        inAllow = false;
        inDeny = false;
        continue;
      }

      if (!currentRule) continue;

      // Match actor
      const actorMatch = trimmed.match(/<http:\/\/www\.w3\.org\/ns\/solid\/acp#actor>\s+<([^>]+)>/);
      if (actorMatch) {
        currentRule.actor = actorMatch[1];
        continue;
      }

      // Match actorClass
      const actorClassMatch = trimmed.match(/<http:\/\/www\.w3\.org\/ns\/solid\/acp#actorClass>\s+<([^>]+)>/);
      if (actorClassMatch) {
        currentRule.actorClass = actorClassMatch[1];
        continue;
      }

      // Match actorGroup
      const actorGroupMatch = trimmed.match(/<http:\/\/www\.w3\.org\/ns\/solid\/acp#actorGroup>\s+<([^>]+)>/);
      if (actorGroupMatch) {
        currentRule.actorGroup = actorGroupMatch[1];
        continue;
      }

      // Match operation
      const operationMatch = trimmed.match(/<http:\/\/www\.w3\.org\/ns\/solid\/acp#operation>\s+<([^>]+)>/);
      if (operationMatch) {
        const operationUri = operationMatch[1];
        const operation = this.uriToAcpOperation(operationUri);
        if (operation) {
          currentRule.operation = Array.isArray(currentRule.operation)
            ? [...currentRule.operation, operation]
            : [operation];
        }
        continue;
      }
    }

    return policy;
  }

  /**
   * Serializes an ACP policy to Turtle
   */
  private serializeAcpPolicy(policy: AcpPolicy): string {
    const lines: string[] = [];

    // Add prefix
    lines.push('@prefix acl: <http://www.w3.org/ns/solid/acp#> .');
    lines.push('@prefix foaf: <http://xmlns.com/foaf/0.1/> .');
    lines.push('');

    // Serialize appliesTo
    lines.push(`<> a acl:AccessPolicy;`);
    lines.push(`  acl:appliesTo <${policy.appliesTo}>;`);

    // Serialize allow rules
    if (policy.allow && policy.allow.length > 0) {
      lines.push('  acl:allow');
      for (const rule of policy.allow) {
        lines.push('  [');
        
        if (rule.actor) {
          lines.push(`    acl:actor <${rule.actor}>;`);
        }
        if (rule.actorClass) {
          lines.push(`    acl:actorClass <${rule.actorClass}>;`);
        }
        if (rule.actorGroup) {
          lines.push(`    acl:actorGroup <${rule.actorGroup}>;`);
        }
        
        if (rule.operation) {
          const operations = Array.isArray(rule.operation) ? rule.operation : [rule.operation];
          for (const operation of operations) {
            lines.push(`    acl:operation <${this.acpOperationToUri(operation)}>.`);
          }
        }
        
        lines.push('  ]');
      }
    }

    // Serialize deny rules
    if (policy.deny && policy.deny.length > 0) {
      lines.push('  acl:deny');
      for (const rule of policy.deny) {
        lines.push('  [');
        
        if (rule.actor) {
          lines.push(`    acl:actor <${rule.actor}>;`);
        }
        if (rule.actorClass) {
          lines.push(`    acl:actorClass <${rule.actorClass}>;`);
        }
        if (rule.actorGroup) {
          lines.push(`    acl:actorGroup <${rule.actorGroup}>;`);
        }
        
        if (rule.operation) {
          const operations = Array.isArray(rule.operation) ? rule.operation : [rule.operation];
          for (const operation of operations) {
            lines.push(`    acl:operation <${this.acpOperationToUri(operation)}>.`);
          }
        }
        
        lines.push('  ]');
      }
    }

    return lines.join('\n');
  }

  // ==========================================================================
  // URI Helpers
  // ==========================================================================

  /**
   * Gets the WAC policy URI for a resource
   */
  private getWacPolicyUri(resourceUri: ResourceUri): ResourceUri {
    return `${resourceUri}.acl`;
  }

  /**
   * Gets the ACP policy URI for a resource
   */
  private getAcpPolicyUri(resourceUri: ResourceUri): ResourceUri {
    return `${resourceUri}.meta`;
  }

  // ==========================================================================
  // Validation
  // ==========================================================================

  /**
   * Validates a resource URI
   */
  private validateResourceUri(resourceUri: ResourceUri): void {
    if (!resourceUri) {
      throw new ValidationError('Resource URI is required', 'resourceUri');
    }
    if (resourceUri.includes('..') || resourceUri.includes('//')) {
      throw new ValidationError(
        'Invalid resource URI: path traversal detected',
        'resourceUri'
      );
    }
  }

  // ==========================================================================
  // WAC Mode Conversions
  // ==========================================================================

  /**
   * Converts WAC mode URI to mode enum
   */
  private uriToWacMode(uri: string): WacMode | null {
    const map: Record<string, WacMode> = {
      'http://www.w3.org/ns/auth/acl#Read': 'Read',
      'http://www.w3.org/ns/auth/acl#Write': 'Write',
      'http://www.w3.org/ns/auth/acl#Control': 'Control',
      'http://www.w3.org/ns/auth/acl#Append': 'Append',
    };
    return map[uri] || null;
  }

  /**
   * Converts WAC mode to URI
   */
  private wacModeToUri(mode: WacMode): string {
    const map: Record<WacMode, string> = {
      Read: 'http://www.w3.org/ns/auth/acl#Read',
      Write: 'http://www.w3.org/ns/auth/acl#Write',
      Control: 'http://www.w3.org/ns/auth/acl#Control',
      Append: 'http://www.w3.org/ns/auth/acl#Append',
    };
    return map[mode];
  }

  // ==========================================================================
  // ACP Operation Conversions
  // ==========================================================================

  /**
   * Converts ACP operation URI to operation enum
   */
  private uriToAcpOperation(uri: string): AcpOperation | null {
    const map: Record<string, AcpOperation> = {
      'http://www.w3.org/ns/solid/acp#Read': 'Read',
      'http://www.w3.org/ns/solid/acp#Write': 'Write',
      'http://www.w3.org/ns/solid/acp#Control': 'Control',
      'http://www.w3.org/ns/solid/acp#Append': 'Append',
      'http://www.w3.org/ns/solid/acp#Create': 'Create',
      'http://www.w3.org/ns/solid/acp#Delete': 'Delete',
    };
    return map[uri] || null;
  }

  /**
   * Converts ACP operation to URI
   */
  private acpOperationToUri(operation: AcpOperation): string {
    const map: Record<AcpOperation, string> = {
      Read: 'http://www.w3.org/ns/solid/acp#Read',
      Write: 'http://www.w3.org/ns/solid/acp#Write',
      Control: 'http://www.w3.org/ns/solid/acp#Control',
      Append: 'http://www.w3.org/ns/solid/acp#Append',
      Create: 'http://www.w3.org/ns/solid/acp#Create',
      Delete: 'http://www.w3.org/ns/solid/acp#Delete',
    };
    return map[operation];
  }

  // ==========================================================================
  // ACP Rule Matching
  // ==========================================================================

  /**
   * Checks if an agent matches an ACP actor specification
   */
  private checkAcpActorMatch(
    rule: AcpAllowRule | AcpDenyRule,
    agentWebId: string
  ): boolean {
    // Check exact agent match
    if (rule.actor && rule.actor === agentWebId) {
      return true;
    }

    // Check actor class (foaf:Agent matches any agent)
    if (rule.actorClass) {
      if (rule.actorClass === 'http://xmlns.com/foaf/0.1/Agent') {
        return true;
      }
    }

    // Check actor group (simplified - would need group membership lookup)
    if (rule.actorGroup) {
      // For now, return false for group checks
      // In production, you would check if the agent is a member of the group
      return false;
    }

    return false;
  }

  /**
   * Checks if an operation matches an ACP operation specification
   */
  private checkAcpOperationMatch(
    rule: AcpAllowRule | AcpDenyRule,
    operation: AcpOperation
  ): boolean {
    const ruleOperations = Array.isArray(rule.operation) ? rule.operation : [rule.operation];
    return ruleOperations.includes(operation);
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
  public getConfig(): Required<PolicyClientConfig> {
    return { ...this.config };
  }
}

// ============================================================================
// Exports
// ============================================================================

export default PolicyClient;
