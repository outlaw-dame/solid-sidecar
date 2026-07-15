import type {
  AccessControlModel,
  AcpAllowRule,
  AcpDenyRule,
  AcpOperation,
  AcpPolicy,
  ContainerUri,
  HttpHeaders,
  PolicyResource,
  ResourceMetadata,
  ResourceUri,
  SolidSidecarLogger,
  WacAuthorization,
  WacMode,
  WacPolicy,
} from '../types';
import { ResourceNotFoundError, ValidationError } from '../types';
import { nullLogger } from '../utils';
import { ResourceClient, type ResourceClientConfig } from './resource-client';

export interface PolicyClientConfig extends ResourceClientConfig {
  defaultModel?: AccessControlModel;
  logger?: SolidSidecarLogger;
}

type PolicyWriteOptions = {
  contentType?: string;
  headers?: HttpHeaders;
  ifMatch?: string | string[];
  ifNoneMatch?: string | string[];
};

type ResolvedPolicyClientConfig = {
  defaultModel: AccessControlModel;
  logger: SolidSidecarLogger;
};

export const DEFAULT_POLICY_CLIENT_CONFIG = {
  defaultModel: 'wac',
  logger: nullLogger,
} satisfies ResolvedPolicyClientConfig;

const ACL = 'http://www.w3.org/ns/auth/acl#';
const ACP = 'http://www.w3.org/ns/solid/acp#';
const FOAF_AGENT = 'http://xmlns.com/foaf/0.1/Agent';
const WAC_MODES = new Set<WacMode>(['Read', 'Write', 'Control', 'Append']);
const ACP_OPERATIONS = new Set<AcpOperation>([
  'Read',
  'Write',
  'Control',
  'Append',
  'Create',
  'Delete',
]);

function values(value: string | string[] | undefined): string[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

function getStringField(
  record: Record<string, string | string[]>,
  field: string
): string[] {
  return values(record[field]);
}

export class PolicyClient {
  private readonly config: ResolvedPolicyClientConfig;
  private readonly resourceClient: ResourceClient;

  constructor(config: PolicyClientConfig = {}) {
    const defaultModel = config.defaultModel ?? DEFAULT_POLICY_CLIENT_CONFIG.defaultModel;
    if (defaultModel !== 'wac' && defaultModel !== 'acp') {
      throw new ValidationError(
        `Unsupported access control model: ${defaultModel}`,
        'defaultModel'
      );
    }
    this.config = {
      defaultModel,
      logger: config.logger ?? DEFAULT_POLICY_CLIENT_CONFIG.logger,
    };
    this.resourceClient = new ResourceClient(config);
  }

  public async getWacPolicy(resourceUri: ResourceUri): Promise<WacPolicy | null> {
    const resource = this.resolveResource(resourceUri);
    const direct = await this.readPolicy(this.getPolicyUri(resource, 'wac'), 'wac');
    if (direct) return direct as WacPolicy;
    const container = this.parentContainer(resource);
    if (container === resource) return null;
    return (await this.readPolicy(this.getPolicyUri(container, 'wac'), 'wac')) as
      | WacPolicy
      | null;
  }

  public async setWacPolicy(
    resourceUri: ResourceUri,
    policy: WacPolicy,
    options: PolicyWriteOptions = {}
  ): Promise<ResourceMetadata> {
    const resource = this.resolveResource(resourceUri);
    this.validateWacPolicy(policy, resource);
    return this.resourceClient.put(
      this.getPolicyUri(resource, 'wac'),
      this.serializeWacPolicy(policy),
      {
        contentType: options.contentType ?? 'text/turtle',
        headers: options.headers,
        ifMatch: options.ifMatch,
        ifNoneMatch: options.ifNoneMatch,
        link: `<${ACL}Authorization>; rel="type"`,
      }
    );
  }

  public async addWacAuthorization(
    resourceUri: ResourceUri,
    authorization: WacAuthorization,
    options: PolicyWriteOptions = {}
  ): Promise<ResourceMetadata> {
    const resource = this.resolveResource(resourceUri);
    const current = await this.getWacPolicy(resource);
    const next: WacPolicy = {
      '@id': current?.['@id'] ?? this.getPolicyUri(resource, 'wac'),
      authorization: [...(current?.authorization ?? []), authorization],
    };
    return this.setWacPolicy(resource, next, options);
  }

  public async removeWacAuthorization(
    resourceUri: ResourceUri,
    authorizationId: string,
    options: PolicyWriteOptions = {}
  ): Promise<ResourceMetadata> {
    const resource = this.resolveResource(resourceUri);
    const current = await this.getWacPolicy(resource);
    if (!current) {
      throw new ValidationError('No WAC policy found for resource', 'resourceUri');
    }
    const authorization = current.authorization.filter(
      item => item['@id'] !== authorizationId
    );
    if (authorization.length === current.authorization.length) {
      throw new ValidationError('WAC authorization was not found', 'authorizationId');
    }
    return this.setWacPolicy(resource, { ...current, authorization }, options);
  }

  public async getAcpPolicy(resourceUri: ResourceUri): Promise<AcpPolicy | null> {
    const resource = this.resolveResource(resourceUri);
    const direct = await this.readPolicy(this.getPolicyUri(resource, 'acp'), 'acp');
    if (direct) return direct as AcpPolicy;
    const container = this.parentContainer(resource);
    if (container === resource) return null;
    return (await this.readPolicy(this.getPolicyUri(container, 'acp'), 'acp')) as
      | AcpPolicy
      | null;
  }

  public async setAcpPolicy(
    resourceUri: ResourceUri,
    policy: AcpPolicy,
    options: PolicyWriteOptions = {}
  ): Promise<ResourceMetadata> {
    const resource = this.resolveResource(resourceUri);
    this.validateAcpPolicy(policy, resource);
    return this.resourceClient.put(
      this.getPolicyUri(resource, 'acp'),
      this.serializeAcpPolicy(policy),
      {
        contentType: options.contentType ?? 'text/turtle',
        headers: options.headers,
        ifMatch: options.ifMatch,
        ifNoneMatch: options.ifNoneMatch,
        link: `<${ACP}AccessPolicy>; rel="type"`,
      }
    );
  }

  public async addAcpAllowRule(
    resourceUri: ResourceUri,
    rule: AcpAllowRule,
    options: PolicyWriteOptions = {}
  ): Promise<ResourceMetadata> {
    const resource = this.resolveResource(resourceUri);
    const current = await this.getAcpPolicy(resource);
    const next: AcpPolicy = {
      '@id': current?.['@id'] ?? this.getPolicyUri(resource, 'acp'),
      appliesTo: current?.appliesTo ?? resource,
      allow: [...(current?.allow ?? []), rule],
      deny: [...(current?.deny ?? [])],
    };
    return this.setAcpPolicy(resource, next, options);
  }

  public async addAcpDenyRule(
    resourceUri: ResourceUri,
    rule: AcpDenyRule,
    options: PolicyWriteOptions = {}
  ): Promise<ResourceMetadata> {
    const resource = this.resolveResource(resourceUri);
    const current = await this.getAcpPolicy(resource);
    const next: AcpPolicy = {
      '@id': current?.['@id'] ?? this.getPolicyUri(resource, 'acp'),
      appliesTo: current?.appliesTo ?? resource,
      allow: [...(current?.allow ?? [])],
      deny: [...(current?.deny ?? []), rule],
    };
    return this.setAcpPolicy(resource, next, options);
  }

  public async getPolicy(
    resourceUri: ResourceUri,
    model: AccessControlModel = this.config.defaultModel
  ): Promise<PolicyResource | null> {
    if (model === 'wac') {
      const policy = await this.getWacPolicy(resourceUri);
      return policy
        ? { uri: this.getPolicyUri(this.resolveResource(resourceUri), 'wac'), model, policy }
        : null;
    }
    if (model === 'acp') {
      const policy = await this.getAcpPolicy(resourceUri);
      return policy
        ? { uri: this.getPolicyUri(this.resolveResource(resourceUri), 'acp'), model, policy }
        : null;
    }
    throw new ValidationError(`Unsupported access control model: ${model}`, 'model');
  }

  public async setPolicy(
    resourceUri: ResourceUri,
    policy: WacPolicy | AcpPolicy,
    model: AccessControlModel = this.config.defaultModel,
    options: PolicyWriteOptions = {}
  ): Promise<ResourceMetadata> {
    if (model === 'wac') return this.setWacPolicy(resourceUri, policy as WacPolicy, options);
    if (model === 'acp') return this.setAcpPolicy(resourceUri, policy as AcpPolicy, options);
    throw new ValidationError(`Unsupported access control model: ${model}`, 'model');
  }

  public async discoverPolicyUri(resourceUri: ResourceUri): Promise<ResourceUri> {
    const resource = this.resolveResource(resourceUri);
    const metadata = await this.resourceClient.head(resource);
    const acl = metadata.links?.find(link => link.rel.toLowerCase() === 'acl');
    if (!acl) return this.getPolicyUri(resource, 'wac');
    return this.assertPolicyUri(new URL(acl.uri, resource).toString());
  }

  public async checkWacAccess(
    resourceUri: ResourceUri,
    agentWebId: string,
    mode: WacMode
  ): Promise<boolean> {
    const resource = this.resolveResource(resourceUri);
    const agent = this.validateActor(agentWebId, 'agentWebId');
    if (!WAC_MODES.has(mode)) return false;
    const policy = await this.getWacPolicy(resource);
    if (!policy) return false;
    return policy.authorization.some(auth => {
      const agentMatch =
        getStringField(auth, 'agent').includes(agent) ||
        getStringField(auth, 'agentClass').includes(FOAF_AGENT);
      return (
        agentMatch &&
        this.authorizationCovers(getStringField(auth, 'accessTo'), resource) &&
        values(auth.mode).includes(mode)
      );
    });
  }

  public async checkAcpAccess(
    resourceUri: ResourceUri,
    agentWebId: string,
    operation: AcpOperation
  ): Promise<boolean> {
    const resource = this.resolveResource(resourceUri);
    const agent = this.validateActor(agentWebId, 'agentWebId');
    if (!ACP_OPERATIONS.has(operation)) return false;
    const policy = await this.getAcpPolicy(resource);
    if (!policy) return false;
    const matches = (rule: AcpAllowRule | AcpDenyRule): boolean =>
      (getStringField(rule, 'actor').includes(agent) ||
        getStringField(rule, 'actorClass').includes(FOAF_AGENT)) &&
      values(rule.operation).includes(operation);
    if ((policy.deny ?? []).some(matches)) return false;
    return (policy.allow ?? []).some(matches);
  }

  private async readPolicy(
    policyUri: ResourceUri,
    model: 'wac' | 'acp'
  ): Promise<WacPolicy | AcpPolicy | null> {
    try {
      const resource = await this.resourceClient.get(policyUri, {}, 'text/turtle');
      return model === 'wac'
        ? this.parseWacPolicy(resource.content, resource.uri)
        : this.parseAcpPolicy(resource.content, resource.uri);
    } catch (error) {
      if (error instanceof ResourceNotFoundError) return null;
      throw error;
    }
  }

  private resolveResource(resourceUri: ResourceUri | ContainerUri): ResourceUri {
    if (!resourceUri?.trim()) {
      throw new ValidationError('Resource URI is required', 'resourceUri');
    }
    const base = new URL(this.resourceClient.getHttpClient().getConfig().baseUrl);
    let resource: URL;
    try {
      resource = new URL(resourceUri, base);
    } catch {
      throw new ValidationError('Resource URI is invalid', 'resourceUri');
    }
    if (!['http:', 'https:'].includes(resource.protocol) || resource.username || resource.password) {
      throw new ValidationError('Resource URI is outside the configured scope', 'resourceUri');
    }
    const basePath = base.pathname.endsWith('/') ? base.pathname : `${base.pathname}/`;
    const resourcePath = resource.pathname.endsWith('/')
      ? resource.pathname
      : `${resource.pathname}/`;
    if (
      resource.origin !== base.origin ||
      (basePath !== '/' && resourcePath !== basePath && !resourcePath.startsWith(basePath))
    ) {
      throw new ValidationError('Resource URI is outside the configured scope', 'resourceUri');
    }
    resource.hash = '';
    return resource.toString();
  }

  private assertPolicyUri(policyUri: string): ResourceUri {
    return this.resolveResource(policyUri);
  }

  private getPolicyUri(resourceUri: ResourceUri, model: 'wac' | 'acp'): ResourceUri {
    const url = new URL(resourceUri);
    url.hash = '';
    url.search = '';
    url.pathname = `${url.pathname}${model === 'wac' ? '.acl' : '.meta'}`;
    return this.assertPolicyUri(url.toString());
  }

  private parentContainer(resourceUri: ResourceUri): ContainerUri {
    const url = new URL(resourceUri);
    if (url.pathname.endsWith('/')) return url.toString();
    url.pathname = url.pathname.slice(0, url.pathname.lastIndexOf('/') + 1);
    url.search = '';
    url.hash = '';
    return url.toString();
  }

  private authorizationCovers(accessTo: string[], resourceUri: string): boolean {
    return accessTo.some(candidate => {
      if (candidate === '*') return false;
      try {
        const scope = new URL(candidate, resourceUri);
        const resource = new URL(resourceUri);
        if (scope.origin !== resource.origin) return false;
        if (scope.toString() === resource.toString()) return true;
        const path = scope.pathname.endsWith('/') ? scope.pathname : `${scope.pathname}/`;
        return scope.pathname.endsWith('/') && resource.pathname.startsWith(path);
      } catch {
        return false;
      }
    });
  }

  private validateWacPolicy(policy: WacPolicy, resourceUri: string): void {
    if (!Array.isArray(policy.authorization)) {
      throw new ValidationError('WAC authorization must be an array', 'authorization');
    }
    for (const auth of policy.authorization) {
      if (auth.type !== 'Authorization') {
        throw new ValidationError('Invalid WAC authorization type', 'type');
      }
      const subjects = [
        ...getStringField(auth, 'agent'),
        ...getStringField(auth, 'agentClass'),
        ...getStringField(auth, 'agentGroup'),
      ];
      if (subjects.length === 0) {
        throw new ValidationError('WAC authorization requires an agent selector', 'agent');
      }
      subjects.forEach(value => this.validateIri(value, 'agent'));
      const accessTo = getStringField(auth, 'accessTo');
      if (accessTo.length === 0 || !this.authorizationCovers(accessTo, resourceUri)) {
        throw new ValidationError('WAC accessTo must cover the target resource', 'accessTo');
      }
      const modes = values(auth.mode);
      if (modes.length === 0 || modes.some(mode => !WAC_MODES.has(mode as WacMode))) {
        throw new ValidationError('WAC authorization contains an invalid mode', 'mode');
      }
    }
  }

  private validateAcpPolicy(policy: AcpPolicy, resourceUri: string): void {
    const appliesTo = this.validateIri(policy.appliesTo, 'appliesTo');
    if (appliesTo !== resourceUri) {
      throw new ValidationError('ACP appliesTo must equal the target resource', 'appliesTo');
    }
    for (const rule of [...(policy.allow ?? []), ...(policy.deny ?? [])]) {
      const actors = [
        ...getStringField(rule, 'actor'),
        ...getStringField(rule, 'actorClass'),
        ...getStringField(rule, 'actorGroup'),
      ];
      if (actors.length === 0) {
        throw new ValidationError('ACP rule requires an actor selector', 'actor');
      }
      actors.forEach(value => this.validateIri(value, 'actor'));
      const operations = values(rule.operation);
      if (
        operations.length === 0 ||
        operations.some(operation => !ACP_OPERATIONS.has(operation as AcpOperation))
      ) {
        throw new ValidationError('ACP rule contains an invalid operation', 'operation');
      }
    }
  }

  private validateActor(value: string, field: string): string {
    return this.validateIri(value, field);
  }

  private validateIri(value: string, field: string): string {
    if (!value || /[<>\u0000-\u0020]/.test(value)) {
      throw new ValidationError(`Invalid ${field} IRI`, field);
    }
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw new ValidationError(`Invalid ${field} IRI`, field);
    }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
      throw new ValidationError(`Invalid ${field} IRI`, field);
    }
    return url.toString();
  }

  private iri(value: string, field: string): string {
    return `<${this.validateIri(value, field)}>`;
  }

  private serializeWacPolicy(policy: WacPolicy): string {
    const lines = [`@prefix acl: <${ACL}> .`, ''];
    policy.authorization.forEach((auth, index) => {
      const subject = auth['@id']
        ? this.iri(auth['@id'], 'authorizationId')
        : `_:auth${index}`;
      const predicates: string[] = ['a acl:Authorization'];
      getStringField(auth, 'accessTo').forEach(value =>
        predicates.push(`acl:accessTo ${this.iri(value, 'accessTo')}`)
      );
      getStringField(auth, 'agent').forEach(value =>
        predicates.push(`acl:agent ${this.iri(value, 'agent')}`)
      );
      getStringField(auth, 'agentClass').forEach(value =>
        predicates.push(`acl:agentClass ${this.iri(value, 'agentClass')}`)
      );
      getStringField(auth, 'agentGroup').forEach(value =>
        predicates.push(`acl:agentGroup ${this.iri(value, 'agentGroup')}`)
      );
      values(auth.mode).forEach(mode => predicates.push(`acl:mode <${ACL}${mode}>`));
      lines.push(`${subject} ${predicates.join(' ;\n  ')} .`, '');
    });
    return lines.join('\n');
  }

  private serializeAcpPolicy(policy: AcpPolicy): string {
    const lines = [`@prefix acp: <${ACP}> .`, ''];
    const serializeRule = (rule: AcpAllowRule | AcpDenyRule): string => {
      const predicates: string[] = [];
      getStringField(rule, 'actor').forEach(value =>
        predicates.push(`acp:actor ${this.iri(value, 'actor')}`)
      );
      getStringField(rule, 'actorClass').forEach(value =>
        predicates.push(`acp:actorClass ${this.iri(value, 'actorClass')}`)
      );
      getStringField(rule, 'actorGroup').forEach(value =>
        predicates.push(`acp:actorGroup ${this.iri(value, 'actorGroup')}`)
      );
      values(rule.operation).forEach(operation =>
        predicates.push(`acp:operation <${ACP}${operation}>`)
      );
      return `[ ${predicates.join(' ; ')} ]`;
    };
    const predicates = [`a acp:AccessPolicy`, `acp:appliesTo ${this.iri(policy.appliesTo, 'appliesTo')}`];
    (policy.allow ?? []).forEach(rule => predicates.push(`acp:allow ${serializeRule(rule)}`));
    (policy.deny ?? []).forEach(rule => predicates.push(`acp:deny ${serializeRule(rule)}`));
    lines.push(`<> ${predicates.join(' ;\n  ')} .`, '');
    return lines.join('\n');
  }

  private parseWacPolicy(turtle: string, policyUri: ResourceUri): WacPolicy {
    const authorization: WacAuthorization[] = [];
    const blocks = turtle.split(/\.\s*(?:\r?\n|$)/);
    for (const block of blocks) {
      if (!block.includes('acl:Authorization') && !block.includes(`${ACL}Authorization`)) continue;
      const subject = block.match(/(?:<([^>]+)>|(_:[A-Za-z][\w-]*))\s+/);
      const accessTo = [...block.matchAll(/acl:accessTo\s+<([^>]+)>/g)].map(m => m[1]!);
      const agent = [...block.matchAll(/acl:agent\s+<([^>]+)>/g)].map(m => m[1]!);
      const agentClass = [...block.matchAll(/acl:agentClass\s+<([^>]+)>/g)].map(m => m[1]!);
      const agentGroup = [...block.matchAll(/acl:agentGroup\s+<([^>]+)>/g)].map(m => m[1]!);
      const mode = [...block.matchAll(/acl:mode\s+<[^>]+#(Read|Write|Control|Append)>/g)].map(
        m => m[1] as WacMode
      );
      if (accessTo.length === 0 || mode.length === 0) continue;
      authorization.push({
        ...(subject?.[1] !== undefined && { '@id': subject[1] }),
        type: 'Authorization',
        accessTo: accessTo[0]!,
        ...(agent.length > 0 && { agent: agent.length === 1 ? agent[0]! : agent }),
        ...(agentClass.length > 0 && {
          agentClass: agentClass.length === 1 ? agentClass[0]! : agentClass,
        }),
        ...(agentGroup.length > 0 && {
          agentGroup: agentGroup.length === 1 ? agentGroup[0]! : agentGroup,
        }),
        mode: mode.length === 1 ? mode[0]! : mode,
      });
    }
    return { '@id': policyUri, authorization };
  }

  private parseAcpPolicy(turtle: string, policyUri: ResourceUri): AcpPolicy {
    const appliesTo = turtle.match(/acp:appliesTo\s+<([^>]+)>/)?.[1] ?? '';
    const parseRules = (predicate: 'allow' | 'deny') =>
      [...turtle.matchAll(new RegExp(`acp:${predicate}\\s+\\[([^\\]]+)\\]`, 'g'))].map(
        match => {
          const body = match[1] ?? '';
          const actor = [...body.matchAll(/acp:actor\s+<([^>]+)>/g)].map(m => m[1]!);
          const actorClass = [...body.matchAll(/acp:actorClass\s+<([^>]+)>/g)].map(m => m[1]!);
          const actorGroup = [...body.matchAll(/acp:actorGroup\s+<([^>]+)>/g)].map(m => m[1]!);
          const operation = [...body.matchAll(/acp:operation\s+<[^>]+#(Read|Write|Control|Append|Create|Delete)>/g)].map(
            m => m[1] as AcpOperation
          );
          return {
            type: predicate,
            ...(actor.length > 0 && { actor: actor.length === 1 ? actor[0]! : actor }),
            ...(actorClass.length > 0 && {
              actorClass: actorClass.length === 1 ? actorClass[0]! : actorClass,
            }),
            ...(actorGroup.length > 0 && {
              actorGroup: actorGroup.length === 1 ? actorGroup[0]! : actorGroup,
            }),
            operation: operation.length === 1 ? operation[0]! : operation,
          };
        }
      );
    return {
      '@id': policyUri,
      appliesTo,
      allow: parseRules('allow') as AcpAllowRule[],
      deny: parseRules('deny') as AcpDenyRule[],
    };
  }

  public getResourceClient(): ResourceClient {
    return this.resourceClient;
  }

  public getConfig(): ResolvedPolicyClientConfig {
    return { ...this.config };
  }
}

export default PolicyClient;
