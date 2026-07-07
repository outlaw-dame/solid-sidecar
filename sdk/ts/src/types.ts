/**
 * Solid Sidecar TypeScript SDK - Types
 * Phase: 27 - SDK/Client Compatibility Layer
 * Version: v1.0.0
 * Created: 2026-07-07
 * Author: Mistral Vibe
 * License: MIT
 *
 * This file contains all TypeScript types and interfaces for the SDK.
 */

// ============================================================================
// Core Types
// ============================================================================

/**
 * Solid Sidecar configuration options
 */
export interface SolidSidecarConfig {
  /** Base URL of the Solid Sidecar instance */
  baseUrl: string;
  
  /** Timeout for HTTP requests in milliseconds */
  timeout?: number;
  
  /** Maximum number of retries for failed requests */
  maxRetries?: number;
  
  /** Base delay for exponential backoff in milliseconds */
  retryDelay?: number;
  
  /** Maximum delay for exponential backoff in milliseconds */
  maxRetryDelay?: number;
  
  /** Custom fetch implementation (for testing or browser environments) */
  fetch?: typeof fetch;
  
  /** Whether to validate SSL certificates (default: true) */
  validateSsl?: boolean;
  
  /** Custom logger for SDK events */
  logger?: SolidSidecarLogger;
}

/**
 * Logger interface for SDK events
 */
export interface SolidSidecarLogger {
  /** Log debug messages */
  debug: (message: string, ...args: unknown[]) => void;
  /** Log info messages */
  info: (message: string, ...args: unknown[]) => void;
  /** Log warning messages */
  warn: (message: string, ...args: unknown[]) => void;
  /** Log error messages */
  error: (message: string, ...args: unknown[]) => void;
}

// ============================================================================
// Authentication Types
// ============================================================================

/**
 * DPoP key pair for signing proofs
 */
export interface DpopKeyPair {
  /** Private key in JWK format */
  privateKey: JsonWebKey;
  /** Public key in JWK format */
  publicKey: JsonWebKey;
  /** Key identifier */
  kid?: string;
  /** Creation timestamp */
  createdAt: number;
}

/**
 * DPoP proof generation options
 */
export interface DpopProofOptions {
  /** HTTP method for the request */
  method: HttpMethod;
  /** URL for the request (without query parameters) */
  url: string;
  /** Unique nonce for this proof */
  jti?: string;
  /** Issued-at timestamp (Unix epoch in seconds) */
  iat?: number;
  /** Access token to bind (for ath claim) */
  accessToken?: string;
}

/**
 * DPoP proof result
 */
export interface DpopProof {
  /** The complete DPoP proof JWT */
  jwt: string;
  /** The JWT header */
  header: DpopHeader;
  /** The JWT claims */
  claims: DpopClaims;
  /** The JWT signature */
  signature: string;
}

/**
 * DPoP JWT header
 */
export interface DpopHeader {
  /** Token type - must be 'dpop+jwt' */
  typ: string;
  /** Algorithm used for signing */
  alg: string;
  /** Public key in JWK format */
  jwk: JsonWebKey;
}

/**
 * DPoP JWT claims
 */
export interface DpopClaims {
  /** HTTP method */
  htm: HttpMethod;
  /** HTTP URL */
  htu: string;
  /** Unique nonce */
  jti: string;
  /** Issued-at timestamp */
  iat: number;
  /** Access token hash (SHA-256, base64url) */
  ath?: string;
}

/**
 * Token response from OIDC issuer
 */
export interface TokenResponse {
  /** Access token */
  access_token: string;
  /** Token type (usually 'Bearer' or 'DPoP') */
  token_type: string;
  /** Access token expiration in seconds */
  expires_in: number;
  /** Refresh token (optional) */
  refresh_token?: string;
  /** Scope granted */
  scope?: string;
  /** Issued-at timestamp */
  issued_at?: number;
}

/**
 * Token set with additional metadata
 */
export interface TokenSet extends TokenResponse {
  /** Expiration timestamp (Unix epoch in milliseconds) */
  expires_at: number;
  /** Issued-at timestamp (Unix epoch in milliseconds) */
  issued_at: number;
  /** DPoP key pair used for this token */
  dpopKeyPair?: DpopKeyPair;
}

/**
 * PKCE code verifier and challenge
 */
export interface PkcePair {
  /** Code verifier (43-128 characters) */
  codeVerifier: string;
  /** Code challenge (base64url(sha256(codeVerifier))) */
  codeChallenge: string;
  /** Method for code challenge (S256 or plain) */
  codeChallengeMethod: 'S256' | 'plain';
}

// ============================================================================
// HTTP Types
// ============================================================================

/** HTTP methods */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';

/** HTTP status codes */
export type HttpStatusCode = number;

/** HTTP headers */
export interface HttpHeaders {
  [key: string]: string;
}

/** HTTP request options */
export interface HttpRequestOptions {
  /** HTTP method */
  method: HttpMethod;
  /** Request URL */
  url: string;
  /** Request headers */
  headers?: HttpHeaders;
  /** Request body */
  body?: string | Uint8Array | ReadableStream<Uint8Array> | null;
  /** Timeout in milliseconds */
  timeout?: number;
}

/** HTTP response */
export interface HttpResponse<T = unknown> {
  /** HTTP status code */
  status: HttpStatusCode;
  /** Response headers */
  headers: HttpHeaders;
  /** Response body */
  body: T;
  /** Raw response (for debugging) */
  raw?: Response;
}

/** Error response from API */
export interface ApiError {
  /** Error code */
  code: string;
  /** Error message */
  message: string;
  /** Error details */
  details?: Record<string, unknown>;
  /** HTTP status code */
  statusCode: HttpStatusCode;
  /** Request ID for correlation */
  requestId?: string;
}

// ============================================================================
// Resource Types
// ============================================================================

/** Resource URI */
export type ResourceUri = string;

/** Container URI */
export type ContainerUri = ResourceUri;

/** Resource metadata */
export interface ResourceMetadata {
  /** Resource URI */
  uri: ResourceUri;
  /** Content type */
  contentType?: string;
  /** Content length in bytes */
  contentLength?: number;
  /** ETag for optimistic concurrency control */
  etag?: string;
  /** Last modified timestamp (RFC 1123) */
  lastModified?: string;
  /** Last modified timestamp (Unix epoch in milliseconds) */
  lastModifiedAt?: number;
  /** Link headers (RDF types, etc.) */
  links?: Link[];
  /** Whether the resource exists */
  exists: boolean;
}

/** Link header representation */
export interface Link {
  /** Link URI */
  uri: string;
  /** Link relation */
  rel: string;
}

/** Resource content */
export interface Resource {
  /** Resource URI */
  uri: ResourceUri;
  /** Resource metadata */
  metadata: ResourceMetadata;
  /** Resource content as string */
  content: string;
}

/** Container listing result */
export interface ContainerListing {
  /** Container URI */
  containerUri: ContainerUri;
  /** List of resources in the container */
  resources: ResourceUri[];
  /** List of subcontainers */
  containers: ContainerUri[];
  /** Metadata about the listing */
  metadata: ResourceMetadata;
}

/** Conditional write options */
export interface ConditionalWriteOptions {
  /** If-Match ETag - only write if resource matches this ETag */
  ifMatch?: string | string[];
  /** If-None-Match ETag - only write if resource doesn't match this ETag */
  ifNoneMatch?: string | string[];
}

// ============================================================================
// Policy Types
// ============================================================================

/** Access control model */
export type AccessControlModel = 'wac' | 'acp' | 'sai';

/** WAC access mode */
export type WacMode = 'Read' | 'Write' | 'Control' | 'Append';

/** WAC agent types */
export type WacAgentType = 'agent' | 'agentClass' | 'agentGroup';

/** WAC authorization */
export interface WacAuthorization {
  /** Authorization URI */
  '@id'?: string;
  /** Type */
  type: 'Authorization';
  /** Resource this authorization applies to */
  accessTo: ResourceUri;
  /** Agent (WebID, class, or group) */
  [agentType: string]: string | string[];
  /** Access modes granted */
  mode: WacMode | WacMode[];
}

/** WAC policy */
export interface WacPolicy {
  /** Policy URI */
  '@id'?: string;
  /** List of authorizations */
  authorization: WacAuthorization[];
}

/** ACP operation */
export type AcpOperation = 'Read' | 'Write' | 'Control' | 'Append' | 'Create' | 'Delete';

/** ACP actor types */
export type AcpActorType = 'actor' | 'actorClass' | 'actorGroup';

/** ACP access rule (allow or deny) */
export interface AcpAccessRule {
  /** List of actors this rule applies to */
  [actorType: string]: string | string[];
  /** Operations allowed or denied */
  operation: AcpOperation | AcpOperation[];
}

/** ACP allow rule */
export interface AcpAllowRule extends AcpAccessRule {
  /** Rule type */
  type: 'allow';
}

/** ACP deny rule */
export interface AcpDenyRule extends AcpAccessRule {
  /** Rule type */
  type: 'deny';
}

/** ACP policy */
export interface AcpPolicy {
  /** Policy URI */
  '@id'?: string;
  /** Resource this policy applies to */
  appliesTo: ResourceUri;
  /** List of allow rules */
  allow?: AcpAllowRule[];
  /** List of deny rules */
  deny?: AcpDenyRule[];
}

/** Policy resource */
export interface PolicyResource {
  /** Policy URI */
  uri: ResourceUri;
  /** Access control model */
  model: AccessControlModel;
  /** Policy content */
  policy: WacPolicy | AcpPolicy;
  /** Policy as RDF/Turtle string */
  turtle?: string;
  /** Policy as JSON-LD string */
  jsonLd?: string;
}

// ============================================================================
// Notification Types
// ============================================================================

/** Notification event types */
export type NotificationEventType =
  | 'ResourceCreated'
  | 'ResourceUpdated'
  | 'ResourceDeleted'
  | 'ContainerCreated'
  | 'ContainerUpdated'
  | 'ContainerDeleted'
  | 'PolicyCreated'
  | 'PolicyUpdated'
  | 'PolicyDeleted';

/** Notification event */
export interface NotificationEvent {
  /** Unique event identifier */
  id: string;
  /** Event type */
  type: NotificationEventType;
  /** Resource URI that was affected */
  resource: ResourceUri;
  /** Container URI that contains the resource */
  container?: ContainerUri;
  /** Timestamp of the event (ISO 8601) */
  timestamp: string;
  /** WebID of the agent that caused the change */
  agent?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
  /** Sequence number for ordering */
  sequence?: number;
}

/** Notification subscription options */
export interface NotificationSubscriptionOptions {
  /** Resource or container URI to subscribe to */
  resourceUri: ResourceUri | ContainerUri;
  /** Last event ID to resume from */
  cursor?: string;
  /** Maximum number of events to receive */
  maxEvents?: number;
  /** Timeout in milliseconds */
  timeout?: number;
  /** Callback for events */
  onEvent?: (event: NotificationEvent) => void;
  /** Callback for errors */
  onError?: (error: Error) => void;
  /** Callback for connection close */
  onClose?: () => void;
}

/** Notification subscription */
export interface NotificationSubscription {
  /** Subscription ID */
  id: string;
  /** Resource being subscribed to */
  resourceUri: ResourceUri | ContainerUri;
  /** Whether the subscription is active */
  isActive: boolean;
  /** Close the subscription */
  close: () => Promise<void>;
  /** Resume the subscription from a cursor */
  resume: (cursor: string) => Promise<void>;
}

// ============================================================================
// RDF Types
// ============================================================================

/** RDF format */
export type RdfFormat = 'text/turtle' | 'application/ld+json' | 'application/n-triples' | 'application/rdf+xml';

/** RDF quad */
export interface RdfQuad {
  /** Subject */
  subject: string;
  /** Predicate */
  predicate: string;
  /** Object */
  object: string;
  /** Graph (optional) */
  graph?: string;
}

/** RDF dataset */
export interface RdfDataset {
  /** List of quads */
  quads: RdfQuad[];
  /** Formats available */
  formats: RdfFormat[];
}

/** RDF parser/serializer interface */
export interface RdfCodec {
  /** Parse RDF from string */
  parse: (input: string, format: RdfFormat) => RdfDataset;
  /** Serialize RDF dataset to string */
  serialize: (dataset: RdfDataset, format: RdfFormat) => string;
  /** Parse and canonicalize RDF */
  parseCanonical: (input: string, format: RdfFormat) => string;
}

// ============================================================================
// Error Types
// ============================================================================

/** Base error class for SDK errors */
export class SolidSidecarError extends Error {
  /** Error code */
  public readonly code: string;
  /** HTTP status code */
  public readonly statusCode?: HttpStatusCode;
  /** Request ID for correlation */
  public readonly requestId?: string;
  /** Underlying error */
  public readonly cause?: Error;

  constructor(
    message: string,
    options: {
      code: string;
      statusCode?: HttpStatusCode;
      requestId?: string;
      cause?: Error;
    }
  ) {
    super(message);
    this.name = this.constructor.name;
    this.code = options.code;
    this.statusCode = options.statusCode;
    this.requestId = options.requestId;
    this.cause = options.cause;

    // Maintain proper stack trace for custom errors
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

/** Authentication error */
export class AuthenticationError extends SolidSidecarError {
  constructor(
    message: string,
    options: Omit<ConstructorParameters<typeof SolidSidecarError>[1], 'code'> = {}
  ) {
    super(message, { code: 'AUTHENTICATION_ERROR', ...options });
  }
}

/** Authorization error */
export class AuthorizationError extends SolidSidecarError {
  constructor(
    message: string,
    options: Omit<ConstructorParameters<typeof SolidSidecarError>[1], 'code'> = {}
  ) {
    super(message, { code: 'AUTHORIZATION_ERROR', ...options });
  }
}

/** Network error */
export class NetworkError extends SolidSidecarError {
  constructor(
    message: string,
    options: Omit<ConstructorParameters<typeof SolidSidecarError>[1], 'code'> = {}
  ) {
    super(message, { code: 'NETWORK_ERROR', ...options });
  }
}

/** Resource not found error */
export class ResourceNotFoundError extends SolidSidecarError {
  public readonly uri: ResourceUri;

  constructor(
    message: string,
    uri: ResourceUri,
    options: Omit<ConstructorParameters<typeof SolidSidecarError>[1], 'code'> = {}
  ) {
    super(message, { code: 'RESOURCE_NOT_FOUND', ...options });
    this.uri = uri;
  }
}

/** Conflict error (e.g., conditional write failed) */
export class ConflictError extends SolidSidecarError {
  public readonly etag?: string;

  constructor(
    message: string,
    etag?: string,
    options: Omit<ConstructorParameters<typeof SolidSidecarError>[1], 'code'> = {}
  ) {
    super(message, { code: 'CONFLICT', ...options });
    this.etag = etag;
  }
}

/** Rate limit error */
export class RateLimitError extends SolidSidecarError {
  public readonly retryAfter?: number;

  constructor(
    message: string,
    retryAfter?: number,
    options: Omit<ConstructorParameters<typeof SolidSidecarError>[1], 'code'> = {}
  ) {
    super(message, { code: 'RATE_LIMIT', ...options });
    this.retryAfter = retryAfter;
  }
}

/** Validation error */
export class ValidationError extends SolidSidecarError {
  public readonly field?: string;

  constructor(
    message: string,
    field?: string,
    options: Omit<ConstructorParameters<typeof SolidSidecarError>[1], 'code'> = {}
  ) {
    super(message, { code: 'VALIDATION_ERROR', ...options });
    this.field = field;
  }
}

/** Precondition failed error */
export class PreconditionFailedError extends SolidSidecarError {
  public readonly expectedEtag?: string;
  public readonly actualEtag?: string;

  constructor(
    message: string,
    expectedEtag?: string,
    actualEtag?: string,
    options: Omit<ConstructorParameters<typeof SolidSidecarError>[1], 'code'> = {}
  ) {
    super(message, { code: 'PRECONDITION_FAILED', ...options });
    this.expectedEtag = expectedEtag;
    this.actualEtag = actualEtag;
  }
}

// ============================================================================
// JSON Web Key types (subset used by DPoP)
// ============================================================================

/** JSON Web Key */
export interface JsonWebKey {
  /** Key type */
  kty: 'EC' | 'RSA' | 'OKP';
  /** Key usage */
  use?: 'sig' | 'enc';
  /** Key operations */
  key_ops?: string[];
  /** Algorithm */
  alg?: string;
  /** Key ID */
  kid?: string;
  /** X coordinate (EC) */
  x?: string;
  /** Y coordinate (EC) */
  y?: string;
  /** Curve (EC) */
  crv?: string;
  /** Modulus (RSA) */
  n?: string;
  /** Exponent (RSA) */
  e?: string;
  /** Public exponent (RSA) */
  d?: string;
  /** Prime factor (RSA) */
  p?: string;
  /** Prime factor (RSA) */
  q?: string;
  /** X coordinate (Ed25519) */
  x5c?: string[];
}

// ============================================================================
// Utility Types
// ============================================================================

/** Pagination options */
export interface PaginationOptions {
  /** Page number (1-indexed) */
  page?: number;
  /** Items per page */
  pageSize?: number;
  /** Cursor for pagination */
  cursor?: string;
}

/** Sort options */
export interface SortOptions {
  /** Field to sort by */
  field: string;
  /** Sort direction */
  direction: 'asc' | 'desc';
}

/** Query options */
export interface QueryOptions {
  /** Pagination */
  pagination?: PaginationOptions;
  /** Sorting */
  sort?: SortOptions[];
  /** Filter criteria */
  filter?: Record<string, unknown>;
}

/** Result with pagination */
export interface PaginatedResult<T> {
  /** Results */
  results: T[];
  /** Total count */
  total: number;
  /** Current page */
  page: number;
  /** Items per page */
  pageSize: number;
  /** Next cursor */
  nextCursor?: string;
  /** Previous cursor */
  previousCursor?: string;
  /** Whether there are more results */
  hasMore: boolean;
}

/** Retry options for exponential backoff */
export interface RetryOptions {
  /** Maximum number of retries */
  maxRetries: number;
  /** Base delay in milliseconds */
  baseDelay: number;
  /** Maximum delay in milliseconds */
  maxDelay: number;
  /** Jitter factor (0-1) */
  jitterFactor: number;
  /** Whether to retry on 4xx errors */
  retryOn4xx?: boolean;
  /** Specific status codes to retry */
  retryableStatuses?: HttpStatusCode[];
}

/** Default retry options */
export const DEFAULT_RETRY_OPTIONS: Required<RetryOptions> = {
  maxRetries: 3,
  baseDelay: 1000,
  maxDelay: 30000,
  jitterFactor: 0.1,
  retryOn4xx: false,
  retryableStatuses: [429, 500, 502, 503, 504],
};
