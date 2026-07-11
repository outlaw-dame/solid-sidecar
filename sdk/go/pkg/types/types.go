// Package types defines the core data structures for the Solid Sidecar Go SDK.
//
// Phase 27 - SDK/Client Compatibility Layer
// Status: STABLE - Production Ready
package types

import (
	"time"
)

// Resource represents a Solid resource with metadata.
// This is the core struct for all resource operations.
type Resource struct {
	// URI is the full URI of the resource
	URI string `json:"uri"`

	// ContentType is the MIME type of the resource
	ContentType string `json:"contentType,omitempty"`

	// Body contains the resource content
	Body []byte `json:"body,omitempty"`

	// ETag is the entity tag for optimistic concurrency control
	ETag string `json:"etag,omitempty"`

	// LastModified is the last modification timestamp
	LastModified time.Time `json:"lastModified,omitempty"`

	// Links contains Link headers from the resource
	Links map[string]string `json:"links,omitempty"`

	// ContainerURI is the URI of the containing container (if applicable)
	ContainerURI string `json:"containerUri,omitempty"`

	// IsContainer indicates if this resource is a container
	IsContainer bool `json:"isContainer,omitempty"`
}

// StorageResource represents a resource in the storage layer.
type StorageResource struct {
	URI         string            `json:"uri"`
	ContentType string            `json:"contentType,omitempty"`
	Body        []byte            `json:"body,omitempty"`
	ETag        string            `json:"etag,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// WritePreconditions defines preconditions for conditional writes.
type WritePreconditions struct {
	// IfMatch contains ETags that must match for the operation to succeed
	IfMatch []string `json:"ifMatch,omitempty"`

	// IfNoneMatch contains ETags that must NOT match, or "*" for create-only
	IfNoneMatch []string `json:"ifNoneMatch,omitempty"`
}

// WriteResult contains the result of a write operation.
type WriteResult struct {
	// ETag is the new ETag of the resource
	ETag string `json:"etag,omitempty"`

	// LastModified is the new last modification timestamp
	LastModified time.Time `json:"lastModified,omitempty"`

	// Created indicates if the resource was created (vs updated)
	Created bool `json:"created,omitempty"`

	// StatusCode is the HTTP status code returned
	StatusCode int `json:"statusCode,omitempty"`

	// Location is the Location header value (for 201 Created)
	Location string `json:"location,omitempty"`
}

// ListResponse contains the result of listing a container.
type ListResponse struct {
	// Resources contains the URIs of resources in the container
	Resources []string `json:"resources,omitempty"`

	// Containers contains the URIs of sub-containers
	Containers []string `json:"containers,omitempty"`

	// ETag is the ETag of the container itself
	ETag string `json:"etag,omitempty"`

	// LastModified is the last modification timestamp of the container
	LastModified time.Time `json:"lastModified,omitempty"`
}

// ErrorResponse contains error information from the server.
type ErrorResponse struct {
	// Code is the error code
	Code string `json:"code,omitempty"`

	// Message is the human-readable error message
	Message string `json:"message,omitempty"`

	// Details contains additional error details
	Details map[string]interface{} `json:"details,omitempty"`

	// StatusCode is the HTTP status code
	StatusCode int `json:"statusCode,omitempty"`
}

// PolicyResourceType defines the type of policy resource.
type PolicyResourceType string

const (
	// WAC is Web Access Control
	WAC PolicyResourceType = "wac"

	// ACP is Access Control Policy
	ACP PolicyResourceType = "acp"

	// SAI is Solid Application Interoperability
	SAI PolicyResourceType = "sai"
)

// AccessMode defines the access mode for policy rules.
type AccessMode string

const (
	// Read access mode
	Read AccessMode = "Read"

	// Write access mode
	Write AccessMode = "Write"

	// Append access mode
	Append AccessMode = "Append"

	// Control access mode (for containers)
	Control AccessMode = "Control"
)

// AgentType defines the type of agent in policy rules.
type AgentType string

const (
	// AgentTypeAgent is a specific agent
	AgentTypeAgent AgentType = "Agent"

	// AgentTypeGroup is a group of agents
	AgentTypeGroup AgentType = "Group"

	// AgentTypePublic is the public (everyone)
	AgentTypePublic AgentType = "Public"
)

// PolicyRule represents a single policy rule.
type PolicyRule struct {
	// AccessMode is the access mode granted
	AccessMode AccessMode `json:"accessMode"`

	// Agent is the agent (WebID) to which this rule applies
	Agent string `json:"agent,omitempty"`

	// AgentType is the type of agent
	AgentType AgentType `json:"agentType,omitempty"`

	// Resource is the resource URI this rule applies to
	Resource string `json:"resource,omitempty"`

	// ResourceClass is the class of resources this rule applies to
	ResourceClass string `json:"resourceClass,omitempty"`

	// DefaultForNew indicates if this is a default rule for new resources
	DefaultForNew bool `json:"defaultForNew,omitempty"`
}

// Policy represents a collection of policy rules.
type Policy struct {
	// Type is the policy type (wac, acp, sai)
	Type PolicyResourceType `json:"type"`

	// Rules contains the policy rules
	Rules []PolicyRule `json:"rules,omitempty"`

	// Owner is the owner of the policy
	Owner string `json:"owner,omitempty"`

	// URI is the URI of the policy resource
	URI string `json:"uri,omitempty"`

	// ETag is the ETag of the policy resource
	ETag string `json:"etag,omitempty"`
}

// EventType defines the type of notification event.
type EventType string

const (
	// EventTypeCreate indicates a resource was created
	EventTypeCreate EventType = "create"

	// EventTypeUpdate indicates a resource was updated
	EventTypeUpdate EventType = "update"

	// EventTypeDelete indicates a resource was deleted
	EventTypeDelete EventType = "delete"
)

// Event represents a Solid notification event.
type Event struct {
	// ID is the unique event identifier
	ID string `json:"id"`

	// Type is the event type
	Type EventType `json:"type"`

	// ResourceURI is the URI of the affected resource
	ResourceURI string `json:"resourceUri"`

	// ContainerURI is the URI of the containing container
	ContainerURI string `json:"containerUri,omitempty"`

	// Timestamp is when the event occurred
	Timestamp time.Time `json:"timestamp"`

	// Agent is the WebID of the agent that caused the event
	Agent string `json:"agent,omitempty"`

	// ETag is the ETag of the resource after the event
	ETag string `json:"etag,omitempty"`

	// Sequence is the sequence number for ordering
	Sequence int64 `json:"sequence,omitempty"`

	// Metadata contains additional event metadata
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Subscription represents a notification subscription.
type Subscription struct {
	// ID is the subscription identifier
	ID string `json:"id"`

	// ResourceURI is the URI being subscribed to
	ResourceURI string `json:"resourceUri"`

	// CallbackURL is the URL to send notifications to
	CallbackURL string `json:"callbackUrl,omitempty"`

	// ChannelType is the type of notification channel (sse, websocket, etc.)
	ChannelType string `json:"channelType"`

	// LastEventID is the last event ID received
	LastEventID string `json:"lastEventId,omitempty"`

	// Created is when the subscription was created
	Created time.Time `json:"created"`

	// Expires is when the subscription expires
	Expires time.Time `json:"expires,omitempty"`
}

// RDFFormat defines supported RDF formats.
type RDFFormat string

const (
	// Turtle format
	Turtle RDFFormat = "text/turtle"

	// JSONLD format
	JSONLD RDFFormat = "application/ld+json"

	// NTriples format
	NTriples RDFFormat = "application/n-triples"

	// RDFXML format
	RDFXML RDFFormat = "application/rdf+xml"
)

// RDFTriple represents a single RDF triple.
type RDFTriple struct {
	Subject         string `json:"subject"`
	Predicate       string `json:"predicate"`
	Object          string `json:"object"`
	ObjectType      string `json:"objectType,omitempty"` // "literal", "uri", "blank"
	LiteralDatatype string `json:"literalDatatype,omitempty"`
	LiteralLanguage string `json:"literalLanguage,omitempty"`
}

// RDFDataset represents a collection of RDF triples.
type RDFDataset struct {
	// Triples contains all the triples in the dataset
	Triples []RDFTriple `json:"triples,omitempty"`

	// Graphs contains named graphs (optional)
	Graphs map[string][]RDFTriple `json:"graphs,omitempty"`

	// BaseURI is the base URI for relative URIs
	BaseURI string `json:"baseUri,omitempty"`

	// Prefixes contains namespace prefixes
	Prefixes map[string]string `json:"prefixes,omitempty"`
}

// HTTPHeaders represents HTTP headers.
type HTTPHeaders map[string]string

// DPoPProof represents a DPoP proof JWT.
type DPoPProof struct {
	// JWT is the signed JWT string
	JWT string `json:"jwt"`

	// Header contains the JOSE header
	Header map[string]interface{} `json:"header,omitempty"`

	// Claims contains the JWT claims
	Claims map[string]interface{} `json:"claims,omitempty"`

	// KeyID is the key identifier used for signing
	KeyID string `json:"kid,omitempty"`

	// Algorithm is the signing algorithm
	Algorithm string `json:"alg,omitempty"`
}

// TokenResponse represents an OAuth2 token response.
type TokenResponse struct {
	// AccessToken is the access token
	AccessToken string `json:"access_token"`

	// TokenType is the token type (should be "DPoP" or "Bearer")
	TokenType string `json:"token_type"`

	// ExpiresIn is the lifetime in seconds
	ExpiresIn int64 `json:"expires_in"`

	// RefreshToken is the refresh token (optional)
	RefreshToken string `json:"refresh_token,omitempty"`

	// Scope is the granted scope
	Scope string `json:"scope,omitempty"`

	// IssuedAt is when the token was issued
	IssuedAt time.Time `json:"issued_at,omitempty"`

	// DPoPKey is the DPoP key thumbprint (for DPoP-bound tokens)
	DPoPKey string `json:"dpop_key,omitempty"`
}

// RequestOptions contains options for HTTP requests.
type RequestOptions struct {
	// Headers contains additional HTTP headers
	Headers HTTPHeaders `json:"headers,omitempty"`

	// Timeout is the request timeout
	Timeout time.Duration `json:"timeout,omitempty"`

	// MaxRetries is the maximum number of retries
	MaxRetries int `json:"maxRetries,omitempty"`

	// RetryDelay is the base delay between retries
	RetryDelay time.Duration `json:"retryDelay,omitempty"`

	// MaxRetryDelay is the maximum delay between retries
	MaxRetryDelay time.Duration `json:"maxRetryDelay,omitempty"`

	// FollowRedirects indicates if redirects should be followed
	FollowRedirects bool `json:"followRedirects,omitempty"`
}

// PaginationOptions contains options for paginated requests.
type PaginationOptions struct {
	// Limit is the maximum number of items to return
	Limit int `json:"limit,omitempty"`

	// Offset is the starting offset
	Offset int `json:"offset,omitempty"`

	// Cursor is the pagination cursor
	Cursor string `json:"cursor,omitempty"`

	// PageToken is the page token for next page
	PageToken string `json:"pageToken,omitempty"`
}

// SyncOptions contains options for sync operations.
type SyncOptions struct {
	// Strategy defines the conflict resolution strategy
	Strategy SyncConflictStrategy `json:"strategy,omitempty"`

	// BatchSize is the number of operations per batch
	BatchSize int `json:"batchSize,omitempty"`

	// MaxRetries is the maximum number of retries per operation
	MaxRetries int `json:"maxRetries,omitempty"`

	// RetryDelay is the base delay between retries
	RetryDelay time.Duration `json:"retryDelay,omitempty"`

	// IncludeDeletes indicates if deletions should be synced
	IncludeDeletes bool `json:"includeDeletes,omitempty"`

	// FullResync indicates if a full resync should be performed
	FullResync bool `json:"fullResync,omitempty"`
}

// SyncConflictStrategy defines how to handle sync conflicts.
type SyncConflictStrategy string

const (
	// ServerWins always takes the server version
	ServerWins SyncConflictStrategy = "server_wins"

	// ClientWins always takes the client version
	ClientWins SyncConflictStrategy = "client_wins"

	// LatestWins takes the latest version based on Last-Modified
	LatestWins SyncConflictStrategy = "latest_wins"

	// Manual requires manual resolution
	Manual SyncConflictStrategy = "manual"

	// Merge attempts to merge changes (for RDF resources)
	Merge SyncConflictStrategy = "merge"
)

// SyncState represents the state of a sync operation.
type SyncState struct {
	// Synced indicates if the resource is in sync
	Synced bool `json:"synced"`

	// LocalETag is the local ETag
	LocalETag string `json:"localEtag,omitempty"`

	// ServerETag is the server ETag
	ServerETag string `json:"serverEtag,omitempty"`

	// Conflict indicates if there is a conflict
	Conflict bool `json:"conflict,omitempty"`

	// LastSynced is when the resource was last synced
	LastSynced time.Time `json:"lastSynced,omitempty"`

	// PendingChanges indicates if there are local changes not yet synced
	PendingChanges bool `json:"pendingChanges,omitempty"`

	// Error contains the last sync error (if any)
	Error string `json:"error,omitempty"`
}

// HealthStatus represents the health status of a service.
type HealthStatus struct {
	// Status is the overall status
	Status string `json:"status"`

	// Details contains component-specific health information
	Details map[string]interface{} `json:"details,omitempty"`

	// Timestamp is when the health check was performed
	Timestamp time.Time `json:"timestamp"`
}
