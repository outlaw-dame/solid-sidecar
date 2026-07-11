# Solid Sidecar SDK - Client Contract

**Phase 27 - SDK/Client Compatibility Layer**  
**Status: STABLE - Production Ready - FULLY HARDENED**

This document defines the client contract for the Solid Sidecar Go SDK. It specifies the expected behavior, guarantees, and constraints for all SDK components.

---

## Table of Contents

1. [Overview](#overview)
2. [Authentication and Security](#authentication-and-security)
3. [Resource Operations](#resource-operations)
4. [Policy Operations](#policy-operations)
5. [Notification Operations](#notification-operations)
6. [WebID Operations](#webid-operations)
7. [Sync Operations](#sync-operations)
8. [RDF Operations](#rdf-operations)
9. [Error Handling](#error-handling)
10. [Security Guarantees](#security-guarantees)
11. [Compatibility Claims](#compatibility-claims)

---

## Overview

The Solid Sidecar Go SDK provides a client library for interacting with a Solid Sidecar instance. It is designed to be:

- **Secure**: All operations include security checks and follow best practices
- **Reliable**: Built-in retry logic with exponential backoff and jitter
- **Compatible**: Follows Solid protocol specifications
- **Thread-safe**: All client instances can be safely used concurrently
- **Well-documented**: Clear contract and examples

### Client Architecture

```
Native App
  ↓
Solid Sidecar Go SDK
  ├── HTTPClient (with DPoP, retry, SSRF protection)
  ├── ResourceClient (CRUD, conditional writes)
  ├── PolicyClient (WAC/ACP/SAI)
  ├── NotificationClient (SSE/WebSocket)
  ├── WebIDClient (discovery, profiles)
  ├── SyncClient (offline-first, conflict resolution)
  └── RDFCodec (Turtle/JSON-LD parsing/serialization)
  ↓
Solid Sidecar Gateway
  ↓
Community Solid Server
```

---

## Authentication and Security

### DPoP Authentication

The SDK supports DPoP (Demonstrating Proof-of-Possession) authentication as specified by [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449).

**Client Requirements:**
- Must provide a `dpopProofFunc` that generates valid DPoP proofs
- DPoP proof JWT must include:
  - `typ`: `dpop+jwt`
  - `jti`: Unique identifier for the proof
  - `htm`: HTTP method (GET, POST, etc.)
  - `htu`: HTTP URI (target URL)
  - `iat`: Issued at timestamp (current time)
  - `exp`: Expiration timestamp (short-lived, typically < 5 minutes)
  - `ath`: Access token hash (SHA-256 of the access token)

**SDK Guarantees:**
- DPoP proofs are sent in the `DPoP` header
- Access tokens are sent in the `Authorization: DPoP <token>` header
- Both headers are always sent together
- Proofs are regenerated for each request (not cached)

**Example:**
```go
// Create DPoP keystore
keystore, err := dpop_keystore.NewDPoPKeyStore()
if err != nil {
    // handle error
}

// Generate access token (from your auth flow)
accessToken := "your-access-token"

// Create HTTP client with DPoP
httpClient, _ := utils.NewHTTPClient("https://sidecar.example.com", nil)
httpClient.SetAccessToken(accessToken)
httpClient.SetDPoPProofFunc(func(method, url string) (string, error) {
    return keystore.GenerateProof(method, url, accessToken)
})
```

### SSRF Prevention

**SDK Guarantees:**
- All URLs are validated before requests are made
- Only `http` and `https` schemes are allowed
- URLs with credentials (user:pass@host) are rejected
- Private IP addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x, etc.) are blocked in production
- Localhost and 127.0.0.1 are allowed only in development mode
- IPv6 private ranges are also blocked

**Example of Blocked URLs:**
```
file:///etc/passwd           // Blocked: Invalid scheme
ftp://example.com           // Blocked: Invalid scheme
http://user:pass@example.com // Blocked: Credentials in URL
http://10.0.0.1/            // Blocked: Private IP
http://192.168.1.1/         // Blocked: Private IP
http://localhost/            // Allowed in development only
https://example.com/        // Allowed
```

### Input Validation

**SDK Guarantees:**
- All URIs are validated as proper URLs
- HTTP methods are validated (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
- Request body size is limited (default: 10MB)
- Response body size is limited (default: 10MB)
- Headers are validated and sanitized

---

## Resource Operations

### URI Construction

The SDK provides methods for constructing resource URIs following Solid conventions.

**Rules:**
- Resource URIs must be valid HTTP/HTTPS URLs
- Container URIs typically end with `/`
- Policy resource URIs use extensions: `.acl` (WAC), `.acp` (ACP), `.sai` (SAI)
- Fragment identifiers (`#`) are preserved in WebID URIs

**Example:**
```go
client, _ := clients.NewResourceClient("https://pod.example.com/", nil)

// Resource URIs
resourceURI := "https://pod.example.com/data/file.txt"
containerURI := "https://pod.example.com/data/"

// Policy URIs
wacURI := client.GetPolicyURI(resourceURI, types.WAC)  // "https://pod.example.com/data/file.txt.acl"
acpURI := client.GetPolicyURI(resourceURI, types.ACP)  // "https://pod.example.com/data/file.txt.acp"
```

### CRUD Operations

#### GET

Retrieves a resource from the server.

**Request:**
```
GET /{resource-path} HTTP/1.1
Host: pod.example.com
Accept: text/turtle, application/ld+json, */*
Authorization: DPoP {access-token}
DPoP: {dpop-proof}
```

**Response:**
- `200 OK`: Resource retrieved successfully
- `404 Not Found`: Resource does not exist
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Access denied

**SDK Method:**
```go
resource, err := client.Get(ctx, "https://pod.example.com/data/file.txt", nil)
```

#### HEAD

Retrieves resource metadata without the body.

**Request:**
```
HEAD /{resource-path} HTTP/1.1
Host: pod.example.com
Authorization: DPoP {access-token}
DPoP: {dpop-proof}
```

**Response:**
- `200 OK`: Resource exists, metadata in headers
- `404 Not Found`: Resource does not exist

**SDK Method:**
```go
resource, err := client.Head(ctx, "https://pod.example.com/data/file.txt", nil)
```

#### PUT

Creates or replaces a resource.

**Request:**
```
PUT /{resource-path} HTTP/1.1
Host: pod.example.com
Content-Type: text/turtle
If-Match: "etag-value"          // Optional: for conditional update
If-None-Match: "*"             // Optional: for create-only
Authorization: DPoP {access-token}
DPoP: {dpop-proof}

{resource-body}
```

**Response:**
- `201 Created`: Resource created
- `200 OK` or `204 No Content`: Resource updated
- `412 Precondition Failed`: Conditional write failed
- `409 Conflict`: Resource already exists (when using If-None-Match: *)

**SDK Method:**
```go
// Simple PUT
result, err := client.Put(ctx, uri, contentType, body, nil, nil)

// PUT with preconditions
preconditions := &types.WritePreconditions{
    IfMatch: []string{"current-etag"},
}
result, err := client.Put(ctx, uri, contentType, body, preconditions, nil)

// Create-only (fails if exists)
result, err := client.Create(ctx, uri, contentType, body, nil)
```

#### DELETE

Deletes a resource.

**Request:**
```
DELETE /{resource-path} HTTP/1.1
Host: pod.example.com
If-Match: "etag-value"          // Required for conditional delete
Authorization: DPoP {access-token}
DPoP: {dpop-proof}
```

**Response:**
- `200 OK` or `204 No Content`: Resource deleted
- `404 Not Found`: Resource does not exist
- `412 Precondition Failed`: ETag does not match

**SDK Method:**
```go
// Delete with precondition
err := client.Delete(ctx, uri, &types.WritePreconditions{
    IfMatch: []string{"current-etag"},
}, nil)

// Delete with ETag
err := client.DeleteConditional(ctx, uri, "current-etag", nil)
```

#### PATCH

Performs a partial update using SPARQL Update.

**Request:**
```
PATCH /{resource-path} HTTP/1.1
Host: pod.example.com
Content-Type: application/sparql-update
If-Match: "etag-value"          // Optional: for conditional patch
Authorization: DPoP {access-token}
DPoP: {dpop-proof}

{SPARQL-Update-query}
```

**SDK Method:**
```go
sparql := `PREFIX dc: <http://purl.org/dc/elements/1.1/>
DELETE { <> dc:title ?title }
INSERT { <> dc:title "New Title" }
WHERE { <> dc:title ?title }`

result, err := client.Patch(ctx, uri, sparql, preconditions, nil)
```

### Conditional Writes

The SDK implements Optimistic Concurrency Control (OCC) using ETags.

**Guarantees:**
- All write operations (PUT, DELETE, PATCH) support `If-Match` and `If-None-Match` headers
- `If-Match: "etag"`: Write succeeds only if current ETag matches
- `If-None-Match: "etag"`: Write succeeds only if current ETag does NOT match
- `If-None-Match: "*"`: Write succeeds only if resource does not exist (create-only)

**Error Handling:**
- `412 Precondition Failed`: Returned when conditions are not met
- SDK returns `utils.ErrPreconditionFailed` for 412 responses
- Resource clients return `ErrResourceModified` for DELETE conflicts

**Example:**
```go
// Get current ETag
resource, _ := client.Head(ctx, uri, nil)
currentETag := resource.ETag

// Update with condition
preconditions := &types.WritePreconditions{
    IfMatch: []string{currentETag},
}
result, err := client.Put(ctx, uri, contentType, newBody, preconditions, nil)

if err == utils.ErrPreconditionFailed {
    // Concurrent modification detected
    // Refresh and retry or notify user
}
```

### Container Operations

#### List Container

Lists the contents of a container.

**Request:**
```
GET /{container-path} HTTP/1.1
Host: pod.example.com
Accept: text/turtle
Authorization: DPoP {access-token}
DPoP: {dpop-proof}
```

**Response:**
- Body contains container listing in Turtle format
- Resources and sub-containers are identified by their types

**SDK Method:**
```go
response, err := client.List(ctx, "https://pod.example.com/data/", nil)
// response.Resources: list of resource URIs
// response.Containers: list of container URIs
```

#### Create Container

Creates a new container.

**SDK Method:**
```go
// Create a BasicContainer
result, err := client.CreateContainer(
    ctx,
    "https://pod.example.com/new-container/",
    "http://www.w3.org/ns/ldp#BasicContainer",
    nil,
)
```

---

## Policy Operations

### Policy Types

The SDK supports three policy formats:

1. **WAC (Web Access Control)**: Legacy format, Turtle-based
   - Extension: `.acl`
   - Content-Type: `text/turtle`

2. **ACP (Access Control Policy)**: Modern format, JSON-LD-based
   - Extension: `.acp`
   - Content-Type: `application/ld+json`

3. **SAI (Solid Application Interoperability)**: Application-level policies
   - Extension: `.sai`
   - Content-Type: `application/ld+json`

### Policy URI Construction

**SDK Method:**
```go
policyClient, _ := clients.NewPolicyClient("https://pod.example.com/", nil)

wacURI := policyClient.GetPolicyURI(resourceURI, types.WAC)  // .acl
acpURI := policyClient.GetPolicyURI(resourceURI, types.ACP)  // .acp
saiURI := policyClient.GetPolicyURI(resourceURI, types.SAI)  // .sai
```

### Retrieve Policy

**SDK Method:**
```go
policy, err := policyClient.Get(ctx, policyURI, nil)
// policy.Type: WAC, ACP, or SAI
// policy.Rules: list of PolicyRule
// policy.ETag: current ETag
```

### Create/Update Policy

**SDK Method:**
```go
// Create a policy
policy := &types.Policy{
    Type: types.ACP,
    Rules: []types.PolicyRule{
        {
            AccessMode: types.Read,
            Agent:      "https://user.example.com/profile#me",
            AgentType:  types.AgentTypeAgent,
        },
        {
            AccessMode: types.Write,
            Agent:      "https://user.example.com/profile#me",
            AgentType:  types.AgentTypeAgent,
        },
    },
}

// Put policy with conditional write
result, err := policyClient.Put(ctx, policyURI, policy, &types.WritePreconditions{
    IfNoneMatch: []string{"*"}, // Create only
}, nil)
```

### Add/Remove Rules

**SDK Methods:**
```go
// Add a rule to existing policy
newPolicy, err := policyClient.AddRule(
    ctx,
    policyURI,
    types.PolicyRule{
        AccessMode: types.Read,
        Agent:      "https://friend.example.com/profile#me",
        AgentType:  types.AgentTypeAgent,
    },
    currentETag,
    nil,
)

// Remove a rule by index
newPolicy, err := policyClient.RemoveRule(
    ctx,
    policyURI,
    ruleIndex,  // 0-based index
    currentETag,
    nil,
)
```

### Policy Serialization

**WAC (Turtle Format):**
```turtle
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<> acl:Authorization auth-1 ;
    acl:mode acl:Read ;
    acl:agent <https://user.example.com/profile#me> ;
    acl:accessTo <https://pod.example.com/data/file.txt> .

<> acl:Authorization auth-2 ;
    acl:mode acl:Write ;
    acl:agent <https://user.example.com/profile#me> ;
    acl:accessTo <https://pod.example.com/data/file.txt> .
```

**ACP (JSON-LD Format):**
```json
{
  "@context": "https://www.w3.org/ns/solid/acp/context.jsonld",
  "@type": "AccessControl",
  "rule": [
    {
      "@type": "AccessGrant",
      "access": "Read",
      "agent": "https://user.example.com/profile#me",
      "agentClass": "Agent"
    },
    {
      "@type": "AccessGrant",
      "access": "Write",
      "agent": "https://user.example.com/profile#me",
      "agentClass": "Agent"
    }
  ]
}
```

---

## Notification Operations

### Endpoint Discovery

The SDK discovers notification endpoints using `.well-known` endpoints.

**Discovery Order:**
1. `.well-known/solid-notifications`
2. `.well-known/notifications`
3. Default: `{base}/notifications`

**SDK Method:**
```go
endpoint, err := notificationClient.DiscoverNotificationEndpoint(ctx)
```

### Subscription Management

#### Create Subscription

**Request:**
```
POST /notifications HTTP/1.1
Host: pod.example.com
Content-Type: application/json
Authorization: DPoP {access-token}
DPoP: {dpop-proof}

{
  "resourceUri": "https://pod.example.com/data/",
  "channelType": "sse",
  "callbackUrl": "https://myapp.com/notifications"
}
```

**SDK Method:**
```go
subscription, err := notificationClient.CreateSubscription(
    ctx,
    "https://pod.example.com/data/",
    "https://myapp.com/notifications",
    "sse",
    nil,
)
```

#### List Subscriptions

**SDK Method:**
```go
subscriptions, err := notificationClient.ListSubscriptions(ctx, nil)
```

#### Delete Subscription

**SDK Method:**
```go
err := notificationClient.DeleteSubscription(ctx, subscriptionID, nil)
```

### Event Streaming (Server-Sent Events)

**Subscribe to Events:**
```go
err := notificationClient.Subscribe(ctx, subscriptionID, func(event *types.Event) {
    // Handle event
    fmt.Printf("Event %s: %s on %s\n", event.ID, event.Type, event.ResourceURI)
})
```

**Event Structure:**
```json
{
  "id": "event-123",
  "type": "update",
  "resourceUri": "https://pod.example.com/data/file.txt",
  "containerUri": "https://pod.example.com/data/",
  "agent": "https://user.example.com/profile#me",
  "action": "write",
  "timestamp": "2024-01-15T10:30:00Z",
  "metadata": {},
  "sequenceNumber": 42
}
```

**Event Types:**
- `create`: Resource was created
- `update`: Resource was updated
- `delete`: Resource was deleted

**SSE Connection:**
- Events are received via Server-Sent Events
- Connection URL: `{notification-endpoint}/{subscription-id}/sse`
- Automatic reconnection on connection loss
- Exponential backoff between reconnection attempts

### Historical Events

**Retrieve Past Events:**
```go
events, lastID, err := notificationClient.GetEvents(
    ctx,
    subscriptionID,
    since,  // Optional: start time
    100,    // Optional: limit
    nil,
)
```

---

## WebID Operations

### WebID Discovery

The SDK supports multiple WebID discovery methods:

1. **Direct Validation**: If the identifier is already a valid WebID URI
2. **URL Discovery**: Follow redirects and check Link headers for `rel="me"`
3. **WebFinger**: Discover WebID from email or other identifiers
4. **.well-known**: Check common `.well-known` endpoints

**SDK Method:**
```go
webID, err := webidClient.DiscoverWebID(ctx, identifier, nil)
// identifier can be:
// - "https://user.example.com/profile#me" (direct WebID)
// - "https://user.example.com" (URL that redirects or has Link header)
// - "user@example.com" (email for WebFinger)
```

### Profile Retrieval

**SDK Method:**
```go
profile, err := webidClient.GetProfile(ctx, "https://user.example.com/profile#me", nil)
```

**Profile Structure:**
```json
{
  "uri": "https://user.example.com/profile#me",
  "subject": "https://user.example.com/profile#me",
  "types": ["http://xmlns.com/foaf/0.1/Person"],
  "name": "John Doe",
  "label": "John",
  "description": "Software Developer",
  "image": "https://user.example.com/profile.jpg",
  "url": "https://johndoe.com",
  "storage": ["https://pod.example.com/"],
  "inbox": "https://pod.example.com/inbox/",
  "outbox": "https://pod.example.com/outbox/"
}
```

### Profile Fields

**Helper Methods:**
```go
// Get individual fields
name, _ := webidClient.GetName(ctx, webID, nil)
image, _ := webidClient.GetImage(ctx, webID, nil)
storage, _ := webidClient.GetStorage(ctx, webID, nil)
inbox, _ := webidClient.GetInbox(ctx, webID, nil)
outbox, _ := webidClient.GetOutbox(ctx, webID, nil)

// Verify WebID
valid, err := webidClient.VerifyWebID(ctx, webID, nil)
```

---

## Sync Operations

### Sync Architecture

The SyncClient provides offline-first synchronization with conflict resolution:

**Features:**
- Change tracking (local and server)
- ETag-based conflict detection
- Multiple conflict resolution strategies
- Batch operations
- Automatic retry with exponential backoff
- Event-driven sync

### Conflict Resolution Strategies

**Strategy Types:**
```go
types.ServerWins    // Discard local changes, use server version
types.ClientWins    // Overwrite server with local changes
types.LatestWins   // Use the most recently modified version
types.Merge        // Merge changes (for RDF resources)
types.Manual       // Require manual resolution
```

### Basic Sync

**Sync Single Resource:**
```go
state, err := syncClient.Sync(ctx, resourceURI, nil)
// state.Synced: whether sync was successful
// state.Conflict: whether a conflict was detected
// state.LocalETag: current local ETag
// state.ServerETag: current server ETag
```

**Sync Multiple Resources:**
```go
states, err := syncClient.SyncBatch(ctx, []string{uri1, uri2, uri3}, nil)
```

**Sync All Tracked Resources:**
```go
states, err := syncClient.SyncAll(ctx, nil)
```

### Full Sync

Performs a two-phase sync: pull all server changes first, then push local changes.

```go
results, err := syncClient.FullSync(ctx, nil)
```

### Change Tracking

**Add Changes:**
```go
// Add a single change (RDF triple)
triple := types.RDFTriple{
    Subject:   "https://pod.example.com/data/file.txt",
    Predicate: "http://purl.org/dc/elements/1.1/title",
    Object:    "My File",
    ObjectType: "literal",
}
syncClient.AddChange(resourceURI, triple)

// Add multiple changes
syncClient.AddChanges(resourceURI, []types.RDFTriple{triple1, triple2})
```

**Check for Pending Changes:**
```go
hasChanges := syncClient.HasPendingChanges(resourceURI)
changes := syncClient.GetPendingChanges(resourceURI)
```

### Conflict Handling

**Set Conflict Strategy:**
```go
syncClient.SetConflictStrategy(types.LatestWins)
```

**Set Conflict Handler:**
```go
syncClient.SetOnConflict(func(resourceURI, localETag, serverETag string) types.SyncConflictStrategy {
    // Custom logic to determine strategy
    if shouldPreferServer(resourceURI) {
        return types.ServerWins
    }
    return types.ClientWins
})
```

**Manual Conflict Resolution:**
```go
// Check if resource has conflict
if syncClient.CheckConflict(resourceURI) {
    // Resolve conflict
    state, err := syncClient.ResolveConflict(resourceURI, types.Merge)
}
```

---

## RDF Operations

### Format Support

The RDFCodec supports multiple RDF formats:

- **Turtle**: `text/turtle` (default for parsing/serialization)
- **JSON-LD**: `application/ld+json`
- **N-Triples**: `application/n-triples`
- **RDF/XML**: `application/rdf+xml`

### Parsing

**Parse RDF Data:**
```go
codec := clients.NewRDFCodec(nil)

// Parse from bytes
dataset, err := codec.Parse(rdfData, types.Turtle)

// Parse from string
dataset, err := codec.ParseString(rdfString, "text/turtle")

// Auto-detect format
dataset, err := codec.Parse(rdfData, "")  // Detects format automatically
```

**Dataset Structure:**
```go
type RDFDataset struct {
    Triples  []RDFTriple            // Default graph triples
    Graphs   map[string][]RDFTriple  // Named graphs
    Prefixes map[string]string       // Namespace prefixes
    BaseURI  string                  // Base URI for relative URIs
}

type RDFTriple struct {
    Subject         string
    Predicate       string
    Object          string
    ObjectType      string  // "uri", "literal", "blank"
    LiteralDatatype string  // For literal objects
    LiteralLanguage string  // For literal objects
}
```

### Serialization

**Serialize Dataset:**
```go
// Serialize to Turtle
turtleData, err := codec.Serialize(dataset, types.Turtle)

// Serialize to JSON-LD
jsonldData, err := codec.Serialize(dataset, types.JSONLD)

// Serialize to string
str, err := codec.SerializeToString(dataset, types.Turtle)
```

### Prefix Management

**Add Custom Prefixes:**
```go
codec := clients.NewRDFCodec(&clients.RDFCodecOptions{
    Prefixes: map[string]string{
        "ex": "http://example.org/ns#",
        "my": "https://my-ontology.org/",
    },
})

// Or add after creation
codec.AddPrefix("ex", "http://example.org/ns#")
```

---

## Error Handling

### Error Types

The SDK defines specific error types for different scenarios:

**Common Errors:**
```go
utils.ErrNetwork         // Network-level errors
utils.ErrAuthentication   // 401 Unauthorized
utils.ErrAuthorization    // 403 Forbidden
utils.ErrNotFound         // 404 Not Found
utils.ErrConflict         // 409 Conflict
utils.ErrPreconditionFailed // 412 Precondition Failed
utils.ErrRateLimited      // 429 Too Many Requests
utils.ErrValidation       // Validation errors
utils.ErrSecurity         // Security violations
```

**Resource Errors:**
```go
clients.ErrResourceNotFound   // Resource does not exist
clients.ErrResourceExists     // Resource already exists
clients.ErrResourceModified    // Resource was modified (ETag mismatch)
```

**Policy Errors:**
```go
clients.ErrPolicyNotFound
clients.ErrPolicyConflict
clients.ErrInvalidPolicy
```

**Notification Errors:**
```go
clients.ErrSubscriptionNotFound
clients.ErrInvalidSubscription
clients.ErrSubscriptionConflict
```

**WebID Errors:**
```go
clients.ErrWebIDNotFound
clients.ErrInvalidWebID
clients.ErrWebIDDiscoveryFailed
```

**Sync Errors:**
```go
clients.ErrSyncNotSupported
clients.ErrSyncConflict
clients.ErrSyncFailed
clients.ErrNoChanges
```

**RDF Errors:**
```go
clients.ErrRDFParse
clients.ErrRDFSerialization
clients.ErrUnsupportedFormat
```

### Error Checking

**Pattern:**
```go
result, err := client.SomeOperation(ctx, params)
if err != nil {
    if err == utils.ErrAuthentication {
        // Handle authentication error
    } else if err == utils.ErrPreconditionFailed {
        // Handle conflict
    } else if errors.Is(err, clients.ErrResourceNotFound) {
        // Handle not found
    } else {
        // Handle other error
    }
}
```

### Context Propagation

All SDK methods accept `context.Context` for:
- Cancellation
- Timeout
- Deadline
- Request-scoped values

**Example:**
```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

resource, err := client.Get(ctx, uri, nil)
if ctx.Err() == context.DeadlineExceeded {
    // Handle timeout
}
```

---

## Security Guarantees

### Input Validation

✅ **All URIs are validated:**
- Must be valid HTTP/HTTPS URLs
- No credentials in URLs
- No private IPs in production
- Proper URL encoding

✅ **HTTP methods are validated:**
- Only standard methods allowed (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)

✅ **Body sizes are limited:**
- Request body: max 10MB (configurable)
- Response body: max 10MB (configurable)

### Authentication

✅ **DPoP support:**
- Proof generation via callback
- Automatic inclusion in requests
- Always paired with access token

✅ **Token handling:**
- Secure storage (in-memory only)
- No token logging
- No token transmission without DPoP

### Network Security

✅ **TLS requirements:**
- TLS 1.2 minimum
- TLS 1.3 preferred
- Certificate validation (except localhost in dev)

✅ **SSRF prevention:**
- Scheme validation
- IP validation
- Credential blocking
- Private IP blocking (production)

### Data Protection

✅ **ETag-based concurrency control:**
- All writes support If-Match/If-None-Match
- Automatic conflict detection
- Multiple conflict resolution strategies

✅ **Atomic operations:**
- PUT is atomic (all or nothing)
- DELETE is atomic
- PATCH uses SPARQL Update (atomic by spec)

---

## Compatibility Claims

### Solid Protocol Support

| Feature | Support Level | Notes |
|--------|--------------|-------|
| Solid HTTP | ✅ Full | All standard methods supported |
| DPoP Authentication | ✅ Full | RFC 9449 compliant |
| WAC (Web Access Control) | ✅ Full | Read/Write with Turtle |
| ACP (Access Control Policy) | ✅ Full | JSON-LD format |
| SAI (Solid App Interop) | ✅ Basic | Core support |
| Notifications | ✅ Full | SSE support |
| RDF | ✅ Full | Turtle, JSON-LD, N-Triples, RDF/XML |
| Containers | ✅ Full | Basic, Direct, Indirect |
| Conditional Requests | ✅ Full | If-Match, If-None-Match |

### Standard Compliance

- ✅ [RFC 7231](https://datatracker.ietf.org/doc/html/rfc7231) - HTTP/1.1 Semantics
- ✅ [RFC 7232](https://datatracker.ietf.org/doc/html/rfc7232) - Conditional Requests
- ✅ [RFC 7235](https://datatracker.ietf.org/doc/html/rfc7235) - HTTP Authentication
- ✅ [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) - DPoP
- ✅ [Solid Protocol](https://solidproject.org/TR/protocol) - Core specifications
- ✅ [Linked Data Platform](https://www.w3.org/TR/ldp/) - Container operations
- ✅ [Web Access Control](https://www.w3.org/Submission/web-acl/) - WAC policies
- ✅ [Access Control Policy](https://solidproject.org/TR/acp) - ACP policies

### Implementation Status

| Component | Status | Maturity |
|-----------|--------|----------|
| HTTPClient | ✅ Complete | Production-ready |
| ResourceClient | ✅ Complete | Production-ready |
| PolicyClient | ✅ Complete | Production-ready |
| NotificationClient | ✅ Complete | Production-ready |
| WebIDClient | ✅ Complete | Production-ready |
| SyncClient | ✅ Complete | Production-ready |
| RDFCodec | ✅ Complete | Production-ready |

---

## Best Practices

### Authentication Flow

```go
// 1. Initialize DPoP keystore
keystore, err := auth.NewDPoPKeyStore()
if err != nil {
    log.Fatal(err)
}

// 2. Obtain access token (from your OIDC/Solid-OIDC flow)
accessToken, err := obtainAccessToken()
if err != nil {
    log.Fatal(err)
}

// 3. Create HTTP client with auth
httpClient, err := utils.NewHTTPClient("https://sidecar.example.com", &types.RequestOptions{
    Timeout: 30 * time.Second,
})
if err != nil {
    log.Fatal(err)
}

httpClient.SetAccessToken(accessToken)
httpClient.SetDPoPProofFunc(func(method, url string) (string, error) {
    return keystore.GenerateProof(method, url, accessToken)
})

// 4. Create resource client
resourceClient, err := clients.NewResourceClient("https://sidecar.example.com", &clients.ResourceClientOptions{
    RequestOptions: &types.RequestOptions{
        Timeout: 30 * time.Second,
    },
})
if err != nil {
    log.Fatal(err)
}

// Reuse HTTP client's auth
resourceClient.SetAccessToken(accessToken)
resourceClient.SetDPoPProofFunc(httpClient.GetDPoPProofFunc())
```

### Resource Management

```go
// Always use context with timeout
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

// Check if resource exists
exists, err := resourceClient.Exists(ctx, uri)
if err != nil {
    // handle error
}

// Get resource with metadata
resource, err := resourceClient.Get(ctx, uri, nil)
if err != nil {
    if err == clients.ErrResourceNotFound {
        // Resource doesn't exist
    }
    // handle other error
}

// Update resource with conditional write
preconditions := &types.WritePreconditions{
    IfMatch: []string{resource.ETag},
}
result, err := resourceClient.Put(ctx, uri, "text/turtle", newBody, preconditions, nil)
if err == utils.ErrPreconditionFailed {
    // Concurrent modification - refresh and retry
}
```

### Error Handling

```go
// Comprehensive error handling
resource, err := client.Get(ctx, uri, nil)
if err != nil {
    // Check context first
    if ctx.Err() != nil {
        return fmt.Errorf("operation cancelled: %w", ctx.Err())
    }
    
    // Check specific error types
    if errors.Is(err, utils.ErrAuthentication) {
        // Re-authenticate
        return fmt.Errorf("authentication failed: %w", err)
    }
    
    if errors.Is(err, utils.ErrPreconditionFailed) {
        // Conflict - refresh and retry
        return fmt.Errorf("conflict: %w", err)
    }
    
    if errors.Is(err, clients.ErrResourceNotFound) {
        // Resource doesn't exist
        return fmt.Errorf("not found: %w", err)
    }
    
    // Generic error
    return fmt.Errorf("operation failed: %w", err)
}
```

### Batch Operations

```go
// Batch get multiple resources
uris := []string{uri1, uri2, uri3}
var wg sync.WaitGroup
results := make([]*types.Resource, len(uris))

for i, uri := range uris {
    wg.Add(1)
    go func(idx int, u string) {
        defer wg.Done()
        resource, err := client.Get(ctx, u, nil)
        if err != nil {
            // Handle error
            return
        }
        results[idx] = resource
    }(i, uri)
}
wg.Wait()
```

---

## Versioning

This document describes the client contract for **Phase 27 - SDK/Client Compatibility Layer** of the Solid Sidecar project.

**SDK Version:** 1.0.0  
**Status:** STABLE - Production Ready - FULLY HARDENED  
**Last Updated:** 2026-07-08

---

## Support

For issues, questions, or contributions:

- **Repository:** [github.com/outlaw-dame/solid-sidecar](https://github.com/outlaw-dame/solid-sidecar)
- **Phase:** 27 - SDK/Client Compatibility Layer
- **Status:** STABLE - Production Ready - FULLY HARDENED

---

*This document is part of the Solid Sidecar SDK and is licensed under the same terms as the project.*
