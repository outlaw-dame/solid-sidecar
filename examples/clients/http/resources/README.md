# Resource CRUD Examples

**Phase**: 27 - SDK/Client Compatibility Layer  
**Component**: Resource Operations  
**Version**: v1.0.0  
**Created**: 2026-07-07  
**Author**: Mistral Vibe  
**Status**: STABLE - Production Ready  

---

## Overview

This directory contains examples for **Solid Resource CRUD operations** against Solid Sidecar. These examples demonstrate how to create, read, update, and delete resources following the [Solid Protocol](https://solidproject.org/TR/protocol) specification.

**Key Principle**: All resource operations follow standard HTTP methods with Solid-specific semantics for:
- Content-Type negotiation (RDF vs non-RDF)
- Container operations
- Link headers
- ETag/conditional requests
- WAC/ACP policy resources

---

## Resource Types

Solid Sidecar supports the following resource types:

| Resource Type | Description | Content Types |
|---------------|-------------|---------------|
| RDF Resource | Structured data (Turtle, JSON-LD, N-Triples, RDF/XML) | `text/turtle`, `application/ld+json`, `application/n-triples`, `application/rdf+xml` |
| Non-RDF Resource | Binary or text data | `text/plain`, `application/octet-stream`, `application/json`, etc. |
| Container | Directory-like resource that contains other resources | `text/turtle` (with container metadata) |
| Policy Resource | Access control policy (WAC or ACP) | `text/turtle` (WAC), `application/ld+json` (ACP) |

---

## Files in This Directory

| File | Description | HTTP Methods |
|------|-------------|---------------|
| [get-resource.sh](./get-resource.sh) | Retrieve a resource | GET |
| [head-resource.sh](./head-resource.sh) | Get resource metadata only | HEAD |
| [put-resource.sh](./put-resource.sh) | Create or replace a resource | PUT |
| [patch-resource.sh](./patch-resource.sh) | Partial update (RDF resources) | PATCH |
| [delete-resource.sh](./delete-resource.sh) | Delete a resource | DELETE |
| [list-container.sh](./list-container.sh) | List container contents | GET |
| [conditional-put.sh](./conditional-put.sh) | Create/update with If-Match/If-None-Match | PUT |
| [conditional-delete.sh](./conditional-delete.sh) | Delete with If-Match | DELETE |

---

## Resource CRUD Operations

### GET - Retrieve a Resource

Retrieves the content and metadata of a resource.

**Request**:
```http
GET /container/resource.ttl HTTP/1.1
Host: sidecar.example.com
Authorization: DPoP access-token
DPoP: dpop-proof-jwt
Accept: text/turtle, application/ld+json
```

**Response**:
```http
HTTP/1.1 200 OK
Content-Type: text/turtle
ETag: "abc123"
Last-Modified: Wed, 07 Jul 2026 00:00:00 GMT
Link: <http://www.w3.org/ns/ldp#BasicContainer>; rel="type"

@prefix ex: <http://example.org/ns#> .
...
```

### HEAD - Get Resource Metadata

Retrieves only the metadata (headers) of a resource, without the body.

**Request**:
```http
HEAD /container/resource.ttl HTTP/1.1
Host: sidecar.example.com
Authorization: DPoP access-token
DPoP: dpop-proof-jwt
Accept: text/turtle
```

**Response**:
```http
HTTP/1.1 200 OK
Content-Type: text/turtle
Content-Length: 1234
ETag: "abc123"
Last-Modified: Wed, 07 Jul 2026 00:00:00 GMT
Link: <http://www.w3.org/ns/ldp#BasicContainer>; rel="type"
```

### PUT - Create or Replace a Resource

Creates a new resource or replaces an existing one.

**Request**:
```http
PUT /container/new-resource.ttl HTTP/1.1
Host: sidecar.example.com
Authorization: DPoP access-token
DPoP: dpop-proof-jwt
Content-Type: text/turtle

@prefix ex: <http://example.org/ns#> .
...
```

**Response** (Success - Created):
```http
HTTP/1.1 201 Created
Location: /container/new-resource.ttl
ETag: "new-etag"
Last-Modified: Wed, 07 Jul 2026 00:00:00 GMT
Link: <http://www.w3.org/ns/ldp#Resource>; rel="type"
```

**Response** (Success - Updated):
```http
HTTP/1.1 200 OK
ETag: "updated-etag"
Last-Modified: Wed, 07 Jul 2026 00:00:01 GMT
```

### PATCH - Partial Update

Performs a partial update on an RDF resource using SPARQL Update.

**Request**:
```http
PATCH /container/resource.ttl HTTP/1.1
Host: sidecar.example.com
Authorization: DPoP access-token
DPoP: dpop-proof-jwt
Content-Type: application/sparql-update

PREFIX ex: <http://example.org/ns#>
INSERT DATA { ex:subject ex:predicate "new-value" }
WHERE { }
```

**Response**:
```http
HTTP/1.1 200 OK
ETag: "updated-etag"
Last-Modified: Wed, 07 Jul 2026 00:00:01 GMT
```

### DELETE - Delete a Resource

Deletes an existing resource.

**Request**:
```http
DELETE /container/resource.ttl HTTP/1.1
Host: sidecar.example.com
Authorization: DPoP access-token
DPoP: dpop-proof-jwt
```

**Response**:
```http
HTTP/1.1 204 No Content
```

---

## Container Operations

### List Container Contents

Lists all resources contained within a container.

**Request**:
```http
GET /container/ HTTP/1.1
Host: sidecar.example.com
Authorization: DPoP access-token
DPoP: dpop-proof-jwt
Accept: text/turtle
```

**Response**:
```http
HTTP/1.1 200 OK
Content-Type: text/turtle

<http://sidecar.example.com/container/resource1.ttl> a <http://www.w3.org/ns/ldp#Resource> .
<http://sidecar.example.com/container/resource2.ttl> a <http://www.w3.org/ns/ldp#Resource> .
<http://sidecar.example.com/container/subcontainer/> a <http://www.w3.org/ns/ldp#BasicContainer> .
```

### Create Container

Creates a new container.

**Request**:
```http
PUT /new-container/ HTTP/1.1
Host: sidecar.example.com
Authorization: DPoP access-token
DPoP: dpop-proof-jwt
Content-Type: text/turtle
Link: <http://www.w3.org/ns/ldp#BasicContainer>; rel="type"

@prefix ldp: <http://www.w3.org/ns/ldp#> .
<> a ldp:BasicContainer .
```

**Response**:
```http
HTTP/1.1 201 Created
Location: /new-container/
ETag: "container-etag"
Last-Modified: Wed, 07 Jul 2026 00:00:00 GMT
Link: <http://www.w3.org/ns/ldp#BasicContainer>; rel="type"
```

---

## Conditional Requests

Solid Sidecar supports conditional requests using ETags for optimistic concurrency control.

### If-Match - Only if unchanged

Only perform the operation if the resource has not been modified since the given ETag.

**Request**:
```http
PUT /container/resource.ttl HTTP/1.1
Host: sidecar.example.com
Authorization: DPoP access-token
DPoP: dpop-proof-jwt
Content-Type: text/turtle
If-Match: "abc123"

@prefix ex: <http://example.org/ns#> .
...
```

**Response** (Success - Not Modified):
```http
HTTP/1.1 200 OK
ETag: "new-etag"
Last-Modified: Wed, 07 Jul 2026 00:00:01 GMT
```

**Response** (Error - Precondition Failed):
```http
HTTP/1.1 412 Precondition Failed
```

### If-None-Match - Only if not exists or changed

Only perform the operation if the resource doesn't exist or has been modified.

**Request** (Create only if doesn't exist):
```http
PUT /container/new-resource.ttl HTTP/1.1
Host: sidecar.example.com
Authorization: DPoP access-token
DPoP: dpop-proof-jwt
Content-Type: text/turtle
If-None-Match: *

@prefix ex: <http://example.org/ns#> .
...
```

**Response** (Success - Created):
```http
HTTP/1.1 201 Created
Location: /container/new-resource.ttl
ETag: "new-etag"
```

**Response** (Error - Already Exists):
```http
HTTP/1.1 412 Precondition Failed
```

---

## Headers

### Request Headers

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes | DPoP-bound access token |
| `DPoP` | Yes | DPoP proof JWT |
| `Accept` | No | Preferred response content types |
| `Content-Type` | Yes (for PUT/PATCH) | Content type of request body |
| `If-Match` | No | ETag for conditional requests |
| `If-None-Match` | No | ETag or * for conditional requests |
| `Link` | No (for PUT) | Resource type hints |

### Response Headers

| Header | Description |
|--------|-------------|
| `Content-Type` | Content type of response body |
| `Content-Length` | Length of response body |
| `ETag` | Current ETag of the resource |
| `Last-Modified` | Last modification timestamp |
| `Location` | Resource URL (for 201 Created) |
| `Link` | Resource type and other metadata |

---

## Error Responses

| Status Code | Error | Description |
|-------------|-------|-------------|
| 400 | Bad Request | Invalid request syntax |
| 401 | Unauthorized | Authentication required or failed |
| 403 | Forbidden | Access denied (policy violation) |
| 404 | Not Found | Resource does not exist |
| 409 | Conflict | Resource already exists (non-idempotent PUT) |
| 412 | Precondition Failed | If-Match or If-None-Match failed |
| 413 | Payload Too Large | Request body exceeds limits |
| 415 | Unsupported Media Type | Content-Type not supported |
| 429 | Too Many Requests | Rate limited |
| 500 | Internal Server Error | Server error |

---

## Content Negotiation

Solid Sidecar supports content negotiation for both requests and responses.

### Supported Content Types

**RDF Formats**:
- `text/turtle` (default for RDF)
- `application/ld+json` (JSON-LD)
- `application/n-triples`
- `application/rdf+xml`

**Non-RDF Formats**:
- `text/plain`
- `application/octet-stream`
- `application/json`
- `image/*`
- `audio/*`
- `video/*`

### Accept Header

Clients can specify preferred response formats:

```http
Accept: text/turtle;q=1.0, application/ld+json;q=0.9, */*;q=0.1
```

The server will respond with the best matching format.

---

## Security Considerations

All resource operations MUST:

1. **Use HTTPS** for all production endpoints
2. **Include DPoP proof** with every authenticated request
3. **Validate URLs** before making requests
4. **Handle errors securely** - don't expose sensitive information
5. **Respect rate limits** - implement exponential backoff
6. **Use conditional requests** to prevent lost updates
7. **Validate ETags** to detect concurrent modifications

### IDOR Prevention

All resource URIs MUST be validated to ensure the requesting agent has access:

1. **Validate resource URI** is within the agent's allowed scope
2. **Check policies** before allowing operations
3. **Use ETags** for optimistic concurrency control
4. **Never trust client-provided URIs** without validation

### SSRF Prevention

All resource URIs MUST be validated to prevent Server-Side Request Forgery:

1. **Validate URI scheme** is http or https
2. **Validate URI host** is within allowed domains
3. **Reject URIs with credentials** in the path or query
4. **Normalize URIs** to prevent bypass attempts

---

## Testing

Test your resource operations with:

1. **Valid authenticated requests** - should succeed
2. **Missing DPoP proof** - should fail with 401
3. **Invalid DPoP proof** - should fail with 401
4. **Expired access token** - should fail with 401
5. **Nonexistent resource** - should return 404
6. **Existing resource with If-None-Match: *** - should return 412
7. **Concurrent modification** - should return 412 with If-Match
8. **Large payload** - should return 413
9. **Unsupported content type** - should return 415
10. **Rate limited requests** - should return 429

---

## References

- [Solid Protocol Specification](https://solidproject.org/TR/protocol)
- [Linked Data Platform 1.0](https://www.w3.org/TR/ldp/)
- [HTTP/1.1](https://datatracker.ietf.org/doc/html/rfc7231)
- [Client Contract](../docs/client-contract.md)
- [Client Security Requirements](../docs/client-security.md)
