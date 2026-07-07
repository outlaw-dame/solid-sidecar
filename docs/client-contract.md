# Solid Sidecar Client Contract

**Document Type**: Client API Contract  
**Version**: v1.0.0  
**Created**: 2026-07-07  
**Author**: Mistral Vibe  
**Phase**: 27 - SDK/Client Compatibility Layer  
**Status**: ✅ DRAFT - Under Active Development  
**Last Verified**: 2026-07-07  

---

## ⚠️ DISCLAIMER

**This document defines the STABLE client contract for Solid Sidecar v0.2.0 Beta.**

> **IMPORTANT**: This is a **SPECIFICATION**, not implementation. All client SDKs (TypeScript, Go, Rust) MUST conform to this contract. Any deviation is a bug.
>
> **COMPATIBILITY ORACLE**: Community Solid Server (CSS) remains the authority. This sidecar provides a compatible surface. When in doubt, CSS behavior is correct.
>
> **ENFORCEMENT MODE**: By default, the sidecar operates in **SHADOW MODE**. Authorization decisions are observed but NOT enforced. Clients must NOT assume enforcement unless explicitly configured.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Base URL and Endpoints](#2-base-url-and-endpoints)
3. [Transport Layer](#3-transport-layer)
4. [Authentication Contract](#4-authentication-contract)
5. [Request Headers](#5-request-headers)
6. [Response Headers](#6-response-headers)
7. [Resource CRUD Contract](#7-resource-crud-contract)
8. [Container Operations](#8-container-operations)
9. [Policy Resource Contract](#9-policy-resource-contract)
10. [Notification Contract](#10-notification-contract)
11. [Error Model](#11-error-model)
12. [Rate Limiting](#12-rate-limiting)
13. [Content Negotiation](#13-content-negotiation)
14. [Compression](#14-compression)
15. [CORS](#15-cors)
16. [Security Guarantees](#16-security-guarantees)
17. [Compatibility Matrix](#17-compatibility-matrix)
18. [Conformance Requirements](#18-conformance-requirements)

---

## 1. Overview

### 1.1 Purpose

This document defines the **stable HTTP contract** between clients (web, mobile, SDK) and Solid Sidecar. It specifies:

- **What** requests clients can make
- **How** to authenticate and authorize
- **What** responses to expect
- **What** errors look like
- **What** guarantees are provided

### 1.2 Audience

- Native app developers (iOS, Android, Flutter, React Native)
- Web app developers
- SDK maintainers
- Integration test authors
- Security auditors

### 1.3 Contract Stability

| Component | Stability | Backwards Compatibility |
|-----------|-----------|--------------------------|
| Authentication | ✅ STABLE | Will not change without major version |
| Resource CRUD | ✅ STABLE | Will not change without major version |
| Policy Resources | ✅ STABLE | Will not change without major version |
| Notifications | ⚠️ EXPERIMENTAL | May change in minor versions |
| SAI Endpoints | ⚠️ EXPERIMENTAL | May change in minor versions |

### 1.4 Terminology

| Term | Definition |
|------|------------|
| CSS | Community Solid Server - the reference implementation |
| DPoP | Demonstrating Proof of Possession - JWT-bound access tokens |
| WebID | Decentralized identifier for agents in Solid |
| WAC | Web Access Control - access control policy format |
| ACP | Access Control Policy - alternative access control format |
| SAI | Solid Application Interoperability |
| Pod | Personal Online Datastore - user's data storage |
| Resource | Any addressable entity in a Pod (files, containers, etc.) |

---

## 2. Base URL and Endpoints

### 2.1 Base URL

```
https://{host}:{port}/ 
```

**Default Production**: `https://localhost:8443/`  
**Default Development**: `http://localhost:8443/` (HTTP allowed in dev only)

### 2.2 Endpoint Categories

| Category | Path Prefix | Purpose |
|----------|-------------|---------|
| **Core Resources** | `/` | Resource CRUD operations |
| **Containers** | `/` | Container listing, creation |
| **Authentication** | N/A | Headers-based (no dedicated endpoints) |
| **Health** | `/healthz` | Liveness probe |
| **Readiness** | `/readyz` | Readiness probe |
| **Admin** | `/admin/` | Administrative operations |
| **Metrics** | `/metrics` | Observability metrics |
| **SAI** | `/sai/` | Solid Application Interoperability (EXPERIMENTAL) |

### 2.3 Reserved Paths

The following paths are **reserved for sidecar operations** and MUST NOT be used for resource storage:

```
/healthz
/readyz
/admin/
/metrics
/sai/
/.well-known/
```

**Any request to a reserved path that doesn't match the expected operation WILL return 404 or 405.**

---

## 3. Transport Layer

### 3.1 Protocol

| Environment | Protocol | Port | Security |
|-------------|----------|------|----------|
| Production | HTTPS | 8443 | ✅ Required |
| Development | HTTP/HTTPS | 8443 | ⚠️ HTTPS Recommended |

**HTTPS Requirements**:
- TLS 1.2 minimum
- TLS 1.3 recommended
- Modern cipher suites only (no CBC mode, no TLS 1.0/1.1)
- Certificate validation MUST be enabled

### 3.2 HTTP/2 Support

| Feature | Status | Notes |
|---------|--------|-------|
| HTTP/2 | ✅ Supported | Enabled by default |
| HTTP/1.1 | ✅ Supported | Always available |
| Keep-Alive | ✅ Supported | Connection reuse enabled |

### 3.3 Connection Limits

| Limit | Value | Type |
|-------|-------|------|
| Max concurrent connections | 1000 | Per client |
| Connection timeout | 30s | Configurable |
| Keep-alive timeout | 90s | Configurable |
| Idle connection timeout | 90s | Configurable |

---

## 4. Authentication Contract

### 4.1 Overview

Solid Sidecar uses **DPoP-bound Bearer tokens** for authentication. This is the **ONLY** supported authentication method.

**Authentication Flow**:
```
1. Client obtains access token from OIDC provider
2. Client generates DPoP proof JWT
3. Client sends both in Authorization header
4. Sidecar validates DPoP proof and access token
5. Sidecar validates token claims (issuer, audience, expiration)
6. Sidecar extracts WebID from token
7. Request proceeds with authenticated context
```

### 4.2 Access Token Requirements

**Format**: JWT (RFC 7519)

**Required Claims**:

| Claim | Required | Value | Notes |
|-------|----------|-------|-------|
| `iss` | ✅ | Issuer URL | Must match allowed issuers |
| `sub` | ✅ | Subject | User identifier |
| `aud` | ✅ | Audience | Must match sidecar audience |
| `exp` | ✅ | Expiration | Must be in future |
| `nbf` | ⚠️ Recommended | Not Before | If present, must be in past |
| `iat` | ⚠️ Recommended | Issued At | If present, used for replay |
| `cnf` | ✅ | Confirmation | Must contain `jkt` (JWT Key Thumbprint) |

**Token Signature**: RS256 only (ES256, PS256 NOT supported)

**Token Lifetime**: Maximum 1 hour recommended (configurable)

### 4.3 DPoP Proof Requirements

**Format**: JWT (RFC 7519, RFC 9449)

**Required Claims**:

| Claim | Required | Value | Notes |
|-------|----------|-------|-------|
| `typ` | ✅ | `dpop+jwt` | Type identifier |
| `jwk` | ✅ | JWK | Public key for proof verification |
| `htu` | ✅ | HTTP URI | Target URI (method + path) |
| `htm` | ✅ | HTTP Method | GET, POST, PUT, DELETE, PATCH, HEAD |
| `iat` | ✅ | Issued At | Timestamp of proof generation |
| `nonce` | ⚠️ Conditional | Nonce | Required if provided by server |

**Additional Requirements**:
- `jwk.use` MUST be `sig`
- `jwk.kty` MUST be `RSA` (EC not supported)
- `jwk.alg` MUST be `RS256`
- `jwk.key_ops` MUST include `sign`

**Proof Signature**: RS256 only

**Proof Binding**:
- The `ath` (Access Token Hash) claim MUST be present
- `ath` = SHA-256 hash of the access token (as base64url-encoded bytes)

### 4.4 Authorization Header Format

```http
Authorization: DPoP {access_token}
```

**Where `{access_token}` is the base64url-encoded JWT access token.**

**DPoP Proof Header** (separate from Authorization):
```http
DPoP: {dpop_proof_jwt}
```

**Both headers MUST be present for authenticated requests.**

### 4.5 Authentication Flow Examples

#### Example 1: GET Request

```http
GET /container/resource.ttl HTTP/1.1
Host: localhost:8443
Authorization: DPoP eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsInN1YiI6Imh0dHBzOi8vZXhhbXBsZS5jb20vY2FyZC91c2VyIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsImV4cCI6MTc1OTk5OTk5OSwianRpIjoiYWJjZDEyMyIsIm5iZiI6MTc1OTk5NjQwMCwiaWF0IjoxNzU5OTk2NDAwLCJjbmYiOnsiYWxnIjoiUlMyNTYiLCJqd2siOnsia2t5IjoiZXhhbXBsZV9rZXkiLCJ1c2UiOiJzaWciLCJrZXlvcHMiOlsiZ2V0Iiwic2lnbiJdLCJkIjoiSHV0V1hCM0JkZjh2YWxHZ21WbGFWQ0o5V2ViVlptQ0prWlE9IiwiZSI6Im5EdVF6Wm1sc1pXRjBaV1F6TVVWd016SXRORGMwWlRWb0pBZG1sQ1FzSmlRc0J3Z1FWU0UzZzlJZ2tWb3k9In0sInZhbF90aW1lIjoxNzU5OTk2NDAwfX0sImF0aCI6IkV4YW1wbGVTdHJpbmdfVHJ1c3RlZF9Ub2tlbnMiLCJzaWduYXR1cmUiOiJSRzI1NiJ9.XXXXX
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IlJTMjU2IiwidHlwIjoiZHBvcCtqd3QiLCJqd2siOnsia2t5IjoiZXhhbXBsZV9rZXkiLCJ1c2UiOiJzaWciLCJrZXlvcHMiOlsiZ2V0Iiwic2lnbiJdLCJkIjoiSHV0V1hCM0JkZjh2YWxHZ21WbGFWQ0o5V2ViVlptQ0prWlE9IiwiZSI6Im5EdVF6Wm1sc1pXRjBaV1F6TVVWd016SXRORGMwWlRWb0pBZG1sQ1FzSmlRc0J3Z1FWU0UzZzlJZ2tWb3k9In0sInZhbF90aW1lIjoxNzU5OTk2NDAwfSwiaWF0IjoxNzU5OTk2NDAwLCJodGUiOiJodHRwczovL2xvY2FsaG9zdDo4NDQzL2NvbnRhaW5lci9yZXNvdXJjZS50dGwiLCJodG0iOiJHRVQiLCJhY3RpZCI6IkFjY2Vzc1Rva2VuX2hhc2giLCJhcGwiOiJVVEY4In19.XXXXX
Accept: text/turtle
```

#### Example 2: PUT Request with DPoP

```http
PUT /container/new-resource.ttl HTTP/1.1
Host: localhost:8443
Authorization: DPoP eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...XXXXX
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IlJTMjU2IiwidHlwIjoiZHBvcCtqd3Qi...XXXXX
Content-Type: text/turtle
Content-Length: 123

@prefix ex: <http://example.org/> .
ex:subject ex:predicate ex:object .
```

### 4.6 Authentication Errors

| Error | HTTP Status | Error Code | Description |
|-------|-------------|------------|-------------|
| Missing Authorization | 401 | `auth_missing` | No Authorization header |
| Invalid token format | 401 | `auth_invalid_token` | Malformed JWT |
| Token expired | 401 | `auth_token_expired` | `exp` claim in past |
| Token not yet valid | 401 | `auth_token_not_valid_yet` | `nbf` claim in future |
| Invalid issuer | 401 | `auth_invalid_issuer` | `iss` not in allowed list |
| Invalid audience | 401 | `auth_invalid_audience` | `aud` doesn't match |
| Invalid signature | 401 | `auth_invalid_signature` | Signature verification failed |
| Missing DPoP proof | 401 | `auth_missing_dpop` | No DPoP header |
| Invalid DPoP format | 401 | `auth_invalid_dpop` | Malformed DPoP JWT |
| DPoP/token mismatch | 401 | `auth_dpop_mismatch` | `ath` doesn't match token hash |
| DPoP key mismatch | 401 | `auth_dpop_key_mismatch` | DPoP key doesn't match token `cnf.jkt` |
| Token replay detected | 401 | `auth_replay` | Token already used (nonce) |
| DPoP URI mismatch | 401 | `auth_dpop_uri_mismatch` | DPoP `htu` doesn't match request |
| DPoP method mismatch | 401 | `auth_dpop_method_mismatch` | DPoP `htm` doesn't match request |

### 4.7 Authentication Security

**Replay Protection**:
- Nonce values are tracked per client
- Tokens with nonces are rejected if reused
- Nonce cache TTL: 10 minutes (configurable)

**Key Binding**:
- DPoP proof MUST be bound to access token via `ath` claim
- Access token MUST contain `cnf.jkt` matching DPoP public key

**Issuer Validation**:
- Only tokens from configured issuers are accepted
- Issuer discovery is bounded (timeout: 5s, max redirects: 0)
- JWKS cache: 5 minutes TTL

**HTTPS Enforcement**:
- All issuer discovery MUST use HTTPS
- All JWKS fetching MUST use HTTPS
- HTTP URLs are rejected

---

## 5. Request Headers

### 5.1 Standard Headers

| Header | Required | Purpose | Notes |
|--------|----------|---------|-------|
| `Host` | ✅ | Target host | Standard HTTP |
| `User-Agent` | ⚠️ Recommended | Client identification | Helps with debugging |
| `Accept` | ⚠️ Recommended | Response format | See Content Negotiation |
| `Content-Type` | ✅ (for write) | Request body format | Required for PUT, POST, PATCH |
| `Content-Length` | ✅ (for body) | Body size | Required for requests with body |
| `Accept-Encoding` | ⚠️ Optional | Compression | See Compression |

### 5.2 Solid-Specific Headers

| Header | Required | Purpose | Notes |
|--------|----------|---------|-------|
| `Authorization` | ✅ (auth) | Bearer token | Required for authenticated requests |
| `DPoP` | ✅ (auth) | DPoP proof JWT | Required for DPoP authentication |
| `Want-Digest` | ⚠️ Optional | Request ETag | Server may provide ETag |
| `If-Match` | ⚠️ Optional | Conditional write | Required ETag match |
| `If-None-Match` | ⚠️ Optional | Conditional write | Required ETag NOT match |

### 5.3 Sidecar-Specific Headers

| Header | Required | Purpose | Notes |
|--------|----------|---------|-------|
| `X-Request-ID` | ❌ (auto) | Request identifier | Automatically added, included in responses |
| `X-Solid-Mode` | ❌ (auto) | Runtime mode | `css_proxy`, `hybrid`, or `native` |

---

## 6. Response Headers

### 6.1 Standard Headers

| Header | Always | Purpose | Notes |
|--------|--------|---------|-------|
| `Content-Type` | ✅ | Response format | Based on Accept header |
| `Content-Length` | ✅ | Body size | Always present |
| `ETag` | ✅ (resources) | Resource identifier | Weak or strong ETag |
| `Last-Modified` | ✅ (resources) | Last modification time | RFC 7232 format |
| `Cache-Control` | ✅ | Caching directives | Varies by resource |
| `Vary` | ✅ | Cache key | Includes `Accept`, `Authorization` |

### 6.2 Solid-Specific Headers

| Header | Always | Purpose | Notes |
|--------|--------|---------|-------|
| `WAC-Allow` | ✅ (WAC) | WAC permissions | Present on resources with WAC |
| `Link` | ✅ (containers) | Container relations | `rel="acl"`, `rel="describedby"` |
| `MS-Author-Via` | ⚠️ Debug | Via header | Only if configured |

### 6.3 Sidecar-Specific Headers

| Header | Always | Purpose | Notes |
|--------|--------|---------|-------|
| `X-Request-ID` | ✅ | Request identifier | Echoed from request |
| `X-Solid-Mode` | ✅ | Runtime mode | Current mode |
| `X-Authz-Enforcement-Mode` | ✅ | Authorization mode | `shadow`, `enforce`, `dry-run`, `enforce_canary` |

### 6.4 Error Response Headers

| Header | Always | Purpose | Notes |
|--------|--------|---------|-------|
| `Retry-After` | ⚠️ Conditional | Retry delay | Present on 429, 503 |

---

## 7. Resource CRUD Contract

### 7.1 Overview

Resources are addressed by URI. The sidecar supports standard HTTP methods:

| Method | Purpose | Idempotent | Safe |
|--------|---------|------------|------|
| GET | Retrieve resource | ✅ | ✅ |
| HEAD | Retrieve metadata only | ✅ | ✅ |
| PUT | Create/Replace resource | ✅ | ❌ |
| POST | Create resource (server-assigned URI) | ❌ | ❌ |
| PATCH | Partial update | ❌ | ❌ |
| DELETE | Delete resource | ✅ | ❌ |

### 7.2 Resource Identification

**URI Format**:
```
{scheme}://{host}:{port}/{path}[?{query}]
```

**Path Requirements**:
- Must be valid URI path
- Must not contain `..` or `.` segments (normalized)
- Must not exceed 8192 bytes
- Must not contain null bytes

**Query Parameters**:
- Query parameters are preserved but not interpreted by sidecar
- Passed through to backend (CSS or native runtime)

### 7.3 GET Request

**Purpose**: Retrieve a resource

**Request**:
```http
GET {uri} HTTP/1.1
Host: {host}
Authorization: DPoP {access_token}
DPoP: {dpop_proof}
Accept: {content_type}
```

**Response - Success (200)**:
```http
HTTP/1.1 200 OK
Content-Type: {content_type}
ETag: "{etag}"
Last-Modified: {timestamp}
Cache-Control: {directives}
Vary: Accept, Authorization
Content-Length: {length}

{body}
```

**Response - Not Found (404)**:
```http
HTTP/1.1 404 Not Found
Content-Type: application/problem+json
Content-Length: {length}

{
  "type": "https://solidproject.org/problem/not-found",
  "title": "Resource not found",
  "status": 404,
  "detail": "The requested resource does not exist",
  "instance": "{request_id}",
  "request_id": "{request_id}"
}
```

**Response - Forbidden (403)**:
```http
HTTP/1.1 403 Forbidden
Content-Type: application/problem+json
Content-Length: {length}

{
  "type": "https://solidproject.org/problem/forbidden",
  "title": "Access denied",
  "status": 403,
  "detail": "You do not have permission to access this resource",
  "instance": "{request_id}",
  "request_id": "{request_id}"
}
```

**Status Codes**:
| Code | Meaning | Condition |
|------|---------|-----------|
| 200 | OK | Resource exists and is accessible |
| 401 | Unauthorized | Authentication required or failed |
| 403 | Forbidden | Authenticated but not authorized |
| 404 | Not Found | Resource does not exist |
| 405 | Method Not Allowed | Method not supported for this resource |
| 406 | Not Acceptable | Cannot satisfy Accept header |
| 415 | Unsupported Media Type | Cannot handle Content-Type |

### 7.4 HEAD Request

**Purpose**: Retrieve resource metadata only (no body)

**Request**: Same as GET but without body

**Response**: Same headers as GET but without body

**Status Codes**: Same as GET

### 7.5 PUT Request

**Purpose**: Create or replace a resource

**Request**:
```http
PUT {uri} HTTP/1.1
Host: {host}
Authorization: DPoP {access_token}
DPoP: {dpop_proof}
Content-Type: {content_type}
Content-Length: {length}
If-Match: "{etag}"  # Optional: for conditional update
If-None-Match: "{etag}"  # Optional: for conditional create

{body}
```

**Response - Created (201)**:
```http
HTTP/1.1 201 Created
Content-Type: application/problem+json
Location: {uri}
ETag: "{etag}"
Last-Modified: {timestamp}
Content-Length: 0
```

**Response - No Content (204)**: (Replace)
```http
HTTP/1.1 204 No Content
ETag: "{new_etag}"
Last-Modified: {timestamp}
Content-Length: 0
```

**Response - Precondition Failed (412)**:
```http
HTTP/1.1 412 Precondition Failed
Content-Type: application/problem+json
Content-Length: {length}

{
  "type": "https://solidproject.org/problem/precondition-failed",
  "title": "Precondition failed",
  "status": 412,
  "detail": "If-Match or If-None-Match precondition not met",
  "instance": "{request_id}",
  "request_id": "{request_id}"
}
```

**Status Codes**:
| Code | Meaning | Condition |
|------|---------|-----------|
| 201 | Created | Resource created (If-None-Match: * or not present) |
| 204 | No Content | Resource replaced (If-Match matched) |
| 401 | Unauthorized | Authentication failed |
| 403 | Forbidden | Not authorized to write |
| 404 | Not Found | Parent container doesn't exist |
| 409 | Conflict | Resource already exists (If-None-Match: *) |
| 412 | Precondition Failed | ETag precondition not met |
| 413 | Payload Too Large | Body exceeds limits |
| 415 | Unsupported Media Type | Content-Type not supported |

### 7.6 POST Request

**Purpose**: Create a resource with server-assigned URI (typically in containers)

**Request**:
```http
POST {container_uri} HTTP/1.1
Host: {host}
Authorization: DPoP {access_token}
DPoP: {dpop_proof}
Content-Type: {content_type}
Content-Length: {length}
Slug: {suggested_name}  # Optional

{body}
```

**Response - Created (201)**:
```http
HTTP/1.1 201 Created
Content-Type: application/problem+json
Location: {new_uri}
ETag: "{etag}"
Last-Modified: {timestamp}
Content-Length: 0
```

**Status Codes**:
| Code | Meaning | Condition |
|------|---------|-----------|
| 201 | Created | Resource created at Location |
| 401 | Unauthorized | Authentication failed |
| 403 | Forbidden | Not authorized to write |
| 404 | Not Found | Container doesn't exist |
| 405 | Method Not Allowed | POST not allowed on this resource |
| 409 | Conflict | Slug already exists |
| 413 | Payload Too Large | Body exceeds limits |
| 415 | Unsupported Media Type | Content-Type not supported |

### 7.7 PATCH Request

**Purpose**: Partial update of a resource

**Request**:
```http
PATCH {uri} HTTP/1.1
Host: {host}
Authorization: DPoP {access_token}
DPoP: {dpop_proof}
Content-Type: application/sparql-update  # or other patch formats
Content-Length: {length}
If-Match: "{etag}"  # Required for PATCH

{patch_body}
```

**Response - No Content (204)**:
```http
HTTP/1.1 204 No Content
ETag: "{new_etag}"
Last-Modified: {timestamp}
Content-Length: 0
```

**Status Codes**:
| Code | Meaning | Condition |
|------|---------|-----------|
| 204 | No Content | Resource updated |
| 401 | Unauthorized | Authentication failed |
| 403 | Forbidden | Not authorized to write |
| 404 | Not Found | Resource doesn't exist |
| 405 | Method Not Allowed | PATCH not supported for this resource |
| 412 | Precondition Failed | If-Match required but missing or not met |
| 413 | Payload Too Large | Body exceeds limits |
| 415 | Unsupported Media Type | Content-Type not supported |

### 7.8 DELETE Request

**Purpose**: Delete a resource

**Request**:
```http
DELETE {uri} HTTP/1.1
Host: {host}
Authorization: DPoP {access_token}
DPoP: {dpop_proof}
If-Match: "{etag}"  # Required for DELETE
```

**Response - No Content (204)**:
```http
HTTP/1.1 204 No Content
Content-Length: 0
```

**Status Codes**:
| Code | Meaning | Condition |
|------|---------|-----------|
| 204 | No Content | Resource deleted |
| 401 | Unauthorized | Authentication failed |
| 403 | Forbidden | Not authorized to delete |
| 404 | Not Found | Resource doesn't exist |
| 405 | Method Not Allowed | DELETE not supported for this resource |
| 412 | Precondition Failed | If-Match required but missing or not met |

### 7.9 Conditional Requests

**If-Match**: Requires current ETag to match
- If resource ETag matches any value in `If-Match`: Request proceeds
- If no match: 412 Precondition Failed
- If `If-Match: *`: Requires resource to exist (412 if not found)

**If-None-Match**: Requires current ETag NOT to match
- If resource ETag matches any value in `If-None-Match`: 412 Precondition Failed
- If no match: Request proceeds
- If `If-None-Match: *`: Requires resource to NOT exist (412 if found)

### 7.10 ETag Guarantees

| Guarantee | Details |
|-----------|---------|
| **Existence** | Every resource response includes ETag |
| **Uniqueness** | ETag uniquely identifies resource state |
| **Change on write** | ETag changes on every write (PUT, PATCH, DELETE) |
| **Weak vs Strong** | Strong ETags by default, weak if cannot guarantee byte-for-byte |
| **Format** | Double-quoted string (RFC 7232) |

### 7.11 Resource Size Limits

| Limit | Default | Configurable | Notes |
|-------|---------|--------------|-------|
| Max body size | 10 MB | ✅ | Requests exceeding limit return 413 |
| Max header size | 8 KB | ✅ | Headers exceeding limit are rejected |
| Max URI length | 8192 bytes | ✅ | URIs exceeding limit are rejected |

---

## 8. Container Operations

### 8.1 Container Discovery

Containers are resources that contain other resources. They can be discovered via:

1. **Link Header**: Resources in a container include a `Link` header with `rel="acl"` and `rel="describedby"`
2. **GET with Accept**: Request container with `Accept: text/turtle` to get RDF description
3. **Metadata**: Containers have `type` property indicating container type

### 8.2 Container Types

| Type | URI | Description |
|------|-----|-------------|
| Basic Container | `http://www.w3.org/ns/ldp#BasicContainer` | Simple container |
| Direct Container | `http://www.w3.org/ns/ldp#DirectContainer` | Container with membership |

### 8.3 Container Listing

**Request**:
```http
GET {container_uri} HTTP/1.1
Host: {host}
Authorization: DPoP {access_token}
DPoP: {dpop_proof}
Accept: text/turtle
```

**Response**:
```http
HTTP/1.1 200 OK
Content-Type: text/turtle
Link: <{acl_uri}>; rel="acl"
Link: <{metadata_uri}>; rel="describedby"
ETag: "{etag}"
Last-Modified: {timestamp}

@prefix ldp: <http://www.w3.org/ns/ldp#> .
@prefix solid: <http://www.w3.org/ns/solid/terms#> .

<{container_uri}>
    a ldp:BasicContainer ;
    solid:size 42 ;
    ldp:contains 
        <{container_uri}/resource1> ,
        <{container_uri}/resource2> ,
        <{container_uri}/resource3> .
```

### 8.4 Container Creation

**Request**:
```http
PUT {container_uri}/ HTTP/1.1
Host: {host}
Authorization: DPoP {access_token}
DPoP: {dpop_proof}
Content-Type: text/turtle
Content-Length: {length}
If-None-Match: *

@prefix ldp: <http://www.w3.org/ns/ldp#> .
<>
    a ldp:BasicContainer .
```

---

## 9. Policy Resource Contract

### 9.1 Overview

Solid Sidecar supports **Web Access Control (WAC)** and **Access Control Policy (ACP)** for authorization. By default, authorization runs in **SHADOW MODE** - decisions are observed but NOT enforced.

**WARNING**: Policy enforcement requires explicit configuration. Do NOT assume policies are enforced unless you have verified the enforcement mode.

### 9.2 WAC (Web Access Control)

#### WAC Resource Discovery

WAC rules are stored in `.acl` resources alongside the resource they control.

**Link Header**: Resources with WAC include a `Link` header:
```http
Link: <{uri}.acl>; rel="acl"
```

#### WAC Resource Format

```turtle
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<{#resource}>
    acl:accessTo <{resource}> ;
    acl:mode acl:Control ;
    acl:agentClass foaf:Agent ;
    acl:read true ;
    acl:write true ;
    acl:append false .
```

#### WAC Operations

| Operation | Method | WAC Check | Notes |
|-----------|--------|-----------|-------|
| Read | GET, HEAD | ✅ | Checks `acl:read` |
| Write | PUT, POST, PATCH | ✅ | Checks `acl:write` or `acl:append` |
| Delete | DELETE | ✅ | Checks `acl:write` |

### 9.3 ACP (Access Control Policy)

ACP is an alternative to WAC with more fine-grained control. It is **EXPERIMENTAL** in v0.2.0.

#### ACP Resource Discovery

ACP policies are stored in `.acp` resources.

**Link Header**: Resources with ACP include a `Link` header:
```http
Link: <{uri}.acp>; rel="acl"
```

#### ACP Resource Format

```json
{
  "@context": [
    "https://www.w3.org/ns/solid/acp/context.jsonld",
    "https://www.w3.org/ns/auth/acl.jsonld"
  ],
  "policy": [
    {
      "allow": [
        {
          "agent": { "class": "http://xmlns.com/foaf/0.1/Agent" },
          "action": ["read", "write"]
        }
      ],
      "applyTo": "{resource}"
    }
  ]
}
```

### 9.4 Policy Endpoints

**Note**: These endpoints are for **policy resource management**, not authorization decisions.

| Method | Path | Purpose |
|--------|------|---------|
| GET | `{uri}.acl` | Get WAC for resource |
| PUT | `{uri}.acl` | Set WAC for resource |
| DELETE | `{uri}.acl` | Remove WAC from resource |
| GET | `{uri}.acp` | Get ACP for resource |
| PUT | `{uri}.acp` | Set ACP for resource |
| DELETE | `{uri}.acp` | Remove ACP from resource |

### 9.5 Authorization Headers

**Note**: Authorization is handled via DPoP-bound access tokens, not via these headers. These headers are for **future compatibility**.

The sidecar may add the following headers to responses:

| Header | Purpose | Notes |
|--------|---------|-------|
| `WAC-Allow` | WAC permissions | Present when WAC is evaluated |

---

## 10. Notification Contract

### 10.1 Overview

**Status**: ⚠️ EXPERIMENTAL

Solid Sidecar supports **Server-Sent Events (SSE)** and **WebSockets** for notifications. This is based on the Solid Notifications Protocol.

### 10.2 Subscription

**Request** (SSE):
```http
GET /subscriptions/{subscription_id} HTTP/1.1
Host: {host}
Authorization: DPoP {access_token}
DPoP: {dpop_proof}
Accept: text/event-stream
```

**Request** (WebSocket):
```http
GET /subscriptions/{subscription_id} HTTP/1.1
Host: {host}
Authorization: DPoP {access_token}
DPoP: {dpop_proof}
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Protocol: solid-notifications
```

**Response** (SSE):
```http
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive

```

### 10.3 Event Format

**SSE Event**:
```
event: {event_type}
data: {json_event}
id: {event_id}
retry: {reconnect_time}

{json_event}
```

**JSON Event**:
```json
{
  "id": "{event_id}",
  "type": "{event_type}",
  "timestamp": "{iso8601_timestamp}",
  "resource": "{resource_uri}",
  "container": "{container_uri}",
  "agent": "{webid}",
  "action": "{action}",
  "metadata": { ... }
}
```

### 10.4 Event Types

| Type | Description | Trigger |
|------|-------------|---------|
| `ResourceCreated` | Resource was created | PUT/POST to non-existent URI |
| `ResourceUpdated` | Resource was updated | PUT/PATCH to existing URI |
| `ResourceDeleted` | Resource was deleted | DELETE |
| `ContainerCreated` | Container was created | PUT with ldp:Container type |
| `ContainerDeleted` | Container was deleted | DELETE on container |

### 10.5 Subscription Management

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/subscriptions/` | Create subscription |
| GET | `/subscriptions/{id}` | Get subscription (SSE/WS) |
| GET | `/subscriptions/` | List subscriptions |
| DELETE | `/subscriptions/{id}` | Delete subscription |

---

## 11. Error Model

### 11.1 Error Format

All errors return **Problem Details** format (RFC 7807) with JSON content type:

```json
{
  "type": "{uri}",
  "title": "{short_description}",
  "status": {http_status_code},
  "detail": "{detailed_description}",
  "instance": "{request_uri}",
  "request_id": "{request_id}",
  "timestamp": "{iso8601_timestamp}"
}
```

**Additional Fields** (when applicable):
```json
{
  "retry_after": 120,
  "limit": 1000,
  "current": 1001
}
```

### 11.2 Error Types

| Type URI | Title | Status | Description |
|----------|-------|--------|-------------|
| `https://solidproject.org/problem/not-found` | Resource not found | 404 | Resource does not exist |
| `https://solidproject.org/problem/forbidden` | Access denied | 403 | Not authorized |
| `https://solidproject.org/problem/unauthorized` | Authentication required | 401 | Invalid or missing credentials |
| `https://solidproject.org/problem/precondition-failed` | Precondition failed | 412 | If-Match/If-None-Match failed |
| `https://solidproject.org/problem/conflict` | Conflict | 409 | Resource already exists |
| `https://solidproject.org/problem/payload-too-large` | Payload too large | 413 | Body exceeds limits |
| `https://solidproject.org/problem/unsupported-media-type` | Unsupported media type | 415 | Content-Type not supported |
| `https://solidproject.org/problem/method-not-allowed` | Method not allowed | 405 | HTTP method not supported |
| `https://solidproject.org/problem/not-acceptable` | Not acceptable | 406 | Cannot satisfy Accept header |
| `https://solidproject.org/problem/too-many-requests` | Too many requests | 429 | Rate limit exceeded |
| `https://solidproject.org/problem/service-unavailable` | Service unavailable | 503 | Temporary unavailability |

### 11.3 Error Security

**Redaction Rules**:
- ❌ NO access tokens in error responses
- ❌ NO DPoP proofs in error responses
- ❌ NO private resource bodies in error responses
- ❌ NO full stack traces in production
- ✅ Generic error types only
- ✅ Request ID for correlation

**Logging**: All errors are logged with full context (but redacted) for debugging.

---

## 12. Rate Limiting

### 12.1 Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `RateLimit.Enabled` | `true` | Enable rate limiting |
| `RateLimit.RequestsPerWindow` | `100` | Requests per window |
| `RateLimit.Window` | `1m` | Window duration |
| `RateLimit.BurstSize` | `200` | Burst allowance |

### 12.2 Rate Limit Headers

**Response Headers**:
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 30
```

**When Limited**:
```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/problem+json
Retry-After: 30

{
  "type": "https://solidproject.org/problem/too-many-requests",
  "title": "Too many requests",
  "status": 429,
  "detail": "Rate limit exceeded",
  "instance": "{request_id}",
  "request_id": "{request_id}",
  "retry_after": 30
}
```

### 12.3 Per-IP Limiting

Rate limiting is **per-IP address** using fixed-window algorithm. Each IP has its own counter.

---

## 13. Content Negotiation

### 13.1 Supported Content Types

**Request**:
| Content-Type | Format | Notes |
|--------------|--------|-------|
| `text/turtle` | Turtle | ✅ Recommended for RDF |
| `application/ld+json` | JSON-LD | ✅ Full support |
| `application/n-triples` | N-Triples | ✅ Supported |
| `application/rdf+xml` | RDF/XML | ✅ Supported |
| `text/plain` | Plain text | ✅ Supported |
| `application/octet-stream` | Binary | ✅ Supported |

**Response**:
- Server will respond with the most preferred format from the `Accept` header
- If no `Accept` header, defaults to `text/turtle` for RDF resources, `application/octet-stream` for others

### 13.2 Accept Header Processing

**Example**:
```http
Accept: text/turtle;q=1.0, application/ld+json;q=0.8, */*;q=0.1
```

Server will respond with `text/turtle` if available.

---

## 14. Compression

### 14.1 Supported Algorithms

| Algorithm | Request | Response | Notes |
|-----------|---------|----------|-------|
| gzip | ✅ | ✅ | Always available |
| zstd | ✅ | ✅ | Faster, less CPU |
| br | ❌ | ❌ | Not supported |
| deflate | ❌ | ❌ | Not supported (deflate != gzip) |

### 14.2 Compression Headers

**Request**:
```http
Accept-Encoding: gzip, zstd
```

**Response**:
```http
Content-Encoding: gzip  # or zstd
Vary: Accept-Encoding
```

### 14.3 Compression Limits

| Limit | Default | Configurable |
|-------|---------|--------------|
| Max compressed size | 100 MB | ✅ |
| Max decompressed size | 10 MB | ✅ |

---

## 15. CORS

### 15.1 CORS Headers

**Preflight (OPTIONS)**:
```http
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: {origin}
Access-Control-Allow-Methods: GET, HEAD, PUT, POST, PATCH, DELETE, OPTIONS
Access-Control-Allow-Headers: Authorization, DPoP, Content-Type, Accept, Accept-Encoding
Access-Control-Max-Age: 86400
Access-Control-Expose-Headers: ETag, Last-Modified, Link, WAC-Allow
```

**Actual Response**:
```http
Access-Control-Allow-Origin: {origin}
Access-Control-Expose-Headers: ETag, Last-Modified, Link, WAC-Allow
```

### 15.2 CORS Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `CORS.Enabled` | `true` | Enable CORS |
| `CORS.AllowOrigin` | `*` | Allowed origins (comma-separated) |
| `CORS.AllowCredentials` | `false` | Allow credentials |
| `CORS.MaxAge` | `86400` | Preflight cache duration |

---

## 16. Security Guarantees

### 16.1 Authentication Guarantees

| Guarantee | Details |
|-----------|---------|
| **Token Validation** | Every access token is validated (signature, claims, expiration) |
| **DPoP Verification** | Every DPoP proof is verified (signature, binding, nonce) |
| **Replay Protection** | Tokens cannot be reused within the nonce cache window |
| **Key Binding** | DPoP proof is cryptographically bound to access token |
| **Issuer Restriction** | Only tokens from configured issuers are accepted |

### 16.2 Authorization Guarantees

| Guarantee | Details | Notes |
|-----------|---------|-------|
| **Shadow Mode Default** | Authorization decisions are observed but NOT enforced by default |
| **Enforcement Safety** | Enforcement mode requires explicit configuration and comparison evidence |
| **Policy Evaluation** | WAC and ACP policies are evaluated for every request |
| **Decision Caching** | Authorization decisions are cached with smart invalidation |

### 16.3 Transport Security Guarantees

| Guarantee | Details |
|-----------|---------|
| **HTTPS Enforcement** | All outbound requests use HTTPS (no exceptions) |
| **SSRF Protection** | All outbound requests are validated against SSRF attacks |
| **Redirect Blocking** | Automatic redirects are blocked (prevents redirect-based attacks) |
| **IP Validation** | Private, loopback, link-local IPs are blocked |
| **Host Validation** | Localhost, .local, .localhost domains are blocked |

### 16.4 Privacy Guarantees

| Guarantee | Details |
|-----------|---------|
| **No Token Logging** | Access tokens and DPoP proofs are never logged |
| **Redaction** | Sensitive data is automatically redacted in logs |
| **Error Sanitization** | Error responses never contain sensitive information |
| **Header Protection** | Authorization and DPoP headers are never logged |

### 16.5 Rate Limiting Guarantees

| Guarantee | Details |
|-----------|---------|
| **Per-IP Limiting** | Each IP has independent rate limit |
| **Fixed Window** | Uses fixed-window algorithm for predictability |
| **Burst Allowance** | Burst requests are allowed within limits |
| **Auto-Recovery** | Clients can resume after rate limit window passes |

---

## 17. Compatibility Matrix

### 17.1 Solid Protocol Compliance

| Feature | Compliance | Notes |
|---------|------------|-------|
| Authentication (DPoP) | ✅ Full | DPoP-bound Bearer tokens |
| Authorization (WAC) | ✅ Full | Shadow mode, enforcement optional |
| Authorization (ACP) | ✅ Full | Shadow mode, enforcement optional |
| Resource CRUD | ✅ Full | GET, HEAD, PUT, POST, PATCH, DELETE |
| Containers | ✅ Full | Basic Container, Direct Container |
| Content Negotiation | ✅ Full | RDF formats + binary |
| CORS | ✅ Full | Configurable origins |
| Notifications | ⚠️ Experimental | SSE and WebSocket support |
| SAI | ⚠️ Experimental | Solid Application Interoperability |

### 17.2 Solid Spec Compliance

| Specification | Version | Compliance |
|---------------|---------|------------|
| Solid Protocol | 2023 | ✅ Substantial |
| Solid-OIDC | 1.0 | ✅ Full |
| DPoP | RFC 9449 | ✅ Full |
| LDP | 1.0 | ✅ Full |
| WAC | Latest | ✅ Full |
| ACP | Latest | ✅ Full |

---

## 18. Conformance Requirements

### 18.1 Client Requirements

Clients MUST:

1. **Authentication**: Always include DPoP-bound access tokens
2. **Headers**: Include `DPoP` header with proof JWT for every authenticated request
3. **Conditional Writes**: Use `If-Match` for PUT/PATCH/DELETE operations
4. **Error Handling**: Handle all documented error types gracefully
5. **Rate Limiting**: Respect `Retry-After` headers and rate limit responses
6. **Content-Type**: Always specify `Content-Type` for write operations
7. **ETag**: Use ETags for cache validation and conflict detection

### 18.2 Client Recommendations

Clients SHOULD:

1. **Exponential Backoff**: Use exponential backoff for retries (start: 1s, max: 30s)
2. **Connection Pooling**: Reuse HTTP connections
3. **Compression**: Use `Accept-Encoding: gzip, zstd`
4. **Caching**: Cache responses based on `Cache-Control` headers
5. **Validation**: Validate all responses (status codes, content types)
6. **Logging**: Log requests and responses (with sensitive data redacted)

### 18.3 Client Restrictions

Clients MUST NOT:

1. **Reserved Paths**: Use paths under `/admin/`, `/healthz`, `/readyz`, `/metrics`
2. **Credential Exposure**: Include secrets in URLs or headers (other than Authorization/DPoP)
3. **Unsafe Methods**: Use methods other than GET, HEAD, PUT, POST, PATCH, DELETE, OPTIONS
4. **Large Payloads**: Send payloads exceeding 10 MB without chunking
5. **Ignore Errors**: Ignore error responses and assume success

---

## Document Metadata

**Document Owner**: Mistral Vibe  
**Last Updated**: 2026-07-07  
**Next Review**: Before v0.2.0 Beta release  
**Approval Required**: Yes (for Beta release)  

**Related Documents**:
- `docs/client-security.md` - Client Security Requirements (companion document)
- `docs/README.md` - Main documentation
- `docs/v1-product-roadmap.md` - Product roadmap
- `docs/phase-27-sdk-client-compatibility.md` - Phase 27 specification

**Implementation References**:
- `internal/gateway/server.go` - Server implementation
- `internal/proxy/reverse_proxy.go` - Proxy implementation
- `internal/authn/` - Authentication implementation
- `internal/authz/` - Authorization implementation

---

*This document defines Phase 27: SDK/Client Compatibility Layer - Client Contract*
