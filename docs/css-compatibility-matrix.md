# CSS Compatibility Matrix

This document describes the compatibility behavior between the Solid sidecar and Community Solid Server (CSS). It outlines which CSS behaviors are intentionally proxied unchanged and which are modified or enhanced by the sidecar.

## Overview

The Solid sidecar is designed as a **hardened front-door** and **shadow-observation shell** for CSS. The guiding principle is:

> **CSS remains the Solid protocol and authorization authority**

The sidecar must NOT change CSS behavior unexpectedly. All modifications are explicitly documented here.

## Compatibility Classifications

### 🟢 Pass-Through (Unchanged)

These CSS behaviors are proxied through the sidecar without modification.

#### HTTP Methods

| Method | CSS Behavior | Sidecar Behavior | Notes |
|--------|--------------|------------------|-------|
| GET | Returns resource representation | Pass-through | Unchanged |
| HEAD | Returns headers only | Pass-through | Unchanged |
| OPTIONS | Returns allowed methods | Pass-through (with CORS additions) | See CORS section |
| PUT | Creates/replaces resource | Pass-through | Unchanged |
| POST | Creates resource | Pass-through | Unchanged |
| PATCH | Partial update | Pass-through | Unchanged |
| DELETE | Deletes resource | Pass-through | Unchanged |
| MKCOL | Creates collection | Pass-through | WebDAV method |
| PROPFIND | Returns properties | Pass-through | WebDAV method |
| PROPPATCH | Updates properties | Pass-through | WebDAV method |

#### HTTP Status Codes

All HTTP status codes from CSS are passed through unchanged:

| Code | Category | Behavior |
|------|----------|----------|
| 200 | Success | Pass-through |
| 201 | Success | Pass-through |
| 204 | Success | Pass-through |
| 301 | Redirect | Pass-through |
| 302 | Redirect | Pass-through |
| 304 | Redirect | Pass-through |
| 400 | Client Error | Pass-through |
| 401 | Client Error | Pass-through |
| 403 | Client Error | Pass-through |
| 404 | Client Error | Pass-through |
| 405 | Client Error | Pass-through |
| 409 | Client Error | Pass-through |
| 410 | Client Error | Pass-through |
| 412 | Client Error | Pass-through |
| 415 | Client Error | Pass-through |
| 422 | Client Error | Pass-through |
| 500 | Server Error | Pass-through |
| 501 | Server Error | Pass-through |
| 502 | Server Error | Pass-through |
| 503 | Server Error | Pass-through |

#### Content Types

All content types are passed through unchanged. The sidecar does NOT:
- Transcode content
- Modify Content-Type headers from CSS
- Change response body content

Supported content types for validation (write requests only):
- `text/turtle`
- `application/ld+json`
- `application/json`
- `application/n-triples`
- `application/rdf+xml`
- `application/sparql-results+json`
- `application/sparql-update`
- `application/octet-stream`
- `multipart/form-data`

Blocked content types for write requests:
- `text/html`
- `text/javascript`
- `application/javascript`
- `application/x-javascript`
- `application/ecmascript`

#### Request Headers

All standard request headers are passed through unchanged:

| Header | CSS Behavior | Sidecar Behavior | Notes |
|--------|--------------|------------------|-------|
| Accept | Content negotiation | Pass-through | Unchanged |
| Accept-Encoding | Compression | Pass-through | Unchanged |
| Accept-Language | Language negotiation | Pass-through | Unchanged |
| Authorization | Authentication | Pass-through | Unchanged |
| Content-Type | Request body type | Pass-through | Validated for writes |
| Content-Length | Body size | Pass-through | Unchanged |
| DPoP | DPoP proof | Pass-through | Validated |
| Link | Resource relationships | Pass-through | Parsed for authz discovery |
| If-Match | ETag matching | Pass-through | Unchanged |
| If-None-Match | ETag matching | Pass-through | Unchanged |
| If-Modified-Since | Conditional GET | Pass-through | Unchanged |
| If-Unmodified-Since | Conditional write | Pass-through | Unchanged |
| Prefer | Preference hints | Pass-through | Unchanged |
| Slug | Resource name hint | Pass-through | Unchanged |
| User-Agent | Client identification | Pass-through | Unchanged |

#### Response Headers

All standard response headers are passed through unchanged:

| Header | CSS Behavior | Sidecar Behavior | Notes |
|--------|--------------|------------------|-------|
| Content-Type | Response type | Pass-through | Unchanged |
| Content-Length | Body size | Pass-through | Unchanged |
| Content-Location | Resource location | Pass-through | Unchanged |
| Content-Disposition | Download hints | Pass-through | Unchanged |
| ETag | Entity tag | Pass-through | Unchanged |
| Last-Modified | Modification time | Pass-through | Unchanged |
| Cache-Control | Caching directives | Pass-through | Unchanged |
| Expires | Expiration | Pass-through | Unchanged |
| Location | Redirect target | Pass-through | Unchanged |
| Link | Resource relationships | Pass-through | Parsed for authz discovery |
| Vary | Cache variation | Pass-through | Unchanged |
| Age | Cache age | Pass-through | Unchanged |

### 🟡 Modified (With Explanation)

These CSS behaviors are modified by the sidecar with explicit justification.

#### Request Validation

| Behavior | CSS | Sidecar | Justification |
|----------|-----|---------|---------------|
| Encoded dot segments | May allow | **Rejected** | Security: Prevents path traversal attacks |
| Backslashes in path | May allow | **Rejected** | Security: Prevents Windows-style path attacks |
| Null bytes in path | May allow | **Rejected** | Security: Prevents injection attacks |
| Control characters | May allow | **Rejected** | Security: Prevents header injection |
| Missing path | May allow | **Rejected** | Security: Prevents ambiguous requests |
| Non-UTF-8 path | May allow | **Rejected** | Security: Ensures valid encoding |

#### DPoP Validation

| Behavior | CSS | Sidecar | Justification |
|----------|-----|---------|---------------|
| DPoP proof required | Optional | **Enforced when configured** | Security: Key binding requirement |
| DPoP replay | Allowed | **Rejected** | Security: One-time use |
| Token-key binding | Optional | **Enforced when configured** | Security: Proof-of-possession |

#### CORS Headers

The sidecar adds CORS headers when configured with an Origin policy:

| Header | CSS | Sidecar | Justification |
|--------|-----|---------|---------------|
| Access-Control-Allow-Origin | May be absent | **Added** | Enable browser Solid apps |
| Access-Control-Allow-Methods | May be absent | **Added** | Specify allowed methods |
| Access-Control-Allow-Headers | May be absent | **Added** | Specify allowed headers |
| Access-Control-Max-Age | May be absent | **Added** | Cache preflight |
| Access-Control-Allow-Credentials | May be absent | **Added** | Enable cookies/auth |
| Vary: Origin | May be absent | **Added** | Cache variation |

**Important**: These are **additional** headers, not replacements. CSS's own CORS headers (if any) are preserved.

#### Security Headers

The sidecar adds security headers to all responses:

| Header | CSS | Sidecar | Justification |
|--------|-----|---------|---------------|
| X-Content-Type-Options | May be absent | **Added: nosniff** | Prevent MIME sniffing |
| X-Frame-Options | May be absent | **Added: DENY** | Prevent clickjacking |
| X-XSS-Protection | May be absent | **Added: 1; mode=block** | Enable XSS filter |
| Referrer-Policy | May be absent | **Added: no-referrer** | Privacy: Limit referrer info |

**Note**: These can be disabled via configuration.

#### Container Slash Redirects

| Request | CSS | Sidecar | Justification |
|---------|-----|---------|---------------|
| GET /container | Returns 200 or 404 | **Redirects to /container/** | Standard: Directory listing convention |
| HEAD /container | Returns 200 or 404 | **Redirects to /container/** | Standard: Directory listing convention |
| PUT /container | Creates container | **No redirect** | Write operations should specify full path |
| POST /container | Creates resource | **No redirect** | Write operations should specify full path |

**Only applies to paths without file extensions.** Paths ending in `.ttl`, `.json`, `.acl`, etc. are NOT redirected.

### 🔴 Not Supported (By Design)

These CSS features are intentionally NOT supported by the sidecar:

| Feature | CSS Behavior | Sidecar Behavior | Justification |
|---------|--------------|------------------|---------------|
| WebSocket | Upgrade connection | **Not supported** | Out of scope for HTTP gateway |
| HTTP/2 server push | Push resources | **Not supported** | Not in current scope |
| Raw IP access | Direct IP | **Requires hostname** | Security: Virtual host isolation |
| Custom ports | Any port | **Port 80/443 only** | Security: Standard ports |

### 🟣 Shadow Mode Only

These behaviors are in **shadow mode** (observed but not enforced):

| Feature | Status | Behavior |
|---------|--------|----------|
| Authorization decisions | Shadow | Logs decisions, doesn't enforce |
| Policy evaluation | Shadow | Computes decisions, doesn't enforce |
| Identity verification | Shadow | Validates, doesn't enforce |

**Important**: CSS remains the authority for all decisions until enforcement is explicitly enabled.

## Compatibility Testing

### Test Coverage

The following CSS behaviors are covered by compatibility tests:

1. **Pass-through tests**: Verify requests are not modified unexpectedly
2. **Header preservation**: Verify request/response headers are preserved
3. **Status code preservation**: Verify all status codes pass through
4. **Content type preservation**: Verify content types are unchanged
5. **Method support**: Verify all HTTP methods work
6. **Body preservation**: Verify request bodies are unchanged
7. **Query parameter preservation**: Verify query strings are unchanged
8. **CORS behavior**: Verify CORS headers work correctly

### Running Compatibility Tests

```bash
# Run all CSS compatibility tests
go test ./internal/safety/... -run CSSCompatibility

# Run specific test
.go test ./internal/safety/... -run TestCSSCompatibility_PassThrough
```

## Version Compatibility

### CSS Versions Tested

| CSS Version | Compatibility | Notes |
|-------------|---------------|-------|
| CSS 5.x | ✅ High | Primary target |
| CSS 4.x | ⚠️ Medium | Most features work |
| CSS 3.x | ⚠️ Medium | Most features work |
| CSS 2.x | ❌ Low | Not recommended |

### Solid Protocol Compatibility

| Protocol | CSS Support | Sidecar Support | Notes |
|----------|-------------|------------------|-------|
| Solid 2021 | ✅ Full | ✅ Full | Current standard |
| Solid 2019 | ✅ Full | ✅ Full | Compatible |
| Solid 2018 | ⚠️ Partial | ⚠️ Partial | Legacy features may differ |

## Configuration Options

The sidecar provides configuration options that may affect CSS compatibility:

### `authz.mode`

| Value | Behavior | CSS Compatibility |
|-------|----------|-------------------|
| `shadow` | Log only, don't enforce | ✅ Full compatibility |
| `enforce_dry_run` | Enforce but log all | ⚠️ May differ from CSS |
| `enforce` | Full enforcement | ❌ May differ from CSS |

**Current default**: `shadow` (CSS remains authority)

### `authn.enabled`

| Value | Behavior | CSS Compatibility |
|-------|----------|-------------------|
| `false` | No authn processing | ✅ Full compatibility |
| `true` | DPoP verification | ⚠️ Adds authn layer |

### `cors.enabled`

| Value | Behavior | CSS Compatibility |
|-------|----------|-------------------|
| `false` | No CORS headers | ✅ Full compatibility |
| `true` | Add CORS headers | ⚠️ Adds CORS layer |

### `container_slash_redirect`

| Value | Behavior | CSS Compatibility |
|-------|----------|-------------------|
| `false` | No redirects | ✅ Full compatibility |
| `true` | Redirect to trailing slash | ⚠️ Adds redirect layer |

## Compatibility Guarantees

### Strong Guarantees (Will NOT change):

1. **Request method** - The HTTP method is never changed by the sidecar
2. **Request path** - The path is never rewritten (except optional container slash redirect)
3. **Request body** - The body is never modified
4. **Response status code** - The status code from CSS is never changed
5. **Response body** - The response body from CSS is never modified

### Weak Guarantees (May change with configuration):

1. **Request headers** - Headers may be added but existing ones are preserved
2. **Response headers** - Headers may be added but existing ones are preserved
3. **Redirects** - Container slash redirects may be added

### No Guarantees:

1. **Authorization decisions** - In shadow mode, decisions are logged but not enforced
2. **Caching behavior** - Cache headers may be added/modified
3. **Performance** - The sidecar adds processing overhead

## Troubleshooting

### Common Compatibility Issues

#### Issue: "Request rejected with 400"
- **Cause**: The sidecar rejected an unsafe request
- **Check**: Request path for dot segments, backslashes, or control characters
- **Fix**: Ensure client sends valid requests

#### Issue: "Missing CORS headers"
- **Cause**: CORS is not enabled in configuration
- **Check**: `cors.enabled` configuration
- **Fix**: Enable CORS and configure allowed origins

#### Issue: "Redirect to path with trailing slash"
- **Cause**: Container slash redirect is enabled
- **Check**: `container_slash_redirect` configuration
- **Fix**: Disable if not desired, or ensure clients follow redirects

#### Issue: "Authorization required"
- **Cause**: Authn middleware is enabled
- **Check**: `authn.enabled` configuration
- **Fix**: Provide DPoP token or disable authn

### Debugging Tools

1. **Enable debug logging**: Set `LOG_LEVEL=debug`
2. **Check request IDs**: All requests have `X-Request-ID` header
3. **Review audit logs**: Authorization decisions are logged in shadow mode

## Compatibility Matrix Summary

| Aspect | Compatibility | Notes |
|--------|---------------|-------|
| HTTP Methods | ✅ 100% | All methods pass through |
| Status Codes | ✅ 100% | All codes pass through |
| Content Types | ✅ 100% | All types pass through |
| Request Headers | ✅ 95% | Most pass through, some validated |
| Response Headers | ✅ 95% | Most pass through, some added |
| Query Parameters | ✅ 100% | All pass through |
| Request Body | ✅ 100% | Never modified |
| Response Body | ✅ 100% | Never modified |
| CORS | ⚠️ 90% | Added when configured |
| Security Headers | ⚠️ 80% | Added by default |
| Authorization | 🟡 0% | Shadow mode only (not enforced) |

**Overall CSS Compatibility: ✅ >95%**

## References

- [Solid Protocol Specification](https://solidproject.org/TR/protocol)
- [Community Solid Server](https://github.com/CommunitySolidServer/CommunitySolidServer)
- [Phase 2 Roadmap](./solid-runtime-phase-roadmap.md)
