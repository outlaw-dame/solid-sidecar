# Solid Sidecar Client Security Requirements

**Document Type**: Security Specification  
**Version**: v1.0.0  
**Created**: 2026-07-07  
**Author**: Mistral Vibe  
**Phase**: 27 - SDK/Client Compatibility Layer  
**Status**: ✅ DRAFT - Under Active Development  
**Classification**: RESTRICTED - Security Sensitive  

---

## ⚠️ SECURITY WARNING

> **THIS DOCUMENT CONTAINS SECURITY-SENSITIVE INFORMATION**
>
> **DO NOT**:
> - Store this document in unencrypted form
> - Share this document outside the project team
> - Commit sensitive examples to public repositories
> - Use example credentials in production
>
> **DO**:
> - Review this document before implementing any client
> - Follow all security requirements strictly
> - Audit all implementations against this document
> - Report any security concerns immediately

---

## Table of Contents

1. [Security Overview](#1-security-overview)
2. [Threat Model](#2-threat-model)
3. [Authentication Security](#3-authentication-security)
4. [Authorization Security](#4-authorization-security)
5. [Transport Security](#5-transport-security)
6. [Data Security](#6-data-security)
7. [Input Validation](#7-input-validation)
8. [Output Encoding](#8-output-encoding)
9. [Error Handling](#9-error-handling)
10. [Rate Limiting and DoS Protection](#10-rate-limiting-and-dos-protection)
11. [Cryptographic Requirements](#11-cryptographic-requirements)
12. [Key Management](#12-key-management)
13. [Session Security](#13-session-security)
14. [CORS Security](#14-cors-security)
15. [CSRF Protection](#15-csrf-protection)
16. [SSRF Protection](#16-ssrf-protection)
17. [IDOR Prevention](#17-idor-prevention)
18. [Injection Prevention](#18-injection-prevention)
19. [Information Disclosure Prevention](#19-information-disclosure-prevention)
20. [Logging and Auditing](#20-logging-and-auditing)
21. [Dependency Security](#21-dependency-security)
22. [Secure Defaults](#22-secure-defaults)
23. [Security Testing Requirements](#23-security-testing-requirements)
24. [Incident Response](#24-incident-response)
25. [Security Checklist](#25-security-checklist)

---

## 1. Security Overview

### 1.1 Purpose

This document defines **MANDATORY security requirements** for all Solid Sidecar client implementations. Every client SDK (TypeScript, Go, Rust), example, and integration MUST comply with these requirements.

**Violations of this document are security vulnerabilities.**

### 1.2 Scope

This document applies to:
- TypeScript/JS client SDK (`sdk/ts/`)
- Go client SDK (`sdk/go/`)
- Rust client crate (`rust/solid-sidecar-client/`)
- HTTP examples (`examples/clients/http/`)
- TypeScript examples (`examples/clients/typescript/`)
- Integration tests (`test/integration/`)
- Any code that communicates with Solid Sidecar

### 1.3 Security Principles

All client implementations MUST follow these principles:

1. **Defense in Depth**: Multiple layers of security controls
2. **Fail Secure**: Default to secure behavior on error
3. **Least Privilege**: Minimum necessary permissions
4. **Never Trust, Always Verify**: Validate all inputs, never assume
5. **Redact by Default**: Sensitive data is never logged or exposed
6. **Explicit Over Implicit**: Security behavior must be explicit
7. **Minimal Surface Area**: Smallest possible attack surface

### 1.4 Security Classification

| Classification | Description | Examples |
|---------------|-------------|----------|
| **CRITICAL** | Must be implemented, no exceptions | Token validation, DPoP binding |
| **HIGH** | Must be implemented, rare exceptions | HTTPS enforcement, SSRF protection |
| **MEDIUM** | Should be implemented | Rate limiting, input validation |
| **LOW** | Recommended | Connection pooling, caching |

---

## 2. Threat Model

### 2.1 Assets

| Asset | Confidentiality | Integrity | Availability |
|-------|----------------|-----------|--------------|
| User Data | ✅ HIGH | ✅ HIGH | ✅ HIGH |
| Access Tokens | ✅ CRITICAL | ✅ CRITICAL | ✅ HIGH |
| DPoP Private Keys | ✅ CRITICAL | ✅ CRITICAL | ✅ HIGH |
| WebID Profiles | ✅ MEDIUM | ✅ MEDIUM | ✅ MEDIUM |
| Policy Resources | ✅ HIGH | ✅ CRITICAL | ✅ MEDIUM |
| Resource Metadata | ✅ LOW | ✅ HIGH | ✅ MEDIUM |

### 2.2 Threat Actors

| Actor | Capability | Motivation |
|-------|------------|------------|
| **Unauthenticated Remote** | Network access, no credentials | Data theft, vandalism |
| **Authenticated User** | Valid credentials, normal access | Data theft, privilege escalation |
| **Compromised Client** | Full client control, user credentials | Lateral movement, data exfiltration |
| **Malicious Server** | Control of Solid Sidecar instance | Credential harvesting, MITM |
| **Network Observer** | Passive monitoring, MITM capability | Eavesdropping, data theft |

### 2.3 Attack Surface

| Component | Attack Surface | Risk |
|-----------|----------------|------|
| Authentication | Token theft, replay, forgery | CRITICAL |
| Authorization | Policy bypass, privilege escalation | CRITICAL |
| Transport | Eavesdropping, MITM, injection | CRITICAL |
| Data Storage | Local data theft, tampering | HIGH |
| Key Storage | Private key extraction | CRITICAL |
| Network | SSRF, DoS, injection | HIGH |

---

## 3. Authentication Security

### 3.1 Token Security (CRITICAL)

#### 3.1.1 Token Storage

**MUST**:
- Store access tokens in **secure storage** only:
  - **Browser**: `HttpOnly`, `Secure`, `SameSite=Strict` cookies OR Web Crypto API
  - **Node.js**: Environment variables OR encrypted file storage
  - **iOS**: Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
  - **Android**: Android Keystore with `PURPOSE_SIGN`
  - **React Native**: Secure storage library (react-native-keychain, expo-secure-store)
  - **Flutter**: flutter_secure_storage
  - **Electron**: safeStorage

**MUST NOT**:
- ❌ Store tokens in localStorage
- ❌ Store tokens in sessionStorage
- ❌ Store tokens in plaintext files
- ❌ Store tokens in memory without secure clearing
- ❌ Store tokens in logs
- ❌ Store tokens in URLs

#### 3.1.2 Token Transmission

**MUST**:
- Always use HTTPS (TLS 1.2+) for token transmission
- Include tokens in `Authorization: DPoP {token}` header only
- Never include tokens in URLs (query parameters, path)
- Verify certificate validity (no `NODE_TLS_rejectUnauthorized=0`)

**MUST NOT**:
- ❌ Send tokens over HTTP
- ❌ Send tokens in URL parameters
- ❌ Send tokens in URL fragments
- ❌ Send tokens in cookies (unless HttpOnly+Secure)
- ❌ Disable certificate validation

#### 3.1.3 Token Validation

Clients **MUST** validate received tokens (if applicable):
- Signature verification (JWS)
- Required claims present (`iss`, `sub`, `aud`, `exp`, `cnf`)
- `iss` is in allowed issuers list
- `aud` matches client identifier
- `exp` is in the future
- `cnf.jkt` matches expected key thumbprint

**MUST NOT**:
- ❌ Accept tokens without validation
- ❌ Accept tokens with invalid signatures
- ❌ Accept tokens with missing required claims
- ❌ Accept tokens from untrusted issuers
- ❌ Accept expired tokens

#### 3.1.4 Token Lifecycle

**MUST**:
- Request shortest practical token lifetime from issuer
- Refresh tokens **before** expiration (recommended: 5 minutes before)
- Handle token refresh failures by:
  1. Queuing pending requests
  2. Retrying with new token
  3. Failing gracefully if refresh fails
- Clear tokens on logout
- Clear tokens on session timeout

**MUST NOT**:
- ❌ Use tokens past expiration
- ❌ Cache tokens indefinitely
- ❌ Continue using invalidated tokens
- ❌ Leak tokens during refresh

### 3.2 DPoP Security (CRITICAL)

#### 3.2.1 DPoP Proof Generation

**MUST**:
- Generate DPoP proof for **EVERY** authenticated request
- Include all required claims:
  - `typ`: `dpop+jwt`
  - `jwk`: Public key (RSA only, RS256)
  - `htu`: Full HTTP URI (method + path + query)
  - `htm`: HTTP method (uppercase)
  - `iat`: Issued at timestamp
  - `ath`: SHA-256 hash of access token
- Sign with private key corresponding to `jwk`
- Use RS256 algorithm only

**MUST NOT**:
- ❌ Reuse DPoP proofs across requests
- ❌ Use EC keys (only RSA supported by server)
- ❌ Use algorithms other than RS256
- ❌ Omit required claims
- ❌ Use weak key sizes (< 2048 bits for RSA)

#### 3.2.2 Key Generation

**MUST**:
- Generate RSA keys with **minimum 2048 bits** (3072+ recommended)
- Use cryptographically secure random number generator
- Store private keys in secure storage (see Token Storage)
- Rotate keys periodically (recommended: 90 days)
- Handle key rotation without breaking existing sessions

**MUST NOT**:
- ❌ Use keys < 2048 bits
- ❌ Use predictable seeds for key generation
- ❌ Store private keys in plaintext
- ❌ Reuse keys across different clients/users

#### 3.2.3 Nonce Handling

**MUST**:
- Track server-provided nonces
- Include nonce in DPoP proof if provided
- Reject responses with unknown nonces
- Clear nonce cache periodically

**MUST NOT**:
- ❌ Reuse nonces
- ❌ Ignore nonce requirements

#### 3.2.4 DPoP/Token Binding

**MUST**:
- Cryptographically bind DPoP proof to access token via `ath` claim
- `ath` = SHA-256(access_token_bytes)
- Ensure `jwk` thumbprint matches token's `cnf.jkt`

**MUST NOT**:
- ❌ Send DPoP with wrong token binding
- ❌ Send DPoP with mismatched key

### 3.3 WebID Security (HIGH)

#### 3.3.1 WebID Resolution

**MUST**:
- Validate WebID URIs before resolution
- Only resolve WebIDs over HTTPS
- Implement timeout for resolution (max 5 seconds)
- Limit recursion depth (max 5 redirects)
- Block SSRF targets (localhost, private IPs, etc.)

**MUST NOT**:
- ❌ Resolve WebIDs over HTTP
- ❌ Follow infinite redirects
- ❌ Resolve arbitrary URIs as WebIDs
- ❌ Trust unauthenticated WebID documents

#### 3.3.2 WebID Validation

**MUST**:
- Validate WebID document structure
- Verify WebID matches token `sub` claim
- Check for deactivation
- Validate against known WebID profiles

---

## 4. Authorization Security

### 4.1 Policy Evaluation (CRITICAL)

**MUST**:
- **NEVER** assume authorization based on local policy evaluation alone
- **ALWAYS** respect server's authorization decisions
- Treat shadow mode as "observed but not enforced"
- Only enable enforcement mode with explicit server configuration

**MUST NOT**:
- ❌ Bypass server authorization decisions
- ❌ Cache authorization decisions without invalidation
- ❌ Assume enforcement is active without verification

### 4.2 WAC Security (HIGH)

**MUST**:
- Validate WAC document structure
- Check for required properties (`accessTo`, `mode`, agent, actions)
- Validate WebID URIs in policies
- Limit policy size (max 100KB)
- Limit rule count (max 1000 rules)

**MUST NOT**:
- ❌ Accept malformed WAC documents
- ❌ Process WAC with unlimited size
- ❌ Trust WAC from untrusted sources

### 4.3 ACP Security (HIGH)

**MUST**:
- Validate ACP JSON structure
- Check `@context` for required contexts
- Validate `policy` array structure
- Limit document size (max 100KB)
- Limit action count per rule (max 10)

**MUST NOT**:
- ❌ Accept malformed ACP documents
- ❌ Process ACP with unlimited nesting
- ❌ Trust ACP from untrusted sources

### 4.4 IDOR Prevention (CRITICAL)

**MUST**:
- **ALWAYS** verify resource ownership before operations
- Check that client has access to resource before any read/write
- Use server-side authorization, not client-side assumptions
- For container listings, verify client can access container
- For resource operations, verify client can access resource

**MUST NOT**:
- ❌ Trust client-provided resource URIs without verification
- ❌ Allow access to resources based on URL pattern alone
- ❌ Assume same-user access for all resources

**IDOR Checklist**:
- [ ] Every GET verifies read access
- [ ] Every PUT/POST/PATCH/DELETE verifies write access
- [ ] Container listings verify container access
- [ ] Policy reads verify policy access
- [ ] All operations respect server authorization

---

## 5. Transport Security

### 5.1 HTTPS Requirements (CRITICAL)

**MUST**:
- Use HTTPS for ALL connections in production
- Use TLS 1.2 or higher (TLS 1.3 recommended)
- Enable certificate validation (ALWAYS)
- Use modern cipher suites only:
  - TLS_AES_256_GCM_SHA384
  - TLS_CHACHA20_POLY1305_SHA256
  - TLS_AES_128_GCM_SHA256
  - ECDHE-ECDSA-AES256-GCM-SHA384
  - ECDHE-RSA-AES256-GCM-SHA384
- Disable weak protocols: SSLv3, TLS 1.0, TLS 1.1
- Disable weak cipher suites: DES, 3DES, RC4, CBC mode

**MUST NOT**:
- ❌ Use HTTP in production
- ❌ Use TLS < 1.2
- ❌ Disable certificate validation
- ❌ Use weak cipher suites

### 5.2 SSRF Protection (CRITICAL)

**MUST**:
- Validate ALL outbound URLs before making requests
- Block private IP ranges:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
  - 127.0.0.0/8 (loopback)
  - 169.254.0.0/16 (link-local)
  - ::1/128 (IPv6 loopback)
  - fc00::/7 (IPv6 unique local)
  - fe80::/10 (IPv6 link-local)
- Block reserved hostnames:
  - localhost
  - *.localhost
  - *.local
  - .local
  - loopback
- Block arbitrary port access
- Only allow HTTPS URLs
- Implement timeout for outbound requests (max 10 seconds)
- Disable automatic redirects

**MUST NOT**:
- ❌ Make requests to arbitrary user-provided URLs
- ❌ Follow redirects to internal addresses
- ❌ Access private network ranges

### 5.3 Connection Security

**MUST**:
- Implement connection timeouts (max 30 seconds)
- Implement read/write timeouts (max 30 seconds)
- Limit concurrent connections per host (max 100)
- Use connection pooling with limits
- Validate server certificates:
  - Check against CA bundle
  - Verify hostname matches certificate
  - Check expiration
  - Check revocation (OCSP/CRL if available)

**MUST NOT**:
- ❌ Have unbounded connection timeouts
- ❌ Ignore certificate errors
- ❌ Allow unlimited concurrent connections

---

## 6. Data Security

### 6.1 Data at Rest (HIGH)

**MUST**:
- Encrypt sensitive data at rest:
  - Access tokens
  - DPoP private keys
  - User data (if cached locally)
- Use platform-native encryption:
  - iOS: Data Protection API
  - Android: EncryptedSharedPreferences
  - Node.js: Encrypted file system
  - Browser: IndexedDB with encryption

**MUST NOT**:
- ❌ Store sensitive data unencrypted
- ❌ Use weak encryption (DES, RC4, single DES)

### 6.2 Data in Transit (CRITICAL)

**MUST**:
- Encrypt ALL data in transit with HTTPS
- Use forward secrecy (ECDHE cipher suites)
- Verify server identity before sending data

**MUST NOT**:
- ❌ Send data over unencrypted connections
- ❌ Send data over HTTP in production

### 6.3 Data in Memory (MEDIUM)

**MUST**:
- Clear sensitive data from memory when no longer needed
- Use secure memory clearing (overwrite with zeros)
- Limit sensitive data retention time
- Use immutable data structures for sensitive data

**MUST NOT**:
- ❌ Retain sensitive data in memory indefinitely
- ❌ Allow sensitive data to be swapped to disk

### 6.4 Cache Security (MEDIUM)

**MUST**:
- Implement cache invalidation on write operations
- Respect server `Cache-Control` headers
- Limit cache size (max 100MB per client)
- Implement cache TTL (max 1 hour)
- Clear cache on authentication changes

**MUST NOT**:
- ❌ Serve stale data after write operations
- ❌ Cache sensitive responses indefinitely
- ❌ Cache responses without validation

---

## 7. Input Validation

### 7.1 URI Validation (CRITICAL)

**MUST**:
- Validate ALL URIs before use
- Reject URIs that:
  - Contain `..` or `.` path segments (after normalization)
  - Exceed 8192 bytes
  - Contain null bytes
  - Contain invalid UTF-8
  - Use unsupported schemes (only `http`, `https`)
- Normalize URIs before processing
- Reject reserved paths:
  - `/admin/`
  - `/healthz`
  - `/readyz`
  - `/metrics`
  - `/sai/`
  - `/.well-known/`

**MUST NOT**:
- ❌ Process URIs without validation
- ❌ Allow path traversal
- ❌ Allow access to reserved paths

### 7.2 Header Validation (HIGH)

**MUST**:
- Validate header names:
  - Must be valid HTTP token (RFC 7230)
  - Must not exceed 8KB per header
  - Must not contain null bytes
- Validate header values:
  - Must not exceed 8KB
  - Must not contain null bytes
  - Must be valid UTF-8 (or ASCII for certain headers)
- Reject headers with:
  - Non-ASCII characters in certain contexts
  - Control characters
  - Leading/trailing whitespace (except where allowed)

**MUST NOT**:
- ❌ Forward malformed headers
- ❌ Allow unlimited header size

### 7.3 Body Validation (HIGH)

**MUST**:
- Validate `Content-Length`:
  - Must not exceed 10MB (default, configurable)
  - Must match actual body size
- Validate body content:
  - Must not contain null bytes (for text formats)
  - Must be valid UTF-8 for text formats
  - Must not exceed size limits for RDF formats
- For RDF formats:
  - Validate structure
  - Limit triple count (max 100,000)
  - Limit blank node count (max 10,000)
  - Limit IRIs per resource (max 100,000)

**MUST NOT**:
- ❌ Process bodies without size limits
- ❌ Allow unlimited RDF document size

### 7.4 Query Parameter Validation (HIGH)

**MUST**:
- Validate query parameter names and values
- Reject parameters that:
  - Exceed 1024 bytes per parameter
  - Exceed 8192 bytes total
  - Contain null bytes
  - Contain control characters

**MUST NOT**:
- ❌ Process unbounded query parameters

---

## 8. Output Encoding

### 8.1 Response Body Encoding (HIGH)

**MUST**:
- Validate all response bodies before use
- Sanitize HTML/XML content if rendering in browser
- Escape special characters when displaying
- Validate content types match expected types

**MUST NOT**:
- ❌ Render raw response bodies as HTML
- ❌ Trust `Content-Type` header without validation

### 8.2 Error Message Encoding (CRITICAL)

**MUST**:
- **NEVER** include sensitive information in error messages
- Redact ALL of the following from errors:
  - Access tokens
  - DPoP proofs
  - Private keys
  - User credentials
  - WebID values (partial redaction acceptable)
  - Resource URIs (if sensitive)
  - Full stack traces (in production)
- Use generic error messages for end users
- Include request ID for debugging

**MUST NOT**:
- ❌ Return access tokens in error responses
- ❌ Return DPoP proofs in error responses
- ❌ Return private keys in error responses
- ❌ Return stack traces to end users

### 8.3 Logging Encoding (CRITICAL)

**MUST**:
- **NEVER** log sensitive information:
  - Access tokens
  - DPoP proofs
  - Private keys
  - User credentials
  - Authorization/DPoP headers
  - Full request/response bodies for sensitive resources
- Redact sensitive fields automatically
- Use structured logging with redaction
- Include request ID for correlation

**Redaction Patterns** (MUST be applied):
```
- Bearer tokens: Redact entire value
- DPoP proofs: Redact entire value
- Private keys: Redact entire value
- Passwords: Redact entire value
- WebIDs: Partial redaction (keep domain, redact path)
- URIs: Partial redaction for sensitive paths
```

**MUST NOT**:
- ❌ Log raw access tokens
- ❌ Log raw DPoP proofs
- ❌ Log private keys
- ❌ Log Authorization/DPoP headers

---

## 9. Error Handling

### 9.1 Error Classification (CRITICAL)

**MUST** classify errors into:

| Category | Retryable | Action |
|----------|-----------|--------|
| **Network Error** | ✅ | Retry with exponential backoff |
| **Timeout** | ✅ | Retry with exponential backoff |
| **Rate Limited (429)** | ✅ | Retry after `Retry-After` |
| **Service Unavailable (503)** | ✅ | Retry with exponential backoff |
| **Authentication Error (401)** | ❌ | Do NOT retry, fail gracefully |
| **Authorization Error (403)** | ❌ | Do NOT retry, fail gracefully |
| **Not Found (404)** | ❌ | Do NOT retry, fail gracefully |
| **Bad Request (400)** | ❌ | Do NOT retry, fail gracefully |
| **Precondition Failed (412)** | ❌ | Do NOT retry, report to user |

### 9.2 Retry Strategy (CRITICAL)

**MUST** implement exponential backoff with jitter:

```
Base delay: 1 second
Max delay: 30 seconds
Max attempts: 5 (configurable)
Jitter: ±25% random

Delay calculation:
  delay = min(base * 2^attempt + jitter, max_delay)
```

**MUST**:
- Respect `Retry-After` header when present
- Implement circuit breaker pattern:
  - Failures threshold: 5 consecutive failures
  - Recovery timeout: 30 seconds
  - Half-open test: 1 request
- Differentiate between retryable and non-retryable errors
- Clear circuit breaker on success

**MUST NOT**:
- ❌ Retry authentication errors
- ❌ Retry indefinitely
- ❌ Ignore `Retry-After` header
- ❌ Retry without backoff

### 9.3 Error Propagation (HIGH)

**MUST**:
- Preserve error context through the stack
- Include request ID in all errors
- Wrap errors, don't lose them
- Provide actionable error messages to callers

**MUST NOT**:
- ❌ Swallow errors silently
- ❌ Lose error context
- ❌ Expose internal errors to end users

---

## 10. Rate Limiting and DoS Protection

### 10.1 Client-Side Rate Limiting (MEDIUM)

**MUST**:
- Respect server rate limits
- Implement client-side request throttling
- Limit concurrent requests per host (max 10)
- Implement request queuing

**MUST NOT**:
- ❌ Flood server with requests
- ❌ Ignore rate limit headers

### 10.2 DoS Protection (HIGH)

**MUST**:
- Limit request size (max 10MB)
- Limit header size (max 8KB)
- Limit URI length (max 8192)
- Limit concurrent connections (max 100 per host)
- Implement request timeouts (max 30 seconds)

**MUST NOT**:
- ❌ Allow unbounded request sizes
- ❌ Allow unlimited concurrent connections

---

## 11. Cryptographic Requirements

### 11.1 Algorithms (CRITICAL)

**MUST USE**:
- **Symmetric**: AES-256-GCM (for data encryption)
- **Asymmetric**: RSA-2048+, RSA-3072 recommended (for signing)
- **Hash**: SHA-256, SHA-384, SHA-512
- **HMAC**: HMAC-SHA-256, HMAC-SHA-384
- **KDF**: PBKDF2, Argon2
- **RNG**: Cryptographically secure (CSPRNG)

**MUST NOT USE**:
- ❌ DES, 3DES, RC4, RC5, RC6
- ❌ MD5, SHA-1
- ❌ ECB mode
- ❌ CBC mode without integrity
- ❌ Non-CSPRNG random sources

### 11.2 Key Sizes (CRITICAL)

| Algorithm | Minimum | Recommended | Notes |
|-----------|---------|-------------|-------|
| RSA | 2048 bits | 3072 bits | Signing only |
| ECDSA | 256 bits | 384 bits | Not supported by server |
| AES | 256 bits | 256 bits | GCM mode only |
| SHA | 256 bits | 384 bits | SHA-2 family |

### 11.3 JOSE Requirements (CRITICAL)

**MUST**:
- Use JWS (JSON Web Signature) for DPoP proofs
- Use JWK (JSON Web Key) for key representation
- Use RS256 algorithm for signatures
- Validate all JWS signatures
- Validate all JWK parameters

**MUST NOT**:
- ❌ Use none algorithm
- ❌ Use symmetric algorithms for DPoP
- ❌ Skip JWS/JWK validation

---

## 12. Key Management

### 12.1 Key Generation (CRITICAL)

**MUST**:
- Use platform-native key generation:
  - **Browser**: Web Crypto API `window.crypto.subtle.generateKey()`
  - **Node.js**: `crypto.generateKeyPair()`
  - **iOS**: SecKeyCreateRandomKey
  - **Android**: KeyPairGenerator
  - **Go**: `crypto/rand` + `crypto/rsa`
  - **Rust**: `ring` or `rust-crypto`
- Use minimum 2048-bit RSA keys
- Use CSPRNG for all random values

**MUST NOT**:
- ❌ Use predictable key generation
- ❌ Use keys < 2048 bits
- ❌ Reuse keys across clients

### 12.2 Key Storage (CRITICAL)

**MUST** use platform-native secure storage:

| Platform | API | Notes |
|----------|-----|-------|
| Browser | Web Crypto + IndexedDB | Encrypt with Web Crypto |
| Node.js | Environment variables + encrypted file | Use `dotenv` + encryption |
| iOS | Keychain | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` |
| Android | Android Keystore | `PURPOSE_SIGN`, `DIGEST_NONE` |
| React Native | react-native-keychain | Secure storage |
| Flutter | flutter_secure_storage | Secure storage |
| Electron | safeStorage | Encrypted storage |
| Go | Platform keyring | `github.com/99designs/keyring` |
| Rust | Platform-specific | Use OS keychain |

**MUST NOT**:
- ❌ Store private keys in plaintext
- ❌ Store private keys in localStorage
- ❌ Store private keys in sessionStorage
- ❌ Store private keys in config files

### 12.3 Key Rotation (HIGH)

**MUST**:
- Rotate DPoP keys periodically (recommended: 90 days)
- Handle key rotation without breaking sessions
- Generate new key before old key expires
- Sign new DPoP proofs with new key
- Server must accept proofs from both old and new keys during transition

**MUST NOT**:
- ❌ Use same key indefinitely
- ❌ Rotate keys without transition period

### 12.4 Key Destruction (MEDIUM)

**MUST**:
- Securely clear private key memory when no longer needed
- Overwrite key material with zeros
- Ensure key is not recoverable after destruction

---

## 13. Session Security

### 13.1 Session Management (HIGH)

**MUST**:
- Generate unique session ID for each session
- Store session state securely
- Implement session timeout (recommended: 24 hours)
- Clear session on logout
- Clear session on token expiration

**MUST NOT**:
- ❌ Use predictable session IDs
- ❌ Store session in URL
- ❌ Store session in localStorage without encryption

### 13.2 Session Timeout (MEDIUM)

**MUST**:
- Implement idle timeout (recommended: 30 minutes)
- Implement absolute timeout (recommended: 24 hours)
- Clear all session data on timeout
- Notify user before timeout

### 13.3 Concurrent Session Handling (MEDIUM)

**MUST**:
- Handle concurrent requests from same session
- Use session-level locking for critical operations
- Prevent race conditions in session state

---

## 14. CORS Security

### 14.1 CORS Configuration (HIGH)

**MUST**:
- Configure CORS only for trusted origins
- Never use `Access-Control-Allow-Origin: *` in production
- Always include `Vary: Origin` header
- Validate `Origin` header against allowed list

**MUST NOT**:
- ❌ Allow arbitrary origins in production
- ❌ Allow credentials with `*` origin

### 14.2 Preflight Handling (MEDIUM)

**MUST**:
- Implement OPTIONS endpoint for preflight
- Cache preflight responses (max 86400 seconds)
- Validate preflight request headers

---

## 15. CSRF Protection

### 15.1 CSRF Tokens (MEDIUM)

**MUST**:
- Implement CSRF protection for state-changing operations
- Generate unique CSRF token per session
- Include CSRF token in:
  - Form submissions
  - State-changing requests
- Validate CSRF token on server (if applicable)

**MUST NOT**:
- ❌ Use predictable CSRF tokens
- ❌ Reuse CSRF tokens

### 15.2 SameSite Cookies (MEDIUM)

**MUST**:
- Use `SameSite=Strict` or `SameSite=Lax` for cookies
- Never use `SameSite=None` without `Secure`

---

## 16. SSRF Protection

### 16.1 Outbound Request Validation (CRITICAL)

**MUST** implement multi-layered SSRF protection:

#### Layer 1: URL Scheme Validation
```
ALLOW: https
BLOCK: http, ftp, file, data, javascript, mailto, etc.
```

#### Layer 2: Host Validation
```
BLOCK:
- localhost
- *.localhost
- *.local
- .local
- 127.0.0.1
- ::1
- any bare hostname without dots
```

#### Layer 3: IP Address Validation
```
BLOCK:
- 10.0.0.0/8 (Private)
- 172.16.0.0/12 (Private)
- 192.168.0.0/16 (Private)
- 127.0.0.0/8 (Loopback)
- 169.254.0.0/16 (Link-local)
- 0.0.0.0/8 (Current network)
- 100.64.0.0/10 (Carrier-grade NAT)
- 192.0.0.0/24 (IETF Protocol Assignments)
- 192.0.2.0/24 (TEST-NET-1)
- 198.51.100.0/24 (TEST-NET-2)
- 203.0.113.0/24 (TEST-NET-3)
- 224.0.0.0/4 (Multicast)
- ::1/128 (IPv6 Loopback)
- fc00::/7 (IPv6 Unique Local)
- fe80::/10 (IPv6 Link-local)
- ff00::/8 (IPv6 Multicast)
```

#### Layer 4: Port Validation
```
BLOCK:
- Ports < 1 (Invalid)
- Ports > 65535 (Invalid)
- Well-known ports that should not be accessed (22, 23, 25, etc.)
```

#### Layer 5: DNS Resolution Validation
```
- Resolve hostname to IP
- Validate ALL resolved IPs against blocklist
- Fail if ANY IP is blocked
```

#### Layer 6: Redirect Blocking
```
- Never follow automatic redirects
- Explicitly handle each redirect
- Re-validate redirect target
```

**MUST NOT**:
- ❌ Make requests to arbitrary URLs
- ❌ Follow redirects automatically
- ❌ Access internal network addresses
- ❌ Access localhost or private addresses

### 16.2 Safe Defaults (CRITICAL)

**MUST**:
- Default to **blocking** all outbound requests
- Only allow outbound requests to explicitly configured hosts
- Require explicit opt-in for outbound request features

---

## 17. IDOR Prevention

### 17.1 Resource Access Control (CRITICAL)

**MUST** implement the following checks for EVERY request:

```
FOR EVERY REQUEST:
1. Extract resource URI from request
2. Extract WebID from access token
3. Query server for authorization decision
4. Verify WebID has access to resource
5. Verify access mode (read/write) is permitted
6. Proceed ONLY if all checks pass
```

**MUST NOT**:
- ❌ Trust client-provided resource URIs
- ❌ Assume access based on URL patterns
- ❌ Cache authorization decisions without resource context

### 17.2 Container Access (HIGH)

**MUST**:
- Verify client can access container before listing
- Verify client can access container before creating resources
- Check container ACL for each operation

### 17.3 Policy Access (HIGH)

**MUST**:
- Verify client can access policy resource before reading
- Verify client can modify policy resource before writing
- Check policy ACL for each policy operation

### 17.4 Testing IDOR Protection (CRITICAL)

**MUST** implement integration tests that:
1. Create resources with different owners
2. Attempt to access each other's resources
3. Verify all cross-owner access is blocked
4. Verify all same-owner access is allowed
5. Test with:
   - Different users
   - Different containers
   - Different resource types
   - Different access modes (read, write, control)

---

## 18. Injection Prevention

### 18.1 HTTP Header Injection (CRITICAL)

**MUST**:
- Validate all header values
- Reject headers containing:
  - Newlines (`\r`, `\n`)
  - Null bytes
  - Control characters
- Use platform-native header setting (not string concatenation)

**MUST NOT**:
- ❌ Concatenate user input into headers
- ❌ Allow CRLF in header values

### 18.2 RDF Injection (HIGH)

**MUST**:
- Validate all RDF input
- Limit RDF document size (max 10MB)
- Limit triple count (max 100,000)
- Limit blank node count (max 10,000)
- Validate IRIs (max length: 8192 bytes)
- Validate literals (max length: 4096 bytes)

**MUST NOT**:
- ❌ Process unbounded RDF documents
- ❌ Allow infinite blank node nesting

### 18.3 Path Traversal Prevention (CRITICAL)

**MUST**:
- Normalize all paths before processing
- Reject paths containing:
  - `..` (parent directory)
  - `.` (current directory)
  - Null bytes
  - Control characters
- Use platform-native path resolution

**MUST NOT**:
- ❌ Process paths without normalization
- ❌ Allow path traversal via encoded characters (%2e%2e)

### 18.4 Content-Type Validation (HIGH)

**MUST**:
- Validate `Content-Type` header matches body content
- Reject mismatched content types
- For RDF formats, validate structure

**MUST NOT**:
- ❌ Trust `Content-Type` without validation
- ❌ Process content with mismatched type

---

## 19. Information Disclosure Prevention

### 19.1 Sensitive Data Exposure (CRITICAL)

**MUST NEVER** expose:
- Access tokens
- DPoP proofs
- Private keys
- User credentials
- WebID values (partial redaction acceptable)
- Resource URIs (if sensitive)
- Server internal state
- Stack traces (in production)

### 19.2 Error Information (CRITICAL)

**MUST**:
- Return generic error messages to end users
- Include request ID for debugging
- Log full error details internally (redacted)

**MUST NOT**:
- ❌ Return internal error details to users
- ❌ Return server state in errors

### 19.3 Timing Attacks (MEDIUM)

**MUST**:
- Use constant-time comparisons for:
  - Token validation
  - Signature verification
  - MAC verification
- Avoid branching on sensitive data

**MUST NOT**:
- ❌ Use variable-time comparisons for security checks

### 19.4 Version Information (MEDIUM)

**MUST**:
- Remove or obscure version information in production
- Never expose internal library versions

---

## 20. Logging and Auditing

### 20.1 Logging Requirements (CRITICAL)

**MUST**:
- Log all authentication attempts (success/failure)
- Log all authorization decisions
- Log all outbound requests
- Log all errors
- Include in logs:
  - Timestamp (ISO 8601)
  - Request ID
  - Operation type
  - Success/failure
  - Error code (if applicable)

**MUST REDACT** from logs:
- Access tokens
- DPoP proofs
- Private keys
- User credentials
- Authorization/DPoP headers
- Full request/response bodies for sensitive resources

### 20.2 Audit Trail (HIGH)

**MUST**:
- Maintain audit trail for:
  - Authentication events
  - Authorization changes
  - Resource modifications
  - Configuration changes
- Include in audit entries:
  - Timestamp
  - Request ID
  - User/WebID
  - Resource URI
  - Operation type
  - Outcome
  - IP address (if available)

### 20.3 Log Security (MEDIUM)

**MUST**:
- Protect log files from unauthorized access
- Rotate log files (max size: 100MB, max age: 30 days)
- Encrypt sensitive logs at rest

---

## 21. Dependency Security

### 21.1 Dependency Management (HIGH)

**MUST**:
- Use dependency locking (package-lock.json, go.mod, Cargo.lock)
- Regularly update dependencies
- Scan for vulnerable dependencies:
  - npm: `npm audit`
  - Go: `govulncheck`
  - Rust: `cargo audit`
  - Node: `npm audit`, `snyk`
- Remove unused dependencies
- Use minimal dependency set

**MUST NOT**:
- ❌ Use outdated dependencies with known vulnerabilities
- ❌ Use unpinned dependencies

### 21.2 Dependency Pinning (MEDIUM)

**MUST**:
- Pin all dependencies to specific versions
- Use exact versions, not ranges (where possible)
- Review dependency changes before updating

### 21.3 Supply Chain Security (MEDIUM)

**MUST**:
- Verify dependency integrity (checksums)
- Use verified sources (official registries)
- Sign dependencies if possible

---

## 22. Secure Defaults

### 22.1 Configuration (CRITICAL)

**MUST** have secure defaults:

| Setting | Default | Notes |
|---------|---------|-------|
| Enforcement Mode | shadow | Prevents accidental enforcement |
| HTTPS | enabled | Prevents plaintext transmission |
| Rate Limiting | enabled | Prevents DoS |
| CORS | disabled | Prevents CSRF |
| DPoP Required | true | Prevents token-only auth |
| Token Validation | strict | Prevents weak validation |

### 22.2 Fail-Secure Behavior (CRITICAL)

**MUST**:
- Default to secure behavior on error
- Fail closed, not open
- Deny access on uncertainty

**MUST NOT**:
- ❌ Fail open on error
- ❌ Allow access on uncertainty

---

## 23. Security Testing Requirements

### 23.1 Unit Tests (CRITICAL)

**MUST** test:
- Token validation
- DPoP proof generation
- URI validation
- Input validation
- Output encoding
- Error handling
- Retry logic
- Rate limiting

### 23.2 Integration Tests (CRITICAL)

**MUST** test:
- Full authentication flow
- Authorization with different users
- Resource CRUD operations
- Policy operations
- Error conditions
- Rate limiting
- Timeout handling

### 23.3 Security Tests (CRITICAL)

**MUST** test:
- IDOR vulnerabilities
- SSRF vulnerabilities
- Injection attacks
- Token theft scenarios
- Replay attacks
- Man-in-the-middle scenarios

### 23.4 Fuzz Testing (MEDIUM)

**MUST**:
- Fuzz test all parsers (RDF, JSON, etc.)
- Fuzz test all input handlers
- Use coverage-guided fuzzing

### 23.5 Penetration Testing (MEDIUM)

**MUST**:
- Perform penetration testing before release
- Test with OWASP ZAP or similar
- Address all findings before release

---

## 24. Incident Response

### 24.1 Security Vulnerability Reporting

If a security vulnerability is discovered:

1. **DO NOT** disclose publicly
2. **DO** report to project security team immediately
3. **DO** provide detailed reproduction steps
4. **DO** work with team on remediation

### 24.2 Vulnerability Handling

**MUST**:
- Acknowledge report within 24 hours
- Assess severity within 48 hours
- Provide patch within 72 hours (for critical)
- Coordinate disclosure with reporter

---

## 25. Security Checklist

### 25.1 Pre-Implementation Checklist

- [ ] Review this document
- [ ] Review `docs/client-contract.md`
- [ ] Understand threat model
- [ ] Design security architecture
- [ ] Get security review of design

### 25.2 Implementation Checklist

**CRITICAL**:
- [ ] All tokens stored securely
- [ ] All tokens transmitted over HTTPS
- [ ] All tokens validated
- [ ] All DPoP proofs generated correctly
- [ ] All DPoP proofs bound to tokens
- [ ] SSRF protection implemented
- [ ] IDOR protection implemented
- [ ] Injection prevention implemented
- [ ] Error handling implemented
- [ ] Sensitive data redacted in logs

**HIGH**:
- [ ] Input validation implemented
- [ ] Output encoding implemented
- [ ] Rate limiting implemented
- [ ] Retry logic implemented
- [ ] Key management implemented
- [ ] Session security implemented
- [ ] CORS configured securely
- [ ] Dependency scanning implemented

**MEDIUM**:
- [ ] Cache security implemented
- [ ] Timing attack prevention
- [ ] Fuzz testing implemented
- [ ] Logging security implemented
- [ ] Audit trail implemented

### 25.3 Pre-Release Checklist

- [ ] All CRITICAL checks passed
- [ ] All HIGH checks passed
- [ ] All MEDIUM checks passed
- [ ] Security audit completed
- [ ] Penetration testing completed
- [ ] All findings addressed
- [ ] Documentation complete

---

## Document Metadata

**Document Owner**: Mistral Vibe  
**Last Updated**: 2026-07-07  
**Next Review**: Before v0.2.0 Beta release  
**Approval Required**: Yes (Security Team)  
**Classification**: RESTRICTED - Security Sensitive  

**Related Documents**:
- `docs/client-contract.md` - Client API Contract (companion document)
- `docs/security-audit-v0.2.0.md` - Security audit
- `docs/security-posture-v0.2.0.md` - Security posture
- `internal/authn/` - Authentication implementation
- `internal/authz/` - Authorization implementation

**Standards References**:
- RFC 7519: JWT
- RFC 9449: DPoP
- RFC 7807: Problem Details
- OWASP Top 10
- OWASP ASVS
- OWASP Cheat Sheet Series

---

*This document defines Phase 27: SDK/Client Compatibility Layer - Client Security Requirements*
