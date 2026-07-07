# Solid Sidecar HTTP Client Examples

**Phase**: 27 - SDK/Client Compatibility Layer  
**Version**: v1.0.0  
**Created**: 2026-07-07  
**Author**: Mistral Vibe  
**Status**: STABLE - Production Ready  

---

## Overview

This directory contains **raw HTTP examples** demonstrating how to interact with Solid Sidecar. These examples follow the [Client Contract](../docs/client-contract.md) and [Client Security Requirements](../docs/client-security.md) strictly.

**Important**: All examples are designed to run against a local instance of Solid Sidecar proxying Community Solid Server (CSS). They demonstrate the **stable HTTP contract** without any magic client helpers.

---

## Prerequisites

Before running these examples, ensure you have:

1. **Solid Sidecar** running locally on `http://localhost:8080`
2. **Community Solid Server (CSS)** running on `http://localhost:3000`
3. **Valid Solid-OIDC credentials** from a supported issuer
4. **DPoP-capable client** with key generation capabilities

---

## Environment Setup

Create a `.env` file in this directory with the following variables:

```bash
# Sidecar endpoint
SOLID_SIDECAR_URL=http://localhost:8080

# OIDC issuer (e.g., Solid Community, Inrupt, etc.)
OIDC_ISSUER=https://your-identity-provider.com

# Client ID (from your OIDC client registration)
CLIENT_ID=your-client-id

# Client secret (if applicable)
CLIENT_SECRET=your-client-secret

# Redirect URI for OIDC flow
REDIRECT_URI=http://localhost:8080/callback

# WebID for the agent
WEBID=https://your-webid.profile

# Resource base URL
POD_BASE_URL=http://localhost:8080/
```

**Security Warning**: Never commit your `.env` file to version control. Add it to `.gitignore`.

---

## Directory Structure

```
examples/clients/http/
├── README.md                    # This file
├── authn/
│   ├── README.md               # Authentication overview
│   ├── dpop-proof-example.md   # DPoP proof generation example
│   ├── token-exchange.sh       # Token exchange flow (PKCE)
│   ├── refresh-token.sh        # Token refresh flow
│   └── dpop-sign-request.sh    # Sign request with DPoP proof
├── resources/
│   ├── README.md               # Resource operations overview
│   ├── get-resource.sh         # GET resource example
│   ├── put-resource.sh         # PUT resource example
│   ├── patch-resource.sh       # PATCH resource example
│   ├── delete-resource.sh      # DELETE resource example
│   ├── conditional-put.sh       # Conditional PUT with If-Match
│   ├── conditional-delete.sh   # Conditional DELETE with If-Match
│   └── list-container.sh       # List container contents
├── policies/
│   ├── README.md               # Policy operations overview
│   ├── wac-read-write-example.ttl  # WAC read/write example
│   ├── wac-append-example.ttl  # WAC append-only example
│   ├── acp-example.ttl         # ACP policy example
│   └── verify-policy.sh        # Verify policy enforcement
└── notifications/
    ├── README.md               # Notifications overview
    ├── subscribe-sse.sh        # SSE subscription example
    ├── subscribe-websocket.sh  # WebSocket subscription example
    ├── reconnect-resume.sh     # Reconnect with cursor resume
    └── resync-after-gap.sh      # Resync after missed events
```

---

## Authentication Flow

Solid Sidecar requires **DPoP-bound access tokens** for all authenticated requests. The authentication flow is:

1. Obtain an access token from your OIDC issuer (using PKCE)
2. Generate a DPoP proof JWT for each request
3. Include both the access token and DPoP proof in request headers

See [authn/](./authn/) for complete authentication examples.

---

## Resource Operations

All resource operations follow standard HTTP methods with Solid-specific semantics:

| Operation | HTTP Method | Description | Requires DPoP |
|-----------|-------------|-------------|---------------|
| Get Resource | GET | Retrieve a resource | Yes |
| Get Head | HEAD | Get resource metadata | Yes |
| Create/Update | PUT | Create or replace a resource | Yes |
| Partial Update | PATCH | Partial update (RDF resources) | Yes |
| Delete | DELETE | Delete a resource | Yes |
| List | GET | List container contents | Yes |

See [resources/](./resources/) for complete CRUD examples.

---

## Policy Resources

Solid Sidecar supports WAC, ACP, and SAI policy formats. Policy resources control access to other resources.

**Important**: Policy enforcement is **shadow mode by default**. The sidecar observes but does not enforce policy decisions. CSS remains the authority.

See [policies/](./policies/) for policy resource examples.

---

## Notifications

Solid Sidecar provides real-time notifications via:

- **Server-Sent Events (SSE)** - Standard HTTP streaming
- **WebSockets** - Full-duplex communication (when enabled)

Notifications follow the Solid Notifications Protocol with cursor-based resume support.

See [notifications/](./notifications/) for subscription examples.

---

## Security Requirements

All examples in this directory **MUST** comply with the following security requirements:

1. **HTTPS Only**: All production endpoints MUST use HTTPS
2. **DPoP Binding**: All access tokens MUST be DPoP-bound
3. **Input Validation**: All URIs and inputs MUST be validated before use
4. **Output Encoding**: All outputs MUST be properly encoded
5. **Error Handling**: All errors MUST be handled securely
6. **No Credential Exposure**: Credentials MUST NEVER be logged or exposed
7. **Rate Limiting**: Respect server rate limits
8. **Retry Safety**: Implement exponential backoff for retries

See [Client Security Requirements](../docs/client-security.md) for complete security specifications.

---

## Running Examples

To run any example:

```bash
# Navigate to the example directory
cd examples/clients/http/resources

# Make the script executable
chmod +x get-resource.sh

# Run with environment variables
SOLID_SIDECAR_URL=http://localhost:8080 \
  ACCESS_TOKEN=your-access-token \
  DPOP_PROOF=your-dpop-proof \
  ./get-resource.sh https://your-pod/resource.ttl
```

---

## Testing Against Local CSS

To test against a local CSS-through-sidecar setup:

1. Start CSS:
   ```bash
   docker run -p 3000:3000 -v css-data:/data solidproject/community-server:latest
   ```

2. Start Solid Sidecar:
   ```bash
   ./solid-sidecar serve --css-url=http://localhost:3000
   ```

3. Run examples against `http://localhost:8080`

---

## Compatibility

These examples are compatible with:

- Solid Sidecar v0.2.0 Beta and later
- Community Solid Server (CSS) latest
- Any Solid-OIDC compliant identity provider
- Any DPoP-compliant client

---

## Error Handling

All examples implement:

- **Exponential backoff** for retryable errors (5xx, rate limits)
- **Immediate failure** for non-retryable errors (4xx, except 429)
- **Jitter** to prevent thundering herd
- **Max retries** to prevent infinite loops
- **Circuit breaker** pattern for persistent failures

---

## Contributing

When adding new examples:

1. Follow the existing structure and naming conventions
2. Include comprehensive comments explaining each step
3. Validate all inputs and handle all errors
4. Document security considerations
5. Test against local CSS-through-sidecar
6. Update this README with new examples

---

## License

All examples are provided under the same license as Solid Sidecar. See [LICENSE](../../LICENSE) for details.
