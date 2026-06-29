# Authn Identity Confidence

This document describes the current identity-confidence boundary in `internal/authn`.

The current implementation validates bounded identity claim shapes, discovers issuer metadata plus JWKS documents with bounded HTTP fetches and copy-safe cache entries, verifies compact RS256 JWTs against JWKS material, performs cooldown-protected JWKS refresh on verification failure, and provides an issuer-backed verifier that only discovers tokens from explicitly allowed issuers. It does not yet perform DPoP confirmation binding, WebID ownership checks, middleware integration, or authz request-builder integration.

## Current scaffold

Implemented:

- bounded JSON claim parsing;
- issuer URI validation;
- WebID URI validation with fragment support;
- allowed issuer checks;
- expected audience checks;
- expiration checks;
- issued-at future checks;
- bounded client identifier validation;
- typed `TrustedIdentity` output for later request-builder integration;
- bounded OpenID Provider metadata discovery;
- issuer mismatch rejection;
- JSON content-type checks when content type is present;
- bounded JWKS fetches;
- JWKS key-count bounds;
- JWKS URI same-origin checks;
- copy-safe issuer/JWKS cache entries;
- cache TTL bounds;
- cooldown-protected JWKS refresh;
- compact JWT parsing;
- RS256-only signature verification;
- JWKS key selection by `kid`;
- RSA JWK safety checks for `kty`, `alg`, `use`, modulus, and exponent;
- verified JWT claims converted through `ValidateIdentityClaims` into `TrustedIdentity`;
- issuer-backed token verification through `IdentityVerifier`;
- pre-discovery issuer allowlist enforcement so arbitrary token issuers cannot trigger network discovery;
- one bounded JWKS refresh and retry after JWT verification failure.

Not implemented yet:

- `cnf` / DPoP key binding checks;
- WebID profile ownership proof;
- middleware integration;
- authz request-builder integration;
- e2e tests with real signed tokens from a test issuer.

## Safety rule

Do not treat parsed claims, fetched issuer metadata, or unverified tokens as trusted identity. `VerifyIdentityJWT` verifies signatures against already-provided JWKS material. `IdentityVerifier` additionally discovers issuer metadata and JWKS, but only for configured allowed issuers. Middleware must still avoid using verified identity for authorization until DPoP binding and integration work are complete.

## WebID handling

WebID subjects may include fragment identifiers such as:

```text
https://alice.example/profile/card#me
```

The validator preserves the fragment. Issuers remain stricter and must not include a fragment.

## Issuer discovery and JWKS handling

The discovery client:

- requires HTTPS issuer and JWKS URIs;
- rejects issuer metadata when the returned issuer does not match the requested issuer;
- requires JWKS URI to be same-origin with the issuer;
- uses bounded response reads;
- checks JSON content type when content type is present;
- bounds JWKS key count;
- rejects JWKS URIs with query strings or fragments;
- caches issuer metadata and JWKS responses until bounded expiry;
- returns deep copies of JWKS keys so caller mutation cannot poison the cache;
- supports cooldown-protected JWKS refresh to handle key rotation without repeated refresh storms.

## JWT verification handling

The JWT verifier currently:

- accepts compact JWS form only;
- rejects malformed or oversized header, payload, or signature segments;
- supports RS256 only;
- requires a `kid` header;
- selects an RSA JWK from JWKS by `kid`;
- rejects JWK `alg` or `use` mismatches;
- rejects RSA keys below 2048 bits;
- verifies the signature before parsing identity claims;
- applies issuer, audience, expiration, issued-at, WebID, and client-ID validation after signature verification.

## Issuer-backed verifier handling

`IdentityVerifier` currently:

- requires a non-empty allowed issuer list;
- parses the compact token only far enough to extract untrusted issuer claims;
- rejects issuers not in the allowlist before discovery;
- discovers issuer metadata through `IssuerDiscoveryClient`;
- fetches JWKS through the bounded cache;
- verifies the token with `VerifyIdentityJWT`;
- refreshes JWKS at most once after JWT verification failure, subject to the discovery client's refresh cooldown;
- returns `TrustedIdentity` only after signature and claim validation succeed.

## Next implementation steps

1. Add DPoP confirmation/key-binding checks where the token provides confirmation material.
2. Add middleware integration behind an explicit config flag.
3. Pass trusted identity into authz request construction only after verification succeeds.
4. Add e2e tests with real signed tokens once test issuer infrastructure exists.
