# Authn Identity Confidence

This document describes the current identity-confidence boundary in `internal/authn`.

The current implementation validates bounded identity claim shapes and can discover issuer metadata plus JWKS documents with bounded HTTP fetches and copy-safe cache entries. It does not yet perform production JWT signature verification, key binding checks, or WebID ownership checks.

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
- bounded JWKS fetches;
- JWKS key-count bounds;
- copy-safe issuer/JWKS cache entries;
- cache TTL bounds.

Not implemented yet:

- JWT signature verification;
- key selection by `kid`;
- key rotation refresh policy beyond cache expiry;
- `cnf` / DPoP key binding checks;
- WebID profile ownership proof;
- middleware integration;
- authz request-builder integration.

## Safety rule

Do not treat parsed claims as trusted identity unless they come from a future verifier that has validated the issuer, token signature, audience, expiration, and key binding.

The current scaffold is for testable validation and discovery rules only. Middleware must not use it as proof of identity until signature verification lands.

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
- uses bounded response reads;
- bounds JWKS key count;
- rejects JWKS URIs with query strings or fragments;
- caches issuer metadata and JWKS responses until bounded expiry;
- returns deep copies of JWKS keys so caller mutation cannot poison the cache.

## Next implementation steps

1. Add JWT signature verification using cached JWKS keys.
2. Add key selection by `kid` and supported algorithm.
3. Add DPoP confirmation/key-binding checks where the token provides confirmation material.
4. Add middleware integration behind an explicit config flag.
5. Pass trusted identity into authz request construction only after verification succeeds.
6. Add e2e tests with real signed tokens once test issuer infrastructure exists.
