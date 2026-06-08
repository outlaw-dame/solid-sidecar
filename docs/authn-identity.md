# Authn Identity Confidence

This document describes the current identity-confidence boundary in `internal/authn`.

The current implementation validates bounded identity claim shapes. It does not yet perform production JWT signature verification, issuer discovery, JWKS retrieval, or WebID ownership checks.

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
- typed `TrustedIdentity` output for later request-builder integration.

Not implemented yet:

- OpenID Provider discovery;
- JWKS fetching;
- JWKS cache refresh;
- JWT signature verification;
- key rotation behavior;
- `cnf` / DPoP key binding checks;
- WebID profile ownership proof;
- middleware integration;
- authz request-builder integration.

## Safety rule

Do not treat parsed claims as trusted identity unless they come from a future verifier that has validated the issuer, token signature, audience, expiration, and key binding.

The current scaffold is for testable validation rules and future integration only.

## WebID handling

WebID subjects may include fragment identifiers such as:

```text
https://alice.example/profile/card#me
```

The validator preserves the fragment. Issuers remain stricter and must not include a fragment.

## Next implementation steps

1. Add issuer discovery with bounded HTTP client.
2. Add JWKS fetch/cache with timeout and size limits.
3. Add JWT signature verification.
4. Add DPoP confirmation/key-binding checks where the token provides confirmation material.
5. Add middleware integration behind an explicit config flag.
6. Pass trusted identity into authz request construction only after verification succeeds.
