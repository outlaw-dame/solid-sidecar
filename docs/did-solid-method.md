# `did:solid` Method Design

This document defines the initial project design for `did:solid` in `solid-sidecar`.

`did:solid` is a project-defined DID method extension for Solid identity portability and controller verification. It is not yet an external standard and must not be treated as a replacement for WebID, Solid-OIDC, WAC, ACP, or CSS-compatible authorization behavior.

## Purpose

`did:solid` gives this Go/Rust Solid runtime a DID-native identity layer that can bind a controller key set to a Solid WebID, storage endpoint, issuer endpoint, and related Solid services.

The method exists to support:

- portable controller identity;
- key rotation independent of a single account password;
- bidirectional DID/WebID proof;
- future multi-device and multi-storage controller models;
- modern cryptographic identity without breaking existing Solid clients.

## Non-goals

- Do not use DID ownership alone as an authorization grant.
- Do not bypass Solid-OIDC identity verification.
- Do not bypass WAC, ACP, SAI, or CSS-compatible authorization semantics.
- Do not require existing Solid clients to understand DID documents.
- Do not require blockchain anchoring.
- Do not expose private storage metadata through DID resolution.

## Method syntax

Initial syntax:

```text
did:solid:<method-specific-id>
```

Identifier constraints:

- ASCII only;
- URL-safe characters only;
- no query string;
- no fragment;
- bounded length;
- canonical lowercase form unless a future version explicitly permits case-sensitive identifiers.

The method-specific ID should resolve to a Solid-controlled DID document location by configured resolver policy. The first implementation should avoid hardcoding global assumptions and should support local/test resolver mappings.

## DID document requirements

A valid `did:solid` DID document must include:

- `id` equal to the DID being resolved;
- at least one verification method;
- at least one authentication relationship;
- a WebID service endpoint;
- a Solid storage service endpoint;
- an OIDC issuer service endpoint;
- update/rotation metadata where supported.

Recommended service endpoint types:

```json
{
  "service": [
    {
      "id": "#webid",
      "type": "SolidWebID",
      "serviceEndpoint": "https://example.test/profile/card#me"
    },
    {
      "id": "#storage",
      "type": "SolidStorage",
      "serviceEndpoint": "https://pod.example.test/"
    },
    {
      "id": "#issuer",
      "type": "SolidOIDCIssuer",
      "serviceEndpoint": "https://issuer.example.test/"
    },
    {
      "id": "#notifications",
      "type": "SolidNotifications",
      "serviceEndpoint": "https://pod.example.test/.notifications/"
    }
  ]
}
```

## Verification methods

Preferred key types:

- Ed25519 for compact signing keys;
- P-256 as an optional compatibility profile for browser/WebCrypto-backed flows;
- RSA only where needed for compatibility with existing issuer/JWKS flows.

Rules:

- verification methods must be bounded and explicitly typed;
- unsupported key types fail DID binding;
- weak keys fail DID binding;
- authentication keys and assertion keys must be distinguished where possible;
- key IDs must resolve within the same DID document unless a future delegated-key profile is explicitly documented.

## DID-to-WebID binding

DID resolution alone is not enough. A trusted `did:solid` binding requires:

1. resolving the DID document;
2. extracting the WebID service endpoint;
3. validating the WebID URI shape;
4. fetching the WebID profile through the existing bounded Solid/WebID profile path;
5. verifying a backlink from WebID profile to DID;
6. verifying issuer/client/DPoP identity according to Solid-OIDC rules;
7. binding the DID to the canonical internal `AgentIdentity` only after all required checks succeed.

Initial backlink predicate should be documented in fixtures before implementation. Until then, DID/WebID binding is design-only.

## WebID-to-DID binding

A WebID profile may claim one or more `did:solid` identifiers only if the project defines and tests the exact RDF predicate and shape.

Rules:

- absence of a DID claim leaves the identity WebID-only;
- malformed DID claim is ignored or treated as DID-binding failure, not authn failure, unless strict mode is enabled;
- conflicting DID claims must not increase access;
- DID binding must be privacy-safe in logs and metrics.

## Canonical agent model

After successful binding, the runtime may represent identity as:

```text
AgentIdentity {
  webid: URI
  did: optional DID
  issuer: URI
  client_id: URI/string
  token_binding_key_thumbprint: string
  assurance_level: enum
  verification_source: enum
}
```

Authorization must continue to evaluate policy semantics explicitly. DID presence is identity evidence, not an access-control grant.

## Resolution policy

The first resolver should support:

- local test vectors;
- explicit resolver mappings in config;
- HTTPS DID document retrieval where configured;
- bounded fetch size;
- timeout/cancellation;
- JSON content-type validation where present;
- cache TTL bounds;
- privacy-safe errors.

Do not perform arbitrary network resolution from untrusted DID input unless resolver policy explicitly allows it.

## Update and rotation

A `did:solid` update/rotation story must cover:

- adding keys;
- removing compromised keys;
- rotating authentication keys;
- preserving WebID binding evidence;
- rejecting silent controller replacement;
- cache invalidation after rotation;
- audit-safe rotation events.

Key rotation must not silently transfer access. The authorization layer remains policy-driven.

## Deactivation

A deactivated DID must:

- fail DID binding;
- degrade to WebID-only behavior only if the WebID/OIDC path is independently valid and policy permits it;
- invalidate DID resolver cache entries;
- emit privacy-safe operator-visible diagnostics.

## Security requirements

- No authorization shortcut from DID ownership.
- No arbitrary resolver network fetch without explicit policy.
- No unbounded DID document size.
- No unsupported key types.
- No weak keys.
- No DID/WebID mismatch acceptance.
- No logging of private keys, tokens, DPoP proofs, request bodies, resource bodies, or policy bodies.
- No high-cardinality raw DID/WebID metrics.

## Privacy requirements

DID identifiers may be globally correlatable. The runtime must:

- avoid logging raw DID values by default;
- use privacy-safe hashes for aggregate metrics;
- avoid exposing private storage endpoints in public DID documents unless the owner explicitly chose that exposure;
- support WebID-only behavior for users that do not opt into DID binding.

## Implementation phases

1. Finalize DID method syntax and RDF backlink predicate.
2. Add resolver test vectors.
3. Implement strict DID parser in Go.
4. Implement local/test resolver.
5. Implement HTTPS resolver behind explicit config.
6. Implement DID document validation.
7. Implement WebID backlink validation.
8. Integrate optional DID binding into `AgentIdentity`.
9. Add CSS/WebID compatibility tests proving WebID-only behavior remains unchanged.
10. Add rotation/deactivation fixtures.

## Stop conditions

Pause `did:solid` work if:

- DID binding would grant access without policy;
- WebID backlink semantics are ambiguous;
- resolver behavior requires arbitrary untrusted network fetches;
- key rotation semantics are unsafe;
- privacy impact cannot be bounded;
- existing Solid clients would need DID support to keep working.
