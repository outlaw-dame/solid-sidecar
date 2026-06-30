# `did:solid` Method Plan

This document defines the initial project plan for `did:solid` support in `solid-sidecar`.

`did:solid` is treated as a project-defined DID method extension until there is a stable external specification that this repository intentionally adopts. It must strengthen Solid identity portability and cryptographic controller verification without bypassing Solid's WebID, Solid-OIDC, WAC, ACP, or future SAI authorization semantics.

## Safety rule

`did:solid` must not grant access by itself.

A DID can identify and verify a controller. Authorization remains policy-driven. Access to resources still depends on verified Solid identity and applicable authorization policy.

## Goals

- Define a Solid-native DID method shape for this project.
- Bind DID controller identity to WebID identity without replacing WebID.
- Support key rotation and service endpoint updates with auditable rules.
- Preserve compatibility with existing Solid-OIDC/WebID clients.
- Prepare a resolver implementation path in Go and deterministic validation kernels in Rust if needed.
- Keep all DID-derived authorization behavior disabled until policy semantics explicitly support DID references.

## Non-goals

- Do not replace WebID.
- Do not replace Solid-OIDC.
- Do not treat DID possession as authorization.
- Do not add blockchain dependencies by default.
- Do not require existing Solid clients to understand `did:solid`.
- Do not allow arbitrary DID resolvers to trigger unbounded network discovery.

## Initial method syntax

```text
did:solid:<method-specific-id>
```

The method-specific identifier must be:

- URL-safe;
- bounded in length;
- case-normalized where appropriate;
- free of query strings, fragments, and path traversal ambiguity;
- parseable without network access;
- stable across key rotation.

Future examples may use one of these forms after the method design is finalized:

```text
did:solid:alice.example
```

```text
did:solid:z6Mk...
```

```text
did:solid:sha256-...
```

This document does not yet choose the final method-specific-id format. That choice must be made before resolver implementation.

## DID document requirements

A valid `did:solid` DID document should include:

- `id` equal to the DID being resolved;
- verification methods for controller keys;
- authentication relationships;
- assertion relationships where needed;
- service endpoints for Solid identity/runtime integration.

Recommended service endpoints:

```json
{
  "id": "did:solid:example#solid-storage",
  "type": "SolidStorage",
  "serviceEndpoint": "https://pod.example/"
}
```

```json
{
  "id": "did:solid:example#webid",
  "type": "SolidWebID",
  "serviceEndpoint": "https://pod.example/profile/card#me"
}
```

```json
{
  "id": "did:solid:example#oidc-issuer",
  "type": "SolidOIDCIssuer",
  "serviceEndpoint": "https://issuer.example/"
}
```

Optional service endpoints:

- Solid notification endpoint;
- profile/documentation endpoint;
- storage description endpoint.

## WebID binding

`did:solid` must use bidirectional binding before the runtime treats DID and WebID as belonging to the same agent.

DID document to WebID:

- DID document contains a WebID service endpoint.
- The WebID URI must be syntactically valid and preserve fragments.
- The WebID endpoint must use `https` unless a local test mode explicitly allows otherwise.

WebID to DID:

- WebID profile contains an explicit link back to the DID.
- The backlink predicate must be documented before implementation.
- The backlink must be fetched with bounded size/time limits.
- The backlink must match the DID being resolved.

Binding succeeds only when both directions agree.

## Solid-OIDC binding

A resolved DID document may advertise a Solid-OIDC issuer endpoint, but the runtime must still validate tokens through the normal Solid-OIDC path.

Rules:

- issuer allowlists still apply;
- JWT signatures still require verified JWKS material;
- DPoP binding still applies;
- `webid` claims still require validation;
- DID service endpoints cannot override a token issuer unless explicitly allowed by config and verified through the selected trust policy.

## Verification methods

Preferred key types:

- Ed25519 for compact modern controller keys;
- P-256 as an optional compatibility key where WebCrypto/browser support matters;
- RSA only when compatibility requires it, with minimum key-size checks aligned with existing JWT/JWKS safety rules.

Rules:

- verification methods must be bounded in count and size;
- unsupported key types fail DID binding;
- private key material is never logged;
- key identifiers must not allow path/query/fragment confusion;
- key rotation must be explicit and auditable.

## Resolution model

Initial resolver design should support one configured resolution source at a time:

1. local/static test resolver;
2. HTTPS resolver endpoint;
3. Solid profile/storage-backed resolver;
4. future native registry/index resolver.

The resolver must:

- reject unsupported DID methods;
- parse without network access first;
- enforce allowed resolver/source policy;
- use bounded HTTP clients;
- limit document size;
- require JSON content type where applicable;
- cache documents with bounded TTL;
- return deep copies from cache;
- expose privacy-safe errors;
- never trigger arbitrary unbounded network discovery from user-supplied DID strings.

## Update and rotation model

The method must define how DID documents are updated.

Required decisions before implementation:

- where DID documents are stored;
- who controls updates;
- how update authority is authenticated;
- how keys are rotated;
- how compromised keys are removed;
- how WebID endpoint changes are authorized;
- how issuer endpoint changes are authorized;
- how old DID document versions are audited;
- how caches are invalidated.

Until these are decided, runtime support must be read-only/test-only.

## Deactivation model

The method must define deactivation semantics.

Required decisions:

- how deactivation is represented;
- whether deactivation is reversible;
- how resolver caches observe deactivation;
- what happens to WebID binding after deactivation;
- what happens to existing sessions after deactivation;
- how deactivation is audited.

Runtime behavior before full design:

- if a DID is deactivated, DID binding fails;
- WebID-only behavior may continue if Solid-OIDC remains valid and policy allows it;
- deactivated DID must not create access-deny or access-allow surprises outside documented policy behavior.

## Internal identity model

`did:solid` should feed an optional DID field into the canonical identity model:

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

Rules:

- WebID remains required for normal Solid identity.
- DID is optional.
- DID binding may increase assurance level only after bidirectional verification.
- DID binding does not increase authorization.
- Metrics use privacy-safe hashes rather than raw WebIDs or DIDs.

## Policy interaction

Initial policy interaction:

- WAC and ACP continue to evaluate WebID/public/group/client semantics as implemented.
- DID references in policy are not enforceable until explicitly designed, parsed, tested, and compared.
- If DID policy support is added later, it must be feature-gated and shadow-only first.

Future DID-aware policy work may include:

- DID subject references in project-specific policy extensions;
- DID-backed group membership proofs;
- DID-backed client/application identity;
- DID-to-WebID equivalence assertions;
- DID rotation-aware policy invalidation.

None of these are part of initial enforcement readiness.

## Privacy considerations

DIDs can create correlation risk across pods, issuers, clients, and resource accesses.

Mitigations:

- do not log raw DID values by default;
- avoid high-cardinality DID metrics;
- do not publish DID links automatically from private profiles;
- document correlation implications before user-facing use;
- allow DID support to be disabled;
- keep DID resolver caches scoped and bounded;
- avoid global discovery unless explicitly designed.

## Security considerations

Risks:

- DID-to-WebID spoofing;
- malicious DID documents;
- malicious service endpoints;
- key confusion;
- stale key rotation state;
- resolver SSRF;
- cache poisoning;
- accidental authorization shortcut;
- privacy/correlation leaks.

Required controls:

- strict DID parser;
- allowed resolver/source policy;
- HTTPS-only remote resolution outside test mode;
- bounded fetches;
- content-type validation;
- document-size limits;
- verification method validation;
- bidirectional WebID binding;
- cache copy safety;
- explicit feature flags;
- shadow-only policy interaction until reviewed.

## Implementation phases

### DID Phase D1: Method design finalization

- choose method-specific-id format;
- define DID document service endpoint vocabulary;
- define WebID backlink predicate;
- define resolution source model;
- define update/rotation/deactivation model;
- add test vectors.

Acceptance criteria:

- method design is complete enough to implement without guessing;
- invalid examples and attack examples are documented;
- compatibility with existing WebID/Solid-OIDC is preserved.

### DID Phase D2: Parser and validation scaffolding

- strict `did:solid` parser;
- DID document struct/model;
- verification method validation;
- service endpoint validation;
- bounded validation errors;
- unit tests and negative tests.

Acceptance criteria:

- malformed DIDs fail predictably;
- unsupported fields fail safe or are ignored according to documented rules;
- parser performs no network access.

### DID Phase D3: Resolver interface and local resolver

- resolver interface;
- static/local resolver for tests;
- cache model;
- resolver metrics;
- test vectors.

Acceptance criteria:

- test DID documents resolve deterministically;
- cache returns copy-safe documents;
- resolver failures are privacy-safe.

### DID Phase D4: HTTPS/Solid-backed resolver

- bounded HTTP resolver;
- allowed source policy;
- content-type checks;
- document-size limits;
- timeout/cancellation;
- SSRF protections;
- cache TTL controls.

Acceptance criteria:

- arbitrary DID strings cannot trigger arbitrary network fetches;
- malicious endpoints fail closed for DID binding;
- WebID-only authn is unaffected by DID resolver failures.

### DID Phase D5: WebID/Solid-OIDC binding

- DID document WebID endpoint validation;
- WebID backlink validation;
- issuer endpoint consistency checks;
- canonical identity model integration;
- assurance-level calculation;
- privacy-safe logs.

Acceptance criteria:

- DID/WebID binding requires agreement in both directions;
- DID binding does not alter authorization decisions;
- identity injection tests cover DID fields.

### DID Phase D6: Shadow policy experiments

- document whether WAC/ACP can or should reference DID subjects;
- add feature-gated shadow-only parser/evaluator handling if chosen;
- compare against CSS behavior where possible;
- never enforce DID policy references before review.

Acceptance criteria:

- DID-aware policy support remains opt-in and shadow-only;
- no DID policy ambiguity becomes enforceable.

## Test vectors

Add fixtures for:

- valid `did:solid` document;
- invalid method;
- invalid method-specific-id;
- missing WebID service;
- invalid WebID URI;
- mismatched WebID backlink;
- missing backlink;
- unsupported key type;
- weak RSA key;
- duplicate key IDs;
- malicious service endpoint;
- oversized DID document;
- resolver timeout;
- cache copy mutation attempt;
- deactivated DID;
- rotated key;
- issuer endpoint mismatch.

## Stop conditions

Pause `did:solid` work if:

- method-specific-id format remains ambiguous;
- WebID backlink predicate is not defined;
- resolver source model requires arbitrary unbounded network discovery;
- DID binding would bypass DPoP/Solid-OIDC;
- DID binding would grant access without WAC/ACP/SAI policy;
- key rotation semantics are unclear;
- privacy/correlation risks are not documented;
- implementation requires guessing Solid authorization semantics.
