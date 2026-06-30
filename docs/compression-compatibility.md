# Compression Compatibility Plan

This document defines how `solid-sidecar` should add Gzip and Zstd support without breaking Solid compatibility, CSS pass-through behavior, HTTP semantics, caching, range requests, or existing clients.

Compression is a performance feature. It must never change Solid authorization behavior, resource identity, RDF semantics, request routing, or CSS compatibility. It must be negotiated, observable, bounded, and reversible.

## Scope

This plan covers:

- response compression for sidecar-generated responses;
- optional response compression for proxied CSS responses when safe;
- request decompression only where explicitly configured and safe;
- Gzip as the first broadly compatible content-coding;
- Zstd as an opt-in content-coding behind explicit feature/config gates;
- cache and ETag correctness;
- range request safety;
- streaming behavior;
- e2e compatibility tests against direct CSS behavior.

This plan does not cover RDF graph compression, storage-layer compression, archive formats, or application-level resource transformations.

## Compatibility rule

The sidecar must default to compatibility-preserving behavior:

- if a client does not send `Accept-Encoding`, return identity-compatible responses;
- if a client sends `Accept-Encoding: gzip`, Gzip may be used only for eligible responses;
- if a client sends `Accept-Encoding: zstd`, Zstd may be used only when Zstd support is explicitly enabled;
- if the response already has `Content-Encoding`, do not recompress it;
- if a request uses a content-coding the sidecar cannot safely decode or proxy unchanged, reject or pass through according to explicit config and compatibility tests;
- never compress in ways that corrupt `Content-Length`, `Content-Range`, `ETag`, `Digest`, signatures, or streaming semantics.

## Phase C1: compression configuration model

Implement configuration before implementation behavior.

Suggested shape:

```yaml
compression:
  enabled: false
  responses:
    gzip_enabled: true
    zstd_enabled: false
    min_size_bytes: 1024
    level: default
    proxied_css_responses: false
  requests:
    decompression_enabled: false
    gzip_enabled: true
    zstd_enabled: false
    max_decompressed_bytes: 10485760
  compatibility:
    skip_range_requests: true
    skip_already_encoded: true
    skip_unknown_content_type: true
    add_vary_accept_encoding: true
```

Rules:

- response compression must be disabled by default until tests exist;
- Gzip may become default-on later only after compatibility evidence;
- Zstd must remain explicit opt-in until client/intermediary compatibility is proven;
- proxied CSS response compression must be separate from sidecar-generated response compression;
- request decompression must remain explicit opt-in.

Acceptance criteria:

- config validation rejects ambiguous combinations;
- Zstd cannot be enabled accidentally by enabling generic compression;
- max decompressed size is required before request decompression can be enabled.

## Phase C2: response content-coding negotiation

Implement HTTP negotiation correctly.

Rules:

- parse `Accept-Encoding` according to q-values;
- respect `identity;q=0` where feasible, but fail safely if no acceptable encoding can be produced;
- prefer identity over compression for ineligible responses;
- select Gzip only when client accepts Gzip and response is eligible;
- select Zstd only when client accepts Zstd, response is eligible, and config enables Zstd;
- always emit `Vary: Accept-Encoding` when response representation can vary by encoding;
- do not double-compress;
- do not compress if `Cache-Control: no-transform` is present unless explicitly documented and tested as safe.

Acceptance criteria:

- clients without `Accept-Encoding` get identity responses;
- `Accept-Encoding: gzip` negotiates Gzip only for eligible responses;
- `Accept-Encoding: zstd` does not negotiate Zstd unless enabled;
- q-value tests choose the correct encoding;
- `Vary: Accept-Encoding` is present for compressed variants.

## Phase C3: response eligibility rules

Compression eligibility must be conservative.

Eligible response types:

- text/plain;
- text/turtle;
- application/ld+json;
- application/json;
- application/sparql-query;
- application/sparql-results+json;
- text/html only for sidecar-generated diagnostics/runbook pages, if any.

Usually ineligible response types:

- already-compressed media such as images, video, audio, zip, gzip, zstd, brotli, parquet, wasm where compression is ineffective or risky;
- small responses below configured threshold;
- responses with unknown or unsafe content type when `skip_unknown_content_type` is enabled;
- responses with `Content-Encoding` already set;
- partial content responses;
- upgrade/hijacked/streaming protocols;
- sensitive error bodies unless reviewed.

Acceptance criteria:

- tests cover eligible RDF/JSON/text responses;
- tests cover skipped image/binary/already-encoded responses;
- small responses are not compressed;
- compressed and identity variants are byte-compatible after decompression.

## Phase C4: proxied CSS response safety

CSS pass-through compatibility matters more than bandwidth savings.

Initial rule:

- sidecar-generated responses may be compressed first;
- proxied CSS responses should remain identity/pass-through until direct CSS vs sidecar comparison tests prove safety.

When proxied compression is enabled:

- strip or recompute `Content-Length` correctly;
- add or preserve `Vary: Accept-Encoding` correctly;
- preserve `Cache-Control`, `Link`, `Allow`, `Accept-Patch`, `WAC-Allow`, and Solid-specific headers;
- never alter response status;
- never alter RDF content after decompression;
- never alter authorization outcomes;
- never compress 304 responses;
- never compress 204 responses;
- never compress responses to `HEAD` bodies, but ensure metadata reflects actual transfer behavior.

Acceptance criteria:

- direct CSS and sidecar identity responses match for baseline fixtures;
- compressed sidecar responses decompress to the same body as direct CSS for eligible fixtures;
- Solid-specific headers survive compression;
- `HEAD` responses remain header-correct and bodyless.

## Phase C5: ETag and validators

Compression changes the representation transferred over HTTP. Validators must remain correct.

Rules:

- do not reuse strong identity ETags for compressed variants unless they are intentionally weak or variant-aware;
- preserve weak ETags only when safe;
- if the sidecar compresses a response and cannot produce correct validator semantics, strip or weaken ETag according to documented policy;
- never let identity/gzip/zstd variants share a cache entry without `Vary: Accept-Encoding`;
- preserve `Last-Modified` when compression does not alter resource modification semantics;
- document behavior for `If-None-Match` and `If-Modified-Since`.

Acceptance criteria:

- cache tests prove identity, gzip, and zstd variants do not cross-contaminate;
- conditional requests do not produce incorrect 304 responses;
- ETag policy is documented and tested.

## Phase C6: range request safety

Dynamic compression and byte ranges can conflict.

Initial rule:

- skip dynamic compression when the request contains `Range`;
- pass range requests through to CSS unchanged;
- do not compress 206 Partial Content;
- do not synthesize compressed byte ranges until a later dedicated design exists.

Acceptance criteria:

- `Range` requests through sidecar match direct CSS behavior;
- 206 responses are not dynamically compressed;
- `Content-Range` is never emitted for a different encoded byte stream than the one actually sent.

## Phase C7: request decompression safety

Request decompression is higher risk than response compression.

Initial rule:

- request decompression is disabled by default;
- compressed requests may be passed through unchanged to CSS only if CSS compatibility is verified;
- sidecar decompression is allowed only when explicitly enabled and bounded.

If enabled:

- support Gzip first;
- keep Zstd request decompression behind a separate explicit flag;
- enforce compressed and decompressed size limits;
- protect against decompression bombs;
- set or normalize request headers before forwarding;
- decide whether CSS receives decompressed body or original encoded body, and test both paths before enabling;
- reject unsupported content-codings clearly.

Acceptance criteria:

- oversized decompressed bodies are rejected before exhausting memory;
- unsupported request encodings fail safely;
- `Content-Length` and `Content-Encoding` are correct after any transformation;
- request-body logs remain disabled.

## Phase C8: streaming behavior

Compression must not break streaming or long-lived responses.

Rules:

- do not buffer unbounded responses just to compress them;
- skip compression for unknown-length streams unless streaming compression is explicitly implemented and tested;
- preserve flushing behavior for streaming responses;
- skip compression for protocol upgrades;
- bound compressor memory.

Acceptance criteria:

- readiness/health responses remain fast;
- long-lived responses do not accumulate unbounded memory;
- streaming responses are either explicitly skipped or explicitly stream-compressed with tests.

## Phase C9: security and privacy

Compression can create side-channel risk when secrets and attacker-controlled content are reflected into the same compressed response.

Rules:

- do not compress responses that include tokens, proofs, secrets, or sensitive reflected input;
- avoid compression for detailed error bodies that may include user-provided values;
- never log raw compressed or decompressed bodies;
- record only aggregate compression metrics;
- make compression disablement a one-line operational rollback.

Acceptance criteria:

- authn/authz error responses are reviewed before compression is allowed;
- logs do not include compressed or decompressed bodies;
- operators can disable compression without code changes.

## Phase C10: observability

Expose aggregate metrics only.

Suggested metrics:

- responses eligible for compression;
- responses compressed by encoding;
- responses skipped by reason;
- compression ratio buckets;
- compression latency buckets;
- request decompression attempts;
- decompression rejections by reason;
- compressor errors.

Do not include WebIDs, DIDs, resource paths, query strings, tokens, policy bodies, or request bodies in compression metrics.

## Phase C11: test matrix

Required tests:

- no `Accept-Encoding` -> identity;
- `Accept-Encoding: gzip` -> gzip when eligible;
- `Accept-Encoding: zstd` -> identity when Zstd disabled;
- `Accept-Encoding: zstd` -> zstd when Zstd enabled and eligible;
- q-value negotiation;
- `Vary: Accept-Encoding` presence;
- ETag/conditional request behavior;
- `HEAD` behavior;
- `Range` pass-through;
- already encoded response skipped;
- small response skipped;
- no-transform response skipped;
- CSS direct vs sidecar identity comparison;
- CSS direct vs sidecar decompressed compressed-body comparison;
- unsupported request `Content-Encoding` behavior;
- decompression size limit behavior if request decompression is enabled.

## Implementation order

1. Add config and validation only.
2. Add sidecar-generated response Gzip.
3. Add negotiation tests and `Vary` handling.
4. Add CSS pass-through identity comparison tests.
5. Add proxied CSS response Gzip behind explicit config.
6. Add ETag/range/HEAD hardening tests.
7. Add Zstd response support behind explicit config.
8. Add request decompression only if needed and explicitly scoped.
9. Add observability metrics.
10. Update local/staging runbooks with rollback guidance.

## Stop conditions

Pause compression implementation if:

- direct CSS vs sidecar compatibility cannot be measured;
- compressed responses corrupt headers or validators;
- range requests differ from CSS behavior;
- ETags or caches cross-contaminate variants;
- request decompression risks unbounded memory;
- Zstd breaks existing clients or intermediaries;
- compression risks exposing secrets through side channels.
