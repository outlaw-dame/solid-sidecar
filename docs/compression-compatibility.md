# Compression Compatibility Plan

This document defines how `solid-sidecar` should add Gzip and Zstd support without breaking Solid clients, CSS compatibility, HTTP semantics, caches, range requests, ETags, signatures, or streaming behavior.

Compression is a performance feature, not a protocol shortcut. It must be negotiated, reversible, observable, and safe to disable immediately.

## Goals

- Support response compression for compatible clients.
- Support Gzip first because it is widely deployed and broadly compatible.
- Support Zstd only behind explicit configuration because client and intermediary support is newer and less universal.
- Preserve CSS behavior for clients that do not advertise compression support.
- Keep Solid protocol behavior unchanged.
- Avoid corrupting `HEAD`, `Range`, `ETag`, `Content-Length`, `Content-Encoding`, and cache semantics.
- Keep request decompression off by default until limits, threat model, and CSS compatibility are proven.

## Non-goals for the first implementation

- Do not require clients to support compression.
- Do not force Zstd globally.
- Do not compress every response.
- Do not decompress arbitrary request bodies by default.
- Do not change RDF, ACL, ACP, SAI, or storage semantics.
- Do not alter authorization behavior based on compression state.

## Compatibility rule

The sidecar must preserve identity-compatible responses when the client does not opt into compression.

A request without `Accept-Encoding: gzip` or `Accept-Encoding: zstd` must receive an uncompressed response unless CSS itself returns an encoded response.

A request with `Accept-Encoding: gzip` may receive Gzip only if response compression is enabled and the response is eligible.

A request with `Accept-Encoding: zstd` may receive Zstd only if Zstd is explicitly enabled and the response is eligible.

If both Gzip and Zstd are acceptable, the sidecar may prefer Zstd only when configured to do so. Otherwise, prefer Gzip until deployment evidence proves Zstd is safe with target clients and intermediaries.

## Configuration shape

Initial config should be explicit and conservative:

```yaml
compression:
  responses:
    enabled: false
    gzip:
      enabled: true
      min_bytes: 1024
      level: default
    zstd:
      enabled: false
      min_bytes: 1024
      level: default
    prefer: gzip
    skip_content_types:
      - image/
      - audio/
      - video/
      - application/zip
      - application/gzip
      - application/zstd
      - application/octet-stream
    skip_sensitive_responses: true # Skip when Authorization/Cookie request headers, Set-Cookie, or Cache-Control: private/no-store are present.
    skip_error_responses: true
    skip_ranges: true
  requests:
    decompression_enabled: false
    allowed_encodings:
      - gzip
    max_decompressed_bytes: 10485760
    zstd_enabled: false
```

Notes:

- `responses.enabled` must default to `false` until e2e compatibility tests exist.
- `zstd.enabled` must default to `false` even after Gzip support lands.
- request decompression must default to `false`.
- response compression can be enabled independently from request decompression.
- `skip_sensitive_responses` must default to `true` and remain enabled unless a threat model explicitly approves a narrower policy.

## Response compression rules

The sidecar may compress a response only when all of the following are true:

1. response compression is enabled;
2. the client advertises a supported encoding in `Accept-Encoding`;
3. CSS did not already return `Content-Encoding`;
4. the response status is eligible;
5. the method is eligible;
6. the response body is above the configured minimum size when size is known;
7. the content type is not skipped;
8. the request is not a range request when `skip_ranges` is enabled;
9. the response is not sensitive when `skip_sensitive_responses` is enabled;
10. compression will not make response metadata incorrect.

Eligible methods:

- `GET` may be compressed.
- `HEAD` must never emit a body, but metadata must remain consistent.
- `OPTIONS` should usually remain uncompressed unless there is strong evidence it helps.
- write responses should be conservative and remain uncompressed initially.

Eligible statuses:

- Prefer `200 OK` for the initial implementation.
- Avoid `204 No Content`, `205 Reset Content`, and `304 Not Modified`.
- Avoid redirects initially.
- Avoid error responses while `skip_error_responses` is true.

## Header handling

When the sidecar compresses a response, it must:

- set `Content-Encoding` to the selected encoding;
- add or merge `Vary: Accept-Encoding`;
- remove `Content-Length` unless the compressed length is known before headers are sent;
- avoid sending stale identity-length values;
- preserve `Content-Type`;
- preserve privacy-safe cache headers unless variant handling requires adjustment;
- avoid compressing if the response already has `Content-Encoding`.

When the sidecar does not compress a response, it should preserve CSS headers unchanged except for existing sidecar safety headers.

## Sensitive response handling

Compression over HTTPS can create side-channel risk when secrets and attacker-controlled bytes share the same compressed response context. The initial implementation must treat sensitive-response skipping as a safety gate, not as a performance preference.

When `skip_sensitive_responses` is enabled, the sidecar must skip dynamic compression if any of the following are true:

- the request includes an `Authorization` header;
- the request includes a `Cookie` header;
- the response includes `Set-Cookie`;
- the response includes `WWW-Authenticate`;
- `Cache-Control` includes `private`, `no-store`, or another configured sensitive directive;
- the status is an authn/authz failure such as `401` or `403`;
- the response is an authn/authz diagnostic, token exchange response, DPoP-related failure, policy diagnostic, or identity binding diagnostic;
- the response body is known to include token material, proof material, session identifiers, private policy content, or reflected secret-bearing request data;
- deployment config marks the path, content type, or upstream service as sensitive.

The sidecar must not inspect or log response bodies to decide whether they are sensitive. Sensitivity decisions must come from request headers, response headers, status/method, route/config metadata, and known middleware context.

If the implementation cannot determine whether a response is sensitive, it must prefer identity/no compression.

## ETag handling

Compression changes the bytes on the wire. Therefore, strong validators must not describe two different byte representations.

Initial safe policy:

- If CSS returns a strong `ETag` and the sidecar dynamically compresses the response, convert it to a weak validator or remove it until a variant-aware ETag strategy exists.
- If CSS returns a weak `ETag`, it may be preserved if the runtime documents that it represents semantic equivalence rather than octet identity.
- If sidecar-managed caching is later added, cache keys must include the selected content-coding variant.

Future variant-aware policy:

- identity, gzip, and zstd variants may each have distinct strong ETags;
- `Vary: Accept-Encoding` must always be present for compressed variants;
- conditional requests must be evaluated against the correct variant.

## Range request handling

Dynamic compression and byte ranges are easy to corrupt because ranges apply to a selected representation.

Initial safe policy:

- Do not dynamically compress responses to requests containing `Range`.
- Preserve CSS behavior for range requests.
- If CSS returns `206 Partial Content`, pass it through unchanged.
- Do not attempt to synthesize compressed ranges.

Future policy may support pre-compressed variants only if range semantics are implemented against the compressed representation and tested carefully.

## `HEAD` handling

`HEAD` responses must not include a body.

Initial safe policy:

- Do not dynamically compress `HEAD` responses.
- Preserve CSS metadata unless a later variant-aware design intentionally reports the selected representation metadata.
- Tests must verify that `HEAD` never emits compressed body bytes.

## Request decompression rules

Request decompression is higher risk than response compression because it changes the body CSS receives and introduces decompression-bomb risks.

Initial policy:

- request decompression is disabled by default;
- unsupported request `Content-Encoding` values should be passed through to CSS or rejected only behind explicit compatibility tests;
- when enabled, decompression must enforce both compressed and decompressed byte limits;
- decompressed body size must be bounded before proxying to CSS;
- decompression failures must produce safe client errors without logging request bodies;
- `Content-Encoding` must be removed before forwarding a decompressed body;
- `Content-Length` must be updated or removed;
- request hashes/audit metadata must clearly distinguish compressed and decompressed forms.

Allowed initial request encoding:

- Gzip only.

Zstd request decompression must remain disabled until response-side Zstd is proven and decompression-bomb protections are tested.

## Streaming behavior

Dynamic compression must not break streaming resources or long-lived responses.

Initial policy:

- skip compression for unknown streaming content types;
- skip compression for responses that flush frequently unless streaming compression is explicitly tested;
- avoid buffering unbounded responses to decide whether to compress;
- expose metrics for skipped streaming responses.

## Content type guidance

Good initial candidates:

- `text/turtle`;
- `application/ld+json`;
- `application/json`;
- `text/plain`;
- `text/html`;
- `text/css`;
- `application/javascript`;
- XML/RDF textual formats where used.

Skip by default:

- images;
- audio;
- video;
- archives;
- already-compressed formats;
- unknown binary content;
- very small responses.

## Security considerations

Compression can interact with secrets and attacker-controlled reflection.

Initial policy:

- do not compress responses that intentionally include token material;
- do not compress sensitive responses as defined above while `skip_sensitive_responses` is enabled;
- do not log compressed or decompressed bodies;
- keep authn/authz error responses uncompressed while error body shape is under review;
- allow operators to disable compression instantly;
- expose compression decision metrics without identifiers;
- include compression in the threat model before enabling by default.

## Metrics

Expose aggregate counters only:

- compression response candidates;
- compressed with gzip;
- compressed with zstd;
- skipped because client did not accept encoding;
- skipped because already encoded;
- skipped because range request;
- skipped because sensitive response;
- skipped because content type;
- skipped because too small;
- skipped because status/method;
- compression errors;
- request decompression attempts;
- request decompression rejected;
- decompressed byte-limit failures.

Do not include WebIDs, resource URLs, query strings, request bodies, response bodies, or policy bodies in metrics labels.

## Tests

Required before enabling Gzip:

- no `Accept-Encoding` returns identity-compatible response;
- `Accept-Encoding: gzip` returns `Content-Encoding: gzip` only when enabled;
- compressed body decompresses to CSS body for eligible `GET`;
- `Vary: Accept-Encoding` is present for compressed responses;
- existing `Vary` values are preserved and merged;
- `Content-Length` is removed or correct;
- existing `Content-Encoding` from CSS is not double-compressed;
- small bodies are skipped;
- skipped content types are skipped;
- requests with `Authorization` skip compression while `skip_sensitive_responses` is enabled;
- requests with `Cookie` skip compression while `skip_sensitive_responses` is enabled;
- responses with `Set-Cookie` skip compression while `skip_sensitive_responses` is enabled;
- responses with `Cache-Control: private` or `Cache-Control: no-store` skip compression while `skip_sensitive_responses` is enabled;
- authn/authz failure responses skip compression;
- `Range` requests pass through unchanged;
- `HEAD` never emits a body;
- `304`, `204`, and `206` are not dynamically compressed;
- strong ETag behavior follows the chosen safe policy.

Required before enabling Zstd:

- all Gzip compatibility tests pass for Zstd variants;
- clients without `zstd` support still get identity or Gzip;
- Zstd is disabled by default;
- `prefer: zstd` is ignored unless Zstd is enabled;
- caches keep identity, Gzip, and Zstd variants separate;
- staging evidence confirms intermediaries preserve Zstd responses correctly.

Required before request decompression:

- compressed and decompressed size limits;
- decompression-bomb rejection;
- malformed Gzip rejection;
- body forwarding correctness;
- `Content-Encoding` removal after decompression;
- `Content-Length` correction/removal;
- CSS compatibility tests for decompressed writes;
- privacy-safe failure logs.

## Rollout order

1. Add config schema with all compression disabled by default.
2. Add response negotiation parser tests.
3. Add sensitive-response classification and skip-reason tests.
4. Add Gzip response compression for eligible `GET` only.
5. Add CSS comparison tests for identity vs Gzip.
6. Add metrics and skip reasons.
7. Enable Gzip in local/staging only.
8. Add Zstd implementation behind disabled config.
9. Add Zstd e2e tests.
10. Enable Zstd only in controlled staging.
11. Consider request decompression only after response compression is stable.

## Stop conditions

Disable or pause compression work if:

- responses differ from CSS when client did not opt in;
- dynamic compression corrupts headers;
- range requests break;
- `HEAD` emits body bytes;
- caches mix identity/Gzip/Zstd variants;
- clients or intermediaries mishandle Zstd;
- compression interacts with authn/authz error bodies in a way that could leak sensitive information;
- sensitive-response detection is ambiguous or cannot be tested;
- operators cannot immediately disable compression.
