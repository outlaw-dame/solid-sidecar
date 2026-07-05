# Transport Network Policy Hardening

This document records the first implementation slice for fixture distribution transport network hardening.

## Current slice

This slice adds a shared outbound transport network policy helper, regression tests, and explicit hardened HTTP/S3 construction paths. It intentionally does not yet replace the legacy constructors in `internal/authz/fixture_distribution_transport.go`.

The helper provides:

- production-default HTTPS enforcement;
- userinfo rejection;
- localhost, `.localhost`, `.local`, single-label hostname rejection;
- loopback, private, link-local, multicast, and unspecified IP rejection;
- an HTTP client factory that disables redirects;
- dial-time DNS resolution validation;
- dialing the already-validated resolved IP address;
- a security-error classifier for transport policy failures.

The hardened wiring path provides:

- `NewHardenedHTTPTransport`, which configures `HTTPTransport` with the shared policy HTTP client;
- `HTTPTransport.SetHardenedBaseURL`, which validates base URLs through the shared policy;
- `NewHardenedS3TransportWithOptions`, which fails closed on unsafe custom S3 endpoints and configures the AWS SDK HTTP client through the shared policy;
- `S3Transport.SetHardenedS3Endpoint`, which validates and stores custom S3 endpoints through the shared policy.

## Why this is separate from legacy replacement

`internal/authz/fixture_distribution_transport.go` is currently very large and includes HTTP, local file, S3, and SSH/SFTP behavior. The safer implementation sequence is:

1. Add the shared policy helper and tests.
2. Add explicit hardened HTTP/S3 construction paths.
3. Replace legacy HTTP transport URL validation and client creation with the hardened path.
4. Replace legacy S3 custom endpoint setup with the hardened path.
5. Harden SSH/SFTP host-key and host-resolution policy separately.

This keeps each PR reviewable and avoids a broad rewrite that could accidentally alter fixture distribution semantics.

## Next acceptance criteria

The next PR should:

- make `NewHTTPTransport` call the hardened HTTP client path by default;
- make `HTTPTransport.SetBaseURL` delegate to `SetHardenedBaseURL` by default;
- make `validateHTTPTargetURL` delegate to the shared policy helper;
- make `NewS3TransportWithOptions` delegate custom endpoint setup to the hardened S3 path by default;
- require HTTPS for S3 custom endpoints unless an explicit local-test policy is passed;
- ensure invalid S3 custom endpoints are never silently ignored in SDK option callbacks.

## Stop conditions

Do not mark HTTP/S3 transport network hardening complete until:

- no HTTP/S3 remote path relies only on hostname string checks;
- private-IP denial is tested at dial time;
- redirects are disabled or explicitly safe by policy;
- S3 custom endpoint errors fail transport setup or upload deterministically;
- compatibility/local-test relaxations are explicit and cannot be enabled accidentally in production.
