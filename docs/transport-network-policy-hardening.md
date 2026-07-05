# Transport Network Policy Hardening

This document records the first implementation slice for fixture distribution transport network hardening.

## Current slice

This slice adds a shared outbound transport network policy helper and regression tests. It intentionally does not yet rewrite the large existing transport implementation file.

The helper provides:

- production-default HTTPS enforcement;
- userinfo rejection;
- localhost, `.localhost`, `.local`, single-label hostname rejection;
- loopback, private, link-local, multicast, and unspecified IP rejection;
- an HTTP client factory that disables redirects;
- dial-time DNS resolution validation;
- dialing the already-validated resolved IP address to reduce DNS-rebinding/TOCTOU risk;
- a security-error classifier for transport policy failures.

## Why this is separate from wiring

`internal/authz/fixture_distribution_transport.go` is currently very large and includes HTTP, local file, S3, and SSH/SFTP behavior. The safer implementation sequence is:

1. Add the shared policy helper and tests.
2. Wire HTTP transport URL validation and client creation to the helper.
3. Wire S3 custom endpoint validation and SDK HTTP client configuration to the helper.
4. Harden SSH/SFTP host-key and host-resolution policy separately.

This keeps each PR reviewable and avoids a broad rewrite that could accidentally alter fixture distribution semantics.

## Next acceptance criteria

The next PR should:

- replace `validateHTTPTargetURL` with the shared policy helper or make it delegate to the helper;
- make `NewHTTPTransport` use `OutboundTransportNetworkPolicy.NewHTTPClient` or an equivalent transport with the same dial-time checks;
- validate `HTTPTransport.SetBaseURL` through the same policy;
- make S3 custom endpoints fail closed before SDK client creation;
- require HTTPS for S3 custom endpoints unless an explicit local-test policy is passed;
- ensure invalid S3 custom endpoints are never silently ignored in SDK option callbacks.

## Stop conditions

Do not mark HTTP/S3 transport network hardening complete until:

- no HTTP/S3 remote path relies only on hostname string checks;
- DNS-rebinding/private-IP denial is tested at dial time;
- redirects are disabled or explicitly safe by policy;
- S3 custom endpoint errors fail transport setup or upload deterministically;
- compatibility/local-test relaxations are explicit and cannot be enabled accidentally in production.
