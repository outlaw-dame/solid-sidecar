# Transport Security Reconciliation

This document reconciles the current fixture distribution transport code with the existing `internal/authz/transport_security_audit.md`.

The existing audit is useful, but it overstates readiness in several places. Treat this document as the current source of truth until the transport code is hardened and the original audit is updated.

## Scope

Reviewed areas:

- HTTP fixture distribution transport URL validation.
- S3 fixture distribution transport endpoint, credential, and upload behavior.
- SSH/SFTP fixture distribution transport host, authentication, host-key, and path behavior.
- Shared error redaction and retry behavior.

## Summary

Current status: **not production-passed yet**.

The transport layer has substantial validation and useful scaffolding, but production readiness needs more hardening before the audit can honestly say all transports are secure.

Primary issues:

1. HTTP and S3 endpoint validation is mostly string-based and does not provide dial-time IP validation.
2. S3 custom endpoint validation currently allows `http`, which is unsafe outside explicit local test fixtures.
3. S3 custom endpoint handling can ignore an invalid endpoint inside the AWS SDK option callback instead of failing transport creation or upload deterministically.
4. SSH host-key checking can be disabled and uses `ssh.InsecureIgnoreHostKey()` in non-strict mode; this must be impossible in production mode without an explicit development-only opt-in.
5. The original audit says S3/SSH are secure, but the code still needs stronger SSRF, DNS rebinding, credential-redaction, and host-key-policy guarantees.

## Required hardening before claiming production readiness

### 1. Shared outbound network policy

Add a shared transport network policy helper similar to the DID resolver hardening work:

- parse outbound endpoint URLs;
- require HTTPS by default;
- reject userinfo-bearing URLs;
- reject localhost, `.localhost`, `.local`, single-label hostnames, private IPs, loopback, link-local, multicast, and unspecified addresses;
- use a custom `http.Transport.DialContext` that resolves hostnames, validates every resolved IP, then dials the already-validated IP;
- disable redirects by default unless a transport explicitly supports safe redirect policy;
- make local-test relaxations explicit through config and tests.

Apply this to:

- HTTPTransport;
- S3 custom endpoints;
- any future remote fixture transport.

Acceptance criteria:

- hostname string checks are not the only SSRF defense;
- DNS rebinding cannot bypass private/loopback/link-local checks;
- local/test exceptions are explicit and impossible to enable accidentally in production config.

### 2. S3 endpoint policy

S3 endpoint hardening should require:

- standard AWS endpoints by default;
- custom endpoints disabled unless explicitly enabled;
- custom endpoints require HTTPS unless explicit local-test mode is enabled;
- endpoint validation happens before creating or using the SDK client;
- invalid endpoint configuration returns an error instead of being silently skipped in an options callback;
- endpoint and credential errors are sanitized before returning/logging;
- bucket allowlisting for production deployments where fixture distribution targets are known.

Acceptance criteria:

- `NewS3TransportWithOptions` fails for unsafe custom endpoints;
- `SetAWSCredentials` and default credential initialization never include secrets in returned errors;
- `uploadToS3` never silently ignores an invalid configured endpoint;
- tests cover loopback/private endpoints, `http` custom endpoints, and sanitized credential/config errors.

### 3. SSH/SFTP host-key policy

SSH hardening should require:

- strict host-key checking by default for any non-test transport;
- non-strict host-key checking allowed only behind an explicit development/test option;
- if strict checking is true and `known_hosts` is absent or invalid, fail closed;
- no fallback from strict mode to `ssh.InsecureIgnoreHostKey()`;
- host validation rejects localhost, loopback, private, link-local, and single-label hostnames unless explicitly allowed for local tests;
- SSH/SFTP connection errors are sanitized before returning/logging;
- private key parse errors never include key material;
- password/private-key authentication settings are cleared on `Close()`.

Acceptance criteria:

- production SSH transport construction cannot default to insecure host-key acceptance;
- strict host-key callback creation failure is fatal;
- tests cover strict-without-known-hosts, invalid-known-hosts, non-strict-without-dev-allowance, and sensitive error redaction.

### 4. Error redaction

The existing `sanitizeError` helper is useful but should be applied consistently to transport errors that may include:

- AWS access key IDs;
- AWS secret access keys;
- AWS session tokens;
- SSH private key material;
- private key paths where sensitive;
- passwords;
- authorization headers;
- signed URLs;
- endpoint URLs with userinfo.

Acceptance criteria:

- tests assert returned errors do not include provided AWS or SSH secrets;
- retry-exhausted errors preserve safe reason codes while dropping raw provider errors;
- transport logs and metrics never use raw target URLs or credentials as labels.

### 5. Existing audit correction

Update `internal/authz/transport_security_audit.md` after the code hardening lands:

- downgrade current S3/SSH/HTTP status from "secure" to "requires hardening" until the above controls are implemented;
- remove examples that describe insecure fallback as acceptable;
- replace "passed with recommendations" with evidence-backed status;
- link to tests and PRs that prove the claims.

## Recommended implementation order

1. Add shared outbound network policy helper and tests.
2. Wire helper into HTTP transport.
3. Wire helper into S3 custom endpoint setup and fail unsafe endpoints early.
4. Harden SSH strict host-key default and fail-closed behavior.
5. Add credential/error-redaction regression tests.
6. Update `internal/authz/transport_security_audit.md` to reflect the new evidence.

## Stop conditions

Do not mark transport security as production-ready if:

- any remote endpoint path relies only on hostname string checks;
- custom S3 endpoints can use plain HTTP outside local-test mode;
- invalid custom endpoints are silently ignored;
- SSH non-strict host-key checking is enabled by default;
- strict SSH mode can degrade to insecure host-key acceptance;
- returned errors can contain AWS/SSH credentials or private key material;
- tests do not cover DNS-rebinding/private-IP denial paths.
