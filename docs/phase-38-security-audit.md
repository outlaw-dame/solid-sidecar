# Phase 38: Security Audit and Formal Hardening

## Overview

Phase 38 focuses on subjecting the solid-sidecar runtime to adversarial review, fuzzing, invariant testing, and external audit readiness. This phase ensures that the codebase meets production-grade security standards before full enforcement can be enabled.

**Related**: `docs/solid-platform-maturity-phases.md` Phase 26

## Goals

1. **Complete Threat Model**: Comprehensive threat model covering all runtime components
2. **Fuzz Testing**: Fuzz targets for all high-risk parsers
3. **Property Testing**: Authorization invariant tests
4. **Dependency Audit**: Supply-chain security review
5. **Secret Scanning**: Log redaction and secret detection
6. **Isolation Decisions**: Parser sandboxing/process isolation
7. **Audit Readiness**: External audit checklist and procedures
8. **Vulnerability Management**: Disclosure policy and tracking
9. **Security Regression Suite**: Automated security tests
10. **Severity Taxonomy**: Release-blocking criteria

## Implementation

### 1. Threat Model Completion

#### Current State
Existing threat model in `docs/threat-model.md` covers:
- Authentication threats (token theft, DPoP replay, identity spoofing)
- Authorization threats
- Compression threats
- Caching threats
- DID threats
- Policy parsing threats

#### Extensions Needed
- [x] Storage layer threats
- [x] Transport layer threats (fixture distribution)
- [x] Indexing threats
- [x] Notification threats
- [x] Migration threats

### 2. Fuzz Targets

High-risk parsers requiring fuzz coverage:

#### RDF Parsers
- **Target**: `rust/solid_rdf_parser`
- **Status**: ✅ Rust fuzz targets exist via cargo-fuzz
- **Implementation**: Add fuzz tests for Turtle, N-Triples parsing
- **Fixtures**: Long-lived fuzz fixtures in `rust/fuzz/fixtures/`

#### WAC Parser
- **Target**: `internal/authz/wac`
- **Status**: ❌ NOT STARTED
- **Action**: Create fuzz target for WAC policy parsing
- **File**: `internal/authz/wac/fuzz_test.go`

#### ACP Parser
- **Target**: `internal/authz/acp`
- **Status**: ❌ NOT STARTED
- **Action**: Create fuzz target for ACP policy parsing
- **File**: `internal/authz/acp/fuzz_test.go`

#### DID Parser
- **Target**: `internal/identity/did_parser.go`
- **Status**: ❌ NOT STARTED
- **Action**: Create fuzz target for DID parsing
- **File**: `internal/identity/did_parser_fuzz_test.go`

#### HTTP Target Parser
- **Target**: URL parsing in gateway
- **Status**: ❌ NOT STARTED
- **Action**: Create fuzz target for URL/HTTP target parsing
- **File**: `internal/gateway/url_parser_fuzz_test.go`

#### Compression Negotiation Parser
- **Target**: `internal/compression`
- **Status**: ❌ NOT STARTED
- **Action**: Create fuzz target for Accept-Encoding parsing
- **File**: `internal/compression/fuzz_test.go`

#### Config Parser
- **Target**: `internal/config`
- **Status**: ❌ NOT STARTED
- **Action**: Create fuzz target for configuration parsing
- **File**: `internal/config/config_fuzz_test.go`

### 3. Property Tests for Authorization Invariants

Authorization invariants that must hold:

1. **No Implicit Allows**: A request must never be allowed without explicit policy
2. **Policy Precedence**: Deny rules must override allow rules
3. **Identity Binding**: Authorization decisions must be bound to verified identity
4. **Resource Stability**: Same request + same identity + same policy = same decision
5. **Cache Consistency**: Cached decisions must match fresh evaluations
6. **Shadow Mode Safety**: Shadow mode decisions must never affect actual access

**Implementation**: `internal/authz/invariants_test.go`

```go
package authz

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestAuthorizationInvariants(t *testing.T) {
	t.Run("NoImplicitAllows", func(t *testing.T) {
		// Test that requests without matching policy are denied
		// Test that absence of policy = deny (fail-closed)
	})
	
	t.Run("DenyOverridesAllow", func(t *testing.T) {
		// Test that deny rules take precedence over allow rules
		// Test with conflicting WAC/ACP rules
	})
	
	t.Run("IdentityBinding", func(t *testing.T) {
		// Test that decisions are bound to verified identity
		// Test that spoofed identity cannot gain access
	})
	
	t.Run("DeterministicDecisions", func(t *testing.T) {
		// Test that same inputs produce same outputs
		// Test across multiple evaluations
	})
	
	t.Run("CacheConsistency", func(t *testing.T) {
		// Test that cached decisions match fresh evaluations
		// Test cache invalidation on policy changes
	})
	
	t.Run("ShadowModeSafety", func(t *testing.T) {
		// Test that shadow mode decisions don't affect actual access
		// Test that shadow mode cannot be accidentally enabled as enforcement
	})
}
```

### 4. Dependency Audit and Supply-Chain Policy

#### Current Dependencies
```bash
go list -m all > dependencies.txt
go list -json -m all | jq '{name, version, path, dirty}' > dependencies.json
```

#### Audit Steps
1. **Identify Critical Dependencies**: Parse Go modules and Rust crates
2. **Check for Known Vulnerabilities**: Use `govulncheck` and `cargo audit`
3. **Evaluate Transitive Dependencies**: Check dependency trees
4. **Pin Versions**: Ensure all dependencies use pinned versions
5. **Update Policy**: Define when to update dependencies

**File**: `docs/dependency-audit-2026-07-04.md`

#### Supply-Chain Policy
- All direct dependencies must be from verified sources
- No dynamic code loading
- All binaries must be reproducible
- Dependencies must be audited before major version bumps
- Vulnerability patches must be applied within SLA

### 5. Secret Scanning and Log-Redaction Tests

#### Secret Types to Detect
- Access tokens
- DPoP proofs
- Refresh tokens
- Private keys
- API keys
- Database credentials
- TLS certificates

#### Log Redaction Requirements
- ✅ Tokens never logged (verified in threat-model.md)
- ✅ DPoP proofs never logged (verified in threat-model.md)
- ✅ Private key material never logged (verified in threat-model.md)
- ✅ Request bodies never logged (verified in privacy-review.md)
- ✅ Policy bodies never logged (verified in privacy-review.md)
- ⚠️ WebIDs/DIDs logged as sanitized hashes only

**Implementation**: `internal/observability/logging_redaction_test.go`

```go
package observability

import (
	"bytes"
	"log/slog"
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestLogRedaction(t *testing.T) {
	t.Run("TokenRedaction", func(t *testing.T) {
		// Test that access tokens are redacted in logs
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		
		// Attempt to log a token
		logger.Info("request", "token", "secret-token-12345")
		
		output := buf.String()
		assert.NotContains(t, output, "secret-token-12345")
		assert.Contains(t, output, "[REDACTED]")
	})
	
	t.Run("DPoPRedaction", func(t *testing.T) {
		// Test that DPoP proofs are redacted
	})
	
	t.Run("RequestBodyRedaction", func(t *testing.T) {
		// Test that request bodies are never logged
	})
}
```

### 6. Parser Sandboxing / Process Isolation Decision

#### Options Analysis

**Option 1: In-Process with Memory Limits**
- Pros: Fast, no IPC overhead
- Cons: Memory corruption in parser affects main process
- **Decision**: Acceptable for Go parsers with bounded allocations

**Option 2: Separate Process**
- Pros: Complete isolation, crash doesn't affect main process
- Cons: IPC overhead, complexity
- **Decision**: Required for Rust RDF parser (already separate process)

**Option 3: WASM Sandbox**
- Pros: Strong isolation, portable
- Cons: Performance overhead, complexity
- **Decision**: Future consideration, not required for current scope

**Implementation**: Document in `docs/parser-isolation-decision.md`

### 7. External Audit Checklist

#### Pre-Audit Preparation
- [ ] All code formatted and linted
- [ ] All tests passing
- [ ] No compiler warnings
- [ ] No todo/fixme comments (or documented as acceptable)
- [ ] Architecture documentation complete
- [ ] Threat model complete
- [ ] Security controls documented
- [ ] Data flow diagrams available

#### Audit Scope
- [ ] Authentication flow
- [ ] Authorization flow
- [ ] Policy parsing and evaluation
- [ ] DID resolution
- [ ] Storage operations
- [ ] Network operations
- [ ] Log handling
- [ ] Error handling
- [ ] Configuration

#### Audit Deliverables
- Findings report
- Severity classification
- Remediation recommendations
- Retest verification

**File**: `docs/external-audit-checklist.md`

### 8. Vulnerability Disclosure Policy

**Policy**:
1. Private disclosure to maintainers
2. 90-day embargo for critical issues
3. Coordinated public disclosure
4. CVE assignment for eligible issues
5. Credit to reporters (optional)

**File**: `docs/VULNERABILITY-DISCLOSURE.md`

**Template**:
```markdown
# Vulnerability Disclosure Policy

## Scope

This policy applies to security vulnerabilities in the solid-sidecar project.

## Reporting

Please report security vulnerabilities to: security@outlaw-dame.example

## Response

- Initial response within 24 hours
- Triaged within 48 hours
- Fix or mitigation within 7 days (critical), 30 days (high)

## Severity Classification

- Critical: Remote code execution, privilege escalation, data breach
- High: Denial of service, information disclosure
- Medium: Limited impact, requires user interaction
- Low: Informational, minimal impact

## Disclosure

- Private disclosure to maintainers
- Coordinated public disclosure after fix
- CVE assignment through MITRE
- Credit to reporter (optional)
```

### 9. Security Regression Suite

Automated tests to prevent security regressions:

**File**: `internal/security/regression_test.go`

```go
package security

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestSecurityRegressions(t *testing.T) {
	t.Run("NoImplicitAllows", func(t *testing.T) {
		// Verify that requests without policy are denied
	})
	
	t.Run("TokenBindingRequired", func(t *testing.T) {
		// Verify that tokens must be DPoP-bound
	})
	
	t.Run("NoTokenInLogs", func(t *testing.T) {
		// Verify that tokens never appear in logs
	})
	
	t.Run("SSRFProtection", func(t *testing.T) {
		// Verify that SSRF attacks are blocked
	})
	
	t.Run("RedirectProtection", func(t *testing.T) {
		// Verify that redirects are not followed
	})
	
	t.Run("InputValidation", func(t *testing.T) {
		// Verify that all inputs are validated
	})
	
	t.Run("NoPrivateIPAccess", func(t *testing.T) {
		// Verify that private IPs cannot be accessed
	})
}
```

### 10. Release-Blocking Severity Taxonomy

**File**: `docs/release-blocking-severity.md`

| Severity | Description | Release Blocking | SLA |
|----------|-------------|-----------------|-----|
| Critical | RCE, priv esc, data breach | YES | 24h |
| High | DoS, info disclosure, auth bypass | YES | 7d |
| Medium | Limited impact, requires user action | NO | 30d |
| Low | Informational, minimal impact | NO | 90d |

**Criteria for Release Blocking**:
- Critical: Must be fixed before any release
- High: Must be fixed before major/minor release
- Medium: Should be fixed before major release
- Low: Can be deferred

## Files to Create/Modify

### Documentation
1. [x] `docs/phase-38-security-audit.md` - This document
2. [ ] `docs/dependency-audit-2026-07-04.md` - Dependency audit results
3. [ ] `docs/parser-isolation-decision.md` - Parser sandboxing decision
4. [ ] `docs/external-audit-checklist.md` - Audit preparation checklist
5. [ ] `docs/VULNERABILITY-DISCLOSURE.md` - Vulnerability disclosure policy
6. [ ] `docs/release-blocking-severity.md` - Severity taxonomy

### Test Files
1. [ ] `internal/authz/invariants_test.go` - Authorization invariant tests
2. [ ] `internal/identity/did_parser_fuzz_test.go` - DID parser fuzzing
3. [ ] `internal/authz/wac/fuzz_test.go` - WAC parser fuzzing
4. [ ] `internal/authz/acp/fuzz_test.go` - ACP parser fuzzing
5. [ ] `internal/gateway/url_parser_fuzz_test.go` - URL parser fuzzing
6. [ ] `internal/compression/fuzz_test.go` - Compression parser fuzzing
7. [ ] `internal/config/config_fuzz_test.go` - Config parser fuzzing
8. [ ] `internal/observability/logging_redaction_test.go` - Log redaction tests
9. [ ] `internal/security/regression_test.go` - Security regression suite

### Rust Fuzz Targets
1. [x] `rust/solid_rdf_parser/fuzz` - RDF parser fuzzing (already exists)
2. [ ] `rust/solid_policy_kernel/fuzz` - Policy kernel fuzzing

## Acceptance Criteria

### Must Have
- [ ] Complete threat model covering all components
- [ ] Fuzz targets for all high-risk parsers
- [ ] Property tests for authorization invariants
- [ ] Dependency audit completed
- [ ] Secret scanning and log redaction verified
- [ ] Parser isolation decision documented
- [ ] External audit checklist created
- [ ] Vulnerability disclosure policy created
- [ ] Security regression suite implemented
- [ ] Release-blocking severity taxonomy defined

### Should Have
- [ ] Fuzz targets integrated into CI (smoke tests)
- [ ] Security regression suite runs on every PR
- [ ] Dependency scanning in CI
- [ ] Secret scanning in CI

### Nice to Have
- [ ] Full fuzzing in nightly builds
- [ ] Coverage-guided fuzzing
- [ ] Automated dependency updates
- [ ] CVE monitoring

## Dependencies

- Phase 37: Production Deployment and Monitoring (COMPLETE)
- Go 1.25+ (for fuzzing support)
- Rust stable (for cargo-fuzz)

## Stop Conditions

- Critical security vulnerabilities discovered that block all work
- Fuzzing reveals unfixed parser vulnerabilities
- Authorization invariant tests fail

## Next Phase

After Phase 38 completes, proceed to Phase 39: Continued Platform Maturity
or Phase 13: Decision Cache and Invalidation (whichever is higher priority)
