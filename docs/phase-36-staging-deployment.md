# Phase 36: Staging Deployment and Traffic Comparison

## Overview

Phase 36 focuses on deploying the solid-sidecar with all Phase 34 and Phase 35 improvements to a staging environment and comparing its behavior against Community Solid Server (CSS) to ensure compatibility and identify any divergence before production deployment.

This phase addresses the repository audit requirement for "staged traffic comparison evidence" and ensures that the sidecar can safely operate in front of CSS without breaking existing Solid clients.

## Goals

1. **Staging Deployment**: Deploy solid-sidecar with fixture distribution transports enabled in staging
2. **Traffic Comparison**: Compare sidecar behavior against CSS for all operations
3. **Compatibility Testing**: Verify Solid client compatibility
4. **Rollback Verification**: Ensure rollback procedures work correctly

## Implementation Scope

### 1. Staging Environment Setup

#### Infrastructure Requirements
- Staging CSS instance (same version as production)
- Staging solid-sidecar instance with all transports configured
- Load balancer or reverse proxy to route traffic (optional, for canary testing)
- Monitoring and logging infrastructure

#### Configuration
- Staging configuration file with all transports enabled
- Environment variables for staging-specific settings
- Feature flags for gradual rollout

#### Staging Configuration Example
```yaml
# configs/sidecar.staging.yaml
gateway:
  listen_addr: ":8443"
  backend_url: "http://css-staging:3000"

authz:
  mode: shadow  # Start in shadow mode for comparison

authn:
  enabled: true
  allowed_issuers:
    - "https://staging-issuer.example.org"

transport:
  fixture_distribution:
    enabled: true
    transports:
      http:
        enabled: true
        base_url: "https://fixture-dist-staging.example.org"
      s3:
        enabled: true
        bucket: "solid-fixtures-staging"
        region: "us-east-1"
      ssh:
        enabled: true
        host: "fixture-server-staging.example.org"
        port: 22
        username: "fixture-user"
        strict_host_key_checking: true
        known_hosts: |
          fixture-server-staging.example.org ssh-rsa AAAAB3NzaC1...
      local:
        enabled: true
        base_path: "/var/lib/solid/fixtures"

observability:
  metrics:
    enabled: true
  logging:
    level: debug
```

### 2. Traffic Comparison Harness

#### Comparison Methodology
- **Direct Comparison**: Send identical requests to both CSS and sidecar, compare responses
- **Shadow Mode**: Sidecar processes requests but doesn't enforce, compare decisions
- **Canary Mode**: Route small percentage of traffic through sidecar, compare behavior

#### Comparison Dimensions
- HTTP status codes
- Response headers
- Response body (for non-sensitive endpoints)
- Response timing
- Error rates

#### Comparison Implementation
Extend existing `CSSComparisonHarness` to support:
- Transport operation comparison
- Fixture distribution verification
- End-to-end flow testing

```go
// internal/authz/css_comparison_transport.go
package authz

// CSSTransportComparisonResult contains comparison results for transport operations
type CSSTransportComparisonResult struct {
    TransportType DistributionMethod
    Operation     string
    CSSResult     TransportResult
    SidecarResult TransportResult
    Match        bool
    Diffs        []string
}

// CompareTransportOperations compares transport behavior between CSS and sidecar
func CompareTransportOperations(ctx context.Context, 
    cssClient CSSClient, 
    sidecarClient TransportClient,
    operations []TransportOperation) []CSSTransportComparisonResult
```

#### Comparison Acceptance Criteria
- 100% match for read operations (GET, HEAD, OPTIONS)
- 100% match for metadata operations
- 99%+ match for write operations (accounting for timing differences)
- All differences are documented and understood

### 3. Compatibility Testing

#### Solid Client Compatibility Matrix
Test with popular Solid clients:
- **Mashlib**: JavaScript Solid client library
- **RDFLib.js**: RDF library commonly used with Solid
- **Solid-File-Client**: Node.js Solid file client
- **Custom clients**: Any production Solid applications

#### Compatibility Test Cases
- Authentication flows (DPoP, OAuth)
- Resource read/write/delete
- Container operations
- ACL/WAC operations
- ACP operations (if supported)
- Fixture distribution (if used by clients)

#### Compatibility Acceptance Criteria
- All major Solid clients can authenticate through sidecar
- All major Solid clients can perform CRUD operations through sidecar
- No client-specific breakage
- All compatibility issues are documented

### 4. Rollback and Emergency Procedures

#### Rollback Triggers
- Sidecar errors exceed threshold (e.g., 1% error rate)
- Response time degradation > 2x CSS baseline
- Compatibility issues with production clients
- Security incident requiring immediate rollback

#### Rollback Mechanisms
- **Configuration**: Switch to pass-through mode (sidecar proxies to CSS without processing)
- **DNS**: Point traffic back to CSS directly
- **Load Balancer**: Remove sidecar from rotation
- **Emergency Bypass**: Environment variable or file-based bypass

#### Rollback Verification
- Verify rollback can be completed in < 5 minutes
- Verify rollback doesn't lose in-flight requests
- Verify rollback doesn't corrupt any state
- Verify rollback can be reversed

#### Rollback Acceptance Criteria
- Rollback procedure is documented and tested
- Rollback can be completed within SLA (5 minutes)
- No data loss during rollback
- Rollback is reversible

## Files to Create/Modify

1. `configs/sidecar.staging.yaml` - Staging configuration
2. `deploy/compose/docker-compose.staging.yml` - Staging Docker Compose
3. `internal/authz/css_comparison_transport.go` - Transport comparison harness
4. `internal/authz/css_comparison_transport_test.go` - Comparison tests
5. `docs/runbook-staging.md` - Staging runbook (update existing)
6. `docs/rollback-procedure.md` - Rollback documentation
7. `internal/test/compatibility/solid_client_compatibility_test.go` - Client compatibility tests

## Dependencies

- Existing CSS instance for staging
- Docker/Docker Compose for staging deployment
- Monitoring infrastructure (Prometheus, Grafana)
- Logging infrastructure (ELK, Loki, or similar)

## Acceptance Criteria for Phase 36 Completion

### Must Have
- [ ] Staging environment deployed with solid-sidecar
- [ ] Traffic comparison harness implemented and running
- [ ] Compatibility testing completed with major Solid clients
- [ ] Rollback procedures documented and tested
- [ ] All staging tests passing

### Should Have
- [ ] Canary deployment mechanism
- [ ] Automated rollback detection
- [ ] Performance baselines established
- [ ] Client-specific compatibility documentation

### Nice to Have
- [ ] Blue/green deployment setup
- [ ] Automated canary analysis
- [ ] Client-specific runbooks
- [ ] Performance regression alerts

## Stop Conditions

Pause implementation if any of these occur:
- Staging environment cannot be established
- Traffic comparison reveals unacceptable divergence from CSS
- Compatibility issues cannot be resolved with major Solid clients
- Rollback procedures cannot meet SLA requirements

## Next Phase

After Phase 36 completes, proceed to Phase 37: Production Deployment and Monitoring
