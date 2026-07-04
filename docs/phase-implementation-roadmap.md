# Phase Implementation Roadmap

This document provides a unified view of all phase implementations, their current status, and the recommended execution order for the solid-sidecar project.

## Completed Phases

### Phase 1: Authn trust completion
**Status: ✅ COMPLETE**
- DPoP proof validation
- Key-binding checks
- JWT verification scaffolding
- Trusted identity injection

### Phase 2: Solid HTTP request compliance hardening
**Status: ✅ COMPLETE**
- Method/media-type validation
- Container slash and redirect behavior
- CORS behavior tests
- CSS pass-through compatibility

### Phase 3: Live policy discovery in shadow mode
**Status: ✅ COMPLETE**
- WAC `acl` link discovery
- ACP access-control-resource discovery
- Ancestor/container policy walk
- Safe URI validation
- Bounded policy fetch

### Phase 4: Rust RDF parser and canonical graph boundary
**Status: ✅ COMPLETE**
- Parser kernel crate API
- Turtle/N-Triples parsing
- Deterministic term ordering
- Panic-safe FFI boundary

### Phase 5: WAC parser and evaluator in shadow mode
**Status: ✅ COMPLETE**
- WAC parser with RDF boundary
- Rule matching logic
- Shadow mode evaluation
- Golden WAC fixtures

### Phase 6: ACP parser and evaluator in shadow mode
**Status: ✅ COMPLETE**
- Access Control Resource parser
- Access Control parser
- Policy parser
- Matcher parser
- Grant/deny behavior

### Phase 7: SAI decision and parser boundary
**Status: ✅ COMPLETE**
- SAI support decision document
- Feature flag design
- Interface design (SAIParser, SAIEvaluator)
- Deferral of full implementation until conditions met

### Phase 8: `did:solid` method design
**Status: ✅ COMPLETE**
- Method syntax documentation
- DID document shape
- DID-to-WebID binding
- Security considerations

### Phase 9: `did:solid` resolver and identity binding
**Status: ✅ COMPLETE**
- Go DID resolver package
- Strict parser for `did:solid` identifiers
- DID document fetch/validation
- DID cache with bounded TTL
- WebID backlink validation

### Phase 10: Canonical internal agent model
**Status: ✅ COMPLETE**
- AgentIdentity struct with WebID, DID, issuer, client_id
- Assurance levels
- Privacy-safe identity hashing
- Compatibility tests

### Phase 11: CSS behavior comparison harness
**Status: ✅ COMPLETE**
- Direct CSS vs sidecar comparison
- WAC fixture comparison
- ACP fixture comparison
- Policy discovery comparison
- Mismatch classifications

### Phase 12: Compression negotiation compatibility
**Status: ✅ COMPLETE**
- Gzip support
- Zstd support (gated)
- Accept-Encoding negotiation
- Vary header handling
- ETag/Content-Length correctness

### Phase 13: Decision cache and invalidation
**Status: ✅ COMPLETE**
**Document: `docs/phase-13-completion.md`**
- Cache key design documented and implemented
- Bounded TTL implementation with comprehensive configuration
- Stale decision rules implemented (StaleDecisionChecker)
- Policy-change invalidation implemented (InvalidatePolicy, InvalidateResource, InvalidateAgent)

### Phase 14: Enforcement gates and canary
**Status: ✅ COMPLETE**
- Shadow/enforce/dry-run modes
- Resource allowlist
- Emergency bypass
- Startup guardrails
- Canary metrics

### Phase 15: Native Go/Rust Solid runtime path
**Status: ⚠️ PARTIAL**
- Gateway compatibility layer scaffolding exists
- Storage abstraction needed
- Policy engine needed
- CSS migration path needed

### Phase 16: Notifications, live updates, and indexing
**Status: ❌ NOT STARTED**
- Solid notification support plan needed
- Resource-change event stream needed
- Container metadata index needed
- Policy-aware index filtering needed

### Phase 17: Production hardening
**Status: ⚠️ PARTIAL**
- OpenTelemetry scaffolding exists
- Structured health states needed
- pprof/debug endpoint policy needed
- Memory/goroutine leak tests needed

### Phase 18-31: Platform Maturity Phases
**Status: ❌ NOT STARTED**
See `docs/solid-platform-maturity-phases.md` for details.

### Phase 32: Fixture Distribution Transport Infrastructure
**Status: ✅ COMPLETE**
- Transport interface and registry
- HTTPTransport fully implemented
- S3Transport stub (transport layer only)
- SSHTransport stub (transport layer only)
- LocalFileTransport stub

### Phase 33: Fixture Distribution Transport Implementation
**Status: ✅ COMPLETE**
- HTTPTransport fully functional
- LocalFileTransport stub
- S3Transport stub
- SSHTransport stub
- Exponential backoff implementation
- Comprehensive test coverage

### Phase 34: Fixture Distribution Transport SDK Integration
**Status: ✅ COMPLETE** (as of 2026-07-03)
- S3Transport with full AWS SDK v2 integration
- SSHTransport with full SSH library integration
- Proper host key verification for SSH (known_hosts format)
- SSRF protection for S3 endpoints
- Comprehensive test coverage including host key verification
- Updated documentation

## Current Phase: 35

### Phase 35: Performance Testing, Security Hardening, and Monitoring
**Status: ✅ COMPLETE**
**Document: `docs/phase-35-performance-and-hardening.md`**
**Completion Date: 2026-07-03**

**Goals:**
1. Performance benchmarks for all transports
2. Security audit of transport implementations
3. Monitoring metrics for transport operations
4. CI/e2e evidence verification

**Implementation:**
- Transport performance benchmarks (S3, SSH, LocalFile, HTTP)
- Security hardening (SSRF, host key verification, input validation)
- Observability integration (metrics, logging, health checks)
- CI automation for performance and security testing

## Current Phase: 38

### Phase 36: Staging Deployment and Traffic Comparison
**Status: ✅ COMPLETE**
**Document: `docs/phase-36-staging-deployment.md`**
**Completion Date: 2026-07-03**

**Goals:**
1. ✅ Deploy to staging environment (configuration and Docker Compose ready)
2. ✅ Compare behavior against CSS (CSS comparison transport harness)
3. ✅ Test Solid client compatibility (compatibility tests)
4. ✅ Verify rollback procedures (rollback documentation)

**Implementation:**
- Staging environment setup
- Traffic comparison harness
- Client compatibility testing
- Rollback and emergency procedures

### Phase 37: Production Deployment and Monitoring
**Status: ✅ COMPLETE**
**Document: `docs/phase-37-production-deployment.md`**
**Completion Date: 2026-07-04**
**Completion Summary: `docs/phase-37-completion.md`**

**Goals:**
1. ✅ Production deployment planning
2. ✅ Full monitoring implementation
3. ✅ Alerting and incident response
4. ✅ Production rollout

**Implementation:**
- Production configuration and deployment manifests
- Complete monitoring stack (metrics, logs, traces)
- Alerting rules and incident response procedures
- Canary and gradual rollout mechanism

## Future Phases

### Phase 37: Production Deployment and Monitoring
**Status: 📝 PLANNED**

**Goals:**
1. Production deployment planning
2. Full monitoring implementation
3. Alerting and incident response
4. Production rollout

### Phase 38: Security Audit and Formal Hardening
**Status: 📝 PLANNED**
**Related: `docs/solid-platform-maturity-phases.md` Phase 26**

### Phase 39+: Continued Platform Maturity
See `docs/solid-platform-maturity-phases.md` for Phases 18-31.

## Execution Priority

Based on the repository audit and current state, the recommended execution order is:

1. **Phase 15** - Native Go/Rust Solid runtime path
   - Required for migration from CSS
   - Currently partial
   - **CURRENT PRIORITY**
   
2. **Phase 16-17** - Notifications, live updates, and production hardening
   - Required for production operations
   - Currently partial
   
3. **Phase 18-31** - Platform Maturity Phases
   - See `docs/solid-platform-maturity-phases.md` for details

**Note**: Phase 38 (Security Audit and Formal Hardening) and Phase 13 (Decision Cache and Invalidation) are now COMPLETE.

## Blockers

The following must be resolved before enforcement can be enabled:

1. ✅ **Authn middleware** - DPoP/JWT verification is complete
2. ✅ **Policy discovery** - Live discovery with cache is complete
3. ⚠️ **RDF parser boundary** - Scaffolding exists, needs completion
4. ⚠️ **WAC/ACP parsers** - Complete, need enforcement mode
5. ⚠️ **CSS comparison harness** - Complete
6. ✅ **Decision cache** - Fully implemented and tested
7. ✅ **Enforcement gates** - Complete with emergency bypass
8. ⚠️ **Logs privacy review** - AgentIdentity redaction complete, needs broader review

## Current Safety Boundary

**The sidecar MUST remain CSS-authoritative and non-enforcing until ALL of the following are true:**

- ✅ CI and e2e checks are visible and reliable
- ✅ Authn middleware accepts only verified and key-bound identity
- ✅ Live policy discovery and loading/cache works in shadow mode
- ⚠️ RDF parser boundary needs completion
- ✅ WAC parser in shadow mode
- ✅ WAC evaluator in shadow mode
- ✅ WAC/ACP parser/evaluator can be compared against CSS
- ❌ Mismatch rate needs to be measured
- ✅ Enforcement gates and emergency bypass exist
- ✅ Decision cache implemented for enforcement performance
- ⚠️ Logs need privacy review (AgentIdentity redaction complete)

## Quick Status Check

Run the following to verify current state:

```bash
# Verify all Go tests pass
bash scripts/verify.sh go

# Verify all Rust tests pass  
bash scripts/verify.sh rust

# Verify formatting
bash scripts/verify.sh all

# Check GitHub CI status
gh run list --limit 5 -s success

# Check for failed runs
gh run list --limit 5 -s failure
```

## Documents Reference

- `docs/solid-runtime-phase-roadmap.md` - Original Phase 1-17 roadmap
- `docs/solid-platform-maturity-phases.md` - Phase 18-31 roadmap
- `docs/repository-audit-2026-07-02.md` - Current audit and reconciliation
- `docs/implementation-status.md` - Current implementation status
- `docs/phase-13-completion.md` - Phase 13 completion (Decision Cache)
- `docs/phase-33-completion.md` - Phase 33 completion
- `docs/phase-34-completion.md` - Phase 34 completion
- `docs/phase-35-performance-and-hardening.md` - Phase 35 definition
- `docs/phase-36-staging-deployment.md` - Phase 36 definition
- `docs/phase-37-production-deployment.md` - Phase 37 definition
- `docs/phase-38-security-audit.md` - Phase 38 definition
- `docs/phase-38-completion.md` - Phase 38 completion
