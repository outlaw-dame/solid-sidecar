# Phase 17: Production Hardening Plan

## Overview
Phase 17 focuses on production readiness through structured health monitoring, debug endpoint security, and memory/goroutine leak prevention.

## Current State
- OpenTelemetry scaffolding exists in `internal/observability/`
- Basic health checks exist in `internal/health/`
- Missing: Structured health states, pprof/debug endpoint policy, memory/goroutine leak tests

## Tasks

### 1. Structured Health States
**Objective**: Implement comprehensive health state management with multiple dimensions.

**Implementation**:
- [ ] Create `HealthState` struct with dimensions:
  - Overall status (healthy, degraded, unhealthy)
  - Component statuses (storage, policy, auth, etc.)
  - Dependency statuses (CSS, databases, etc.)
  - Performance metrics (latency, throughput)
- [ ] Implement health state aggregation logic
- [ ] Add health state to readiness/liveness endpoints
- [ ] Create health state transition logging
- [ ] Add health metrics to OpenTelemetry

**Files to modify**:
- `internal/health/health.go` - Extend with structured states
- `internal/health/health_test.go` - Add comprehensive tests
- `internal/observability/metrics.go` - Add health metrics

### 2. pprof/debug Endpoint Policy
**Objective**: Secure debug endpoints with proper access controls.

**Implementation**:
- [ ] Create debug endpoint middleware with:
  - Authentication requirements (DPoP/JWT)
  - Authorization checks (admin-only access)
  - Rate limiting
  - IP allowlist support
  - Disabled by default in production
- [ ] Secure pprof endpoints (/debug/pprof/*)
- [ ] Secure metrics endpoints (/metrics)
- [ ] Secure health endpoints (/health/*)
- [ ] Configuration flags for enabling/disabling debug mode

**Files to modify**:
- `internal/gateway/debug.go` - New debug endpoint handlers
- `internal/gateway/middleware.go` - Add debug auth middleware
- `internal/config/config.go` - Add debug endpoint config
- `cmd/solid-sidecar/main.go` - Wire up debug endpoints

### 3. Memory/Goroutine Leak Tests
**Objective**: Detect and prevent memory and goroutine leaks.

**Implementation**:
- [ ] Create goroutine leak detection:
  - Track goroutine creation with unique IDs
  - Monitor goroutine cleanup on shutdown
  - Detect goroutines running longer than expected
  - Report leaks in tests
- [ ] Create memory leak detection:
  - Track allocations in key paths
  - Monitor memory growth patterns
  - Set memory thresholds
  - GC pressure monitoring
- [ ] Add leak detection to CI:
  - Run tests with race detector
  - Run tests with memory profiler
  - Fail builds on detected leaks
- [ ] Create stress tests:
  - High concurrency scenarios
  - Long-running scenarios
  - Resource exhaustion scenarios

**Files to modify**:
- `internal/runtime/runtime_test.go` - Add leak detection
- `internal/observability/leak_detection.go` - New leak detection package
- `internal/observability/leak_detection_test.go` - Tests
- `.github/workflows/ci.yml` - Add leak detection to CI

## Security Considerations
- Debug endpoints must be disabled by default
- All debug endpoints must require authentication
- Health endpoints should not expose sensitive information
- Memory profiling should be rate-limited
- Goroutine tracking should have minimal overhead

## Testing Strategy
- Unit tests for health state logic
- Integration tests for debug endpoint security
- Stress tests for leak detection
- CI integration for automated leak detection

## Acceptance Criteria
- [ ] All health endpoints return structured status
- [ ] Debug endpoints are secured and disabled by default
- [ ] Leak detection runs in CI without false positives
- [ ] No memory or goroutine leaks in existing tests
- [ ] All new code has comprehensive tests
- [ ] Documentation updated for all new features

## Dependencies
- Phase 15 (Runtime path) - Complete
- Phase 16 (Notifications) - Complete
- OpenTelemetry - Exists

## Estimated Effort
- Health states: 2-3 hours
- Debug endpoint policy: 3-4 hours
- Leak tests: 4-5 hours
- Total: 9-12 hours

## Next Phase
After Phase 17, proceed to Phase 18-31 (Platform Maturity Phases) as defined in `docs/solid-platform-maturity-phases.md`.