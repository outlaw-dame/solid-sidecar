# Runtime Mode Gating

**Phase 40 Task 7 Implementation**

This document describes the runtime mode gating system implemented to ensure safe operation of the Solid runtime. The system prevents unsafe mode transitions in production environments and requires explicit readiness verification.

## Overview

The Solid runtime supports three operational modes:

1. **CSS Proxy Mode (`css_proxy`)** - Default, safest mode where all requests are proxied to Community Solid Server
2. **Hybrid Mode (`hybrid`)** - Mixed mode where some requests use native path, others use CSS
3. **Native Mode (`native`)** - Full native Solid runtime where all requests are handled natively

## Production Safety Guardrails

### Default Configuration

In production environments, the runtime is configured with safety guardrails enabled by default:

```go
// DefaultRuntimeConfig returns a safe default configuration
func DefaultRuntimeConfig() RuntimeConfig {
    return RuntimeConfig{
        Mode:                RuntimeModeCSSProxy,
        ProductionMode:      true,  // Production safety enabled by default
        AllowNativeMode:     false, // Native mode disabled by default
        AllowHybridMode:     false, // Hybrid mode disabled by default  
        RequireComparisonEvidence: true, // Require CSS comparison before transitions
        // ... other settings
    }
}
```

### Guardrail Behavior

With production guardrails enabled:

1. **❌ BLOCKED**: Transition from `css_proxy` → `hybrid` or `native` 
2. **❌ BLOCKED**: Transition from `hybrid` → `native`
3. **✅ ALLOWED**: Transition from `native` → `hybrid` or `css_proxy` (rollback)
4. **✅ ALLOWED**: Transition from `hybrid` → `css_proxy` (rollback)
5. **✅ ALLOWED**: Same mode transitions

### Enabling Advanced Modes

To enable hybrid or native modes in production, you must:

1. **Explicitly allow the mode**:
   ```go
   config.AllowNativeMode = true  // For native mode
   config.AllowHybridMode = true  // For hybrid mode
   ```

2. **Provide comparison evidence** (if required):
   ```go
   config.RequireComparisonEvidence = true
   config.ComparisonEvidence = RuntimeModeComparisonEvidence{
       ComparisonPassed: true,
       NativeComparison: RuntimeComparisonResults{
           Passed: true,
           // ... test results
       },
       HybridComparison: RuntimeComparisonResults{
           Passed: true,
           // ... test results
       },
   }
   ```

## Comparison Evidence System

### Purpose

The comparison evidence system ensures that mode transitions only occur after comprehensive testing that verifies:
- Behavioral compatibility between CSS and native implementations
- No regressions in Solid protocol compliance
- Acceptable performance characteristics
- Proper error handling and edge cases

### Evidence Structure

```go
// RuntimeModeComparisonEvidence stores CSS comparison results for mode transition verification
type RuntimeModeComparisonEvidence struct {
    // CSSProxyBaseline contains baseline behavior evidence from CSS proxy mode
    CSSProxyBaseline RuntimeComparisonBaseline
    
    // HybridComparison contains comparison results from hybrid mode testing
    HybridComparison RuntimeComparisonResults
    
    // NativeComparison contains comparison results from native mode testing
    NativeComparison RuntimeComparisonResults
    
    // LastComparisonTimestamp is when the most recent comparison was performed
    LastComparisonTimestamp time.Time
    
    // ComparisonPassed indicates whether comparison tests passed for transition readiness
    ComparisonPassed bool
}

// RuntimeComparisonBaseline stores baseline behavior measurements
type RuntimeComparisonBaseline struct {
    RequestCount    int64
    SuccessRate     float64  // Percentage
    AverageLatency  time.Duration
    ErrorRate       float64  // Percentage
}

// RuntimeComparisonResults stores comparison test results between modes
type RuntimeComparisonResults struct {
    ComparisonTimestamp time.Time
    TestDuration        time.Duration
    RequestCount        int64
    BehaviorMatches     int64
    BehaviorMismatches  int64
    AllowedDifferences  int64
    CriticalMismatches  int64
    Passed              bool
}
```

### Evidence Management

The runtime provides APIs for managing comparison evidence:

```go
// SetComparisonEvidence sets the complete CSS comparison evidence
runtime.SetComparisonEvidence(evidence RuntimeModeComparisonEvidence)

// UpdateComparisonEvidence updates specific comparison results
runtime.UpdateComparisonEvidence(mode RuntimeMode, results RuntimeComparisonResults)

// ClearComparisonEvidence clears all comparison evidence
runtime.ClearComparisonEvidence()

// IsModeTransitionAllowed checks if a mode transition would be allowed
allowed := runtime.IsModeTransitionAllowed(RuntimeModeNative)
```

## Rollback Controls

### Automatic History Tracking

The runtime automatically tracks mode transition history to enable safe rollbacks:

```go
// ModeHistory returns the recent mode transition history
history := runtime.ModeHistory() // Returns []RuntimeMode

// RollbackMode reverts to the previous runtime mode if safe
runtime.RollbackMode()
```

### Rollback Behavior

- Rollbacks are subject to the same production guardrails as forward transitions
- Only transitions that would be allowed in the current configuration can be rolled back
- History is limited to the last 10 transitions to prevent memory bloat
- Rollbacks are logged as warnings for operational visibility

## Development vs Production Configuration

### Development Configuration

For testing and development, use `TestRuntimeConfig()` which disables production guardrails:

```go
// TestRuntimeConfig returns a configuration suitable for testing
// This disables production safety guardrails to allow mode transitions in tests
func TestRuntimeConfig() RuntimeConfig {
    return RuntimeConfig{
        ProductionMode:      false, // Disabled for testing
        AllowNativeMode:     true,  // Allow all modes in tests
        AllowHybridMode:     true,  // Allow all modes in tests
        RequireComparisonEvidence: false, // Don't require comparison evidence in tests
        ComparisonEvidence: RuntimeModeComparisonEvidence{
            ComparisonPassed: true, // Assume tests have passed comparison
        },
        // ... other settings
    }
}
```

### Configuration Examples

**Production Configuration (Safe Default):**
```yaml
runtime:
  mode: css_proxy
  production_mode: true
  allow_native_mode: false
  allow_hybrid_mode: false
  require_comparison_evidence: true
```

**Staging Configuration (With Safety):**
```yaml
runtime:
  mode: css_proxy
  production_mode: true
  allow_native_mode: false
  allow_hybrid_mode: true
  require_comparison_evidence: true
  comparison_evidence:
    comparison_passed: true
    hybrid_comparison:
      passed: true
      behavior_matches: 1000
      behavior_mismatches: 0
      critical_mismatches: 0
```

**Development Configuration (Unrestricted):**
```yaml
runtime:
  mode: css_proxy
  production_mode: false
  allow_native_mode: true
  allow_hybrid_mode: true
  require_comparison_evidence: false
```

## Transition Workflow

### Safe Migration Path

1. **Start in CSS Proxy Mode** (default)
   - All requests proxied to CSS
   - Establish baseline behavior

2. **Generate Comparison Evidence**
   - Run comprehensive tests comparing CSS vs native behavior
   - Capture performance metrics and error rates
   - Verify protocol compliance

3. **Enable Hybrid Mode** (requires evidence)
   - Configure `allow_hybrid_mode: true`
   - Provide valid comparison evidence
   - Monitor behavior and performance

4. **Generate Native Evidence**
   - Run comprehensive tests for native mode
   - Verify all critical paths work correctly

5. **Enable Native Mode** (requires evidence)
   - Configure `allow_native_mode: true`
   - Provide valid comparison evidence
   - Gradual rollout with monitoring

6. **Maintain Rollback Capability**
   - Keep CSS running for fallback
   - Monitor for regressions
   - Quick rollback if issues detected

## Error Handling

When a mode transition is blocked, the error message includes the reason:

```
"cannot transition from css_proxy to native: production safety guardrails prevent this transition"
```

This provides clear operational feedback about why the transition was blocked.

## Operational Considerations

### Production Safety Principles

1. **Fail Safe**: Default to the safest mode (CSS proxy)
2. **Explicit Opt-in**: Advanced modes require explicit configuration
3. **Evidence-Based**: Transitions require proven compatibility
4. **Reversible**: Always maintain ability to rollback to safer modes
5. **Visible**: All mode changes are logged for operational awareness

### Monitoring and Alerting

- Mode transitions should trigger alerts in production
- Rollback events should trigger high-priority alerts
- Failed transition attempts should be logged and monitored
- Comparison evidence expiration should be monitored

### Configuration Management

- Production configurations should require multiple approvals
- Runtime mode changes should be audited
- Comparison evidence should have expiration timestamps
- Configuration changes should be version-controlled

## Security Considerations

### Attack Surface Reduction

- Production guardrails reduce the attack surface by limiting runtime modes
- Native mode has the largest attack surface (full Solid implementation)
- CSS proxy mode has the smallest attack surface (delegates to CSS)

### Defense in Depth

- Multiple layers of protection prevent unsafe configurations
- Production mode + guardrails + evidence requirements
- Each layer must be explicitly bypassed

### Audit Trail

- All mode transitions are logged with timestamps
- Rollback events are logged as warnings
- Failed attempts are logged with reasons
- Provides comprehensive audit trail for security investigations

## API Reference

### Configuration Types

```go
// RuntimeMode represents the current runtime mode
type RuntimeMode string

const (
    RuntimeModeCSSProxy RuntimeMode = "css_proxy"
    RuntimeModeHybrid   RuntimeMode = "hybrid"  
    RuntimeModeNative   RuntimeMode = "native"
)

// RuntimeConfig holds configuration for the Solid runtime
type RuntimeConfig struct {
    Mode                    RuntimeMode
    ProductionMode          bool
    AllowNativeMode         bool
    AllowHybridMode         bool
    RequireComparisonEvidence bool
    ComparisonEvidence      RuntimeModeComparisonEvidence
    // ... other fields
}
```

### Runtime Methods

```go
// Mode returns the current runtime mode
func (rt *Runtime) Mode() RuntimeMode

// SetMode changes the runtime mode with validation
func (rt *Runtime) SetMode(mode RuntimeMode) error

// RollbackMode reverts to the previous runtime mode
func (rt *Runtime) RollbackMode() error

// ModeHistory returns the recent mode transition history
func (rt *Runtime) ModeHistory() []RuntimeMode

// IsModeTransitionAllowed checks if a transition would be allowed
func (rt *Runtime) IsModeTransitionAllowed(to RuntimeMode) bool

// SetComparisonEvidence sets comparison evidence
func (rt *Runtime) SetComparisonEvidence(evidence RuntimeModeComparisonEvidence)

// UpdateComparisonEvidence updates specific comparison results  
func (rt *Runtime) UpdateComparisonEvidence(mode RuntimeMode, results RuntimeComparisonResults) error

// ClearComparisonEvidence clears all comparison evidence
func (rt *Runtime) ClearComparisonEvidence()
```

### Configuration Helpers

```go
// DefaultRuntimeConfig returns a safe default configuration
func DefaultRuntimeConfig() RuntimeConfig

// TestRuntimeConfig returns a configuration suitable for testing
func TestRuntimeConfig() RuntimeConfig
```

## Implementation Status

✅ **Task 7: Runtime Mode Gating - COMPLETE**

- ✅ Ensure `native` mode cannot be enabled in production without explicit guardrails
- ✅ Ensure `hybrid` mode cannot be enabled in production without explicit guardrails  
- ✅ Add comparison evidence requirements for mode transitions
- ✅ Add rollback controls for runtime mode changes
- ✅ Document runtime mode safety and readiness requirements

## Next Steps

1. **Integration Testing**: Test runtime mode gating in integration environments
2. **Configuration Documentation**: Update configuration schema with new runtime options
3. **Monitoring Integration**: Add metrics and alerts for runtime mode changes
4. **Evidence Generation Tools**: Create tools for generating comparison evidence
5. **Migration Playbook**: Document step-by-step migration procedures

## See Also

- `docs/phase-40-status-reconciliation.md` - Phase 40 task tracking
- `docs/solid-runtime-roadmap-index.md` - Runtime roadmap
- `internal/runtime/runtime.go` - Runtime implementation
- `internal/runtime/runtime_test.go` - Runtime tests