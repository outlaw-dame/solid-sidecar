# Phase 19: Cache Invalidation Design

**Status**: Design Complete, Partial Implementation  
**Date**: 2026-07-09  
**Priority**: P0 - Critical for Authorization Authority

---

## Overview

This document describes the cache invalidation design for Phase 19 (Native Authorization Authority). The goal is to ensure that authorization caches are invalidated when storage writes occur, preventing stale decisions that could lead to security vulnerabilities.

## Problem Statement

When resources or policies are written to storage, the authorization decision cache and policy cache must be invalidated to ensure that:
1. New/updated policies take effect immediately
2. Resource changes are reflected in authorization decisions
3. No stale allow/deny decisions persist

Without proper cache invalidation, an attacker could:
- Update a policy but have the old decision cached (allowing unauthorized access)
- Update a resource but have the old policy cached (denying legitimate access)
- Delete a policy but have decisions cached (incorrect authorization)

## Current State

### What Exists

1. **Policy Engine Cache** (`internal/runtime/policy.go`)
   - `invalidatePolicyCache(policyURI)` method exists (line 921)
   - Called when policies are stored (line 424)
   - Performs full cache invalidation for safety

2. **Decision Cache** (`internal/authz/cache/cache.go`)
   - MemoryCache with Get/Put/Invalidate methods
   - Supports `InvalidatePolicy`, `InvalidateResource`, `InvalidateAgent`
   - No automatic invalidation on storage writes

3. **Storage Layer** (`internal/storage/interface.go`)
   - No cache invalidation hooks
   - Storage operations are independent of cache

### What's Missing

1. **Automatic cache invalidation** when resources are written/deleted
2. **Policy cache invalidation** when policy resources change
3. **Decision cache invalidation** when any resource changes
4. **Storage-cache integration** mechanism

---

## Design

### Option 1: Explicit Invalidation (Current Implementation)

**Approach**: Add explicit cache invalidation calls at the storage layer boundaries.

**Pros**:
- Simple and safe
- No hidden behavior
- Easy to understand and debug
- No performance overhead for unused features

**Cons**:
- Requires manual calls
- Easy to forget
- Not automatic

**Implementation**:
```go
// After writing a resource:
storage.Put(ctx, uri, resource)
policyEngine.InvalidateResource(uri)
authzCache.InvalidateResource(uri)

// After writing a policy:
storage.Put(ctx, policyURI, policyResource)
policyEngine.InvalidatePolicy(policyURI)
authzCache.InvalidatePolicy(policyURI)
```

### Option 2: Event-Driven Invalidation (Recommended for Production)

**Approach**: Storage layer emits events on writes, cache layers subscribe and invalidate.

**Pros**:
- Automatic
- Loose coupling
- Scalable
- Can be extended to other caches

**Cons**:
- More complex
- Event ordering concerns
- Performance overhead
- Harder to debug

**Implementation**:
```go
// Storage layer emits events
storage.OnWrite(func(uri string) {
    eventBus.Publish(ResourceWritten{URI: uri})
})

// Cache layers subscribe
eventBus.Subscribe(func(evt ResourceWritten) {
    authzCache.InvalidateResource(evt.URI)
})
```

### Option 3: Storage-Cache Integration (Future)

**Approach**: Storage layer directly invalidates caches.

**Pros**:
- Tight integration
- Guaranteed consistency
- Most efficient

**Cons**:
- Tight coupling
- Violates separation of concerns
- Hard to test
- Hard to swap implementations

---

## Current Implementation (Phase 19 Partial)

### Decision Cache Invalidation API

The `internal/authz/cache/cache.go` already provides:

```go
// Invalidate all entries for a specific policy version
InvalidatePolicy(ctx context.Context, policyVersion string) error

// Invalidate all entries for a specific resource
InvalidateResource(ctx context.Context, resource string) error

// Invalidate all entries for a specific agent
InvalidateAgent(ctx context.Context, agent string) error

// Clear all cache entries
Clear(ctx context.Context) error
```

### Policy Engine Cache Invalidation

The `internal/runtime/policy.go` already has:

```go
// invalidatePolicyCache invalidates cache entries for a specific policy
func (p *PolicyEngineLayer) invalidatePolicyCache(policyURI string)

// InvalidateAllCache invalidates all cached evaluation results
func (p *PolicyEngineLayer) InvalidateAllCache()
```

These are called:
- When policies are stored (line 424)
- When policies are deleted (line 1045)

### Missing Pieces

1. **Resource write invalidation**: No automatic invalidation when regular resources are written
2. **Decision cache access**: The gateway doesn't have access to the authz decision cache
3. **Storage hooks**: No mechanism to hook into storage writes

---

## Recommended Implementation Path

### Phase 19.1: Explicit Invalidation (Immediate)

Add explicit cache invalidation calls in the storage adapter layer:

```go
// In internal/runtime/storage_adapter.go
func (a *StorageEngineAdapter) Put(ctx context.Context, uri string, resource *storage.WriteResource) error {
    err := a.backend.Put(ctx, uri, resource)
    if err != nil {
        return err
    }
    
    // Invalidate caches for this resource
    if a.policyEngine != nil {
        a.policyEngine.InvalidateResource(uri)
    }
    if a.authzCache != nil {
        a.authzCache.InvalidateResource(uri)
    }
    
    return nil
}
```

**Status**: Not yet implemented

### Phase 19.2: Policy Cache Invalidation (Partial)

The policy cache already invalidates when policies are written. This covers:
- WAC policy changes
- ACP policy changes
- SAI policy changes

**Status**: ✅ Implemented

### Phase 19.3: Decision Cache Invalidation (Partial)

The decision cache has the API but isn't automatically called on writes.

**Status**: ⚠️ API exists, automatic calling not implemented

### Phase 19.4: Storage Write Hooks (Future)

Add hooks to the StorageBackend interface for write events:

```go
type StorageBackend interface {
    // Existing methods...
    
    // SetWriteHook sets a callback to be called after writes
    SetWriteHook(hook func(uri string))
    
    // SetDeleteHook sets a callback to be called after deletes
    SetDeleteHook(hook func(uri string))
}
```

**Status**: ❌ Not implemented

---

## Acceptance Criteria (Phase 19)

From `docs/solid-platform-maturity-phases.md`:

- [x] Enforcement-ready WAC evaluator path (partial - middleware implemented)
- [ ] Enforcement-ready ACP evaluator path
- [ ] SAI enforcement decision according to Phase 7 outcome
- [ ] Policy discovery cache with invalidation tied to storage writes **← THIS DOCUMENT**
- [ ] Deny/allow reason taxonomy safe for audit and client-facing diagnostics
- [ ] Strict fail-closed/fail-open policy by endpoint class
- [ ] Operator-visible decision trace IDs
- [ ] Emergency CSS-authoritative fallback where CSS is still present
- [ ] Regression suite proving previous shadow fixtures behave the same under enforcement

## What's Been Implemented

1. ✅ **Enforcement Middleware** (`internal/authz/middleware.go`)
   - Actually enforces authorization decisions when enforcement is enabled
   - Returns 403 Forbidden on Deny decisions
   - Falls back to CSS on Abstain decisions
   - Logs all enforcement decisions
   - Integrated into gateway server

2. ✅ **Enforcement Tests** (`internal/authz/middleware_test.go`)
   - Tests for Allow decisions
   - Tests for Deny decisions
   - Tests for shadow mode passthrough
   - Tests for evaluation errors
   - Tests for custom status codes

3. ✅ **Policy Cache Invalidation** (`internal/runtime/policy.go`)
   - Invalidates when policies are stored/deleted
   - Full cache flush for safety

4. ⚠️ **Decision Cache API** (`internal/authz/cache/cache.go`)
   - Invalidation API exists
   - Not automatically called on storage writes

## What Needs to Be Done

### P0 (Critical)

1. **Add explicit cache invalidation to storage adapter**
   - Modify `internal/runtime/storage_adapter.go` to invalidate caches on Put/Delete
   - Call `policyEngine.InvalidateResource(uri)`
   - Call `authzCache.InvalidateResource(uri)`

2. **Wire up the decision cache to the gateway**
   - Pass decision cache to gateway
   - Make it available to middleware

3. **Add cache invalidation tests**
   - Test that writes invalidate caches
   - Test that policies invalidate caches
   - Test that stale decisions don't persist

### P1 (High)

4. **Implement CSS comparison thresholds**
   - Track mismatch rates
   - Block enforcement if mismatch rate too high
   - Configurable thresholds

5. **Add regression suite**
   - Compare shadow vs enforcement behavior
   - Ensure same decisions in both modes

### P2 (Medium)

6. **Implement automatic storage hooks**
   - Add WriteHook/DeleteHook to StorageBackend interface
   - Implement event-driven invalidation

7. **Add fine-grained cache invalidation**
   - Track which cache entries depend on which resources
   - Only invalidate affected entries

---

## Security Considerations

### Cache Poisoning
- Cache entries must include evaluator/policy/parser versions
- Stale entries must be detected and rejected
- Cache must be invalidated on evaluator/policy changes

### Time-of-Check to Time-of-Use
- Authorization check and resource access must be atomic
- Cache TTL must be short enough to prevent ToCTOU attacks
- Consider caching only for GET requests, not writes

### Cache Invalidation Race Conditions
- Multiple concurrent writes could lead to missed invalidations
- Use proper locking in cache invalidation methods
- Consider version numbers for cache entries

---

## Testing

### Unit Tests Needed

1. `TestCacheInvalidationOnResourceWrite`
2. `TestCacheInvalidationOnPolicyWrite`
3. `TestCacheInvalidationOnResourceDelete`
4. `TestCacheInvalidationConcurrency`
5. `TestCacheInvalidationRaceConditions`

### Integration Tests Needed

1. `TestEndToEndCacheInvalidation`
2. `TestPolicyChangeTakesEffectImmediately`
3. `TestResourceChangeAffectsAuthorization`

---

## Recommendations

1. **Start with explicit invalidation** (Option 1) for Phase 19
2. **Add comprehensive tests** before marking as complete
3. **Document the cache invalidation strategy**
4. **Monitor cache hit/miss rates** in production
5. **Implement automatic hooks** (Option 2) as a follow-up

---

## Files to Modify

### For Explicit Invalidation (Recommended First Step)

1. `internal/runtime/storage_adapter.go`
   - Add cache references
   - Call invalidation methods on Put/Delete

2. `internal/gateway/server.go`
   - Pass caches to storage adapter
   - Wire up cache invalidation

3. `internal/authz/cache/cache.go`
   - Already has needed methods

### For Event-Driven Invalidation (Future)

1. `internal/storage/interface.go`
   - Add hook methods to StorageBackend

2. `internal/runtime/event_stream.go`
   - Add storage write events

3. `internal/authz/cache/cache.go`
   - Subscribe to storage events

---

## Conclusion

The infrastructure for cache invalidation exists (invalidation methods), but the automatic tying to storage writes is not complete. For Phase 19 to be marked complete, we need:

1. ✅ Enforcement middleware that actually enforces decisions (DONE)
2. ⚠️ Cache invalidation API (EXISTS)
3. ❌ Automatic cache invalidation on storage writes (NOT DONE)
4. ❌ CSS comparison thresholds (NOT DONE)

**Recommended**: Implement explicit cache invalidation calls in the storage adapter as the next step. This provides the "tied to storage writes" requirement in a safe, explicit manner.
