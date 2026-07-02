# Replay and Cache Multi-Instance Story

This document describes the replay protection and cache coordination strategy for multi-instance deployments as required by Phase 17.

## Overview

In a multi-instance deployment of the Solid runtime:

- Multiple runtime instances serve traffic behind a load balancer
- DPoP replay protection must be coordinated across instances
- Authorization decision caches must be invalidated consistently
- Policy document caches must be consistent across instances

This document describes the strategies for handling these scenarios.

## Replay Protection Multi-Instance Strategy

### Problem Statement

DPoP (Demonstrating Proof of Possession) requires that each proof can only be used once. In a multi-instance deployment:

1. Client sends request with DPoP proof to Instance A
2. Instance A validates and accepts the proof
3. Client immediately sends another request with the same proof to Instance B
4. Instance B must reject the proof as a replay

### Solution: Distributed Replay Cache

#### Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Instance A  │    │  Instance B  │    │  Instance C  │
└──────┬──────┘    └──────┬──────┘    └──────┬──────┘
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────────────────────────────────────────┐
│           Distributed Replay Cache               │
│  (Redis, DynamoDB, etc.)                         │
└─────────────────────────────────────────────────┘
```

#### Implementation Options

**Option 1: Redis Cluster**

```yaml
# Configuration for distributed replay cache
replay_cache:
  backend: "redis" # memory, redis, dynamodb
  redis:
    endpoints: ["redis-primary:6379", "redis-replica:6379"]
    password: "" # From environment
    ttl: "1h" # Match nonce TTL
    prefix: "solid:replay:"
    connection_timeout: "100ms"
    read_timeout: "50ms"
    write_timeout: "50ms"
  dynamodb:
    table_name: "solid-replay-cache"
    region: "us-east-1"
    ttl_attribute: "expires_at"
    read_capacity: 1000
    write_capacity: 1000
```

**Option 2: In-Memory with Gossip**

For deployments where external dependencies are not desired:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Instance A  │◄──►│  Instance B  │◄──►│  Instance C  │
│  Replay     │    │  Replay     │    │  Replay     │
│  Cache      │    │  Cache      │    │  Cache      │
└─────────────┘    └─────────────┘    └─────────────┘
     ▲                   ▲                   ▲
     │                   │                   │
     ▼                   ▼                   ▼
┌─────────────────────────────────────────────────┐
│           Gossip Protocol                         │
│  (Broadcast replay cache entries to peers)       │
└─────────────────────────────────────────────────┘
```

#### Replay Cache Interface

```go
// ReplayCache defines the interface for replay protection
type ReplayCache interface {
    // CheckAndSet checks if the nonce exists, and if not, stores it
    // Returns true if this is the first time seeing this nonce (allow)
    // Returns false if this nonce was already seen (replay - deny)
    CheckAndSet(ctx context.Context, nonce string, ttl time.Duration) (bool, error)
    
    // Cleanup removes expired entries (called periodically)
    Cleanup(ctx context.Context) error
    
    // Close releases resources
    Close() error
}

// DistributedReplayCache implements ReplayCache with distributed backend
type DistributedReplayCache struct {
    backend    ReplayCacheBackend
    localCache *lru.Cache // Local LRU cache for performance
    ttl        time.Duration
    metrics    ReplayCacheMetrics
}

// ReplayCacheBackend defines the backend storage interface
type ReplayCacheBackend interface {
    Get(ctx context.Context, key string) (bool, error)
    Set(ctx context.Context, key string, ttl time.Duration) error
    Delete(ctx context.Context, key string) error
}
```

#### Implementation

**Redis Backend:**

```go
// RedisReplayBackend implements ReplayCacheBackend using Redis
type RedisReplayBackend struct {
    client redis.Client
    prefix string
}

func (r *RedisReplayBackend) Get(ctx context.Context, key string) (bool, error) {
    redisKey := r.prefix + key
    result, err := r.client.Exists(ctx, redisKey).Result()
    if err != nil {
        return false, fmt.Errorf("redis get failed: %w", err)
    }
    return result == 1, nil
}

func (r *RedisReplayBackend) Set(ctx context.Context, key string, ttl time.Duration) error {
    redisKey := r.prefix + key
    _, err := r.client.Set(ctx, redisKey, "1", ttl).Result()
    if err != nil {
        return fmt.Errorf("redis set failed: %w", err)
    }
    return nil
}
```

**Gossip-Based Coordination:**

```go
// GossipReplayCache implements ReplayCache with gossip-based coordination
type GossipReplayCache struct {
    mu         sync.RWMutex
    entries    map[string]time.Time
    ttl        time.Duration
    peers      []string
    gossipPort int
    
    // For gossip communication
    gossipInterval time.Duration
    gossipTimeout  time.Duration
}

func (g *GossipReplayCache) StartGossip() {
    ticker := time.NewTicker(g.gossipInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            g.broadcastReplayEntries()
            g.receiveReplayEntries()
        }
    }
}

func (g *GossipReplayCache) broadcastReplayEntries() {
    // Send local entries to all peers
    // Use HTTP or gRPC for communication
}

func (g *GossipReplayCache) receiveReplayEntries() {
    // Receive entries from peers and merge into local cache
}
```

#### Performance Considerations

| Approach | Latency | Throughput | Complexity | Dependencies |
|----------|---------|------------|------------|--------------|
| Local Only | ~1μs | Very High | Low | None |
| Redis | ~1-5ms | High | Medium | Redis Cluster |
| DynamoDB | ~5-10ms | Medium | Medium | AWS DynamoDB |
| Gossip | ~10-100ms | Medium | High | None |

**Recommendation**: Use Redis for most deployments. Use gossip only when external dependencies cannot be used.

#### Fallback Behavior

If the distributed cache is unavailable:

1. **Degrade to local cache**: Each instance maintains its own replay cache
2. **Increase nonce TTL**: Extend TTL to account for clock skew between instances
3. **Log warnings**: Alert operators that replay protection is degraded
4. **Fail closed**: If uncertainty exists, deny access (replay suspected)

```go
// Configurable fallback behavior
func (r *ReplayCache) CheckAndSet(ctx context.Context, nonce string, ttl time.Duration) (bool, error) {
    // Try distributed cache first
    if r.distributed != nil {
        allowed, err := r.distributed.CheckAndSet(ctx, nonce, ttl)
        if err == nil {
            return allowed, nil
        }
        
        // Log error but continue with local cache
        r.logger.Warn("Distributed replay cache unavailable", "error", err)
        r.metrics.RecordDistributedCacheError()
    }
    
    // Fall back to local cache
    return r.local.CheckAndSet(nonce, ttl)
}
```

## Cache Coordination Multi-Instance Strategy

### Problem Statement

Authorization decision caches store:
- Agent identity
- Resource URI
- Policy hash
- Decision (allow/deny)
- Timestamp

When policies change, all instances must invalidate their caches for affected resources.

### Solution: Cache Invalidation Strategies

#### Strategy 1: Time-Based Invalidation

```yaml
# Simple TTL-based invalidation
cache:
  decision:
    enabled: true
    ttl: "5m" # Short TTL for safety
    max_size: 10000
```

**Pros**: Simple, no coordination needed
**Cons**: Sub-optimal performance, cache stampede possible

#### Strategy 2: Policy Version Invalidation

Include policy version in cache key:

```
cache_key = hash(agent + resource + policy_version + parser_version + evaluator_version)
```

When policy changes, version increments, cache key changes, old entries are naturally invalidated.

**Pros**: Automatic invalidation, no coordination needed
**Cons**: Requires version tracking in policy documents

#### Strategy 3: Explicit Invalidation Messages

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Instance A  │    │  Instance B  │    │  Instance C  │
└──────┬──────┘    └──────┬──────┘    └──────┬──────┘
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────────────────────────────────────────┐
│           Message Queue / PubSub                   │
│  (NATS, Kafka, Redis PubSub, etc.)                │
└─────────────────────────────────────────────────┘
```

```go
// CacheInvalidationMessage defines the invalidation message structure
type CacheInvalidationMessage struct {
    Type      string    `json:"type"`      // "policy_change", "resource_update"
    Resource  string    `json:"resource"`  // Resource URI
    Policy    string    `json:"policy"`    // Policy URI
    Timestamp time.Time `json:"timestamp"` // When change occurred
    Version   string    `json:"version"`   // New policy version
}

// CacheInvalidator handles cache invalidation messages
type CacheInvalidator struct {
    pubsub      PubSub
    cache       DecisionCache
    subscriptions map[string]chan CacheInvalidationMessage
}

func (c *CacheInvalidator) Subscribe(resource string) chan CacheInvalidationMessage {
    ch := make(chan CacheInvalidationMessage, 100)
    c.subscriptions[resource] = ch
    c.pubsub.Subscribe("cache-invalidation", ch)
    return ch
}

func (c *CacheInvalidator) Invalidate(msg CacheInvalidationMessage) {
    // Broadcast to all instances
    c.pubsub.Publish("cache-invalidation", msg)
    
    // Also invalidate local cache
    c.cache.InvalidateForResource(msg.Resource)
}

// Listen for invalidation messages
func (c *CacheInvalidator) Start() {
    for msg := range c.pubsub.Subscribe("cache-invalidation") {
        c.cache.InvalidateForResource(msg.Resource)
        c.cache.InvalidateForPolicy(msg.Policy)
    }
}
```

#### Strategy 4: Distributed Cache with Automatic Invalidation

Use a distributed cache that supports:
- TTL-based expiration
- PubSub notifications on key changes
- Atomic operations

**Redis Example:**

```go
// RedisDecisionCache implements DecisionCache with Redis
type RedisDecisionCache struct {
    client      redis.Client
    prefix      string
    ttl         time.Duration
    pubsub      *redis.PubSub
    localCache  *lru.Cache // Local LRU for performance
}

func (r *RedisDecisionCache) Get(key DecisionCacheKey) (*DecisionResult, bool, error) {
    // Check local cache first
    if result, ok := r.localCache.Get(key); ok {
        return result.(*DecisionResult), true, nil
    }
    
    // Check Redis
    redisKey := r.prefix + key.String()
    data, err := r.client.Get(ctx, redisKey).Bytes()
    if err == redis.Nil {
        return nil, false, nil
    }
    if err != nil {
        return nil, false, err
    }
    
    var result DecisionResult
    if err := json.Unmarshal(data, &result); err != nil {
        return nil, false, err
    }
    
    // Store in local cache
    r.localCache.Add(key, &result)
    return &result, true, nil
}

func (r *RedisDecisionCache) InvalidateForPolicy(policyURI string) {
    // Publish invalidation message
    r.pubsub.Publish("policy-invalidation", policyURI)
    
    // Invalidate all decisions for this policy
    pattern := r.prefix + "*:*:" + policyURI + ":*" 
    // Use Redis SCAN + DEL or KEYS + DEL (careful with KEYS in production)
}

func (r *RedisDecisionCache) Start() {
    // Subscribe to invalidation messages
    go func() {
        for msg := range r.pubsub.Channel() {
            var policyURI string
            json.Unmarshal([]byte(msg.Payload), &policyURI)
            r.InvalidateForPolicy(policyURI)
        }
    }()
}
```

### Recommended Strategy: Hybrid Approach

**For most deployments**:

1. **Primary**: Policy version in cache key (Strategy 2)
2. **Fallback**: TTL-based invalidation (Strategy 1)
3. **Optional**: PubSub for immediate invalidation (Strategy 3)

**Configuration**:

```yaml
cache:
  decision:
    enabled: true
    backend: "local" # local, redis, hybrid
    ttl: "5m"
    max_size: 10000
    
    # For hybrid/redis backends
    redis:
      endpoints: ["redis:6379"]
      password: ""
      
    # For pubsub invalidation
    pubsub:
      enabled: true
      backend: "redis" # redis, nats, kafka
      channel: "cache-invalidation"
      
    # Version-based invalidation
    version_in_cache_key: true
```

## Multi-Instance Coordination Summary

### Decision Matrix

| Scenario | Recommended Approach | Complexity | Dependencies |
|----------|---------------------|------------|--------------|
| Single Instance | Local cache only | Low | None |
| Few Instances (2-5) | Gossip + local | Medium | None |
| Many Instances (5+) | Redis + pubsub | Medium | Redis |
| Cloud Deployment | DynamoDB + SNS | Medium | AWS |

### Implementation Priority

1. **Phase 1**: Local cache with TTL (already implemented)
2. **Phase 2**: Policy version in cache key
3. **Phase 3**: Redis backend for cache
4. **Phase 4**: Redis pubsub for invalidation
5. **Phase 5**: Gossip protocol for dependency-free deployments

### Monitoring and Metrics

Track the following metrics for cache coordination:

```go
type CacheMetrics struct {
    // Local cache metrics
    LocalHits      int64
    LocalMisses    int64
    LocalEvictions int64
    
    // Distributed cache metrics
    DistributedHits      int64
    DistributedMisses    int64
    DistributedErrors   int64
    DistributedLatency   time.Duration
    
    // Invalidation metrics
    InvalidationMessagesSent     int64
    InvalidationMessagesReceived int64
    InvalidationLatency          time.Duration
    
    // Fallback metrics
    FallbackToLocalCount int64
    DegradedModeDuration time.Duration
}
```

### Health Checks

Add health checks for cache coordination:

```go
// CacheCoordinationHealth checks cache coordination health
func (c *CacheCoordinator) Health() (HealthState, error) {
    // Check if distributed cache is available
    if c.distributed != nil {
        if err := c.distributed.Ping(); err != nil {
            return HealthStateDegraded, fmt.Errorf("distributed cache unavailable: %w", err)
        }
    }
    
    // Check if pubsub is working
    if c.pubsub != nil {
        if err := c.pubsub.Ping(); err != nil {
            return HealthStateDegraded, fmt.Errorf("pubsub unavailable: %w", err)
        }
    }
    
    return HealthStateHealthy, nil
}
```

## Conclusion

For multi-instance deployments:

1. **Replay Protection**: Use Redis cluster for most deployments, gossip for dependency-free deployments
2. **Cache Coordination**: Use hybrid approach with policy versions in cache keys, TTL fallback, and optional pubsub
3. **Monitoring**: Track cache hit rates, invalidation latency, and degradation events
4. **Fallback**: Degrade gracefully when coordination services are unavailable

This approach provides a balance between performance, consistency, and operational simplicity.
