package authn

import "time"

// DistributedReplayCache is an interface for distributed replay cache implementations
// that can be used across multiple sidecar instances
type DistributedReplayCache interface {
	// Store records a key with its expiration time
	// Returns true if the key was stored (not a duplicate), false if it was a replay
	Store(key string, expiresAt time.Time) (bool, error)
	// Check returns true if the key exists and has not expired
	Check(key string) (bool, error)
	// Close cleans up any resources
	Close() error
}

// RedisReplayCache is a sample implementation using Redis (stub for future implementation)
// This is a placeholder that demonstrates the interface - actual Redis implementation
// would require redis client dependencies
type RedisReplayCache struct {
	// Placeholder for Redis client
	// In actual implementation: client *redis.Client
	prefix     string
	defaultTTL time.Duration
}

// NewRedisReplayCache creates a new Redis-based replay cache
// This is a stub - actual implementation requires Redis client
func NewRedisReplayCache(address string, prefix string, defaultTTL time.Duration) (*RedisReplayCache, error) {
	// In actual implementation, this would connect to Redis
	// For now, return a stub that doesn't actually work
	return &RedisReplayCache{
		prefix:     prefix,
		defaultTTL: defaultTTL,
	}, nil
}

// Store implements DistributedReplayCache
func (r *RedisReplayCache) Store(key string, expiresAt time.Time) (bool, error) {
	// In actual implementation, this would use Redis SET NX EX
	// For now, return an error indicating Redis is not implemented
	return false, ErrDistributedCacheNotImplemented
}

// Check implements DistributedReplayCache
func (r *RedisReplayCache) Check(key string) (bool, error) {
	// In actual implementation, this would use Redis EXISTS with TTL check
	return false, ErrDistributedCacheNotImplemented
}

// Close implements DistributedReplayCache
func (r *RedisReplayCache) Close() error {
	// In actual implementation, this would close the Redis connection
	return nil
}

// ErrDistributedCacheNotImplemented is returned when distributed cache is not implemented
var ErrDistributedCacheNotImplemented = errorSafe("distributed replay cache not implemented")

// errorSafe creates a safe error that doesn't leak sensitive information
type errorSafe string

func (e errorSafe) Error() string {
	return string(e)
}

// NoOpReplayCache is a no-op implementation for testing
type NoOpReplayCache struct{}

// NewNoOpReplayCache creates a new no-op replay cache
func NewNoOpReplayCache() *NoOpReplayCache {
	return &NoOpReplayCache{}
}

// Store always returns true (no replay detection)
func (n *NoOpReplayCache) Store(key string, expiresAt time.Time) (bool, error) {
	return true, nil
}

// Check always returns false (no replay detected)
func (n *NoOpReplayCache) Check(key string) (bool, error) {
	return false, nil
}

// Close is a no-op
func (n *NoOpReplayCache) Close() error {
	return nil
}
