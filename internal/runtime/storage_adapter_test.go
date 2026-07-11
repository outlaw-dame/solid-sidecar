package runtime

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/outlaw-dame/solid-sidecar/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockStorageBackend is a mock implementation of storage.StorageBackend for testing
type mockStorageBackend struct {
	name string
	data map[string]*storage.Resource
}

func newMockStorageBackend(name string) *mockStorageBackend {
	return &mockStorageBackend{
		name: name,
		data: make(map[string]*storage.Resource),
	}
}

func (m *mockStorageBackend) Name() string {
	return m.name
}

func (m *mockStorageBackend) Description() string {
	return "Mock storage backend for testing"
}

func (m *mockStorageBackend) Initialize(ctx context.Context, config map[string]string) error {
	return nil
}

func (m *mockStorageBackend) Get(ctx context.Context, uri string) (*storage.Resource, error) {
	if res, ok := m.data[uri]; ok {
		return res, nil
	}
	return nil, storage.ErrNotFound
}

func (m *mockStorageBackend) GetMetadata(ctx context.Context, uri string) (*storage.Metadata, error) {
	if res, ok := m.data[uri]; ok {
		return &res.Metadata, nil
	}
	return nil, storage.ErrNotFound
}

func (m *mockStorageBackend) Put(ctx context.Context, uri string, resource *storage.WriteResource) error {
	m.data[uri] = &storage.Resource{
		URI:      uri,
		Body:     resource.Body,
		Metadata: resource.Metadata,
	}
	return nil
}

func (m *mockStorageBackend) Delete(ctx context.Context, uri string) error {
	delete(m.data, uri)
	return nil
}

func (m *mockStorageBackend) List(ctx context.Context, containerURI string) ([]*storage.Metadata, error) {
	var results []*storage.Metadata
	for uri, res := range m.data {
		// Simple filter: if containerURI is a prefix of uri, include it
		if len(uri) > len(containerURI) && uri[:len(containerURI)] == containerURI {
			results = append(results, &res.Metadata)
		}
	}
	return results, nil
}

func (m *mockStorageBackend) Exists(ctx context.Context, uri string) (bool, error) {
	_, ok := m.data[uri]
	return ok, nil
}

func (m *mockStorageBackend) StoreBlob(ctx context.Context, data []byte) (storage.ContentAddress, error) {
	return storage.ContentAddress("mock-blob-hash"), nil
}

func (m *mockStorageBackend) GetBlob(ctx context.Context, address storage.ContentAddress) ([]byte, error) {
	return nil, errors.New("not implemented in mock")
}

func (m *mockStorageBackend) BlobExists(ctx context.Context, address storage.ContentAddress) (bool, error) {
	return false, nil
}

func (m *mockStorageBackend) DeleteBlob(ctx context.Context, address storage.ContentAddress) error {
	return nil
}

func (m *mockStorageBackend) GetQuota(ctx context.Context, storageRoot string) (*storage.QuotaInfo, error) {
	return &storage.QuotaInfo{}, nil
}

func (m *mockStorageBackend) CheckQuota(ctx context.Context, storageRoot string, additionalBytes int64) error {
	return nil
}

func (m *mockStorageBackend) GetTombstone(ctx context.Context, uri string) (*storage.Tombstone, error) {
	return nil, storage.ErrNotFound
}

func (m *mockStorageBackend) StoreTombstone(ctx context.Context, tombstone *storage.Tombstone) error {
	return nil
}

func (m *mockStorageBackend) DeleteTombstone(ctx context.Context, uri string) error {
	return nil
}

func (m *mockStorageBackend) ListTombstones(ctx context.Context, storageRoot string) ([]*storage.Tombstone, error) {
	return []*storage.Tombstone{}, nil
}

func (m *mockStorageBackend) GetLayoutVersion(ctx context.Context) (storage.StorageLayoutVersion, error) {
	return storage.CurrentStorageLayoutVersion, nil
}

func (m *mockStorageBackend) SetLayoutVersion(ctx context.Context, version storage.StorageLayoutVersion) error {
	return nil
}

func (m *mockStorageBackend) Backup(ctx context.Context, writer io.Writer) error {
	return nil
}

func (m *mockStorageBackend) Restore(ctx context.Context, reader io.Reader) error {
	return nil
}

func (m *mockStorageBackend) ScanIntegrity(ctx context.Context) (*storage.IntegrityReport, error) {
	return &storage.IntegrityReport{}, nil
}

func (m *mockStorageBackend) HealthCheck(ctx context.Context) error {
	return nil
}

func (m *mockStorageBackend) Close() error {
	return nil
}

// =============================================================================
// StorageEngineAdapter Tests
// =============================================================================

func TestStorageEngineAdapter_BasicOperations(t *testing.T) {
	ctx := context.Background()
	logger := testLogger()

	// Create mock backend
	mockBackend := newMockStorageBackend("mock")

	// Create adapter
	adapter := NewStorageEngineAdapter(mockBackend, logger)

	t.Run("Get non-existent resource", func(t *testing.T) {
		_, err := adapter.Get(ctx, "https://example.com/resource")
		require.Error(t, err)
		assert.Equal(t, ErrResourceNotFound, err)
	})

	t.Run("Put and Get resource", func(t *testing.T) {
		// Create a runtime resource
		runtimeResource := &StorageResource{
			URI:          "https://example.com/resource",
			ContentType:  "text/plain",
			Body:         []byte("Hello, World!"),
			ETag:         "\"abc123\"",
			LastModified: time.Now(),
			Metadata: StorageResourceMetadata{
				Size:         13,
				ContentType:  "text/plain",
				ETag:         "\"abc123\"",
				LastModified: time.Now(),
				Created:      time.Now(),
				Custom: map[string]string{
					"resourceType": "Resource",
				},
			},
		}

		// Put the resource
		err := adapter.Put(ctx, "https://example.com/resource", runtimeResource)
		require.NoError(t, err)

		// Get the resource back
		gotResource, err := adapter.Get(ctx, "https://example.com/resource")
		require.NoError(t, err)
		assert.Equal(t, "https://example.com/resource", gotResource.URI)
		assert.Equal(t, "text/plain", gotResource.ContentType)
		assert.Equal(t, []byte("Hello, World!"), gotResource.Body)
	})

	t.Run("Delete resource", func(t *testing.T) {
		// Put a resource first
		runtimeResource := &StorageResource{
			URI:          "https://example.com/delete-me",
			ContentType:  "text/plain",
			Body:         []byte("Delete me"),
			LastModified: time.Now(),
		}
		err := adapter.Put(ctx, "https://example.com/delete-me", runtimeResource)
		require.NoError(t, err)

		// Verify it exists
		exists, err := adapter.Exists(ctx, "https://example.com/delete-me")
		require.NoError(t, err)
		assert.True(t, exists)

		// Delete it
		err = adapter.Delete(ctx, "https://example.com/delete-me")
		require.NoError(t, err)

		// Verify it's gone
		exists, err = adapter.Exists(ctx, "https://example.com/delete-me")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("List resources", func(t *testing.T) {
		// Put some resources
		for i := 0; i < 3; i++ {
			uri := "https://example.com/container/res" + string(rune('a'+i))
			runtimeResource := &StorageResource{
				URI:          uri,
				ContentType:  "text/plain",
				Body:         []byte("content"),
				LastModified: time.Now(),
			}
			err := adapter.Put(ctx, uri, runtimeResource)
			require.NoError(t, err)
		}

		// List the container
		resources, err := adapter.List(ctx, "https://example.com/container/")
		require.NoError(t, err)
		assert.Len(t, resources, 3)
	})

	t.Run("Head resource", func(t *testing.T) {
		// Put a resource
		runtimeResource := &StorageResource{
			URI:          "https://example.com/head-test",
			ContentType:  "application/json",
			Body:         []byte(`{"key": "value"}`),
			ETag:         "\"etag123\"",
			LastModified: time.Now(),
			Metadata: StorageResourceMetadata{
				Size:         15,
				ContentType:  "application/json",
				ETag:         "\"etag123\"",
				LastModified: time.Now(),
				Created:      time.Now(),
			},
		}
		err := adapter.Put(ctx, "https://example.com/head-test", runtimeResource)
		require.NoError(t, err)

		// Head the resource
		metadata, err := adapter.Head(ctx, "https://example.com/head-test")
		require.NoError(t, err)
		assert.Equal(t, "https://example.com/head-test", metadata.Custom["uri"])
		assert.Equal(t, "application/json", metadata.ContentType)
	})
}

func TestStorageEngineAdapter_Validation(t *testing.T) {
	ctx := context.Background()
	logger := testLogger()

	// Create mock backend
	mockBackend := newMockStorageBackend("mock")

	// Create adapter
	adapter := NewStorageEngineAdapter(mockBackend, logger)

	t.Run("Empty URI validation", func(t *testing.T) {
		_, err := adapter.Get(ctx, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "URI cannot be empty")
	})

	t.Run("Invalid URI validation", func(t *testing.T) {
		_, err := adapter.Get(ctx, "not-a-valid-uri")
		require.Error(t, err)
		// Should fail validation
	})

	t.Run("Nil resource validation", func(t *testing.T) {
		err := adapter.Put(ctx, "https://example.com/test", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resource cannot be nil")
	})
}

func TestStorageEngineAdapter_Metrics(t *testing.T) {
	ctx := context.Background()
	logger := testLogger()

	// Create mock backend
	mockBackend := newMockStorageBackend("mock")

	// Create adapter
	adapter := NewStorageEngineAdapter(mockBackend, logger)

	// Perform some operations
	_, _ = adapter.Get(ctx, "https://example.com/nonexistent") // Will fail, but still counts
	runtimeResource := &StorageResource{
		URI:          "https://example.com/test",
		ContentType:  "text/plain",
		Body:         []byte("test"),
		LastModified: time.Now(),
	}
	_ = adapter.Put(ctx, "https://example.com/test", runtimeResource)
	_, _ = adapter.Get(ctx, "https://example.com/test") // Should succeed

	// Check metrics
	metrics := adapter.metrics.GetMetrics()
	totalRequests := metrics.TotalRequests
	assert.Greater(t, totalRequests, int64(0), "Expected some requests to be recorded")

	// Check that we have some get operations
	assert.Greater(t, metrics.GetOperations, int64(0), "Expected get operations to be recorded")

	// Check that we have some put operations
	assert.Greater(t, metrics.PutOperations, int64(0), "Expected put operations to be recorded")
}

func TestStorageEngineAdapter_HealthCheck(t *testing.T) {
	ctx := context.Background()
	logger := testLogger()

	// Create mock backend
	mockBackend := newMockStorageBackend("mock")

	// Create adapter
	adapter := NewStorageEngineAdapter(mockBackend, logger)

	// Health check should succeed
	err := adapter.HealthCheck(ctx)
	assert.NoError(t, err)
}

func TestStorageEngineAdapterWithBackend(t *testing.T) {
	logger := testLogger()

	// Create mock backend
	mockBackend := newMockStorageBackend("mock")

	// Create adapter using the convenience function
	adapter := NewStorageEngineAdapterWithBackend(mockBackend, logger)

	assert.NotNil(t, adapter)
	assert.Equal(t, "mock", adapter.Name())
}

func TestStorageEngineAdapter_Name(t *testing.T) {
	logger := testLogger()

	// Create mock backend
	mockBackend := newMockStorageBackend("test-backend")

	// Create adapter
	adapter := NewStorageEngineAdapter(mockBackend, logger)

	assert.Equal(t, "test-backend", adapter.Name())
}

// =============================================================================
// Mock Implementations for Cache Invalidation Tests (Phase 19)
// =============================================================================

// MockPolicyCacheInvalidator implements PolicyCacheInvalidator interface for testing
type MockPolicyCacheInvalidator struct {
	mu                 sync.Mutex
	invalidateAllCalls int
}

func NewMockPolicyCacheInvalidator() *MockPolicyCacheInvalidator {
	return &MockPolicyCacheInvalidator{}
}

// InvalidateAllCache implements PolicyCacheInvalidator
func (m *MockPolicyCacheInvalidator) InvalidateAllCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invalidateAllCalls++
}

// GetInvalidateAllCalls returns the number of times InvalidateAllCache was called
func (m *MockPolicyCacheInvalidator) GetInvalidateAllCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.invalidateAllCalls
}

// MockAuthzCacheInvalidator implements AuthzCacheInvalidator interface for testing
type MockAuthzCacheInvalidator struct {
	mu                      sync.Mutex
	invalidateResourceCalls []string
}

func NewMockAuthzCacheInvalidator() *MockAuthzCacheInvalidator {
	return &MockAuthzCacheInvalidator{
		invalidateResourceCalls: make([]string, 0),
	}
}

// InvalidateResource implements AuthzCacheInvalidator
func (m *MockAuthzCacheInvalidator) InvalidateResource(ctx context.Context, resource string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invalidateResourceCalls = append(m.invalidateResourceCalls, resource)
	return nil
}

// GetInvalidateResourceCalls returns the list of resources that were invalidated
func (m *MockAuthzCacheInvalidator) GetInvalidateResourceCalls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]string, len(m.invalidateResourceCalls))
	copy(result, m.invalidateResourceCalls)
	return result
}

// =============================================================================
// Cache Invalidation Tests for Phase 19
// =============================================================================

func TestStorageEngineAdapter_CacheInvalidation(t *testing.T) {
	ctx := context.Background()
	logger := testLogger()

	t.Run("Put invalidates caches", func(t *testing.T) {
		t.Parallel()

		// Create mock backend
		mockBackend := newMockStorageBackend("mock")

		// Create mock cache invalidators
		mockPolicyCacheInvalidator := NewMockPolicyCacheInvalidator()
		mockAuthzCacheInvalidator := NewMockAuthzCacheInvalidator()

		// Create adapter with cache hooks
		adapter := NewStorageEngineAdapterWithCache(
			mockBackend,
			logger,
			mockPolicyCacheInvalidator,
			mockAuthzCacheInvalidator,
		)

		// Create a resource to write
		testURI := "https://example.com/test-resource"
		runtimeResource := &StorageResource{
			URI:          testURI,
			ContentType:  "text/plain",
			Body:         []byte("test content"),
			LastModified: time.Now(),
			Metadata: StorageResourceMetadata{
				Size:         12,
				ContentType:  "text/plain",
				LastModified: time.Now(),
				Created:      time.Now(),
				Custom: map[string]string{
					"resourceType": "Resource",
				},
			},
		}

		// Put the resource
		err := adapter.Put(ctx, testURI, runtimeResource)
		require.NoError(t, err)

		// Verify cache invalidation was called
		assert.Equal(t, 1, mockPolicyCacheInvalidator.GetInvalidateAllCalls(), "Policy cache should be invalidated on Put")

		invalidateResourceCalls := mockAuthzCacheInvalidator.GetInvalidateResourceCalls()
		assert.Len(t, invalidateResourceCalls, 1, "Authz cache should be invalidated for resource on Put")
		assert.Equal(t, testURI, invalidateResourceCalls[0], "Authz cache should be invalidated for correct URI")
	})

	t.Run("Delete invalidates caches", func(t *testing.T) {
		t.Parallel()

		// Create mock backend
		mockBackend := newMockStorageBackend("mock")

		// Create mock cache invalidators
		mockPolicyCacheInvalidator := NewMockPolicyCacheInvalidator()
		mockAuthzCacheInvalidator := NewMockAuthzCacheInvalidator()

		// Create adapter with cache hooks
		adapter := NewStorageEngineAdapterWithCache(
			mockBackend,
			logger,
			mockPolicyCacheInvalidator,
			mockAuthzCacheInvalidator,
		)

		// Put a resource first
		testURI := "https://example.com/delete-test"
		runtimeResource := &StorageResource{
			URI:          testURI,
			ContentType:  "text/plain",
			Body:         []byte("test content"),
			LastModified: time.Now(),
		}
		err := adapter.Put(ctx, testURI, runtimeResource)
		require.NoError(t, err)

		// Get current counts to reset tracking
		putInvalidations := mockPolicyCacheInvalidator.GetInvalidateAllCalls()
		_ = mockAuthzCacheInvalidator.GetInvalidateResourceCalls()

		// Delete the resource
		err = adapter.Delete(ctx, testURI)
		require.NoError(t, err)

		// Verify cache invalidation was called for Delete
		assert.Equal(t, putInvalidations+1, mockPolicyCacheInvalidator.GetInvalidateAllCalls(), "Policy cache should be invalidated on Delete")

		invalidateResourceCalls := mockAuthzCacheInvalidator.GetInvalidateResourceCalls()
		assert.Len(t, invalidateResourceCalls, 2, "Authz cache should be invalidated for resource on Put and Delete")
		assert.Equal(t, testURI, invalidateResourceCalls[1], "Authz cache should be invalidated for correct URI on Delete")
	})

	t.Run("Get does not invalidate caches", func(t *testing.T) {
		t.Parallel()

		// Create mock backend
		mockBackend := newMockStorageBackend("mock")

		// Create mock cache invalidators
		mockPolicyCacheInvalidator := NewMockPolicyCacheInvalidator()
		mockAuthzCacheInvalidator := NewMockAuthzCacheInvalidator()

		// Create adapter with cache hooks
		adapter := NewStorageEngineAdapterWithCache(
			mockBackend,
			logger,
			mockPolicyCacheInvalidator,
			mockAuthzCacheInvalidator,
		)

		// Put a resource first
		testURI := "https://example.com/get-test"
		runtimeResource := &StorageResource{
			URI:          testURI,
			ContentType:  "text/plain",
			Body:         []byte("test content"),
			LastModified: time.Now(),
			Metadata: StorageResourceMetadata{
				Size:         12,
				ContentType:  "text/plain",
				LastModified: time.Now(),
				Created:      time.Now(),
				Custom: map[string]string{
					"resourceType": "Resource",
				},
			},
		}
		err := adapter.Put(ctx, testURI, runtimeResource)
		require.NoError(t, err)

		// Get current counts to establish baseline
		baselinePolicyInvalidations := mockPolicyCacheInvalidator.GetInvalidateAllCalls()
		baselineAuthzInvalidations := len(mockAuthzCacheInvalidator.GetInvalidateResourceCalls())

		// Get the resource (should NOT trigger cache invalidation)
		_, err = adapter.Get(ctx, testURI)
		require.NoError(t, err)

		// Verify cache invalidation was NOT called
		assert.Equal(t, baselinePolicyInvalidations, mockPolicyCacheInvalidator.GetInvalidateAllCalls(), "Policy engine cache should NOT be invalidated on Get")

		assert.Equal(t, baselineAuthzInvalidations, len(mockAuthzCacheInvalidator.GetInvalidateResourceCalls()), "Authz cache should NOT be invalidated on Get")
	})

	t.Run("Cache invalidation with nil invalidators does not panic", func(t *testing.T) {
		t.Parallel()

		// Create mock backend
		mockBackend := newMockStorageBackend("mock")

		// Create adapter with nil cache invalidators (should not panic)
		adapter := NewStorageEngineAdapterWithCache(
			mockBackend,
			logger,
			nil, // policyCacheInvalidator
			nil, // authzCacheInvalidator
		)

		// Put a resource - should not panic with nil invalidators
		testURI := "https://example.com/nil-cache-test"
		runtimeResource := &StorageResource{
			URI:          testURI,
			ContentType:  "text/plain",
			Body:         []byte("test content"),
			LastModified: time.Now(),
			Metadata: StorageResourceMetadata{
				Size:         12,
				ContentType:  "text/plain",
				LastModified: time.Now(),
				Created:      time.Now(),
				Custom: map[string]string{
					"resourceType": "Resource",
				},
			},
		}

		err := adapter.Put(ctx, testURI, runtimeResource)
		require.NoError(t, err)

		// Delete should also not panic
		err = adapter.Delete(ctx, testURI)
		require.NoError(t, err)
	})
}

// Helper function to create a test logger
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
