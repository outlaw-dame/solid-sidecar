package runtime

import (
	"context"
	"errors"
	"io"
	"log/slog"
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

// Helper function to create a test logger
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
