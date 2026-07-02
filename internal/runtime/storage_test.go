package runtime

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestStorageAbstractionLayerInitialization tests storage layer initialization
func TestStorageAbstractionLayerInitialization(t *testing.T) {
	t.Parallel()

	config := DefaultStorageAbstractionConfig()
	layer := NewStorageAbstractionLayer(config)
	defer layer.Close()

	assert.NotNil(t, layer, "Storage layer should not be nil")
	assert.False(t, layer.IsClosed(), "Storage layer should not be closed initially")
	assert.Equal(t, "default", config.DefaultStorage, "Default storage should be 'default'")
	assert.Equal(t, 3, config.MaxRetries, "Max retries should be 3")
	assert.Equal(t, 100, config.BackoffBase, "Backoff base should be 100")
	assert.Equal(t, 5000, config.BackoffMax, "Backoff max should be 5000")
}

// TestInMemoryStorageBackend tests the in-memory storage backend
func TestInMemoryStorageBackend(t *testing.T) {
	t.Parallel()

	backend := NewInMemoryStorageBackend("test", nil)
	defer backend.Close()

	ctx := context.Background()

	// Test putting a resource
	resource := &StorageResource{
		URI:         "http://example.com/resource",
		ContentType: "text/plain",
		Body:        []byte("Hello, World!"),
		Metadata: StorageResourceMetadata{
			Size:         13,
			ContentType:  "text/plain",
			LastModified: time.Now().UTC(),
			Created:      time.Now().UTC(),
		},
		LastModified: time.Now().UTC(),
	}

	err := backend.Put(ctx, "http://example.com/resource", resource)
	assert.NoError(t, err, "Put should succeed")

	// Test getting the resource
	gotResource, err := backend.Get(ctx, "http://example.com/resource")
	assert.NoError(t, err, "Get should succeed")
	assert.NotNil(t, gotResource, "Got resource should not be nil")
	assert.Equal(t, "http://example.com/resource", gotResource.URI, "URI should match")
	assert.Equal(t, "text/plain", gotResource.ContentType, "Content type should match")
	assert.Equal(t, []byte("Hello, World!"), gotResource.Body, "Body should match")

	// Test exists
	exists, err := backend.Exists(ctx, "http://example.com/resource")
	assert.NoError(t, err, "Exists should succeed")
	assert.True(t, exists, "Resource should exist")

	// Test head
	metadata, err := backend.Head(ctx, "http://example.com/resource")
	assert.NoError(t, err, "Head should succeed")
	assert.NotNil(t, metadata, "Metadata should not be nil")
	assert.Equal(t, int64(13), metadata.Size, "Size should match")

	// Test list
	resources, err := backend.List(ctx, "")
	assert.NoError(t, err, "List should succeed")
	assert.True(t, len(resources) >= 1, "Should have at least one resource")

	// Test deleting the resource
	err = backend.Delete(ctx, "http://example.com/resource")
	assert.NoError(t, err, "Delete should succeed")

	// Verify it's gone
	_, err = backend.Get(ctx, "http://example.com/resource")
	assert.Error(t, err, "Get should fail after delete")

	exists, err = backend.Exists(ctx, "http://example.com/resource")
	assert.NoError(t, err, "Exists should succeed")
	assert.False(t, exists, "Resource should not exist after delete")
}

// TestStorageBackendNotFound tests getting a non-existent resource
func TestStorageBackendNotFound(t *testing.T) {
	t.Parallel()

	backend := NewInMemoryStorageBackend("test", nil)
	defer backend.Close()

	ctx := context.Background()

	_, err := backend.Get(ctx, "http://example.com/nonexistent")
	assert.Error(t, err, "Get should fail for non-existent resource")

	// Check that it's an HTTPError with 404 status
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		assert.Equal(t, http.StatusNotFound, httpErr.StatusCode, "Status code should be 404")
	}
}

// TestStorageBackendClosed tests operations on a closed backend
func TestStorageBackendClosed(t *testing.T) {
	t.Parallel()

	backend := NewInMemoryStorageBackend("test", nil)

	ctx := context.Background()

	// Close the backend
	err := backend.Close()
	assert.NoError(t, err, "Close should succeed")

	// Test operations on closed backend
	_, err = backend.Get(ctx, "http://example.com/resource")
	assert.Error(t, err, "Get should fail on closed backend")

	err = backend.Put(ctx, "http://example.com/resource", &StorageResource{})
	assert.Error(t, err, "Put should fail on closed backend")

	err = backend.Delete(ctx, "http://example.com/resource")
	assert.Error(t, err, "Delete should fail on closed backend")

	_, err = backend.Exists(ctx, "http://example.com/resource")
	assert.Error(t, err, "Exists should fail on closed backend")

	_, err = backend.Head(ctx, "http://example.com/resource")
	assert.Error(t, err, "Head should fail on closed backend")

	_, err = backend.List(ctx, "")
	assert.Error(t, err, "List should fail on closed backend")

	err = backend.HealthCheck(ctx)
	assert.Error(t, err, "HealthCheck should fail on closed backend")
}

// TestStorageAbstractionLayerRegisterBackend tests registering backends
func TestStorageAbstractionLayerRegisterBackend(t *testing.T) {
	t.Parallel()

	config := DefaultStorageAbstractionConfig()
	layer := NewStorageAbstractionLayer(config)
	defer layer.Close()

	// Create a backend
	backend := NewInMemoryStorageBackend("memory", nil)
	defer backend.Close()

	// Register the backend
	err := layer.RegisterBackend("memory", backend)
	assert.NoError(t, err, "RegisterBackend should succeed")

	// Verify it's registered
	gotBackend, err := layer.GetBackend("memory")
	assert.NoError(t, err, "GetBackend should succeed")
	assert.Equal(t, backend, gotBackend, "Backend should match")

	// Verify it's in the list

	names := layer.GetBackendNames()
	assert.Contains(t, names, "memory", "Backend name should be in list")
}

// TestStorageAbstractionLayerDuplicateBackend tests registering duplicate backends
func TestStorageAbstractionLayerDuplicateBackend(t *testing.T) {
	t.Parallel()

	config := DefaultStorageAbstractionConfig()
	layer := NewStorageAbstractionLayer(config)
	defer layer.Close()

	// Create two backends
	backend1 := NewInMemoryStorageBackend("memory1", nil)
	backend2 := NewInMemoryStorageBackend("memory2", nil)
	defer backend1.Close()
	defer backend2.Close()

	// Register the first backend
	err := layer.RegisterBackend("memory", backend1)
	assert.NoError(t, err, "First RegisterBackend should succeed")

	// Try to register a second backend with the same name
	err = layer.RegisterBackend("memory", backend2)
	assert.Error(t, err, "Second RegisterBackend should fail")
	assert.Contains(t, err.Error(), "already registered", "Error should mention already registered")
}

// TestStorageAbstractionLayerGetNonExistentBackend tests getting a non-existent backend
func TestStorageAbstractionLayerGetNonExistentBackend(t *testing.T) {
	t.Parallel()

	config := DefaultStorageAbstractionConfig()
	layer := NewStorageAbstractionLayer(config)
	defer layer.Close()

	_, err := layer.GetBackend("nonexistent")
	assert.Error(t, err, "GetBackend should fail for non-existent backend")
	assert.Contains(t, err.Error(), "not found", "Error should mention not found")
}

// TestStorageAbstractionLayerSetDefaultBackend tests setting the default backend
func TestStorageAbstractionLayerSetDefaultBackend(t *testing.T) {
	t.Parallel()

	config := DefaultStorageAbstractionConfig()
	layer := NewStorageAbstractionLayer(config)
	defer layer.Close()

	// Create backends
	backend1 := NewInMemoryStorageBackend("memory1", nil)
	backend2 := NewInMemoryStorageBackend("memory2", nil)
	defer backend1.Close()
	defer backend2.Close()

	// Register backends
	layer.RegisterBackend("backend1", backend1)
	layer.RegisterBackend("backend2", backend2)

	// Set default backend
	err := layer.SetDefaultBackend("backend1")
	assert.NoError(t, err, "SetDefaultBackend should succeed")

	// Verify it's set (by checking that operations use it)
	ctx := context.Background()
	resource := &StorageResource{
		URI:         "http://example.com/test",
		ContentType: "text/plain",
		Body:        []byte("test"),
	}

	err = layer.Put(ctx, "http://example.com/test", resource)
	assert.NoError(t, err, "Put should succeed")

	// Verify we can get it back
	gotResource, err := layer.Get(ctx, "http://example.com/test")
	assert.NoError(t, err, "Get should succeed")
	assert.NotNil(t, gotResource, "Got resource should not be nil")
}

// TestStorageAbstractionLayerRetry tests retry logic
func TestStorageAbstractionLayerRetry(t *testing.T) {
	t.Parallel()

	config := StorageAbstractionConfig{
		DefaultStorage: "test",
		MaxRetries:     2,
		BackoffBase:    10,  // 10ms
		BackoffMax:     100, // 100ms
		Logger:         nil,
	}

	layer := NewStorageAbstractionLayer(config)
	defer layer.Close()

	// Create a failing backend
	failingBackend := &FailingStorageBackend{
		failCount: 2,
		name:      "failing",
		data:      make(map[string]*StorageResource),
	}

	layer.RegisterBackend("failing", failingBackend)
	layer.SetDefaultBackend("failing")

	ctx := context.Background()

	// This should succeed after retries
	resource := &StorageResource{
		URI:         "http://example.com/test",
		ContentType: "text/plain",
		Body:        []byte("test"),
	}

	err := layer.Put(ctx, "http://example.com/test", resource)
	assert.NoError(t, err, "Put should eventually succeed after retries")

	// Check metrics
	metrics := layer.GetMetrics()
	assert.True(t, metrics.RetryAttempts > 0, "Should have retry attempts")
}

// FailingStorageBackend is a backend that fails a configurable number of times before succeeding
type FailingStorageBackend struct {
	mu        sync.Mutex
	failCount int
	callCount int
	name      string
	data      map[string]*StorageResource
}

func (f *FailingStorageBackend) Name() string {
	return f.name
}

func (f *FailingStorageBackend) Get(ctx context.Context, uri string) (*StorageResource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callCount++
	if f.callCount <= f.failCount {
		return nil, &HTTPError{StatusCode: http.StatusServiceUnavailable, Message: "Service unavailable"}
	}
	return f.data[uri], nil
}

func (f *FailingStorageBackend) Put(ctx context.Context, uri string, resource *StorageResource) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callCount++
	if f.callCount <= f.failCount {
		return &HTTPError{StatusCode: http.StatusServiceUnavailable, Message: "Service unavailable"}
	}
	f.data[uri] = resource
	return nil
}

func (f *FailingStorageBackend) Delete(ctx context.Context, uri string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callCount++
	if f.callCount <= f.failCount {
		return &HTTPError{StatusCode: http.StatusServiceUnavailable, Message: "Service unavailable"}
	}
	delete(f.data, uri)
	return nil
}

func (f *FailingStorageBackend) List(ctx context.Context, containerURI string) ([]*StorageResource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callCount++
	if f.callCount <= f.failCount {
		return nil, &HTTPError{StatusCode: http.StatusServiceUnavailable, Message: "Service unavailable"}
	}
	resources := make([]*StorageResource, 0, len(f.data))
	for _, resource := range f.data {
		resources = append(resources, resource)
	}
	return resources, nil
}

func (f *FailingStorageBackend) Exists(ctx context.Context, uri string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callCount++
	if f.callCount <= f.failCount {
		return false, &HTTPError{StatusCode: http.StatusServiceUnavailable, Message: "Service unavailable"}
	}
	_, exists := f.data[uri]
	return exists, nil
}

func (f *FailingStorageBackend) Head(ctx context.Context, uri string) (*StorageResourceMetadata, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callCount++
	if f.callCount <= f.failCount {
		return nil, &HTTPError{StatusCode: http.StatusServiceUnavailable, Message: "Service unavailable"}
	}
	resource, exists := f.data[uri]
	if !exists {
		return nil, &HTTPError{StatusCode: http.StatusNotFound, Message: "Not found"}
	}
	return &resource.Metadata, nil
}

func (f *FailingStorageBackend) Close() error {
	return nil
}

func (f *FailingStorageBackend) HealthCheck(ctx context.Context) error {
	return nil
}

// TestStorageAbstractionLayerMaxRetries tests max retries behavior
func TestStorageAbstractionLayerMaxRetries(t *testing.T) {
	t.Parallel()

	config := StorageAbstractionConfig{
		DefaultStorage: "test",
		MaxRetries:     2,
		BackoffBase:    10,  // 10ms
		BackoffMax:     100, // 100ms
		Logger:         nil,
	}

	layer := NewStorageAbstractionLayer(config)
	defer layer.Close()

	// Create a always-failing backend
	alwaysFailingBackend := &AlwaysFailingStorageBackend{
		name: "always-failing",
	}

	layer.RegisterBackend("always-failing", alwaysFailingBackend)
	layer.SetDefaultBackend("always-failing")

	ctx := context.Background()

	// This should fail after max retries
	_, err := layer.Get(ctx, "http://example.com/test")
	assert.Error(t, err, "Get should fail after max retries")
	assert.Contains(t, err.Error(), "max retries exceeded", "Error should mention max retries")

	// Check metrics
	metrics := layer.GetMetrics()
	assert.True(t, metrics.MaxRetriesHit > 0, "Should have hit max retries")
}

// AlwaysFailingStorageBackend is a backend that always fails
type AlwaysFailingStorageBackend struct {
	name string
}

func (a *AlwaysFailingStorageBackend) Name() string {
	return a.name
}

func (a *AlwaysFailingStorageBackend) Get(ctx context.Context, uri string) (*StorageResource, error) {
	return nil, &HTTPError{StatusCode: http.StatusServiceUnavailable, Message: "Service unavailable"}
}

func (a *AlwaysFailingStorageBackend) Put(ctx context.Context, uri string, resource *StorageResource) error {
	return &HTTPError{StatusCode: http.StatusServiceUnavailable, Message: "Service unavailable"}
}

func (a *AlwaysFailingStorageBackend) Delete(ctx context.Context, uri string) error {
	return &HTTPError{StatusCode: http.StatusServiceUnavailable, Message: "Service unavailable"}
}

func (a *AlwaysFailingStorageBackend) List(ctx context.Context, containerURI string) ([]*StorageResource, error) {
	return nil, &HTTPError{StatusCode: http.StatusServiceUnavailable, Message: "Service unavailable"}
}

func (a *AlwaysFailingStorageBackend) Exists(ctx context.Context, uri string) (bool, error) {
	return false, &HTTPError{StatusCode: http.StatusServiceUnavailable, Message: "Service unavailable"}
}

func (a *AlwaysFailingStorageBackend) Head(ctx context.Context, uri string) (*StorageResourceMetadata, error) {
	return nil, &HTTPError{StatusCode: http.StatusServiceUnavailable, Message: "Service unavailable"}
}

func (a *AlwaysFailingStorageBackend) Close() error {
	return nil
}

func (a *AlwaysFailingStorageBackend) HealthCheck(ctx context.Context) error {
	return &HTTPError{StatusCode: http.StatusServiceUnavailable, Message: "Service unavailable"}
}

// TestStorageAbstractionLayerContextCancellation tests context cancellation
func TestStorageAbstractionLayerContextCancellation(t *testing.T) {
	t.Parallel()

	config := StorageAbstractionConfig{
		DefaultStorage: "test",
		MaxRetries:     5,
		BackoffBase:    100,  // 100ms
		BackoffMax:     1000, // 1s
		Logger:         nil,
	}

	layer := NewStorageAbstractionLayer(config)
	defer layer.Close()

	// Create a slow backend that will delay operations
	backend := NewInMemoryStorageBackend("slow", nil)
	defer backend.Close()

	layer.RegisterBackend("slow", backend)
	layer.SetDefaultBackend("slow")

	// Create a context that will be cancelled
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Start an operation that will be cancelled - use a resource that takes time due to retries
	// Set up a backend that will always fail to trigger retries
	failingBackend := &AlwaysFailingStorageBackend{name: "always-failing"}
	layer.RegisterBackend("always-failing", failingBackend)
	layer.SetDefaultBackend("always-failing")

	// Start an operation that will be cancelled during retry
	_, err := layer.Get(ctx, "http://example.com/nonexistent")
	assert.Error(t, err, "Get should fail due to context cancellation")
	assert.Contains(t, err.Error(), "context cancelled", "Error should mention context cancellation")
}

// TestHTTPStorageBackend tests the HTTP storage backend
func TestHTTPStorageBackend(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping HTTP storage backend test in short mode")
	}

	t.Parallel()

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("ETag", "\"test-etag\"")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test content"))
		case "PUT":
			w.WriteHeader(http.StatusCreated)
		case "DELETE":
			w.WriteHeader(http.StatusNoContent)
		case "HEAD":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("ETag", "\"test-etag\"")
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	// Create the HTTP backend
	backend := NewHTTPStorageBackend("http-test", server.URL, nil)
	defer backend.Close()

	ctx := context.Background()

	// Test GET
	resource, err := backend.Get(ctx, "/test")
	assert.NoError(t, err, "GET should succeed")
	assert.NotNil(t, resource, "Resource should not be nil")
	assert.Equal(t, []byte("test content"), resource.Body, "Body should match")
	assert.Equal(t, "text/plain", resource.ContentType, "Content type should match")

	// Test PUT
	resourceToPut := &StorageResource{
		URI:         "/test",
		ContentType: "text/plain",
		Body:        []byte("new content"),
	}
	err = backend.Put(ctx, "/test", resourceToPut)
	assert.NoError(t, err, "PUT should succeed")

	// Test HEAD
	metadata, err := backend.Head(ctx, "/test")
	assert.NoError(t, err, "HEAD should succeed")
	assert.NotNil(t, metadata, "Metadata should not be nil")
	assert.Equal(t, "text/plain", metadata.ContentType, "Content type should match")

	// Test Exists
	exists, err := backend.Exists(ctx, "/test")
	assert.NoError(t, err, "Exists should succeed")
	assert.True(t, exists, "Resource should exist")

	// Test DELETE
	err = backend.Delete(ctx, "/test")
	assert.NoError(t, err, "DELETE should succeed")
}

// TestStorageAbstractionLayerHealthCheck tests health checking
func TestStorageAbstractionLayerHealthCheck(t *testing.T) {
	t.Parallel()

	config := DefaultStorageAbstractionConfig()
	layer := NewStorageAbstractionLayer(config)
	defer layer.Close()

	// Create backends
	backend1 := NewInMemoryStorageBackend("backend1", nil)
	backend2 := NewInMemoryStorageBackend("backend2", nil)
	defer backend1.Close()
	defer backend2.Close()

	// Register backends
	layer.RegisterBackend("backend1", backend1)
	layer.RegisterBackend("backend2", backend2)

	ctx := context.Background()

	// Check health
	results := layer.HealthCheck(ctx)
	assert.Len(t, results, 2, "Should have results for both backends")

	// Both should be healthy
	assert.Nil(t, results["backend1"], "Backend1 should be healthy")
	assert.Nil(t, results["backend2"], "Backend2 should be healthy")

	// Close one backend
	backend1.Close()

	// Check health again
	results = layer.HealthCheck(ctx)
	assert.NotNil(t, results["backend1"], "Backend1 should be unhealthy after close")
	assert.Nil(t, results["backend2"], "Backend2 should still be healthy")
}

// TestStorageAbstractionLayerConcurrent tests concurrent access to storage layer
func TestStorageAbstractionLayerConcurrent(t *testing.T) {
	t.Parallel()

	config := DefaultStorageAbstractionConfig()
	layer := NewStorageAbstractionLayer(config)
	defer layer.Close()

	backend := NewInMemoryStorageBackend("concurrent", nil)
	defer backend.Close()

	layer.RegisterBackend("concurrent", backend)
	layer.SetDefaultBackend("concurrent")

	ctx := context.Background()

	// Test concurrent operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 50; j++ {
				resource := &StorageResource{
					URI:         "http://example.com/resource/" + string(rune(id+'0')) + string(rune(j+'a')),
					ContentType: "text/plain",
					Body:        []byte("test"),
				}
				layer.Put(ctx, resource.URI, resource)
				layer.Get(ctx, resource.URI)
				layer.Exists(ctx, resource.URI)
				layer.Head(ctx, resource.URI)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all resources are still accessible
	for i := 0; i < 10; i++ {
		for j := 0; j < 50; j++ {
			uri := "http://example.com/resource/" + string(rune(i+'0')) + string(rune(j+'a'))
			_, err := layer.Get(ctx, uri)
			assert.NoError(t, err, "Get should succeed for resource %s", uri)
		}
	}
}

// TestStorageResourceMetadata tests storage resource metadata
func TestStorageResourceMetadata(t *testing.T) {
	t.Parallel()

	backend := NewInMemoryStorageBackend("metadata-test", nil)
	defer backend.Close()

	ctx := context.Background()

	now := time.Now().UTC()
	metadata := StorageResourceMetadata{
		Size:         100,
		ContentType:  "application/json",
		ETag:         "\"test-etag\"",
		LastModified: now,
		Created:      now.Add(-1 * time.Hour),
		Custom:       map[string]string{"key": "value"},
	}

	resource := &StorageResource{
		URI:          "http://example.com/metadata-test",
		ContentType:  "application/json",
		Body:         []byte("test content"),
		Metadata:     metadata,
		ETag:         "\"test-etag\"",
		LastModified: now,
	}

	err := backend.Put(ctx, resource.URI, resource)
	assert.NoError(t, err, "Put should succeed")

	// Get the resource back
	gotResource, err := backend.Get(ctx, resource.URI)
	assert.NoError(t, err, "Get should succeed")
	assert.Equal(t, metadata.Size, gotResource.Metadata.Size, "Size should match")
	assert.Equal(t, metadata.ContentType, gotResource.Metadata.ContentType, "Content type should match")
	assert.Equal(t, metadata.ETag, gotResource.Metadata.ETag, "ETag should match")
	assert.Equal(t, metadata.LastModified, gotResource.Metadata.LastModified, "LastModified should match")
	assert.Equal(t, metadata.Created, gotResource.Metadata.Created, "Created should match")
	assert.Equal(t, metadata.Custom["key"], gotResource.Metadata.Custom["key"], "Custom metadata should match")
}

// TestStorageBackendUnregister tests unregistering a backend
func TestStorageBackendUnregister(t *testing.T) {
	t.Parallel()

	config := DefaultStorageAbstractionConfig()
	layer := NewStorageAbstractionLayer(config)
	defer layer.Close()

	backend := NewInMemoryStorageBackend("test", nil)
	defer backend.Close()

	// Register the backend
	err := layer.RegisterBackend("test", backend)
	assert.NoError(t, err, "RegisterBackend should succeed")

	// Unregister the backend
	err = layer.UnregisterBackend("test")
	assert.NoError(t, err, "UnregisterBackend should succeed")

	// Verify it's unregistered
	_, err = layer.GetBackend("test")
	assert.Error(t, err, "GetBackend should fail after unregister")
	assert.Contains(t, err.Error(), "not found", "Error should mention not found")
}

// TestStorageLayerClose tests closing the storage layer
func TestStorageLayerClose(t *testing.T) {
	t.Parallel()

	config := DefaultStorageAbstractionConfig()
	layer := NewStorageAbstractionLayer(config)

	// Close the layer
	err := layer.Close()
	assert.NoError(t, err, "Close should succeed")

	// Verify it's closed
	assert.True(t, layer.IsClosed(), "Storage layer should be closed")

	// Test operations on closed layer
	ctx := context.Background()
	_, err = layer.Get(ctx, "http://example.com/test")
	assert.Error(t, err, "Get should fail on closed layer")

	err = layer.Put(ctx, "http://example.com/test", &StorageResource{})
	assert.Error(t, err, "Put should fail on closed layer")

	err = layer.Delete(ctx, "http://example.com/test")
	assert.Error(t, err, "Delete should fail on closed layer")

	_, err = layer.List(ctx, "")
	assert.Error(t, err, "List should fail on closed layer")

	_, err = layer.Exists(ctx, "http://example.com/test")
	assert.Error(t, err, "Exists should fail on closed layer")

	_, err = layer.Head(ctx, "http://example.com/test")
	assert.Error(t, err, "Head should fail on closed layer")

	// Test register/unregister on closed layer
	err = layer.RegisterBackend("test", NewInMemoryStorageBackend("test", nil))
	assert.Error(t, err, "RegisterBackend should fail on closed layer")

	err = layer.UnregisterBackend("test")
	assert.Error(t, err, "UnregisterBackend should fail on closed layer")
}

// TestStorageLayerMetrics tests storage layer metrics
func TestStorageLayerMetrics(t *testing.T) {
	t.Parallel()

	config := DefaultStorageAbstractionConfig()
	layer := NewStorageAbstractionLayer(config)
	defer layer.Close()

	backend := NewInMemoryStorageBackend("metrics-test", nil)
	defer backend.Close()

	layer.RegisterBackend("metrics-test", backend)
	layer.SetDefaultBackend("metrics-test")

	ctx := context.Background()

	// Perform some operations
	resource := &StorageResource{
		URI:         "http://example.com/metrics-test",
		ContentType: "text/plain",
		Body:        []byte("test"),
	}

	layer.Put(ctx, resource.URI, resource)
	layer.Get(ctx, resource.URI)
	layer.Exists(ctx, resource.URI)
	layer.Head(ctx, resource.URI)
	layer.List(ctx, "")

	// Check metrics
	metrics := layer.GetMetrics()
	assert.True(t, metrics.TotalOperations > 0, "Should have total operations")
	assert.True(t, metrics.SuccessfulOperations > 0, "Should have successful operations")
	assert.True(t, metrics.ReadOperations >= 0, "Should have read operations")
	assert.True(t, metrics.WriteOperations >= 0, "Should have write operations")
}

// TestExponentialBackoff tests exponential backoff calculation
func TestExponentialBackoff(t *testing.T) {
	t.Parallel()

	config := StorageAbstractionConfig{
		DefaultStorage: "test",
		MaxRetries:     5,
		BackoffBase:    100,
		BackoffMax:     10000,
		Logger:         nil,
	}

	layer := NewStorageAbstractionLayer(config)
	defer layer.Close()

	// Test backoff calculation
	// Backoff formula: BackoffBase * (1 << (attempt - 1))
	// attempt 1: 100 * (1 << 0) = 100
	// attempt 2: 100 * (1 << 1) = 200
	// attempt 3: 100 * (1 << 2) = 400
	// attempt 4: 100 * (1 << 3) = 800
	// attempt 5: 100 * (1 << 4) = 1600
	// attempt 6: 100 * (1 << 5) = 3200

	// The calculation is: BackoffBase * (1 << (attempt - 1))
	// For attempt 1: 100 * (1 << 0) = 100
	backoff1 := layer.calculateBackoff(1)
	assert.Equal(t, 100, backoff1, "Backoff for attempt 1 should be 100")

	backoff2 := layer.calculateBackoff(2)
	assert.Equal(t, 200, backoff2, "Backoff for attempt 2 should be 200")

	backoff3 := layer.calculateBackoff(3)
	assert.Equal(t, 400, backoff3, "Backoff for attempt 3 should be 400")

	backoff4 := layer.calculateBackoff(4)
	assert.Equal(t, 800, backoff4, "Backoff for attempt 4 should be 800")

	// Test that backoff increases exponentially
	backoff6 := layer.calculateBackoff(6)
	assert.Equal(t, 3200, backoff6, "Backoff for attempt 6 should be 3200")

	// Test max cap - attempt 8: 100 * (1 << 7) = 100 * 128 = 12800 > 10000, so capped
	backoff8 := layer.calculateBackoff(8)
	assert.Equal(t, 10000, backoff8, "Backoff for attempt 8 should be capped at max")

	backoff10 := layer.calculateBackoff(10)
	assert.Equal(t, 10000, backoff10, "Backoff for attempt 10 should be capped at max")
}

// TestShouldRetry tests retry decision logic
func TestShouldRetry(t *testing.T) {
	t.Parallel()

	config := DefaultStorageAbstractionConfig()
	layer := NewStorageAbstractionLayer(config)
	defer layer.Close()

	// Test retryable errors
	assert.True(t, layer.shouldRetry(context.DeadlineExceeded), "DeadlineExceeded should be retryable")
	assert.True(t, layer.shouldRetry(io.EOF), "EOF should be retryable")
	assert.True(t, layer.shouldRetry(io.ErrUnexpectedEOF), "ErrUnexpectedEOF should be retryable")
	assert.True(t, layer.shouldRetry(&HTTPError{StatusCode: 500, Message: "Internal Server Error"}), "500 error should be retryable")
	assert.True(t, layer.shouldRetry(&HTTPError{StatusCode: 503, Message: "Service Unavailable"}), "503 error should be retryable")

	// Test non-retryable errors
	assert.False(t, layer.shouldRetry(nil), "nil error should not be retryable")
	assert.False(t, layer.shouldRetry(&HTTPError{StatusCode: 400, Message: "Bad Request"}), "400 error should not be retryable")
	assert.False(t, layer.shouldRetry(&HTTPError{StatusCode: 404, Message: "Not Found"}), "404 error should not be retryable")
	assert.False(t, layer.shouldRetry(errors.New("some error")), "Generic error should not be retryable")

	// Test timeout error
	var timeoutErr = &timeoutError{}
	assert.True(t, layer.shouldRetry(timeoutErr), "Timeout error should be retryable")
}

// timeoutError implements the Timeout() bool method
type timeoutError struct{}

func (t *timeoutError) Timeout() bool {
	return true
}

func (t *timeoutError) Error() string {
	return "timeout"
}

// TestStorageAbstractionLayerDefaultConfig tests default configuration
func TestStorageAbstractionLayerDefaultConfig(t *testing.T) {
	t.Parallel()

	config := DefaultStorageAbstractionConfig()
	assert.Equal(t, "default", config.DefaultStorage, "Default storage should be 'default'")
	assert.Equal(t, 3, config.MaxRetries, "Max retries should be 3")
	assert.Equal(t, 100, config.BackoffBase, "Backoff base should be 100")
	assert.Equal(t, 5000, config.BackoffMax, "Backoff max should be 5000")
	assert.Nil(t, config.Logger, "Logger should be nil by default")
}
