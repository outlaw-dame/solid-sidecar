package runtime

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemoryStoragePutConditionalIfNoneMatchCreatesOnlyWhenMissing(t *testing.T) {
	t.Parallel()
	backend := NewInMemoryStorageBackend("conditional", nil)
	defer backend.Close()
	ctx := context.Background()
	resource := &StorageResource{URI: "http://example.com/new", ContentType: "text/plain", Body: []byte("first")}

	err := backend.PutConditional(ctx, resource.URI, resource, StoragePreconditions{IfNoneMatch: []string{"*"}})
	require.NoError(t, err)

	err = backend.PutConditional(ctx, resource.URI, &StorageResource{URI: resource.URI, Body: []byte("second")}, StoragePreconditions{IfNoneMatch: []string{"*"}})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrStoragePreconditionFailed))
}

func TestInMemoryStoragePutConditionalIfMatchPreventsLostUpdate(t *testing.T) {
	t.Parallel()
	backend := NewInMemoryStorageBackend("conditional", nil)
	defer backend.Close()
	ctx := context.Background()
	uri := "http://example.com/resource"

	initial := &StorageResource{URI: uri, ContentType: "text/plain", Body: []byte("initial"), ETag: "\"v1\""}
	require.NoError(t, backend.PutConditional(ctx, uri, initial, StoragePreconditions{IfNoneMatch: []string{"*"}}))

	fresh := &StorageResource{URI: uri, ContentType: "text/plain", Body: []byte("fresh"), ETag: "\"v2\""}
	require.NoError(t, backend.PutConditional(ctx, uri, fresh, StoragePreconditions{IfMatch: []string{"\"v1\""}}))

	stale := &StorageResource{URI: uri, ContentType: "text/plain", Body: []byte("stale"), ETag: "\"v3\""}
	err := backend.PutConditional(ctx, uri, stale, StoragePreconditions{IfMatch: []string{"\"v1\""}})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrStoragePreconditionFailed))

	stored, err := backend.Get(ctx, uri)
	require.NoError(t, err)
	assert.Equal(t, []byte("fresh"), stored.Body)
	assert.Equal(t, "\"v2\"", stored.ETag)
}

func TestInMemoryStorageDeleteConditionalRequiresMatchingETag(t *testing.T) {
	t.Parallel()
	backend := NewInMemoryStorageBackend("conditional", nil)
	defer backend.Close()
	ctx := context.Background()
	uri := "http://example.com/delete"

	require.NoError(t, backend.PutConditional(ctx, uri, &StorageResource{URI: uri, Body: []byte("body"), ETag: "\"delete-v1\""}, StoragePreconditions{}))

	err := backend.DeleteConditional(ctx, uri, StoragePreconditions{IfMatch: []string{"\"wrong\""}})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrStoragePreconditionFailed))

	exists, err := backend.Exists(ctx, uri)
	require.NoError(t, err)
	assert.True(t, exists)

	require.NoError(t, backend.DeleteConditional(ctx, uri, StoragePreconditions{IfMatch: []string{"\"delete-v1\""}}))
	exists, err = backend.Exists(ctx, uri)
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestStorageLayerConditionalUnsupportedBackendFailsClosed(t *testing.T) {
	t.Parallel()
	layer := NewStorageAbstractionLayer(DefaultStorageAbstractionConfig())
	defer layer.Close()
	backend := &AlwaysFailingStorageBackend{name: "plain"}
	require.NoError(t, layer.RegisterBackend("plain", backend))
	require.NoError(t, layer.SetDefaultBackend("plain"))

	err := layer.PutConditional(context.Background(), "http://example.com/resource", &StorageResource{URI: "http://example.com/resource", Body: []byte("body")}, StoragePreconditions{IfMatch: []string{"*"}})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrStorageConditionalUnsupported))
}

func TestStorageLayerPutConditionalRoutesThroughBackend(t *testing.T) {
	t.Parallel()
	layer := NewStorageAbstractionLayer(DefaultStorageAbstractionConfig())
	defer layer.Close()
	backend := NewInMemoryStorageBackend("conditional", nil)
	defer backend.Close()
	require.NoError(t, layer.RegisterBackend("conditional", backend))
	require.NoError(t, layer.SetDefaultBackend("conditional"))
	ctx := context.Background()
	uri := "http://example.com/layer"

	require.NoError(t, layer.PutConditional(ctx, uri, &StorageResource{URI: uri, Body: []byte("one"), ETag: "\"one\""}, StoragePreconditions{IfNoneMatch: []string{"*"}}))
	err := layer.PutConditional(ctx, uri, &StorageResource{URI: uri, Body: []byte("two"), ETag: "\"two\""}, StoragePreconditions{IfMatch: []string{"\"stale\""}})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrStoragePreconditionFailed))
}

func TestHTTPStoragePutConditionalPropagatesHeaders(t *testing.T) {
	t.Parallel()
	var sawIfMatch string
	var sawIfNoneMatch string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		sawIfMatch = r.Header.Get("If-Match")
		sawIfNoneMatch = r.Header.Get("If-None-Match")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	backend := NewHTTPStorageBackend("http", server.URL, nil)
	defer backend.Close()
	err := backend.PutConditional(context.Background(), "/resource", &StorageResource{URI: "/resource", ContentType: "text/plain", Body: []byte("body")}, StoragePreconditions{
		IfMatch:     []string{"\"v1\""},
		IfNoneMatch: []string{"\"other\""},
	})
	require.NoError(t, err)
	assert.Equal(t, "\"v1\"", sawIfMatch)
	assert.Equal(t, "\"other\"", sawIfNoneMatch)
}

func TestHTTPStoragePutConditionalMapsPreconditionFailed(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPreconditionFailed)
	}))
	defer server.Close()

	backend := NewHTTPStorageBackend("http", server.URL, nil)
	defer backend.Close()
	err := backend.PutConditional(context.Background(), "/resource", &StorageResource{URI: "/resource", Body: []byte("body")}, StoragePreconditions{IfMatch: []string{"\"missing\""}})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrStoragePreconditionFailed))
}

func TestConditionalWriteGeneratesStrongETagWhenMissing(t *testing.T) {
	t.Parallel()
	backend := NewInMemoryStorageBackend("conditional", nil)
	defer backend.Close()
	ctx := context.Background()
	uri := "http://example.com/generated"

	require.NoError(t, backend.PutConditional(ctx, uri, &StorageResource{URI: uri, ContentType: "text/plain", Body: []byte("body")}, StoragePreconditions{}))
	stored, err := backend.Get(ctx, uri)
	require.NoError(t, err)
	assert.NotEmpty(t, stored.ETag)
	assert.Equal(t, stored.ETag, stored.Metadata.ETag)
	assert.Equal(t, int64(4), stored.Metadata.Size)
	assert.False(t, stored.Metadata.Created.IsZero())
	assert.WithinDuration(t, time.Now().UTC(), stored.LastModified, time.Second)
}
