package runtime

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerOperationCreateRejectsDuplicateResource(t *testing.T) {

	service := newTestContainerOperationService(t)
	ctx := context.Background()
	container := "http://example.com/container/"

	created, err := service.CreateResource(ctx, container, "note.txt", &StorageResource{ContentType: "text/plain", Body: []byte("first")})
	require.NoError(t, err)
	assert.Equal(t, "http://example.com/container/note.txt", created.URI)

	_, err = service.CreateResource(ctx, container, "note.txt", &StorageResource{ContentType: "text/plain", Body: []byte("second")})
	require.Error(t, err)
	var httpErr *HTTPError
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusConflict, httpErr.StatusCode)

	stored, err := service.storage.Get(ctx, "http://example.com/container/note.txt")
	require.NoError(t, err)
	assert.Equal(t, []byte("first"), stored.Body)
}

func TestContainerOperationListMembersOnlyDirectChildren(t *testing.T) {

	service := newTestContainerOperationService(t)
	ctx := context.Background()
	container := "http://example.com/container/"

	_, err := service.CreateResource(ctx, container, "a.txt", &StorageResource{ContentType: "text/plain", Body: []byte("a")})
	require.NoError(t, err)
	_, err = service.CreateResource(ctx, container, "b.txt", &StorageResource{ContentType: "text/plain", Body: []byte("b")})
	require.NoError(t, err)
	require.NoError(t, service.storage.Put(ctx, "http://example.com/container/nested/c.txt", &StorageResource{URI: "http://example.com/container/nested/c.txt", Body: []byte("nested")}))
	require.NoError(t, service.storage.Put(ctx, "http://example.com/other.txt", &StorageResource{URI: "http://example.com/other.txt", Body: []byte("other")}))

	members, err := service.ListMembers(ctx, container)
	require.NoError(t, err)
	require.Len(t, members, 2)
	assert.Equal(t, "http://example.com/container/a.txt", members[0].URI)
	assert.Equal(t, "http://example.com/container/b.txt", members[1].URI)
}

func TestContainerOperationDeleteRemovesResource(t *testing.T) {

	service := newTestContainerOperationService(t)
	ctx := context.Background()
	container := "http://example.com/container/"
	created, err := service.CreateResource(ctx, container, "delete.txt", &StorageResource{ContentType: "text/plain", Body: []byte("delete")})
	require.NoError(t, err)

	require.NoError(t, service.DeleteResource(ctx, created.URI))
	exists, err := service.storage.Exists(ctx, created.URI)
	require.NoError(t, err)
	assert.False(t, exists)

	err = service.DeleteResource(ctx, created.URI)
	require.Error(t, err)
	var httpErr *HTTPError
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusNotFound, httpErr.StatusCode)
}

func TestContainerOperationConcurrentCreateAllowsOnlyOneWinner(t *testing.T) {

	service := newTestContainerOperationService(t)
	ctx := context.Background()
	container := "http://example.com/container/"

	var wg sync.WaitGroup
	var mu sync.Mutex
	var successes int
	var conflicts int
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := service.CreateResource(ctx, container, "same.txt", &StorageResource{ContentType: "text/plain", Body: []byte(fmt.Sprintf("body-%d", i))})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successes++
				return
			}
			var httpErr *HTTPError
			if assert.ErrorAs(t, err, &httpErr) && httpErr.StatusCode == http.StatusConflict {
				conflicts++
			}
		}(i)
	}
	wg.Wait()

	assert.Equal(t, 1, successes)
	assert.Equal(t, 15, conflicts)
	members, err := service.ListMembers(ctx, container)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, "http://example.com/container/same.txt", members[0].URI)
}

func TestContainerURIHelpers(t *testing.T) {

	normalized, err := NormalizeContainerURI("http://example.com/container")
	require.NoError(t, err)
	assert.Equal(t, "http://example.com/container/", normalized)

	parent, err := ParentContainerURI("http://example.com/container/resource.txt")
	require.NoError(t, err)
	assert.Equal(t, "http://example.com/container/", parent)

	assert.True(t, IsDirectContainerMember("http://example.com/container/", "http://example.com/container/resource.txt"))
	assert.True(t, IsDirectContainerMember("http://example.com/container/", "http://example.com/container/subcontainer/"))
	assert.False(t, IsDirectContainerMember("http://example.com/container/", "http://example.com/container/nested/resource.txt"))
	assert.False(t, IsDirectContainerMember("http://example.com/container/", "http://example.com/other.txt"))
}

func TestValidateResourceNameRejectsUnsafeNames(t *testing.T) {

	invalid := []string{
		"", ".", "..",
		"nested/name", "nested\\name",
		"bad\nname",
		"bad\x00name",
		"bad\x01name",
		"bad\x1fname",
		"bad\x7fname",
		"%zz",
	}
	for _, name := range invalid {
		assert.Error(t, ValidateResourceName(name), "name %q should be rejected", name)
	}
	assert.NoError(t, ValidateResourceName("safe name.txt"))
}

func newTestContainerOperationService(t *testing.T) *ContainerOperationService {
	t.Helper()
	layer := NewStorageAbstractionLayer(DefaultStorageAbstractionConfig())
	backend := NewInMemoryStorageBackend("default", nil)
	require.NoError(t, layer.RegisterBackend("default", backend))
	require.NoError(t, layer.SetDefaultBackend("default"))
	t.Cleanup(func() { _ = layer.Close() })
	return NewContainerOperationService(layer)
}
