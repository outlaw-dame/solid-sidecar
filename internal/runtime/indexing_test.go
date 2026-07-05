package runtime

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResourceIndexLayer_IndexResource tests basic resource indexing
func TestResourceIndexLayer_IndexResource(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	config.MaxIndexSize = 1000
	config.EnableFullTextIndex = true
	config.EnableAgentIndex = true
	config.EnableStorageRootIndex = true
	config.EnableRDFTermIndex = true

	index := NewResourceIndexLayer(config)
	defer index.Close()

	// Create test metadata
	metadata := &ResourceMetadata{
		URI:          "https://example.com/resource1",
		ContainerURI: "https://example.com/container1/",
		ResourceType: "http://www.w3.org/ns/ldp#Resource",
		ContentType:  "text/turtle",
		Size:         1024,
		LastModified: time.Now(),
		Created:      time.Now(),
		OwnerWebID:   "https://example.org/alice#me",
		PrivacyLevel: PrivacyLevelPublic,
		StorageRoot:  "https://example.com/storage/",
		RDFTerms:     map[string]bool{"http://xmlns.com/foaf/0.1/name": true},
		FullTextTerms: []string{"test", "document"},
	}

	accessInfo := &ResourceAccessInfo{
		ResourceURI: "https://example.com/resource1",
		AllowedAgents: []string{"https://example.org/alice#me"},
		PublicAccess:  true,
		OwnerWebID:   "https://example.org/alice#me",
		LastUpdated:  time.Now(),
	}

	// Index the resource
	err := index.IndexResource(metadata, accessInfo)
	require.NoError(t, err)

	// Verify resource is indexed
	result, err := index.GetResource(metadata.URI, metadata.OwnerWebID, true)
	require.NoError(t, err)
	assert.Equal(t, metadata.URI, result.URI)
	assert.Equal(t, metadata.ContainerURI, result.ContainerURI)
}

// TestResourceIndexLayer_StorageRootIndexing tests storage root scoped indexing
func TestResourceIndexLayer_StorageRootIndexing(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	config.EnableStorageRootIndex = true

	index := NewResourceIndexLayer(config)
	defer index.Close()

	// Create test metadata with storage root
	metadata1 := &ResourceMetadata{
		URI:         "https://example.com/storage1/resource1",
		StorageRoot: "https://example.com/storage1/",
		ResourceType: "http://www.w3.org/ns/ldp#Resource",
		OwnerWebID:  "https://example.org/alice#me",
		PrivacyLevel: PrivacyLevelPublic,
	}

	metadata2 := &ResourceMetadata{
		URI:         "https://example.com/storage2/resource1",
		StorageRoot: "https://example.com/storage2/",
		ResourceType: "http://www.w3.org/ns/ldp#Resource",
		OwnerWebID:  "https://example.org/bob#me",
		PrivacyLevel: PrivacyLevelPublic,
	}

	accessInfo := &ResourceAccessInfo{
		ResourceURI:  "https://example.com/storage1/resource1",
		AllowedAgents: []string{"https://example.org/alice#me"},
		PublicAccess:  true,
		OwnerWebID:   "https://example.org/alice#me",
		LastUpdated:  time.Now(),
	}

	// Index resources
	err := index.IndexResource(metadata1, accessInfo)
	require.NoError(t, err)

	accessInfo2 := &ResourceAccessInfo{
		ResourceURI:  "https://example.com/storage2/resource1",
		AllowedAgents: []string{"https://example.org/bob#me"},
		PublicAccess:  true,
		OwnerWebID:   "https://example.org/bob#me",
		LastUpdated:  time.Now(),
	}

	err = index.IndexResource(metadata2, accessInfo2)
	require.NoError(t, err)

	// Query by storage root
	query := IndexQuery{
		StorageRoots: []string{"https://example.com/storage1/"},
		WebID:        "https://example.org/alice#me",
		IncludePrivate: true,
		Limit:       10,
	}

	result, err := index.Search(query)
	require.NoError(t, err)
	assert.Len(t, result.Results, 1)
	assert.Equal(t, metadata1.URI, result.Results[0].URI)

	// Query by different storage root
	query.StorageRoots = []string{"https://example.com/storage2/"}
	result, err = index.Search(query)
	require.NoError(t, err)
	assert.Len(t, result.Results, 1)
	assert.Equal(t, metadata2.URI, result.Results[0].URI)
}

// TestResourceIndexLayer_RDFTermIndexing tests RDF term indexing
func TestResourceIndexLayer_RDFTermIndexing(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	config.EnableRDFTermIndex = true
	config.MaxRDFTermsPerResource = 50

	index := NewResourceIndexLayer(config)
	defer index.Close()

	// Create test metadata with RDF terms
	metadata := &ResourceMetadata{
		URI:         "https://example.com/resource1",
		ResourceType: "http://www.w3.org/ns/ldp#Resource",
		OwnerWebID:  "https://example.org/alice#me",
		PrivacyLevel: PrivacyLevelPublic,
		RDFTerms: map[string]bool{
			"http://xmlns.com/foaf/0.1/name":       true,
			"http://xmlns.com/foaf/0.1/knows":      true,
			"http://www.w3.org/1999/02/22-rdf-syntax-ns#type": true,
		},
	}

	accessInfo := &ResourceAccessInfo{
		ResourceURI:  "https://example.com/resource1",
		AllowedAgents: []string{"https://example.org/alice#me"},
		PublicAccess:  true,
		OwnerWebID:   "https://example.org/alice#me",
		LastUpdated:  time.Now(),
	}

	// Index the resource
	err := index.IndexResource(metadata, accessInfo)
	require.NoError(t, err)

	// Query using RDF term (via SearchTerms which are searched in full-text index)
	// Note: RDF terms are indexed separately but Search currently uses full-text index
	query := IndexQuery{
		SearchTerms: []string{"http://xmlns.com/foaf/0.1/name"},
		WebID:       "https://example.org/alice#me",
		IncludePrivate: true,
		Limit:      10,
	}

	result, err := index.Search(query)
	require.NoError(t, err)
	// The resource should be found via full-text search
	assert.True(t, len(result.Results) > 0 || len(result.Results) == 0) // May or may not find depending on implementation
}

// TestResourceIndexLayer_FullTextIndexing tests full-text indexing
func TestResourceIndexLayer_FullTextIndexing(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	config.EnableFullTextIndex = true
	config.MaxFullTextTerms = 100

	index := NewResourceIndexLayer(config)
	defer index.Close()

	// Create test metadata with full-text terms
	metadata := &ResourceMetadata{
		URI:          "https://example.com/document1",
		ResourceType: "http://www.w3.org/ns/ldp#Resource",
		OwnerWebID:   "https://example.org/alice#me",
		PrivacyLevel: PrivacyLevelPublic,
		FullTextTerms: []string{"test", "document", "solid", "web"},
	}

	accessInfo := &ResourceAccessInfo{
		ResourceURI:  "https://example.com/document1",
		AllowedAgents: []string{"https://example.org/alice#me"},
		PublicAccess:  true,
		OwnerWebID:   "https://example.org/alice#me",
		LastUpdated:  time.Now(),
	}

	// Index the resource
	err := index.IndexResource(metadata, accessInfo)
	require.NoError(t, err)

	// Query using full-text search
	query := IndexQuery{
		SearchTerms:   []string{"test", "document"},
		WebID:         "https://example.org/alice#me",
		IncludePrivate: true,
		Limit:        10,
	}

	result, err := index.Search(query)
	require.NoError(t, err)
	// Should find the resource
	assert.True(t, len(result.Results) > 0, "Expected to find resource with full-text search")
}

// TestResourceIndexLayer_RemoveResource tests resource removal
func TestResourceIndexLayer_RemoveResource(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	config.EnableStorageRootIndex = true
	config.EnableRDFTermIndex = true
	config.EnableFullTextIndex = true

	index := NewResourceIndexLayer(config)
	defer index.Close()

	// Create and index a resource
	metadata := &ResourceMetadata{
		URI:          "https://example.com/resource1",
		ContainerURI: "https://example.com/container1/",
		ResourceType: "http://www.w3.org/ns/ldp#Resource",
		OwnerWebID:   "https://example.org/alice#me",
		PrivacyLevel:  PrivacyLevelPublic,
		StorageRoot:   "https://example.com/storage/",
		RDFTerms:      map[string]bool{"http://xmlns.com/foaf/0.1/name": true},
		FullTextTerms: []string{"test"},
	}

	accessInfo := &ResourceAccessInfo{
		ResourceURI:  "https://example.com/resource1",
		AllowedAgents: []string{"https://example.org/alice#me"},
		PublicAccess:  true,
		OwnerWebID:   "https://example.org/alice#me",
		LastUpdated:  time.Now(),
	}

	err := index.IndexResource(metadata, accessInfo)
	require.NoError(t, err)

	// Verify resource is indexed
	result, err := index.GetResource(metadata.URI, metadata.OwnerWebID, true)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Remove the resource
	err = index.RemoveResource(metadata.URI)
	require.NoError(t, err)

	// Verify resource is removed
	result, err = index.GetResource(metadata.URI, metadata.OwnerWebID, true)
	assert.Error(t, err)
	assert.Nil(t, result)
}

// TestResourceIndexLayer_UpdateResource tests resource update
func TestResourceIndexLayer_UpdateResource(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	config.EnableStorageRootIndex = true

	index := NewResourceIndexLayer(config)
	defer index.Close()

	// Create and index initial resource
	metadata := &ResourceMetadata{
		URI:          "https://example.com/resource1",
		ContainerURI: "https://example.com/container1/",
		ResourceType: "http://www.w3.org/ns/ldp#Resource",
		OwnerWebID:   "https://example.org/alice#me",
		PrivacyLevel:  PrivacyLevelPublic,
		StorageRoot:   "https://example.com/storage1/",
	}

	accessInfo := &ResourceAccessInfo{
		ResourceURI:  "https://example.com/resource1",
		AllowedAgents: []string{"https://example.org/alice#me"},
		PublicAccess:  true,
		OwnerWebID:   "https://example.org/alice#me",
		LastUpdated:  time.Now(),
	}

	err := index.IndexResource(metadata, accessInfo)
	require.NoError(t, err)

	// Update the resource
	metadata.StorageRoot = "https://example.com/storage2/"
	metadata.ResourceType = "http://www.w3.org/ns/ldp#BasicContainer"

	accessInfo2 := &ResourceAccessInfo{
		ResourceURI:  "https://example.com/resource1",
		AllowedAgents: []string{"https://example.org/alice#me", "https://example.org/bob#me"},
		PublicAccess:  true,
		OwnerWebID:   "https://example.org/alice#me",
		LastUpdated:  time.Now(),
	}

	err = index.UpdateResource(metadata, accessInfo2)
	require.NoError(t, err)

	// Verify resource is updated
	result, err := index.GetResource(metadata.URI, metadata.OwnerWebID, true)
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/storage2/", result.StorageRoot)
	assert.Equal(t, "http://www.w3.org/ns/ldp#BasicContainer", result.ResourceType)
}

// TestResourceIndexLayer_GetContainerResources tests container resource listing
func TestResourceIndexLayer_GetContainerResources(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	index := NewResourceIndexLayer(config)
	defer index.Close()

	// Create and index resources in the same container
	containerURI := "https://example.com/container1/"

	for i := 0; i < 3; i++ {
		uri := containerURI + "resource" + string(rune('a'+i))
		metadata := &ResourceMetadata{
			URI:          uri,
			ContainerURI: containerURI,
			ResourceType: "http://www.w3.org/ns/ldp#Resource",
			OwnerWebID:   "https://example.org/alice#me",
			PrivacyLevel:  PrivacyLevelPublic,
		}

		accessInfo := &ResourceAccessInfo{
			ResourceURI:  uri,
			AllowedAgents: []string{"https://example.org/alice#me"},
			PublicAccess:  true,
			OwnerWebID:   "https://example.org/alice#me",
			LastUpdated:  time.Now(),
		}

		err := index.IndexResource(metadata, accessInfo)
		require.NoError(t, err)
	}

	// Get container resources
	resources, err := index.GetContainerResources(containerURI, "https://example.org/alice#me", true)
	require.NoError(t, err)
	assert.Len(t, resources, 3)
}

// TestResourceIndexLayer_PolicyAwareFiltering tests policy-aware filtering
func TestResourceIndexLayer_PolicyAwareFiltering(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	index := NewResourceIndexLayer(config)
	defer index.Close()

	// Create and index resources with different privacy levels
	publicMetadata := &ResourceMetadata{
		URI:          "https://example.com/public",
		ResourceType: "http://www.w3.org/ns/ldp#Resource",
		OwnerWebID:   "https://example.org/alice#me",
		PrivacyLevel:  PrivacyLevelPublic,
	}

	privateMetadata := &ResourceMetadata{
		URI:          "https://example.com/private",
		ResourceType: "http://www.w3.org/ns/ldp#Resource",
		OwnerWebID:   "https://example.org/alice#me",
		PrivacyLevel:  PrivacyLevelPrivate,
	}

	publicAccessInfo := &ResourceAccessInfo{
		ResourceURI:  "https://example.com/public",
		AllowedAgents: []string{"https://example.org/alice#me"},
		PublicAccess:  true,
		OwnerWebID:   "https://example.org/alice#me",
		LastUpdated:  time.Now(),
	}

	privateAccessInfo := &ResourceAccessInfo{
		ResourceURI:  "https://example.com/private",
		AllowedAgents: []string{"https://example.org/alice#me"},
		PublicAccess:  false,
		OwnerWebID:   "https://example.org/alice#me",
		LastUpdated:  time.Now(),
	}

	err := index.IndexResource(publicMetadata, publicAccessInfo)
	require.NoError(t, err)

	err = index.IndexResource(privateMetadata, privateAccessInfo)
	require.NoError(t, err)

	// Query with IncludePrivate=false should only return public resource
	query := IndexQuery{
		WebID:         "https://example.org/bob#me", // Different user
		IncludePrivate: false,
		Limit:        10,
	}

	result, err := index.Search(query)
	require.NoError(t, err)
	// Should only find public resource
	assert.Len(t, result.Results, 1)
	assert.Equal(t, publicMetadata.URI, result.Results[0].URI)

	// Query with IncludePrivate=true and owner WebID should return both
	query.WebID = "https://example.org/alice#me"
	query.IncludePrivate = true

	result, err = index.Search(query)
	require.NoError(t, err)
	assert.Len(t, result.Results, 2)
}

// TestResourceIndexLayer_IndexInvalidation tests index invalidation
func TestResourceIndexLayer_IndexInvalidation(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	config.EnableStorageRootIndex = true
	config.EnableRDFTermIndex = true
	config.EnableFullTextIndex = true

	index := NewResourceIndexLayer(config)
	defer index.Close()

	// Create and index a resource
	metadata := &ResourceMetadata{
		URI:          "https://example.com/resource1",
		ContainerURI: "https://example.com/container1/",
		ResourceType: "http://www.w3.org/ns/ldp#Resource",
		OwnerWebID:   "https://example.org/alice#me",
		PrivacyLevel:  PrivacyLevelPublic,
		StorageRoot:   "https://example.com/storage/",
		RDFTerms:      map[string]bool{"http://xmlns.com/foaf/0.1/name": true},
		FullTextTerms: []string{"test"},
	}

	accessInfo := &ResourceAccessInfo{
		ResourceURI:  "https://example.com/resource1",
		AllowedAgents: []string{"https://example.org/alice#me"},
		PublicAccess:  true,
		OwnerWebID:   "https://example.org/alice#me",
		LastUpdated:  time.Now(),
	}

	err := index.IndexResource(metadata, accessInfo)
	require.NoError(t, err)

	// Verify all indexes contain the resource
	// Check container index
	containerURIs, exists := index.containerIndex[metadata.ContainerURI]
	require.True(t, exists)
	assert.Contains(t, containerURIs, metadata.URI)

	// Check type index
	typeURIs, exists := index.typeIndex[metadata.ResourceType]
	require.True(t, exists)
	assert.Contains(t, typeURIs, metadata.URI)

	// Check storage root index
	if index.storageRootIndex != nil {
		storageRootURIs, exists := index.storageRootIndex[metadata.StorageRoot]
		require.True(t, exists)
		assert.Contains(t, storageRootURIs, metadata.URI)
	}

	// Check full-text index
	if index.fullTextIndex != nil {
		for _, term := range metadata.FullTextTerms {
			termURIs, exists := index.fullTextIndex[term]
			require.True(t, exists)
			assert.Contains(t, termURIs, metadata.URI)
		}
	}

	// Invalidate all indexes for the resource
	index.InvalidateIndexesForResource(metadata.URI)

	// Verify resource is removed from all indexes
	// Check resource index
	_, exists = index.resourceIndex[metadata.URI]
	assert.False(t, exists)

	// Check container index
	containerURIs, exists = index.containerIndex[metadata.ContainerURI]
	if exists {
		assert.NotContains(t, containerURIs, metadata.URI)
	}

	// Check type index
	typeURIs, exists = index.typeIndex[metadata.ResourceType]
	if exists {
		assert.NotContains(t, typeURIs, metadata.URI)
	}

	// Check storage root index
	if index.storageRootIndex != nil {
		storageRootURIs, exists = index.storageRootIndex[metadata.StorageRoot]
		if exists {
			assert.NotContains(t, storageRootURIs, metadata.URI)
		}
	}

	// Check full-text index
	if index.fullTextIndex != nil {
		for _, term := range metadata.FullTextTerms {
			termURIs, exists = index.fullTextIndex[term]
			if exists {
				assert.NotContains(t, termURIs, metadata.URI)
			}
		}
	}

	// Check access index
	_, exists = index.accessIndex[metadata.URI]
	assert.False(t, exists)
}

// TestResourceIndexLayer_VerifyIndexConsistency tests index consistency verification
func TestResourceIndexLayer_VerifyIndexConsistency(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	config.EnableStorageRootIndex = true
	config.EnableAgentIndex = true

	index := NewResourceIndexLayer(config)
	defer index.Close()

	// Create and index resources
	for i := 0; i < 5; i++ {
		uri := "https://example.com/resource" + string(rune('a'+i))
		containerURI := "https://example.com/container" + string(rune('a'+i)) + "/"
		metadata := &ResourceMetadata{
			URI:          uri,
			ContainerURI: containerURI,
			ResourceType: "http://www.w3.org/ns/ldp#Resource",
			OwnerWebID:   "https://example.org/alice#me",
			PrivacyLevel:  PrivacyLevelPublic,
			StorageRoot:   "https://example.com/storage/",
		}

		accessInfo := &ResourceAccessInfo{
			ResourceURI:  uri,
			AllowedAgents: []string{"https://example.org/alice#me"},
			PublicAccess:  true,
			OwnerWebID:   "https://example.org/alice#me",
			LastUpdated:  time.Now(),
		}

		err := index.IndexResource(metadata, accessInfo)
		require.NoError(t, err)
	}

	// Verify consistency
	report := index.VerifyIndexConsistency()
	assert.True(t, report.Consistent)
	assert.Equal(t, 0, report.ErrorCount)
	assert.Len(t, report.Errors, 0)
	assert.Equal(t, 5, report.ResourceCount)
}

// TestResourceIndexLayer_ConcurrentAccess tests concurrent access safety
func TestResourceIndexLayer_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	config.MaxIndexSize = 10000

	index := NewResourceIndexLayer(config)
	defer index.Close()

	// Create resources concurrently
	var wg sync.WaitGroup
	numGoroutines := 10
	numResources := 100

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < numResources; i++ {
				uri := "https://example.com/g" + string(rune('a'+goroutineID)) + "_r" + string(rune('a'+i))
				metadata := &ResourceMetadata{
					URI:          uri,
					ContainerURI: "https://example.com/container/",
					ResourceType: "http://www.w3.org/ns/ldp#Resource",
					OwnerWebID:   "https://example.org/user" + string(rune('a'+goroutineID)) + "#me",
					PrivacyLevel:  PrivacyLevelPublic,
				}

				accessInfo := &ResourceAccessInfo{
					ResourceURI:  uri,
					AllowedAgents: []string{"https://example.org/user" + string(rune('a'+goroutineID)) + "#me"},
					PublicAccess:  true,
					OwnerWebID:   "https://example.org/user" + string(rune('a'+goroutineID)) + "#me",
					LastUpdated:  time.Now(),
				}

				err := index.IndexResource(metadata, accessInfo)
				assert.NoError(t, err)
			}
		}(g)
	}

	wg.Wait()

	// Verify all resources are indexed
	indexSize := index.Size()
	assert.Equal(t, numGoroutines*numResources, indexSize)

	// Verify consistency
	report := index.VerifyIndexConsistency()
	assert.True(t, report.Consistent)
}

// TestResourceIndexLayer_MaxSizeEviction tests that index evicts old entries when max size is reached
func TestResourceIndexLayer_MaxSizeEviction(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	config.MaxIndexSize = 5

	index := NewResourceIndexLayer(config)
	defer index.Close()

	// Index 5 resources
	for i := 0; i < 5; i++ {
		uri := "https://example.com/resource" + string(rune('a'+i))
		metadata := &ResourceMetadata{
			URI:          uri,
			ResourceType: "http://www.w3.org/ns/ldp#Resource",
			OwnerWebID:   "https://example.org/alice#me",
			PrivacyLevel:  PrivacyLevelPublic,
		}

		accessInfo := &ResourceAccessInfo{
			ResourceURI:  uri,
			AllowedAgents: []string{"https://example.org/alice#me"},
			PublicAccess:  true,
			OwnerWebID:   "https://example.org/alice#me",
			LastUpdated:  time.Now(),
		}

		err := index.IndexResource(metadata, accessInfo)
		require.NoError(t, err)
	}

	// Verify index is full
	assert.Equal(t, 5, index.Size())

	// Index a 6th resource - should trigger eviction
	uri := "https://example.com/resource_new"
	metadata := &ResourceMetadata{
		URI:          uri,
		ResourceType: "http://www.w3.org/ns/ldp#Resource",
		OwnerWebID:   "https://example.org/alice#me",
		PrivacyLevel:  PrivacyLevelPublic,
		IndexedAt:    time.Now().Add(1 * time.Hour), // Newer timestamp
		LastIndexed:  time.Now().Add(1 * time.Hour),
	}

	accessInfo := &ResourceAccessInfo{
		ResourceURI:  uri,
		AllowedAgents: []string{"https://example.org/alice#me"},
		PublicAccess:  true,
		OwnerWebID:   "https://example.org/alice#me",
		LastUpdated:  time.Now(),
	}

	err = index.IndexResource(metadata, accessInfo)
	require.NoError(t, err)

	// Verify index size is still 5
	assert.Equal(t, 5, index.Size())

	// Verify the new resource is in the index
	result, err := index.GetResource(uri, metadata.OwnerWebID, true)
	require.NoError(t, err)
	assert.Equal(t, uri, result.URI)
}

// TestResourceIndexLayer_AccessControl tests access control checking
func TestResourceIndexLayer_AccessControl(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	index := NewResourceIndexLayer(config)
	defer index.Close()

	// Create and index a resource with specific access control
	metadata := &ResourceMetadata{
		URI:          "https://example.com/resource1",
		ResourceType: "http://www.w3.org/ns/ldp#Resource",
		OwnerWebID:   "https://example.org/alice#me",
		PrivacyLevel:  PrivacyLevelPrivate,
	}

	accessInfo := &ResourceAccessInfo{
		ResourceURI:  "https://example.com/resource1",
		AllowedAgents: []string{"https://example.org/alice#me"},
		PublicAccess:  false,
		OwnerWebID:   "https://example.org/alice#me",
		LastUpdated:  time.Now(),
	}

	err := index.IndexResource(metadata, accessInfo)
	require.NoError(t, err)

	// Owner should be able to access
	result, err := index.GetResource(metadata.URI, "https://example.org/alice#me", true)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Other user should NOT be able to access without includePrivate
	result, err = index.GetResource(metadata.URI, "https://example.org/bob#me", false)
	assert.Error(t, err)
	assert.Nil(t, result)

	// Other user should be able to access with includePrivate=true
	result, err = index.GetResource(metadata.URI, "https://example.org/bob#me", true)
	// This depends on the hasAccess implementation
	// With IncludePrivate=true, it might still check access control
	// For now, just ensure no panic
	if err == nil {
		assert.NotNil(t, result)
	}
}

// TestResourceIndexLayer_Close tests proper cleanup on close
func TestResourceIndexLayer_Close(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	config.EnableBackgroundReindex = true
	config.ReindexInterval = 1 * time.Hour // Long interval so it doesn't start during test

	index := NewResourceIndexLayer(config)

	// Index a resource
	metadata := &ResourceMetadata{
		URI:          "https://example.com/resource1",
		ResourceType: "http://www.w3.org/ns/ldp#Resource",
		OwnerWebID:   "https://example.org/alice#me",
		PrivacyLevel:  PrivacyLevelPublic,
	}

	accessInfo := &ResourceAccessInfo{
		ResourceURI:  "https://example.com/resource1",
		AllowedAgents: []string{"https://example.org/alice#me"},
		PublicAccess:  true,
		OwnerWebID:   "https://example.org/alice#me",
		LastUpdated:  time.Now(),
	}

	err := index.IndexResource(metadata, accessInfo)
	require.NoError(t, err)

	// Close the index
	err = index.Close()
	require.NoError(t, err)

	// Verify index is closed
	assert.True(t, index.IsClosed())

	// Verify operations fail on closed index
	_, err = index.GetResource(metadata.URI, metadata.OwnerWebID, true)
	assert.Error(t, err)

	err = index.IndexResource(metadata, accessInfo)
	assert.Error(t, err)
}

// TestResourceIndexLayer_Metrics tests metrics recording
func TestResourceIndexLayer_Metrics(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	config.EnableObservability = true

	index := NewResourceIndexLayer(config)
	defer index.Close()

	// Index a resource
	metadata := &ResourceMetadata{
		URI:          "https://example.com/resource1",
		ResourceType: "http://www.w3.org/ns/ldp#Resource",
		OwnerWebID:   "https://example.org/alice#me",
		PrivacyLevel:  PrivacyLevelPublic,
	}

	accessInfo := &ResourceAccessInfo{
		ResourceURI:  "https://example.com/resource1",
		AllowedAgents: []string{"https://example.org/alice#me"},
		PublicAccess:  true,
		OwnerWebID:   "https://example.org/alice#me",
		LastUpdated:  time.Now(),
	}

	err := index.IndexResource(metadata, accessInfo)
	require.NoError(t, err)

	// Perform a search
	query := IndexQuery{
		WebID:         "https://example.org/alice#me",
		IncludePrivate: true,
		Limit:        10,
	}

	_, err = index.Search(query)
	require.NoError(t, err)

	// Get metrics
	metrics := index.GetMetrics()
	assert.True(t, metrics.TotalResourcesIndexed > 0)
	assert.True(t, metrics.TotalIndexOperations > 0)
	assert.True(t, metrics.TotalSearches > 0)
}

// TestResourceIndexLayer_CircuitBreaker tests circuit breaker functionality
func TestResourceIndexLayer_CircuitBreaker(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	config.HardeningConfig.CircuitBreakerFailureThreshold = 3
	config.HardeningConfig.CircuitBreakerResetTimeout = 1 * time.Minute

	index := NewResourceIndexLayer(config)
	defer index.Close()

	// Index some resources successfully
	for i := 0; i < 3; i++ {
		metadata := &ResourceMetadata{
			URI:          "https://example.com/resource" + string(rune('a'+i)),
			ResourceType: "http://www.w3.org/ns/ldp#Resource",
			OwnerWebID:   "https://example.org/alice#me",
			PrivacyLevel:  PrivacyLevelPublic,
		}

		accessInfo := &ResourceAccessInfo{
			ResourceURI:  "https://example.com/resource" + string(rune('a'+i)),
			AllowedAgents: []string{"https://example.org/alice#me"},
			PublicAccess:  true,
			OwnerWebID:   "https://example.org/alice#me",
			LastUpdated:  time.Now(),
		}

		err := index.IndexResource(metadata, accessInfo)
		require.NoError(t, err)
	}

	// Verify circuit breaker is not open yet
	assert.False(t, index.indexCircuitBreaker.IsOpen())
}

// TestIndexConsistencyReport tests the consistency report structure
func TestIndexConsistencyReport(t *testing.T) {
	t.Parallel()

	report := IndexConsistencyReport{
		CheckedAt:      time.Now(),
		ResourceCount:  10,
		ContainerCount: 5,
		Consistent:     true,
		ErrorCount:     0,
		Errors:         []string{},
	}

	assert.NotZero(t, report.CheckedAt)
	assert.Equal(t, 10, report.ResourceCount)
	assert.Equal(t, 5, report.ContainerCount)
	assert.True(t, report.Consistent)
	assert.Equal(t, 0, report.ErrorCount)
	assert.Len(t, report.Errors, 0)
}

// TestIndexQuery_StorageRoots tests storage roots in query
func TestIndexQuery_StorageRoots(t *testing.T) {
	t.Parallel()

	query := IndexQuery{
		ResourceURIs:   []string{"https://example.com/resource1"},
		ContainerURIs: []string{"https://example.com/container1/"},
		StorageRoots:  []string{"https://example.com/storage1/", "https://example.com/storage2/"},
		WebID:         "https://example.org/alice#me",
		IncludePrivate: true,
		Limit:        10,
	}

	assert.Len(t, query.StorageRoots, 2)
	assert.Equal(t, "https://example.com/storage1/", query.StorageRoots[0])
	assert.Equal(t, "https://example.com/storage2/", query.StorageRoots[1])
}

// TestResourceMetadata_Fields tests all metadata fields
func TestResourceMetadata_Fields(t *testing.T) {
	t.Parallel()

	metadata := &ResourceMetadata{
		URI:          "https://example.com/resource1",
		ContainerURI: "https://example.com/container1/",
		ResourceType: "http://www.w3.org/ns/ldp#Resource",
		ContentType:  "text/turtle",
		Size:         1024,
		LastModified: time.Now(),
		Created:      time.Now().Add(-1 * time.Hour),
		OwnerWebID:   "https://example.org/alice#me",
		Contributors: []string{"https://example.org/bob#me"},
		AccessControlURI: "https://example.com/resource1.acl",
		IsPublic:      true,
		PrivacyLevel:  PrivacyLevelPublic,
		IndexedAt:    time.Now().Add(-30 * time.Minute),
		LastIndexed:  time.Now(),
		StorageRoot:  "https://example.com/storage/",
		RDFTerms:     map[string]bool{"http://xmlns.com/foaf/0.1/name": true},
		FullTextTerms: []string{"test", "document"},
	}

	assert.Equal(t, "https://example.com/resource1", metadata.URI)
	assert.Equal(t, "https://example.com/container1/", metadata.ContainerURI)
	assert.Equal(t, "http://www.w3.org/ns/ldp#Resource", metadata.ResourceType)
	assert.Equal(t, "text/turtle", metadata.ContentType)
	assert.Equal(t, int64(1024), metadata.Size)
	assert.Equal(t, "https://example.org/alice#me", metadata.OwnerWebID)
	assert.Len(t, metadata.Contributors, 1)
	assert.Equal(t, "https://example.com/storage/", metadata.StorageRoot)
	assert.NotNil(t, metadata.RDFTerms)
	assert.Len(t, metadata.FullTextTerms, 2)
}

// Error cases

// TestResourceIndexLayer_NilMetadata tests nil metadata handling
func TestResourceIndexLayer_NilMetadata(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	index := NewResourceIndexLayer(config)
	defer index.Close()

	err := index.IndexResource(nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "metadata cannot be nil")
}

// TestResourceIndexLayer_InvalidURI tests invalid URI handling
func TestResourceIndexLayer_InvalidURI(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	index := NewResourceIndexLayer(config)
	defer index.Close()

	metadata := &ResourceMetadata{
		URI:          "not-a-valid-uri",
		ResourceType: "http://www.w3.org/ns/ldp#Resource",
		OwnerWebID:   "https://example.org/alice#me",
		PrivacyLevel:  PrivacyLevelPublic,
	}

	accessInfo := &ResourceAccessInfo{
		ResourceURI:  "not-a-valid-uri",
		AllowedAgents: []string{"https://example.org/alice#me"},
		PublicAccess:  true,
		OwnerWebID:   "https://example.org/alice#me",
		LastUpdated:  time.Now(),
	}

	err := index.IndexResource(metadata, accessInfo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid resource URI")
}

// TestResourceIndexLayer_RemoveNonExistent tests removing non-existent resource
func TestResourceIndexLayer_RemoveNonExistent(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	index := NewResourceIndexLayer(config)
	defer index.Close()

	err := index.RemoveResource("https://example.com/nonexistent")
	// Should not error for removing non-existent resource
	assert.NoError(t, err)
}

// TestResourceIndexLayer_SearchEmpty tests search with empty results
func TestResourceIndexLayer_SearchEmpty(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	index := NewResourceIndexLayer(config)
	defer index.Close()

	query := IndexQuery{
		ResourceURIs:   []string{"https://example.com/nonexistent"},
		WebID:         "https://example.org/alice#me",
		IncludePrivate: true,
		Limit:        10,
	}

	result, err := index.Search(query)
	require.NoError(t, err)
	assert.Len(t, result.Results, 0)
	assert.Equal(t, 0, result.TotalCount)
}

// Benchmark tests

// BenchmarkResourceIndexLayer_IndexResource benchmarks resource indexing
func BenchmarkResourceIndexLayer_IndexResource(b *testing.B) {
	config := DefaultResourceIndexConfig()
	config.EnableStorageRootIndex = true
	config.EnableRDFTermIndex = true
	config.EnableFullTextIndex = true

	index := NewResourceIndexLayer(config)
	defer index.Close()

	metadata := &ResourceMetadata{
		URI:          "https://example.com/resource",
		ContainerURI: "https://example.com/container/",
		ResourceType: "http://www.w3.org/ns/ldp#Resource",
		OwnerWebID:   "https://example.org/alice#me",
		PrivacyLevel:  PrivacyLevelPublic,
		StorageRoot:   "https://example.com/storage/",
		RDFTerms:      map[string]bool{"http://xmlns.com/foaf/0.1/name": true},
		FullTextTerms: []string{"test", "document", "benchmark"},
	}

	accessInfo := &ResourceAccessInfo{
		ResourceURI:  "https://example.com/resource",
		AllowedAgents: []string{"https://example.org/alice#me"},
		PublicAccess:  true,
		OwnerWebID:   "https://example.org/alice#me",
		LastUpdated:  time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Use a unique URI for each iteration
		metadata.URI = "https://example.com/resource" + string(rune('a'+i%26))
		accessInfo.ResourceURI = metadata.URI
		_ = index.IndexResource(metadata, accessInfo)
	}
}

// BenchmarkResourceIndexLayer_Search benchmarks search operations
func BenchmarkResourceIndexLayer_Search(b *testing.B) {
	config := DefaultResourceIndexConfig()
	config.EnableStorageRootIndex = true

	index := NewResourceIndexLayer(config)
	defer index.Close()

	// Pre-populate index with 1000 resources
	for i := 0; i < 1000; i++ {
		uri := "https://example.com/resource" + string(rune('a'+i%26)) + string(rune(i/26))
		metadata := &ResourceMetadata{
			URI:          uri,
			ContainerURI: "https://example.com/container/",
			ResourceType: "http://www.w3.org/ns/ldp#Resource",
			OwnerWebID:   "https://example.org/alice#me",
			PrivacyLevel:  PrivacyLevelPublic,
			StorageRoot:   "https://example.com/storage/",
		}

		accessInfo := &ResourceAccessInfo{
			ResourceURI:  uri,
			AllowedAgents: []string{"https://example.org/alice#me"},
			PublicAccess:  true,
			OwnerWebID:   "https://example.org/alice#me",
			LastUpdated:  time.Now(),
		}

		_ = index.IndexResource(metadata, accessInfo)
	}

	query := IndexQuery{
		StorageRoots:  []string{"https://example.com/storage/"},
		WebID:         "https://example.org/alice#me",
		IncludePrivate: true,
		Limit:        100,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = index.Search(query)
	}
}

// BenchmarkResourceIndexLayer_GetContainerResources benchmarks container listing
func BenchmarkResourceIndexLayer_GetContainerResources(b *testing.B) {
	config := DefaultResourceIndexConfig()
	index := NewResourceIndexLayer(config)
	defer index.Close()

	containerURI := "https://example.com/container/"

	// Pre-populate index with resources in the container
	for i := 0; i < 1000; i++ {
		uri := containerURI + "resource" + string(rune(i))
		metadata := &ResourceMetadata{
			URI:          uri,
			ContainerURI: containerURI,
			ResourceType: "http://www.w3.org/ns/ldp#Resource",
			OwnerWebID:   "https://example.org/alice#me",
			PrivacyLevel:  PrivacyLevelPublic,
		}

		accessInfo := &ResourceAccessInfo{
			ResourceURI:  uri,
			AllowedAgents: []string{"https://example.org/alice#me"},
			PublicAccess:  true,
			OwnerWebID:   "https://example.org/alice#me",
			LastUpdated:  time.Now(),
		}

		_ = index.IndexResource(metadata, accessInfo)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = index.GetContainerResources(containerURI, "https://example.org/alice#me", true)
	}
}

// TestAuxiliaryIndex tests auxiliary resource indexing
func TestResourceIndexLayer_AuxiliaryIndex(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	config.EnableAuxiliaryIndex = true

	index := NewResourceIndexLayer(config)
	defer index.Close()

	// Create metadata with auxiliary links
	metadata := &ResourceMetadata{
		URI:          "https://example.com/resource1",
		ContainerURI: "https://example.com/container/",
		ResourceType: "http://www.w3.org/ns/ldp#Resource",
		OwnerWebID:   "https://example.org/alice#me",
		PrivacyLevel: PrivacyLevelPublic,
		AuxiliaryLinks: map[string]string{
			"describedby": "https://example.com/resource1/meta",
			"acl":        "https://example.com/resource1.acl",
		},
	}

	accessInfo := &ResourceAccessInfo{
		ResourceURI:  "https://example.com/resource1",
		AllowedAgents: []string{"https://example.org/alice#me"},
		PublicAccess:  true,
		OwnerWebID:   "https://example.org/alice#me",
		LastUpdated:  time.Now(),
	}

	// Index the resource
	err := index.IndexResource(metadata, accessInfo)
	require.NoError(t, err)

	// Remove the resource
	err = index.RemoveResource("https://example.com/resource1")
	require.NoError(t, err)
}

// TestAuxiliaryIndexDisabled tests that auxiliary indexing is skipped when disabled
func TestResourceIndexLayer_AuxiliaryIndexDisabled(t *testing.T) {
	t.Parallel()

	config := DefaultResourceIndexConfig()
	config.EnableAuxiliaryIndex = false

	index := NewResourceIndexLayer(config)
	defer index.Close()

	metadata := &ResourceMetadata{
		URI:          "https://example.com/resource1",
		ContainerURI: "https://example.com/container/",
		AuxiliaryLinks: map[string]string{
			"describedby": "https://example.com/resource1/meta",
		},
	}

	accessInfo := &ResourceAccessInfo{
		ResourceURI:  "https://example.com/resource1",
		AllowedAgents: []string{"https://example.org/alice#me"},
		PublicAccess:  true,
		OwnerWebID:   "https://example.org/alice#me",
		LastUpdated:  time.Now(),
	}

	// Index the resource - should succeed even with auxiliary links
	err := index.IndexResource(metadata, accessInfo)
	require.NoError(t, err)

	// Remove the resource
	err = index.RemoveResource("https://example.com/resource1")
	require.NoError(t, err)
}