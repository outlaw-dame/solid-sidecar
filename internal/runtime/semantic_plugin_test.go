package runtime

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockSemanticPlugin is a mock implementation of SemanticSearchPlugin for testing
type MockSemanticPlugin struct {
	name        string
	version     string
	description string
	indexedURIs map[string]bool
	vectors     map[string][]float32
	searchFunc  func(query string, webID string, storageRoots []string, limit int) ([]SemanticSearchResult, error)
	closed      bool
}

func (m *MockSemanticPlugin) Name() string        { return m.name }
func (m *MockSemanticPlugin) Version() string     { return m.version }
func (m *MockSemanticPlugin) Description() string { return m.description }
func (m *MockSemanticPlugin) Initialize(config map[string]interface{}, logger *slog.Logger) error {
	return nil
}
func (m *MockSemanticPlugin) IndexResource(ctx context.Context, uri string, content []byte, metadata *ResourceMetadata, accessInfo *ResourceAccessInfo) error {
	m.indexedURIs[uri] = true
	return nil
}
func (m *MockSemanticPlugin) RemoveResource(ctx context.Context, uri string) error {
	delete(m.indexedURIs, uri)
	return nil
}
func (m *MockSemanticPlugin) Search(ctx context.Context, query string, webID string, storageRoots []string, limit int) ([]SemanticSearchResult, error) {
	if m.searchFunc != nil {
		return m.searchFunc(query, webID, storageRoots, limit)
	}
	return nil, nil
}
func (m *MockSemanticPlugin) GetResourceVectors(ctx context.Context, uri string) ([]float32, error) {
	if vectors, exists := m.vectors[uri]; exists {
		return vectors, nil
	}
	return nil, errors.New("vectors not found")
}
func (m *MockSemanticPlugin) PrivacyCheck() error { return nil }
func (m *MockSemanticPlugin) Close() error {
	m.closed = true
	return nil
}

// FailingPrivacyPlugin is a mock plugin that always fails privacy checks
type FailingPrivacyPlugin struct {
	MockSemanticPlugin
}

func (f *FailingPrivacyPlugin) PrivacyCheck() error {
	return errors.New("privacy violation detected")
}

func TestSemanticPluginManager_New(t *testing.T) {
	t.Parallel()

	config := DefaultSemanticPluginConfig()
	config.Enabled = true

	manager := NewSemanticPluginManager(config)
	assert.NotNil(t, manager)
	assert.False(t, manager.IsClosed())
}

func TestSemanticPluginManager_RegisterPlugin(t *testing.T) {
	t.Parallel()

	config := DefaultSemanticPluginConfig()
	manager := NewSemanticPluginManager(config)
	defer manager.Close()

	plugin := &MockSemanticPlugin{
		name:        "test-plugin",
		version:     "1.0.0",
		description: "Test semantic plugin",
		indexedURIs: make(map[string]bool),
		vectors:     make(map[string][]float32),
	}

	// Register plugin
	err := manager.RegisterPlugin("test", plugin)
	require.NoError(t, err)

	// Verify plugin is registered
	active := manager.GetActivePlugin()
	assert.NotNil(t, active)
	assert.Equal(t, "test-plugin", active.Name())
}

func TestSemanticPluginManager_RegisterPlugin_MaxPlugins(t *testing.T) {
	t.Parallel()

	config := DefaultSemanticPluginConfig()
	config.MaxPlugins = 2
	manager := NewSemanticPluginManager(config)
	defer manager.Close()

	plugin1 := &MockSemanticPlugin{name: "plugin1", version: "1.0.0", indexedURIs: make(map[string]bool)}
	plugin2 := &MockSemanticPlugin{name: "plugin2", version: "1.0.0", indexedURIs: make(map[string]bool)}
	plugin3 := &MockSemanticPlugin{name: "plugin3", version: "1.0.0", indexedURIs: make(map[string]bool)}

	err := manager.RegisterPlugin("p1", plugin1)
	require.NoError(t, err)

	err = manager.RegisterPlugin("p2", plugin2)
	require.NoError(t, err)

	// Third plugin should fail
	err = manager.RegisterPlugin("p3", plugin3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "maximum number of plugins")
}

func TestSemanticPluginManager_SetActivePlugin(t *testing.T) {
	t.Parallel()

	config := DefaultSemanticPluginConfig()
	manager := NewSemanticPluginManager(config)
	defer manager.Close()

	plugin1 := &MockSemanticPlugin{name: "plugin1", version: "1.0.0", indexedURIs: make(map[string]bool)}
	plugin2 := &MockSemanticPlugin{name: "plugin2", version: "1.0.0", indexedURIs: make(map[string]bool)}

	manager.RegisterPlugin("p1", plugin1)
	manager.RegisterPlugin("p2", plugin2)

	// Set active to plugin2
	err := manager.SetActivePlugin("p2")
	require.NoError(t, err)

	active := manager.GetActivePlugin()
	assert.Equal(t, "plugin2", active.Name())
}

func TestSemanticPluginManager_SetActivePlugin_NotFound(t *testing.T) {
	t.Parallel()

	config := DefaultSemanticPluginConfig()
	manager := NewSemanticPluginManager(config)
	defer manager.Close()

	plugin := &MockSemanticPlugin{name: "plugin1", version: "1.0.0", indexedURIs: make(map[string]bool)}
	manager.RegisterPlugin("p1", plugin)

	// Try to set non-existent plugin
	err := manager.SetActivePlugin("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSemanticPluginManager_IndexResource(t *testing.T) {
	t.Parallel()

	config := DefaultSemanticPluginConfig()
	config.Enabled = true
	manager := NewSemanticPluginManager(config)
	defer manager.Close()

	plugin := &MockSemanticPlugin{
		name:        "test-plugin",
		version:     "1.0.0",
		indexedURIs: make(map[string]bool),
	}
	manager.RegisterPlugin("test", plugin)

	metadata := &ResourceMetadata{
		URI:          "https://example.com/resource1",
		IsPublic:     true,
		ResourceType: "http://www.w3.org/ns/ldp#Resource",
	}

	ctx := context.Background()
	err := manager.IndexResource(ctx, "https://example.com/resource1", []byte("test content"), metadata, nil)
	require.NoError(t, err)

	// Verify resource was indexed
	assert.True(t, plugin.indexedURIs["https://example.com/resource1"])
}

func TestSemanticPluginManager_IndexResource_Disabled(t *testing.T) {
	t.Parallel()

	config := DefaultSemanticPluginConfig()
	config.Enabled = false // Disabled
	manager := NewSemanticPluginManager(config)
	defer manager.Close()

	plugin := &MockSemanticPlugin{
		name:        "test-plugin",
		version:     "1.0.0",
		indexedURIs: make(map[string]bool),
	}
	manager.RegisterPlugin("test", plugin)

	metadata := &ResourceMetadata{
		URI:      "https://example.com/resource1",
		IsPublic: true,
	}

	ctx := context.Background()
	err := manager.IndexResource(ctx, "https://example.com/resource1", []byte("test content"), metadata, nil)
	assert.Error(t, err)
	assert.Equal(t, "semantic search is disabled", err.Error())
}

func TestSemanticPluginManager_IndexResource_PrivacyBlocked(t *testing.T) {
	t.Parallel()

	config := DefaultSemanticPluginConfig()
	config.Enabled = true
	config.PrivacyPolicy = "strict"
	manager := NewSemanticPluginManager(config)
	defer manager.Close()

	plugin := &MockSemanticPlugin{
		name:        "test-plugin",
		version:     "1.0.0",
		indexedURIs: make(map[string]bool),
	}
	manager.RegisterPlugin("test", plugin)

	// Try to index a non-public resource with strict policy
	metadata := &ResourceMetadata{
		URI:      "https://example.com/private",
		IsPublic: false, // Not public
	}

	ctx := context.Background()
	err := manager.IndexResource(ctx, "https://example.com/private", []byte("private content"), metadata, nil)
	// Should not return error, just skip indexing
	assert.NoError(t, err)
	// Resource should not be indexed
	assert.False(t, plugin.indexedURIs["https://example.com/private"])
}

func TestSemanticPluginManager_IndexResource_PublicAllowed(t *testing.T) {
	t.Parallel()

	config := DefaultSemanticPluginConfig()
	config.Enabled = true
	config.PrivacyPolicy = "strict"
	manager := NewSemanticPluginManager(config)
	defer manager.Close()

	plugin := &MockSemanticPlugin{
		name:        "test-plugin",
		version:     "1.0.0",
		indexedURIs: make(map[string]bool),
	}
	manager.RegisterPlugin("test", plugin)

	// Index a public resource - should be allowed
	metadata := &ResourceMetadata{
		URI:      "https://example.com/public",
		IsPublic: true,
	}

	ctx := context.Background()
	err := manager.IndexResource(ctx, "https://example.com/public", []byte("public content"), metadata, nil)
	require.NoError(t, err)
	assert.True(t, plugin.indexedURIs["https://example.com/public"])
}

func TestSemanticPluginManager_RemoveResource(t *testing.T) {
	t.Parallel()

	config := DefaultSemanticPluginConfig()
	config.Enabled = true
	manager := NewSemanticPluginManager(config)
	defer manager.Close()

	plugin := &MockSemanticPlugin{
		name:        "test-plugin",
		version:     "1.0.0",
		indexedURIs: make(map[string]bool),
	}
	manager.RegisterPlugin("test", plugin)

	// Index a resource first
	metadata := &ResourceMetadata{
		URI:      "https://example.com/resource1",
		IsPublic: true,
	}
	ctx := context.Background()
	manager.IndexResource(ctx, "https://example.com/resource1", []byte("test"), metadata, nil)
	assert.True(t, plugin.indexedURIs["https://example.com/resource1"])

	// Remove the resource
	err := manager.RemoveResource(ctx, "https://example.com/resource1")
	require.NoError(t, err)
	assert.False(t, plugin.indexedURIs["https://example.com/resource1"])
}

func TestSemanticPluginManager_Search(t *testing.T) {
	t.Parallel()

	config := DefaultSemanticPluginConfig()
	config.Enabled = true
	manager := NewSemanticPluginManager(config)
	defer manager.Close()

	expectedResults := []SemanticSearchResult{
		{URI: "https://example.com/result1", Score: 0.95, Metadata: map[string]interface{}{"type": "resource"}},
		{URI: "https://example.com/result2", Score: 0.85, Metadata: map[string]interface{}{"type": "resource"}},
	}

	plugin := &MockSemanticPlugin{
		name:    "test-plugin",
		version: "1.0.0",
		searchFunc: func(query string, webID string, storageRoots []string, limit int) ([]SemanticSearchResult, error) {
			return expectedResults, nil
		},
		indexedURIs: make(map[string]bool),
	}
	manager.RegisterPlugin("test", plugin)

	ctx := context.Background()
	results, err := manager.Search(ctx, "test query", "https://example.org/user#me", nil, 10)
	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, "https://example.com/result1", results[0].URI)
	assert.Equal(t, float32(0.95), results[0].Score)
}

func TestSemanticPluginManager_Search_Disabled(t *testing.T) {
	t.Parallel()

	config := DefaultSemanticPluginConfig()
	config.Enabled = false
	manager := NewSemanticPluginManager(config)
	defer manager.Close()

	plugin := &MockSemanticPlugin{
		name:    "test-plugin",
		version: "1.0.0",
	}
	manager.RegisterPlugin("test", plugin)

	ctx := context.Background()
	_, err := manager.Search(ctx, "test query", "", nil, 10)
	assert.Error(t, err)
	assert.Equal(t, "semantic search is disabled", err.Error())
}

func TestSemanticPluginManager_PrivacyCheck(t *testing.T) {
	t.Parallel()

	config := DefaultSemanticPluginConfig()
	manager := NewSemanticPluginManager(config)
	defer manager.Close()

	// Plugin with passing privacy check
	plugin1 := &MockSemanticPlugin{
		name:        "plugin1",
		version:     "1.0.0",
		indexedURIs: make(map[string]bool),
	}
	manager.RegisterPlugin("p1", plugin1)

	// Plugin with failing privacy check - create a custom plugin type
	plugin2 := &FailingPrivacyPlugin{
		MockSemanticPlugin: MockSemanticPlugin{
			name:        "plugin2",
			version:     "1.0.0",
			indexedURIs: make(map[string]bool),
		},
	}
	manager.RegisterPlugin("p2", plugin2)

	// Privacy check should fail because of plugin2
	err := manager.PrivacyCheck()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "privacy violation detected")
}

func TestSemanticPluginManager_Close(t *testing.T) {
	t.Parallel()

	config := DefaultSemanticPluginConfig()
	manager := NewSemanticPluginManager(config)

	plugin := &MockSemanticPlugin{
		name:        "test-plugin",
		version:     "1.0.0",
		indexedURIs: make(map[string]bool),
	}
	manager.RegisterPlugin("test", plugin)

	err := manager.Close()
	require.NoError(t, err)

	assert.True(t, manager.IsClosed())
	assert.True(t, plugin.closed)
}

func TestSemanticPluginManager_RegisterAfterClose(t *testing.T) {
	t.Parallel()

	config := DefaultSemanticPluginConfig()
	manager := NewSemanticPluginManager(config)

	err := manager.Close()
	require.NoError(t, err)

	plugin := &MockSemanticPlugin{
		name:        "test-plugin",
		version:     "1.0.0",
		indexedURIs: make(map[string]bool),
	}

	// Should fail to register after close
	err = manager.RegisterPlugin("test", plugin)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestSemanticPluginManager_DoubleClose(t *testing.T) {
	t.Parallel()

	config := DefaultSemanticPluginConfig()
	manager := NewSemanticPluginManager(config)

	err := manager.Close()
	require.NoError(t, err)

	// Second close should be safe
	err = manager.Close()
	assert.NoError(t, err)
}

func TestDefaultSemanticPluginConfig(t *testing.T) {
	t.Parallel()

	config := DefaultSemanticPluginConfig()

	// Default should have semantic search disabled for privacy
	assert.False(t, config.Enabled)
	assert.Equal(t, "strict", config.PrivacyPolicy)
	assert.Equal(t, 5, config.MaxPlugins)
}

func TestSemanticPluginManager_NoActivePlugin(t *testing.T) {
	t.Parallel()

	config := DefaultSemanticPluginConfig()
	config.Enabled = true
	manager := NewSemanticPluginManager(config)
	defer manager.Close()

	// No plugins registered
	active := manager.GetActivePlugin()
	assert.Nil(t, active)

	ctx := context.Background()
	_, err := manager.Search(ctx, "query", "", nil, 10)
	assert.Error(t, err)
	assert.Equal(t, "no active semantic plugin", err.Error())
}

// Test helper to create a working semantic plugin manager
func createTestSemanticManager() *SemanticPluginManager {
	config := DefaultSemanticPluginConfig()
	config.Enabled = true
	manager := NewSemanticPluginManager(config)

	plugin := &MockSemanticPlugin{
		name:        "test-plugin",
		version:     "1.0.0",
		description: "Test semantic plugin",
		indexedURIs: make(map[string]bool),
		vectors:     make(map[string][]float32),
	}
	manager.RegisterPlugin("test", plugin)

	return manager
}
