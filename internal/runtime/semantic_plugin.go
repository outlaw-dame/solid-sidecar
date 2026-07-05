// Package runtime provides the native Go/Rust Solid runtime path.
// This file implements the semantic/search plugin interface for Phase 23.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

// SemanticSearchPlugin defines the interface for semantic search plugins.
// Plugins must implement strict privacy gates and cannot ingest private resource bodies
// without explicit policy authorization.
type SemanticSearchPlugin interface {
	// Name returns the plugin name
	Name() string

	// Version returns the plugin version
	Version() string

	// Description returns a description of the plugin
	Description() string

	// Initialize initializes the plugin with configuration
	Initialize(config map[string]interface{}, logger *slog.Logger) error

	// IndexResource indexes a resource for semantic search
	// MUST respect privacy constraints - only index public/metadata content unless explicitly authorized
	IndexResource(ctx context.Context, uri string, content []byte, metadata *ResourceMetadata, accessInfo *ResourceAccessInfo) error

	// RemoveResource removes a resource from the semantic index
	RemoveResource(ctx context.Context, uri string) error

	// Search performs a semantic search
	// Results must be filtered based on the querying agent's access permissions
	Search(ctx context.Context, query string, webID string, storageRoots []string, limit int) ([]SemanticSearchResult, error)

	// GetResourceVectors returns semantic vectors for a resource
	// Used for similarity searches and nearest neighbor queries
	GetResourceVectors(ctx context.Context, uri string) ([]float32, error)

	// PrivacyCheck verifies that the plugin respects privacy constraints
	// Returns nil if privacy constraints are satisfied, error otherwise
	PrivacyCheck() error

	// Close cleans up plugin resources
	Close() error
}

// SemanticSearchResult represents a result from a semantic search
type SemanticSearchResult struct {
	// URI is the resource URI
	URI string

	// Score is the relevance/similarity score (0.0 to 1.0)
	Score float32

	// Metadata contains additional result metadata
	Metadata map[string]interface{}
}

// SemanticPluginConfig holds configuration for the semantic search plugin manager
type SemanticPluginConfig struct {
	// Enabled determines if semantic search is enabled
	Enabled bool

	// MaxPlugins is the maximum number of plugins that can be loaded
	MaxPlugins int

	// PluginTimeout is the timeout for plugin operations
	PluginTimeout int64

	// DefaultPlugin is the name of the default plugin to use
	DefaultPlugin string

	// PrivacyPolicy defines the privacy policy for semantic search
	// "strict" - no private content indexing without explicit policy
	// "moderate" - index metadata only, no bodies
	// "permissive" - allow indexing based on access control (not recommended)
	PrivacyPolicy string

	// Logger is the logger for the plugin manager
	Logger *slog.Logger
}

// DefaultSemanticPluginConfig returns a safe default configuration
// having semantic search disabled by default for privacy safety
func DefaultSemanticPluginConfig() SemanticPluginConfig {
	return SemanticPluginConfig{
		Enabled:       false, // Disabled by default for privacy
		MaxPlugins:    5,
		PluginTimeout: 5000, // 5 seconds
		DefaultPlugin: "",
		PrivacyPolicy: "strict",
		Logger:        nil,
	}
}

// SemanticPluginManager manages semantic search plugins
type SemanticPluginManager struct {
	mu sync.RWMutex

	config SemanticPluginConfig

	// Plugins is the map of registered plugins
	plugins map[string]SemanticSearchPlugin

	// activePlugin is the currently active plugin
	activePlugin SemanticSearchPlugin

	// Logger
	logger *slog.Logger

	// Close state
	closed bool
}

// NewSemanticPluginManager creates a new semantic plugin manager
func NewSemanticPluginManager(config SemanticPluginConfig) *SemanticPluginManager {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	return &SemanticPluginManager{
		config:  config,
		plugins: make(map[string]SemanticSearchPlugin),
		logger:  config.Logger,
		closed:  false,
	}
}

// RegisterPlugin registers a semantic search plugin
func (m *SemanticPluginManager) RegisterPlugin(name string, plugin SemanticSearchPlugin) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("semantic plugin manager is closed")
	}

	if len(m.plugins) >= m.config.MaxPlugins {
		return fmt.Errorf("maximum number of plugins (%d) reached", m.config.MaxPlugins)
	}

	m.plugins[name] = plugin
	m.logger.Info("Registered semantic search plugin", "name", name, "version", plugin.Version())

	// If this is the first plugin and no active plugin is set, make it active
	if m.activePlugin == nil && m.config.DefaultPlugin == "" {
		m.activePlugin = plugin
		m.logger.Info("Set as active plugin", "name", name)
	}

	return nil
}

// SetActivePlugin sets the active plugin by name
func (m *SemanticPluginManager) SetActivePlugin(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("semantic plugin manager is closed")
	}

	plugin, exists := m.plugins[name]
	if !exists {
		return fmt.Errorf("plugin %s not found", name)
	}

	m.activePlugin = plugin
	m.logger.Info("Set active semantic plugin", "name", name)
	return nil
}

// GetActivePlugin returns the currently active plugin
func (m *SemanticPluginManager) GetActivePlugin() SemanticSearchPlugin {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.activePlugin
}

// IndexResource indexes a resource using the active plugin
func (m *SemanticPluginManager) IndexResource(ctx context.Context, uri string, content []byte, metadata *ResourceMetadata, accessInfo *ResourceAccessInfo) error {
	m.mu.RLock()
	plugin := m.activePlugin
	m.mu.RUnlock()

	if plugin == nil {
		return errors.New("no active semantic plugin")
	}

	if !m.config.Enabled {
		return errors.New("semantic search is disabled")
	}

	// Check privacy policy before indexing
	if err := m.checkPrivacyPolicy(uri, metadata, accessInfo); err != nil {
		m.logger.Warn("Semantic indexing blocked by privacy policy", "uri", uri, "error", err)
		return nil // Don't return error, just skip indexing for privacy
	}

	return plugin.IndexResource(ctx, uri, content, metadata, accessInfo)
}

// RemoveResource removes a resource from the semantic index
func (m *SemanticPluginManager) RemoveResource(ctx context.Context, uri string) error {
	m.mu.RLock()
	plugin := m.activePlugin
	m.mu.RUnlock()

	if plugin == nil {
		return errors.New("no active semantic plugin")
	}

	if !m.config.Enabled {
		return nil // If disabled, just return success
	}

	return plugin.RemoveResource(ctx, uri)
}

// Search performs a semantic search using the active plugin
func (m *SemanticPluginManager) Search(ctx context.Context, query string, webID string, storageRoots []string, limit int) ([]SemanticSearchResult, error) {
	m.mu.RLock()
	plugin := m.activePlugin
	m.mu.RUnlock()

	if plugin == nil {
		return nil, errors.New("no active semantic plugin")
	}

	if !m.config.Enabled {
		return nil, errors.New("semantic search is disabled")
	}

	return plugin.Search(ctx, query, webID, storageRoots, limit)
}

// GetResourceVectors returns semantic vectors for a resource
func (m *SemanticPluginManager) GetResourceVectors(ctx context.Context, uri string) ([]float32, error) {
	m.mu.RLock()
	plugin := m.activePlugin
	m.mu.RUnlock()

	if plugin == nil {
		return nil, errors.New("no active semantic plugin")
	}

	if !m.config.Enabled {
		return nil, errors.New("semantic search is disabled")
	}

	return plugin.GetResourceVectors(ctx, uri)
}

// PrivacyCheck verifies all plugins respect privacy constraints
func (m *SemanticPluginManager) PrivacyCheck() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for name, plugin := range m.plugins {
		if err := plugin.PrivacyCheck(); err != nil {
			m.logger.Error("Privacy check failed for plugin", "name", name, "error", err)
			return fmt.Errorf("plugin %s failed privacy check: %w", name, err)
		}
	}

	return nil
}

// checkPrivacyPolicy checks if indexing is allowed based on the privacy policy
func (m *SemanticPluginManager) checkPrivacyPolicy(uri string, metadata *ResourceMetadata, accessInfo *ResourceAccessInfo) error {
	switch m.config.PrivacyPolicy {
	case "strict":
		// Only allow indexing if resource is explicitly public or metadata-only
		if metadata != nil && !metadata.IsPublic {
			// Check if this is a metadata-only resource (no body content)
			// In strict mode, we don't index non-public resources
			return fmt.Errorf("strict privacy policy: cannot index non-public resource %s", uri)
		}
	case "moderate":
		// Only index metadata, not body content
		// This is handled by the caller not passing content
		return nil
	case "permissive":
		// Allow based on access control
		if accessInfo != nil && !accessInfo.PublicAccess {
			return fmt.Errorf("permissive privacy policy: no public access for resource %s", uri)
		}
	default:
		// Unknown policy, default to strict
		if metadata != nil && !metadata.IsPublic {
			return fmt.Errorf("unknown privacy policy: cannot index non-public resource %s", uri)
		}
	}

	return nil
}

// Close closes the plugin manager and all plugins
func (m *SemanticPluginManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true

	// Close all plugins
	for name, plugin := range m.plugins {
		if err := plugin.Close(); err != nil {
			m.logger.Error("Error closing plugin", "name", name, "error", err)
			// Continue closing other plugins
		}
	}

	m.plugins = nil
	m.activePlugin = nil

	m.logger.Info("Semantic plugin manager closed")
	return nil
}

// IsClosed returns true if the manager is closed
func (m *SemanticPluginManager) IsClosed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.closed
}

// ErrSemanticSearchDisabled is returned when semantic search is disabled
var ErrSemanticSearchDisabled = errors.New("semantic search is disabled")

// ErrNoSemanticPlugin is returned when no semantic plugin is active
var ErrNoSemanticPlugin = errors.New("no semantic search plugin active")
