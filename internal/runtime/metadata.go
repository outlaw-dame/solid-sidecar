package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// MetadataIndexLayer implements Layer 3: Metadata/index layer
// This layer provides efficient resource discovery and metadata indexing
// for the Solid runtime
//
// Key principles:
// - Efficient resource discovery without full scans
// - Metadata indexing for fast lookups
// - Privacy-safe indexing (no sensitive data in indexes)
// - Support for container hierarchies
// - Integration with storage abstraction layer
type MetadataIndexLayer struct {
	mu sync.RWMutex

	config MetadataIndexConfig

	// Index structures
	resourceIndex  map[string]*ResourceMetadataRecord // URI -> metadata
	containerIndex map[string]*ContainerIndexRecord   // Container URI -> children
	typeIndex      map[string]*TypeIndexRecord        // Content-Type -> URIs
	webIDIndex     map[string]*WebIDIndexRecord       // WebID -> resources

	// Storage layer reference (optional, for lazy loading)
	storage *StorageAbstractionLayer

	// Metrics
	metrics MetadataIndexMetrics

	// Logger
	logger *slog.Logger

	// Close state
	closeChan chan struct{}
	closed    bool
}

// MetadataIndexConfig holds configuration for the metadata/index layer
type MetadataIndexConfig struct {
	// MaxIndexSize is the maximum number of entries per index
	MaxIndexSize int

	// IndexUpdateInterval is how often to update indexes from storage
	IndexUpdateInterval time.Duration

	// EnableAutoIndex enables automatic index updates
	EnableAutoIndex bool

	// Logger is the logger for this layer
	Logger *slog.Logger
}

// DefaultMetadataIndexConfig returns a safe default configuration
func DefaultMetadataIndexConfig() MetadataIndexConfig {
	return MetadataIndexConfig{
		MaxIndexSize:        100000,
		IndexUpdateInterval: 5 * time.Minute,
		EnableAutoIndex:     true,
		Logger:              nil,
	}
}

// MetadataIndexMetrics holds metrics for the metadata/index layer
type MetadataIndexMetrics struct {
	mu sync.RWMutex

	// Index operations
	IndexUpdates      int64
	IndexUpdateErrors int64

	// Query operations
	GetByURIQueries      int64
	GetByTypeQueries     int64
	GetByWebIDQueries    int64
	ListContainerQueries int64

	// Index sizes
	ResourceIndexSize  int64
	ContainerIndexSize int64
	TypeIndexSize      int64
	WebIDIndexSize     int64

	// Last index update
	LastIndexUpdate time.Time
}

// RecordIndexUpdate records an index update
func (m *MetadataIndexMetrics) RecordIndexUpdate() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.IndexUpdates++
	m.LastIndexUpdate = time.Now()
}

// RecordIndexUpdateError records an index update error
func (m *MetadataIndexMetrics) RecordIndexUpdateError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.IndexUpdateErrors++
}

// RecordGetByURIQuery records a GetByURI query
func (m *MetadataIndexMetrics) RecordGetByURIQuery() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.GetByURIQueries++
}

// RecordGetByTypeQuery records a GetByType query
func (m *MetadataIndexMetrics) RecordGetByTypeQuery() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.GetByTypeQueries++
}

// RecordGetByWebIDQuery records a GetByWebID query
func (m *MetadataIndexMetrics) RecordGetByWebIDQuery() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.GetByWebIDQueries++
}

// RecordListContainerQuery records a ListContainer query
func (m *MetadataIndexMetrics) RecordListContainerQuery() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ListContainerQueries++
}

// ResourceMetadataRecord holds metadata for a resource in the index
type ResourceMetadataRecord struct {
	// URI is the resource identifier
	URI string

	// ContentType is the MIME type
	ContentType string

	// Size is the size in bytes
	Size int64

	// ETag is the entity tag
	ETag string

	// LastModified is when the resource was last modified
	LastModified time.Time

	// Created is when the resource was created
	Created time.Time

	// Container is the parent container
	Container string

	// WebIDs that have access to this resource (privacy-safe: hashed)
	AccessingWebIDs []string

	// Custom metadata
	Custom map[string]string
}

// ContainerIndexRecord holds metadata for a container in the index
type ContainerIndexRecord struct {
	// URI is the container identifier
	URI string

	// Children are the URIs of resources in this container
	Children []string

	// Size is the number of children
	Size int64

	// LastModified is when the container was last modified
	LastModified time.Time
}

// TypeIndexRecord holds metadata for a content type in the index
type TypeIndexRecord struct {
	// ContentType is the MIME type
	ContentType string

	// ResourceURIs are URIs of resources with this content type
	ResourceURIs []string

	// Count is the number of resources with this type
	Count int
}

// WebIDIndexRecord holds metadata for a WebID in the index
type WebIDIndexRecord struct {
	// WebID is the WebID identifier (hashed for privacy)
	WebID string

	// ResourceURIs are URIs of resources accessible by this WebID
	ResourceURIs []string

	// Count is the number of resources accessible by this WebID
	Count int
}

// NewMetadataIndexLayer creates a new metadata/index layer
func NewMetadataIndexLayer(config MetadataIndexConfig) *MetadataIndexLayer {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	layer := &MetadataIndexLayer{
		config:         config,
		resourceIndex:  make(map[string]*ResourceMetadataRecord),
		containerIndex: make(map[string]*ContainerIndexRecord),
		typeIndex:      make(map[string]*TypeIndexRecord),
		webIDIndex:     make(map[string]*WebIDIndexRecord),
		logger:         config.Logger,
		closeChan:      make(chan struct{}),
		closed:         false,
		metrics:        MetadataIndexMetrics{},
	}

	config.Logger.Info("Metadata/index layer initialized",
		"max_index_size", config.MaxIndexSize,
		"index_update_interval", config.IndexUpdateInterval,
		"enable_auto_index", config.EnableAutoIndex,
	)

	// Start auto-indexing if enabled
	if config.EnableAutoIndex && config.IndexUpdateInterval > 0 {
		go layer.startAutoIndexing()
	}

	return layer
}

// SetStorageLayer sets the storage layer reference for lazy loading
func (m *MetadataIndexLayer) SetStorageLayer(storage *StorageAbstractionLayer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.storage = storage
}

// startAutoIndexing starts the automatic index update process
func (m *MetadataIndexLayer) startAutoIndexing() {
	ticker := time.NewTicker(m.config.IndexUpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.UpdateIndexesFromStorage(context.Background()); err != nil {
				m.metrics.RecordIndexUpdateError()
				m.logger.Error("Auto index update failed", "error", err)
			} else {
				m.metrics.RecordIndexUpdate()
			}
		case <-m.closeChan:
			return
		}
	}
}

// UpdateIndexesFromStorage updates all indexes from the storage layer
func (m *MetadataIndexLayer) UpdateIndexesFromStorage(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("metadata index layer is closed")
	}

	if m.storage == nil {
		// No storage layer, skip
		return nil
	}

	// Clear existing indexes
	m.resourceIndex = make(map[string]*ResourceMetadataRecord)
	m.containerIndex = make(map[string]*ContainerIndexRecord)
	m.typeIndex = make(map[string]*TypeIndexRecord)
	m.webIDIndex = make(map[string]*WebIDIndexRecord)

	// Get all resources from storage
	// In a real implementation, we would use a more efficient method
	// For now, we'll use List with empty container to get all resources
	resources, err := m.storage.List(ctx, "")
	if err != nil {
		return fmt.Errorf("list resources from storage: %w", err)
	}

	// Rebuild indexes
	for _, resource := range resources {
		m.addToIndexes(resource)
	}

	m.logger.Info("Indexes updated from storage",
		"resource_count", len(m.resourceIndex),
		"container_count", len(m.containerIndex),
		"type_count", len(m.typeIndex),
	)

	return nil
}

// addToIndexes adds a resource to all indexes
func (m *MetadataIndexLayer) addToIndexes(resource *StorageResource) {
	// Check size limits
	if len(m.resourceIndex) >= m.config.MaxIndexSize {
		// Index is full, skip
		m.logger.Warn("Index size limit reached, skipping addition",
			"uri", resource.URI,
			"max_size", m.config.MaxIndexSize,
		)
		return
	}

	// Create resource metadata record
	record := &ResourceMetadataRecord{
		URI:          resource.URI,
		ContentType:  resource.ContentType,
		Size:         resource.Metadata.Size,
		ETag:         resource.ETag,
		LastModified: resource.LastModified,
		Created:      resource.Metadata.Created,
		Container:    extractContainerURI(resource.URI),
		Custom:       resource.Metadata.Custom,
	}

	// Add to resource index
	m.resourceIndex[resource.URI] = record

	// Add to container index
	container := record.Container
	if containerRecord, exists := m.containerIndex[container]; exists {
		containerRecord.Children = append(containerRecord.Children, resource.URI)
		containerRecord.Size = int64(len(containerRecord.Children))
		containerRecord.LastModified = maxTime(containerRecord.LastModified, record.LastModified)
	} else {
		m.containerIndex[container] = &ContainerIndexRecord{
			URI:          container,
			Children:     []string{resource.URI},
			Size:         1,
			LastModified: record.LastModified,
		}
	}

	// Add to type index
	typeRecord, exists := m.typeIndex[resource.ContentType]
	if exists {
		typeRecord.ResourceURIs = append(typeRecord.ResourceURIs, resource.URI)
		typeRecord.Count++
	} else {
		m.typeIndex[resource.ContentType] = &TypeIndexRecord{
			ContentType:  resource.ContentType,
			ResourceURIs: []string{resource.URI},
			Count:        1,
		}
	}
}

// extractContainerURI extracts the container URI from a resource URI
func extractContainerURI(resourceURI string) string {
	// Find the last / in the URI (before any trailing /)
	uri := resourceURI
	// Remove trailing /
	for len(uri) > 0 && uri[len(uri)-1] == '/' {
		uri = uri[:len(uri)-1]
	}

	// Find last /
	lastSlash := -1
	for i := len(uri) - 1; i >= 0; i-- {
		if uri[i] == '/' {
			lastSlash = i
			break
		}
	}

	if lastSlash < 0 {
		return ""
	}

	return uri[:lastSlash+1]
}

// maxTime returns the later of two times
func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// GetResourceMetadata retrieves metadata for a resource by URI
func (m *MetadataIndexLayer) GetResourceMetadata(uri string) (*ResourceMetadataRecord, error) {
	// Validate URI to prevent injection attacks and path traversal
	if err := ValidateURI(uri); err != nil {
		m.metrics.RecordGetByURIQuery()
		return nil, fmt.Errorf("invalid URI: %w", err)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, errors.New("metadata index layer is closed")
	}

	m.metrics.RecordGetByURIQuery()

	record, exists := m.resourceIndex[uri]
	if !exists {
		return nil, fmt.Errorf("resource %q not found in index", uri)
	}

	// Return a copy for thread safety
	return &ResourceMetadataRecord{
		URI:             record.URI,
		ContentType:     record.ContentType,
		Size:            record.Size,
		ETag:            record.ETag,
		LastModified:    record.LastModified,
		Created:         record.Created,
		Container:       record.Container,
		AccessingWebIDs: append([]string(nil), record.AccessingWebIDs...),
		Custom:          copyMap(record.Custom),
	}, nil
}

// GetResourcesByType retrieves URIs of resources with a specific content type
func (m *MetadataIndexLayer) GetResourcesByType(contentType string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, errors.New("metadata index layer is closed")
	}

	m.metrics.RecordGetByTypeQuery()

	record, exists := m.typeIndex[contentType]
	if !exists {
		return []string{}, nil
	}

	// Return a copy
	uris := make([]string, len(record.ResourceURIs))
	copy(uris, record.ResourceURIs)
	return uris, nil
}

// GetResourcesByWebID retrieves URIs of resources accessible by a WebID
// Note: WebIDs are hashed for privacy
func (m *MetadataIndexLayer) GetResourcesByWebID(webID string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, errors.New("metadata index layer is closed")
	}

	m.metrics.RecordGetByWebIDQuery()

	// Hash the WebID for privacy
	hashedWebID := hashWebID(webID)

	record, exists := m.webIDIndex[hashedWebID]
	if !exists {
		return []string{}, nil
	}

	// Return a copy
	uris := make([]string, len(record.ResourceURIs))
	copy(uris, record.ResourceURIs)
	return uris, nil
}

// ListContainer retrieves the children of a container
func (m *MetadataIndexLayer) ListContainer(containerURI string) ([]string, error) {
	// Validate container URI to prevent injection attacks and path traversal
	if err := ValidateContainerURI(containerURI); err != nil {
		return nil, fmt.Errorf("invalid container URI: %w", err)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, errors.New("metadata index layer is closed")
	}

	m.metrics.RecordListContainerQuery()

	record, exists := m.containerIndex[containerURI]
	if !exists {
		return []string{}, nil
	}

	// Return a copy
	uris := make([]string, len(record.Children))
	copy(uris, record.Children)
	return uris, nil
}

// GetContainerMetadata retrieves metadata for a container
func (m *MetadataIndexLayer) GetContainerMetadata(containerURI string) (*ContainerIndexRecord, error) {
	// Validate container URI to prevent injection attacks and path traversal
	if err := ValidateContainerURI(containerURI); err != nil {
		return nil, fmt.Errorf("invalid container URI: %w", err)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return nil, errors.New("metadata index layer is closed")
	}

	record, exists := m.containerIndex[containerURI]
	if !exists {
		return nil, fmt.Errorf("container %q not found in index", containerURI)
	}

	// Return a copy
	return &ContainerIndexRecord{
		URI:          record.URI,
		Children:     append([]string(nil), record.Children...),
		Size:         record.Size,
		LastModified: record.LastModified,
	}, nil
}

// AddResource adds a resource to the indexes
func (m *MetadataIndexLayer) AddResource(resource *StorageResource) error {
	// Validate resource URI to prevent injection attacks and path traversal
	if err := ValidateURI(resource.URI); err != nil {
		return fmt.Errorf("invalid resource URI: %w", err)
	}

	// Validate resource size to prevent DoS attacks
	if err := ValidateResourceSize(int64(len(resource.Body))); err != nil {
		return fmt.Errorf("resource validation failed: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("metadata index layer is closed")
	}

	m.addToIndexes(resource)
	return nil
}

// RemoveResource removes a resource from the indexes
func (m *MetadataIndexLayer) RemoveResource(uri string) error {
	// Validate URI to prevent injection attacks and path traversal
	if err := ValidateURI(uri); err != nil {
		return fmt.Errorf("invalid URI: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("metadata index layer is closed")
	}

	// Get resource info before removing from indexes
	var contentType string
	if resource, exists := m.resourceIndex[uri]; exists {
		contentType = resource.ContentType
	}

	// Remove from resource index
	delete(m.resourceIndex, uri)

	// Remove from container index
	container := extractContainerURI(uri)
	if record, exists := m.containerIndex[container]; exists {
		newChildren := make([]string, 0, len(record.Children))
		for _, childURI := range record.Children {
			if childURI != uri {
				newChildren = append(newChildren, childURI)
			}
		}
		record.Children = newChildren
		record.Size = int64(len(newChildren))
	}

	// Remove from type index
	if contentType != "" {
		if typeRecord, typeExists := m.typeIndex[contentType]; typeExists {
			newURIs := make([]string, 0, len(typeRecord.ResourceURIs))
			for _, typeURI := range typeRecord.ResourceURIs {
				if typeURI != uri {
					newURIs = append(newURIs, typeURI)
				}
			}
			typeRecord.ResourceURIs = newURIs
			typeRecord.Count = len(newURIs)
		}
	}

	return nil
}

// UpdateResource updates a resource in the indexes
func (m *MetadataIndexLayer) UpdateResource(resource *StorageResource) error {
	// Validate resource URI to prevent injection attacks and path traversal
	if err := ValidateURI(resource.URI); err != nil {
		return fmt.Errorf("invalid resource URI: %w", err)
	}

	// Validate resource size to prevent DoS attacks
	if err := ValidateResourceSize(int64(len(resource.Body))); err != nil {
		return fmt.Errorf("resource validation failed: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return errors.New("metadata index layer is closed")
	}

	// First remove the old version from indexes
	// Note: We can't call RemoveResource here as it would deadlock (tries to acquire lock)
	// Instead, we use the same removal logic as RemoveResource but without locking

	// Get old resource info before removing
	var oldContentType string
	if oldResource, exists := m.resourceIndex[resource.URI]; exists {
		oldContentType = oldResource.ContentType
	}

	// Remove from resource index
	delete(m.resourceIndex, resource.URI)

	// Remove from container index
	container := extractContainerURI(resource.URI)
	if containerRecord, exists := m.containerIndex[container]; exists {
		newChildren := make([]string, 0, len(containerRecord.Children))
		for _, childURI := range containerRecord.Children {
			if childURI != resource.URI {
				newChildren = append(newChildren, childURI)
			}
		}
		containerRecord.Children = newChildren
		containerRecord.Size = int64(len(newChildren))
	}

	// Remove from type index
	if oldContentType != "" {
		if typeRecord, typeExists := m.typeIndex[oldContentType]; typeExists {
			newURIs := make([]string, 0, len(typeRecord.ResourceURIs))
			for _, typeURI := range typeRecord.ResourceURIs {
				if typeURI != resource.URI {
					newURIs = append(newURIs, typeURI)
				}
			}
			typeRecord.ResourceURIs = newURIs
			typeRecord.Count = len(newURIs)
		}
	}

	// Remove from WebID index
	for _, webIDRecord := range m.webIDIndex {
		newURIs := make([]string, 0, len(webIDRecord.ResourceURIs))
		for _, u := range webIDRecord.ResourceURIs {
			if u != resource.URI {
				newURIs = append(newURIs, u)
			}
		}
		webIDRecord.ResourceURIs = newURIs
	}

	// Then add the new version
	m.addToIndexes(resource)
	return nil
}

// hashWebID hashes a WebID for privacy-safe indexing
func hashWebID(webID string) string {
	// Simple hash for demonstration
	// In production, use a proper cryptographic hash
	if webID == "" {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(webID))
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// copyMap creates a copy of a map
func copyMap(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// Close closes the metadata/index layer
func (m *MetadataIndexLayer) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true
	close(m.closeChan)

	// Clear indexes to free memory
	m.resourceIndex = nil
	m.containerIndex = nil
	m.typeIndex = nil
	m.webIDIndex = nil

	m.logger.Info("Metadata/index layer closed")
	return nil
}

// IsClosed returns true if the layer is closed
func (m *MetadataIndexLayer) IsClosed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.closed
}

// GetMetrics returns the current metrics
func (m *MetadataIndexLayer) GetMetrics() *MetadataIndexMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return &m.metrics
}

// Size returns the current size of the indexes
func (m *MetadataIndexLayer) Size() (int, int, int, int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.resourceIndex), len(m.containerIndex), len(m.typeIndex), len(m.webIDIndex)
}
