// Package runtime provides the native Go/Rust Solid runtime path.
// This file implements Layer 6.6: Indexing layer for Solid resources.
package runtime

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Hardening constants for Phase 16 resource indexing
const (
	// DefaultMaxResourceSize is the maximum size for indexed resources (10MB)
	DefaultMaxResourceSize = 10 * 1024 * 1024

	// DefaultMaxOwnerWebIDs is the maximum number of owners per resource
	DefaultMaxOwnerWebIDs = 10

	// DefaultMaxContributors is the maximum number of contributors per resource
	DefaultMaxContributors = 50

	// DefaultMaxAllowedAgents is the maximum number of allowed agents in access info
	DefaultMaxAllowedAgents = 100

	// DefaultMaxAllowedGroups is the maximum number of allowed groups in access info
	DefaultMaxAllowedGroups = 20
)

// ResourceIndexError represents errors specific to the resource indexing layer
var (
	ErrIndexClosed                 = errors.New("resource index layer is closed")
	ErrResourceTooLargeForIndexing = errors.New("resource too large to index")
	ErrIndexLimitReached           = errors.New("index limit reached")
	ErrInvalidResourceMetadata     = errors.New("invalid resource metadata")
	ErrAccessInfoInvalid           = errors.New("invalid access control information")
	ErrIndexingRateLimitExceeded   = errors.New("indexing rate limit exceeded")
	ErrIndexCircuitBreakerOpen     = errors.New("index circuit breaker is open")
)

// ResourceIndexHardeningConfig holds hardening configuration for the resource index layer
type ResourceIndexHardeningConfig struct {
	// MaxResourceSize is the maximum size of resources to index (in bytes)
	MaxResourceSize int64

	// MaxOwners is the maximum number of owners per resource
	MaxOwners int

	// MaxContributors is the maximum number of contributors per resource
	MaxContributors int

	// MaxAllowedAgents is the maximum number of allowed agents in access info
	MaxAllowedAgents int

	// MaxAllowedGroups is the maximum number of allowed groups in access info
	MaxAllowedGroups int

	// IndexRateLimit is the maximum indexing operations per second
	IndexRateLimit float64

	// IndexBurstLimit is the burst limit for indexing operations
	IndexBurstLimit int

	// CircuitBreakerFailureThreshold is the failure threshold for the circuit breaker
	CircuitBreakerFailureThreshold int

	// CircuitBreakerResetTimeout is the reset timeout for the circuit breaker
	CircuitBreakerResetTimeout time.Duration
}

// DefaultResourceIndexHardeningConfig returns safe defaults for resource indexing hardening
func DefaultResourceIndexHardeningConfig() ResourceIndexHardeningConfig {
	return ResourceIndexHardeningConfig{
		MaxResourceSize:                DefaultMaxResourceSize,
		MaxOwners:                      DefaultMaxOwnerWebIDs,
		MaxContributors:                DefaultMaxContributors,
		MaxAllowedAgents:               DefaultMaxAllowedAgents,
		MaxAllowedGroups:               DefaultMaxAllowedGroups,
		IndexRateLimit:                 100.0, // 100 indexing operations per second
		IndexBurstLimit:                200,   // Allow bursts up to 200 operations
		CircuitBreakerFailureThreshold: 5,
		CircuitBreakerResetTimeout:     30 * time.Second,
	}
}

// ResourceIndexLayer implements Layer 6.6: Resource indexing layer
// This layer provides indexing capabilities for Solid resources
// with privacy-aware filtering and WebID-scoped access.
//
// Key principles:
// - No private resource body indexing unless explicitly allowed
// - WebID-scoped index access
// - Policy-aware index filtering
// - Efficient indexing for performance
// - Memory-safe with bounded index sizes
type ResourceIndexLayer struct {
	mu sync.RWMutex

	config ResourceIndexConfig

	// Hardening configuration
	hardeningConfig ResourceIndexHardeningConfig

	// Resource index (URI -> ResourceMetadata)
	resourceIndex map[string]*ResourceMetadata

	// Container index (container URI -> []resource URIs)
	containerIndex map[string][]string

	// Agent index (WebID -> []resource URIs they have access to)
	agentIndex map[string][]string

	// Type index (resource type -> []resource URIs)
	typeIndex map[string][]string

	// Full-text index (term -> []resource URIs) - only for public/metadata content
	fullTextIndex map[string][]string

	// Access control index (resource URI -> access info)
	accessIndex map[string]*ResourceAccessInfo

	// Storage root index (storage root URI -> []resource URIs)
	storageRootIndex map[string][]string

	// Auxiliary resource index (main resource URI -> []auxiliary resource URIs)
	auxiliaryIndex map[string][]string

	// RDF term index (RDF term -> []resource URIs) - optional
	rdfTermIndex map[string][]string

	// Index statistics and observability
	indexMetrics ResourceIndexMetrics

	// Rate limiter for indexing operations
	indexRateLimiter *RateLimiter

	// Circuit breaker for indexing operations
	indexCircuitBreaker *CircuitBreaker

	// Global operation counter for metrics
	globalOperationCount int64

	// Logger
	logger *slog.Logger

	// Close state
	closeChan chan struct{}
	closed    bool
}

// ResourceIndexConfig holds configuration for the resource indexing layer
type ResourceIndexConfig struct {
	// MaxIndexSize is the maximum number of resources to index
	MaxIndexSize int

	// EnableFullTextIndex enables full-text indexing (only for public content)
	EnableFullTextIndex bool

	// MaxFullTextTerms is the maximum number of terms to index per resource
	MaxFullTextTerms int

	// EnableAgentIndex enables agent-based indexing
	EnableAgentIndex bool

	// EnableStorageRootIndex enables storage root-based indexing
	EnableStorageRootIndex bool

	// EnableAuxiliaryIndex enables auxiliary resource indexing (optional)
	EnableAuxiliaryIndex bool

	// EnableRDFTermIndex enables RDF term indexing (optional)
	EnableRDFTermIndex bool

	// MaxRDFTermsPerResource is the maximum number of RDF terms to index per resource
	MaxRDFTermsPerResource int

	// IndexRetentionTime is how long indexed entries are retained
	IndexRetentionTime time.Duration

	// EnableObservability enables observability metrics
	EnableObservability bool

	// EnableBackgroundReindex enables background reindexing
	EnableBackgroundReindex bool

	// ReindexInterval is how often to run background reindex
	ReindexInterval time.Duration

	// ReindexBatchSize is the number of resources to reindex in each batch
	ReindexBatchSize int

	// HardeningConfig contains security and reliability settings
	HardeningConfig ResourceIndexHardeningConfig

	// Logger is the logger for this layer
	Logger *slog.Logger
}

// DefaultResourceIndexConfig returns a safe default configuration
func DefaultResourceIndexConfig() ResourceIndexConfig {
	return ResourceIndexConfig{
		MaxIndexSize:             100000, // 100K resources max
		EnableFullTextIndex:      true,
		MaxFullTextTerms:         100,    // 100 terms per resource max
		EnableAgentIndex:         true,
		EnableStorageRootIndex:   true,
		EnableAuxiliaryIndex:     true,
		EnableRDFTermIndex:       false,   // Disabled by default
		MaxRDFTermsPerResource:   50,      // 50 RDF terms per resource max
		IndexRetentionTime:       0,       // Disabled by default to avoid background goroutines
		EnableObservability:      true,
		EnableBackgroundReindex: false,    // Disabled by default
		ReindexInterval:          24 * time.Hour,
		ReindexBatchSize:         1000,
		HardeningConfig:          DefaultResourceIndexHardeningConfig(),
		Logger:                   nil,
	}
}

// ResourceIndexMetrics holds metrics for the resource indexing layer
type ResourceIndexMetrics struct {
	mu sync.RWMutex

	// Index statistics
	TotalResourcesIndexed int64
	TotalIndexOperations  int64
	IndexHits             int64
	IndexMisses           int64

	// Search statistics
	TotalSearches      int64
	SuccessfulSearches int64
	SearchErrors       int64

	// Memory statistics
	EstimatedMemoryUsage int64

	// Last index update time
	LastIndexUpdate time.Time
}

// RecordIndexOperation records an index operation
func (m *ResourceIndexMetrics) RecordIndexOperation() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TotalIndexOperations++
	m.LastIndexUpdate = time.Now()
}

// RecordResourceIndexed records a resource being indexed
func (m *ResourceIndexMetrics) RecordResourceIndexed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TotalResourcesIndexed++
	m.RecordIndexOperation()
}

// RecordIndexHit records an index hit
func (m *ResourceIndexMetrics) RecordIndexHit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.IndexHits++
	m.RecordIndexOperation()
}

// RecordIndexMiss records an index miss
func (m *ResourceIndexMetrics) RecordIndexMiss() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.IndexMisses++
	m.RecordIndexOperation()
}

// RecordSearch records a search operation
func (m *ResourceIndexMetrics) RecordSearch(success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TotalSearches++
	if success {
		m.SuccessfulSearches++
	} else {
		m.SearchErrors++
	}
}

// ResourceMetadata holds metadata about an indexed resource
type ResourceMetadata struct {
	// URI is the resource URI
	URI string

	// ContainerURI is the URI of the container
	ContainerURI string

	// ResourceType is the type of resource (from metadata)
	ResourceType string

	// ContentType is the content type
	ContentType string

	// Size is the size in bytes
	Size int64

	// LastModified is when the resource was last modified
	LastModified time.Time

	// Created is when the resource was created
	Created time.Time

	// OwnerWebID is the WebID of the resource owner
	OwnerWebID string

	// Contributors are WebIDs of contributors
	Contributors []string

	// AccessControlURI is the URI of the access control document
	AccessControlURI string

	// IsPublic indicates if the resource is publicly accessible
	IsPublic bool

	// PrivacyLevel indicates the privacy sensitivity
	PrivacyLevel PrivacyLevel

	// IndexedAt is when this resource was indexed
	IndexedAt time.Time

	// LastIndexed is when this resource was last indexed
	LastIndexed time.Time

	// StorageRoot is the storage root URI for this resource
	StorageRoot string

	// RDFTerms contains RDF terms extracted from the resource (optional)
	// Only populated if RDF term indexing is enabled
	RDFTerms map[string]bool

	// FullTextTerms contains full-text search terms (optional)
	// Only populated if full-text indexing is enabled
	FullTextTerms []string

	// AuxiliaryLinks contains links to auxiliary resources (optional)
	// Only populated if auxiliary indexing is enabled
	AuxiliaryLinks map[string]string
}

// ResourceAccessInfo holds access control information for a resource
type ResourceAccessInfo struct {
	// ResourceURI is the URI of the resource
	ResourceURI string

	// AllowedAgents are WebIDs of agents with read access
	AllowedAgents []string

	// AllowedGroups are URIs of groups with read access
	AllowedGroups []string

	// PublicAccess indicates if public read access is allowed
	PublicAccess bool

	// OwnerWebID is the owner of the resource
	OwnerWebID string

	// LastUpdated is when access info was last updated
	LastUpdated time.Time
}

// IndexedResource represents a resource in the index
type IndexedResource struct {
	URI          string
	ContainerURI string
	ResourceType string
	ContentType  string
	Size         int64
	LastModified time.Time
	OwnerWebID   string
	PrivacyLevel PrivacyLevel
	StorageRoot  string
	AccessInfo   *ResourceAccessInfo
}

// IndexQuery represents a query to the index
type IndexQuery struct {
	// ResourceURIs are specific URIs to search for
	ResourceURIs []string

	// ContainerURIs are specific containers to search in
	ContainerURIs []string

	// ResourceTypes are specific resource types to search for
	ResourceTypes []string

	// ContentTypes are specific content types to search for
	ContentTypes []string

	// OwnerWebIDs are specific owners to search for
	OwnerWebIDs []string

	// ContributorWebIDs are specific contributors to search for
	ContributorWebIDs []string

	// SearchTerms are terms to search for in full-text index
	SearchTerms []string

	// MinSize is the minimum size to include
	MinSize int64

	// MaxSize is the maximum size to include
	MaxSize int64

	// MinPrivacyLevel is the minimum privacy level to include
	MinPrivacyLevel PrivacyLevel

	// MaxPrivacyLevel is the maximum privacy level to include
	MaxPrivacyLevel PrivacyLevel

	// WebID is the WebID of the querying agent (for access control)
	WebID string

	// IncludePrivate indicates if private resources should be included
	IncludePrivate bool

	// Limit is the maximum number of results to return
	Limit int

	// Offset is the offset for pagination
	Offset int

	// SortBy specifies the sort field
	SortBy string

	// SortOrder specifies the sort order (asc, desc)
	SortOrder string

	// StorageRoots are the storage roots to scope the query to
	// If empty, query is not scoped to specific storage roots
	StorageRoots []string
}

// IndexResult represents the result of an index query
type IndexResult struct {
	// Results are the matching resources
	Results []IndexedResource

	// TotalCount is the total number of matching resources
	TotalCount int

	// QueryTime is how long the query took
	QueryTime time.Duration

	// HasMore indicates if there are more results available
	HasMore bool
}

// NewResourceIndexLayer creates a new resource indexing layer
func NewResourceIndexLayer(config ResourceIndexConfig) *ResourceIndexLayer {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	layer := &ResourceIndexLayer{
		config:          config,
		hardeningConfig: config.HardeningConfig,
		resourceIndex:   make(map[string]*ResourceMetadata),
		containerIndex:  make(map[string][]string),
		agentIndex:      make(map[string][]string),
		typeIndex:       make(map[string][]string),
		accessIndex:     make(map[string]*ResourceAccessInfo),
		logger:          config.Logger,
		closeChan:       make(chan struct{}),
		closed:          false,
		indexMetrics:    ResourceIndexMetrics{},
	}

	// Initialize full-text index if enabled
	if config.EnableFullTextIndex {
		layer.fullTextIndex = make(map[string][]string)
	}

	// Initialize storage root index if enabled
	if config.EnableStorageRootIndex {
		layer.storageRootIndex = make(map[string][]string)
	}

	// Initialize auxiliary index if enabled
	if config.EnableAuxiliaryIndex {
		layer.auxiliaryIndex = make(map[string][]string)
	}

	// Initialize RDF term index if enabled
	if config.EnableRDFTermIndex {
		layer.rdfTermIndex = make(map[string][]string)
	}

	// Initialize rate limiter if configured
	if config.HardeningConfig.IndexRateLimit > 0 {
		layer.indexRateLimiter = NewRateLimiter(
			config.HardeningConfig.IndexRateLimit,
			config.HardeningConfig.IndexBurstLimit,
		)
	}

	// Initialize circuit breaker if configured
	if config.HardeningConfig.CircuitBreakerFailureThreshold > 0 {
		layer.indexCircuitBreaker = NewCircuitBreaker(
			config.HardeningConfig.CircuitBreakerFailureThreshold,
			config.HardeningConfig.CircuitBreakerResetTimeout,
		)
	}

	// Set up index cleanup if retention is configured
	if config.IndexRetentionTime > 0 {
		go layer.indexCleanup(config.IndexRetentionTime)
	}

	config.Logger.Info("Resource index layer initialized",
		"max_index_size", config.MaxIndexSize,
		"enable_full_text_index", config.EnableFullTextIndex,
		"max_full_text_terms", config.MaxFullTextTerms,
		"enable_agent_index", config.EnableAgentIndex,
		"enable_storage_root_index", config.EnableStorageRootIndex,
		"enable_rdf_term_index", config.EnableRDFTermIndex,
		"max_rdf_terms_per_resource", config.MaxRDFTermsPerResource,
		"index_retention_time", config.IndexRetentionTime,
		"enable_background_reindex", config.EnableBackgroundReindex,
		"reindex_interval", config.ReindexInterval,
		"reindex_batch_size", config.ReindexBatchSize,
		"max_resource_size", config.HardeningConfig.MaxResourceSize,
		"index_rate_limit", config.HardeningConfig.IndexRateLimit,
		"index_burst_limit", config.HardeningConfig.IndexBurstLimit,
		"circuit_breaker_enabled", config.HardeningConfig.CircuitBreakerFailureThreshold > 0,
	)

	// Set up background reindex if enabled
	if config.EnableBackgroundReindex && config.ReindexInterval > 0 {
		go layer.backgroundReindexRoutine()
	}

	return layer
}

// indexCleanup periodically cleans up old index entries
func (i *ResourceIndexLayer) indexCleanup(retentionTime time.Duration) {
	ticker := time.NewTicker(1 * time.Hour) // Clean up every hour
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			i.cleanOldIndexEntries(retentionTime)
		case <-i.closeChan:
			i.logger.Info("Resource index cleanup stopped")
			return
		}
	}
}

// cleanOldIndexEntries removes index entries older than the retention time
func (i *ResourceIndexLayer) cleanOldIndexEntries(retentionTime time.Duration) {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.closed {
		return
	}

	cutoff := time.Now().Add(-retentionTime)

	// Clean up resource index
	for uri, metadata := range i.resourceIndex {
		if metadata.LastIndexed.Before(cutoff) {
			delete(i.resourceIndex, uri)
			// Also remove from other indexes
			i.removeFromOtherIndexes(uri, metadata)
		}
	}

	i.logger.Debug("Cleaned up old index entries")
}

// removeFromOtherIndexes removes a resource from all indexes except the main resource index
func (i *ResourceIndexLayer) removeFromOtherIndexes(uri string, metadata *ResourceMetadata) {
	// Remove from container index
	if containerURI := metadata.ContainerURI; containerURI != "" {
		if uris, exists := i.containerIndex[containerURI]; exists {
			newUris := make([]string, 0, len(uris))
			for _, u := range uris {
				if u != uri {
					newUris = append(newUris, u)
				}
			}
			if len(newUris) == 0 {
				delete(i.containerIndex, containerURI)
			} else {
				i.containerIndex[containerURI] = newUris
			}
		}
	}

	// Remove from agent index
	if i.config.EnableAgentIndex {
		if owner := metadata.OwnerWebID; owner != "" {
			if uris, exists := i.agentIndex[owner]; exists {
				newUris := make([]string, 0, len(uris))
				for _, u := range uris {
					if u != uri {
						newUris = append(newUris, u)
					}
				}
				if len(newUris) == 0 {
					delete(i.agentIndex, owner)
				} else {
					i.agentIndex[owner] = newUris
				}
			}
		}

		// Remove from contributor indexes
		for _, contributor := range metadata.Contributors {
			if uris, exists := i.agentIndex[contributor]; exists {
				newUris := make([]string, 0, len(uris))
				for _, u := range uris {
					if u != uri {
						newUris = append(newUris, u)
					}
				}
				if len(newUris) == 0 {
					delete(i.agentIndex, contributor)
				} else {
					i.agentIndex[contributor] = newUris
				}
			}
		}
	}

	// Remove from type index
	if resourceType := metadata.ResourceType; resourceType != "" {
		if uris, exists := i.typeIndex[resourceType]; exists {
			newUris := make([]string, 0, len(uris))
			for _, u := range uris {
				if u != uri {
					newUris = append(newUris, u)
				}
			}
			if len(newUris) == 0 {
				delete(i.typeIndex, resourceType)
			} else {
				i.typeIndex[resourceType] = newUris
			}
		}
	}

	// Remove from access index
	delete(i.accessIndex, uri)

	// Remove from storage root index if enabled
	if i.storageRootIndex != nil {
		if storageRoot := metadata.StorageRoot; storageRoot != "" {
			if uris, exists := i.storageRootIndex[storageRoot]; exists {
				newUris := make([]string, 0, len(uris))
				for _, u := range uris {
					if u != uri {
						newUris = append(newUris, u)
					}
				}
				if len(newUris) == 0 {
					delete(i.storageRootIndex, storageRoot)
				} else {
					i.storageRootIndex[storageRoot] = newUris
				}
			}
		}
	}

	// Remove from auxiliary index if enabled
	if i.auxiliaryIndex != nil && metadata.AuxiliaryLinks != nil {
		if _, exists := i.auxiliaryIndex[uri]; exists {
			delete(i.auxiliaryIndex, uri)
		}
	}

	// Remove from RDF term index if enabled
	if i.rdfTermIndex != nil && metadata.RDFTerms != nil {
		for term := range metadata.RDFTerms {
			if uris, exists := i.rdfTermIndex[term]; exists {
				newUris := make([]string, 0, len(uris))
				for _, u := range uris {
					if u != uri {
						newUris = append(newUris, u)
					}
				}
				if len(newUris) == 0 {
					delete(i.rdfTermIndex, term)
				} else {
					i.rdfTermIndex[term] = newUris
				}
			}
		}
	}
}

// backgroundReindexRoutine periodically reindexes resources in batches
func (i *ResourceIndexLayer) backgroundReindexRoutine() {
	ticker := time.NewTicker(i.config.ReindexInterval)
	defer ticker.Stop()

	for {
		select {
		case <-i.closeChan:
			return
		case <-ticker.C:
			if err := i.performBackgroundReindex(); err != nil {
				i.logger.Error("Background reindex failed", "error", err)
			}
		}
	}
}

// performBackgroundReindex performs a single batch of reindexing
func (i *ResourceIndexLayer) performBackgroundReindex() error {
	i.mu.RLock()
	batchSize := i.config.ReindexBatchSize
	if batchSize <= 0 {
		batchSize = 1000
	}
	i.mu.RUnlock()

	// Get all resource URIs
	i.mu.RLock()
	allURIs := make([]string, 0, len(i.resourceIndex))
	for uri := range i.resourceIndex {
		allURIs = append(allURIs, uri)
	}
	i.mu.RUnlock()

	if len(allURIs) == 0 {
		return nil
	}

	// Process in batches
	for offset := 0; offset < len(allURIs); offset += batchSize {
		end := offset + batchSize
		if end > len(allURIs) {
			end = len(allURIs)
		}
		batch := allURIs[offset:end]

		for _, uri := range batch {
			// Re-index this resource
			metadata, exists := i.resourceIndex[uri]
			if !exists {
				continue
			}

			accessInfo, accessExists := i.accessIndex[uri]
			if !accessExists {
				continue
			}

			// Remove old entries
			if err := i.RemoveResource(uri); err != nil {
				i.logger.Warn("Failed to remove resource during reindex", "uri", uri, "error", err)
				continue
			}

			// Re-add with updated metadata
			if err := i.IndexResource(metadata, accessInfo); err != nil {
				i.logger.Warn("Failed to reindex resource", "uri", uri, "error", err)
				// Try to restore the old entry
				i.resourceIndex[uri] = metadata
				i.accessIndex[uri] = accessInfo
				continue
			}

			// Checkpoint: log progress
			if (offset+end) % 100 == 0 {
				i.logger.Debug("Background reindex progress", "processed", offset+end, "total", len(allURIs))
			}
		}
	}

	i.logger.Info("Background reindex completed", "total_resources", len(allURIs))
	return nil
}

// IndexConsistencyReport represents the result of an index consistency check
type IndexConsistencyReport struct {
	// CheckedAt is when the consistency check was performed
	CheckedAt time.Time

	// ResourceCount is the number of resources in the main index
	ResourceCount int

	// ContainerCount is the number of containers in the container index
	ContainerCount int

	// Consistent indicates if all indexes are consistent
	Consistent bool

	// ErrorCount is the number of consistency errors found
	ErrorCount int

	// Errors contains descriptions of all consistency errors
	Errors []string
}

// VerifyIndexConsistency checks the consistency of all indexes
func (i *ResourceIndexLayer) VerifyIndexConsistency() IndexConsistencyReport {
	i.mu.RLock()
	defer i.mu.RUnlock()

	report := IndexConsistencyReport{
		CheckedAt:      time.Now(),
		ResourceCount:  len(i.resourceIndex),
		ContainerCount: len(i.containerIndex),
	}

	// Check container index consistency
	for containerURI, uris := range i.containerIndex {
		for _, uri := range uris {
			if _, exists := i.resourceIndex[uri]; !exists {
				report.Errors = append(report.Errors, fmt.Sprintf("Container index references non-existent resource: %s -> %s", containerURI, uri))
				report.ErrorCount++
			}
		}
	}

	// Check type index consistency
	for resourceType, uris := range i.typeIndex {
		for _, uri := range uris {
			if _, exists := i.resourceIndex[uri]; !exists {
				report.Errors = append(report.Errors, fmt.Sprintf("Type index references non-existent resource: %s -> %s", resourceType, uri))
				report.ErrorCount++
			}
		}
	}

	// Check agent index consistency
	if i.agentIndex != nil {
		for agent, uris := range i.agentIndex {
			for _, uri := range uris {
				if _, exists := i.resourceIndex[uri]; !exists {
					report.Errors = append(report.Errors, fmt.Sprintf("Agent index references non-existent resource: %s -> %s", agent, uri))
					report.ErrorCount++
				}
			}
		}
	}

	// Check storage root index consistency
	if i.storageRootIndex != nil {
		for storageRoot, uris := range i.storageRootIndex {
			for _, uri := range uris {
				if _, exists := i.resourceIndex[uri]; !exists {
					report.Errors = append(report.Errors, fmt.Sprintf("Storage root index references non-existent resource: %s -> %s", storageRoot, uri))
					report.ErrorCount++
				}
			}
		}
	}

	// Check access index consistency
	for uri := range i.accessIndex {
		if _, exists := i.resourceIndex[uri]; !exists {
			report.Errors = append(report.Errors, fmt.Sprintf("Access index references non-existent resource: %s", uri))
			report.ErrorCount++
		}
	}

	report.Consistent = report.ErrorCount == 0
	return report
}

// InvalidateIndexesForResource invalidates all index entries for a specific resource
// This is called when a resource is updated or deleted to ensure consistency
func (i *ResourceIndexLayer) InvalidateIndexesForResource(uri string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	// Remove from resource index
	delete(i.resourceIndex, uri)

	// Remove from container index
	for containerURI, uris := range i.containerIndex {
		newUris := make([]string, 0, len(uris))
		for _, u := range uris {
			if u != uri {
				newUris = append(newUris, u)
			}
		}
		if len(newUris) == 0 {
			delete(i.containerIndex, containerURI)
		} else {
			i.containerIndex[containerURI] = newUris
		}
	}

	// Remove from type index
	for resourceType, uris := range i.typeIndex {
		newUris := make([]string, 0, len(uris))
		for _, u := range uris {
			if u != uri {
				newUris = append(newUris, u)
			}
		}
		if len(newUris) == 0 {
			delete(i.typeIndex, resourceType)
		} else {
			i.typeIndex[resourceType] = newUris
		}
	}

	// Remove from agent index
	if i.agentIndex != nil {
		for agent, uris := range i.agentIndex {
			newUris := make([]string, 0, len(uris))
			for _, u := range uris {
				if u != uri {
					newUris = append(newUris, u)
				}
			}
			if len(newUris) == 0 {
				delete(i.agentIndex, agent)
			} else {
				i.agentIndex[agent] = newUris
			}
		}
	}

	// Remove from storage root index
	if i.storageRootIndex != nil {
		for storageRoot, uris := range i.storageRootIndex {
			newUris := make([]string, 0, len(uris))
			for _, u := range uris {
				if u != uri {
					newUris = append(newUris, u)
				}
			}
			if len(newUris) == 0 {
				delete(i.storageRootIndex, storageRoot)
			} else {
				i.storageRootIndex[storageRoot] = newUris
			}
		}
	}

	// Remove from RDF term index
	if i.rdfTermIndex != nil {
		for term, uris := range i.rdfTermIndex {
			newUris := make([]string, 0, len(uris))
			for _, u := range uris {
				if u != uri {
					newUris = append(newUris, u)
				}
			}
			if len(newUris) == 0 {
				delete(i.rdfTermIndex, term)
			} else {
				i.rdfTermIndex[term] = newUris
			}
		}
	}

	// Remove from access index
	delete(i.accessIndex, uri)

	// Remove from full-text index
	if i.fullTextIndex != nil {
		for term, uris := range i.fullTextIndex {
			newUris := make([]string, 0, len(uris))
			for _, u := range uris {
				if u != uri {
					newUris = append(newUris, u)
				}
			}
			if len(newUris) == 0 {
				delete(i.fullTextIndex, term)
			} else {
				i.fullTextIndex[term] = newUris
			}
		}
	}

	i.logger.Debug("Invalidated all indexes for resource", "uri", uri)
}

// IndexResource indexes a resource in all applicable indexes
func (i *ResourceIndexLayer) IndexResource(metadata *ResourceMetadata, accessInfo *ResourceAccessInfo) error {
	// Validate metadata
	if err := i.validateMetadata(metadata); err != nil {
		return err
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	if i.closed {
		return errors.New("resource index layer is closed")
	}

	// Check index size limit
	if len(i.resourceIndex) >= i.config.MaxIndexSize {
		// Remove oldest entry (FIFO eviction)
		i.evictOldestEntry()
	}

	// Set timestamps
	metadata.IndexedAt = time.Now().UTC()
	metadata.LastIndexed = metadata.IndexedAt

	// Add to resource index
	i.resourceIndex[metadata.URI] = metadata

	// Add to container index
	if metadata.ContainerURI != "" {
		i.containerIndex[metadata.ContainerURI] = append(i.containerIndex[metadata.ContainerURI], metadata.URI)
	}

	// Add to type index
	if metadata.ResourceType != "" {
		i.typeIndex[metadata.ResourceType] = append(i.typeIndex[metadata.ResourceType], metadata.URI)
	}

	// Add to agent index if enabled
	if i.config.EnableAgentIndex {
		if metadata.OwnerWebID != "" {
			i.agentIndex[metadata.OwnerWebID] = append(i.agentIndex[metadata.OwnerWebID], metadata.URI)
		}

		for _, contributor := range metadata.Contributors {
			i.agentIndex[contributor] = append(i.agentIndex[contributor], metadata.URI)
		}
	}

	// Add to access index
	if accessInfo != nil {
		i.accessIndex[metadata.URI] = accessInfo
	}

	// Add to storage root index if enabled
	if i.config.EnableStorageRootIndex && i.storageRootIndex != nil {
		if metadata.StorageRoot != "" {
			i.storageRootIndex[metadata.StorageRoot] = append(i.storageRootIndex[metadata.StorageRoot], metadata.URI)
		}
	}

	// Add to auxiliary index if enabled
	if i.config.EnableAuxiliaryIndex && i.auxiliaryIndex != nil && metadata.AuxiliaryLinks != nil {
		for auxURI := range metadata.AuxiliaryLinks {
			i.auxiliaryIndex[metadata.URI] = append(i.auxiliaryIndex[metadata.URI], auxURI)
		}
	}

	// Add to RDF term index if enabled
	if i.config.EnableRDFTermIndex && i.rdfTermIndex != nil && metadata.RDFTerms != nil {
		for term := range metadata.RDFTerms {
			i.rdfTermIndex[term] = append(i.rdfTermIndex[term], metadata.URI)
		}
	}

	// Add to full-text index if enabled
	if i.config.EnableFullTextIndex && i.fullTextIndex != nil && len(metadata.FullTextTerms) > 0 {
		for _, term := range metadata.FullTextTerms {
			i.fullTextIndex[term] = append(i.fullTextIndex[term], metadata.URI)
		}
	}

	// Update metrics
	if i.config.EnableObservability {
		i.indexMetrics.RecordResourceIndexed()
	}

	i.logger.Debug("Resource indexed",
		"uri", metadata.URI,
		"resource_type", metadata.ResourceType,
		"owner", metadata.OwnerWebID,
		"privacy_level", metadata.PrivacyLevel,
		"storage_root", metadata.StorageRoot,
	)

	return nil
}

// evictOldestEntry removes the oldest entry from the index
func (i *ResourceIndexLayer) evictOldestEntry() {
	var oldestURI string
	var oldestTime time.Time
	first := true

	for uri, metadata := range i.resourceIndex {
		if first || metadata.LastIndexed.Before(oldestTime) {
			oldestURI = uri
			oldestTime = metadata.LastIndexed
			first = false
		}
	}

	if oldestURI != "" {
		metadata := i.resourceIndex[oldestURI]
		i.removeFromOtherIndexes(oldestURI, metadata)
		delete(i.resourceIndex, oldestURI)
		i.logger.Debug("Evicted oldest index entry", "uri", oldestURI)
	}
}

// validateMetadata validates resource metadata before indexing
func (i *ResourceIndexLayer) validateMetadata(metadata *ResourceMetadata) error {
	if metadata == nil {
		return errors.New("metadata cannot be nil")
	}

	// Validate URI
	if err := ValidateURI(metadata.URI); err != nil {
		return fmt.Errorf("invalid resource URI: %w", err)
	}

	// Validate container URI if present
	if metadata.ContainerURI != "" {
		if err := ValidateContainerURI(metadata.ContainerURI); err != nil {
			return fmt.Errorf("invalid container URI: %w", err)
		}
	}

	// Validate content type if present
	if metadata.ContentType != "" {
		if err := ValidateContentType(metadata.ContentType); err != nil {
			return fmt.Errorf("invalid content type: %w", err)
		}
	}

	// Validate owner WebID if present
	if metadata.OwnerWebID != "" {
		if err := ValidateWebID(metadata.OwnerWebID); err != nil {
			return fmt.Errorf("invalid owner WebID: %w", err)
		}
	}

	// Validate contributor WebIDs if present
	for _, contributor := range metadata.Contributors {
		if err := ValidateWebID(contributor); err != nil {
			return fmt.Errorf("invalid contributor WebID: %w", err)
		}
	}

	// Validate access control URI if present
	if metadata.AccessControlURI != "" {
		if err := ValidatePolicyURI(metadata.AccessControlURI); err != nil {
			return fmt.Errorf("invalid access control URI: %w", err)
		}
	}

	return nil
}

// UpdateResource updates an existing resource in the index
func (i *ResourceIndexLayer) UpdateResource(metadata *ResourceMetadata, accessInfo *ResourceAccessInfo) error {
	// Validate metadata
	if err := i.validateMetadata(metadata); err != nil {
		return err
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	if i.closed {
		return errors.New("resource index layer is closed")
	}

	// Check if resource exists
	existing, exists := i.resourceIndex[metadata.URI]
	if !exists {
		return fmt.Errorf("resource %s not found in index", metadata.URI)
	}

	// Update metadata
	metadata.LastIndexed = time.Now().UTC()

	// Preserve some existing values if not provided
	if metadata.ContainerURI == "" {
		metadata.ContainerURI = existing.ContainerURI
	}
	if metadata.ResourceType == "" {
		metadata.ResourceType = existing.ResourceType
	}
	if metadata.ContentType == "" {
		metadata.ContentType = existing.ContentType
	}
	if metadata.OwnerWebID == "" {
		metadata.OwnerWebID = existing.OwnerWebID
	}
	if len(metadata.Contributors) == 0 {
		metadata.Contributors = existing.Contributors
	}
	if metadata.AccessControlURI == "" {
		metadata.AccessControlURI = existing.AccessControlURI
	}
	if metadata.PrivacyLevel == "" {
		metadata.PrivacyLevel = existing.PrivacyLevel
	}

	// Update in resource index
	i.resourceIndex[metadata.URI] = metadata

	// Update in access index
	if accessInfo != nil {
		i.accessIndex[metadata.URI] = accessInfo
	}

	// Update metrics
	if i.config.EnableObservability {
		i.indexMetrics.RecordResourceIndexed()
	}

	i.logger.Debug("Resource updated in index", "uri", metadata.URI)

	return nil
}

// RemoveResource removes a resource from all indexes
func (i *ResourceIndexLayer) RemoveResource(uri string) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.closed {
		return errors.New("resource index layer is closed")
	}

	// Check if resource exists
	metadata, exists := i.resourceIndex[uri]
	if !exists {
		return fmt.Errorf("resource %s not found in index", uri)
	}

	// Remove from all indexes
	i.removeFromOtherIndexes(uri, metadata)
	delete(i.resourceIndex, uri)

	// Update metrics
	if i.config.EnableObservability {
		i.indexMetrics.RecordIndexOperation()
	}

	i.logger.Debug("Resource removed from index", "uri", uri)

	return nil
}

// Search searches the index based on the provided query
func (i *ResourceIndexLayer) Search(query IndexQuery) (*IndexResult, error) {
	// Validate query
	if err := i.validateQuery(&query); err != nil {
		return nil, err
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	if i.closed {
		return nil, errors.New("resource index layer is closed")
	}

	startTime := time.Now()

	// Collect candidate URIs
	candidateURIs := i.getCandidateURIs(&query)

	// Filter and score candidates
	results := i.filterAndScoreCandidates(candidateURIs, &query)

	// Sort results
	i.sortResults(results, &query)

	// Apply limit and offset for pagination
	limitedResults := i.applyPagination(results, &query)

	// Convert to IndexedResource format
	indexedResults := i.convertToIndexedResources(limitedResults)

	// Check for more results
	hasMore := len(results) > query.Offset+len(limitedResults)

	// Update metrics
	if i.config.EnableObservability {
		i.indexMetrics.RecordSearch(true)
	}

	queryTime := time.Since(startTime)

	return &IndexResult{
		Results:    indexedResults,
		TotalCount: len(results),
		QueryTime:  queryTime,
		HasMore:    hasMore,
	}, nil
}

// validateQuery validates a search query
func (i *ResourceIndexLayer) validateQuery(query *IndexQuery) error {
	if query == nil {
		return errors.New("query cannot be nil")
	}

	// Validate WebID if provided
	if query.WebID != "" {
		if err := ValidateWebID(query.WebID); err != nil {
			return fmt.Errorf("invalid WebID in query: %w", err)
		}
	}

	// Validate URIs if provided
	for _, uri := range query.ResourceURIs {
		if err := ValidateURI(uri); err != nil {
			return fmt.Errorf("invalid resource URI in query: %w", err)
		}
	}

	for _, uri := range query.ContainerURIs {
		if err := ValidateContainerURI(uri); err != nil {
			return fmt.Errorf("invalid container URI in query: %w", err)
		}
	}

	// Validate limit
	if query.Limit <= 0 {
		query.Limit = 50 // Default limit
	}
	if query.Limit > 1000 {
		query.Limit = 1000 // Maximum limit
	}

	// Validate offset
	if query.Offset < 0 {
		query.Offset = 0
	}

	return nil
}

// getCandidateURIs gets candidate URIs based on the query
func (i *ResourceIndexLayer) getCandidateURIs(query *IndexQuery) map[string]*ResourceMetadata {
	candidates := make(map[string]*ResourceMetadata)

	// If specific resource URIs are requested, start with those
	if len(query.ResourceURIs) > 0 {
		for _, uri := range query.ResourceURIs {
			if metadata, exists := i.resourceIndex[uri]; exists {
				candidates[uri] = metadata
			}
		}
		return candidates
	}

	// If container URIs are specified, get resources from those containers
	if len(query.ContainerURIs) > 0 {
		for _, containerURI := range query.ContainerURIs {
			if uris, exists := i.containerIndex[containerURI]; exists {
				for _, uri := range uris {
					if metadata, exists := i.resourceIndex[uri]; exists {
						candidates[uri] = metadata
					}
				}
			}
		}
		return candidates
	}

	// If resource types are specified, get resources of those types
	if len(query.ResourceTypes) > 0 {
		for _, resourceType := range query.ResourceTypes {
			if uris, exists := i.typeIndex[resourceType]; exists {
				for _, uri := range uris {
					if metadata, exists := i.resourceIndex[uri]; exists {
						candidates[uri] = metadata
					}
				}
			}
		}
		return candidates
	}

	// If owner WebIDs are specified, get resources owned by those WebIDs
	if query.WebID != "" && i.config.EnableAgentIndex {
		if uris, exists := i.agentIndex[query.WebID]; exists {
			for _, uri := range uris {
				if metadata, exists := i.resourceIndex[uri]; exists {
					candidates[uri] = metadata
				}
			}
		}
		return candidates
	}

	// If storage roots are specified, get resources from those storage roots
	if len(query.StorageRoots) > 0 && i.storageRootIndex != nil {
		for _, storageRoot := range query.StorageRoots {
			if uris, exists := i.storageRootIndex[storageRoot]; exists {
				for _, uri := range uris {
					if metadata, exists := i.resourceIndex[uri]; exists {
						candidates[uri] = metadata
					}
				}
			}
		}
		if len(candidates) > 0 {
			return candidates
		}
	}

	// If no specific filters, return all resources (with access control)
	for uri, metadata := range i.resourceIndex {
		candidates[uri] = metadata
	}

	return candidates
}

// filterAndScoreCandidates filters and scores candidate resources based on the query
func (i *ResourceIndexLayer) filterAndScoreCandidates(candidates map[string]*ResourceMetadata, query *IndexQuery) []*ResourceMetadata {
	var results []*ResourceMetadata

	for uri, metadata := range candidates {
		// Skip if privacy level doesn't match
		if query.MinPrivacyLevel != "" && metadata.PrivacyLevel < query.MinPrivacyLevel {
			continue
		}
		if query.MaxPrivacyLevel != "" && metadata.PrivacyLevel > query.MaxPrivacyLevel {
			continue
		}

		// Skip if not public and user doesn't have access
		if !i.hasAccess(uri, query.WebID, query.IncludePrivate) {
			continue
		}

		// Filter by content type
		if len(query.ContentTypes) > 0 {
			matches := false
			for _, contentType := range query.ContentTypes {
				if metadata.ContentType == contentType {
					matches = true
					break
				}
			}
			if !matches {
				continue
			}
		}

		// Filter by owner
		if len(query.OwnerWebIDs) > 0 {
			matches := false
			for _, owner := range query.OwnerWebIDs {
				if metadata.OwnerWebID == owner {
					matches = true
					break
				}
			}
			if !matches {
				continue
			}
		}

		// Filter by contributor
		if len(query.ContributorWebIDs) > 0 {
			matches := false
			for _, contributor := range query.ContributorWebIDs {
				for _, metadataContributor := range metadata.Contributors {
					if metadataContributor == contributor {
						matches = true
						break
					}
				}
				if matches {
					break
				}
			}
			if !matches {
				continue
			}
		}

		// Filter by size
		if query.MinSize >= 0 && metadata.Size < query.MinSize {
			continue
		}
		if query.MaxSize >= 0 && metadata.Size > query.MaxSize {
			continue
		}

		results = append(results, metadata)
	}

	return results
}

// hasAccess checks if the specified WebID has access to the resource
func (i *ResourceIndexLayer) hasAccess(resourceURI, webID string, includePrivate bool) bool {
	// If includePrivate is true and we have a WebID, allow access
	if includePrivate && webID != "" {
		return true
	}

	// Check access index
	if accessInfo, exists := i.accessIndex[resourceURI]; exists {
		// Public access
		if accessInfo.PublicAccess {
			return true
		}

		// Agent access
		if webID != "" {
			for _, agent := range accessInfo.AllowedAgents {
				if agent == webID {
					return true
				}
			}
			// Check groups (simplified for now)
			for _, group := range accessInfo.AllowedGroups {
				if i.isAgentInGroup(webID, group) {
					return true
				}
			}
		}

		// Owner access
		if metadata, exists := i.resourceIndex[resourceURI]; exists {
			if metadata.OwnerWebID == webID {
				return true
			}
			// Check contributors
			for _, contributor := range metadata.Contributors {
				if contributor == webID {
					return true
				}
			}
		}
	}

	// If resource is public, allow access
	if metadata, exists := i.resourceIndex[resourceURI]; exists {
		if metadata.IsPublic {
			return true
		}
		// If privacy level is public, allow access
		if metadata.PrivacyLevel == PrivacyLevelPublic {
			return true
		}
	}

	return false
}

// isAgentInGroup checks if an agent is in a group (simplified implementation)
func (i *ResourceIndexLayer) isAgentInGroup(agent, group string) bool {
	// In a real implementation, this would query group membership
	// For now, we return false as a safe default
	return false
}

// sortResults sorts results based on the query parameters
func (i *ResourceIndexLayer) sortResults(results []*ResourceMetadata, query *IndexQuery) {
	if len(results) <= 1 {
		return
	}

	switch query.SortBy {
	case "last_modified", "modified":
		if query.SortOrder == "desc" {
			// Sort by last modified descending (newest first)
			for j := 0; j < len(results)-1; j++ {
				for k := j + 1; k < len(results); k++ {
					if results[k].LastModified.After(results[j].LastModified) {
						results[j], results[k] = results[k], results[j]
					}
				}
			}
		} else {
			// Sort by last modified ascending (oldest first)
			for j := 0; j < len(results)-1; j++ {
				for k := j + 1; k < len(results); k++ {
					if results[k].LastModified.Before(results[j].LastModified) {
						results[j], results[k] = results[k], results[j]
					}
				}
			}
		}
	case "created":
		if query.SortOrder == "desc" {
			// Sort by created descending (newest first)
			for j := 0; j < len(results)-1; j++ {
				for k := j + 1; k < len(results); k++ {
					if results[k].Created.After(results[j].Created) {
						results[j], results[k] = results[k], results[j]
					}
				}
			}
		} else {
			// Sort by created ascending (oldest first)
			for j := 0; j < len(results)-1; j++ {
				for k := j + 1; k < len(results); k++ {
					if results[k].Created.Before(results[j].Created) {
						results[j], results[k] = results[k], results[j]
					}
				}
			}
		}
	case "size":
		if query.SortOrder == "desc" {
			// Sort by size descending (largest first)
			for j := 0; j < len(results)-1; j++ {
				for k := j + 1; k < len(results); k++ {
					if results[k].Size > results[j].Size {
						results[j], results[k] = results[k], results[j]
					}
				}
			}
		} else {
			// Sort by size ascending (smallest first)
			for j := 0; j < len(results)-1; j++ {
				for k := j + 1; k < len(results); k++ {
					if results[k].Size < results[j].Size {
						results[j], results[k] = results[k], results[j]
					}
				}
			}
		}
	default:
		// Default sort: by last modified descending
		for j := 0; j < len(results)-1; j++ {
			for k := j + 1; k < len(results); k++ {
				if results[k].LastModified.After(results[j].LastModified) {
					results[j], results[k] = results[k], results[j]
				}
			}
		}
	}
}

// applyPagination applies pagination to results
func (i *ResourceIndexLayer) applyPagination(results []*ResourceMetadata, query *IndexQuery) []*ResourceMetadata {
	if query.Offset >= len(results) {
		return []*ResourceMetadata{}
	}

	end := query.Offset + query.Limit
	if end > len(results) {
		end = len(results)
	}

	return results[query.Offset:end]
}

// convertToIndexedResources converts ResourceMetadata to IndexedResource
func (i *ResourceIndexLayer) convertToIndexedResources(metadataList []*ResourceMetadata) []IndexedResource {
	results := make([]IndexedResource, 0, len(metadataList))

	for _, metadata := range metadataList {
		accessInfo := i.accessIndex[metadata.URI]
		results = append(results, IndexedResource{
			URI:          metadata.URI,
			ContainerURI: metadata.ContainerURI,
			ResourceType: metadata.ResourceType,
			ContentType:  metadata.ContentType,
			Size:         metadata.Size,
			LastModified: metadata.LastModified,
			OwnerWebID:   metadata.OwnerWebID,
			PrivacyLevel: metadata.PrivacyLevel,
			StorageRoot:  metadata.StorageRoot,
			AccessInfo:   accessInfo,
		})
	}

	return results
}

// GetResource retrieves a single resource from the index
func (i *ResourceIndexLayer) GetResource(uri string, webID string, includePrivate bool) (*IndexedResource, error) {
	// Validate URI
	if err := ValidateURI(uri); err != nil {
		return nil, fmt.Errorf("invalid resource URI: %w", err)
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	if i.closed {
		return nil, errors.New("resource index layer is closed")
	}

	// Check if resource exists
	metadata, exists := i.resourceIndex[uri]
	if !exists {
		return nil, fmt.Errorf("resource %s not found in index", uri)
	}

	// Check access
	if !i.hasAccess(uri, webID, includePrivate) {
		return nil, fmt.Errorf("access denied to resource %s", uri)
	}

	// Update metrics
	if i.config.EnableObservability {
		i.indexMetrics.RecordIndexHit()
	}

	accessInfo := i.accessIndex[uri]

	return &IndexedResource{
		URI:          metadata.URI,
		ContainerURI: metadata.ContainerURI,
		ResourceType: metadata.ResourceType,
		ContentType:  metadata.ContentType,
		Size:         metadata.Size,
		LastModified: metadata.LastModified,
		OwnerWebID:   metadata.OwnerWebID,
		PrivacyLevel: metadata.PrivacyLevel,
		AccessInfo:   accessInfo,
	}, nil
}

// GetContainerResources gets all resources in a container
func (i *ResourceIndexLayer) GetContainerResources(containerURI string, webID string, includePrivate bool) ([]IndexedResource, error) {
	// Validate container URI
	if err := ValidateContainerURI(containerURI); err != nil {
		return nil, fmt.Errorf("invalid container URI: %w", err)
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	if i.closed {
		return nil, errors.New("resource index layer is closed")
	}

	// Get URIs in this container
	uris, exists := i.containerIndex[containerURI]
	if !exists {
		return []IndexedResource{}, nil
	}

	var results []IndexedResource

	for _, uri := range uris {
		metadata, exists := i.resourceIndex[uri]
		if !exists {
			continue
		}

		// Check access
		if !i.hasAccess(uri, webID, includePrivate) {
			continue
		}

		accessInfo := i.accessIndex[uri]
		results = append(results, IndexedResource{
			URI:          metadata.URI,
			ContainerURI: metadata.ContainerURI,
			ResourceType: metadata.ResourceType,
			ContentType:  metadata.ContentType,
			Size:         metadata.Size,
			LastModified: metadata.LastModified,
			OwnerWebID:   metadata.OwnerWebID,
			PrivacyLevel: metadata.PrivacyLevel,
			AccessInfo:   accessInfo,
		})
	}

	// Update metrics
	if i.config.EnableObservability {
		i.indexMetrics.RecordIndexHit()
	}

	return results, nil
}

// GetMetrics returns the current metrics
func (i *ResourceIndexLayer) GetMetrics() *ResourceIndexMetrics {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return &i.indexMetrics
}

// Size returns the current number of indexed resources
func (i *ResourceIndexLayer) Size() (int, int, int, int) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.resourceIndex), len(i.containerIndex), len(i.agentIndex), len(i.typeIndex)
}

// Clear clears all indexes
func (i *ResourceIndexLayer) Clear() {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.resourceIndex = make(map[string]*ResourceMetadata)
	i.containerIndex = make(map[string][]string)
	i.agentIndex = make(map[string][]string)
	i.typeIndex = make(map[string][]string)
	i.accessIndex = make(map[string]*ResourceAccessInfo)
	if i.fullTextIndex != nil {
		i.fullTextIndex = make(map[string][]string)
	}
	if i.auxiliaryIndex != nil {
		i.auxiliaryIndex = make(map[string][]string)
	}
	if i.storageRootIndex != nil {
		i.storageRootIndex = make(map[string][]string)
	}
	if i.rdfTermIndex != nil {
		i.rdfTermIndex = make(map[string][]string)
	}

	i.logger.Info("All indexes cleared")
}

// Close closes the resource index layer
func (i *ResourceIndexLayer) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.closed {
		return nil
	}

	i.closed = true
	close(i.closeChan)

	// Clear all indexes directly without calling Clear() to avoid deadlock
	i.resourceIndex = make(map[string]*ResourceMetadata)
	i.containerIndex = make(map[string][]string)
	i.agentIndex = make(map[string][]string)
	i.typeIndex = make(map[string][]string)
	i.accessIndex = make(map[string]*ResourceAccessInfo)
	if i.fullTextIndex != nil {
		i.fullTextIndex = make(map[string][]string)
	}
	if i.auxiliaryIndex != nil {
		i.auxiliaryIndex = make(map[string][]string)
	}
	if i.storageRootIndex != nil {
		i.storageRootIndex = make(map[string][]string)
	}
	if i.rdfTermIndex != nil {
		i.rdfTermIndex = make(map[string][]string)
	}

	i.logger.Info("Resource index layer closed")
	return nil
}

// IsClosed returns true if the layer is closed
func (i *ResourceIndexLayer) IsClosed() bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.closed
}

// IndexAccessInfo updates access control information for a resource
func (i *ResourceIndexLayer) IndexAccessInfo(resourceURI string, accessInfo *ResourceAccessInfo) error {
	// Validate resource URI
	if err := ValidateURI(resourceURI); err != nil {
		return fmt.Errorf("invalid resource URI: %w", err)
	}

	if accessInfo == nil {
		return errors.New("accessInfo cannot be nil")
	}

	// Validate agents
	for _, agent := range accessInfo.AllowedAgents {
		if err := ValidateWebID(agent); err != nil {
			return fmt.Errorf("invalid agent WebID in access info: %w", err)
		}
	}

	// Validate groups
	for _, group := range accessInfo.AllowedGroups {
		if err := ValidateURI(group); err != nil {
			return fmt.Errorf("invalid group URI in access info: %w", err)
		}
	}

	// Validate owner
	if accessInfo.OwnerWebID != "" {
		if err := ValidateWebID(accessInfo.OwnerWebID); err != nil {
			return fmt.Errorf("invalid owner WebID in access info: %w", err)
		}
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	if i.closed {
		return errors.New("resource index layer is closed")
	}

	// Update access index
	i.accessIndex[resourceURI] = accessInfo

	// Update metrics
	if i.config.EnableObservability {
		i.indexMetrics.RecordIndexOperation()
	}

	return nil
}
