// Package storage provides the production storage engine for the Solid runtime.
// This file implements the core storage engine as required by Phase 18.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// storageEngineImpl implements the StorageEngine interface
type storageEngineImpl struct {
	mu sync.RWMutex

	// Configuration
	config EngineConfig

	// Registered backends
	backends map[string]StorageBackend

	// Default backend
	defaultBackend StorageBackend

	// Metadata store
	metadataStore MetadataStore

	// Blob store
	blobStore BlobStore

	// Tombstone store
	tombstoneStore TombstoneStore

	// Quota manager
	quotaManager QuotaManager

	// Layout version
	layoutVersion StorageLayoutVersion

	// Metrics
	metrics EngineMetrics

	// Logger
	logger *slog.Logger

	// Close state
	closed    bool
	closeChan chan struct{}
}

// EngineConfig holds configuration for the storage engine
type EngineConfig struct {
	// DefaultBackend is the name of the default storage backend
	DefaultBackend string

	// BackendConfigs contains configuration for each backend
	BackendConfigs map[string]map[string]string

	// EnableBlobStorage enables content-addressed blob storage
	EnableBlobStorage bool

	// BlobStorageBackend is the backend to use for blob storage (empty = same as default)
	BlobStorageBackend string

	// EnableQuotaManagement enables quota management
	EnableQuotaManagement bool

	// QuotaConfigs contains quota configurations by storage root/tenant
	QuotaConfigs map[string]QuotaConfig

	// EnableTombstones enables tombstone support
	EnableTombstones bool

	// EnableIntegrityScanning enables integrity scanning
	EnableIntegrityScanning bool

	// IntegrityScanInterval is how often to run integrity scans (0 = disabled)
	IntegrityScanInterval time.Duration

	// EnableBackupRestore enables backup/restore functionality
	EnableBackupRestore bool

	// Logger is the logger for the engine
	Logger *slog.Logger
}

// QuotaConfig holds quota configuration for a storage root or tenant
type QuotaConfig struct {
	MaxBytes     int64
	MaxResources int64
}

// DefaultEngineConfig returns a safe default configuration
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		DefaultBackend:          "filesystem",
		BackendConfigs:          make(map[string]map[string]string),
		EnableBlobStorage:       true,
		BlobStorageBackend:      "",
		EnableQuotaManagement:   false,
		QuotaConfigs:            make(map[string]QuotaConfig),
		EnableTombstones:        true,
		EnableIntegrityScanning: false,
		IntegrityScanInterval:   0,
		EnableBackupRestore:     true,
		Logger:                  nil,
	}
}

// EngineMetrics holds metrics for the storage engine
type EngineMetrics struct {
	mu sync.RWMutex

	// Request counts
	GetRequests      int64
	PutRequests      int64
	DeleteRequests   int64
	ListRequests     int64
	MetadataRequests int64

	// Success counts
	GetSuccesses      int64
	PutSuccesses      int64
	DeleteSuccesses   int64
	ListSuccesses     int64
	MetadataSuccesses int64

	// Error counts
	GetErrors      int64
	PutErrors      int64
	DeleteErrors   int64
	ListErrors     int64
	MetadataErrors int64

	// Blob operations
	BlobStoreRequests    int64
	BlobRetrieveRequests int64

	// Transaction operations
	TransactionsStarted    int64
	TransactionsCommitted  int64
	TransactionsRolledBack int64

	// Quota operations
	QuotaChecks   int64
	QuotaExceeded int64

	// Tombstone operations
	TombstoneCreations int64
	TombstoneRestores  int64

	// Error counts by type
	ErrorsByType map[string]int64
}

// RecordRequest records a request
func (m *EngineMetrics) RecordRequest(requestType string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch requestType {
	case "get":
		m.GetRequests++
	case "put":
		m.PutRequests++
	case "delete":
		m.DeleteRequests++
	case "list":
		m.ListRequests++
	case "metadata":
		m.MetadataRequests++
	case "blob_store":
		m.BlobStoreRequests++
	case "blob_retrieve":
		m.BlobRetrieveRequests++
	}
}

// RecordSuccess records a successful operation
func (m *EngineMetrics) RecordSuccess(requestType string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch requestType {
	case "get":
		m.GetSuccesses++
	case "put":
		m.PutSuccesses++
	case "delete":
		m.DeleteSuccesses++
	case "list":
		m.ListSuccesses++
	case "metadata":
		m.MetadataSuccesses++
	}
}

// RecordError records an error
func (m *EngineMetrics) RecordError(requestType string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	errType := classifyError(err)
	if m.ErrorsByType == nil {
		m.ErrorsByType = make(map[string]int64)
	}
	m.ErrorsByType[errType]++

	switch requestType {
	case "get":
		m.GetErrors++
	case "put":
		m.PutErrors++
	case "delete":
		m.DeleteErrors++
	case "list":
		m.ListErrors++
	case "metadata":
		m.MetadataErrors++
	}
}

// classifyError classifies an error into a type
func classifyError(err error) string {
	if err == nil {
		return ""
	}

	// Check for known error types
	switch {
	case errors.Is(err, ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrAlreadyExists):
		return "already_exists"
	case errors.Is(err, ErrPreconditionFailed):
		return "precondition_failed"
	case errors.Is(err, ErrConflict):
		return "conflict"
	case errors.Is(err, ErrQuotaExceeded):
		return "quota_exceeded"
	case errors.Is(err, ErrStorageClosed):
		return "storage_closed"
	case errors.Is(err, ErrInvalidURI):
		return "invalid_uri"
	case errors.Is(err, ErrBackendUnavailable):
		return "backend_unavailable"
	default:
		return "internal"
	}
}

// NewStorageEngine creates a new storage engine
func NewStorageEngine(config EngineConfig) (StorageEngine, error) {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	// Create the engine
	engine := &storageEngineImpl{
		config:    config,
		backends:  make(map[string]StorageBackend),
		metrics:   EngineMetrics{},
		logger:    config.Logger,
		closed:    false,
		closeChan: make(chan struct{}),
	}

	// Set default layout version
	engine.layoutVersion = CurrentStorageLayoutVersion

	// Register default backends
	if err := engine.registerDefaultBackends(config); err != nil {
		return nil, SanitizeError(fmt.Errorf("failed to initialize storage engine: %w", err))
	}

	// Set default backend
	if err := engine.setDefaultBackend(config.DefaultBackend); err != nil {
		return nil, fmt.Errorf("failed to set default backend: %w", err)
	}

	// Initialize metadata store (needs default backend)
	if err := engine.initMetadataStore(config); err != nil {
		return nil, fmt.Errorf("failed to initialize metadata store: %w", err)
	}

	// Initialize blob store
	if config.EnableBlobStorage {
		if err := engine.initBlobStore(config); err != nil {
			return nil, fmt.Errorf("failed to initialize blob store: %w", err)
		}
	}

	// Initialize tombstone store
	if config.EnableTombstones {
		if err := engine.initTombstoneStore(config); err != nil {
			return nil, fmt.Errorf("failed to initialize tombstone store: %w", err)
		}
	}

	// Initialize quota manager
	if config.EnableQuotaManagement {
		if err := engine.initQuotaManager(config); err != nil {
			return nil, fmt.Errorf("failed to initialize quota manager: %w", err)
		}
	}

	// Start background tasks
	if err := engine.startBackgroundTasks(config); err != nil {
		return nil, fmt.Errorf("failed to start background tasks: %w", err)
	}

	config.Logger.Info("Storage engine initialized",
		"default_backend", config.DefaultBackend,
		"blob_storage_enabled", config.EnableBlobStorage,
		"quota_management_enabled", config.EnableQuotaManagement,
		"tombstones_enabled", config.EnableTombstones,
		"integrity_scanning_enabled", config.EnableIntegrityScanning,
		"backup_restore_enabled", config.EnableBackupRestore,
	)

	return engine, nil
}

// initMetadataStore initializes the metadata store
func (s *storageEngineImpl) initMetadataStore(config EngineConfig) error {
	// Use the default backend for metadata
	s.metadataStore = &defaultMetadataStore{
		backend: s.defaultBackend,
	}
	return nil
}

// initBlobStore initializes the blob store
func (s *storageEngineImpl) initBlobStore(config EngineConfig) error {
	// Use the default backend for blobs
	s.blobStore = &defaultBlobStore{
		backend: s.defaultBackend,
	}
	return nil
}

// initTombstoneStore initializes the tombstone store
func (s *storageEngineImpl) initTombstoneStore(config EngineConfig) error {
	s.tombstoneStore = &defaultTombstoneStore{
		tombstones: make(map[string]*Tombstone),
	}
	return nil
}

// initQuotaManager initializes the quota manager
func (s *storageEngineImpl) initQuotaManager(config EngineConfig) error {
	s.quotaManager = &defaultQuotaManager{
		quotas: make(map[string]*QuotaInfo),
	}
	return nil
}

// registerDefaultBackends registers the default storage backends
func (s *storageEngineImpl) registerDefaultBackends(config EngineConfig) error {
	// Register filesystem backend
	fsBackend := NewFilesystemBackend(FilesystemBackendConfig{
		RootPath: "./storage",
		Logger:   s.logger.With("backend", "filesystem"),
	})

	if err := s.RegisterBackend("filesystem", fsBackend); err != nil {
		return SanitizeError(fmt.Errorf("failed to register filesystem backend: %w", err))
	}

	// Register memory backend (for testing)
	memBackend := NewMemoryBackend(MemoryBackendConfig{
		Logger: s.logger.With("backend", "memory"),
	})

	if err := s.RegisterBackend("memory", memBackend); err != nil {
		return SanitizeError(fmt.Errorf("failed to register memory backend: %w", err))
	}

	// Initialize configured backends
	for name, backendConfig := range config.BackendConfigs {
		// Skip if already registered
		if _, exists := s.backends[name]; exists {
			continue
		}

		// Create backend based on configuration
		// This would be extended to support different backend types
		var backend StorageBackend

		backendType := backendConfig["type"]
		rootPath := backendConfig["root_path"]

		switch backendType {
		case "filesystem":
			backend = NewFilesystemBackend(FilesystemBackendConfig{
				RootPath: rootPath,
				Logger:   s.logger.With("backend", name),
			})
		case "memory":
			backend = NewMemoryBackend(MemoryBackendConfig{
				Logger: s.logger.With("backend", name),
			})
		default:
			// For now, default to filesystem
			backend = NewFilesystemBackend(FilesystemBackendConfig{
				RootPath: rootPath,
				Logger:   s.logger.With("backend", name),
			})
		}

		if err := s.RegisterBackend(name, backend); err != nil {
			return SanitizeError(fmt.Errorf("failed to register backend: %w", err))
		}
	}

	return nil
}

// setDefaultBackend sets the default backend
func (s *storageEngineImpl) setDefaultBackend(name string) error {
	backend, exists := s.backends[name]
	if !exists {
		return fmt.Errorf("backend %q not found", name)
	}

	// Initialize the backend if not already done
	if err := backend.Initialize(context.Background(), s.config.BackendConfigs[name]); err != nil {
		return fmt.Errorf("failed to initialize backend %q: %w", name, err)
	}

	s.defaultBackend = backend
	s.logger.Info("Default backend set", "name", name)
	return nil
}

// startBackgroundTasks starts background tasks
func (s *storageEngineImpl) startBackgroundTasks(config EngineConfig) error {
	// Start integrity scanner if enabled
	if config.EnableIntegrityScanning && config.IntegrityScanInterval > 0 {
		go s.integrityScannerLoop(config.IntegrityScanInterval)
	}

	return nil
}

// integrityScannerLoop runs the integrity scanner periodically
func (s *storageEngineImpl) integrityScannerLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.scanIntegrityPeriodic()
		case <-s.closeChan:
			s.logger.Info("Integrity scanner loop stopped")
			return
		}
	}
}

// scanIntegrityPeriodic performs a periodic integrity scan
func (s *storageEngineImpl) scanIntegrityPeriodic() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	report, err := s.Integrity().Scan(ctx)
	if err != nil {
		s.logger.Error("Integrity scan failed", "error", err)
		return
	}

	if report.ResourcesWithIssues > 0 {
		s.logger.Warn("Integrity scan found issues",
			"total_resources", report.TotalResources,
			"resources_with_issues", report.ResourcesWithIssues,
			"metadata_body_mismatches", report.MetadataBodyMismatches,
			"missing_digests", report.MissingDigests,
			"orphaned_blobs", report.OrphanedBlobs,
		)
	} else {
		s.logger.Debug("Integrity scan completed successfully",
			"total_resources", report.TotalResources,
		)
	}
}

// RegisterBackend registers a new storage backend
func (s *storageEngineImpl) RegisterBackend(name string, backend StorageBackend) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStorageClosed
	}

	if _, exists := s.backends[name]; exists {
		return fmt.Errorf("backend %q already registered", name)
	}

	s.backends[name] = backend
	s.logger.Info("Storage backend registered", "name", name, "description", backend.Description())
	return nil
}

// GetBackend returns a storage backend by name
func (s *storageEngineImpl) GetBackend(name string) (StorageBackend, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStorageClosed
	}

	backend, exists := s.backends[name]
	if !exists {
		return nil, fmt.Errorf("%w: backend %q", ErrNotFound, name)
	}

	return backend, nil
}

// Get implements StorageEngine.Get
func (s *storageEngineImpl) Get(ctx context.Context, uri string) (*ReadResource, error) {
	s.metrics.RecordRequest("get")
	defer func() {
		if err := recover(); err != nil {
			s.metrics.RecordError("get", fmt.Errorf("panic: %v", err))
			panic(err)
		}
	}()

	// Validate URI
	if err := validateStorageURI(uri); err != nil {
		s.metrics.RecordError("get", err)
		return nil, err
	}

	// Check if resource is tombstoned
	isTombstoned, err := s.isTombstoned(ctx, uri)
	if err != nil {
		s.metrics.RecordError("get", err)
		return nil, fmt.Errorf("failed to check tombstone: %w", err)
	}

	if isTombstoned {
		return nil, ErrNotFound
	}

	// Get from default backend
	resource, err := s.defaultBackend.Get(ctx, uri)
	if err != nil {
		s.metrics.RecordError("get", err)
		return nil, err
	}

	// Update metadata with computed fields
	if resource.Metadata.ETag == "" {
		resource.Metadata.ETag = generateETag(resource.Body)
	}

	// Ensure content type is set
	if resource.Metadata.ContentType == "" {
		resource.Metadata.ContentType = detectContentType(uri, resource.Body)
	}

	s.metrics.RecordSuccess("get")
	return &ReadResource{
		URI:      uri,
		Body:     resource.Body,
		Metadata: resource.Metadata,
	}, nil
}

// GetMetadata implements StorageEngine.GetMetadata
func (s *storageEngineImpl) GetMetadata(ctx context.Context, uri string) (*Metadata, error) {
	s.metrics.RecordRequest("metadata")

	// Validate URI
	if err := validateStorageURI(uri); err != nil {
		s.metrics.RecordError("metadata", err)
		return nil, err
	}

	// Check if resource is tombstoned
	isTombstoned, err := s.isTombstoned(ctx, uri)
	if err != nil {
		s.metrics.RecordError("metadata", err)
		return nil, fmt.Errorf("failed to check tombstone: %w", err)
	}

	if isTombstoned {
		// For tombstoned resources, return a minimal metadata with tombstone info
		tombstone, err := s.GetTombstone(ctx, uri)
		if err != nil {
			return nil, ErrNotFound
		}
		return &Metadata{
			ResourceType: ResourceTypeUnknown,
			Size:         0,
			ContentType:  "",
			ETag:         "",
			LastModified: tombstone.DeletedAt,
			Created:      time.Time{},
			Owner:        tombstone.DeletedBy,
			Custom: map[string]string{
				"tombstoned": "true",
			},
		}, nil
	}

	// Get from metadata store
	metadata, err := s.metadataStore.GetMetadata(ctx, uri)
	if err != nil {
		s.metrics.RecordError("metadata", err)
		return nil, err
	}

	s.metrics.RecordSuccess("metadata")
	return metadata, nil
}

// Put implements StorageEngine.Put
func (s *storageEngineImpl) Put(ctx context.Context, resource *WriteResource) error {
	s.metrics.RecordRequest("put")

	// Validate URI
	if err := validateStorageURI(resource.URI); err != nil {
		s.metrics.RecordError("put", err)
		return err
	}

	// Validate resource
	if err := validateResource(resource); err != nil {
		s.metrics.RecordError("put", err)
		return err
	}

	// Check quota if enabled
	if s.config.EnableQuotaManagement && resource.Metadata.StorageRoot != "" {
		bodySize := resource.BodySize
		if bodySize == 0 && resource.BodyReader != nil {
			// If we have a reader but not a size, we need to read to determine size
			// For now, we'll use a buffer to read and count
			data, err := io.ReadAll(resource.BodyReader)
			if err != nil {
				s.metrics.RecordError("put", err)
				return SanitizeError(fmt.Errorf("failed to read body for quota check: %w", err))
			}
			bodySize = int64(len(data))
			// Reset the reader
			resource.Body = data
			resource.BodyReader = nil
			resource.BodySize = bodySize
		}

		// Calculate total size: body + metadata
		totalSize := bodySize
		metadataSize := estimateMetadataSize(&resource.Metadata)
		totalSize += metadataSize

		if err := s.quotaManager.CheckQuota(ctx, resource.Metadata.StorageRoot, totalSize); err != nil {
			s.metrics.RecordError("put", err)
			return err
		}
	}

	// Handle preconditions
	if err := s.handlePreconditions(ctx, resource); err != nil {
		s.metrics.RecordError("put", err)
		return err
	}

	// Store blob if content-addressed
	if resource.Metadata.ContentAddress != "" && resource.Metadata.Digest != "" {
		// Verify digest matches
		computedDigest := computeDigest(resource.Body)
		if computedDigest != resource.Metadata.Digest {
			s.metrics.RecordError("put", ErrIntegrityViolation)
			return ErrIntegrityViolation
		}

		// Store in blob store
		address, err := s.blobStore.StoreBlob(ctx, resource.Body)
		if err != nil {
			s.metrics.RecordError("put", err)
			return fmt.Errorf("failed to store blob: %w", err)
		}

		// Update content address
		resource.Metadata.ContentAddress = address
	}

	// Store in default backend
	// Use the original resource since it has the body
	if err := s.defaultBackend.Put(ctx, resource.URI, resource); err != nil {
		s.metrics.RecordError("put", err)
		return err
	}

	// Note: The backend already stores the metadata, so no need to store it separately here
	// The metadata store is available for cases where metadata needs to be updated independently

	// Update quota usage
	if s.config.EnableQuotaManagement && resource.Metadata.StorageRoot != "" {
		if err := s.quotaManager.RecordUsage(ctx, resource.Metadata.StorageRoot, resource.BodySize); err != nil {
			s.logger.Warn("Failed to record quota usage", "storage_root", resource.Metadata.StorageRoot, "error", err)
		}
	}

	s.metrics.RecordSuccess("put")
	return nil
}

// Delete implements StorageEngine.Delete
func (s *storageEngineImpl) Delete(ctx context.Context, uri string) error {
	s.metrics.RecordRequest("delete")

	// Validate URI
	if err := validateStorageURI(uri); err != nil {
		s.metrics.RecordError("delete", err)
		return err
	}

	// Delete from default backend
	if err := s.defaultBackend.Delete(ctx, uri); err != nil && !errors.Is(err, ErrNotFound) {
		s.metrics.RecordError("delete", err)
		return err
	}

	// Delete from metadata store
	if err := s.metadataStore.DeleteMetadata(ctx, uri); err != nil {
		s.logger.Warn("Failed to delete metadata", "uri", uri, "error", err)
	}

	s.metrics.RecordSuccess("delete")
	return nil
}

// DeleteWithTombstone implements StorageEngine.DeleteWithTombstone
func (s *storageEngineImpl) DeleteWithTombstone(ctx context.Context, uri string, tombstone *Tombstone) error {
	s.metrics.RecordRequest("delete")

	// Validate URI
	if err := validateStorageURI(uri); err != nil {
		s.metrics.RecordError("delete", err)
		return err
	}

	// Set tombstone URI if not set
	if tombstone.URI == "" {
		tombstone.URI = uri
	}

	// Set deleted time if not set
	if tombstone.DeletedAt.IsZero() {
		tombstone.DeletedAt = time.Now()
	}

	// Store tombstone first
	if err := s.tombstoneStore.StoreTombstone(ctx, tombstone); err != nil {
		s.metrics.RecordError("delete", err)
		return fmt.Errorf("failed to store tombstone: %w", err)
	}

	// Delete from default backend
	if err := s.defaultBackend.Delete(ctx, uri); err != nil && !errors.Is(err, ErrNotFound) {
		s.metrics.RecordError("delete", err)
		// Try to remove tombstone on failure
		_ = s.tombstoneStore.DeleteTombstone(ctx, uri)
		return err
	}

	// Delete from metadata store
	if err := s.metadataStore.DeleteMetadata(ctx, uri); err != nil {
		s.logger.Warn("Failed to delete metadata", "uri", uri, "error", err)
	}

	s.metrics.RecordSuccess("delete")
	s.metrics.TombstoneCreations++
	return nil
}

// List implements StorageEngine.List
func (s *storageEngineImpl) List(ctx context.Context, containerURI string) ([]*Metadata, error) {
	s.metrics.RecordRequest("list")

	// Validate container URI
	if err := validateStorageURI(containerURI); err != nil {
		s.metrics.RecordError("list", err)
		return nil, err
	}

	// List from default backend
	metadataList, err := s.defaultBackend.List(ctx, containerURI)
	if err != nil {
		s.metrics.RecordError("list", err)
		return nil, err
	}

	// Filter out tombstoned resources
	var result []*Metadata
	for _, metadata := range metadataList {
		isTombstoned, err := s.isTombstoned(ctx, metadata.URI)
		if err != nil {
			s.logger.Warn("Failed to check tombstone", "uri", metadata.URI, "error", err)
			continue
		}
		if !isTombstoned {
			result = append(result, metadata)
		}
	}

	s.metrics.RecordSuccess("list")
	return result, nil
}

// ListWithPrefix implements StorageEngine.ListWithPrefix
func (s *storageEngineImpl) ListWithPrefix(ctx context.Context, containerURI, prefix string) ([]*Metadata, error) {
	s.metrics.RecordRequest("list")

	// Validate container URI
	if err := validateStorageURI(containerURI); err != nil {
		s.metrics.RecordError("list", err)
		return nil, err
	}

	// List all resources and filter by prefix
	allMetadata, err := s.List(ctx, containerURI)
	if err != nil {
		return nil, err
	}

	// Filter by prefix
	var result []*Metadata
	for _, metadata := range allMetadata {
		uri := metadata.URI
		// Remove container URI prefix for comparison
		relativeURI := strings.TrimPrefix(uri, containerURI)
		if strings.HasPrefix(relativeURI, prefix) {
			result = append(result, metadata)
		}
	}

	return result, nil
}

// Exists implements StorageEngine.Exists
func (s *storageEngineImpl) Exists(ctx context.Context, uri string) (bool, error) {
	s.metrics.RecordRequest("metadata")

	// Validate URI
	if err := validateStorageURI(uri); err != nil {
		s.metrics.RecordError("metadata", err)
		return false, err
	}

	// Check existence
	exists, err := s.defaultBackend.Exists(ctx, uri)
	if err != nil {
		s.metrics.RecordError("metadata", err)
		return false, err
	}

	return exists, nil
}

// ExistsWithTombstone implements StorageEngine.ExistsWithTombstone
func (s *storageEngineImpl) ExistsWithTombstone(ctx context.Context, uri string) (bool, bool, error) {
	s.metrics.RecordRequest("metadata")

	// Check if tombstoned
	isTombstoned, err := s.isTombstoned(ctx, uri)
	if err != nil {
		s.metrics.RecordError("metadata", err)
		return false, false, err
	}

	// Check existence
	exists, err := s.Exists(ctx, uri)
	if err != nil {
		s.metrics.RecordError("metadata", err)
		return false, isTombstoned, err
	}

	return exists, isTombstoned, nil
}

// StoreBlob implements StorageEngine.StoreBlob
func (s *storageEngineImpl) StoreBlob(ctx context.Context, data []byte) (ContentAddress, error) {
	s.metrics.RecordRequest("blob_store")

	// Check blob size against quota if enabled
	if s.config.EnableQuotaManagement {
		// For blobs, we need to determine the storage root
		// Blobs are typically stored under a specific storage root
		// For now, we'll use a default blob storage root
		storageRoot := "blobs"

		blobSize := int64(len(data))
		if err := s.quotaManager.CheckQuota(ctx, storageRoot, blobSize); err != nil {
			s.metrics.RecordError("blob_store", err)
			return "", err
		}
	}

	// Store in blob store - it will compute the address
	address, err := s.blobStore.StoreBlob(ctx, data)
	if err != nil {
		s.metrics.RecordError("blob_store", err)
		return "", err
	}

	s.metrics.RecordSuccess("blob_store")
	return address, nil
}

// GetBlob implements StorageEngine.GetBlob
func (s *storageEngineImpl) GetBlob(ctx context.Context, address ContentAddress) ([]byte, error) {
	s.metrics.RecordRequest("blob_retrieve")

	// Retrieve from blob store
	data, err := s.blobStore.GetBlob(ctx, address)
	if err != nil {
		s.metrics.RecordError("blob_retrieve", err)
		return nil, err
	}

	s.metrics.RecordSuccess("blob_retrieve")
	return data, nil
}

// DeleteBlob implements StorageEngine.DeleteBlob
func (s *storageEngineImpl) DeleteBlob(ctx context.Context, address ContentAddress) error {
	s.metrics.RecordRequest("delete")

	// Delete from blob store
	if err := s.blobStore.DeleteBlob(ctx, address); err != nil {
		s.metrics.RecordError("delete", err)
		return err
	}

	s.metrics.RecordSuccess("delete")
	return nil
}

// BlobExists implements StorageEngine.BlobExists
func (s *storageEngineImpl) BlobExists(ctx context.Context, address ContentAddress) (bool, error) {
	s.metrics.RecordRequest("metadata")

	// Check existence
	exists, err := s.blobStore.BlobExists(ctx, address)
	if err != nil {
		s.metrics.RecordError("metadata", err)
		return false, err
	}

	return exists, nil
}

// BeginTransaction implements StorageEngine.BeginTransaction
func (s *storageEngineImpl) BeginTransaction(ctx context.Context) (Transaction, error) {
	s.metrics.RecordRequest("put")

	// Create transaction
	// For now, use a simple in-memory transaction
	// In a production implementation, this would use the backend's transaction support
	txn := &storageTransaction{
		engine:     s,
		ctx:        ctx,
		pending:    make(map[string]*WriteResource),
		deleted:    make(map[string]bool),
		committed:  false,
		rolledBack: false,
		logger:     s.logger.With("component", "transaction"),
	}

	s.metrics.TransactionsStarted++
	return txn, nil
}

// GetQuota implements StorageEngine.GetQuota
func (s *storageEngineImpl) GetQuota(ctx context.Context, storageRoot string) (*QuotaInfo, error) {
	if !s.config.EnableQuotaManagement {
		return &QuotaInfo{
			StorageRoot: storageRoot,
			UsedBytes:   0,
			MaxBytes:    0, // 0 = unlimited
		}, nil
	}

	return s.quotaManager.GetQuota(ctx, storageRoot)
}

// GetTenantQuota implements StorageEngine.GetTenantQuota
func (s *storageEngineImpl) GetTenantQuota(ctx context.Context, tenant string) (*QuotaInfo, error) {
	if !s.config.EnableQuotaManagement {
		return &QuotaInfo{
			Tenant:    tenant,
			UsedBytes: 0,
			MaxBytes:  0, // 0 = unlimited
		}, nil
	}

	return s.quotaManager.GetTenantQuota(ctx, tenant)
}

// CheckQuota implements StorageEngine.CheckQuota
func (s *storageEngineImpl) CheckQuota(ctx context.Context, storageRoot string, additionalBytes int64) error {
	if !s.config.EnableQuotaManagement {
		return nil
	}

	return s.quotaManager.CheckQuota(ctx, storageRoot, additionalBytes)
}

// GetTombstone implements StorageEngine.GetTombstone
func (s *storageEngineImpl) GetTombstone(ctx context.Context, uri string) (*Tombstone, error) {
	return s.tombstoneStore.GetTombstone(ctx, uri)
}

// ListTombstones implements StorageEngine.ListTombstones
func (s *storageEngineImpl) ListTombstones(ctx context.Context, storageRoot string) ([]*Tombstone, error) {
	return s.tombstoneStore.ListTombstones(ctx, storageRoot)
}

// RestoreFromTombstone implements StorageEngine.RestoreFromTombstone
func (s *storageEngineImpl) RestoreFromTombstone(ctx context.Context, uri string, restoreToken string) error {
	// Get tombstone
	tombstone, err := s.GetTombstone(ctx, uri)
	if err != nil {
		return fmt.Errorf("failed to get tombstone: %w", err)
	}

	// Verify restore token
	if tombstone.RestoreToken != "" && tombstone.RestoreToken != restoreToken {
		return fmt.Errorf("%w: invalid restore token", ErrPreconditionFailed)
	}

	// For now, we can't restore without a backup
	// In a production implementation, this would restore from backup
	return fmt.Errorf("restore not implemented")
}

// GetLayoutVersion implements StorageEngine.GetLayoutVersion
func (s *storageEngineImpl) GetLayoutVersion(ctx context.Context) (StorageLayoutVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.layoutVersion, nil
}

// SetLayoutVersion implements StorageEngine.SetLayoutVersion
func (s *storageEngineImpl) SetLayoutVersion(ctx context.Context, version StorageLayoutVersion) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if version < MinSupportedStorageLayoutVersion {
		return fmt.Errorf("version %d is below minimum supported version %d", version, MinSupportedStorageLayoutVersion)
	}

	s.layoutVersion = version
	return nil
}

// MigrateLayout implements StorageEngine.MigrateLayout
func (s *storageEngineImpl) MigrateLayout(ctx context.Context, targetVersion StorageLayoutVersion) error {
	// For now, layout migration is not implemented
	// In a production implementation, this would migrate from current to target version
	return fmt.Errorf("layout migration not implemented")
}

// Backup implements StorageEngine.Backup
func (s *storageEngineImpl) Backup() BackupRestore {
	return &backupRestoreImpl{
		engine: s,
		logger: s.logger.With("component", "backup_restore"),
	}
}

// Integrity implements StorageEngine.Integrity
func (s *storageEngineImpl) Integrity() IntegrityScanner {
	return &integrityScannerImpl{
		engine: s,
		logger: s.logger.With("component", "integrity_scanner"),
	}
}

// HealthCheck implements StorageEngine.HealthCheck
func (s *storageEngineImpl) HealthCheck(ctx context.Context) error {
	// Check default backend health
	if err := s.defaultBackend.HealthCheck(ctx); err != nil {
		return fmt.Errorf("default backend health check failed: %w", err)
	}

	// Check all registered backends
	for name, backend := range s.backends {
		if err := backend.HealthCheck(ctx); err != nil {
			return fmt.Errorf("backend %q health check failed: %w", name, err)
		}
	}

	return nil
}

// Close implements StorageEngine.Close
func (s *storageEngineImpl) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true
	close(s.closeChan)

	// Close all backends
	for name, backend := range s.backends {
		if err := backend.Close(); err != nil {
			s.logger.Error("Error closing backend", "name", name, "error", err)
		}
	}

	s.logger.Info("Storage engine closed")
	return nil
}

// isTombstoned checks if a resource is tombstoned
func (s *storageEngineImpl) isTombstoned(ctx context.Context, uri string) (bool, error) {
	if !s.config.EnableTombstones {
		return false, nil
	}

	tombstone, err := s.tombstoneStore.GetTombstone(ctx, uri)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}

	return tombstone != nil, nil
}

// handlePreconditions handles write preconditions
func (s *storageEngineImpl) handlePreconditions(ctx context.Context, resource *WriteResource) error {
	// Check If-None-Match precondition
	if resource.Preconditions.IfNoneMatch != "" {
		if resource.Preconditions.IfNoneMatch == "*" {
			// Resource must not exist
			exists, err := s.Exists(ctx, resource.URI)
			if err != nil {
				return fmt.Errorf("failed to check existence for If-None-Match: %w", err)
			}
			if exists {
				return ErrPreconditionFailed
			}
		} else {
			// Resource must not have this specific ETag
			metadata, err := s.GetMetadata(ctx, resource.URI)
			if err != nil {
				if errors.Is(err, ErrNotFound) {
					// Resource doesn't exist, precondition is satisfied
					return nil
				}
				return fmt.Errorf("failed to get metadata for If-None-Match: %w", err)
			}
			if metadata.ETag == resource.Preconditions.IfNoneMatch {
				return ErrPreconditionFailed
			}
		}
	}

	// Check If-Match precondition
	if resource.Preconditions.IfMatch != "" {
		if resource.Preconditions.IfMatch == "*" {
			// Resource must exist
			exists, err := s.Exists(ctx, resource.URI)
			if err != nil {
				return fmt.Errorf("failed to check existence for If-Match: %w", err)
			}
			if !exists {
				return ErrPreconditionFailed
			}
		} else {
			// Resource must have this specific ETag
			metadata, err := s.GetMetadata(ctx, resource.URI)
			if err != nil {
				if errors.Is(err, ErrNotFound) {
					return ErrPreconditionFailed
				}
				return fmt.Errorf("failed to get metadata for If-Match: %w", err)
			}
			if metadata.ETag != resource.Preconditions.IfMatch {
				return ErrPreconditionFailed
			}
		}
	}

	// Check Compare-And-Swap precondition
	if resource.Preconditions.CompareAndSwap != nil {
		cas := resource.Preconditions.CompareAndSwap
		metadata, err := s.GetMetadata(ctx, resource.URI)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return ErrPreconditionFailed
			}
			return fmt.Errorf("failed to get metadata for CompareAndSwap: %w", err)
		}

		currentValue, exists := metadata.Custom[cas.Key]
		if !exists {
			currentValue = ""
		}

		if currentValue != cas.ExpectedValue {
			return ErrPreconditionFailed
		}
	}

	return nil
}

// Utility functions

// validateStorageURI validates a storage URI
func validateStorageURI(uri string) error {
	if uri == "" {
		return ErrInvalidURI
	}

	// Prevent path traversal
	if strings.Contains(uri, "..") {
		return ErrInvalidURI
	}

	// Prevent null bytes
	if strings.Contains(uri, "\x00") {
		return ErrInvalidURI
	}

	// More validation could be added here
	return nil
}

// validateResource validates a resource for storage
func validateResource(resource *WriteResource) error {
	if resource.URI == "" {
		return ErrInvalidURI
	}

	// Check body size
	if resource.Body != nil && len(resource.Body) == 0 {
		resource.Body = nil
	}

	return nil
}

// detectContentType detects the content type based on URI and data
func detectContentType(uri string, data []byte) string {
	// Simple detection based on URI extension
	ext := filepath.Ext(uri)

	switch ext {
	case ".ttl":
		return "text/turtle"
	case ".n3":
		return "text/n3"
	case ".json":
		return "application/json"
	case ".jsonld":
		return "application/ld+json"
	case ".rdf":
		return "application/rdf+xml"
	case ".xml":
		return "application/xml"
	case ".html", ".htm":
		return "text/html"
	case ".txt":
		return "text/plain"
	case ".jpeg", ".jpg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	default:
		// Check if data looks like JSON
		if len(data) > 0 && (data[0] == '{' || data[0] == '[') {
			return "application/json"
		}
		// Check if data looks like Turtle
		if len(data) > 0 && strings.HasPrefix(string(data), "@prefix") {
			return "text/turtle"
		}
		return "application/octet-stream"
	}
}

// init initializes the storage package
func init() {
	// Don't initialize here to avoid side effects
	// Initialization should be explicit
}
