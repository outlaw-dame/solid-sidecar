// Package storage provides the production storage engine for the Solid runtime.
// This file implements the filesystem storage backend.
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FilesystemBackendConfig holds configuration for the filesystem backend
type FilesystemBackendConfig struct {
	RootPath string
	Logger   *slog.Logger
}

// filesystemBackend implements StorageBackend using the local filesystem
type filesystemBackend struct {
	config FilesystemBackendConfig
	logger *slog.Logger
	mu     sync.RWMutex
	closed bool

	// Quota tracking
	quotaUsage map[string]*quotaUsageInfo

	// Tombstone tracking
	tombstones map[string]*Tombstone
}

// NewFilesystemBackend creates a new filesystem storage backend
func NewFilesystemBackend(config FilesystemBackendConfig) StorageBackend {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.RootPath == "" {
		config.RootPath = "./storage"
	}
	return &filesystemBackend{
		config:     config,
		logger:     config.Logger.With("backend", "filesystem"),
		quotaUsage: make(map[string]*quotaUsageInfo),
		tombstones: make(map[string]*Tombstone),
	}
}

func (b *filesystemBackend) Name() string        { return "filesystem" }
func (b *filesystemBackend) Description() string { return "Local filesystem storage backend" }

func (b *filesystemBackend) Initialize(ctx context.Context, config map[string]string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	if rootPath, ok := config["root_path"]; ok && rootPath != "" {
		b.config.RootPath = rootPath
	}

	if err := os.MkdirAll(b.config.RootPath, 0750); err != nil {
		return err
	}

	// Initialize metadata directory
	metadataDir := filepath.Join(b.config.RootPath, ".metadata")
	if err := os.MkdirAll(metadataDir, 0750); err != nil {
		return err
	}

	// Initialize blobs directory
	blobsDir := filepath.Join(b.config.RootPath, "blobs")
	if err := os.MkdirAll(blobsDir, 0750); err != nil {
		return err
	}

	// Initialize tombstones directory
	tombstonesDir := filepath.Join(b.config.RootPath, ".tombstones")
	if err := os.MkdirAll(tombstonesDir, 0750); err != nil {
		return err
	}

	// Load existing tombstones
	if err := b.loadTombstones(ctx); err != nil {
		b.logger.Warn("Failed to load existing tombstones", "error", err)
	}

	// Load existing quota info
	if err := b.loadQuotaInfo(ctx); err != nil {
		b.logger.Warn("Failed to load existing quota info", "error", err)
	}

	return nil
}

func (b *filesystemBackend) HealthCheck(ctx context.Context) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return ErrStorageClosed
	}

	if _, err := os.Stat(b.config.RootPath); err != nil {
		return SanitizeError(fmt.Errorf("storage backend not accessible: %w", err))
	}

	return nil
}

func (b *filesystemBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true
	b.quotaUsage = nil
	b.tombstones = nil

	return nil
}

func (b *filesystemBackend) checkClosed() error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return ErrStorageClosed
	}
	return nil
}

func (b *filesystemBackend) checkClosedNoLock() error {
	if b.closed {
		return ErrStorageClosed
	}
	return nil
}

func (b *filesystemBackend) uriToPath(uri string) string {
	cleanURI := strings.Trim(uri, "/")
	if cleanURI == "" {
		cleanURI = "root"
	}
	safeURI := strings.ReplaceAll(cleanURI, "/", string(filepath.Separator))
	safeURI = strings.ReplaceAll(safeURI, ":", "_")
	safeURI = strings.ReplaceAll(safeURI, "?", "_")
	return filepath.Join(b.config.RootPath, safeURI)
}

func (b *filesystemBackend) pathToURI(path string) string {
	relativePath := strings.TrimPrefix(path, b.config.RootPath)
	if relativePath == "" {
		return "/"
	}
	uri := strings.ReplaceAll(relativePath, string(filepath.Separator), "/")
	uri = strings.ReplaceAll(uri, "\\", "/")
	if !strings.HasPrefix(uri, "/") {
		uri = "/" + uri
	}
	return uri
}

func (b *filesystemBackend) metadataPath(uri string) string {
	filePath := b.uriToPath(uri)
	return filePath + ".meta.json"
}

func (b *filesystemBackend) Get(ctx context.Context, uri string) (*Resource, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := b.checkClosedNoLock(); err != nil {
		return nil, err
	}

	// Validate URI is not empty
	if uri == "" {
		return nil, SanitizeError(ErrEmptyURI)
	}

	// Check if tombstoned
	if _, exists := b.tombstones[uri]; exists {
		return nil, ErrNotFound
	}

	filePath := b.uriToPath(uri)
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, SanitizeError(fmt.Errorf("failed to read resource: %w", err))
	}

	var metadata Metadata
	metadataPath := b.metadataPath(uri)
	if metadataData, err := os.ReadFile(metadataPath); err == nil {
		if err := json.Unmarshal(metadataData, &metadata); err != nil {
			return nil, fmt.Errorf("failed to parse metadata: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	// Ensure metadata has required fields
	if metadata.URI == "" {
		metadata.URI = uri
	}
	if metadata.Size == 0 && len(data) > 0 {
		metadata.Size = int64(len(data))
	}
	if metadata.LastModified.IsZero() {
		fileInfo, err := os.Stat(filePath)
		if err == nil {
			metadata.LastModified = fileInfo.ModTime().UTC()
		}
	}
	if metadata.ETag == "" {
		metadata.ETag = generateETag(data)
	}
	if metadata.ResourceType == "" {
		metadata.ResourceType = ResourceTypeResource
	}

	return &Resource{URI: uri, Body: data, Metadata: metadata}, nil
}

func (b *filesystemBackend) GetMetadata(ctx context.Context, uri string) (*Metadata, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := b.checkClosedNoLock(); err != nil {
		return nil, err
	}

	// Check if tombstoned
	if _, exists := b.tombstones[uri]; exists {
		return nil, ErrNotFound
	}

	filePath := b.uriToPath(uri)
	metadataPath := b.metadataPath(uri)

	// Try to read metadata file
	metadataData, err := os.ReadFile(metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			// If metadata file doesn't exist, check if the resource file exists
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				return nil, ErrNotFound
			}
			// Resource exists but no metadata - return basic metadata
			fileInfo, err := os.Stat(filePath)
			if err != nil {
				return nil, SanitizeError(fmt.Errorf("failed to stat resource: %w", err))
			}

			return &Metadata{
				URI:          uri,
				ResourceType: ResourceTypeResource,
				Size:         fileInfo.Size(),
				LastModified: fileInfo.ModTime().UTC(),
				ETag:         generateETagFromFilePath(filePath),
			}, nil
		}
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	var metadata Metadata
	if err := json.Unmarshal(metadataData, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	// Validate metadata
	if metadata.URI == "" {
		metadata.URI = uri
	}
	if metadata.Size == 0 {
		fileInfo, err := os.Stat(filePath)
		if err == nil {
			metadata.Size = fileInfo.Size()
		}
	}

	return &metadata, nil
}

func (b *filesystemBackend) Put(ctx context.Context, uri string, resource *WriteResource) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.checkClosedNoLock(); err != nil {
		return err
	}

	// Validate resource is not nil
	if resource == nil {
		return fmt.Errorf("resource cannot be nil")
	}

	// Validate URI is not empty
	if uri == "" {
		return fmt.Errorf("URI cannot be empty")
	}

	// Handle conditional writes (preconditions)
	if resource.Preconditions.IfMatch != "" || resource.Preconditions.IfNoneMatch != "" {
		currentResource, err := b.getResourceNoLock(uri)
		if err != nil && !os.IsNotExist(err) && !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("failed to check preconditions: %w", err)
		}

		if resource.Preconditions.IfMatch != "" {
			if resource.Preconditions.IfMatch == "*" {
				// Requires resource to exist
				if err != nil {
					return ErrPreconditionFailed
				}
			} else {
				// Requires specific ETag match
				if currentResource == nil || currentResource.Metadata.ETag != resource.Preconditions.IfMatch {
					return ErrPreconditionFailed
				}
			}
		}

		if resource.Preconditions.IfNoneMatch != "" {
			if resource.Preconditions.IfNoneMatch == "*" {
				// Requires resource to NOT exist
				if currentResource != nil {
					return ErrPreconditionFailed
				}
			} else {
				// Requires specific ETag to NOT match
				if currentResource != nil && currentResource.Metadata.ETag == resource.Preconditions.IfNoneMatch {
					return ErrPreconditionFailed
				}
			}
		}
	}

	filePath := b.uriToPath(uri)

	// Create parent directories
	if err := os.MkdirAll(filepath.Dir(filePath), 0750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Handle body
	body := resource.Body
	if body == nil && resource.BodyReader != nil {
		var err error
		body, err = io.ReadAll(resource.BodyReader)
		if err != nil {
			return SanitizeError(fmt.Errorf("failed to read body: %w", err))
		}
	}

	// Check quota
	storageRoot := resource.Metadata.StorageRoot
	if storageRoot == "" {
		storageRoot = uri
		if idx := strings.Index(uri, "/"); idx > 0 {
			storageRoot = uri[:idx]
		}
	}

	// Calculate size for quota: body size + estimated metadata size
	resourceSize := int64(0)
	if body != nil {
		resourceSize += int64(len(body))
	}

	// Add estimated metadata size
	metadataSize := estimateMetadataSize(&resource.Metadata)
	resourceSize += metadataSize

	if resourceSize > 0 {
		if err := b.checkAndUpdateQuota(storageRoot, resourceSize); err != nil {
			return err
		}
	}

	// Write the file
	if err := os.WriteFile(filePath, body, 0640); err != nil {
		// Rollback quota on failure
		if body != nil && storageRoot != "" {
			b.rollbackQuota(storageRoot, int64(len(body)))
		}
		return SanitizeError(fmt.Errorf("failed to write resource: %w", err))
	}

	// Prepare and write metadata
	metadata := resource.Metadata
	if metadata.URI == "" {
		metadata.URI = uri
	}
	if metadata.Size == 0 && body != nil {
		metadata.Size = int64(len(body))
	}
	if metadata.LastModified.IsZero() {
		metadata.LastModified = time.Now().UTC()
	}
	if metadata.ETag == "" && body != nil {
		metadata.ETag = generateETag(body)
	}
	if metadata.ResourceType == "" {
		metadata.ResourceType = ResourceTypeResource
	}
	if metadata.StorageRoot == "" {
		metadata.StorageRoot = storageRoot
	}
	if metadata.LayoutVersion == 0 {
		metadata.LayoutVersion = CurrentStorageLayoutVersion
	}

	metadataData, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := os.WriteFile(b.metadataPath(uri), metadataData, 0640); err != nil {
		return SanitizeError(fmt.Errorf("failed to write metadata: %w", err))
	}

	// Remove tombstone if it exists
	delete(b.tombstones, uri)

	return nil
}

func (b *filesystemBackend) getResourceNoLock(uri string) (*Resource, error) {
	// Validate URI - this method is called with lock already held
	if uri == "" {
		return nil, ErrEmptyURI
	}

	filePath := b.uriToPath(uri)

	// Check if tombstoned
	if _, exists := b.tombstones[uri]; exists {
		return nil, ErrNotFound
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	var metadata Metadata
	metadataPath := b.metadataPath(uri)
	if metadataData, err := os.ReadFile(metadataPath); err == nil {
		json.Unmarshal(metadataData, &metadata)
	}

	return &Resource{URI: uri, Body: data, Metadata: metadata}, nil
}

func (b *filesystemBackend) Delete(ctx context.Context, uri string) error {
	if ctx == nil {
		return ErrNilContext
	}

	// Validate URI
	validatedURI, err := ValidateURI(uri)
	if err != nil {
		return SanitizeError(err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.checkClosedNoLock(); err != nil {
		return SanitizeError(err)
	}

	filePath := b.uriToPath(validatedURI)
	metadataPath := b.metadataPath(uri)

	// Get metadata for quota tracking
	var metadata Metadata
	if metadataData, err := os.ReadFile(metadataPath); err == nil {
		json.Unmarshal(metadataData, &metadata)
	}

	// Remove the file
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return SanitizeError(fmt.Errorf("failed to remove resource: %w", err))
	}

	// Remove metadata
	if err := os.Remove(metadataPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove metadata: %w", err)
	}

	// Update quota - release used space
	if metadata.Size > 0 {
		storageRoot := metadata.StorageRoot
		if storageRoot == "" {
			storageRoot = validatedURI
			if idx := strings.Index(validatedURI, "/"); idx > 0 {
				storageRoot = validatedURI[:idx]
			}
		}
		b.rollbackQuota(storageRoot, metadata.Size)
	}

	return nil
}

func (b *filesystemBackend) List(ctx context.Context, containerURI string) ([]*Metadata, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	// Validate container URI
	validatedURI, err := ValidateURI(containerURI)
	if err != nil {
		return nil, SanitizeError(err)
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := b.checkClosedNoLock(); err != nil {
		return nil, SanitizeError(err)
	}

	containerPath := b.uriToPath(validatedURI)
	if !strings.HasSuffix(containerPath, string(filepath.Separator)) {
		containerPath += string(filepath.Separator)
	}

	entries, err := os.ReadDir(containerPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []*Metadata{}, nil
		}
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var result []*Metadata
	for _, entry := range entries {
		if entry.IsDir() || strings.HasSuffix(entry.Name(), ".meta.json") {
			continue
		}

		uri := b.pathToURI(filepath.Join(containerPath, entry.Name()))

		// Skip tombstoned resources
		if _, exists := b.tombstones[uri]; exists {
			continue
		}

		metadata, err := b.getMetadataNoLock(uri)
		if err != nil {
			continue
		}

		// Limit the number of results to prevent resource exhaustion
		if len(result) >= MaxResourceCountPerList {
			break
		}

		result = append(result, metadata)
	}

	return result, nil
}

func (b *filesystemBackend) getMetadataNoLock(uri string) (*Metadata, error) {
	// Validate URI - this method is called with lock already held
	if uri == "" {
		return nil, ErrEmptyURI
	}

	filePath := b.uriToPath(uri)
	metadataPath := b.metadataPath(uri)

	// Try to read metadata file
	metadataData, err := os.ReadFile(metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			// If metadata file doesn't exist, check if the resource file exists
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				return nil, ErrNotFound
			}
			// Resource exists but no metadata - return basic metadata
			fileInfo, err := os.Stat(filePath)
			if err != nil {
				return nil, err
			}

			return &Metadata{
				URI:          uri,
				ResourceType: ResourceTypeResource,
				Size:         fileInfo.Size(),
				LastModified: fileInfo.ModTime().UTC(),
			}, nil
		}
		return nil, err
	}

	var metadata Metadata
	if err := json.Unmarshal(metadataData, &metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

func (b *filesystemBackend) Exists(ctx context.Context, uri string) (bool, error) {
	if ctx == nil {
		return false, ErrNilContext
	}

	// Validate URI
	validatedURI, err := ValidateURI(uri)
	if err != nil {
		return false, SanitizeError(err)
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := b.checkClosedNoLock(); err != nil {
		return false, SanitizeError(err)
	}

	// Check if tombstoned
	if _, exists := b.tombstones[validatedURI]; exists {
		return false, nil
	}

	filePath := b.uriToPath(validatedURI)
	_, err = os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (b *filesystemBackend) StoreBlob(ctx context.Context, data []byte) (ContentAddress, error) {
	if ctx == nil {
		return "", ErrNilContext
	}

	// Validate data size
	if err := ValidateBodySize(data); err != nil {
		return "", SanitizeError(err)
	}

	address := computeContentAddress(data)

	// Validate the content address
	if err := ValidateContentAddress(address); err != nil {
		return "", SanitizeError(err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.checkClosedNoLock(); err != nil {
		return "", SanitizeError(err)
	}
	blobPath := filepath.Join(b.config.RootPath, "blobs", string(address))

	if err := os.MkdirAll(filepath.Dir(blobPath), 0750); err != nil {
		return "", err
	}

	if err := os.WriteFile(blobPath, data, 0640); err != nil {
		return "", err
	}

	return address, nil
}

func (b *filesystemBackend) GetBlob(ctx context.Context, address ContentAddress) ([]byte, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	// Validate content address
	if err := ValidateContentAddress(address); err != nil {
		return nil, SanitizeError(err)
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := b.checkClosedNoLock(); err != nil {
		return nil, SanitizeError(err)
	}

	blobPath := filepath.Join(b.config.RootPath, "blobs", string(address))
	data, err := os.ReadFile(blobPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, SanitizeError(err)
	}

	// Validate body size
	if err := ValidateBodySize(data); err != nil {
		return nil, SanitizeError(err)
	}

	return data, nil
}

func (b *filesystemBackend) BlobExists(ctx context.Context, address ContentAddress) (bool, error) {
	if ctx == nil {
		return false, ErrNilContext
	}

	// Validate content address
	if err := ValidateContentAddress(address); err != nil {
		return false, SanitizeError(err)
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := b.checkClosedNoLock(); err != nil {
		return false, SanitizeError(err)
	}

	blobPath := filepath.Join(b.config.RootPath, "blobs", string(address))
	_, err := os.Stat(blobPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (b *filesystemBackend) DeleteBlob(ctx context.Context, address ContentAddress) error {
	if ctx == nil {
		return ErrNilContext
	}

	// Validate content address
	if err := ValidateContentAddress(address); err != nil {
		return SanitizeError(err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.checkClosedNoLock(); err != nil {
		return SanitizeError(err)
	}

	blobPath := filepath.Join(b.config.RootPath, "blobs", string(address))
	return os.Remove(blobPath)
}

func (b *filesystemBackend) GetQuota(ctx context.Context, storageRoot string) (*QuotaInfo, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	// Validate storage root
	if err := ValidateStorageRoot(storageRoot); err != nil {
		return nil, SanitizeError(err)
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := b.checkClosedNoLock(); err != nil {
		return nil, SanitizeError(err)
	}

	usage, exists := b.quotaUsage[storageRoot]
	if !exists {
		return &QuotaInfo{
			StorageRoot:   storageRoot,
			UsedBytes:     0,
			MaxBytes:      0, // 0 means unlimited
			UsedResources: 0,
			MaxResources:  0, // 0 means unlimited
		}, nil
	}

	return &QuotaInfo{
		StorageRoot:   storageRoot,
		UsedBytes:     usage.UsedBytes,
		MaxBytes:      usage.MaxBytes,
		UsedResources: usage.UsedResources,
		MaxResources:  usage.MaxResources,
	}, nil
}

func (b *filesystemBackend) CheckQuota(ctx context.Context, storageRoot string, additionalBytes int64) error {
	if ctx == nil {
		return ErrNilContext
	}

	// Validate additional bytes
	if additionalBytes < 0 {
		return SanitizeError(fmt.Errorf("additional bytes cannot be negative"))
	}

	// Validate storage root
	if err := ValidateStorageRoot(storageRoot); err != nil {
		return SanitizeError(err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.checkClosedNoLock(); err != nil {
		return SanitizeError(err)
	}

	return b.checkAndUpdateQuota(storageRoot, additionalBytes)
}

func (b *filesystemBackend) checkAndUpdateQuota(storageRoot string, additionalBytes int64) error {
	usage, exists := b.quotaUsage[storageRoot]
	if !exists {
		usage = &quotaUsageInfo{
			UsedBytes:     0,
			UsedResources: 0,
			MaxBytes:      0, // unlimited
			MaxResources:  0, // unlimited
		}
		b.quotaUsage[storageRoot] = usage
	}

	// Check byte quota
	if usage.MaxBytes > 0 && usage.UsedBytes+additionalBytes > usage.MaxBytes {
		return ErrQuotaExceeded
	}

	// Check resource quota (each resource counts as at least 1 byte)
	if usage.MaxResources > 0 && usage.UsedResources+1 > usage.MaxResources {
		return ErrQuotaExceeded
	}

	// Update usage
	usage.UsedBytes += additionalBytes
	usage.UsedResources += 1

	// Save quota info
	if err := b.saveQuotaInfo(storageRoot, usage); err != nil {
		b.logger.Warn("Failed to save quota info", "storageRoot", storageRoot, "error", err)
	}

	return nil
}

func (b *filesystemBackend) rollbackQuota(storageRoot string, bytesFreed int64) {
	usage, exists := b.quotaUsage[storageRoot]
	if !exists {
		return
	}

	usage.UsedBytes -= bytesFreed
	if usage.UsedBytes < 0 {
		usage.UsedBytes = 0
	}
	usage.UsedResources -= 1
	if usage.UsedResources < 0 {
		usage.UsedResources = 0
	}

	// Save quota info
	b.saveQuotaInfo(storageRoot, usage)
}

func (b *filesystemBackend) saveQuotaInfo(storageRoot string, usage *quotaUsageInfo) error {
	data, err := json.MarshalIndent(usage, "", "  ")
	if err != nil {
		return err
	}

	quotaPath := filepath.Join(b.config.RootPath, ".metadata", "quota_"+strings.ReplaceAll(storageRoot, "/", "_")+".json")
	return os.WriteFile(quotaPath, data, 0640)
}

func (b *filesystemBackend) loadQuotaInfo(ctx context.Context) error {
	quotaDir := filepath.Join(b.config.RootPath, ".metadata")
	entries, err := os.ReadDir(quotaDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "quota_") && strings.HasSuffix(entry.Name(), ".json") {
			quotaPath := filepath.Join(quotaDir, entry.Name())
			data, err := os.ReadFile(quotaPath)
			if err != nil {
				continue
			}

			var usage quotaUsageInfo
			if err := json.Unmarshal(data, &usage); err != nil {
				continue
			}

			// Extract storage root from filename
			storageRoot := strings.TrimPrefix(entry.Name(), "quota_")
			storageRoot = strings.TrimSuffix(storageRoot, ".json")
			storageRoot = strings.ReplaceAll(storageRoot, "_", "/")
			if storageRoot == "" {
				storageRoot = "/"
			}

			b.quotaUsage[storageRoot] = &usage
		}
	}

	return nil
}

func (b *filesystemBackend) GetTombstone(ctx context.Context, uri string) (*Tombstone, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	// Validate URI
	validatedURI, err := ValidateURI(uri)
	if err != nil {
		return nil, SanitizeError(err)
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := b.checkClosedNoLock(); err != nil {
		return nil, SanitizeError(err)
	}

	tombstone, exists := b.tombstones[validatedURI]
	if !exists {
		return nil, ErrNotFound
	}

	return tombstone, nil
}

func (b *filesystemBackend) StoreTombstone(ctx context.Context, tombstone *Tombstone) error {
	if ctx == nil {
		return ErrNilContext
	}

	// Validate tombstone is not nil
	if tombstone == nil {
		return SanitizeError(ErrNilTombstone)
	}

	// Validate tombstone fields
	if err := validateTombstone(tombstone); err != nil {
		return SanitizeError(err)
	}

	// Validate and normalize URI
	validatedURI, err := ValidateURI(tombstone.URI)
	if err != nil {
		return SanitizeError(err)
	}

	// Set default values
	if tombstone.DeletedAt.IsZero() {
		tombstone.DeletedAt = time.Now().UTC()
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.checkClosedNoLock(); err != nil {
		return SanitizeError(err)
	}

	// Store tombstone in memory
	b.tombstones[validatedURI] = tombstone

	// Save tombstone to disk
	// Remove leading slash and replace remaining slashes with underscores
	sanitizedURI := strings.TrimPrefix(tombstone.URI, "/")
	sanitizedURI = strings.ReplaceAll(sanitizedURI, "/", "_")
	tombstonePath := filepath.Join(b.config.RootPath, ".tombstones", sanitizedURI+".json")
	if err := os.MkdirAll(filepath.Dir(tombstonePath), 0750); err != nil {
		return err
	}

	data, err := json.MarshalIndent(tombstone, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(tombstonePath, data, 0640); err != nil {
		return err
	}

	// Delete the actual resource
	filePath := b.uriToPath(validatedURI)
	os.Remove(filePath)
	os.Remove(b.metadataPath(validatedURI))

	return nil
}

func (b *filesystemBackend) DeleteTombstone(ctx context.Context, uri string) error {
	if ctx == nil {
		return ErrNilContext
	}

	// Validate URI
	validatedURI, err := ValidateURI(uri)
	if err != nil {
		return SanitizeError(err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.checkClosedNoLock(); err != nil {
		return SanitizeError(err)
	}

	// Remove from memory
	delete(b.tombstones, validatedURI)

	// Remove from disk
	// Remove leading slash and replace remaining slashes with underscores
	sanitizedURI := strings.TrimPrefix(validatedURI, "/")
	sanitizedURI = strings.ReplaceAll(sanitizedURI, "/", "_")
	tombstonePath := filepath.Join(b.config.RootPath, ".tombstones", sanitizedURI+".json")
	os.Remove(tombstonePath)

	return nil
}

func (b *filesystemBackend) ListTombstones(ctx context.Context, storageRoot string) ([]*Tombstone, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	// Validate storage root
	if err := ValidateStorageRoot(storageRoot); err != nil {
		return nil, SanitizeError(err)
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := b.checkClosedNoLock(); err != nil {
		return nil, SanitizeError(err)
	}

	var result []*Tombstone
	for uri, tombstone := range b.tombstones {
		// Filter by storage root if specified
		if storageRoot == "" || strings.HasPrefix(uri, storageRoot) || uri == storageRoot {
			result = append(result, tombstone)

			// Limit the number of results to prevent resource exhaustion
			if len(result) >= MaxResourceCountPerList {
				break
			}
		}
	}

	return result, nil
}

func (b *filesystemBackend) loadTombstones(ctx context.Context) error {
	tombstonesDir := filepath.Join(b.config.RootPath, ".tombstones")
	entries, err := os.ReadDir(tombstonesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			tombstonePath := filepath.Join(tombstonesDir, entry.Name())
			data, err := os.ReadFile(tombstonePath)
			if err != nil {
				continue
			}

			var tombstone Tombstone
			if err := json.Unmarshal(data, &tombstone); err != nil {
				continue
			}

			// Convert filename back to URI
			uri := strings.ReplaceAll(entry.Name(), "_", "/")
			uri = strings.TrimSuffix(uri, ".json")
			if uri == "" {
				uri = "/"
			} else if !strings.HasPrefix(uri, "/") {
				uri = "/" + uri
			}

			tombstone.URI = uri
			b.tombstones[uri] = &tombstone
		}
	}

	return nil
}

func (b *filesystemBackend) GetLayoutVersion(ctx context.Context) (StorageLayoutVersion, error) {
	if ctx == nil {
		return 0, ErrNilContext
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := b.checkClosedNoLock(); err != nil {
		return 0, SanitizeError(err)
	}

	versionPath := filepath.Join(b.config.RootPath, ".metadata", "layout_version")
	data, err := os.ReadFile(versionPath)
	if err != nil {
		if os.IsNotExist(err) {
			return CurrentStorageLayoutVersion, nil
		}
		return 0, err
	}

	var version StorageLayoutVersion
	if _, err := fmt.Sscanf(string(data), "%d", &version); err != nil {
		return CurrentStorageLayoutVersion, nil
	}

	return version, nil
}

func (b *filesystemBackend) SetLayoutVersion(ctx context.Context, version StorageLayoutVersion) error {
	if ctx == nil {
		return ErrNilContext
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.checkClosedNoLock(); err != nil {
		return SanitizeError(err)
	}

	if version < MinSupportedStorageLayoutVersion {
		return SanitizeError(fmt.Errorf("version %d is below minimum supported version %d", version, MinSupportedStorageLayoutVersion))
	}

	versionPath := filepath.Join(b.config.RootPath, ".metadata", "layout_version")
	if err := os.MkdirAll(filepath.Dir(versionPath), 0750); err != nil {
		return err
	}

	return os.WriteFile(versionPath, []byte(fmt.Sprintf("%d", version)), 0640)
}

func (b *filesystemBackend) Backup(ctx context.Context, writer io.Writer) error {
	if ctx == nil {
		return ErrNilContext
	}

	if writer == nil {
		return fmt.Errorf("writer cannot be nil")
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := b.checkClosedNoLock(); err != nil {
		return SanitizeError(err)
	}

	// Create backup manifest
	manifest := map[string]interface{}{
		"backend":   b.Name(),
		"root_path": b.config.RootPath,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"version":   CurrentStorageLayoutVersion,
	}

	var resources []string
	var metadataFiles []string
	var blobFiles []string
	var tombstoneFiles []string

	// Walk through all files
	rootPath := b.config.RootPath
	if err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(rootPath, path)
		if err != nil {
			return err
		}

		// Skip hidden files and directories (except our special directories)
		if strings.HasPrefix(relPath, ".") {
			if strings.HasPrefix(relPath, ".tombstones") || strings.HasPrefix(relPath, ".metadata") {
				// Include these
			} else {
				return nil
			}
		}

		// Categorize files
		if strings.HasSuffix(relPath, ".meta.json") {
			metadataFiles = append(metadataFiles, relPath)
		} else if strings.HasPrefix(relPath, "blobs") {
			blobFiles = append(blobFiles, relPath)
		} else if strings.HasPrefix(relPath, ".tombstones") {
			tombstoneFiles = append(tombstoneFiles, relPath)
		} else {
			resources = append(resources, relPath)
		}

		return nil
	}); err != nil {
		return fmt.Errorf("failed to walk storage directory: %w", err)
	}

	manifest["resources"] = resources
	manifest["metadata"] = metadataFiles
	manifest["blobs"] = blobFiles
	manifest["tombstones"] = tombstoneFiles

	data, _ := json.MarshalIndent(manifest, "", "  ")
	if _, err := writer.Write(append(data, '\n')); err != nil {
		return err
	}

	// Write all resource files
	for _, relPath := range resources {
		fullPath := filepath.Join(rootPath, relPath)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}

		// Write file header
		fileHeader := fmt.Sprintf("---- FILE: %s ----\n", relPath)
		if _, err := writer.Write([]byte(fileHeader)); err != nil {
			return err
		}

		// Write file size
		sizeHeader := fmt.Sprintf("Content-Length: %d\n\n", len(data))
		if _, err := writer.Write([]byte(sizeHeader)); err != nil {
			return err
		}

		// Write file content
		if _, err := writer.Write(data); err != nil {
			return err
		}

		if _, err := writer.Write([]byte("\n")); err != nil {
			return err
		}
	}

	return nil
}

func (b *filesystemBackend) Restore(ctx context.Context, reader io.Reader) error {
	if ctx == nil {
		return ErrNilContext
	}

	if reader == nil {
		return fmt.Errorf("reader cannot be nil")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.checkClosedNoLock(); err != nil {
		return SanitizeError(err)
	}

	// Read manifest
	var manifest map[string]interface{}
	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("failed to parse backup manifest: %w", err)
	}

	// Check backend compatibility
	if backend, ok := manifest["backend"].(string); !ok || backend != "filesystem" {
		return SanitizeError(fmt.Errorf("incompatible backup: expected filesystem backend"))
	}

	return nil
}

func (b *filesystemBackend) ScanIntegrity(ctx context.Context) (*IntegrityReport, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := b.checkClosedNoLock(); err != nil {
		return nil, SanitizeError(err)
	}

	report := &IntegrityReport{
		ScannedAt:           time.Now().UTC(),
		TotalResources:      0,
		ResourcesWithIssues: 0,
		ResourceReports:     []ResourceIntegrityReport{},
	}

	rootPath := b.config.RootPath

	// Walk through all resource files (excluding metadata, blobs, tombstones)
	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(rootPath, path)
		if err != nil {
			return err
		}

		// Skip special directories and metadata files
		if strings.HasPrefix(relPath, ".") || strings.HasPrefix(relPath, "blobs") {
			return nil
		}

		// Skip metadata files
		if strings.HasSuffix(relPath, ".meta.json") {
			return nil
		}

		report.TotalResources++

		// Check integrity for this resource
		uri := b.pathToURI(path)
		resourceReport, err := b.scanResourceIntegrity(uri)
		if err != nil {
			b.logger.Warn("Failed to scan resource integrity", "uri", uri, "error", err)
			return nil
		}

		if len(resourceReport.Issues) > 0 {
			report.ResourcesWithIssues++
		}

		report.ResourceReports = append(report.ResourceReports, *resourceReport)

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to scan integrity: %w", err)
	}

	return report, nil
}

func (b *filesystemBackend) scanResourceIntegrity(uri string) (*ResourceIntegrityReport, error) {
	report := &ResourceIntegrityReport{
		URI:    uri,
		Issues: []IntegrityIssue{},
	}

	// Get the resource
	resource, err := b.getResourceNoLock(uri)
	if err != nil {
		// If resource doesn't exist, check if there's metadata without body
		_, err2 := b.getMetadataNoLock(uri)
		if err2 == nil {
			// Metadata exists but no body - this is an issue
			report.Issues = append(report.Issues, IntegrityIssue{
				Type:        IssueTypeMetadataBodyMismatch,
				Severity:    SeverityHigh,
				Description: "Metadata exists but resource body is missing",
				Details: map[string]string{
					"uri": uri,
				},
			})
		}
		return report, nil
	}

	// Check if metadata exists
	metadataPath := b.metadataPath(uri)
	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		// No metadata - this might be acceptable for some resources
		// But it's still an issue for integrity
		report.Issues = append(report.Issues, IntegrityIssue{
			Type:        IssueTypeMissingDigest,
			Severity:    SeverityMedium,
			Description: "Resource is missing metadata file",
			Details: map[string]string{
				"uri": uri,
			},
		})
		return report, nil
	}

	// Check if digest matches
	if resource.Metadata.Digest != "" {
		computedDigest := computeDigest(resource.Body)
		if resource.Metadata.Digest != computedDigest {
			report.Issues = append(report.Issues, IntegrityIssue{
				Type:        IssueTypeInvalidDigest,
				Severity:    SeverityCritical,
				Description: "Resource digest does not match metadata",
				Details: map[string]string{
					"uri":      uri,
					"expected": resource.Metadata.Digest,
					"computed": computedDigest,
				},
			})
		}
	} else {
		// No digest stored - generate one
		report.Issues = append(report.Issues, IntegrityIssue{
			Type:        IssueTypeMissingDigest,
			Severity:    SeverityLow,
			Description: "Resource is missing digest in metadata",
			Details: map[string]string{
				"uri": uri,
			},
		})
	}

	// Check if size matches
	if resource.Metadata.Size != int64(len(resource.Body)) {
		report.Issues = append(report.Issues, IntegrityIssue{
			Type:        IssueTypeMetadataBodyMismatch,
			Severity:    SeverityHigh,
			Description: "Resource size does not match metadata",
			Details: map[string]string{
				"uri":      uri,
				"expected": fmt.Sprintf("%d", resource.Metadata.Size),
				"actual":   fmt.Sprintf("%d", len(resource.Body)),
			},
		})
	}

	// Check layout version
	if resource.Metadata.LayoutVersion == 0 {
		report.Issues = append(report.Issues, IntegrityIssue{
			Type:        IssueTypeLayoutVersionMismatch,
			Severity:    SeverityLow,
			Description: "Resource is missing layout version",
			Details: map[string]string{
				"uri": uri,
			},
		})
	} else if resource.Metadata.LayoutVersion < MinSupportedStorageLayoutVersion {
		report.Issues = append(report.Issues, IntegrityIssue{
			Type:        IssueTypeLayoutVersionMismatch,
			Severity:    SeverityHigh,
			Description: "Resource has unsupported layout version",
			Details: map[string]string{
				"uri":            uri,
				"layout_version": fmt.Sprintf("%d", resource.Metadata.LayoutVersion),
				"min_supported":  fmt.Sprintf("%d", MinSupportedStorageLayoutVersion),
			},
		})
	}

	return report, nil
}

// generateETagFromFilePath generates an ETag based on file path and modification time
func generateETagFromFilePath(filePath string) string {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return generateETag([]byte(filePath))
	}

	data := []byte(filePath + fileInfo.ModTime().Format(time.RFC3339))
	return generateETag(data)
}

// Ensure interface is satisfied
var _ StorageBackend = (*filesystemBackend)(nil)
