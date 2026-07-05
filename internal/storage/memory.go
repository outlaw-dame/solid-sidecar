// Package storage provides the production storage engine for the Solid runtime.
// This file implements the in-memory storage backend for testing.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// MemoryBackendConfig holds configuration for the memory backend
type MemoryBackendConfig struct {
	Logger *slog.Logger
}

// memoryResource represents a resource stored in memory
type memoryResource struct {
	URI      string
	Body     []byte
	Metadata Metadata
}

// memoryBackend implements StorageBackend using in-memory storage
type memoryBackend struct {
	config MemoryBackendConfig
	logger *slog.Logger
	mu     sync.RWMutex
	data   map[string]*memoryResource
	blobs  map[string][]byte
	closed bool

	// Quota tracking
	quotaUsage map[string]*quotaUsageInfo

	// Tombstone tracking
	tombstones map[string]*Tombstone

	// Layout version
	layoutVersion StorageLayoutVersion
}

// NewMemoryBackend creates a new in-memory storage backend
func NewMemoryBackend(config MemoryBackendConfig) StorageBackend {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &memoryBackend{
		config:        config,
		logger:        config.Logger.With("backend", "memory"),
		data:          make(map[string]*memoryResource),
		blobs:         make(map[string][]byte),
		quotaUsage:    make(map[string]*quotaUsageInfo),
		tombstones:    make(map[string]*Tombstone),
		layoutVersion: CurrentStorageLayoutVersion,
	}
}

func (b *memoryBackend) Name() string        { return "memory" }
func (b *memoryBackend) Description() string { return "In-memory storage backend for testing" }

func (b *memoryBackend) Initialize(ctx context.Context, config map[string]string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrStorageClosed
	}

	// No initialization needed for memory backend
	return nil
}

func (b *memoryBackend) HealthCheck(ctx context.Context) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return ErrStorageClosed
	}

	return nil
}

func (b *memoryBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true
	b.data = make(map[string]*memoryResource)
	b.blobs = make(map[string][]byte)
	b.quotaUsage = nil
	b.tombstones = nil

	return nil
}

func (b *memoryBackend) checkClosed() error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return ErrStorageClosed
	}
	return nil
}

func (b *memoryBackend) checkClosedNoLock() error {
	if b.closed {
		return ErrStorageClosed
	}
	return nil
}

func (b *memoryBackend) Get(ctx context.Context, uri string) (*Resource, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := b.checkClosedNoLock(); err != nil {
		return nil, err
	}

	// Validate URI is not empty
	if uri == "" {
		return nil, fmt.Errorf("URI cannot be empty")
	}

	// Check if tombstoned
	if _, exists := b.tombstones[uri]; exists {
		return nil, ErrNotFound
	}

	resource, exists := b.data[uri]
	if !exists {
		return nil, ErrNotFound
	}

	return &Resource{URI: resource.URI, Body: resource.Body, Metadata: resource.Metadata}, nil
}

func (b *memoryBackend) GetMetadata(ctx context.Context, uri string) (*Metadata, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := b.checkClosedNoLock(); err != nil {
		return nil, err
	}

	// Check if tombstoned
	if _, exists := b.tombstones[uri]; exists {
		return nil, ErrNotFound
	}

	resource, exists := b.data[uri]
	if !exists {
		return nil, ErrNotFound
	}

	return &resource.Metadata, nil
}

func (b *memoryBackend) Put(ctx context.Context, uri string, resource *WriteResource) error {
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
		currentResource, exists := b.data[uri]

		if resource.Preconditions.IfMatch != "" {
			if resource.Preconditions.IfMatch == "*" {
				// Requires resource to exist
				if !exists {
					return ErrPreconditionFailed
				}
			} else {
				// Requires specific ETag match
				if !exists || currentResource.Metadata.ETag != resource.Preconditions.IfMatch {
					return ErrPreconditionFailed
				}
			}
		}

		if resource.Preconditions.IfNoneMatch != "" {
			if resource.Preconditions.IfNoneMatch == "*" {
				// Requires resource to NOT exist
				if exists {
					return ErrPreconditionFailed
				}
			} else {
				// Requires specific ETag to NOT match
				if exists && currentResource.Metadata.ETag == resource.Preconditions.IfNoneMatch {
					return ErrPreconditionFailed
				}
			}
		}
	}

	// Handle body
	body := resource.Body
	if body == nil && resource.BodyReader != nil {
		var err error
		body, err = io.ReadAll(resource.BodyReader)
		if err != nil {
			return fmt.Errorf("failed to read body: %w", err)
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

	if body != nil {
		if err := b.checkAndUpdateQuota(storageRoot, int64(len(body))); err != nil {
			return err
		}
	}

	// Prepare metadata
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
		metadata.LayoutVersion = b.layoutVersion
	}

	// Store the resource
	b.data[uri] = &memoryResource{URI: uri, Body: body, Metadata: metadata}

	// Remove tombstone if it exists
	delete(b.tombstones, uri)

	return nil
}

func (b *memoryBackend) Delete(ctx context.Context, uri string) error {
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

	// Get metadata for quota tracking
	var metadata Metadata
	if resource, exists := b.data[validatedURI]; exists {
		metadata = resource.Metadata
	}

	// Remove the resource
	delete(b.data, validatedURI)

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

func (b *memoryBackend) List(ctx context.Context, containerURI string) ([]*Metadata, error) {
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

	prefix := validatedURI
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	var result []*Metadata
	for uri, resource := range b.data {
		// Skip tombstoned resources
		if _, exists := b.tombstones[uri]; exists {
			continue
		}

		if strings.HasPrefix(uri, prefix) {
			metadata := resource.Metadata
			result = append(result, &metadata)

			// Limit the number of results to prevent resource exhaustion
			if len(result) >= MaxResourceCountPerList {
				break
			}
		}
	}

	return result, nil
}

func (b *memoryBackend) Exists(ctx context.Context, uri string) (bool, error) {
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

	_, exists := b.data[validatedURI]
	return exists, nil
}

func (b *memoryBackend) StoreBlob(ctx context.Context, data []byte) (ContentAddress, error) {
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

	b.blobs[string(address)] = data

	return address, nil
}

func (b *memoryBackend) GetBlob(ctx context.Context, address ContentAddress) ([]byte, error) {
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

	data, exists := b.blobs[string(address)]
	if !exists {
		return nil, ErrNotFound
	}

	// Validate body size
	if err := ValidateBodySize(data); err != nil {
		return nil, SanitizeError(err)
	}

	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

func (b *memoryBackend) BlobExists(ctx context.Context, address ContentAddress) (bool, error) {
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

	_, exists := b.blobs[string(address)]
	return exists, nil
}

func (b *memoryBackend) DeleteBlob(ctx context.Context, address ContentAddress) error {
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

	delete(b.blobs, string(address))
	return nil
}

func (b *memoryBackend) GetQuota(ctx context.Context, storageRoot string) (*QuotaInfo, error) {
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

func (b *memoryBackend) CheckQuota(ctx context.Context, storageRoot string, additionalBytes int64) error {
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

func (b *memoryBackend) checkAndUpdateQuota(storageRoot string, additionalBytes int64) error {
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

	return nil
}

func (b *memoryBackend) rollbackQuota(storageRoot string, bytesFreed int64) {
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
}

func (b *memoryBackend) GetTombstone(ctx context.Context, uri string) (*Tombstone, error) {
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

func (b *memoryBackend) StoreTombstone(ctx context.Context, tombstone *Tombstone) error {
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

	// Delete the actual resource
	delete(b.data, validatedURI)

	return nil
}

func (b *memoryBackend) DeleteTombstone(ctx context.Context, uri string) error {
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

	return nil
}

func (b *memoryBackend) ListTombstones(ctx context.Context, storageRoot string) ([]*Tombstone, error) {
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

func (b *memoryBackend) GetLayoutVersion(ctx context.Context) (StorageLayoutVersion, error) {
	if ctx == nil {
		return 0, ErrNilContext
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := b.checkClosedNoLock(); err != nil {
		return 0, SanitizeError(err)
	}

	return b.layoutVersion, nil
}

func (b *memoryBackend) SetLayoutVersion(ctx context.Context, version StorageLayoutVersion) error {
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

	b.layoutVersion = version
	return nil
}

func (b *memoryBackend) Backup(ctx context.Context, writer io.Writer) error {
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
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"version":   CurrentStorageLayoutVersion,
	}

	var resources []string
	var metadata []string
	var blobs []string
	var tombstones []string

	// Collect resource data
	for uri := range b.data {
		resources = append(resources, uri)
		metadata = append(metadata, uri+".meta")
	}

	// Collect blob data
	for address := range b.blobs {
		blobs = append(blobs, address)
	}

	// Collect tombstone data
	for uri := range b.tombstones {
		tombstones = append(tombstones, uri)
	}

	manifest["resources"] = resources
	manifest["metadata"] = metadata
	manifest["blobs"] = blobs
	manifest["tombstones"] = tombstones

	data, _ := json.MarshalIndent(manifest, "", "  ")
	if _, err := writer.Write(append(data, '\n')); err != nil {
		return err
	}

	// Write all resources
	for uri, resource := range b.data {
		fileHeader := fmt.Sprintf("---- FILE: %s ----\n", uri)
		if _, err := writer.Write([]byte(fileHeader)); err != nil {
			return err
		}

		sizeHeader := fmt.Sprintf("Content-Length: %d\n\n", len(resource.Body))
		if _, err := writer.Write([]byte(sizeHeader)); err != nil {
			return err
		}

		if _, err := writer.Write(resource.Body); err != nil {
			return err
		}

		if _, err := writer.Write([]byte("\n")); err != nil {
			return err
		}
	}

	return nil
}

func (b *memoryBackend) Restore(ctx context.Context, reader io.Reader) error {
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
	if backend, ok := manifest["backend"].(string); !ok || backend != "memory" {
		return fmt.Errorf("incompatible backup: expected memory backend, got %s", backend)
	}

	return nil
}

func (b *memoryBackend) ScanIntegrity(ctx context.Context) (*IntegrityReport, error) {
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

	// Scan all resources
	for uri, resource := range b.data {
		report.TotalResources++

		// Skip tombstoned resources
		if _, exists := b.tombstones[uri]; exists {
			continue
		}

		resourceReport, err := b.scanResourceIntegrity(uri, resource)
		if err != nil {
			b.logger.Warn("Failed to scan resource integrity", "uri", uri, "error", err)
			continue
		}

		if len(resourceReport.Issues) > 0 {
			report.ResourcesWithIssues++
		}

		report.ResourceReports = append(report.ResourceReports, *resourceReport)
	}

	return report, nil
}

func (b *memoryBackend) scanResourceIntegrity(uri string, resource *memoryResource) (*ResourceIntegrityReport, error) {
	report := &ResourceIntegrityReport{
		URI:    uri,
		Issues: []IntegrityIssue{},
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

// Ensure interface is satisfied
var _ StorageBackend = (*memoryBackend)(nil)
