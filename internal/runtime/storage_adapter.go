// Package runtime provides the native Go/Rust Solid runtime path.
// This file implements the adapter to connect the runtime's StorageBackend interface
// with the production storage engine from internal/storage package.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/outlaw-dame/solid-sidecar/internal/storage"
)

// Errors for the storage adapter
var (
	ErrResourceNotFound   = errors.New("resource not found")
	ErrResourceExists     = errors.New("resource already exists")
	ErrQuotaExceeded      = errors.New("quota exceeded")
	ErrStorageUnavailable = errors.New("storage unavailable")
)

// StorageEngineAdapter adapts the production storage.StorageBackend to the runtime.StorageBackend interface
// This enables the runtime's storage abstraction layer to use the actual production storage engine
type StorageEngineAdapter struct {
	// The underlying production storage backend
	backend storage.StorageBackend

	// Logger for this adapter
	logger *slog.Logger

	// Metrics for tracking adapter operations
	metrics StorageEngineAdapterMetrics
}

// StorageEngineAdapterMetrics holds metrics for the storage engine adapter
type StorageEngineAdapterMetrics struct {
	mu sync.RWMutex

	// Total requests
	TotalRequests int64

	// Successful requests
	SuccessfulRequests int64

	// Failed requests
	FailedRequests int64

	// Operations by type
	GetOperations    int64
	PutOperations    int64
	DeleteOperations int64
	ListOperations   int64

	// Last error
	LastError string
}

// RecordRequest records a request to the adapter
func (m *StorageEngineAdapterMetrics) RecordRequest(operation string, success bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.TotalRequests++
	if success {
		m.SuccessfulRequests++
	} else {
		m.FailedRequests++
		if err != nil {
			m.LastError = err.Error()
		}
	}

	switch operation {
	case "get":
		m.GetOperations++
	case "put":
		m.PutOperations++
	case "delete":
		m.DeleteOperations++
	case "list":
		m.ListOperations++
	}
}

// GetMetrics returns a copy of the current metrics
func (m *StorageEngineAdapterMetrics) GetMetrics() StorageEngineAdapterMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return StorageEngineAdapterMetrics{
		TotalRequests:      m.TotalRequests,
		SuccessfulRequests: m.SuccessfulRequests,
		FailedRequests:     m.FailedRequests,
		GetOperations:      m.GetOperations,
		PutOperations:      m.PutOperations,
		DeleteOperations:   m.DeleteOperations,
		ListOperations:     m.ListOperations,
		LastError:          m.LastError,
	}
}

// NewStorageEngineAdapter creates a new adapter that wraps a production storage backend
func NewStorageEngineAdapter(backend storage.StorageBackend, logger *slog.Logger) *StorageEngineAdapter {
	if logger == nil {
		logger = slog.Default()
	}

	return &StorageEngineAdapter{
		backend: backend,
		logger:  logger,
	}
}

// Name returns the name of the storage backend
func (a *StorageEngineAdapter) Name() string {
	return a.backend.Name()
}

// Get retrieves a resource by URI from the production storage backend
func (a *StorageEngineAdapter) Get(ctx context.Context, uri string) (*StorageResource, error) {
	a.metrics.RecordRequest("get", false, nil)

	// Validate URI
	if uri == "" {
		err := errors.New("URI cannot be empty")
		a.metrics.RecordRequest("get", false, err)
		a.logger.Warn("Get failed: empty URI")
		return nil, err
	}

	// Validate URI format
	if err := ValidateURI(uri); err != nil {
		a.metrics.RecordRequest("get", false, err)
		a.logger.Warn("Get failed: invalid URI", "uri", uri, "error", err)
		return nil, fmt.Errorf("invalid URI: %w", err)
	}

	// Call the production storage backend
	prodResource, err := a.backend.Get(ctx, uri)
	if err != nil {
		// Map known storage errors to runtime errors
		if errors.Is(err, storage.ErrNotFound) {
			a.metrics.RecordRequest("get", false, err)
			a.logger.Debug("Get failed: resource not found", "uri", uri)
			return nil, ErrResourceNotFound
		}
		if errors.Is(err, storage.ErrStorageClosed) {
			a.metrics.RecordRequest("get", false, err)
			a.logger.Error("Get failed: storage closed", "uri", uri)
			return nil, ErrStorageUnavailable
		}

		a.metrics.RecordRequest("get", false, err)
		a.logger.Error("Get failed", "uri", uri, "error", err)
		return nil, fmt.Errorf("storage error: %w", err)
	}

	// Convert production storage resource to runtime storage resource
	runtimeResource, err := a.convertToRuntimeResource(prodResource)
	if err != nil {
		a.metrics.RecordRequest("get", false, err)
		a.logger.Error("Get failed: conversion error", "uri", uri, "error", err)
		return nil, err
	}

	a.metrics.RecordRequest("get", true, nil)
	return runtimeResource, nil
}

// Put stores a resource in the production storage backend
func (a *StorageEngineAdapter) Put(ctx context.Context, uri string, resource *StorageResource) error {
	a.metrics.RecordRequest("put", false, nil)

	// Validate inputs
	if uri == "" {
		err := errors.New("URI cannot be empty")
		a.metrics.RecordRequest("put", false, err)
		a.logger.Warn("Put failed: empty URI")
		return err
	}

	if resource == nil {
		err := errors.New("resource cannot be nil")
		a.metrics.RecordRequest("put", false, err)
		a.logger.Warn("Put failed: nil resource")
		return err
	}

	// Validate URI format
	if err := ValidateURI(uri); err != nil {
		a.metrics.RecordRequest("put", false, err)
		a.logger.Warn("Put failed: invalid URI", "uri", uri, "error", err)
		return fmt.Errorf("invalid URI: %w", err)
	}

	// Convert runtime storage resource to production storage resource
	prodResource, err := a.convertToProductionResource(uri, resource)
	if err != nil {
		a.metrics.RecordRequest("put", false, err)
		a.logger.Error("Put failed: conversion error", "uri", uri, "error", err)
		return err
	}

	// Call the production storage backend
	err = a.backend.Put(ctx, uri, prodResource)
	if err != nil {
		// Map known storage errors
		if errors.Is(err, storage.ErrAlreadyExists) {
			a.metrics.RecordRequest("put", false, err)
			a.logger.Warn("Put failed: already exists", "uri", uri)
			return ErrResourceExists
		}
		if errors.Is(err, storage.ErrQuotaExceeded) {
			a.metrics.RecordRequest("put", false, err)
			a.logger.Warn("Put failed: quota exceeded", "uri", uri)
			return ErrQuotaExceeded
		}
		if errors.Is(err, storage.ErrStorageClosed) {
			a.metrics.RecordRequest("put", false, err)
			a.logger.Error("Put failed: storage closed", "uri", uri)
			return ErrStorageUnavailable
		}

		a.metrics.RecordRequest("put", false, err)
		a.logger.Error("Put failed", "uri", uri, "error", err)
		return fmt.Errorf("storage error: %w", err)
	}

	a.metrics.RecordRequest("put", true, nil)
	return nil
}

// Delete removes a resource from the production storage backend
func (a *StorageEngineAdapter) Delete(ctx context.Context, uri string) error {
	a.metrics.RecordRequest("delete", false, nil)

	// Validate URI
	if uri == "" {
		err := errors.New("URI cannot be empty")
		a.metrics.RecordRequest("delete", false, err)
		a.logger.Warn("Delete failed: empty URI")
		return err
	}

	// Validate URI format
	if err := ValidateURI(uri); err != nil {
		a.metrics.RecordRequest("delete", false, err)
		a.logger.Warn("Delete failed: invalid URI", "uri", uri, "error", err)
		return fmt.Errorf("invalid URI: %w", err)
	}

	// Call the production storage backend
	err := a.backend.Delete(ctx, uri)
	if err != nil {
		// Map known storage errors
		if errors.Is(err, storage.ErrNotFound) {
			a.metrics.RecordRequest("delete", false, err)
			a.logger.Debug("Delete failed: not found", "uri", uri)
			return ErrResourceNotFound
		}
		if errors.Is(err, storage.ErrStorageClosed) {
			a.metrics.RecordRequest("delete", false, err)
			a.logger.Error("Delete failed: storage closed", "uri", uri)
			return ErrStorageUnavailable
		}

		a.metrics.RecordRequest("delete", false, err)
		a.logger.Error("Delete failed", "uri", uri, "error", err)
		return fmt.Errorf("storage error: %w", err)
	}

	a.metrics.RecordRequest("delete", true, nil)
	return nil
}

// List lists resources in a container from the production storage backend
func (a *StorageEngineAdapter) List(ctx context.Context, containerURI string) ([]*StorageResource, error) {
	a.metrics.RecordRequest("list", false, nil)

	// Validate container URI
	if containerURI == "" {
		err := errors.New("container URI cannot be empty")
		a.metrics.RecordRequest("list", false, err)
		a.logger.Warn("List failed: empty container URI")
		return nil, err
	}

	// Validate URI format
	if err := ValidateURI(containerURI); err != nil {
		a.metrics.RecordRequest("list", false, err)
		a.logger.Warn("List failed: invalid container URI", "containerURI", containerURI, "error", err)
		return nil, fmt.Errorf("invalid container URI: %w", err)
	}

	// Call the production storage backend
	prodMetadataList, err := a.backend.List(ctx, containerURI)
	if err != nil {
		// Map known storage errors
		if errors.Is(err, storage.ErrNotFound) {
			a.metrics.RecordRequest("list", false, err)
			a.logger.Debug("List failed: container not found", "containerURI", containerURI)
			return nil, ErrResourceNotFound
		}
		if errors.Is(err, storage.ErrStorageClosed) {
			a.metrics.RecordRequest("list", false, err)
			a.logger.Error("List failed: storage closed", "containerURI", containerURI)
			return nil, ErrStorageUnavailable
		}

		a.metrics.RecordRequest("list", false, err)
		a.logger.Error("List failed", "containerURI", containerURI, "error", err)
		return nil, fmt.Errorf("storage error: %w", err)
	}

	// Convert production metadata list to runtime resource list
	runtimeResources := make([]*StorageResource, 0, len(prodMetadataList))
	for _, prodMetadata := range prodMetadataList {
		runtimeResource := a.convertMetadataToRuntimeResource(prodMetadata)
		runtimeResources = append(runtimeResources, runtimeResource)
	}

	a.metrics.RecordRequest("list", true, nil)
	return runtimeResources, nil
}

// Exists checks if a resource exists in the production storage backend
func (a *StorageEngineAdapter) Exists(ctx context.Context, uri string) (bool, error) {
	a.metrics.RecordRequest("exists", false, nil)

	// Validate URI
	if uri == "" {
		err := errors.New("URI cannot be empty")
		a.metrics.RecordRequest("exists", false, err)
		a.logger.Warn("Exists failed: empty URI")
		return false, err
	}

	// Validate URI format
	if err := ValidateURI(uri); err != nil {
		a.metrics.RecordRequest("exists", false, err)
		a.logger.Warn("Exists failed: invalid URI", "uri", uri, "error", err)
		return false, fmt.Errorf("invalid URI: %w", err)
	}

	// Call the production storage backend
	exists, err := a.backend.Exists(ctx, uri)
	if err != nil {
		// Map known storage errors
		if errors.Is(err, storage.ErrStorageClosed) {
			a.metrics.RecordRequest("exists", false, err)
			a.logger.Error("Exists failed: storage closed", "uri", uri)
			return false, ErrStorageUnavailable
		}

		a.metrics.RecordRequest("exists", false, err)
		a.logger.Error("Exists failed", "uri", uri, "error", err)
		return false, fmt.Errorf("storage error: %w", err)
	}

	a.metrics.RecordRequest("exists", true, nil)
	return exists, nil
}

// Head retrieves metadata only for a resource
func (a *StorageEngineAdapter) Head(ctx context.Context, uri string) (*StorageResourceMetadata, error) {
	a.metrics.RecordRequest("head", false, nil)

	// Validate URI
	if uri == "" {
		err := errors.New("URI cannot be empty")
		a.metrics.RecordRequest("head", false, err)
		a.logger.Warn("Head failed: empty URI")
		return nil, err
	}

	// Validate URI format
	if err := ValidateURI(uri); err != nil {
		a.metrics.RecordRequest("head", false, err)
		a.logger.Warn("Head failed: invalid URI", "uri", uri, "error", err)
		return nil, fmt.Errorf("invalid URI: %w", err)
	}

	// Call the production storage backend
	prodMetadata, err := a.backend.GetMetadata(ctx, uri)
	if err != nil {
		// Map known storage errors
		if errors.Is(err, storage.ErrNotFound) {
			a.metrics.RecordRequest("head", false, err)
			a.logger.Debug("Head failed: metadata not found", "uri", uri)
			return nil, ErrResourceNotFound
		}
		if errors.Is(err, storage.ErrStorageClosed) {
			a.metrics.RecordRequest("head", false, err)
			a.logger.Error("Head failed: storage closed", "uri", uri)
			return nil, ErrStorageUnavailable
		}

		a.metrics.RecordRequest("head", false, err)
		a.logger.Error("Head failed", "uri", uri, "error", err)
		return nil, fmt.Errorf("storage error: %w", err)
	}

	// Convert production metadata to runtime metadata
	runtimeMetadata := a.convertMetadataToRuntimeMetadata(prodMetadata)

	a.metrics.RecordRequest("head", true, nil)
	return runtimeMetadata, nil
}

// Close cleans up the adapter
func (a *StorageEngineAdapter) Close() error {
	// The adapter doesn't own the backend, so we don't close it
	// The runtime's storage abstraction layer manages the lifecycle
	return nil
}

// convertToRuntimeResource converts a production storage.Resource to a runtime.StorageResource
func (a *StorageEngineAdapter) convertToRuntimeResource(prodResource *storage.Resource) (*StorageResource, error) {
	if prodResource == nil {
		return nil, errors.New("nil production resource")
	}

	return &StorageResource{
		URI:          prodResource.URI,
		ContentType:  prodResource.Metadata.ContentType,
		Body:         prodResource.Body,
		ETag:         prodResource.Metadata.ETag,
		LastModified: prodResource.Metadata.LastModified,
		Metadata: StorageResourceMetadata{
			Size:         prodResource.Metadata.Size,
			ContentType:  prodResource.Metadata.ContentType,
			ETag:         prodResource.Metadata.ETag,
			LastModified: prodResource.Metadata.LastModified,
			Created:      prodResource.Metadata.Created,
			Custom: map[string]string{
				"resourceType": string(prodResource.Metadata.ResourceType),
				"uri":          prodResource.Metadata.URI,
				"owner":        prodResource.Metadata.Owner,
				"storageRoot":  prodResource.Metadata.StorageRoot,
				"tenant":       prodResource.Metadata.Tenant,
			},
		},
	}, nil
}

// convertToProductionResource converts a runtime.StorageResource to a production storage.WriteResource
func (a *StorageEngineAdapter) convertToProductionResource(uri string, runtimeResource *StorageResource) (*storage.WriteResource, error) {
	if runtimeResource == nil {
		return nil, errors.New("nil runtime resource")
	}

	// Map runtime resource type to production resource type from custom metadata
	var prodResourceType storage.ResourceType
	if resourceType, ok := runtimeResource.Metadata.Custom["resourceType"]; ok {
		switch resourceType {
		case "Resource":
			prodResourceType = storage.ResourceTypeResource
		case "Container":
			prodResourceType = storage.ResourceTypeContainer
		case "ACL":
			prodResourceType = storage.ResourceTypeACL
		case "ACP":
			prodResourceType = storage.ResourceTypeACP
		case "Metadata":
			prodResourceType = storage.ResourceTypeMetadata
		case "Blob":
			prodResourceType = storage.ResourceTypeBlob
		default:
			prodResourceType = storage.ResourceTypeUnknown
		}
	} else {
		prodResourceType = storage.ResourceTypeResource
	}

	// Extract additional metadata from custom fields
	var owner, storageRoot, tenant string
	if o, ok := runtimeResource.Metadata.Custom["owner"]; ok {
		owner = o
	}
	if sr, ok := runtimeResource.Metadata.Custom["storageRoot"]; ok {
		storageRoot = sr
	}
	if t, ok := runtimeResource.Metadata.Custom["tenant"]; ok {
		tenant = t
	}

	return &storage.WriteResource{
		URI:  uri,
		Body: runtimeResource.Body,
		Metadata: storage.Metadata{
			URI:           uri,
			ResourceType:  prodResourceType,
			ContentType:   runtimeResource.ContentType,
			Size:          runtimeResource.Metadata.Size,
			ETag:          runtimeResource.ETag,
			LastModified:  runtimeResource.LastModified,
			Created:       runtimeResource.Metadata.Created,
			Owner:         owner,
			StorageRoot:   storageRoot,
			Tenant:        tenant,
			LayoutVersion: storage.CurrentStorageLayoutVersion,
		},
	}, nil
}

// convertMetadataToRuntimeResource converts production metadata to a runtime resource
func (a *StorageEngineAdapter) convertMetadataToRuntimeResource(prodMetadata *storage.Metadata) *StorageResource {
	if prodMetadata == nil {
		return nil
	}

	return &StorageResource{
		URI:          prodMetadata.URI,
		ContentType:  prodMetadata.ContentType,
		Body:         nil, // No body in metadata-only response
		ETag:         prodMetadata.ETag,
		LastModified: prodMetadata.LastModified,
		Metadata: StorageResourceMetadata{
			Size:         prodMetadata.Size,
			ContentType:  prodMetadata.ContentType,
			ETag:         prodMetadata.ETag,
			LastModified: prodMetadata.LastModified,
			Created:      prodMetadata.Created,
			Custom: map[string]string{
				"resourceType": string(prodMetadata.ResourceType),
				"uri":          prodMetadata.URI,
				"owner":        prodMetadata.Owner,
				"storageRoot":  prodMetadata.StorageRoot,
				"tenant":       prodMetadata.Tenant,
			},
		},
	}
}

// convertMetadataToRuntimeMetadata converts production metadata to runtime metadata
func (a *StorageEngineAdapter) convertMetadataToRuntimeMetadata(prodMetadata *storage.Metadata) *StorageResourceMetadata {
	if prodMetadata == nil {
		return nil
	}

	return &StorageResourceMetadata{
		Size:         prodMetadata.Size,
		ContentType:  prodMetadata.ContentType,
		ETag:         prodMetadata.ETag,
		LastModified: prodMetadata.LastModified,
		Created:      prodMetadata.Created,
		Custom: map[string]string{
			"resourceType": string(prodMetadata.ResourceType),
			"uri":          prodMetadata.URI,
			"owner":        prodMetadata.Owner,
			"storageRoot":  prodMetadata.StorageRoot,
			"tenant":       prodMetadata.Tenant,
		},
	}
}

// NewStorageEngineAdapterWithBackend creates a new storage engine adapter with a specific backend
// This is the primary integration point between the runtime's storage abstraction
// and the production storage engine.
func NewStorageEngineAdapterWithBackend(backend storage.StorageBackend, logger *slog.Logger) *StorageEngineAdapter {
	if logger == nil {
		logger = slog.Default()
	}
	return NewStorageEngineAdapter(backend, logger)
}

// HealthCheck implements the StorageBackend interface for health checking
func (a *StorageEngineAdapter) HealthCheck(ctx context.Context) error {
	// The production storage backend doesn't have a HealthCheck method in its interface,
	// but we can implement a basic check by attempting a simple operation
	// For now, we just return nil to indicate healthy
	// In a production implementation, this would actually check backend health
	return nil
}
