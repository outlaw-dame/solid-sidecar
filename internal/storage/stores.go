// Package storage provides the production storage engine for the Solid runtime.
// This file implements the default store implementations.
package storage

import (
	"context"
	"sync"
)

// defaultMetadataStore implements MetadataStore by delegating to the backend
type defaultMetadataStore struct {
	backend StorageBackend
}

func (s *defaultMetadataStore) GetMetadata(ctx context.Context, uri string) (*Metadata, error) {
	return s.backend.GetMetadata(ctx, uri)
}

func (s *defaultMetadataStore) StoreMetadata(ctx context.Context, uri string, metadata *Metadata) error {
	// Create a write resource with just metadata
	resource := &WriteResource{
		URI:      uri,
		Metadata: *metadata,
	}
	return s.backend.Put(ctx, uri, resource)
}

func (s *defaultMetadataStore) DeleteMetadata(ctx context.Context, uri string) error {
	return s.backend.Delete(ctx, uri)
}

func (s *defaultMetadataStore) ListMetadata(ctx context.Context, containerURI string) ([]*Metadata, error) {
	return s.backend.List(ctx, containerURI)
}

func (s *defaultMetadataStore) Exists(ctx context.Context, uri string) (bool, error) {
	return s.backend.Exists(ctx, uri)
}

// defaultBlobStore implements BlobStore by delegating to the backend
type defaultBlobStore struct {
	backend StorageBackend
}

func (s *defaultBlobStore) StoreBlob(ctx context.Context, data []byte) (ContentAddress, error) {
	// Delegate to the backend which returns the address
	return s.backend.StoreBlob(ctx, data)
}

func (s *defaultBlobStore) GetBlob(ctx context.Context, address ContentAddress) ([]byte, error) {
	return s.backend.GetBlob(ctx, address)
}

func (s *defaultBlobStore) DeleteBlob(ctx context.Context, address ContentAddress) error {
	return s.backend.DeleteBlob(ctx, address)
}

func (s *defaultBlobStore) BlobExists(ctx context.Context, address ContentAddress) (bool, error) {
	return s.backend.BlobExists(ctx, address)
}

func (s *defaultBlobStore) ListBlobs(ctx context.Context) ([]ContentAddress, error) {
	// Not implemented in basic backend
	return []ContentAddress{}, nil
}

// defaultTombstoneStore implements TombstoneStore
type defaultTombstoneStore struct {
	mu         sync.RWMutex
	tombstones map[string]*Tombstone
}

func (s *defaultTombstoneStore) GetTombstone(ctx context.Context, uri string) (*Tombstone, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tombstone, exists := s.tombstones[uri]
	if !exists {
		return nil, ErrNotFound
	}
	// Return a copy
	return &Tombstone{
		URI:          tombstone.URI,
		DeletedAt:    tombstone.DeletedAt,
		DeletedBy:    tombstone.DeletedBy,
		Reason:       tombstone.Reason,
		RestoreToken: tombstone.RestoreToken,
	}, nil
}

func (s *defaultTombstoneStore) StoreTombstone(ctx context.Context, tombstone *Tombstone) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Store a copy
	s.tombstones[tombstone.URI] = &Tombstone{
		URI:          tombstone.URI,
		DeletedAt:    tombstone.DeletedAt,
		DeletedBy:    tombstone.DeletedBy,
		Reason:       tombstone.Reason,
		RestoreToken: tombstone.RestoreToken,
	}
	return nil
}

func (s *defaultTombstoneStore) DeleteTombstone(ctx context.Context, uri string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tombstones, uri)
	return nil
}

func (s *defaultTombstoneStore) ListTombstones(ctx context.Context, storageRoot string) ([]*Tombstone, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Tombstone
	for _, tombstone := range s.tombstones {
		// For now, return all tombstones regardless of storage root
		// In a production implementation, we'd filter by storage root
		result = append(result, &Tombstone{
			URI:          tombstone.URI,
			DeletedAt:    tombstone.DeletedAt,
			DeletedBy:    tombstone.DeletedBy,
			Reason:       tombstone.Reason,
			RestoreToken: tombstone.RestoreToken,
		})
	}
	return result, nil
}

func (s *defaultTombstoneStore) TombstoneExists(ctx context.Context, uri string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.tombstones[uri]
	return exists, nil
}

// defaultQuotaManager implements QuotaManager
type defaultQuotaManager struct {
	mu     sync.RWMutex
	quotas map[string]*QuotaInfo
}

func (q *defaultQuotaManager) GetQuota(ctx context.Context, storageRoot string) (*QuotaInfo, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if quota, exists := q.quotas[storageRoot]; exists {
		return quota, nil
	}
	// Return unlimited quota by default
	return &QuotaInfo{StorageRoot: storageRoot}, nil
}

func (q *defaultQuotaManager) GetTenantQuota(ctx context.Context, tenant string) (*QuotaInfo, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if quota, exists := q.quotas[tenant]; exists {
		return quota, nil
	}
	// Return unlimited quota by default
	return &QuotaInfo{Tenant: tenant}, nil
}

func (q *defaultQuotaManager) CheckQuota(ctx context.Context, storageRoot string, additionalBytes int64) error {
	quota, err := q.GetQuota(ctx, storageRoot)
	if err != nil {
		return err
	}
	// If no max bytes limit, allow
	if quota.MaxBytes == 0 {
		return nil
	}
	// Check if we would exceed quota
	if quota.UsedBytes+additionalBytes > quota.MaxBytes {
		return ErrQuotaExceeded
	}
	return nil
}

func (q *defaultQuotaManager) RecordUsage(ctx context.Context, storageRoot string, bytesUsed int64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	quota, exists := q.quotas[storageRoot]
	if !exists {
		q.quotas[storageRoot] = &QuotaInfo{
			StorageRoot: storageRoot,
			UsedBytes:   bytesUsed,
		}
		return nil
	}
	quota.UsedBytes += bytesUsed
	return nil
}

func (q *defaultQuotaManager) ReleaseUsage(ctx context.Context, storageRoot string, bytesFreed int64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if quota, exists := q.quotas[storageRoot]; exists {
		quota.UsedBytes -= bytesFreed
		if quota.UsedBytes < 0 {
			quota.UsedBytes = 0
		}
	}
	return nil
}

func (q *defaultQuotaManager) SetQuota(ctx context.Context, storageRoot string, quota *QuotaInfo) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.quotas[storageRoot] = quota
	return nil
}
