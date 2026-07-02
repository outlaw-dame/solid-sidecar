// Package storage provides the production storage engine for the Solid runtime.
// This file implements the in-memory storage backend for testing.
package storage

import (
	"context"
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
}

// NewMemoryBackend creates a new in-memory storage backend
func NewMemoryBackend(config MemoryBackendConfig) StorageBackend {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &memoryBackend{
		config: config,
		logger: config.Logger.With("backend", "memory"),
		data:   make(map[string]*memoryResource),
		blobs:  make(map[string][]byte),
	}
}

func (b *memoryBackend) Name() string        { return "memory" }
func (b *memoryBackend) Description() string { return "In-memory storage backend for testing" }
func (b *memoryBackend) GetQuota(ctx context.Context, storageRoot string) (*QuotaInfo, error) {
	return &QuotaInfo{StorageRoot: storageRoot}, nil
}
func (b *memoryBackend) CheckQuota(ctx context.Context, storageRoot string, additionalBytes int64) error {
	return nil
}
func (b *memoryBackend) GetTombstone(ctx context.Context, uri string) (*Tombstone, error) {
	return nil, ErrNotFound
}
func (b *memoryBackend) StoreTombstone(ctx context.Context, tombstone *Tombstone) error {
	return nil
}
func (b *memoryBackend) DeleteTombstone(ctx context.Context, uri string) error {
	return nil
}
func (b *memoryBackend) GetLayoutVersion(ctx context.Context) (StorageLayoutVersion, error) {
	return CurrentStorageLayoutVersion, nil
}
func (b *memoryBackend) SetLayoutVersion(ctx context.Context, version StorageLayoutVersion) error {
	return nil
}
func (b *memoryBackend) Backup(ctx context.Context, writer io.Writer) error  { return nil }
func (b *memoryBackend) Restore(ctx context.Context, reader io.Reader) error { return nil }
func (b *memoryBackend) ScanIntegrity(ctx context.Context) (*IntegrityReport, error) {
	return nil, nil
}

func (b *memoryBackend) Initialize(ctx context.Context, config map[string]string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrStorageClosed
	}
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
	b.closed = true
	b.data = make(map[string]*memoryResource)
	b.blobs = make(map[string][]byte)
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

func (b *memoryBackend) Get(ctx context.Context, uri string) (*Resource, error) {
	if err := b.checkClosed(); err != nil {
		return nil, err
	}
	b.mu.RLock()
	resource, exists := b.data[uri]
	b.mu.RUnlock()
	if !exists {
		return nil, ErrNotFound
	}
	return &Resource{URI: resource.URI, Body: resource.Body, Metadata: resource.Metadata}, nil
}

func (b *memoryBackend) GetMetadata(ctx context.Context, uri string) (*Metadata, error) {
	if err := b.checkClosed(); err != nil {
		return nil, err
	}
	b.mu.RLock()
	resource, exists := b.data[uri]
	b.mu.RUnlock()
	if !exists {
		return nil, ErrNotFound
	}
	return &resource.Metadata, nil
}

func (b *memoryBackend) Put(ctx context.Context, uri string, resource *WriteResource) error {
	if err := b.checkClosed(); err != nil {
		return err
	}
	body := resource.Body
	if body == nil && resource.BodyReader != nil {
		var err error
		body, err = io.ReadAll(resource.BodyReader)
		if err != nil {
			return err
		}
	}
	metadata := resource.Metadata
	if metadata.URI == "" {
		metadata.URI = uri
	}
	if metadata.Size == 0 {
		metadata.Size = int64(len(body))
	}
	if metadata.LastModified.IsZero() {
		metadata.LastModified = time.Now()
	}
	if metadata.ETag == "" {
		metadata.ETag = generateETag(body)
	}
	b.mu.Lock()
	b.data[uri] = &memoryResource{URI: uri, Body: body, Metadata: metadata}
	b.mu.Unlock()
	return nil
}

func (b *memoryBackend) Delete(ctx context.Context, uri string) error {
	if err := b.checkClosed(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.data, uri)
	return nil
}

func (b *memoryBackend) List(ctx context.Context, containerURI string) ([]*Metadata, error) {
	if err := b.checkClosed(); err != nil {
		return nil, err
	}
	prefix := containerURI
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	var result []*Metadata
	b.mu.RLock()
	defer b.mu.RUnlock()
	for uri, resource := range b.data {
		if strings.HasPrefix(uri, prefix) {
			metadata := resource.Metadata
			result = append(result, &metadata)
		}
	}
	return result, nil
}

func (b *memoryBackend) Exists(ctx context.Context, uri string) (bool, error) {
	if err := b.checkClosed(); err != nil {
		return false, err
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, exists := b.data[uri]
	return exists, nil
}

func (b *memoryBackend) StoreBlob(ctx context.Context, data []byte) (ContentAddress, error) {
	if err := b.checkClosed(); err != nil {
		return "", err
	}
	address := ContentAddress(fmt.Sprintf("%x", sha256Sum(data)))
	b.mu.Lock()
	b.blobs[string(address)] = data
	b.mu.Unlock()
	return address, nil
}

func (b *memoryBackend) GetBlob(ctx context.Context, address ContentAddress) ([]byte, error) {
	if err := b.checkClosed(); err != nil {
		return nil, err
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	data, exists := b.blobs[string(address)]
	if !exists {
		return nil, ErrNotFound
	}
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

func (b *memoryBackend) BlobExists(ctx context.Context, address ContentAddress) (bool, error) {
	if err := b.checkClosed(); err != nil {
		return false, err
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, exists := b.blobs[string(address)]
	return exists, nil
}

func (b *memoryBackend) DeleteBlob(ctx context.Context, address ContentAddress) error {
	if err := b.checkClosed(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.blobs, string(address))
	return nil
}

// Ensure interface is satisfied
var _ StorageBackend = (*memoryBackend)(nil)
