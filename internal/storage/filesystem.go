// Package storage provides the production storage engine for the Solid runtime.
// This file implements the filesystem storage backend.
package storage

import (
	"context"
	"encoding/json"
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
	Logger  *slog.Logger
}

// filesystemBackend implements StorageBackend using the local filesystem
type filesystemBackend struct {
	config FilesystemBackendConfig
	logger *slog.Logger
	mu     sync.RWMutex
	closed bool
}

// NewFilesystemBackend creates a new filesystem storage backend
func NewFilesystemBackend(config FilesystemBackendConfig) StorageBackend {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &filesystemBackend{
		config: config,
		logger: config.Logger.With("backend", "filesystem"),
	}
}

func (b *filesystemBackend) Name() string                              { return "filesystem" }
func (b *filesystemBackend) Description() string                       { return "Local filesystem storage backend" }
func (b *filesystemBackend) GetQuota(ctx context.Context, storageRoot string) (*QuotaInfo, error) {
	return &QuotaInfo{StorageRoot: storageRoot}, nil
}
func (b *filesystemBackend) CheckQuota(ctx context.Context, storageRoot string, additionalBytes int64) error {
	return nil
}
func (b *filesystemBackend) GetTombstone(ctx context.Context, uri string) (*Tombstone, error) {
	return nil, ErrNotFound
}
func (b *filesystemBackend) StoreTombstone(ctx context.Context, tombstone *Tombstone) error {
	return nil
}
func (b *filesystemBackend) DeleteTombstone(ctx context.Context, uri string) error {
	return nil
}
func (b *filesystemBackend) GetLayoutVersion(ctx context.Context) (StorageLayoutVersion, error) {
	return CurrentStorageLayoutVersion, nil
}
func (b *filesystemBackend) SetLayoutVersion(ctx context.Context, version StorageLayoutVersion) error {
	return nil
}
func (b *filesystemBackend) Backup(ctx context.Context, writer io.Writer) error   { return nil }
func (b *filesystemBackend) Restore(ctx context.Context, reader io.Reader) error  { return nil }
func (b *filesystemBackend) ScanIntegrity(ctx context.Context) (*IntegrityReport, error) {
	return nil, nil
}

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
	return nil
}

func (b *filesystemBackend) HealthCheck(ctx context.Context) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return ErrStorageClosed
	}
	if _, err := os.Stat(b.config.RootPath); err != nil {
		return err
	}
	return nil
}

func (b *filesystemBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
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

func (b *filesystemBackend) Get(ctx context.Context, uri string) (*Resource, error) {
	if err := b.checkClosed(); err != nil {
		return nil, err
	}
	filePath := b.uriToPath(uri)
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var metadata Metadata
	if metadataData, err := os.ReadFile(filePath + ".meta.json"); err == nil {
		json.Unmarshal(metadataData, &metadata)
	}
	if metadata.URI == "" {
		metadata.URI = uri
	}
	if metadata.Size == 0 {
		metadata.Size = int64(len(data))
	}
	return &Resource{URI: uri, Body: data, Metadata: metadata}, nil
}

func (b *filesystemBackend) GetMetadata(ctx context.Context, uri string) (*Metadata, error) {
	if err := b.checkClosed(); err != nil {
		return nil, err
	}
	filePath := b.uriToPath(uri)
	var metadata Metadata
	metadataPath := filePath + ".meta.json"
	metadataData, err := os.ReadFile(metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				return nil, ErrNotFound
			}
			return &Metadata{URI: uri, ResourceType: ResourceTypeResource}, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(metadataData, &metadata); err != nil {
		return nil, err
	}
	return &metadata, nil
}

func (b *filesystemBackend) Put(ctx context.Context, uri string, resource *WriteResource) error {
	if err := b.checkClosed(); err != nil {
		return err
	}
	filePath := b.uriToPath(uri)
	if err := os.MkdirAll(filepath.Dir(filePath), 0750); err != nil {
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
	if err := os.WriteFile(filePath, body, 0640); err != nil {
		return err
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
	metadataData, _ := json.MarshalIndent(metadata, "", "  ")
	os.WriteFile(filePath+".meta.json", metadataData, 0640)
	return nil
}

func (b *filesystemBackend) Delete(ctx context.Context, uri string) error {
	if err := b.checkClosed(); err != nil {
		return err
	}
	filePath := b.uriToPath(uri)
	os.Remove(filePath)
	os.Remove(filePath + ".meta.json")
	return nil
}

func (b *filesystemBackend) List(ctx context.Context, containerURI string) ([]*Metadata, error) {
	if err := b.checkClosed(); err != nil {
		return nil, err
	}
	containerPath := b.uriToPath(containerURI)
	if !strings.HasSuffix(containerPath, string(filepath.Separator)) {
		containerPath += string(filepath.Separator)
	}
	entries, err := os.ReadDir(containerPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []*Metadata{}, nil
		}
		return nil, err
	}
	var result []*Metadata
	for _, entry := range entries {
		if entry.IsDir() || strings.HasSuffix(entry.Name(), ".meta.json") {
			continue
		}
		uri := b.pathToURI(filepath.Join(containerPath, entry.Name()))
		metadata, err := b.GetMetadata(ctx, uri)
		if err != nil {
			continue
		}
		result = append(result, metadata)
	}
	return result, nil
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

func (b *filesystemBackend) Exists(ctx context.Context, uri string) (bool, error) {
	if err := b.checkClosed(); err != nil {
		return false, err
	}
	filePath := b.uriToPath(uri)
	_, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (b *filesystemBackend) StoreBlob(ctx context.Context, data []byte) (ContentAddress, error) {
	if err := b.checkClosed(); err != nil {
		return "", err
	}
	address := ContentAddress(fmt.Sprintf("%x", sha256Sum(data)))
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
	if err := b.checkClosed(); err != nil {
		return nil, err
	}
	blobPath := filepath.Join(b.config.RootPath, "blobs", string(address))
	data, err := os.ReadFile(blobPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return data, nil
}

func (b *filesystemBackend) BlobExists(ctx context.Context, address ContentAddress) (bool, error) {
	if err := b.checkClosed(); err != nil {
		return false, err
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
	if err := b.checkClosed(); err != nil {
		return err
	}
	blobPath := filepath.Join(b.config.RootPath, "blobs", string(address))
	return os.Remove(blobPath)
}

// Ensure interface is satisfied
var _ StorageBackend = (*filesystemBackend)(nil)