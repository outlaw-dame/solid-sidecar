// Package storage provides the production storage engine for the Solid runtime.
// This file implements the backup/restore functionality.
package storage

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

// BackupHeader represents the header of a backup file
type BackupHeader struct {
	Version       StorageLayoutVersion `json:"version"`
	CreatedAt     string               `json:"created_at"`
	StorageType   string               `json:"storage_type"`
	LayoutVersion StorageLayoutVersion `json:"layout_version"`
}

// BackupResource represents a single resource in a backup
type BackupResource struct {
	URI         string     `json:"uri"`
	Metadata    Metadata   `json:"metadata"`
	Body        string     `json:"body,omitempty"`
	BodySize    int64      `json:"body_size"`
	ETag        string     `json:"etag"`
	IsTombstone bool       `json:"is_tombstone,omitempty"`
	Tombstone   *Tombstone `json:"tombstone,omitempty"`
}

// backupRestoreImpl implements the BackupRestore interface
type backupRestoreImpl struct {
	engine *storageEngineImpl
	logger *slog.Logger
}

// Backup creates a backup of the storage
func (b *backupRestoreImpl) Backup(ctx context.Context, writer io.Writer) error {
	b.logger.Info("Starting storage backup", "version", CurrentStorageLayoutVersion)

	// Create a backup header
	backupHeader := BackupHeader{
		Version:       CurrentStorageLayoutVersion,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		StorageType:   "solid-sidecar",
		LayoutVersion: CurrentStorageLayoutVersion,
	}

	headerData, err := json.Marshal(backupHeader)
	if err != nil {
		return fmt.Errorf("failed to marshal backup header: %w", err)
	}

	// Write header with newline delimiter
	if _, err := writer.Write(append(headerData, '\n')); err != nil {
		return fmt.Errorf("failed to write backup header: %w", err)
	}

	// Get all resources from the storage engine
	allMetadata, err := b.engine.ListAll(ctx)
	if err != nil {
		return fmt.Errorf("failed to list all resources: %w", err)
	}

	b.logger.Info("Backing up resources", "count", len(allMetadata))

	// Backup each resource
	for i, metadata := range allMetadata {
		select {
		case <-ctx.Done():
			return fmt.Errorf("backup cancelled: %w", ctx.Err())
		default:
		}

		// Get the full resource (body + metadata)
		resource, err := b.engine.Get(ctx, metadata.URI)
		if err != nil {
			b.logger.Warn("Failed to get resource for backup", "uri", metadata.URI, "error", err)
			continue
		}

		// Create backup resource structure
		backupResource := BackupResource{
			URI:      resource.URI,
			Metadata: resource.Metadata,
			Body:     string(resource.Body),
			BodySize: int64(len(resource.Body)),
			ETag:     resource.Metadata.ETag,
		}

		// Marshal and write
		data, err := json.Marshal(backupResource)
		if err != nil {
			b.logger.Warn("Failed to marshal resource for backup", "uri", metadata.URI, "error", err)
			continue
		}

		if _, err := writer.Write(append(data, '\n')); err != nil {
			return fmt.Errorf("failed to write resource backup data: %w", err)
		}

		// Log progress every 100 resources
		if (i+1)%100 == 0 {
			b.logger.Info("Backup progress", "processed", i+1, "total", len(allMetadata))
		}
	}

	// Backup tombstones
	tombstones, err := b.engine.ListTombstones(ctx, "")
	if err != nil {
		b.logger.Warn("Failed to list tombstones for backup", "error", err)
	} else {
		for _, tombstone := range tombstones {
			select {
			case <-ctx.Done():
				return fmt.Errorf("backup cancelled during tombstone backup: %w", ctx.Err())
			default:
			}

			backupTombstone := BackupResource{
				URI:         tombstone.URI,
				IsTombstone: true,
				Tombstone:   tombstone,
			}

			data, err := json.Marshal(backupTombstone)
			if err != nil {
				b.logger.Warn("Failed to marshal tombstone for backup", "uri", tombstone.URI, "error", err)
				continue
			}

			if _, err := writer.Write(append(data, '\n')); err != nil {
				return fmt.Errorf("failed to write tombstone backup data: %w", err)
			}
		}
	}

	b.logger.Info("Storage backup completed successfully")
	return nil
}

// Restore restores from a backup
func (b *backupRestoreImpl) Restore(ctx context.Context, reader io.Reader) error {
	b.logger.Info("Starting storage restore")

	// Use a buffered reader for efficiency
	bufReader := bufio.NewReader(reader)

	// Read and parse the header line
	headerLine, err := bufReader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read backup header: %w", err)
	}

	// Trim the newline
	headerLine = strings.TrimSuffix(headerLine, "\n")
	if headerLine == "" {
		return fmt.Errorf("empty backup header")
	}

	// Parse the header
	var backupHeader BackupHeader
	if err := json.Unmarshal([]byte(headerLine), &backupHeader); err != nil {
		return fmt.Errorf("failed to parse backup header: %w", err)
	}

	// Validate the header
	if backupHeader.Version < MinSupportedStorageLayoutVersion || backupHeader.Version > CurrentStorageLayoutVersion {
		return fmt.Errorf("unsupported backup version: %d (supported: %d-%d)",
			backupHeader.Version, MinSupportedStorageLayoutVersion, CurrentStorageLayoutVersion)
	}

	if backupHeader.StorageType != "solid-sidecar" {
		return fmt.Errorf("unsupported storage type: %s", backupHeader.StorageType)
	}

	b.logger.Info("Restoring backup", "version", backupHeader.Version, "created_at", backupHeader.CreatedAt)

	// Restore each resource line by line
	resourceCount := 0
	tombstoneCount := 0
	errors := 0

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("restore cancelled: %w", ctx.Err())
		default:
		}

		// Read the next line
		line, err := bufReader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read backup line: %w", err)
		}

		// Trim the newline
		line = strings.TrimSuffix(line, "\n")
		if line == "" {
			continue
		}

		// Parse the backup resource
		var backupResource BackupResource
		if err := json.Unmarshal([]byte(line), &backupResource); err != nil {
			b.logger.Warn("Failed to parse backup resource", "line_length", len(line), "error", err)
			errors++
			continue
		}

		if backupResource.IsTombstone {
			// Restore tombstone
			if backupResource.Tombstone != nil {
				if err := b.engine.tombstoneStore.StoreTombstone(ctx, backupResource.Tombstone); err != nil {
					b.logger.Warn("Failed to restore tombstone", "uri", backupResource.URI, "error", err)
					errors++
					continue
				}
				tombstoneCount++
			}
		} else {
			// Restore regular resource
			if err := b.restoreResource(ctx, &backupResource); err != nil {
				b.logger.Warn("Failed to restore resource", "uri", backupResource.URI, "error", err)
				errors++
				continue
			}
			resourceCount++
		}

		// Log progress every 100 items
		if (resourceCount+tombstoneCount)%100 == 0 {
			b.logger.Info("Restore progress", "resources", resourceCount, "tombstones", tombstoneCount, "errors", errors)
		}
	}

	b.logger.Info("Storage restore completed", "resources_restored", resourceCount, "tombstones_restored", tombstoneCount, "errors", errors)

	if errors > 0 {
		return fmt.Errorf("restore completed with %d errors", errors)
	}

	return nil
}

// restoreResource restores a single resource from backup
func (b *backupRestoreImpl) restoreResource(ctx context.Context, backupResource *BackupResource) error {
	// Check if resource already exists (for conflict detection)
	exists, err := b.engine.Exists(ctx, backupResource.URI)
	if err != nil {
		return fmt.Errorf("failed to check if resource exists: %w", err)
	}

	if exists {
		// Check ETag to avoid overwriting unchanged resources
		currentMeta, err := b.engine.GetMetadata(ctx, backupResource.URI)
		if err != nil {
			return fmt.Errorf("failed to get current metadata: %w", err)
		}

		// If ETag matches, skip restoration (idempotent)
		if currentMeta.ETag == backupResource.ETag {
			b.logger.Debug("Resource unchanged, skipping restore", "uri", backupResource.URI, "etag", backupResource.ETag)
			return nil
		}

		// ETag doesn't match - this is a conflict
		b.logger.Warn("Resource conflict during restore", "uri", backupResource.URI, "backup_etag", backupResource.ETag, "current_etag", currentMeta.ETag)
	}

	// Restore the resource
	writeResource := &WriteResource{
		URI:      backupResource.URI,
		Body:     []byte(backupResource.Body),
		Metadata: backupResource.Metadata,
	}

	if err := b.engine.Put(ctx, writeResource); err != nil {
		return fmt.Errorf("failed to restore resource: %w", err)
	}

	return nil
}

// BackupResource backs up a single resource
func (b *backupRestoreImpl) BackupResource(ctx context.Context, uri string, writer io.Writer) error {
	// Get the resource
	resource, err := b.engine.Get(ctx, uri)
	if err != nil {
		return fmt.Errorf("failed to get resource for backup: %w", err)
	}

	// Create a backup structure
	backupData := BackupResource{
		URI:      resource.URI,
		Metadata: resource.Metadata,
		Body:     string(resource.Body),
		BodySize: int64(len(resource.Body)),
		ETag:     resource.Metadata.ETag,
	}

	// Encode and write
	data, err := json.Marshal(backupData)
	if err != nil {
		return fmt.Errorf("failed to marshal backup data: %w", err)
	}

	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("failed to write backup data: %w", err)
	}

	return nil
}

// RestoreResource restores a single resource
func (b *backupRestoreImpl) RestoreResource(ctx context.Context, uri string, reader io.Reader) error {
	// Read and decode the backup data
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read backup data: %w", err)
	}

	var backupData BackupResource
	if err := json.Unmarshal(data, &backupData); err != nil {
		return fmt.Errorf("failed to unmarshal backup data: %w", err)
	}

	// Validate URI matches
	if backupData.URI != uri {
		return fmt.Errorf("URI mismatch: expected %s, got %s", uri, backupData.URI)
	}

	// Restore the resource
	writeResource := &WriteResource{
		URI:      backupData.URI,
		Body:     []byte(backupData.Body),
		Metadata: backupData.Metadata,
	}

	if err := b.engine.Put(ctx, writeResource); err != nil {
		return fmt.Errorf("failed to restore resource: %w", err)
	}

	return nil
}

// ValidateBackup validates a backup file without restoring it
func (b *backupRestoreImpl) ValidateBackup(ctx context.Context, reader io.Reader) error {
	b.logger.Info("Validating backup file")

	bufReader := bufio.NewReader(reader)

	// Read and validate header
	headerLine, err := bufReader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read backup header: %w", err)
	}

	headerLine = strings.TrimSuffix(headerLine, "\n")
	if headerLine == "" {
		return fmt.Errorf("empty backup header")
	}

	var backupHeader BackupHeader
	if err := json.Unmarshal([]byte(headerLine), &backupHeader); err != nil {
		return fmt.Errorf("failed to parse backup header: %w", err)
	}

	// Validate version
	if backupHeader.Version < MinSupportedStorageLayoutVersion || backupHeader.Version > CurrentStorageLayoutVersion {
		return fmt.Errorf("unsupported backup version: %d (supported: %d-%d)",
			backupHeader.Version, MinSupportedStorageLayoutVersion, CurrentStorageLayoutVersion)
	}

	// Count resources and validate each line
	resourceCount := 0
	tombstoneCount := 0

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("validation cancelled: %w", ctx.Err())
		default:
		}

		line, err := bufReader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read backup line: %w", err)
		}

		line = strings.TrimSuffix(line, "\n")
		if line == "" {
			continue
		}

		// Try to parse as resource or tombstone
		var backupResource BackupResource
		if err := json.Unmarshal([]byte(line), &backupResource); err != nil {
			b.logger.Warn("Failed to parse backup line", "error", err)
			return fmt.Errorf("invalid backup format at line %d: %w", resourceCount+tombstoneCount+1, err)
		}

		if backupResource.IsTombstone {
			tombstoneCount++
		} else {
			resourceCount++
		}
	}

	b.logger.Info("Backup validation successful", "version", backupHeader.Version, "resources", resourceCount, "tombstones", tombstoneCount)
	return nil
}

// GetBackupMetadata extracts metadata from a backup without restoring
func (b *backupRestoreImpl) GetBackupMetadata(ctx context.Context, reader io.Reader) (*BackupHeader, int, int, error) {
	bufReader := bufio.NewReader(reader)

	// Read header
	headerLine, err := bufReader.ReadString('\n')
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to read backup header: %w", err)
	}

	headerLine = strings.TrimSuffix(headerLine, "\n")
	if headerLine == "" {
		return nil, 0, 0, fmt.Errorf("empty backup header")
	}

	var backupHeader BackupHeader
	if err := json.Unmarshal([]byte(headerLine), &backupHeader); err != nil {
		return nil, 0, 0, fmt.Errorf("failed to parse backup header: %w", err)
	}

	// Validate version
	if backupHeader.Version < MinSupportedStorageLayoutVersion || backupHeader.Version > CurrentStorageLayoutVersion {
		return nil, 0, 0, fmt.Errorf("unsupported backup version: %d", backupHeader.Version)
	}

	// Count resources and tombstones
	resourceCount := 0
	tombstoneCount := 0

	for {
		select {
		case <-ctx.Done():
			return &backupHeader, resourceCount, tombstoneCount, fmt.Errorf("counting cancelled: %w", ctx.Err())
		default:
		}

		line, err := bufReader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return &backupHeader, resourceCount, tombstoneCount, fmt.Errorf("failed to read backup line: %w", err)
		}

		line = strings.TrimSuffix(line, "\n")
		if line == "" {
			continue
		}

		var backupResource BackupResource
		if err := json.Unmarshal([]byte(line), &backupResource); err != nil {
			// Skip malformed lines but continue counting
			continue
		}

		if backupResource.IsTombstone {
			tombstoneCount++
		} else {
			resourceCount++
		}
	}

	return &backupHeader, resourceCount, tombstoneCount, nil
}
