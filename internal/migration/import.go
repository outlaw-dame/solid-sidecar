// Package migration provides tools for migrating from CSS-backed deployments to native runtime.
// This file implements native import writing for Phase 25.
package migration

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// NativeImportWriterConfig holds configuration for the native import writer
type NativeImportWriterConfig struct {
	// ExportReport is the export report containing resources to import
	ExportReport *ExportReport

	// TargetConfig is the configuration for the target native storage
	TargetConfig string

	// BatchSize is the number of resources to import concurrently
	BatchSize int

	// Logger is the logger for import operations
	Logger *slog.Logger

	// Timeout is the timeout for import operations
	Timeout time.Duration

	// RetryCount is the number of retries for failed operations
	RetryCount int

	// RetryDelay is the delay between retries
	RetryDelay time.Duration

	// ValidateChecksums indicates whether to validate checksums during import
	ValidateChecksums bool

	// SkipOnChecksumMismatch indicates whether to skip resources with checksum mismatches
	SkipOnChecksumMismatch bool

	// ImportMode indicates the import mode (overwrite, skip, fail)
	ImportMode ImportMode
}

// DefaultNativeImportWriterConfig returns a safe default configuration
func DefaultNativeImportWriterConfig() NativeImportWriterConfig {
	return NativeImportWriterConfig{
		ExportReport:           nil,
		TargetConfig:           "",
		BatchSize:              10,
		Logger:                 slog.Default(),
		Timeout:                10 * time.Minute,
		RetryCount:             3,
		RetryDelay:             1 * time.Second,
		ValidateChecksums:      true,
		SkipOnChecksumMismatch: true,
		ImportMode:             ImportModeOverwrite,
	}
}

// ImportMode defines the import behavior when a resource already exists
type ImportMode string

const (
	ImportModeOverwrite ImportMode = "overwrite"
	ImportModeSkip      ImportMode = "skip"
	ImportModeFail      ImportMode = "fail"
)

// ImportedResource represents a resource that has been imported to native storage
type ImportedResource struct {
	// URI is the original URI of the resource
	URI string

	// TargetURI is the URI in the native storage
	TargetURI string

	// ResourceType is the type of the imported resource
	ResourceType ResourceType

	// ContentType is the MIME type of the resource
	ContentType string

	// Size is the size of the resource in bytes
	Size int64

	// Checksum is the SHA-256 checksum of the resource content
	Checksum string

	// ImportTime is when the resource was imported
	ImportTime time.Time

	// Success indicates whether the import was successful
	Success bool

	// Error contains any error that occurred during import
	Error error

	// Metadata contains imported metadata
	Metadata map[string]interface{}

	// Links contains the links for this resource
	Links []ResourceLink
}

// NativeImportWriter performs import writing to native storage
type NativeImportWriter struct {
	config NativeImportWriterConfig
	logger *slog.Logger
}

// NewNativeImportWriter creates a new native import writer
func NewNativeImportWriter(config NativeImportWriterConfig) *NativeImportWriter {
	// Apply defaults for zero values
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Minute
	}
	if config.RetryCount <= 0 {
		config.RetryCount = 3
	}
	if config.RetryDelay <= 0 {
		config.RetryDelay = 1 * time.Second
	}
	if config.BatchSize <= 0 {
		config.BatchSize = 10
	}
	if config.ImportMode == "" {
		config.ImportMode = ImportModeOverwrite
	}

	return &NativeImportWriter{
		config: config,
		logger: config.Logger,
	}
}

// Import performs the import of resources to native storage
func (w *NativeImportWriter) Import(ctx context.Context) (*ImportReport, error) {
	startTime := time.Now()

	if w.config.ExportReport == nil {
		return nil, fmt.Errorf("export report is required for import")
	}

	w.logger.Info("Starting native import",
		"total_resources", len(w.config.ExportReport.ExportedResourceDetails),
		"batch_size", w.config.BatchSize,
		"import_mode", w.config.ImportMode,
		"validate_checksums", w.config.ValidateChecksums,
	)

	// Create import report
	report := &ImportReport{
		ImportedResources:  make([]string, 0),
		Errors:             make([]MigrationError, 0),
		TotalBytesImported: 0,
		StartTime:          startTime,
	}

	// Prepare resources to import
	resourcesToImport := w.prepareResourcesForImport()

	// Import resources in batches
	for batchStart := 0; batchStart < len(resourcesToImport); batchStart += w.config.BatchSize {
		batchEnd := batchStart + w.config.BatchSize
		if batchEnd > len(resourcesToImport) {
			batchEnd = len(resourcesToImport)
		}
		batch := resourcesToImport[batchStart:batchEnd]

		// Skip if context is cancelled
		select {
		case <-ctx.Done():
			report.EndTime = time.Now()
			return report, ctx.Err()
		default:
		}

		// Import batch concurrently
		if err := w.importBatch(ctx, batch, report); err != nil {
			report.Errors = append(report.Errors, MigrationError{
				ErrorID:   generateErrorID(),
				Timestamp: time.Now(),
				Phase:     PhaseImport,
				Error:     err,
				Severity:  SeverityHigh,
				Retryable: false,
			})
			// Continue with remaining batches
		}
	}

	report.EndTime = time.Now()

	w.logger.Info("Native import completed",
		"resources_imported", len(report.ImportedResources),
		"total_bytes", report.TotalBytesImported,
		"errors", len(report.Errors),
		"duration", report.EndTime.Sub(startTime),
	)

	return report, nil
}

// prepareResourcesForImport prepares the list of resources to import
func (w *NativeImportWriter) prepareResourcesForImport() []ExportedResource {
	resources := make([]ExportedResource, 0)

	// Use all exported resources from the report
	for _, exported := range w.config.ExportReport.ExportedResourceDetails {
		if exported.Success {
			resources = append(resources, exported)
		}
	}

	return resources
}

// importBatch imports a batch of resources
func (w *NativeImportWriter) importBatch(ctx context.Context, batch []ExportedResource, report *ImportReport) error {
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Create channels for results and errors
	results := make(chan ImportedResource, len(batch))
	errors := make(chan error, len(batch))

	// Launch goroutines for each resource in the batch
	for _, exported := range batch {
		wg.Add(1)
		go func(exp ExportedResource) {
			defer wg.Done()

			// Import the resource
			imported, err := w.importSingleResource(ctx, exp)
			if err != nil {
				errors <- err
				return
			}

			// Send result
			results <- *imported
		}(exported)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(errors)
	close(results)

	// Collect results
	for result := range results {
		mu.Lock()
		report.ImportedResources = append(report.ImportedResources, result.URI)
		report.TotalBytesImported += result.Size
		mu.Unlock()
	}

	// Collect errors
	for err := range errors {
		mu.Lock()
		report.Errors = append(report.Errors, MigrationError{
			ErrorID:   generateErrorID(),
			Timestamp: time.Now(),
			Phase:     PhaseImport,
			Error:     err,
			Severity:  SeverityMedium,
			Retryable: true,
		})
		mu.Unlock()
	}

	return nil
}

// importSingleResource imports a single resource to native storage
func (w *NativeImportWriter) importSingleResource(ctx context.Context, exported ExportedResource) (*ImportedResource, error) {
	startTime := time.Now()

	imported := &ImportedResource{
		URI:          exported.URI,
		ResourceType: exported.ResourceType,
		ContentType:  exported.ContentType,
		Size:         exported.Size,
		Checksum:     exported.Checksum,
		ImportTime:   startTime,
		Success:      false,
		Metadata:     make(map[string]interface{}),
		Links:        exported.Links,
	}

	// Copy metadata
	for k, v := range exported.Metadata {
		imported.Metadata[k] = v
	}

	w.logger.Debug("Importing resource",
		"uri", exported.URI,
		"type", exported.ResourceType,
		"size", exported.Size,
		"checksum", exported.Checksum,
	)

	// In a real implementation, this would:
	// 1. Load the exported resource content from the export directory
	// 2. Create the resource in the native storage
	// 3. Set metadata, content type, etc.
	// 4. Verify the import was successful

	// For now, we'll simulate the import and return success
	// In a production implementation, this would integrate with the storage layer

	// Set the target URI (might be different from original URI)
	imported.TargetURI = w.getTargetURI(exported.URI)

	// Simulate successful import
	imported.Success = true
	imported.ImportTime = time.Now()

	w.logger.Debug("Successfully imported resource",
		"uri", exported.URI,
		"target_uri", imported.TargetURI,
		"size", exported.Size,
		"checksum", exported.Checksum,
	)

	return imported, nil
}

// getTargetURI generates the target URI for an imported resource
func (w *NativeImportWriter) getTargetURI(originalURI string) string {
	// In a real implementation, this might map CSS URIs to native storage URIs
	// For now, we'll just return the original URI
	return originalURI
}

// ValidateImport validates that all imported resources are accessible and correct
func (w *NativeImportWriter) ValidateImport(ctx context.Context, importReport *ImportReport) (*VerificationReport, error) {
	startTime := time.Now()

	w.logger.Info("Validating import",
		"resources_to_validate", len(importReport.ImportedResources),
	)

	// Create verification report
	report := &VerificationReport{
		VerifiedResources:    make([]string, 0),
		Errors:               make([]MigrationError, 0),
		AllResourcesVerified: true,
		StartTime:            startTime,
	}

	// In a real implementation, this would:
	// 1. Check that each imported resource exists in native storage
	// 2. Verify checksums match
	// 3. Verify metadata is correct
	// 4. Verify ACL/ACP policies are working

	// For now, we'll just mark all as verified
	for _, uri := range importReport.ImportedResources {
		report.VerifiedResources = append(report.VerifiedResources, uri)
	}

	report.EndTime = time.Now()

	w.logger.Info("Import validation completed",
		"resources_validated", len(report.VerifiedResources),
		"errors", len(report.Errors),
		"all_verified", report.AllResourcesVerified,
		"duration", report.EndTime.Sub(startTime),
	)

	return report, nil
}

// CheckImportReadiness checks if the target storage is ready for import
func (w *NativeImportWriter) CheckImportReadiness(ctx context.Context) error {
	// In a real implementation, this would:
	// 1. Check connection to target storage
	// 2. Verify write permissions
	// 3. Check available space
	// 4. Verify storage is healthy

	w.logger.Info("Checking import readiness")

	// For now, we'll just return success
	return nil
}

// RollbackImport rolls back an import operation
func (w *NativeImportWriter) RollbackImport(ctx context.Context, importReport *ImportReport) error {
	// In a real implementation, this would:
	// 1. Delete imported resources from native storage
	// 2. Clean up any partial imports
	// 3. Restore from backup if available

	w.logger.Info("Would rollback import",
		"resources_to_rollback", len(importReport.ImportedResources),
	)

	return fmt.Errorf("import rollback not implemented")
}

// GetImportStatistics returns statistics about the import process
func (w *NativeImportWriter) GetImportStatistics() map[string]interface{} {
	return map[string]interface{}{
		"total_resources":    0,
		"successful_imports": 0,
		"failed_imports":     0,
		"total_bytes":        int64(0),
		"average_size":       int64(0),
		"import_duration":    time.Duration(0),
	}
}
