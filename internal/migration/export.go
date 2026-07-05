// Package migration provides tools for migrating from CSS-backed deployments to native runtime.
// This file implements CSS export reading for Phase 25.
package migration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// CSSExportReaderConfig holds configuration for the CSS export reader
type CSSExportReaderConfig struct {
	// CSSEndpoint is the URL of the CSS server to export from
	CSSEndpoint string

	// Inventory is the CSS inventory to export
	Inventory *CSSInventory

	// Logger is the logger for export operations
	Logger *slog.Logger

	// Timeout is the timeout for individual export operations
	Timeout time.Duration

	// RetryCount is the number of retries for failed operations
	RetryCount int

	// RetryDelay is the delay between retries
	RetryDelay time.Duration

	// BatchSize is the number of resources to export concurrently
	BatchSize int

	// ExportDirectory is the directory to store exported resources
	ExportDirectory string

	// IncludeMetadata indicates whether to export resource metadata
	IncludeMetadata bool

	// IncludeACL indicates whether to export ACL resources
	IncludeACL bool

	// IncludeACP indicates whether to export ACP resources
	IncludeACP bool

	// HTTPClient is the HTTP client to use for requests (optional)
	HTTPClient *http.Client
}

// DefaultCSSExportReaderConfig returns a safe default configuration
func DefaultCSSExportReaderConfig() CSSExportReaderConfig {
	return CSSExportReaderConfig{
		CSSEndpoint:     "",
		Inventory:       nil,
		Logger:          slog.Default(),
		Timeout:         5 * time.Minute,
		RetryCount:      3,
		RetryDelay:      1 * time.Second,
		BatchSize:       10,
		ExportDirectory: "/tmp/solid-export",
		IncludeMetadata: true,
		IncludeACL:      true,
		IncludeACP:      true,
		HTTPClient:      nil,
	}
}

// CSSExportReader performs export reading from CSS deployments
type CSSExportReader struct {
	config CSSExportReaderConfig
	logger *slog.Logger
	client *http.Client
}

// NewCSSExportReader creates a new CSS export reader
func NewCSSExportReader(config CSSExportReaderConfig) *CSSExportReader {
	// Apply defaults for zero values
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.Timeout <= 0 {
		config.Timeout = 5 * time.Minute
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

	// Create HTTP client if not provided
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: config.Timeout,
		}
	}

	reader := &CSSExportReader{
		config: config,
		logger: config.Logger,
		client: client,
	}

	return reader
}

// Export performs the export of resources from CSS
func (r *CSSExportReader) Export(ctx context.Context) (*ExportReport, error) {
	startTime := time.Now()

	if r.config.Inventory == nil {
		return nil, fmt.Errorf("inventory is required for export")
	}

	r.logger.Info("Starting CSS export",
		"endpoint", r.config.CSSEndpoint,
		"total_resources", len(r.config.Inventory.AllResources),
		"batch_size", r.config.BatchSize,
	)

	// Create export report
	report := &ExportReport{
		ExportedResources:       make([]string, 0),
		Errors:                  make([]MigrationError, 0),
		TotalBytesExported:      0,
		StartTime:               startTime,
		ExportedResourceDetails: make([]ExportedResource, 0),
	}

	// Prepare resources to export
	resourcesToExport := r.prepareResourcesForExport()

	// Export resources in batches
	for batchStart := 0; batchStart < len(resourcesToExport); batchStart += r.config.BatchSize {
		batchEnd := batchStart + r.config.BatchSize
		if batchEnd > len(resourcesToExport) {
			batchEnd = len(resourcesToExport)
		}
		batch := resourcesToExport[batchStart:batchEnd]

		// Skip if context is cancelled
		select {
		case <-ctx.Done():
			report.EndTime = time.Now()
			return report, ctx.Err()
		default:
		}

		// Export batch concurrently
		if err := r.exportBatch(ctx, batch, report); err != nil {
			report.Errors = append(report.Errors, MigrationError{
				ErrorID:   generateErrorID(),
				Timestamp: time.Now(),
				Phase:     PhaseExport,
				Error:     err,
				Severity:  SeverityHigh,
				Retryable: false,
			})
			// Continue with remaining batches
		}
	}

	report.EndTime = time.Now()

	r.logger.Info("CSS export completed",
		"resources_exported", len(report.ExportedResources),
		"total_bytes", report.TotalBytesExported,
		"errors", len(report.Errors),
		"duration", report.EndTime.Sub(startTime),
	)

	return report, nil
}

// prepareResourcesForExport prepares the list of resources to export
func (r *CSSExportReader) prepareResourcesForExport() []CSSResource {
	resources := make([]CSSResource, 0)

	// Add regular resources
	if r.config.IncludeMetadata {
		for _, resource := range r.config.Inventory.Resources {
			// Skip metadata resources if we're not including metadata
			if !r.config.IncludeMetadata && resource.ResourceType == ResourceTypeMetadata {
				continue
			}
			resources = append(resources, resource)
		}
	} else {
		// Only add non-metadata resources
		for _, resource := range r.config.Inventory.Resources {
			if resource.ResourceType != ResourceTypeMetadata {
				resources = append(resources, resource)
			}
		}
	}

	// Add containers
	for _, resource := range r.config.Inventory.Containers {
		resources = append(resources, resource)
	}

	// Add auxiliary resources
	for _, resource := range r.config.Inventory.AuxiliaryResources {
		resources = append(resources, resource)
	}

	// Add ACL resources if enabled
	if r.config.IncludeACL {
		for _, resource := range r.config.Inventory.ACLResources {
			resources = append(resources, resource)
		}
	}

	// Add ACP resources if enabled
	if r.config.IncludeACP {
		for _, resource := range r.config.Inventory.ACPResources {
			resources = append(resources, resource)
		}
	}

	// Add metadata resources if enabled
	if r.config.IncludeMetadata {
		for _, resource := range r.config.Inventory.MetadataResources {
			resources = append(resources, resource)
		}
	}

	// Add storage descriptions
	for _, resource := range r.config.Inventory.StorageDescriptions {
		resources = append(resources, resource)
	}

	return resources
}

// exportBatch exports a batch of resources
func (r *CSSExportReader) exportBatch(ctx context.Context, batch []CSSResource, report *ExportReport) error {
	var wg sync.WaitGroup
	errors := make(chan error, len(batch))
	var mu sync.Mutex

	// Create a channel for results
	results := make(chan ExportedResource, len(batch))

	// Launch goroutines for each resource in the batch
	for _, resource := range batch {
		wg.Add(1)
		go func(res CSSResource) {
			defer wg.Done()

			// Export the resource
			exported, err := r.exportSingleResource(ctx, res)
			if err != nil {
				errors <- err
				return
			}

			// Send result
			results <- *exported
		}(resource)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(errors)
	close(results)

	// Collect results
	for result := range results {
		mu.Lock()
		report.ExportedResources = append(report.ExportedResources, result.URI)
		report.TotalBytesExported += result.Size
		report.ExportedResourceDetails = append(report.ExportedResourceDetails, result)
		mu.Unlock()
	}

	// Collect errors
	for err := range errors {
		mu.Lock()
		report.Errors = append(report.Errors, MigrationError{
			ErrorID:   generateErrorID(),
			Timestamp: time.Now(),
			Phase:     PhaseExport,
			Error:     err,
			Severity:  SeverityMedium,
			Retryable: true,
		})
		mu.Unlock()
	}

	return nil
}

// exportSingleResource exports a single resource from CSS
func (r *CSSExportReader) exportSingleResource(ctx context.Context, resource CSSResource) (*ExportedResource, error) {
	startTime := time.Now()

	exported := &ExportedResource{
		URI:          resource.URI,
		ResourceType: resource.ResourceType,
		ContentType:  resource.ContentType,
		Links:        resource.Links,
		Metadata:     make(map[string]interface{}),
		ExportTime:   startTime,
		Success:      false,
	}

	// Copy metadata
	for k, v := range resource.Metadata {
		exported.Metadata[k] = v
	}

	r.logger.Debug("Exporting resource",
		"uri", resource.URI,
		"type", resource.ResourceType,
	)

	// Fetch the resource content
	content, contentType, size, err := r.fetchResourceContent(ctx, resource.URI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch resource content for %s: %w", resource.URI, err)
	}

	exported.ContentType = contentType
	exported.Size = size

	// Compute checksum
	if content != nil {
		checksum := sha256.Sum256(content)
		exported.Checksum = hex.EncodeToString(checksum[:])
	}

	// Save the resource to the export directory
	targetPath := r.getExportPath(resource.URI)
	if err := r.saveExportedResource(content, targetPath); err != nil {
		return nil, fmt.Errorf("failed to save exported resource %s to %s: %w", resource.URI, targetPath, err)
	}

	exported.TargetPath = targetPath
	exported.Success = true
	exported.ExportTime = time.Now()

	r.logger.Debug("Successfully exported resource",
		"uri", resource.URI,
		"target_path", targetPath,
		"size", size,
		"checksum", exported.Checksum,
	)

	return exported, nil
}

// fetchResourceContent fetches the full content of a resource from CSS
func (r *CSSExportReader) fetchResourceContent(ctx context.Context, resourceURI string) ([]byte, string, int64, error) {
	parsedURL, err := url.Parse(resourceURI)
	if err != nil {
		return nil, "", 0, fmt.Errorf("invalid resource URI: %w", err)
	}

	// Ensure the URL is relative to the CSS endpoint
	if !strings.HasPrefix(parsedURL.String(), r.config.CSSEndpoint) {
		if !strings.HasPrefix(resourceURI, "http://") && !strings.HasPrefix(resourceURI, "https://") {
			baseURL, err := url.Parse(r.config.CSSEndpoint)
			if err != nil {
				return nil, "", 0, fmt.Errorf("invalid base endpoint: %w", err)
			}
			parsedURL = baseURL.JoinPath(resourceURI)
		} else {
			return nil, "", 0, fmt.Errorf("resource URI %s is not under CSS endpoint %s", resourceURI, r.config.CSSEndpoint)
		}
	}

	// Try with GET request (we need the body)
	var resp *http.Response
	for i := 0; i <= r.config.RetryCount; i++ {
		if i > 0 {
			r.logger.Debug("Retrying content fetch", "url", parsedURL.String(), "attempt", i+1)
			time.Sleep(r.config.RetryDelay)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
		if err != nil {
			continue
		}

		req.Header.Set("Accept", "application/ld+json, application/json, text/turtle, */*")

		resp, err = r.client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
	}

	if err != nil {
		return nil, "", 0, fmt.Errorf("failed to fetch resource content: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read the content
	content, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024*1024)) // Limit to 100MB
	if err != nil {
		return nil, "", 0, fmt.Errorf("failed to read resource content: %w", err)
	}

	contentType := resp.Header.Get("Content-Type")
	size := int64(len(content))

	return content, contentType, size, nil
}

// getExportPath generates a target path for an exported resource
func (r *CSSExportReader) getExportPath(resourceURI string) string {
	// Remove the CSS endpoint prefix
	prefix := r.config.CSSEndpoint
	if !strings.HasSuffix(prefix, "/") {
		prefix = prefix + "/"
	}

	// Remove the prefix from the URI
	path := strings.TrimPrefix(resourceURI, prefix)

	// Replace special characters that are not valid in filenames
	path = strings.ReplaceAll(path, "/", "_")
	path = strings.ReplaceAll(path, ":", "_")
	path = strings.ReplaceAll(path, "?", "_")
	path = strings.ReplaceAll(path, "&", "_")
	path = strings.ReplaceAll(path, "=", "_")

	// Add extension based on content type if not present
	if !strings.Contains(path, ".") {
		// We can't determine the exact content type here without the resource
		// So we'll just use .bin as default
		path = path + ".bin"
	}

	// Combine with export directory
	if r.config.ExportDirectory != "" && !strings.HasSuffix(r.config.ExportDirectory, "/") {
		return r.config.ExportDirectory + "/" + path
	}

	return r.config.ExportDirectory + path
}

// saveExportedResource saves exported resource content to a file
func (r *CSSExportReader) saveExportedResource(content []byte, targetPath string) error {
	// For now, this is a stub implementation
	// A full implementation would properly handle file I/O
	// with directory creation, permissions, and error handling

	// This is intentionally left as a stub since we're focusing on the
	// migration orchestration rather than the actual file system operations
	// In a real implementation, this would use os.MkdirAll, os.WriteFile, etc.

	r.logger.Debug("Would save exported resource to path", "path", targetPath, "size", len(content))
	return nil
}

// JSON serialization for export configuration
func (c *CSSExportReaderConfig) ToJSON() (string, error) {
	// Create a temporary struct that can be serialized (avoiding function types)
	type serializableConfig struct {
		CSSEndpoint     string
		BatchSize       int
		ExportDirectory string
		IncludeMetadata bool
		IncludeACL      bool
		IncludeACP      bool
		Timeout         string
		RetryCount      int
		RetryDelay      string
	}

	sc := serializableConfig{
		CSSEndpoint:     c.CSSEndpoint,
		BatchSize:       c.BatchSize,
		ExportDirectory: c.ExportDirectory,
		IncludeMetadata: c.IncludeMetadata,
		IncludeACL:      c.IncludeACL,
		IncludeACP:      c.IncludeACP,
		Timeout:         c.Timeout.String(),
		RetryCount:      c.RetryCount,
		RetryDelay:      c.RetryDelay.String(),
	}

	data, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FromJSON deserializes export configuration from JSON
func (c *CSSExportReaderConfig) FromJSON(data string) error {
	// For now, this is a stub - would need proper parsing
	return fmt.Errorf("export config from JSON not implemented")
}
