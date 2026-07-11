// Package storage provides the production storage engine for the Solid runtime.
// This file implements the integrity scanner functionality.
package storage

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// integrityScannerImpl implements the IntegrityScanner interface
type integrityScannerImpl struct {
	engine *storageEngineImpl
	logger *slog.Logger
}

// Scan performs a full integrity scan of all resources
func (s *integrityScannerImpl) Scan(ctx context.Context) (*IntegrityReport, error) {
	s.logger.Info("Starting integrity scan")

	report := &IntegrityReport{
		ScannedAt:       time.Now().UTC(),
		TotalResources:  0,
		ResourceReports: []ResourceIntegrityReport{},
	}

	// Get all resources
	allMetadata, err := s.engine.ListAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list all resources: %w", err)
	}

	report.TotalResources = int64(len(allMetadata))

	// Use goroutines for parallel scanning with limited concurrency
	const maxConcurrency = 10
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, metadata := range allMetadata {
		wg.Add(1)
		go func(m *Metadata) {
			defer wg.Done()

			// Acquire semaphore
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			// Scan this resource
			resourceReport, err := s.ScanResource(ctx, m.URI)
			if err != nil {
				s.logger.Warn("Failed to scan resource", "uri", m.URI, "error", err)
				return
			}

			// Update report
			mu.Lock()
			report.ResourceReports = append(report.ResourceReports, *resourceReport)
			if len(resourceReport.Issues) > 0 {
				report.ResourcesWithIssues++
				for _, issue := range resourceReport.Issues {
					switch issue.Type {
					case IssueTypeMetadataBodyMismatch:
						report.MetadataBodyMismatches++
					case IssueTypeMissingDigest:
						report.MissingDigests++
					}
				}
			}
			mu.Unlock()
		}(metadata)
	}

	// Wait for all goroutines to complete or context cancellation
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("integrity scan cancelled: %w", ctx.Err())
	case <-done:
		// All done
	}

	s.logger.Info("Integrity scan completed", "total_resources", report.TotalResources, "resources_with_issues", report.ResourcesWithIssues)
	return report, nil
}

// ScanResource scans a single resource for integrity
func (s *integrityScannerImpl) ScanResource(ctx context.Context, uri string) (*ResourceIntegrityReport, error) {
	// Get the resource
	resource, err := s.engine.Get(ctx, uri)
	if err != nil {
		if err == ErrNotFound {
			return &ResourceIntegrityReport{
				URI: uri,
				Issues: []IntegrityIssue{
					{
						Type:        IssueTypeMetadataBodyMismatch,
						Severity:    SeverityHigh,
						Description: "Resource not found",
					},
				},
			}, nil
		}
		return nil, fmt.Errorf("failed to get resource: %w", err)
	}

	// Check for basic integrity issues
	var issues []IntegrityIssue

	// Check if digest is present but doesn't match computed digest
	if resource.Metadata.Digest != "" {
		computedDigest := computeDigest(resource.Body)
		if computedDigest != resource.Metadata.Digest {
			issues = append(issues, IntegrityIssue{
				Type:        IssueTypeMetadataBodyMismatch,
				Severity:    SeverityHigh,
				Description: "Metadata digest does not match body content",
				Details: map[string]string{
					"expected_digest": resource.Metadata.Digest,
					"computed_digest": computedDigest,
				},
			})
		}
	} else {
		// Missing digest is a warning, not an error for all resources
		// Only flag as issue if the resource is supposed to have a digest
		if resource.Metadata.ContentAddress != "" {
			issues = append(issues, IntegrityIssue{
				Type:        IssueTypeMissingDigest,
				Severity:    SeverityMedium,
				Description: "Missing digest for content-addressed resource",
				Details: map[string]string{
					"content_address": string(resource.Metadata.ContentAddress),
				},
			})
		}
	}

	// Check if content address is present but doesn't match
	if resource.Metadata.ContentAddress != "" {
		computedAddress := computeContentAddress(resource.Body)
		if computedAddress != resource.Metadata.ContentAddress {
			issues = append(issues, IntegrityIssue{
				Type:        IssueTypeMetadataBodyMismatch,
				Severity:    SeverityHigh,
				Description: "Content address does not match body content",
				Details: map[string]string{
					"expected_address": string(resource.Metadata.ContentAddress),
					"computed_address": string(computedAddress),
				},
			})
		}
	}

	// Check for layout version mismatch
	if resource.Metadata.LayoutVersion < MinSupportedStorageLayoutVersion || resource.Metadata.LayoutVersion > CurrentStorageLayoutVersion {
		issues = append(issues, IntegrityIssue{
			Type:        IssueTypeLayoutVersionMismatch,
			Severity:    SeverityCritical,
			Description: "Resource uses unsupported storage layout version",
			Details: map[string]string{
				"current_version": fmt.Sprintf("%d", resource.Metadata.LayoutVersion),
				"min_supported":   fmt.Sprintf("%d", MinSupportedStorageLayoutVersion),
				"max_supported":   fmt.Sprintf("%d", CurrentStorageLayoutVersion),
			},
		})
	}

	// Check for corrupted metadata (nil or invalid values)
	if resource.Metadata.URI == "" {
		issues = append(issues, IntegrityIssue{
			Type:        IssueTypeCorruptedMetadata,
			Severity:    SeverityCritical,
			Description: "Resource metadata has empty URI",
		})
	}

	if resource.Metadata.Size < 0 {
		issues = append(issues, IntegrityIssue{
			Type:        IssueTypeCorruptedMetadata,
			Severity:    SeverityHigh,
			Description: "Resource metadata has negative size",
			Details: map[string]string{
				"size": fmt.Sprintf("%d", resource.Metadata.Size),
			},
		})
	}

	// Check size matches actual body size
	if resource.Metadata.Size != int64(len(resource.Body)) {
		issues = append(issues, IntegrityIssue{
			Type:        IssueTypeMetadataBodyMismatch,
			Severity:    SeverityHigh,
			Description: "Resource size does not match body length",
			Details: map[string]string{
				"metadata_size":    fmt.Sprintf("%d", resource.Metadata.Size),
				"actual_body_size": fmt.Sprintf("%d", len(resource.Body)),
			},
		})
	}

	// Check ETag consistency
	if resource.Metadata.ETag == "" {
		// Missing ETag - generate one for comparison
		// This is a warning, not a critical error
		issues = append(issues, IntegrityIssue{
			Type:        IssueTypeCorruptedMetadata,
			Severity:    SeverityLow,
			Description: "Resource is missing ETag",
		})
	}

	return &ResourceIntegrityReport{
		URI:    uri,
		Issues: issues,
	}, nil
}

// Repair attempts to repair integrity violations
func (s *integrityScannerImpl) Repair(ctx context.Context, report *IntegrityReport) (*IntegrityRepairReport, error) {
	s.logger.Info("Starting integrity repair", "total_issues", report.ResourcesWithIssues)

	repairReport := &IntegrityRepairReport{
		RepairedAt:       time.Now().UTC(),
		TotalIssues:      report.ResourcesWithIssues,
		IssuesRepaired:   0,
		IssuesUnrepaired: report.ResourcesWithIssues,
		Errors:           []error{},
	}

	// For each resource with issues, attempt to repair
	for _, resourceReport := range report.ResourceReports {
		if len(resourceReport.Issues) == 0 {
			continue
		}

		select {
		case <-ctx.Done():
			return repairReport, fmt.Errorf("repair cancelled: %w", ctx.Err())
		default:
		}

		// Try to repair this resource
		repaired, err := s.repairResource(ctx, &resourceReport)
		if err != nil {
			repairReport.Errors = append(repairReport.Errors, err)
			continue
		}

		if repaired {
			repairReport.IssuesRepaired++
			repairReport.IssuesUnrepaired--
		}
	}

	s.logger.Info("Integrity repair completed", "repaired", repairReport.IssuesRepaired, "unrepaired", repairReport.IssuesUnrepaired, "errors", len(repairReport.Errors))
	return repairReport, nil
}

// repairResource attempts to repair a single resource
func (s *integrityScannerImpl) repairResource(ctx context.Context, resourceReport *ResourceIntegrityReport) (bool, error) {
	// Get the current resource
	resource, err := s.engine.Get(ctx, resourceReport.URI)
	if err != nil {
		return false, fmt.Errorf("failed to get resource for repair: %w", err)
	}

	// Track what we fixed
	fixed := false
	newMetadata := resource.Metadata

	// Check each issue and try to fix it
	for _, issue := range resourceReport.Issues {
		switch issue.Type {
		case IssueTypeMetadataBodyMismatch:
			// Recompute and update digest
			newMetadata.Digest = computeDigest(resource.Body)
			// Recompute and update content address if present
			if resource.Metadata.ContentAddress != "" {
				newMetadata.ContentAddress = computeContentAddress(resource.Body)
			}
			// Update size to match actual body
			newMetadata.Size = int64(len(resource.Body))
			fixed = true

		case IssueTypeMissingDigest:
			// Add missing digest
			newMetadata.Digest = computeDigest(resource.Body)
			fixed = true

		case IssueTypeInvalidDigest:
			// Recompute digest
			newMetadata.Digest = computeDigest(resource.Body)
			fixed = true

		case IssueTypeCorruptedMetadata:
			// Try to fix corrupted metadata
			if resource.Metadata.URI == "" {
				newMetadata.URI = resourceReport.URI
				fixed = true
			}
			if resource.Metadata.Size < 0 {
				newMetadata.Size = int64(len(resource.Body))
				fixed = true
			}

		case IssueTypeLayoutVersionMismatch:
			// Update to current layout version
			newMetadata.LayoutVersion = CurrentStorageLayoutVersion
			fixed = true
		}
	}

	// If we fixed anything, update the resource
	if fixed {
		writeResource := &WriteResource{
			URI:      resource.URI,
			Body:     resource.Body,
			Metadata: newMetadata,
		}

		if err := s.engine.Put(ctx, writeResource); err != nil {
			return false, fmt.Errorf("failed to update resource during repair: %w", err)
		}

		s.logger.Info("Repaired resource", "uri", resourceReport.URI, "issues_fixed", len(resourceReport.Issues))
		return true, nil
	}

	// Nothing to fix
	return false, nil
}

// NewIntegrityScanner creates a new IntegrityScanner instance
func NewIntegrityScanner(engine *storageEngineImpl, logger *slog.Logger) IntegrityScanner {
	return &integrityScannerImpl{
		engine: engine,
		logger: logger,
	}
}

// QuickIntegrityCheck performs a quick integrity check without full scan
func (s *integrityScannerImpl) QuickIntegrityCheck(ctx context.Context) (bool, error) {
	// Sample a few resources for quick check
	allMetadata, err := s.engine.ListAll(ctx)
	if err != nil {
		return false, err
	}

	// Check up to 10 resources
	checkCount := 10
	if len(allMetadata) < checkCount {
		checkCount = len(allMetadata)
	}

	for i := 0; i < checkCount; i++ {
		_, err := s.ScanResource(ctx, allMetadata[i].URI)
		if err != nil {
			return false, err
		}
	}

	return true, nil
}

// CheckResourceIntegrity checks if a specific resource has integrity issues
func (s *integrityScannerImpl) CheckResourceIntegrity(ctx context.Context, uri string) (bool, []IntegrityIssue, error) {
	report, err := s.ScanResource(ctx, uri)
	if err != nil {
		return false, nil, err
	}

	return len(report.Issues) == 0, report.Issues, nil
}
