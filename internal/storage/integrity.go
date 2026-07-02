// Package storage provides the production storage engine for the Solid runtime.
// This file implements the integrity scanner functionality.
package storage

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// integrityScannerImpl implements the IntegrityScanner interface
type integrityScannerImpl struct {
	engine *storageEngineImpl
	logger *slog.Logger
}

// Scan performs an integrity scan
func (s *integrityScannerImpl) Scan(ctx context.Context) (*IntegrityReport, error) {
	// For now, return an empty report
	// In a production implementation, this would scan all resources
	// and verify metadata/body consistency

	return &IntegrityReport{
		ScannedAt:           time.Now(),
		TotalResources:      0,
		ResourcesWithIssues: 0,
		ResourceReports:     []ResourceIntegrityReport{},
	}, nil
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

	return &ResourceIntegrityReport{
		URI:    uri,
		Issues: issues,
	}, nil
}

// Repair attempts to repair integrity violations
func (s *integrityScannerImpl) Repair(ctx context.Context, report *IntegrityReport) (*IntegrityRepairReport, error) {
	// For now, return an empty report
	return &IntegrityRepairReport{
		RepairedAt:       time.Now(),
		TotalIssues:      report.ResourcesWithIssues,
		IssuesRepaired:   0,
		IssuesUnrepaired: report.ResourcesWithIssues,
		Errors:           []error{},
	}, nil
}
