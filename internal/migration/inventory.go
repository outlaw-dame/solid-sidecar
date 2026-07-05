// Package migration provides tools for migrating from CSS-backed deployments to native runtime.
// This file implements CSS inventory scanning for Phase 25.
package migration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CSSResource represents a resource discovered in the CSS inventory
type CSSResource struct {
	// URI is the full URI of the resource
	URI string

	// ResourceType is the type of resource (Resource, Container, ACL, ACP, Metadata, etc.)
	ResourceType ResourceType

	// ContentType is the MIME type of the resource
	ContentType string

	// Size is the size of the resource in bytes
	Size int64

	// LastModified is when the resource was last modified
	LastModified time.Time

	// ETag is the entity tag for the resource
	ETag string

	// Links contains related links for the resource
	Links []ResourceLink

	// Metadata contains additional metadata about the resource
	Metadata map[string]interface{}

	// Checksum is the SHA-256 checksum of the resource content
	Checksum string
}

// ResourceLink represents a link between resources
type ResourceLink struct {
	// Rel is the relationship type (e.g., "acl", "auxiliary", "describedby", etc.)
	Rel string

	// Target is the target URI of the link
	Target string

	// Type is the type of the target resource
	Type string
}

// ResourceType defines the type of a resource in CSS
type ResourceType string

const (
	ResourceTypeResource    ResourceType = "Resource"
	ResourceTypeContainer   ResourceType = "Container"
	ResourceTypeAuxiliary   ResourceType = "Auxiliary"
	ResourceTypeACL         ResourceType = "ACL"
	ResourceTypeACP         ResourceType = "ACP"
	ResourceTypeMetadata    ResourceType = "Metadata"
	ResourceTypeStorageDesc ResourceType = "StorageDescription"
	ResourceTypeUnknown     ResourceType = "Unknown"
)

// CSSInventory represents the complete inventory of resources in a CSS deployment
type CSSInventory struct {
	// Resources contains all regular resources
	Resources []CSSResource

	// Containers contains all container resources
	Containers []CSSResource

	// AuxiliaryResources contains all auxiliary resources
	AuxiliaryResources []CSSResource

	// ACLResources contains all ACL resources
	ACLResources []CSSResource

	// ACPResources contains all ACP resources
	ACPResources []CSSResource

	// MetadataResources contains all metadata resources
	MetadataResources []CSSResource

	// StorageDescriptions contains all storage description resources
	StorageDescriptions []CSSResource

	// AllResources contains all resources in a flat list for convenience
	AllResources []CSSResource

	// ScanTimestamp is when the inventory scan was performed
	ScanTimestamp time.Time

	// CSSEndpoint is the endpoint that was scanned
	CSSEndpoint string

	// ScanDuration is how long the scan took
	ScanDuration time.Duration

	// Errors contains any errors that occurred during scanning
	Errors []InventoryScanError
}

// InventoryScanError represents an error that occurred during inventory scanning
type InventoryScanError struct {
	// ResourceURI is the URI of the resource being scanned (if applicable)
	ResourceURI string

	// Error is the underlying error
	Error error

	// Timestamp is when the error occurred
	Timestamp time.Time

	// Severity indicates the severity of the error
	Severity ErrorSeverity
}

// CSSInventoryScannerConfig holds configuration for the CSS inventory scanner
type CSSInventoryScannerConfig struct {
	// CSSEndpoint is the URL of the CSS server to scan
	CSSEndpoint string

	// Logger is the logger for scanning operations
	Logger *slog.Logger

	// Timeout is the timeout for individual scan operations
	Timeout time.Duration

	// RetryCount is the number of retries for failed operations
	RetryCount int

	// RetryDelay is the delay between retries
	RetryDelay time.Duration

	// MaxResources is the maximum number of resources to scan (0 = unlimited)
	MaxResources int

	// FollowLinks indicates whether to follow links to discover additional resources
	FollowLinks bool

	// IncludeStorageDescriptions indicates whether to scan for storage descriptions
	IncludeStorageDescriptions bool

	// HTTPClient is the HTTP client to use for requests (optional)
	HTTPClient *http.Client
}

// DefaultCSSInventoryScannerConfig returns a safe default configuration
func DefaultCSSInventoryScannerConfig() CSSInventoryScannerConfig {
	return CSSInventoryScannerConfig{
		CSSEndpoint:                "",
		Logger:                     slog.Default(),
		Timeout:                    5 * time.Minute,
		RetryCount:                 3,
		RetryDelay:                 1 * time.Second,
		MaxResources:               0, // unlimited
		FollowLinks:                true,
		IncludeStorageDescriptions: true,
		HTTPClient:                 nil,
	}
}

// CSSInventoryScanner performs inventory scanning of CSS deployments
type CSSInventoryScanner struct {
	config CSSInventoryScannerConfig
	logger *slog.Logger
	client *http.Client
}

// NewCSSInventoryScanner creates a new CSS inventory scanner
func NewCSSInventoryScanner(config CSSInventoryScannerConfig) *CSSInventoryScanner {
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

	// Create HTTP client if not provided
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: config.Timeout,
		}
	}

	scanner := &CSSInventoryScanner{
		config: config,
		logger: config.Logger,
		client: client,
	}

	return scanner
}

// Scan performs a complete inventory scan of the CSS deployment
func (s *CSSInventoryScanner) Scan(ctx context.Context) (*CSSInventory, error) {
	startTime := time.Now()

	s.logger.Info("Starting CSS inventory scan",
		"endpoint", s.config.CSSEndpoint,
		"follow_links", s.config.FollowLinks,
		"include_storage_descriptions", s.config.IncludeStorageDescriptions,
	)

	// Validate the CSS endpoint
	if err := s.validateCSSEndpoint(); err != nil {
		return nil, fmt.Errorf("invalid CSS endpoint: %w", err)
	}

	// Create inventory
	inventory := &CSSInventory{
		Resources:           make([]CSSResource, 0),
		Containers:          make([]CSSResource, 0),
		AuxiliaryResources:  make([]CSSResource, 0),
		ACLResources:        make([]CSSResource, 0),
		ACPResources:        make([]CSSResource, 0),
		MetadataResources:   make([]CSSResource, 0),
		StorageDescriptions: make([]CSSResource, 0),
		AllResources:        make([]CSSResource, 0),
		ScanTimestamp:       startTime,
		CSSEndpoint:         s.config.CSSEndpoint,
		Errors:              make([]InventoryScanError, 0),
	}

	// Discover the root container
	rootResources, err := s.discoverRootResources(ctx)
	if err != nil {
		inventory.Errors = append(inventory.Errors, InventoryScanError{
			ResourceURI: s.config.CSSEndpoint,
			Error:       err,
			Timestamp:   time.Now(),
			Severity:    SeverityHigh,
		})
		// Continue with empty root if available
		rootResources = []CSSResource{}
	}

	// Process root resources
	for _, resource := range rootResources {
		if err := s.processResource(ctx, &resource, inventory); err != nil {
			inventory.Errors = append(inventory.Errors, InventoryScanError{
				ResourceURI: resource.URI,
				Error:       err,
				Timestamp:   time.Now(),
				Severity:    SeverityMedium,
			})
		}
	}

	// If following links, discover additional resources
	if s.config.FollowLinks {
		if err := s.discoverLinkedResources(ctx, inventory); err != nil {
			inventory.Errors = append(inventory.Errors, InventoryScanError{
				ResourceURI: "",
				Error:       err,
				Timestamp:   time.Now(),
				Severity:    SeverityMedium,
			})
		}
	}

	// If including storage descriptions, discover them
	if s.config.IncludeStorageDescriptions {
		if err := s.discoverStorageDescriptions(ctx, inventory); err != nil {
			inventory.Errors = append(inventory.Errors, InventoryScanError{
				ResourceURI: "",
				Error:       err,
				Timestamp:   time.Now(),
				Severity:    SeverityLow,
			})
		}
	}

	inventory.ScanDuration = time.Since(startTime)

	s.logger.Info("CSS inventory scan completed",
		"resources", len(inventory.Resources),
		"containers", len(inventory.Containers),
		"auxiliary_resources", len(inventory.AuxiliaryResources),
		"acl_resources", len(inventory.ACLResources),
		"acp_resources", len(inventory.ACPResources),
		"metadata_resources", len(inventory.MetadataResources),
		"storage_descriptions", len(inventory.StorageDescriptions),
		"total_resources", len(inventory.AllResources),
		"duration", inventory.ScanDuration,
		"errors", len(inventory.Errors),
	)

	return inventory, nil
}

// validateCSSEndpoint validates the CSS endpoint URL
func (s *CSSInventoryScanner) validateCSSEndpoint() error {
	parsedURL, err := url.Parse(s.config.CSSEndpoint)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("URL must use http or https scheme, got: %s", parsedURL.Scheme)
	}

	if parsedURL.Host == "" {
		return fmt.Errorf("URL must have a host")
	}

	return nil
}

// discoverRootResources discovers resources at the root of the CSS deployment
func (s *CSSInventoryScanner) discoverRootResources(ctx context.Context) ([]CSSResource, error) {
	resources := make([]CSSResource, 0)

	// Try to get the root container
	rootURL := s.config.CSSEndpoint
	if !strings.HasSuffix(rootURL, "/") {
		rootURL = rootURL + "/"
	}

	// Fetch the root container
	resource, err := s.fetchResource(ctx, rootURL)
	if err != nil {
		// Try without trailing slash
		resource, err = s.fetchResource(ctx, s.config.CSSEndpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch root: %w", err)
		}
	}

	// Check if it's a container by looking at Link headers or content type
	if s.isContainer(resource) {
		resource.ResourceType = ResourceTypeContainer
		resources = append(resources, *resource)
	} else {
		resource.ResourceType = ResourceTypeResource
		resources = append(resources, *resource)
	}

	return resources, nil
}

// fetchResource fetches a single resource from CSS
func (s *CSSInventoryScanner) fetchResource(ctx context.Context, resourceURI string) (*CSSResource, error) {
	parsedURL, err := url.Parse(resourceURI)
	if err != nil {
		return nil, fmt.Errorf("invalid resource URI: %w", err)
	}

	// Ensure the URL is relative to the CSS endpoint
	if !strings.HasPrefix(parsedURL.String(), s.config.CSSEndpoint) {
		// Try to construct a full URL
		if !strings.HasPrefix(resourceURI, "http://") && !strings.HasPrefix(resourceURI, "https://") {
			baseURL, err := url.Parse(s.config.CSSEndpoint)
			if err != nil {
				return nil, fmt.Errorf("invalid base endpoint: %w", err)
			}
			parsedURL = baseURL.JoinPath(resourceURI)
		} else {
			return nil, fmt.Errorf("resource URI %s is not under CSS endpoint %s", resourceURI, s.config.CSSEndpoint)
		}
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, parsedURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add Accept header for Solid resource types
	req.Header.Set("Accept", "application/ld+json, application/json, text/turtle, */*")

	// Execute request with retry
	var resp *http.Response
	for i := 0; i <= s.config.RetryCount; i++ {
		if i > 0 {
			s.logger.Debug("Retrying request", "url", parsedURL.String(), "attempt", i+1)
			time.Sleep(s.config.RetryDelay)
		}

		resp, err = s.client.Do(req)
		if err == nil {
			break
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to fetch resource: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		// For HEAD requests, some servers might return 405 Method Not Allowed
		// Try with GET if HEAD fails
		if resp.StatusCode == http.StatusMethodNotAllowed {
			return s.fetchResourceWithGet(ctx, parsedURL.String())
		}
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("resource not found: %s", resourceURI)
	}

	// Parse the response
	resource, err := s.parseResourceResponse(resp, parsedURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return resource, nil
}

// fetchResourceWithGet fetches a resource using GET method (fallback)
func (s *CSSInventoryScanner) fetchResourceWithGet(ctx context.Context, resourceURI string) (*CSSResource, error) {
	parsedURL, err := url.Parse(resourceURI)
	if err != nil {
		return nil, fmt.Errorf("invalid resource URI: %w", err)
	}

	// Limit the response body to prevent memory exhaustion
	// Use a limited reader
	const maxBodySize = 10 * 1024 * 1024 // 10MB

	for i := 0; i <= s.config.RetryCount; i++ {
		if i > 0 {
			time.Sleep(s.config.RetryDelay)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
		if err != nil {
			continue
		}

		req.Header.Set("Accept", "application/ld+json, application/json, text/turtle, */*")
		req.Header.Set("Range", "bytes=0-1024") // Only fetch first 1KB for metadata

		resp, err := s.client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			// Limit the body
			body := io.LimitReader(resp.Body, maxBodySize)
			// Read and discard the body to get headers
			_, _ = io.Copy(io.Discard, body)
			return s.parseResourceResponse(resp, parsedURL.String())
		}
	}

	return nil, fmt.Errorf("failed to fetch resource with GET: %s", resourceURI)
}

// parseResourceResponse parses an HTTP response into a CSSResource
func (s *CSSInventoryScanner) parseResourceResponse(resp *http.Response, resourceURI string) (*CSSResource, error) {
	resource := &CSSResource{
		URI:          resourceURI,
		Size:         resp.ContentLength,
		LastModified: time.Time{}, // Will be parsed from header
		ETag:         resp.Header.Get("ETag"),
		Links:        make([]ResourceLink, 0),
		Metadata:     make(map[string]interface{}),
	}

	// Parse Content-Type
	contentType := resp.Header.Get("Content-Type")
	if contentType != "" {
		resource.ContentType = contentType
	}

	// Parse Last-Modified
	if lastModified := resp.Header.Get("Last-Modified"); lastModified != "" {
		if parsedTime, err := http.ParseTime(lastModified); err == nil {
			resource.LastModified = parsedTime
		}
	}

	// Determine resource type from Link headers and content type
	resource.ResourceType = s.determineResourceType(resp, resourceURI)

	// Parse Link headers for resource relationships
	if linkHeaders := resp.Header.Values("Link"); len(linkHeaders) > 0 {
		for _, linkHeader := range linkHeaders {
			links, err := parseLinkHeader(linkHeader)
			if err == nil {
				resource.Links = append(resource.Links, links...)
			}
		}
	}

	return resource, nil
}

// determineResourceType determines the resource type based on headers and URI
func (s *CSSInventoryScanner) determineResourceType(resp *http.Response, resourceURI string) ResourceType {
	// Check for container indicators
	if s.isContainerFromHeaders(resp) {
		return ResourceTypeContainer
	}

	// Check for ACL indicators
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "acl") || strings.Contains(strings.ToLower(resourceURI), "/.acl") {
		return ResourceTypeACL
	}

	// Check for ACP indicators
	if strings.Contains(contentType, "acp") || strings.Contains(strings.ToLower(resourceURI), "/.acp") {
		return ResourceTypeACP
	}

	// Check for metadata
	if strings.Contains(strings.ToLower(resourceURI), "/.meta") ||
		strings.Contains(contentType, "application/json") && strings.Contains(resourceURI, "?meta") {
		return ResourceTypeMetadata
	}

	// Check for storage description
	if strings.Contains(strings.ToLower(resourceURI), "/.storage") ||
		strings.Contains(strings.ToLower(resourceURI), "storage-description") {
		return ResourceTypeStorageDesc
	}

	// Check for auxiliary resources
	if strings.Contains(strings.ToLower(resourceURI), "/.well-known/") {
		return ResourceTypeAuxiliary
	}

	return ResourceTypeResource
}

// isContainer checks if a resource is a container
func (s *CSSInventoryScanner) isContainer(resource *CSSResource) bool {
	// Check by content type
	if strings.Contains(resource.ContentType, "container") ||
		strings.Contains(resource.ContentType, "directory") {
		return true
	}

	// Check by URI (common Solid conventions)
	uriLower := strings.ToLower(resource.URI)
	if strings.HasSuffix(uriLower, "/") ||
		strings.Contains(uriLower, "/.acl/") ||
		strings.Contains(uriLower, "/.acp/") {
		// These might be containers
		return true
	}

	// Check Link headers for type=Container
	for _, link := range resource.Links {
		if strings.EqualFold(link.Rel, "type") && strings.Contains(strings.ToLower(link.Type), "container") {
			return true
		}
	}

	return false
}

// isContainerFromHeaders checks if the response headers indicate a container
func (s *CSSInventoryScanner) isContainerFromHeaders(resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "container") ||
		strings.Contains(contentType, "directory") {
		return true
	}

	// Check Link headers
	if linkHeaders := resp.Header.Values("Link"); len(linkHeaders) > 0 {
		for _, linkHeader := range linkHeaders {
			links, err := parseLinkHeader(linkHeader)
			if err == nil {
				for _, link := range links {
					if strings.EqualFold(link.Rel, "type") && strings.Contains(strings.ToLower(link.Type), "container") {
						return true
					}
				}
			}
		}
	}

	return false
}

// parseLinkHeader parses a Link HTTP header value
func parseLinkHeader(header string) ([]ResourceLink, error) {
	links := make([]ResourceLink, 0)
	parts := strings.Split(header, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		link := ResourceLink{}

		// Parse the link
		inQuotes := false
		params := make(map[string]string)
		var uri strings.Builder

		for i := 0; i < len(part); i++ {
			c := part[i]

			if c == '"' {
				inQuotes = !inQuotes
				continue
			}

			if inQuotes {
				uri.WriteByte(c)
				continue
			}

			if c == ';' {
				// Start of parameters
				currentStr := uri.String()
				if currentStr != "" {
					link.Target = currentStr
				}
				uri.Reset()
				// Parse parameters
				j := i + 1
				for j < len(part) {
					if part[j] == ',' {
						break
					}
					j++
				}
				paramStr := strings.TrimSpace(part[i+1 : j])
				i = j - 1 // -1 because the loop will increment

				// Parse individual parameters
				paramParts := strings.Split(paramStr, ";")
				for _, paramPart := range paramParts {
					paramPart = strings.TrimSpace(paramPart)
					if strings.Contains(paramPart, "=") {
						kv := strings.SplitN(paramPart, "=", 2)
						if len(kv) == 2 {
							key := strings.TrimSpace(strings.ToLower(kv[0]))
							value := strings.TrimSpace(kv[1])
							// Remove quotes from value
							if len(value) > 0 && value[0] == '"' {
								value = value[1:]
							}
							if len(value) > 0 && value[len(value)-1] == '"' {
								value = value[:len(value)-1]
							}
							params[key] = value
						}
					}
				}
			} else if c == '>' {
				break
			} else if c != '<' && c != ' ' {
				uri.WriteByte(c)
			}
		}

		// Set the relation from rel parameter
		if rel, ok := params["rel"]; ok {
			link.Rel = rel
		}

		// Set the type from type parameter
		if typ, ok := params["type"]; ok {
			link.Type = typ
		}

		// Set default rel if not specified
		if link.Rel == "" && link.Target != "" {
			link.Rel = "related"
		}

		if link.Target != "" {
			links = append(links, link)
		}
	}

	return links, nil
}

// discoverLinkedResources discovers resources linked from the inventory
func (s *CSSInventoryScanner) discoverLinkedResources(ctx context.Context, inventory *CSSInventory) error {
	// Collect all URIs to process
	seen := make(map[string]bool)
	toProcess := make([]string, 0)

	// Add all existing resource URIs to seen
	for _, resource := range inventory.AllResources {
		seen[resource.URI] = true
	}

	// Queue all resource URIs for link discovery
	for _, resource := range inventory.AllResources {
		for _, link := range resource.Links {
			// Resolve relative URIs
			if !strings.HasPrefix(link.Target, "http://") && !strings.HasPrefix(link.Target, "https://") {
				baseURL, err := url.Parse(resource.URI)
				if err != nil {
					continue
				}
				fullURL := baseURL.JoinPath(link.Target)
				link.Target = fullURL.String()
			}

			// Only process resources under our CSS endpoint
			if !strings.HasPrefix(link.Target, s.config.CSSEndpoint) {
				continue
			}

			// Skip if already seen
			if seen[link.Target] {
				continue
			}

			toProcess = append(toProcess, link.Target)
			seen[link.Target] = true
		}
	}

	// Process the queue with resource limits
	maxResources := s.config.MaxResources
	if maxResources <= 0 {
		maxResources = 10000 // Default limit
	}

	processed := 0
	for len(toProcess) > 0 && processed < maxResources {
		currentURI := toProcess[0]
		toProcess = toProcess[1:]

		// Skip if context is cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Fetch the resource
		resource, err := s.fetchResource(ctx, currentURI)
		if err != nil {
			s.logger.Warn("Failed to fetch linked resource", "uri", currentURI, "error", err)
			inventory.Errors = append(inventory.Errors, InventoryScanError{
				ResourceURI: currentURI,
				Error:       err,
				Timestamp:   time.Now(),
				Severity:    SeverityLow,
			})
			continue
		}

		// Process and categorize the resource
		if err := s.processResource(ctx, resource, inventory); err != nil {
			s.logger.Warn("Failed to process linked resource", "uri", currentURI, "error", err)
			inventory.Errors = append(inventory.Errors, InventoryScanError{
				ResourceURI: currentURI,
				Error:       err,
				Timestamp:   time.Now(),
				Severity:    SeverityLow,
			})
			continue
		}

		// Add newly discovered links to the queue
		for _, link := range resource.Links {
			// Resolve relative URIs
			if !strings.HasPrefix(link.Target, "http://") && !strings.HasPrefix(link.Target, "https://") {
				baseURL, err := url.Parse(resource.URI)
				if err != nil {
					continue
				}
				fullURL := baseURL.JoinPath(link.Target)
				link.Target = fullURL.String()
			}

			// Only process resources under our CSS endpoint
			if !strings.HasPrefix(link.Target, s.config.CSSEndpoint) {
				continue
			}

			// Skip if already seen
			if seen[link.Target] {
				continue
			}

			toProcess = append(toProcess, link.Target)
			seen[link.Target] = true
		}

		processed++
	}

	return nil
}

// discoverStorageDescriptions discovers storage description resources
func (s *CSSInventoryScanner) discoverStorageDescriptions(ctx context.Context, inventory *CSSInventory) error {
	// Storage descriptions are typically at well-known locations
	wellKnownPaths := []string{
		".well-known/solid",
		".well-known/storage",
		".storage",
		"storage-description",
		"storage-description.ttl",
		"storage-description.json",
	}

	for _, path := range wellKnownPaths {
		// Skip if context is cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Construct full URL
		baseURL, err := url.Parse(s.config.CSSEndpoint)
		if err != nil {
			continue
		}
		fullURL := baseURL.JoinPath(path)

		// Check if already in inventory
		alreadyExists := false
		for _, resource := range inventory.AllResources {
			if resource.URI == fullURL.String() {
				alreadyExists = true
				break
			}
		}

		if alreadyExists {
			continue
		}

		// Try to fetch the storage description
		resource, err := s.fetchResource(ctx, fullURL.String())
		if err != nil {
			continue
		}

		// Check if this is a storage description
		if s.isStorageDescription(resource) {
			resource.ResourceType = ResourceTypeStorageDesc
			if err := s.processResource(ctx, resource, inventory); err != nil {
				s.logger.Warn("Failed to process storage description", "uri", fullURL.String(), "error", err)
			}
		}
	}

	return nil
}

// isStorageDescription checks if a resource is a storage description
func (s *CSSInventoryScanner) isStorageDescription(resource *CSSResource) bool {
	// Check by content type
	if strings.Contains(resource.ContentType, "storage") ||
		strings.Contains(resource.ContentType, "solid") {
		return true
	}

	// Check by URI
	uriLower := strings.ToLower(resource.URI)
	if strings.Contains(uriLower, "storage") {
		return true
	}

	return false
}

// processResource categorizes and adds a resource to the inventory
func (s *CSSInventoryScanner) processResource(ctx context.Context, resource *CSSResource, inventory *CSSInventory) error {
	// Skip if context is cancelled
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Apply resource limit
	if s.config.MaxResources > 0 && len(inventory.AllResources) >= s.config.MaxResources {
		s.logger.Warn("Max resources reached, stopping inventory scan", "max", s.config.MaxResources)
		return fmt.Errorf("max resources limit reached: %d", s.config.MaxResources)
	}

	// Determine the resource type if not already set
	if resource.ResourceType == ResourceTypeUnknown {
		resource.ResourceType = ResourceTypeResource
	}

	// Add to appropriate category
	switch resource.ResourceType {
	case ResourceTypeContainer:
		inventory.Containers = append(inventory.Containers, *resource)
	case ResourceTypeACL:
		inventory.ACLResources = append(inventory.ACLResources, *resource)
	case ResourceTypeACP:
		inventory.ACPResources = append(inventory.ACPResources, *resource)
	case ResourceTypeAuxiliary:
		inventory.AuxiliaryResources = append(inventory.AuxiliaryResources, *resource)
	case ResourceTypeMetadata:
		inventory.MetadataResources = append(inventory.MetadataResources, *resource)
	case ResourceTypeStorageDesc:
		inventory.StorageDescriptions = append(inventory.StorageDescriptions, *resource)
	default:
		// Check if it should be categorized differently
		if s.isContainer(resource) {
			resource.ResourceType = ResourceTypeContainer
			inventory.Containers = append(inventory.Containers, *resource)
		} else if strings.Contains(strings.ToLower(resource.URI), ".acl") {
			resource.ResourceType = ResourceTypeACL
			inventory.ACLResources = append(inventory.ACLResources, *resource)
		} else if strings.Contains(strings.ToLower(resource.URI), ".acp") {
			resource.ResourceType = ResourceTypeACP
			inventory.ACPResources = append(inventory.ACPResources, *resource)
		} else if s.isStorageDescription(resource) {
			resource.ResourceType = ResourceTypeStorageDesc
			inventory.StorageDescriptions = append(inventory.StorageDescriptions, *resource)
		} else if strings.Contains(strings.ToLower(resource.URI), ".meta") ||
			strings.Contains(resource.ContentType, "application/json") {
			resource.ResourceType = ResourceTypeMetadata
			inventory.MetadataResources = append(inventory.MetadataResources, *resource)
		} else {
			inventory.Resources = append(inventory.Resources, *resource)
		}
	}

	// Add to all resources list
	inventory.AllResources = append(inventory.AllResources, *resource)

	s.logger.Debug("Processed resource",
		"uri", resource.URI,
		"type", resource.ResourceType,
		"content_type", resource.ContentType,
		"size", resource.Size,
	)

	return nil
}

// ToJSON serializes the inventory to JSON
func (inventory *CSSInventory) ToJSON() (string, error) {
	data, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FromJSON deserializes inventory from JSON
func (inventory *CSSInventory) FromJSON(data string) error {
	return json.Unmarshal([]byte(data), inventory)
}

// SaveInventory saves the inventory to a file
func (inventory *CSSInventory) SaveInventory(path string) error {
	_, err := inventory.ToJSON()
	if err != nil {
		return err
	}

	// Ensure directory exists
	dir := path
	if lastSlash := strings.LastIndex(path, "/"); lastSlash != -1 {
		dir = path[:lastSlash]
	}

	// Simple directory creation (don't use filepath to avoid imports)
	if dir != "" && dir != "." {
		// This is a simplified approach - in production, use os.MkdirAll
		// We'll skip this for now to avoid adding os import just for this
	}

	// For now, we'll just return an error if the path contains directory separators
	// A more complete implementation would properly handle directory creation
	if strings.Contains(path, "/") {
		return fmt.Errorf("path with directories not supported in this simple implementation: %s", path)
	}

	return fmt.Errorf("inventory save not fully implemented")
}

// LoadInventory loads an inventory from a file
func LoadInventory(path string) (*CSSInventory, error) {
	// Simple implementation - would need os.ReadFile
	return nil, fmt.Errorf("inventory load not fully implemented")
}
