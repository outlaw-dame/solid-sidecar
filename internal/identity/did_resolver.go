package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Resolver provides DID resolution functionality
type Resolver struct {
	options       ResolverOptions
	parser        *DIDParser
	logger        *slog.Logger
	cache         *DIDCache
	localRegistry map[string]DIDDocument // DID string -> DID document (for tests)
	mu            sync.RWMutex
}

// NewResolver creates a new DID resolver
func NewResolver(options ResolverOptions, parser *DIDParser) *Resolver {
	if parser == nil {
		parser = NewDIDParser(DefaultDIDParserOptions())
	}

	var cache *DIDCache
	if options.CacheTTLSeconds > 0 {
		cache = NewDIDCache(time.Duration(options.CacheTTLSeconds) * time.Second)
	}

	return &Resolver{
		options:       options,
		parser:        parser,
		logger:        options.Logger,
		cache:         cache,
		localRegistry: make(map[string]DIDDocument),
	}
}

// Resolve resolves a DID to its DID document
func (r *Resolver) Resolve(ctx context.Context, didString string) (DIDDocumentMetadata, error) {
	// Check if resolver is enabled
	if !r.options.Enabled {
		return DIDDocumentMetadata{}, errors.New("DID resolver is disabled")
	}

	// Parse the DID
	did, err := r.parser.ParseDID(didString)
	if err != nil {
		return DIDDocumentMetadata{}, fmt.Errorf("failed to parse DID: %w", err)
	}

	// Check cache first
	if r.cache != nil {
		if cached, ok := r.cache.Get(did.NormalizedString()); ok {
			return cached, nil
		}
	}

	// Check local registry (for tests)
	r.mu.RLock()
	if doc, ok := r.localRegistry[did.NormalizedString()]; ok {
		r.mu.RUnlock()
		metadata := DIDDocumentMetadata{
			DID:        did,
			Document:   doc,
			ResolvedAt: time.Now(),
			IsCached:   false,
		}
		// Cache it
		if r.cache != nil {
			r.cache.Set(did.NormalizedString(), metadata)
		}
		return metadata, nil
	}
	r.mu.RUnlock()

	// Try to resolve using configured resolvers
	for _, resolverType := range r.options.AllowedResolvers {
		switch resolverType {
		case "local":
			// Already checked local registry above
			continue
		case "https":
			if r.options.DefaultMappingEnabled {
				metadata, err := r.resolveViaHTTPS(ctx, did)
				if err == nil {
					// Cache it
					if r.cache != nil {
						r.cache.Set(did.NormalizedString(), metadata)
					}
					return metadata, nil
				}
				// Log but don't fail - try next resolver
				r.logResolutionError(didString, err)
			}
		default:
			r.logResolutionWarning(fmt.Sprintf("unknown resolver type: %s", resolverType))
		}
	}

	return DIDDocumentMetadata{}, fmt.Errorf("%w: %s", ErrInvalidDID, didString)
}

// resolveViaHTTPS resolves a DID using the default HTTPS mapping
// For did:solid:<host>, tries https://<host>/.well-known/did/solid.json
func (r *Resolver) resolveViaHTTPS(ctx context.Context, did DID) (DIDDocumentMetadata, error) {
	// Only supports host-like IDs for now
	if !r.parser.IsHostLikeID(did.MethodSpecificID) {
		return DIDDocumentMetadata{}, fmt.Errorf("%w: non-host-like IDs require explicit resolver configuration", ErrInvalidDID)
	}

	// Construct URL: https://<host>/.well-known/did/solid.json
	host := r.parser.NormalizeHostLikeID(did.MethodSpecificID)
	rawURL := fmt.Sprintf("https://%s/.well-known/did/solid.json", host)

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return DIDDocumentMetadata{}, fmt.Errorf("invalid resolution URL: %w", err)
	}
	if err := validateOutboundResolutionURL(parsedURL); err != nil {
		return DIDDocumentMetadata{}, err
	}

	// Check context deadline
	if err := ctx.Err(); err != nil {
		return DIDDocumentMetadata{}, fmt.Errorf("context cancelled: %w", err)
	}

	// Create HTTP client with timeout and no redirects
	client := newResolverHTTPClient(r.options.TimeoutSeconds)

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return DIDDocumentMetadata{}, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Accept", "application/did+json")
	req.Header.Set("User-Agent", "solid-sidecar/1.0")

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return DIDDocumentMetadata{}, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return DIDDocumentMetadata{}, fmt.Errorf("HTTP %d: %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	// Check content type
	contentType := resp.Header.Get("Content-Type")
	if !isAllowedDIDDocumentContentType(contentType) {
		return DIDDocumentMetadata{}, fmt.Errorf("unexpected content type: %s", contentType)
	}

	// Read response body with size limit
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(r.options.MaxDocumentBytes)+1))
	if err != nil {
		return DIDDocumentMetadata{}, fmt.Errorf("failed to read response: %w", err)
	}

	// Check size
	if len(body) > r.options.MaxDocumentBytes {
		return DIDDocumentMetadata{}, fmt.Errorf("%w: response exceeds maximum size", ErrDIDTooLong)
	}

	// Parse DID document
	var doc DIDDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return DIDDocumentMetadata{}, fmt.Errorf("failed to parse DID document: %w", err)
	}

	// Validate document
	if err := r.parser.ValidateDIDDocument(doc); err != nil {
		return DIDDocumentMetadata{}, fmt.Errorf("DID document validation failed: %w", err)
	}

	// Verify document ID matches expected DID
	if doc.ID != did.NormalizedString() {
		return DIDDocumentMetadata{}, fmt.Errorf("%w: document ID '%s' does not match expected DID '%s'",
			ErrInvalidDID, doc.ID, did.NormalizedString())
	}

	// Check for deactivation
	if doc.Deactivated {
		return DIDDocumentMetadata{}, fmt.Errorf("%w: DID is deactivated", ErrInvalidDID)
	}

	// Create metadata
	metadata := DIDDocumentMetadata{
		DID:        did,
		Document:   doc,
		ResolvedAt: time.Now(),
		SourceURL:  parsedURL,
		IsCached:   false,
	}

	// Set expiration
	expiresAt := time.Now().Add(time.Duration(r.options.CacheTTLSeconds) * time.Second)
	metadata.ExpiresAt = &expiresAt

	return metadata, nil
}

// RegisterLocalDID registers a DID document in the local registry (for testing)
func (r *Resolver) RegisterLocalDID(didString string, doc DIDDocument) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	did, err := r.parser.ParseDID(didString)
	if err != nil {
		return fmt.Errorf("invalid DID: %w", err)
	}

	// Validate document
	if err := r.parser.ValidateDIDDocument(doc); err != nil {
		return fmt.Errorf("invalid DID document: %w", err)
	}

	// Verify document ID matches
	if doc.ID != did.NormalizedString() {
		return fmt.Errorf("document ID does not match DID")
	}

	r.localRegistry[did.NormalizedString()] = doc
	return nil
}

// ValidateWebIDBacklink validates the bidirectional binding between DID and WebID
func (r *Resolver) ValidateWebIDBacklink(ctx context.Context, didString string, webID string) error {
	// Parse and resolve the DID
	metadata, err := r.Resolve(ctx, didString)
	if err != nil {
		return fmt.Errorf("failed to resolve DID: %w", err)
	}

	// Get WebID service from DID document
	webIDService := metadata.Document.GetSolidWebIDService()
	if webIDService == nil {
		return fmt.Errorf("%w: no WebID service in DID document", ErrWebIDBacklinkMissing)
	}

	// Verify WebID service endpoint matches the provided WebID
	if webIDService.ServiceEndpoint != webID {
		return fmt.Errorf("%w: WebID service endpoint '%s' does not match provided WebID '%s'",
			ErrWebIDBacklinkMissing, webIDService.ServiceEndpoint, webID)
	}

	// Verify WebID service uses HTTPS
	if !webIDService.IsHTTPS() {
		return fmt.Errorf("%w: WebID service endpoint must use HTTPS", ErrWebIDBacklinkMissing)
	}

	// Fetch WebID profile and check for backlink
	if err := r.validateWebIDProfileBacklink(ctx, metadata.DID, webID); err != nil {
		return err
	}

	return nil
}

// validateWebIDProfileBacklink fetches a WebID profile and verifies it links back to the DID
func (r *Resolver) validateWebIDProfileBacklink(ctx context.Context, did DID, webID string) error {
	// Create HTTP client with timeout and no redirects
	client := newResolverHTTPClient(r.options.TimeoutSeconds)

	// Parse WebID URL
	webIDURL, err := url.Parse(webID)
	if err != nil {
		return fmt.Errorf("invalid WebID URL: %w", err)
	}

	// Check context deadline
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled: %w", err)
	}

	if err := validateOutboundResolutionURL(webIDURL); err != nil {
		return fmt.Errorf("%w: WebID profile URL is not allowed", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, webIDURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Accept", "text/turtle,application/ld+json,application/json")
	req.Header.Set("User-Agent", "solid-sidecar/1.0")

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		// In shadow mode, we don't fail hard - just log and return a warning
		r.logResolutionWarning(fmt.Sprintf("failed to fetch WebID profile: %v", err))
		return nil // WebID-only identity can still be valid
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		// In shadow mode, don't fail hard
		r.logResolutionWarning(fmt.Sprintf("WebID profile returned status %d", resp.StatusCode))
		return nil
	}

	// Read response body with size limit
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(r.options.MaxDocumentBytes)+1))
	if err != nil {
		r.logResolutionWarning(fmt.Sprintf("failed to read WebID profile: %v", err))
		return nil
	}

	// Check size
	if len(body) > r.options.MaxDocumentBytes {
		r.logResolutionWarning("WebID profile exceeds maximum size")
		return nil
	}

	// Parse the WebID profile to find the backlink
	// For now, we do a simple string search for the DID in the response
	// In a real implementation, we would parse RDF and look for the predicate
	bodyStr := string(body)

	// Check for the backlink using the predicate
	// The predicate is: <#me> <https://solidproject.org/ns/did#controller> <did:solid:alice.example> .
	if !containsBacklink(bodyStr, did.NormalizedString(), WebIDBacklinkPredicate) {
		return fmt.Errorf("%w: WebID profile does not contain backlink to DID '%s'",
			ErrWebIDBacklinkMissing, did.NormalizedString())
	}

	return nil
}

// containsBacklink checks if a WebID profile contains a backlink to a DID
// This is a simplified implementation - in production, use a proper RDF parser
func containsBacklink(body, did, predicate string) bool {
	// Look for patterns like:
	// <#me> <predicate> <did> .
	// or variations with different quoting

	// Simple string search for now
	// In production, this should use the RDF parser from internal/authz
	return containsString(body, did) && containsString(body, predicate)
}

// containsString is a helper to check if a string contains a substring (case-insensitive)
func containsString(haystack, needle string) bool {
	return containsCIString(haystack, needle)
}

// containsCIString checks for case-insensitive substring
func containsCIString(haystack, needle string) bool {
	return containsStringCI(haystack, needle)
}

// Simple implementation for now
func containsStringCI(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstringCI(s, substr))
}

func containsSubstringCI(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if equalCI(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func equalCI(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if toLower(a[i]) != toLower(b[i]) {
			return false
		}
	}
	return true
}

func toLower(r byte) byte {
	if 'A' <= r && r <= 'Z' {
		return r + ('a' - 'A')
	}
	return r
}

// logResolutionError logs a resolution error
func (r *Resolver) logResolutionError(did string, err error) {
	if r.logger != nil {
		r.logger.Error("DID resolution error",
			"did_method", "solid",
			"error", err,
		)
	}
}

// logResolutionWarning logs a resolution warning
func (r *Resolver) logResolutionWarning(message string) {
	if r.logger != nil {
		r.logger.Warn("DID resolution warning",
			"message", message,
		)
	}
}

// ValidateDIDBinding performs full DID/WebID bidirectional binding validation
func (r *Resolver) ValidateDIDBinding(ctx context.Context, didString, webID string) error {
	// Parse DID
	did, err := r.parser.ParseDID(didString)
	if err != nil {
		return fmt.Errorf("invalid DID: %w", err)
	}

	// Check if DID is did:solid
	if !did.IsSolidDID() {
		return fmt.Errorf("%w: only did:solid DIDs are supported", ErrInvalidDIDMethod)
	}

	// Resolve DID document
	metadata, err := r.Resolve(ctx, didString)
	if err != nil {
		return fmt.Errorf("failed to resolve DID: %w", err)
	}

	// Check document is valid
	if !metadata.IsValid() {
		return fmt.Errorf("%w: resolved DID document is invalid", ErrDIDBindingFailed)
	}

	// Check for deactivation
	if metadata.Document.Deactivated {
		return fmt.Errorf("%w: DID is deactivated", ErrDIDBindingFailed)
	}

	// Validate WebID backlink
	if err := r.ValidateWebIDBacklink(ctx, didString, webID); err != nil {
		return fmt.Errorf("WebID backlink validation failed: %w", err)
	}

	// Verify DID document has required verification methods
	if len(metadata.Document.VerificationMethod) == 0 {
		return fmt.Errorf("%w: no verification methods in DID document", ErrDIDBindingFailed)
	}

	// Verify DID document has authentication
	if !metadata.Document.HasAuthentication() {
		return fmt.Errorf("%w: no authentication methods in DID document", ErrDIDBindingFailed)
	}

	// All checks passed
	return nil
}

// DIDCache provides caching for DID documents
type DIDCache struct {
	mu      sync.RWMutex
	entries map[string]DIDDocumentMetadata
	ttl     time.Duration
}

// NewDIDCache creates a new DID cache
func NewDIDCache(ttl time.Duration) *DIDCache {
	return &DIDCache{
		entries: make(map[string]DIDDocumentMetadata),
		ttl:     ttl,
	}
}

// Get retrieves a cached DID document
func (c *DIDCache) Get(did string) (DIDDocumentMetadata, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	metadata, ok := c.entries[did]
	if !ok {
		return DIDDocumentMetadata{}, false
	}

	// Check if expired
	if metadata.ExpiresAt != nil && time.Now().After(*metadata.ExpiresAt) {
		return DIDDocumentMetadata{}, false
	}

	return metadata, true
}

// Set stores a DID document in the cache
func (c *DIDCache) Set(did string, metadata DIDDocumentMetadata) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Set expiration
	expiresAt := time.Now().Add(c.ttl)
	metadata.ExpiresAt = &expiresAt
	metadata.IsCached = true

	c.entries[did] = metadata
}

// Delete removes a DID document from the cache
func (c *DIDCache) Delete(did string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, did)
}
