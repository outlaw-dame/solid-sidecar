// Package authz provides authorization policy handling for Solid.
package authz

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Default policy fetch configuration
const (
	// DefaultPolicyFetchTimeout is the default timeout for policy fetches
	DefaultPolicyFetchTimeout = 5 * time.Second

	// DefaultPolicyFetchMaxRetries is the default maximum number of retries
	DefaultPolicyFetchMaxRetries = 2

	// DefaultPolicyFetchRetryDelay is the default delay between retries
	DefaultPolicyFetchRetryDelay = 100 * time.Millisecond

	// DefaultPolicyFetchMaxBodySize is the default maximum body size for policy fetches
	// This is set to 1MB to prevent loading very large policy documents
	DefaultPolicyFetchMaxBodySize = 1 << 20 // 1 MiB

	// DefaultPolicyFetchUserAgent is the default User-Agent for policy fetches
	DefaultPolicyFetchUserAgent = "Solid-Sidecar-Policy-Loader/1.0"

	// DefaultPolicyFetchAccept is the default Accept header for policy fetches
	DefaultPolicyFetchAccept = "text/turtle, application/ld+json, application/n-triples, application/rdf+xml, application/sparql-results+json"
)

var (
	// ErrPolicyFetchTimeout is returned when a policy fetch times out
	ErrPolicyFetchTimeout = errors.New("policy fetch timed out")

	// ErrPolicyFetchTooLarge is returned when a policy fetch exceeds the size limit
	ErrPolicyFetchTooLarge = errors.New("policy fetch too large")

	// ErrPolicyFetchInvalidContentType is returned when a policy fetch has an invalid content type
	ErrPolicyFetchInvalidContentType = errors.New("policy fetch invalid content type")

	// ErrPolicyFetchUnsafeURI is returned when a policy URI is unsafe
	ErrPolicyFetchUnsafeURI = errors.New("policy fetch unsafe URI")

	// ErrPolicyFetchFailed is returned when a policy fetch fails
	ErrPolicyFetchFailed = errors.New("policy fetch failed")
)

// PolicyHTTPLoaderOptions configures the HTTP policy loader
type PolicyHTTPLoaderOptions struct {
	// HTTPClient is the HTTP client to use for fetches
	// If nil, http.DefaultClient is used
	HTTPClient *http.Client

	// Timeout is the timeout for policy fetches
	// Default: 5 seconds
	Timeout time.Duration

	// MaxRetries is the maximum number of retries for failed fetches
	// Default: 2
	MaxRetries int

	// RetryDelay is the delay between retries
	// Default: 100ms
	RetryDelay time.Duration

	// MaxBodySize is the maximum body size for policy fetches
	// Default: 1MB
	MaxBodySize int64

	// UserAgent is the User-Agent header to send
	// Default: "Solid-Sidecar-Policy-Loader/1.0"
	UserAgent string

	// Accept is the Accept header to send
	// Default: common RDF content types
	Accept string

	// AllowedSchemes is the list of allowed URI schemes
	// Default: ["http", "https"]
	AllowedSchemes []string

	// AllowedContentTypes is the list of allowed content types
	// If empty, all content types are allowed
	AllowedContentTypes []string

	// DisallowedContentTypes is the list of disallowed content types
	// These are always rejected even if AllowedContentTypes is set
	DisallowedContentTypes []string
}

// PolicyHTTPLoader loads policy documents from HTTP(S) URLs
type PolicyHTTPLoader struct {
	options PolicyHTTPLoaderOptions
	client  *http.Client
}

// NewPolicyHTTPLoader creates a new HTTP policy loader with default options
func NewPolicyHTTPLoader() *PolicyHTTPLoader {
	return NewPolicyHTTPLoaderWithOptions(PolicyHTTPLoaderOptions{})
}

// NewPolicyHTTPLoaderWithOptions creates a new HTTP policy loader with custom options
func NewPolicyHTTPLoaderWithOptions(options PolicyHTTPLoaderOptions) *PolicyHTTPLoader {
	loader := &PolicyHTTPLoader{options: options}

	// Set defaults
	if options.Timeout == 0 {
		loader.options.Timeout = DefaultPolicyFetchTimeout
	}
	if options.MaxRetries == 0 {
		loader.options.MaxRetries = DefaultPolicyFetchMaxRetries
	}
	if options.RetryDelay == 0 {
		loader.options.RetryDelay = DefaultPolicyFetchRetryDelay
	}
	if options.MaxBodySize == 0 {
		loader.options.MaxBodySize = DefaultPolicyFetchMaxBodySize
	}
	if options.UserAgent == "" {
		loader.options.UserAgent = DefaultPolicyFetchUserAgent
	}
	if options.Accept == "" {
		loader.options.Accept = DefaultPolicyFetchAccept
	}
	if len(options.AllowedSchemes) == 0 {
		loader.options.AllowedSchemes = []string{"http", "https"}
	}
	if len(options.DisallowedContentTypes) == 0 {
		loader.options.DisallowedContentTypes = []string{
			"text/html",
			"text/javascript",
			"application/javascript",
			"application/x-javascript",
			"application/ecmascript",
		}
	}

	// Use custom HTTP client or default
	if options.HTTPClient != nil {
		loader.client = options.HTTPClient
	} else {
		loader.client = &http.Client{
			Timeout: loader.options.Timeout,
		}
	}

	return loader
}

// LoadPolicySource implements PolicySourceLoader
func (l *PolicyHTTPLoader) LoadPolicySource(ctx context.Context, source PolicySource) (PolicySourceLoadResult, error) {
	// Validate the source URI
	if err := l.validatePolicySourceURI(source.URI); err != nil {
		return PolicySourceLoadResult{}, fmt.Errorf("%w: %w", ErrPolicyFetchUnsafeURI, err)
	}

	// Parse the URI
	parsedURL, err := url.Parse(source.URI)
	if err != nil {
		return PolicySourceLoadResult{}, fmt.Errorf("%w: invalid URI", ErrPolicyFetchUnsafeURI)
	}

	// Check scheme
	if !l.isAllowedScheme(parsedURL.Scheme) {
		return PolicySourceLoadResult{}, fmt.Errorf("%w: scheme %s not allowed", ErrPolicyFetchUnsafeURI, parsedURL.Scheme)
	}

	// Create request
	req, err := l.createRequest(ctx, parsedURL)
	if err != nil {
		return PolicySourceLoadResult{}, fmt.Errorf("%w: %w", ErrPolicyFetchFailed, err)
	}

	// Execute with retries
	var resp *http.Response
	for attempt := 0; attempt <= l.options.MaxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retry
			select {
			case <-ctx.Done():
				return PolicySourceLoadResult{}, ctx.Err()
			case <-time.After(l.options.RetryDelay):
			}
		}

		// Clone the request for each attempt (body can only be read once)
		if req.Body != nil {
			bodyBytes, err := io.ReadAll(req.Body)
			if err != nil {
				return PolicySourceLoadResult{}, fmt.Errorf("%w: failed to read body", ErrPolicyFetchFailed)
			}
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		resp, err = l.client.Do(req)
		if err != nil {
			if attempt == l.options.MaxRetries {
				return PolicySourceLoadResult{}, fmt.Errorf("%w: %w", ErrPolicyFetchFailed, err)
			}
			continue
		}

		// Check for context cancellation
		if ctx.Err() != nil {
			_ = resp.Body.Close()
			return PolicySourceLoadResult{}, ctx.Err()
		}

		// Check if we should retry on this status code
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotModified {
			// Close the response body before potential retry
			resp.Body.Close()
			// Retry on server errors (5xx) and rate limiting (429)
			if attempt < l.options.MaxRetries && (resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests) {
				continue
			}
			return PolicySourceLoadResult{}, fmt.Errorf("%w: status %d", ErrPolicyFetchFailed, resp.StatusCode)
		}

		// Success - break out of retry loop
		break
	}

	// Check response
	if resp == nil {
		return PolicySourceLoadResult{}, fmt.Errorf("%w: no response", ErrPolicyFetchFailed)
	}

	defer resp.Body.Close()

	// Check Content-Type if present
	contentType := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
	if contentType != "" {
		// Split to get the media type (before ; charset=...)
		mediaType := strings.Split(contentType, ";")[0]
		mediaType = strings.TrimSpace(mediaType)

		// Check against disallowed content types
		if l.isDisallowedContentType(mediaType) {
			return PolicySourceLoadResult{}, fmt.Errorf("%w: disallowed content type %s", ErrPolicyFetchInvalidContentType, contentType)
		}

		// Check against allowed content types (if configured)
		if len(l.options.AllowedContentTypes) > 0 && !l.isAllowedContentType(mediaType) {
			return PolicySourceLoadResult{}, fmt.Errorf("%w: content type %s not allowed", ErrPolicyFetchInvalidContentType, contentType)
		}
	}

	// Read body with size limit
	bodyBytes, err := l.readBodyWithLimit(resp.Body, l.options.MaxBodySize)
	if err != nil {
		return PolicySourceLoadResult{}, fmt.Errorf("%w: %w", ErrPolicyFetchTooLarge, err)
	}

	// Determine the actual content type
	if contentType == "" {
		contentType = l.detectContentType(bodyBytes)
	}

	// Create loaded source
	loaded := LoadedPolicySource{
		Source: PolicySource{
			URI:         source.URI,
			Kind:        source.Kind,
			Priority:    source.Priority,
			ContentType: contentType,
		},
		Content: bodyBytes,
	}

	// Create cache metadata
	nowUnix := time.Now().Unix()
	// For now, use a short expiry (5 minutes) - cache refresh will be added later
	expiresAtUnix := nowUnix + 300

	metadata, err := PolicyCacheRecordForLoadedSource(loaded, nowUnix, expiresAtUnix, "")
	if err != nil {
		return PolicySourceLoadResult{}, fmt.Errorf("%w: failed to create cache record", ErrPolicyFetchFailed)
	}

	return PolicySourceLoadResult{
		Loaded:   loaded,
		Metadata: metadata,
	}, nil
}

// createRequest creates an HTTP request for fetching a policy
func (l *PolicyHTTPLoader) createRequest(ctx context.Context, parsedURL *url.URL) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("User-Agent", l.options.UserAgent)
	req.Header.Set("Accept", l.options.Accept)

	return req, nil
}

// readBodyWithLimit reads a response body with a size limit
func (l *PolicyHTTPLoader) readBodyWithLimit(body io.ReadCloser, maxSize int64) ([]byte, error) {
	// Use a limited reader
	limitedReader := io.LimitReader(body, maxSize+1)
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, err
	}

	// Check if we hit the limit
	if int64(len(bodyBytes)) > maxSize {
		return nil, fmt.Errorf("body size %d exceeds limit %d", len(bodyBytes), maxSize)
	}

	return bodyBytes, nil
}

// validatePolicySourceURI validates a policy source URI for safety
func (l *PolicyHTTPLoader) validatePolicySourceURI(uri string) error {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return errors.New("empty URI")
	}

	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("invalid URI: %w", err)
	}

	// Check for control characters
	if containsControlRune(uri) {
		return errors.New("URI contains control characters")
	}

	// Check for fragments
	if parsed.Fragment != "" {
		return errors.New("URI contains fragment")
	}

	// Check for query parameters (allowed but validated)
	if parsed.RawQuery != "" {
		// Query parameters should not contain control characters
		if containsControlRune(parsed.RawQuery) {
			return errors.New("URI query contains control characters")
		}
	}

	// Check path
	if parsed.Path != "" && containsControlRune(parsed.Path) {
		return errors.New("URI path contains control characters")
	}

	return nil
}

// isAllowedScheme checks if a URI scheme is allowed
func (l *PolicyHTTPLoader) isAllowedScheme(scheme string) bool {
	scheme = strings.ToLower(scheme)
	for _, allowed := range l.options.AllowedSchemes {
		if strings.ToLower(allowed) == scheme {
			return true
		}
	}
	return false
}

// isAllowedContentType checks if a content type is in the allowed list
func (l *PolicyHTTPLoader) isAllowedContentType(contentType string) bool {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	for _, allowed := range l.options.AllowedContentTypes {
		if strings.ToLower(strings.TrimSpace(allowed)) == contentType {
			return true
		}
	}
	return false
}

// isDisallowedContentType checks if a content type is in the disallowed list
func (l *PolicyHTTPLoader) isDisallowedContentType(contentType string) bool {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	for _, disallowed := range l.options.DisallowedContentTypes {
		if strings.ToLower(strings.TrimSpace(disallowed)) == contentType {
			return true
		}
	}
	return false
}

// detectContentType attempts to detect the content type from body bytes
func (l *PolicyHTTPLoader) detectContentType(body []byte) string {
	// Simple heuristic based on content
	if len(body) == 0 {
		return "application/octet-stream"
	}

	// Check for common RDF patterns
	bodyStr := string(body)

	// JSON-LD
	if strings.Contains(bodyStr, "@context") && (strings.Contains(bodyStr, "{") || strings.Contains(bodyStr, "}")) {
		return "application/ld+json"
	}

	// Turtle
	if strings.Contains(bodyStr, "@prefix") || strings.Contains(bodyStr, "@base") {
		return "text/turtle"
	}

	// RDF/XML
	if strings.Contains(bodyStr, "<rdf:RDF") {
		return "application/rdf+xml"
	}

	// N-Triples
	if strings.Contains(bodyStr, "<") && strings.Contains(bodyStr, ">") && strings.Contains(bodyStr, " .") {
		return "application/n-triples"
	}

	return "application/octet-stream"
}

// AncestorPolicyWalk walks up the resource path to find policy sources
// in ancestor containers. This is used for container-level policies.
func AncestorPolicyWalk(
	loader *PolicyHTTPLoader,
	containerURIs []string,
) ([]LoadedPolicySource, error) {
	var loadedSources []LoadedPolicySource

	ctx, cancel := context.WithTimeout(context.Background(), loader.options.Timeout)
	defer cancel()

	// Use default derived tails for policy discovery
	defaultTails := []string{".acl", ".meta", ".well-known/solid"}

	for _, containerURI := range containerURIs {
		// Derive policy sources from this container
		sources, err := DerivedPolicySources(containerURI, defaultTails, "text/turtle")
		if err != nil {
			// Skip this container if we can't derive sources
			continue
		}

		for _, source := range sources {
			// Skip if we already have this source
			if alreadyLoaded(loadedSources, source.URI) {
				continue
			}

			// Try to load the policy source
			result, err := loader.LoadPolicySource(ctx, source)
			if err != nil {
				// Log and continue - we don't fail on individual policy load failures
				// This is shadow mode, so we just skip failed loads
				continue
			}

			loadedSources = append(loadedSources, result.Loaded)
		}
	}

	return loadedSources, nil
}

// alreadyLoaded checks if a URI is already in the loaded sources
func alreadyLoaded(loaded []LoadedPolicySource, uri string) bool {
	for _, source := range loaded {
		if source.Source.URI == uri {
			return true
		}
	}
	return false
}
