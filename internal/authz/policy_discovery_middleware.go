// Package authz provides authorization policy handling for Solid.
package authz

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// PolicyLoader is the interface for loading policy sources
type PolicyLoader interface {
	LoadPolicySource(ctx context.Context, source PolicySource) (PolicySourceLoadResult, error)
}

// PolicyDiscoveryMiddlewareOptions configures the policy discovery middleware
type PolicyDiscoveryMiddlewareOptions struct {
	// Loader is the policy HTTP loader to use for fetching policies
	Loader PolicyLoader

	// AllowedLinkRels is the list of Link relations to follow for policy discovery
	// Default: ["acl", "describedby", "access-control", "policy"]
	AllowedLinkRels []string

	// DerivedURITails is the list of URI tails to derive policy sources from
	// Default: [".acl", ".meta", ".well-known/solid"]
	DerivedURITails []string

	// DefaultContentType is the default content type for policy sources
	// Default: "text/turtle"
	DefaultContentType string

	// Logger is the logger to use
	Logger *slog.Logger

	// Timeout is the timeout for policy discovery
	// Default: 5 seconds
	Timeout time.Duration

	// MaxRetries is the maximum number of retries for failed policy loads
	// Default: 2
	MaxRetries int

	// RetryDelay is the delay between retries
	// Default: 100ms
	RetryDelay time.Duration

	// MaxPolicySources is the maximum number of policy sources to load
	// Default: 10 (to prevent DoS via too many policy fetches)
	MaxPolicySources int

	// MaxTotalBodySize is the maximum total size of all loaded policies
	// Default: 10MB (10 * 1024 * 1024)
	MaxTotalBodySize int64
}

// DefaultPolicyDiscoveryMiddlewareOptions returns options with sensible defaults
func DefaultPolicyDiscoveryMiddlewareOptions(loader PolicyLoader) PolicyDiscoveryMiddlewareOptions {
	return PolicyDiscoveryMiddlewareOptions{
		Loader:             loader,
		AllowedLinkRels:    []string{"acl", "describedby", "access-control", "policy"},
		DerivedURITails:    []string{".acl", ".meta", ".well-known/solid"},
		DefaultContentType: "text/turtle",
		Timeout:            5 * time.Second,
		MaxRetries:         DefaultPolicyFetchMaxRetries,
		RetryDelay:         DefaultPolicyFetchRetryDelay,
		MaxPolicySources:   10,
		MaxTotalBodySize:   10 * 1024 * 1024, // 10 MiB
	}
}

// PolicyDiscoveryMiddleware discovers and loads policies for incoming requests
// It adds the loaded policy documents to the request context for use by evaluators
type PolicyDiscoveryMiddleware struct {
	options PolicyDiscoveryMiddlewareOptions
}

// NewPolicyDiscoveryMiddleware creates a new policy discovery middleware
func NewPolicyDiscoveryMiddleware(options PolicyDiscoveryMiddlewareOptions) (*PolicyDiscoveryMiddleware, error) {
	if options.Loader == nil {
		return nil, errors.New("policy loader is required")
	}
	if options.Timeout == 0 {
		options.Timeout = 5 * time.Second
	}
	if options.MaxRetries == 0 {
		options.MaxRetries = DefaultPolicyFetchMaxRetries
	}
	if options.RetryDelay == 0 {
		options.RetryDelay = DefaultPolicyFetchRetryDelay
	}
	if options.MaxPolicySources == 0 {
		options.MaxPolicySources = 10
	}
	if options.MaxTotalBodySize == 0 {
		options.MaxTotalBodySize = 10 * 1024 * 1024
	}
	if options.DefaultContentType == "" {
		options.DefaultContentType = "text/turtle"
	}
	if len(options.AllowedLinkRels) == 0 {
		options.AllowedLinkRels = []string{"acl", "describedby", "access-control", "policy"}
	}
	if len(options.DerivedURITails) == 0 {
		options.DerivedURITails = []string{".acl", ".meta", ".well-known/solid"}
	}

	return &PolicyDiscoveryMiddleware{options: options}, nil
}

// Middleware returns an http.Handler that performs policy discovery
func (m *PolicyDiscoveryMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip policy discovery for health and readiness endpoints
		if isHealthEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Create context with timeout for policy discovery
		discoveryCtx, cancel := context.WithTimeout(r.Context(), m.options.Timeout)
		defer cancel()

		// Get the resource URI from the request
		resourceURI := resourceURIFromRequest(r)
		if resourceURI == "" {
			// Cannot determine resource URI, skip policy discovery
			logPolicyDiscoverySkip(m.options.Logger, r, "empty resource URI")
			next.ServeHTTP(w, r)
			return
		}

		// Validate resource URI for safety
		if !validResourceURI(resourceURI) {
			logPolicyDiscoverySkip(m.options.Logger, r, "invalid resource URI")
			next.ServeHTTP(w, r)
			return
		}

		// Collect Link headers from the request
		var linkHeaders []string
		for _, header := range r.Header["Link"] {
			if header != "" {
				linkHeaders = append(linkHeaders, header)
			}
		}

		// Discover policy sources
		sources, err := DiscoverPolicySources(PolicyDiscoveryOptions{
			ResourceURI:        resourceURI,
			LinkHeaders:        linkHeaders,
			AllowedLinkRels:    m.options.AllowedLinkRels,
			DerivedURITails:    m.options.DerivedURITails,
			DefaultContentType: m.options.DefaultContentType,
		})
		if err != nil {
			logPolicyDiscoveryError(m.options.Logger, r, "policy discovery failed", err)
			// Continue without policies - evaluator will handle
			next.ServeHTTP(w, r)
			return
		}

		// Limit the number of sources to prevent DoS
		if len(sources) > m.options.MaxPolicySources {
			logPolicyDiscoveryWarning(m.options.Logger, r, "too many policy sources", int64(len(sources)), int64(m.options.MaxPolicySources))
			sources = sources[:m.options.MaxPolicySources]
		}

		// Load policy sources with exponential backoff and concurrency control
		loadedSources, err := m.loadPolicySources(discoveryCtx, sources)
		if err != nil {
			logPolicyDiscoveryError(m.options.Logger, r, "policy loading failed", err)
			// Continue without policies
			next.ServeHTTP(w, r)
			return
		}

		// Convert loaded sources to policy documents
		// Use PolicyDocumentsFromLoadedSources to properly create documents with SHA256 hashes
		policyDocs, err := PolicyDocumentsFromLoadedSources(loadedSources)
		if err != nil {
			logPolicyDiscoveryError(m.options.Logger, r, "failed to create policy documents", err)
			// Continue without policies
			next.ServeHTTP(w, r)
			return
		}

		// Add policy documents to request context
		// This will be picked up by the authz middleware
		r = r.WithContext(WithPolicyDocuments(r.Context(), policyDocs))

		logPolicyDiscoverySuccess(m.options.Logger, r, len(policyDocs), len(sources))
		next.ServeHTTP(w, r)
	})
}

// loadPolicySources loads multiple policy sources with concurrency control
// Uses a semaphore pattern to limit concurrent requests
func (m *PolicyDiscoveryMiddleware) loadPolicySources(ctx context.Context, sources []PolicySource) ([]LoadedPolicySource, error) {
	if len(sources) == 0 {
		return nil, nil
	}

	// Use a channel as a semaphore to limit concurrency
	// For now, use sequential loading to avoid overwhelming the server
	// This can be enhanced to parallel with proper rate limiting
	var loadedSources []LoadedPolicySource
	var loadErrors []error

	for _, source := range sources {
		// Check context cancellation
		if ctx.Err() != nil {
			break
		}

		// Try to load the policy source with retries
		loaded, err := m.loadPolicySourceWithRetry(ctx, source)
		if err != nil {
			// Log but don't fail - continue with other sources
			loadErrors = append(loadErrors, err)
			continue
		}
		loadedSources = append(loadedSources, loaded)
	}

	// If we loaded at least one source successfully, return those
	if len(loadedSources) > 0 {
		// Log errors for failed loads (but don't return error)
		if len(loadErrors) > 0 {
			// Log at debug level since we have some policies
			for _, err := range loadErrors {
				slog.Debug("policy load error", "error", err)
			}
		}
		return loadedSources, nil
	}

	// If all loads failed, return the first error
	if len(loadErrors) > 0 {
		return nil, loadErrors[0]
	}

	return loadedSources, nil
}

// loadPolicySourceWithRetry loads a single policy source with retry logic
func (m *PolicyDiscoveryMiddleware) loadPolicySourceWithRetry(ctx context.Context, source PolicySource) (LoadedPolicySource, error) {
	var lastErr error
	loader := m.options.Loader

	// Apply exponential backoff
	backoff := m.options.RetryDelay
	maxBackoff := backoff * time.Duration(m.options.MaxRetries)

	for attempt := 0; attempt <= m.options.MaxRetries; attempt++ {
		// Check context cancellation
		if ctx.Err() != nil {
			return LoadedPolicySource{}, ctx.Err()
		}

		// Try to load
		result, err := loader.LoadPolicySource(ctx, source)
		if err == nil {
			return result.Loaded, nil
		}

		lastErr = err

		// Don't retry on unsafe URI errors - these are permanent
		if errors.Is(err, ErrPolicyFetchUnsafeURI) {
			break
		}

		// Don't retry on invalid content type - these are permanent
		if errors.Is(err, ErrPolicyFetchInvalidContentType) {
			break
		}

		// Don't retry if we've exhausted retries
		if attempt == m.options.MaxRetries {
			break
		}

		// Wait with backoff
		select {
		case <-ctx.Done():
			return LoadedPolicySource{}, ctx.Err()
		case <-time.After(backoff):
			// Increase backoff exponentially
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}

	return LoadedPolicySource{}, lastErr
}

// resourceURIFromRequest extracts the resource URI from the request
// This is a simplified version - in production, use the same logic as builder.go
func resourceURIFromRequest(r *http.Request) string {
	if r.URL == nil {
		return ""
	}

	// For now, use the raw request URI
	// In production, this should use the same logic as resourceURIForRequest in builder.go
	uri := r.URL.String()
	if uri == "" {
		return ""
	}

	// Remove fragment
	if idx := strings.IndexByte(uri, '#'); idx >= 0 {
		uri = uri[:idx]
	}

	return uri
}

// isHealthEndpoint checks if the request is for a health endpoint
func isHealthEndpoint(path string) bool {
	return path == "/healthz" || path == "/readyz"
}

// Context key for policy documents
type policyDocumentsKey struct{}

// WithPolicyDocuments adds policy documents to the request context
func WithPolicyDocuments(ctx context.Context, docs []PolicyDocument) context.Context {
	return context.WithValue(ctx, policyDocumentsKey{}, docs)
}

// PolicyDocumentsFromContext retrieves policy documents from the request context
func PolicyDocumentsFromContext(ctx context.Context) []PolicyDocument {
	if docs, ok := ctx.Value(policyDocumentsKey{}).([]PolicyDocument); ok {
		return docs
	}
	return nil
}

// Logging helpers

func logPolicyDiscoverySkip(logger *slog.Logger, r *http.Request, reason string) {
	if logger == nil {
		return
	}
	logger.Debug("policy discovery skipped",
		"method", r.Method,
		"path", r.URL.EscapedPath(),
		"reason", reason,
	)
}

func logPolicyDiscoveryError(logger *slog.Logger, r *http.Request, message string, err error) {
	if logger == nil {
		return
	}
	logger.Warn("policy discovery error",
		"method", r.Method,
		"path", r.URL.EscapedPath(),
		"error", err,
		"message", message,
	)
}

func logPolicyDiscoveryWarning(logger *slog.Logger, r *http.Request, message string, current, limit int64) {
	if logger == nil {
		return
	}
	logger.Warn("policy discovery warning",
		"method", r.Method,
		"path", r.URL.EscapedPath(),
		"message", message,
		"current", current,
		"limit", limit,
	)
}

func logPolicyDiscoverySuccess(logger *slog.Logger, r *http.Request, loaded, discovered int) {
	if logger == nil {
		return
	}
	logger.Debug("policy discovery success",
		"method", r.Method,
		"path", r.URL.EscapedPath(),
		"discovered", discovered,
		"loaded", loaded,
	)
}
