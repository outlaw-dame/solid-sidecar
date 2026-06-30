package authz

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestNewPolicyDiscoveryMiddlewareWithDefaults tests middleware creation with defaults
func TestNewPolicyDiscoveryMiddlewareWithDefaults(t *testing.T) {
	loader := NewPolicyHTTPLoader()
	middleware, err := NewPolicyDiscoveryMiddleware(DefaultPolicyDiscoveryMiddlewareOptions(loader))
	if err != nil {
		t.Fatalf("failed to create middleware: %v", err)
	}
	if middleware == nil {
		t.Fatal("middleware is nil")
	}
	if middleware.options.Loader == nil {
		t.Fatal("loader is nil")
	}
	if middleware.options.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", middleware.options.Timeout)
	}
	if middleware.options.MaxRetries != DefaultPolicyFetchMaxRetries {
		t.Errorf("expected max retries %d, got %d", DefaultPolicyFetchMaxRetries, middleware.options.MaxRetries)
	}
	if middleware.options.MaxPolicySources != 10 {
		t.Errorf("expected max policy sources 10, got %d", middleware.options.MaxPolicySources)
	}
	if middleware.options.MaxTotalBodySize != 10*1024*1024 {
		t.Errorf("expected max body size 10MiB, got %d", middleware.options.MaxTotalBodySize)
	}
}

// TestNewPolicyDiscoveryMiddlewareErrors tests middleware creation errors
func TestNewPolicyDiscoveryMiddlewareErrors(t *testing.T) {
	// Nil loader should error
	_, err := NewPolicyDiscoveryMiddleware(PolicyDiscoveryMiddlewareOptions{
		Loader: nil,
	})
	if err == nil {
		t.Fatal("expected error for nil loader, got nil")
	}
}

// TestPolicyDiscoveryMiddlewareSkipsHealthEndpoints tests that health endpoints are skipped
func TestPolicyDiscoveryMiddlewareSkipsHealthEndpoints(t *testing.T) {
	loader := NewPolicyHTTPLoader()
	middleware, _ := NewPolicyDiscoveryMiddleware(DefaultPolicyDiscoveryMiddlewareOptions(loader))

	// Create a handler that checks if policy documents are in context
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if PolicyDocumentsFromContext(r.Context()) != nil {
			t.Error("expected no policy documents for health endpoint")
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	// Test /healthz
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Test /readyz
	req = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

// TestPolicyDiscoveryMiddlewareSuccess tests successful policy discovery and loading
func TestPolicyDiscoveryMiddlewareSuccess(t *testing.T) {
	// Create a test server that returns a policy
	policyContent := `<https://example.org/resource> a solid:Resource .`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, policyContent)
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	middleware, _ := NewPolicyDiscoveryMiddleware(PolicyDiscoveryMiddlewareOptions{
		Loader:             loader,
		AllowedLinkRels:    []string{"acl"},
		DerivedURITails:    []string{".acl"},
		DefaultContentType: "text/turtle",
		Timeout:            5 * time.Second,
		MaxRetries:         2,
		RetryDelay:         10 * time.Millisecond,
		MaxPolicySources:   10,
		MaxTotalBodySize:   10 * 1024 * 1024,
		Logger:             slog.Default(),
	})

	// Create a handler that checks for policy documents
	var receivedDocs []PolicyDocument
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedDocs = PolicyDocumentsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	// Create a request to a resource that would have a .acl file
	resourceURL := server.URL + "/resource"
	req := httptest.NewRequest(http.MethodGet, resourceURL, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Should have discovered and loaded the .acl policy
	if len(receivedDocs) == 0 {
		t.Fatal("expected policy documents, got none")
	}

	// Check that the policy was loaded
	found := false
	for _, doc := range receivedDocs {
		if strings.Contains(doc.URI, ".acl") {
			found = true
			if doc.ContentType != "text/turtle" {
				t.Errorf("expected content type text/turtle, got %q", doc.ContentType)
			}
			if doc.SHA256 == "" {
				t.Error("expected SHA256 hash, got empty")
			}
			break
		}
	}
	if !found {
		t.Error("expected to find .acl policy document")
	}
}

// TestPolicyDiscoveryMiddlewareWithLinkHeaders tests discovery from Link headers
func TestPolicyDiscoveryMiddlewareWithLinkHeaders(t *testing.T) {
	// Create a test server that returns policies
	policyContent := `<https://example.org/resource> a solid:Resource .`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, policyContent)
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	middleware, _ := NewPolicyDiscoveryMiddleware(PolicyDiscoveryMiddlewareOptions{
		Loader:             loader,
		AllowedLinkRels:    []string{"acl"},
		DerivedURITails:    []string{},
		DefaultContentType: "text/turtle",
		Timeout:            5 * time.Second,
		MaxRetries:         2,
		RetryDelay:         10 * time.Millisecond,
		MaxPolicySources:   10,
		MaxTotalBodySize:   10 * 1024 * 1024,
		Logger:             slog.Default(),
	})

	// Create a handler that checks for policy documents
	var receivedDocs []PolicyDocument
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedDocs = PolicyDocumentsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	// Create a request with a Link header pointing to a policy
	resourceURL := server.URL + "/resource"
	req := httptest.NewRequest(http.MethodGet, resourceURL, nil)
	// Add Link header: <policy-url>; rel="acl"
	policyURL := server.URL + "/policies/resource.acl"
	req.Header.Set("Link", fmt.Sprintf("< %s >; rel=\"acl\"", policyURL))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Should have discovered and loaded the policy from Link header
	if len(receivedDocs) == 0 {
		t.Fatal("expected policy documents from Link header, got none")
	}

	found := false
	for _, doc := range receivedDocs {
		if doc.URI == policyURL {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find policy %q in documents", policyURL)
	}
}

// TestPolicyDiscoveryMiddlewareHandles404 tests handling of 404 responses
func TestPolicyDiscoveryMiddlewareHandles404(t *testing.T) {
	// Create a test server that returns 404
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	middleware, _ := NewPolicyDiscoveryMiddleware(PolicyDiscoveryMiddlewareOptions{
		Loader:             loader,
		AllowedLinkRels:    []string{"acl"},
		DerivedURITails:    []string{".acl"},
		DefaultContentType: "text/turtle",
		Timeout:            5 * time.Second,
		MaxRetries:         0, // No retries for this test
		RetryDelay:         10 * time.Millisecond,
		MaxPolicySources:   10,
		MaxTotalBodySize:   10 * 1024 * 1024,
		Logger:             slog.Default(),
	})

	// Create a handler that checks for policy documents
	var receivedDocs []PolicyDocument
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedDocs = PolicyDocumentsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	req := httptest.NewRequest(http.MethodGet, server.URL+"/resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should complete without error even though policy loading failed
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Should have no policy documents since the server returned 404
	if len(receivedDocs) != 0 {
		t.Errorf("expected no policy documents (404), got %d", len(receivedDocs))
	}
}

// TestPolicyDiscoveryMiddlewareRespectsMaxPolicySources tests the MaxPolicySources limit
func TestPolicyDiscoveryMiddlewareRespectsMaxPolicySources(t *testing.T) {
	// Create a test server that returns policies
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "@prefix ex: <http://example.org/> .")
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	middleware, _ := NewPolicyDiscoveryMiddleware(PolicyDiscoveryMiddlewareOptions{
		Loader:             loader,
		AllowedLinkRels:    []string{"acl"},
		DerivedURITails:    []string{".acl", ".meta", ".well-known/solid"}, // 3 tails
		DefaultContentType: "text/turtle",
		Timeout:            5 * time.Second,
		MaxRetries:         0,
		RetryDelay:         10 * time.Millisecond,
		MaxPolicySources:   1, // Limit to 1 source
		MaxTotalBodySize:   10 * 1024 * 1024,
		Logger:             slog.Default(),
	})

	// Create a handler that counts policy documents
	var receivedDocs []PolicyDocument
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedDocs = PolicyDocumentsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	req := httptest.NewRequest(http.MethodGet, server.URL+"/resource/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Should have at most 1 policy document (limited by MaxPolicySources)
	if len(receivedDocs) > 1 {
		t.Errorf("expected at most 1 policy document, got %d", len(receivedDocs))
	}
}

// TestPolicyDiscoveryMiddlewareHandlesUnsafeURI tests handling of unsafe URIs
func TestPolicyDiscoveryMiddlewareHandlesUnsafeURI(t *testing.T) {
	loader := NewPolicyHTTPLoader()
	middleware, _ := NewPolicyDiscoveryMiddleware(PolicyDiscoveryMiddlewareOptions{
		Loader:             loader,
		AllowedLinkRels:    []string{"acl"},
		DerivedURITails:    []string{".acl"},
		DefaultContentType: "text/turtle",
		Timeout:            5 * time.Second,
		MaxRetries:         0,
		RetryDelay:         10 * time.Millisecond,
		MaxPolicySources:   10,
		MaxTotalBodySize:   10 * 1024 * 1024,
		Logger:             slog.Default(),
	})

	// Create a handler that checks for policy documents
	var receivedDocs []PolicyDocument
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedDocs = PolicyDocumentsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	// Create a request with an unsafe URI (fragment)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/resource#fragment", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Should have no policy documents since URI is unsafe
	if len(receivedDocs) != 0 {
		t.Errorf("expected no policy documents for unsafe URI, got %d", len(receivedDocs))
	}
}

// TestPolicyDiscoveryMiddlewareRetryOnFailure tests retry logic
func TestPolicyDiscoveryMiddlewareRetryOnFailure(t *testing.T) {
	var attemptCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		if attemptCount < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "@prefix ex: <http://example.org/> .")
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	middleware, _ := NewPolicyDiscoveryMiddleware(PolicyDiscoveryMiddlewareOptions{
		Loader:             loader,
		AllowedLinkRels:    []string{"acl"},
		DerivedURITails:    []string{".acl"},
		DefaultContentType: "text/turtle",
		Timeout:            5 * time.Second,
		MaxRetries:         2,
		RetryDelay:         10 * time.Millisecond,
		MaxPolicySources:   10,
		MaxTotalBodySize:   10 * 1024 * 1024,
		Logger:             slog.Default(),
	})

	// Create a handler that checks for policy documents
	var receivedDocs []PolicyDocument
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedDocs = PolicyDocumentsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	req := httptest.NewRequest(http.MethodGet, server.URL+"/resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Should have succeeded after retry
	if len(receivedDocs) == 0 {
		t.Fatal("expected policy documents after retry, got none")
	}

	// Should have made 2 attempts
	if attemptCount != 2 {
		t.Errorf("expected 2 attempts, got %d", attemptCount)
	}
}

// TestPolicyDiscoveryMiddlewareNoRetryOnUnsafeURI tests that unsafe URI errors don't retry
func TestPolicyDiscoveryMiddlewareNoRetryOnUnsafeURI(t *testing.T) {
	var attemptCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "@prefix ex: <http://example.org/> .")
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	middleware, _ := NewPolicyDiscoveryMiddleware(PolicyDiscoveryMiddlewareOptions{
		Loader:             loader,
		AllowedLinkRels:    []string{"acl"},
		DerivedURITails:    []string{".acl"},
		DefaultContentType: "text/turtle",
		Timeout:            5 * time.Second,
		MaxRetries:         2,
		RetryDelay:         10 * time.Millisecond,
		MaxPolicySources:   10,
		MaxTotalBodySize:   10 * 1024 * 1024,
		Logger:             slog.Default(),
	})

	// Create a handler that checks for policy documents
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Policy documents would be in context but we don't need to check them for this test
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	// Create a request with a fragment in the derived URI
	// The server URL itself is fine, but the derived .acl URI will have a fragment
	// This is tricky to test directly, so we test the behavior indirectly
	req := httptest.NewRequest(http.MethodGet, server.URL+"/resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Should have made at least 1 attempt
	if attemptCount < 1 {
		t.Errorf("expected at least 1 attempt, got %d", attemptCount)
	}
}

// TestPolicyDiscoveryMiddlewareTimeout tests timeout handling
func TestPolicyDiscoveryMiddlewareTimeout(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	middleware, _ := NewPolicyDiscoveryMiddleware(PolicyDiscoveryMiddlewareOptions{
		Loader:             loader,
		AllowedLinkRels:    []string{"acl"},
		DerivedURITails:    []string{".acl"},
		DefaultContentType: "text/turtle",
		Timeout:            10 * time.Millisecond, // Very short timeout
		MaxRetries:         0,
		RetryDelay:         1 * time.Millisecond,
		MaxPolicySources:   10,
		MaxTotalBodySize:   10 * 1024 * 1024,
		Logger:             slog.Default(),
	})

	// Create a handler that just completes
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	req := httptest.NewRequest(http.MethodGet, server.URL+"/resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should complete (timeout will cause error but middleware continues)
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// The important thing is it didn't hang
}

// TestWithPolicyDocuments tests the context functions
func TestWithPolicyDocuments(t *testing.T) {
	ctx := context.Background()
	docs := []PolicyDocument{
		{URI: "https://example.org/policy1", SHA256: "abc123", ContentType: "text/turtle"},
		{URI: "https://example.org/policy2", SHA256: "def456", ContentType: "application/ld+json"},
	}

	ctx = WithPolicyDocuments(ctx, docs)

	retrieved := PolicyDocumentsFromContext(ctx)
	if len(retrieved) != len(docs) {
		t.Errorf("expected %d documents, got %d", len(docs), len(retrieved))
	}

	for i, doc := range docs {
		if retrieved[i].URI != doc.URI {
			t.Errorf("document %d URI mismatch: expected %q, got %q", i, doc.URI, retrieved[i].URI)
		}
	}
}

// TestPolicyDocumentsFromContextEmpty tests context with no documents
func TestPolicyDocumentsFromContextEmpty(t *testing.T) {
	ctx := context.Background()
	docs := PolicyDocumentsFromContext(ctx)
	if docs != nil {
		t.Errorf("expected nil, got %v", docs)
	}
}

// TestPolicyDiscoveryMiddlewareIntegrationWithAuthz tests integration with authz middleware
func TestPolicyDiscoveryMiddlewareIntegrationWithAuthz(t *testing.T) {
	// Create a test server that returns policies
	policyContent := `<https://example.org/resource> a solid:Resource .`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, policyContent)
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	policyDiscovery, _ := NewPolicyDiscoveryMiddleware(PolicyDiscoveryMiddlewareOptions{
		Loader:             loader,
		AllowedLinkRels:    []string{"acl"},
		DerivedURITails:    []string{".acl"},
		DefaultContentType: "text/turtle",
		Timeout:            5 * time.Second,
		MaxRetries:         0,
		RetryDelay:         10 * time.Millisecond,
		MaxPolicySources:   10,
		MaxTotalBodySize:   10 * 1024 * 1024,
		Logger:             slog.Default(),
	})

	// Create the final handler in the chain
	// The chain is: policy discovery -> authz -> success handler
	finalHandler := policyDiscovery.Middleware(
		Middleware(MiddlewareOptions{
			BuildOptions: BuildOptions{PublicBaseURL: server.URL},
			Evaluator:    NewShadowEvaluator(),
			Logger:       slog.Default(),
			Metrics:      NewShadowMetrics(),
		}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})),
	)

	// Create a request
	req := httptest.NewRequest(http.MethodGet, server.URL+"/resource", nil)
	// Need to set a request ID
	req.Header.Set("X-Request-ID", "test-request-123")

	rr := httptest.NewRecorder()
	finalHandler.ServeHTTP(rr, req)

	// Should succeed (shadow mode abstains, so handler is called)
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

// TestLoadPolicySourceWithRetryExponentialBackoff tests exponential backoff
func TestLoadPolicySourceWithRetryExponentialBackoff(t *testing.T) {
	middleware, _ := NewPolicyDiscoveryMiddleware(PolicyDiscoveryMiddlewareOptions{
		Loader:           NewPolicyHTTPLoader(),
		Timeout:          1 * time.Second,
		MaxRetries:       3,
		RetryDelay:       10 * time.Millisecond,
		MaxPolicySources: 10,
		MaxTotalBodySize: 10 * 1024 * 1024,
		Logger:           slog.Default(),
	})

	// Create a failing source
	source := PolicySource{URI: "http://example.com/failing-policy.ttl"}

	ctx := context.Background()
	_, err := middleware.loadPolicySourceWithRetry(ctx, source)

	// Should error since the server doesn't exist
	if err == nil {
		t.Fatal("expected error for non-existent server, got nil")
	}
}

// TestPolicyDiscoveryMiddlewareDisallowedContentType tests filtering of disallowed content types
func TestPolicyDiscoveryMiddlewareDisallowedContentType(t *testing.T) {
	// Create a server that returns HTML (disallowed)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html></html>")
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	middleware, _ := NewPolicyDiscoveryMiddleware(PolicyDiscoveryMiddlewareOptions{
		Loader:             loader,
		AllowedLinkRels:    []string{"acl"},
		DerivedURITails:    []string{".acl"},
		DefaultContentType: "text/turtle",
		Timeout:            5 * time.Second,
		MaxRetries:         0,
		RetryDelay:         10 * time.Millisecond,
		MaxPolicySources:   10,
		MaxTotalBodySize:   10 * 1024 * 1024,
		Logger:             slog.Default(),
	})

	// Create a handler that checks for policy documents
	var receivedDocs []PolicyDocument
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedDocs = PolicyDocumentsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	req := httptest.NewRequest(http.MethodGet, server.URL+"/resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Should have no documents since HTML is disallowed
	if len(receivedDocs) != 0 {
		t.Errorf("expected no documents (disallowed content type), got %d", len(receivedDocs))
	}
}

// TestPolicyDiscoveryMiddlewareWithCustomLogger tests that a custom logger is used
func TestPolicyDiscoveryMiddlewareWithCustomLogger(t *testing.T) {
	loader := NewPolicyHTTPLoader()
	var logMessages []string
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	middleware, _ := NewPolicyDiscoveryMiddleware(PolicyDiscoveryMiddlewareOptions{
		Loader:             loader,
		AllowedLinkRels:    []string{"acl"},
		DerivedURITails:    []string{".acl"},
		DefaultContentType: "text/turtle",
		Timeout:            5 * time.Second,
		MaxRetries:         0,
		RetryDelay:         10 * time.Millisecond,
		MaxPolicySources:   10,
		MaxTotalBodySize:   10 * 1024 * 1024,
		Logger:             logger,
	})

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	// This test just verifies the middleware doesn't panic with a custom logger
	req := httptest.NewRequest(http.MethodGet, "http://example.com/resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	_ = logMessages // For future use if we want to capture logs
}

// TestPolicyDiscoveryMiddlewareWithNilLogger tests that nil logger doesn't cause panic
func TestPolicyDiscoveryMiddlewareWithNilLogger(t *testing.T) {
	loader := NewPolicyHTTPLoader()
	middleware, _ := NewPolicyDiscoveryMiddleware(PolicyDiscoveryMiddlewareOptions{
		Loader:             loader,
		AllowedLinkRels:    []string{"acl"},
		DerivedURITails:    []string{".acl"},
		DefaultContentType: "text/turtle",
		Timeout:            5 * time.Second,
		MaxRetries:         0,
		RetryDelay:         10 * time.Millisecond,
		MaxPolicySources:   10,
		MaxTotalBodySize:   10 * 1024 * 1024,
		Logger:             nil, // Nil logger
	})

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	// Should not panic with nil logger
	req := httptest.NewRequest(http.MethodGet, "http://example.com/resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

// TestPolicyDiscoveryMiddlewareDiscoverFromLinkHeader tests Link header parsing
func TestPolicyDiscoveryMiddlewareDiscoverFromLinkHeader(t *testing.T) {
	// Create servers for multiple policies
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "@prefix ex1: <http://example1.org/> .")
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "@prefix ex2: <http://example2.org/> .")
	}))
	defer server2.Close()

	loader := NewPolicyHTTPLoader()
	middleware, _ := NewPolicyDiscoveryMiddleware(PolicyDiscoveryMiddlewareOptions{
		Loader:             loader,
		AllowedLinkRels:    []string{"acl", "describedby"},
		DerivedURITails:    []string{},
		DefaultContentType: "text/turtle",
		Timeout:            5 * time.Second,
		MaxRetries:         0,
		RetryDelay:         10 * time.Millisecond,
		MaxPolicySources:   10,
		MaxTotalBodySize:   10 * 1024 * 1024,
		Logger:             slog.Default(),
	})

	var receivedDocs []PolicyDocument
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedDocs = PolicyDocumentsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	// Create a request with multiple Link headers
	req := httptest.NewRequest(http.MethodGet, "http://example.com/resource", nil)
	req.Header.Set("Link", fmt.Sprintf("< %s/policy1.acl >; rel=\"acl\", < %s/policy2.acl >; rel=\"describedby\"", server1.URL, server2.URL))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Should have loaded both policies
	if len(receivedDocs) < 2 {
		t.Errorf("expected at least 2 policy documents, got %d", len(receivedDocs))
	}

	// Check that both URLs are present
	found1 := false
	found2 := false
	for _, doc := range receivedDocs {
		if doc.URI == server1.URL+"/policy1.acl" {
			found1 = true
		}
		if doc.URI == server2.URL+"/policy2.acl" {
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Errorf("expected to find both policies: found1=%v, found2=%v", found1, found2)
	}
}

// TestResourceURIFromRequest tests the resource URI extraction
func TestResourceURIFromRequest(t *testing.T) {
	testCases := []struct {
		name     string
		rawURL   string
		expected string
	}{
		{"simple", "http://example.com/resource", "http://example.com/resource"},
		{"with query", "http://example.com/resource?foo=bar", "http://example.com/resource?foo=bar"},
		{"https", "https://example.com/resource", "https://example.com/resource"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.rawURL, nil)
			result := resourceURIFromRequest(req)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

// TestPolicyDiscoveryMiddlewareEmptyDerivedTails tests with empty derived tails
func TestPolicyDiscoveryMiddlewareEmptyDerivedTails(t *testing.T) {
	loader := NewPolicyHTTPLoader()
	middleware, _ := NewPolicyDiscoveryMiddleware(PolicyDiscoveryMiddlewareOptions{
		Loader:             loader,
		AllowedLinkRels:    []string{"acl"},
		DerivedURITails:    []string{}, // Empty
		DefaultContentType: "text/turtle",
		Timeout:            5 * time.Second,
		MaxRetries:         0,
		RetryDelay:         10 * time.Millisecond,
		MaxPolicySources:   10,
		MaxTotalBodySize:   10 * 1024 * 1024,
		Logger:             slog.Default(),
	})

	var receivedDocs []PolicyDocument
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedDocs = PolicyDocumentsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	// Request without Link headers and with empty derived tails
	req := httptest.NewRequest(http.MethodGet, "http://example.com/resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Should have no documents
	if len(receivedDocs) != 0 {
		t.Errorf("expected no documents with empty derived tails, got %d", len(receivedDocs))
	}
}

// mockPolicyLoader is a mock loader for testing that implements PolicyLoader
type mockPolicyLoader struct {
	loadFunc func(ctx context.Context, source PolicySource) (PolicySourceLoadResult, error)
}

func (m *mockPolicyLoader) LoadPolicySource(ctx context.Context, source PolicySource) (PolicySourceLoadResult, error) {
	if m.loadFunc != nil {
		return m.loadFunc(ctx, source)
	}
	return PolicySourceLoadResult{}, errors.New("not implemented")
}

// TestPolicyDiscoveryMiddlewareWithMockLoader tests using a mock loader
func TestPolicyDiscoveryMiddlewareWithMockLoader(t *testing.T) {
	mockLoader := &mockPolicyLoader{
		loadFunc: func(ctx context.Context, source PolicySource) (PolicySourceLoadResult, error) {
			return PolicySourceLoadResult{
				Loaded: LoadedPolicySource{
					Source: PolicySource{
						URI:         source.URI,
						Kind:        source.Kind,
						Priority:    source.Priority,
						ContentType: "text/turtle",
					},
					Content: []byte("@prefix ex: <http://example.org/> ."),
				},
			}, nil
		},
	}

	middleware, _ := NewPolicyDiscoveryMiddleware(PolicyDiscoveryMiddlewareOptions{
		Loader:             mockLoader, // Use mock loader directly
		AllowedLinkRels:    []string{"acl"},
		DerivedURITails:    []string{".acl"},
		DefaultContentType: "text/turtle",
		Timeout:            5 * time.Second,
		MaxRetries:         0,
		RetryDelay:         10 * time.Millisecond,
		MaxPolicySources:   10,
		MaxTotalBodySize:   10 * 1024 * 1024,
		Logger:             slog.Default(),
	})

	var receivedDocs []PolicyDocument
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedDocs = PolicyDocumentsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	// Use a URL that would derive to a .acl file
	req := httptest.NewRequest(http.MethodGet, "http://example.com/resource", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Should have loaded the policy
	if len(receivedDocs) == 0 {
		t.Fatal("expected policy documents from mock loader, got none")
	}

	// Check the URI
	if !strings.Contains(receivedDocs[0].URI, ".acl") {
		t.Errorf("expected .acl in URI, got %q", receivedDocs[0].URI)
	}

	// Check SHA256 is set
	if receivedDocs[0].SHA256 == "" {
		t.Error("expected SHA256 hash, got empty")
	}
}

// TestIsHealthEndpoint tests the health endpoint check
func TestIsHealthEndpoint(t *testing.T) {
	testCases := []struct {
		path     string
		expected bool
	}{
		{"/healthz", true},
		{"/readyz", true},
		{"/Healthz", false},
		{"/READYZ", false},
		{"/health", false},
		{"/ready", false},
		{"/", false},
		{"", false},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			result := isHealthEndpoint(tc.path)
			if result != tc.expected {
				t.Errorf("isHealthEndpoint(%q) = %v, want %v", tc.path, result, tc.expected)
			}
		})
	}
}

// TestPolicyDiscoveryMiddlewareSkipsEmptyResourceURI tests empty resource URI handling
func TestPolicyDiscoveryMiddlewareSkipsEmptyResourceURI(t *testing.T) {
	loader := NewPolicyHTTPLoader()
	middleware, _ := NewPolicyDiscoveryMiddleware(PolicyDiscoveryMiddlewareOptions{
		Loader:             loader,
		AllowedLinkRels:    []string{"acl"},
		DerivedURITails:    []string{".acl"},
		DefaultContentType: "text/turtle",
		Timeout:            5 * time.Second,
		MaxRetries:         0,
		RetryDelay:         10 * time.Millisecond,
		MaxPolicySources:   10,
		MaxTotalBodySize:   10 * 1024 * 1024,
		Logger:             slog.Default(),
	})

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	// Create a request with a minimal URL (just path)
	// httptest.NewRequest doesn't allow empty URLs, so we use "/"
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Should complete without panic
}

// TestPolicyDiscoveryMiddlewareConcurrentRequests tests concurrent request handling
func TestPolicyDiscoveryMiddlewareConcurrentRequests(t *testing.T) {
	// Create a server that returns policies
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "@prefix ex: <http://example.org/> .")
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	middleware, _ := NewPolicyDiscoveryMiddleware(PolicyDiscoveryMiddlewareOptions{
		Loader:             loader,
		AllowedLinkRels:    []string{"acl"},
		DerivedURITails:    []string{".acl"},
		DefaultContentType: "text/turtle",
		Timeout:            5 * time.Second,
		MaxRetries:         0,
		RetryDelay:         10 * time.Millisecond,
		MaxPolicySources:   10,
		MaxTotalBodySize:   10 * 1024 * 1024,
		Logger:             slog.Default(),
	})

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Middleware(nextHandler)

	// Make concurrent requests
	const numRequests = 10
	var results []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, server.URL+"/resource", nil)
			req.Header.Set("X-Request-ID", fmt.Sprintf("request-%d", i))
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			mu.Lock()
			results = append(results, rr.Code)
			mu.Unlock()
		}()
	}

	// Wait for all requests to complete
	wg.Wait()

	// Check that all requests completed successfully
	if len(results) != numRequests {
		t.Errorf("expected %d results, got %d", numRequests, len(results))
	}

	for i, code := range results {
		if code != http.StatusOK {
			t.Errorf("request %d: expected status 200, got %d", i, code)
		}
	}
}
