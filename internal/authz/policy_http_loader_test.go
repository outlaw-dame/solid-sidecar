package authz

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestNewPolicyHTTPLoaderWithDefaults tests that a new loader has sensible defaults
func TestNewPolicyHTTPLoaderWithDefaults(t *testing.T) {
	loader := NewPolicyHTTPLoader()

	if loader.options.Timeout != DefaultPolicyFetchTimeout {
		t.Errorf("expected timeout %v, got %v", DefaultPolicyFetchTimeout, loader.options.Timeout)
	}
	if loader.options.MaxRetries != DefaultPolicyFetchMaxRetries {
		t.Errorf("expected max retries %d, got %d", DefaultPolicyFetchMaxRetries, loader.options.MaxRetries)
	}
	if loader.options.RetryDelay != DefaultPolicyFetchRetryDelay {
		t.Errorf("expected retry delay %v, got %v", DefaultPolicyFetchRetryDelay, loader.options.RetryDelay)
	}
	if loader.options.MaxBodySize != DefaultPolicyFetchMaxBodySize {
		t.Errorf("expected max body size %d, got %d", DefaultPolicyFetchMaxBodySize, loader.options.MaxBodySize)
	}
	if loader.options.UserAgent != DefaultPolicyFetchUserAgent {
		t.Errorf("expected user agent %q, got %q", DefaultPolicyFetchUserAgent, loader.options.UserAgent)
	}
	if loader.options.Accept != DefaultPolicyFetchAccept {
		t.Errorf("expected accept %q, got %q", DefaultPolicyFetchAccept, loader.options.Accept)
	}
	if len(loader.options.AllowedSchemes) != 2 ||
		loader.options.AllowedSchemes[0] != "http" ||
		loader.options.AllowedSchemes[1] != "https" {
		t.Errorf("expected allowed schemes [http, https], got %v", loader.options.AllowedSchemes)
	}
	if loader.client == nil {
		t.Fatal("expected HTTP client to be initialized")
	}
}

// TestNewPolicyHTTPLoaderWithOptions tests custom options
func TestNewPolicyHTTPLoaderWithOptions(t *testing.T) {
	customTimeout := 10 * time.Second
	customRetries := 5
	customDelay := 200 * time.Millisecond
	customMaxSize := int64(2 << 20) // 2 MiB
	customUserAgent := "Custom-Agent/1.0"
	customAccept := "application/json"
	customSchemes := []string{"https"}

	loader := NewPolicyHTTPLoaderWithOptions(PolicyHTTPLoaderOptions{
		Timeout:           customTimeout,
		MaxRetries:        customRetries,
		RetryDelay:        customDelay,
		MaxBodySize:       customMaxSize,
		UserAgent:         customUserAgent,
		Accept:            customAccept,
		AllowedSchemes:    customSchemes,
		DisallowedContentTypes: []string{"text/html"},
	})

	if loader.options.Timeout != customTimeout {
		t.Errorf("expected timeout %v, got %v", customTimeout, loader.options.Timeout)
	}
	if loader.options.MaxRetries != customRetries {
		t.Errorf("expected max retries %d, got %d", customRetries, loader.options.MaxRetries)
	}
	if loader.options.RetryDelay != customDelay {
		t.Errorf("expected retry delay %v, got %v", customDelay, loader.options.RetryDelay)
	}
	if loader.options.MaxBodySize != customMaxSize {
		t.Errorf("expected max body size %d, got %d", customMaxSize, loader.options.MaxBodySize)
	}
	if loader.options.UserAgent != customUserAgent {
		t.Errorf("expected user agent %q, got %q", customUserAgent, loader.options.UserAgent)
	}
	if loader.options.Accept != customAccept {
		t.Errorf("expected accept %q, got %q", customAccept, loader.options.Accept)
	}
	if len(loader.options.AllowedSchemes) != 1 || loader.options.AllowedSchemes[0] != "https" {
		t.Errorf("expected allowed schemes [https], got %v", loader.options.AllowedSchemes)
	}
}

// TestLoadPolicySourceSuccess tests successful policy loading
func TestLoadPolicySourceSuccess(t *testing.T) {
	// Create a test server
	policyContent := `<https://example.org/resource> a solid:Resource .`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, policyContent)
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	source := PolicySource{
		URI:  server.URL,
		Kind: PolicySourceExplicit,
	}

	result, err := loader.LoadPolicySource(context.Background(), source)
	if err != nil {
		t.Fatalf("LoadPolicySource failed: %v", err)
	}

	if result.Loaded.Source.ContentType != "text/turtle" {
		t.Errorf("expected content type text/turtle, got %q", result.Loaded.Source.ContentType)
	}
	if string(result.Loaded.Content) != policyContent {
		t.Errorf("expected content %q, got %q", policyContent, string(result.Loaded.Content))
	}
	if result.Metadata == (PolicySourceCacheRecord{}) {
		t.Fatal("expected metadata to be set")
	}
}

// TestLoadPolicySourceUnsafeURI tests that unsafe URIs are rejected
func TestLoadPolicySourceUnsafeURI(t *testing.T) {
	loader := NewPolicyHTTPLoader()

	testCases := []struct {
		name string
		uri  string
	}{
		{"empty URI", ""},
		{"URI with control characters", "http://example.com/policy\x00.txt"},
		{"URI with fragment", "http://example.com/policy#section"},
		{"URI with control in query", "http://example.com/policy?x=\x00"},
		{"URI with control in path", "http://example.com/pol\x00icy"},
		{"invalid URI", "not a uri"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			source := PolicySource{URI: tc.uri}
			_, err := loader.LoadPolicySource(context.Background(), source)
			if err == nil {
				t.Error("expected error for unsafe URI, got nil")
			}
			if !errors.Is(err, ErrPolicyFetchUnsafeURI) {
				t.Errorf("expected ErrPolicyFetchUnsafeURI, got %v", err)
			}
		})
	}
}

// TestLoadPolicySourceDisallowedScheme tests that disallowed schemes are rejected
func TestLoadPolicySourceDisallowedScheme(t *testing.T) {
	loader := NewPolicyHTTPLoaderWithOptions(PolicyHTTPLoaderOptions{
		AllowedSchemes: []string{"https"},
	})

	source := PolicySource{URI: "ftp://example.com/policy.ttl"}
	_, err := loader.LoadPolicySource(context.Background(), source)
	if err == nil {
		t.Fatal("expected error for disallowed scheme, got nil")
	}
	if !errors.Is(err, ErrPolicyFetchUnsafeURI) {
		t.Errorf("expected ErrPolicyFetchUnsafeURI, got %v", err)
	}
}

// TestLoadPolicySourceDisallowedContentType tests that disallowed content types are rejected
func TestLoadPolicySourceDisallowedContentType(t *testing.T) {
	// Create a test server that returns HTML
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html></html>")
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	source := PolicySource{URI: server.URL}

	_, err := loader.LoadPolicySource(context.Background(), source)
	if err == nil {
		t.Fatal("expected error for disallowed content type, got nil")
	}
	if !errors.Is(err, ErrPolicyFetchInvalidContentType) {
		t.Errorf("expected ErrPolicyFetchInvalidContentType, got %v", err)
	}
}

// TestLoadPolicySourceAllowedContentTypes tests that only allowed content types pass
func TestLoadPolicySourceAllowedContentTypes(t *testing.T) {
	// Create a test server that returns JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()

	// With allowed content types that include JSON
	loader := NewPolicyHTTPLoaderWithOptions(PolicyHTTPLoaderOptions{
		AllowedContentTypes: []string{"application/json", "text/turtle"},
	})
	source := PolicySource{URI: server.URL}

	_, err := loader.LoadPolicySource(context.Background(), source)
	if err != nil {
		t.Fatalf("expected success for allowed content type, got %v", err)
	}

	// With allowed content types that don't include JSON
	loader2 := NewPolicyHTTPLoaderWithOptions(PolicyHTTPLoaderOptions{
		AllowedContentTypes: []string{"text/turtle"},
	})

	_, err = loader2.LoadPolicySource(context.Background(), source)
	if err == nil {
		t.Fatal("expected error for not allowed content type, got nil")
	}
	if !errors.Is(err, ErrPolicyFetchInvalidContentType) {
		t.Errorf("expected ErrPolicyFetchInvalidContentType, got %v", err)
	}
}

// TestLoadPolicySourceTooLarge tests that large responses are rejected
func TestLoadPolicySourceTooLarge(t *testing.T) {
	// Create a large policy (2 MiB)
	largePolicy := strings.Repeat("a", 2<<20)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, largePolicy)
	}))
	defer server.Close()

	// Set max body size to 1 MiB (default)
	loader := NewPolicyHTTPLoaderWithOptions(PolicyHTTPLoaderOptions{
		MaxBodySize: 1 << 20,
	})
	source := PolicySource{URI: server.URL}

	_, err := loader.LoadPolicySource(context.Background(), source)
	if err == nil {
		t.Fatal("expected error for too large body, got nil")
	}
	if !errors.Is(err, ErrPolicyFetchTooLarge) {
		t.Errorf("expected ErrPolicyFetchTooLarge, got %v", err)
	}
}

// TestLoadPolicySourceNotFound tests handling of 404 status
func TestLoadPolicySourceNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	source := PolicySource{URI: server.URL}

	_, err := loader.LoadPolicySource(context.Background(), source)
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
	if !errors.Is(err, ErrPolicyFetchFailed) {
		t.Errorf("expected ErrPolicyFetchFailed, got %v", err)
	}
}

// TestLoadPolicySourceServerError tests handling of 500 status
func TestLoadPolicySourceServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	source := PolicySource{URI: server.URL}

	_, err := loader.LoadPolicySource(context.Background(), source)
	if err == nil {
		t.Fatal("expected error for 500, got nil")
	}
	if !errors.Is(err, ErrPolicyFetchFailed) {
		t.Errorf("expected ErrPolicyFetchFailed, got %v", err)
	}
}

// TestLoadPolicySourceContentTypeDetection tests content type detection from body
func TestLoadPolicySourceContentTypeDetection(t *testing.T) {
	testCases := []struct {
		name       string
		body       string
		wantPrefix string
	}{
		{"JSON-LD", `{"@context": "https://example.org", "@id": "resource"}`, "application/ld+json"},
		{"Turtle with prefix", `@prefix ex: <http://example.org/> . ex:Resource a owl:Class .`, "text/turtle"},
		{"Turtle with base", `@base <http://example.org/> . <Resource> a owl:Class .`, "text/turtle"},
		{"RDF/XML", `<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"></rdf:RDF>`, "application/rdf+xml"},
		{"N-Triples", `<http://example.org/resource> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://xmlns.com/foaf/0.1/Person> .`, "application/n-triples"},

	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "") // No content type header
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()

			loader := NewPolicyHTTPLoader()
			source := PolicySource{URI: server.URL}

			result, err := loader.LoadPolicySource(context.Background(), source)
			if err != nil {
				t.Fatalf("LoadPolicySource failed: %v", err)
			}

			if !strings.HasPrefix(result.Loaded.Source.ContentType, tc.wantPrefix) {
				t.Errorf("expected content type starting with %q, got %q", tc.wantPrefix, result.Loaded.Source.ContentType)
			}
		})
	}
}

// TestValidatePolicySourceURI tests URI validation
func TestValidatePolicySourceURI(t *testing.T) {
	loader := NewPolicyHTTPLoader()

	testCases := []struct {
		name string
		uri  string
		want error
	}{
		{"valid http", "http://example.com/policy.ttl", nil},
		{"valid https", "https://example.com/policy.ttl", nil},
		{"with query", "https://example.com/policy.ttl?version=1", nil},
		{"with path", "https://example.com/path/to/policy.ttl", nil},
		{"empty", "", fmt.Errorf("empty URI")},
		{"fragment", "http://example.com/policy#section", errors.New("URI contains fragment")},
		{"whitespace", " http://example.com/policy.ttl ", nil}, // should be trimmed
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := loader.validatePolicySourceURI(tc.uri)
			if tc.want == nil {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error %v, got nil", tc.want)
				}
				if tc.want.Error() != err.Error() {
					t.Errorf("expected error %q, got %q", tc.want.Error(), err.Error())
				}
			}
		})
	}
}

// TestIsAllowedScheme tests scheme validation
func TestIsAllowedScheme(t *testing.T) {
	loader := NewPolicyHTTPLoaderWithOptions(PolicyHTTPLoaderOptions{
		AllowedSchemes: []string{"http", "https", "ftp"},
	})

	testCases := []struct {
		scheme string
		want   bool
	}{
		{"http", true},
		{"HTTP", true},
		{"https", true},
		{"HTTPS", true},
		{"ftp", true},
		{"FTP", true},
		{"file", false},
		{"", false},
	}

	for _, tc := range testCases {
		t.Run(tc.scheme, func(t *testing.T) {
			got := loader.isAllowedScheme(tc.scheme)
			if got != tc.want {
				t.Errorf("isAllowedScheme(%q) = %v, want %v", tc.scheme, got, tc.want)
			}
		})
	}
}

// TestContentTypeValidation tests content type validation
func TestContentTypeValidation(t *testing.T) {
	loader := NewPolicyHTTPLoaderWithOptions(PolicyHTTPLoaderOptions{
		AllowedContentTypes:   []string{"text/turtle", "application/ld+json"},
		DisallowedContentTypes: []string{"text/html"},
	})

	// Test allowed content types
	if !loader.isAllowedContentType("text/turtle") {
		t.Error("text/turtle should be allowed")
	}
	if !loader.isAllowedContentType("application/ld+json") {
		t.Error("application/ld+json should be allowed")
	}
	if loader.isAllowedContentType("application/json") {
		t.Error("application/json should not be allowed")
	}

	// Test disallowed content types
	if !loader.isDisallowedContentType("text/html") {
		t.Error("text/html should be disallowed")
	}
	if loader.isDisallowedContentType("text/turtle") {
		t.Error("text/turtle should not be disallowed")
	}
}

// TestAncestorPolicyWalk tests the ancestor policy walk functionality
func TestAncestorPolicyWalk(t *testing.T) {
	// Create a test server for container policies
	container1Policy := `<https://example.org/container1/> a solid:Container .`
	container2Policy := `<https://example.org/container2/> a solid:Container .`

	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		path := r.URL.Path
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)

		if path == "/container1/.acl" {
			fmt.Fprint(w, container1Policy)
		} else if path == "/container2/.acl" {
			fmt.Fprint(w, container2Policy)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	containerURIs := []string{
		fmt.Sprintf("%s/container1/", server.URL),
		fmt.Sprintf("%s/container2/", server.URL),
	}

	loaded, err := AncestorPolicyWalk(loader, containerURIs)
	if err != nil {
		t.Fatalf("AncestorPolicyWalk failed: %v", err)
	}

	// We have 2 containers and 3 default tails (.acl, .meta, .well-known/solid)
	// Only .acl exists for both containers, so 2 loaded sources
	if len(loaded) != 2 {
		t.Errorf("expected 2 loaded sources, got %d", len(loaded))
	}

	// We made requests for all 3 tails for each container = 6 requests
	// But only 2 succeeded (the .acl files)
	if requestCount != 6 {
		t.Errorf("expected 6 requests (3 tails x 2 containers), got %d", requestCount)
	}
}

// TestAncestorPolicyWalkSkipsDuplicates tests that duplicate URIs are skipped
func TestAncestorPolicyWalkSkipsDuplicates(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<> a solid:Container .`)
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	// Same container URI twice
	containerURIs := []string{
		fmt.Sprintf("%s/container/", server.URL),
		fmt.Sprintf("%s/container/", server.URL),
	}

	loaded, err := AncestorPolicyWalk(loader, containerURIs)
	if err != nil {
		t.Fatalf("AncestorPolicyWalk failed: %v", err)
	}

	// Should only load each unique policy source once
	if len(loaded) != 3 {
		t.Errorf("expected 3 loaded sources (one for each tail), got %d", len(loaded))
	}

	// Should only make one request per unique URI
	// We have 3 tails (.acl, .meta, .well-known/solid) so 3 requests
	if requestCount != 3 {
		t.Errorf("expected 3 requests, got %d", requestCount)
	}
}

// TestAncestorPolicyWalkSkipsFailedLoads tests that failed loads are skipped
func TestAncestorPolicyWalkSkipsFailedLoads(t *testing.T) {
	// Server that returns 404 for all requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoader()
	containerURIs := []string{
		fmt.Sprintf("%s/container1/", server.URL),
		fmt.Sprintf("%s/container2/", server.URL),
	}

	// Should not fail even though all loads fail
	loaded, err := AncestorPolicyWalk(loader, containerURIs)
	if err != nil {
		t.Fatalf("AncestorPolicyWalk should not error on failed loads, got %v", err)
	}

	// Should return empty list since all loads failed
	if len(loaded) != 0 {
		t.Errorf("expected 0 loaded sources, got %d", len(loaded))
	}
}

// TestCreateRequest tests request creation
func TestCreateRequest(t *testing.T) {
	loader := NewPolicyHTTPLoaderWithOptions(PolicyHTTPLoaderOptions{
		UserAgent: "Test-Agent/1.0",
		Accept:   "application/json",
	})

	parsedURL, _ := url.Parse("https://example.com/policy.ttl")
	req, err := loader.createRequest(context.Background(), parsedURL)
	if err != nil {
		t.Fatalf("createRequest failed: %v", err)
	}

	if req.Method != http.MethodGet {
		t.Errorf("expected method GET, got %q", req.Method)
	}
	if req.URL.String() != "https://example.com/policy.ttl" {
		t.Errorf("expected URL https://example.com/policy.ttl, got %q", req.URL.String())
	}
	if req.Header.Get("User-Agent") != "Test-Agent/1.0" {
		t.Errorf("expected User-Agent Test-Agent/1.0, got %q", req.Header.Get("User-Agent"))
	}
	if req.Header.Get("Accept") != "application/json" {
		t.Errorf("expected Accept application/json, got %q", req.Header.Get("Accept"))
	}
}

// TestReadBodyWithLimit tests body reading with size limit
func TestReadBodyWithLimit(t *testing.T) {
	loader := NewPolicyHTTPLoader()

	// Test within limit
	smallBody := io.NopCloser(bytes.NewReader([]byte("small content")))
	data, err := loader.readBodyWithLimit(smallBody, 100)
	if err != nil {
		t.Fatalf("readBodyWithLimit failed for small body: %v", err)
	}
	if string(data) != "small content" {
		t.Errorf("expected 'small content', got %q", string(data))
	}

	// Test at limit
	exactLimitBody := io.NopCloser(bytes.NewReader([]byte(strings.Repeat("x", 10))))
	data, err = loader.readBodyWithLimit(exactLimitBody, 10)
	if err != nil {
		t.Fatalf("readBodyWithLimit failed for exact limit: %v", err)
	}
	if len(data) != 10 {
		t.Errorf("expected 10 bytes, got %d", len(data))
	}

	// Test over limit
	largeBody := io.NopCloser(bytes.NewReader([]byte(strings.Repeat("x", 20))))
	_, err = loader.readBodyWithLimit(largeBody, 10)
	if err == nil {
		t.Fatal("expected error for body over limit, got nil")
	}
}

// TestContextCancellation tests that context cancellation is respected
func TestContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoaderWithOptions(PolicyHTTPLoaderOptions{
		Timeout: 10 * time.Millisecond, // Very short timeout
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	source := PolicySource{URI: server.URL}
	_, err := loader.LoadPolicySource(ctx, source)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
}

// TestRetryOnFailure tests that retries are attempted on failure
func TestRetryOnFailure(t *testing.T) {
	var attemptCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		if attemptCount < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<> a solid:Container .`)
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoaderWithOptions(PolicyHTTPLoaderOptions{
		MaxRetries:   2,
		RetryDelay:  1 * time.Millisecond,
		MaxBodySize: 1 << 20,
	})

	source := PolicySource{URI: server.URL}
	_, err := loader.LoadPolicySource(context.Background(), source)
	if err != nil {
		t.Fatalf("LoadPolicySource failed after retries: %v", err)
	}

	if attemptCount != 2 {
		t.Errorf("expected 2 attempts, got %d", attemptCount)
	}
}

// TestMaxRetriesExceeded tests that max retries are respected
func TestMaxRetriesExceeded(t *testing.T) {
	var attemptCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	loader := NewPolicyHTTPLoaderWithOptions(PolicyHTTPLoaderOptions{
		MaxRetries:   2,
		RetryDelay:  1 * time.Millisecond,
		MaxBodySize: 1 << 20,
	})

	source := PolicySource{URI: server.URL}
	_, err := loader.LoadPolicySource(context.Background(), source)
	if err == nil {
		t.Fatal("expected error after max retries exceeded, got nil")
	}

	// Initial attempt + 2 retries = 3 total
	if attemptCount != 3 {
		t.Errorf("expected 3 attempts, got %d", attemptCount)
	}
}

// TestAlreadyLoaded tests the alreadyLoaded helper function
func TestAlreadyLoaded(t *testing.T) {
	loaded := []LoadedPolicySource{
		{Source: PolicySource{URI: "https://example.com/policy1"}},
		{Source: PolicySource{URI: "https://example.com/policy2"}},
	}

	if !alreadyLoaded(loaded, "https://example.com/policy1") {
		t.Error("expected policy1 to be already loaded")
	}
	if !alreadyLoaded(loaded, "https://example.com/policy2") {
		t.Error("expected policy2 to be already loaded")
	}
	if alreadyLoaded(loaded, "https://example.com/policy3") {
		t.Error("expected policy3 to not be already loaded")
	}
	if alreadyLoaded(nil, "https://example.com/policy1") {
		t.Error("expected nil slice to return false")
	}
}
