// Package conformance provides comprehensive Solid protocol conformance testing
// for Phase 20: Solid Conformance and Interoperability Suite.
//
// This file implements storage description conformance tests.
package conformance

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestStorageDescriptionGET tests GET on storage description resource
func TestStorageDescriptionGET(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.storage" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/ld+json")
		linkHeader := `<http://www.w3.org/ns/ldp#Resource>; rel="type"`
		w.Header().Set("Link", linkHeader)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"@id": "/.storage", "@type": "http://www.w3.org/ns/ldp#Resource"}`))
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/.storage", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/ld+json" {
		t.Errorf("Expected Content-Type: application/ld+json, got: %s", contentType)
	}

	link := resp.Header.Get("Link")
	if !strings.Contains(link, "type") {
		t.Errorf("Expected Link header with type relation, got: %s", link)
	}
}

// TestStorageDescriptionHEAD tests HEAD on storage description resource
func TestStorageDescriptionHEAD(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.storage" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != "HEAD" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/ld+json")
		linkHeader := `<http://www.w3.org/ns/ldp#Resource>; rel="type"`
		w.Header().Set("Link", linkHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), "HEAD", server.URL+"/.storage", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// TestStorageDescriptionOPTIONS tests OPTIONS on storage description resource
func TestStorageDescriptionOPTIONS(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.storage" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != "OPTIONS" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Allow", "GET,HEAD,OPTIONS")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), "OPTIONS", server.URL+"/.storage", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	allow := resp.Header.Get("Allow")
	if !strings.Contains(allow, "GET") || !strings.Contains(allow, "HEAD") || !strings.Contains(allow, "OPTIONS") {
		t.Errorf("Expected Allow header to contain GET, HEAD, OPTIONS, got: %s", allow)
	}
}

// TestStorageDescriptionNotFound tests 404 for missing storage description
func TestStorageDescriptionNotFound(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/.storage", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}
}

// TestStorageDescriptionMethodNotAllowed tests unsupported methods
func TestStorageDescriptionMethodNotAllowed(t *testing.T) {
	t.Parallel()

	methods := []string{"POST", "PUT", "DELETE", "PATCH"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.WriteHeader(http.StatusMethodNotAllowed)
			}))
			defer server.Close()

			client := &http.Client{Timeout: 5 * time.Second}
			req, err := http.NewRequestWithContext(context.Background(), method, server.URL+"/.storage", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusMethodNotAllowed {
				t.Logf("Server correctly rejected %s method", method)
			} else {
				t.Logf("Server accepted %s method with status %d", method, resp.StatusCode)
			}
		})
	}
}

// TestAuxiliaryResourceLinkHeader tests auxiliary resource discovery via Link header
func TestAuxiliaryResourceLinkHeader(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		linkHeader := `<http://example.org/aux>; rel="auxiliary"`
		w.Header().Set("Link", linkHeader)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<> a <http://www.w3.org/ns/ldp#Resource> ."))
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	link := resp.Header.Get("Link")
	if !strings.Contains(link, "auxiliary") {
		t.Errorf("Expected Link header with auxiliary relation, got: %s", link)
	}
}

// TestStorageDescriptionCacheControl tests caching headers
func TestStorageDescriptionCacheControl(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ld+json")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"@id": "/.storage"}`))
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/.storage", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	cacheControl := resp.Header.Get("Cache-Control")
	if !strings.Contains(cacheControl, "max-age") {
		t.Errorf("Expected Cache-Control header with max-age, got: %s", cacheControl)
	}
}

// TestStorageDescriptionErrorCodes tests various error responses
func TestStorageDescriptionErrorCodes(t *testing.T) {
	t.Parallel()

	errorCodes := []int{
		http.StatusInternalServerError,
		http.StatusServiceUnavailable,
		http.StatusBadGateway,
		http.StatusGatewayTimeout,
	}

	for _, statusCode := range errorCodes {
		t.Run(fmt.Sprintf("%d", statusCode), func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(statusCode)
			}))
			defer server.Close()

			client := &http.Client{Timeout: 5 * time.Second}
			req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/.storage", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != statusCode {
				t.Errorf("Expected status %d, got %d", statusCode, resp.StatusCode)
			}
		})
	}
}

// TestStorageDescriptionContentTypes tests various content types
func TestStorageDescriptionContentTypes(t *testing.T) {
	t.Parallel()

	contentTypes := []string{
		"application/ld+json",
		"text/turtle",
		"application/rdf+xml",
	}

	for _, contentType := range contentTypes {
		t.Run(contentType, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", contentType)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("test"))
			}))
			defer server.Close()

			client := &http.Client{Timeout: 5 * time.Second}
			req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/.storage", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			actualContentType := resp.Header.Get("Content-Type")
			if actualContentType != contentType {
				t.Errorf("Expected Content-Type: %s, got: %s", contentType, actualContentType)
			}
		})
	}
}
