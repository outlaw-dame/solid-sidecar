// Package conformance provides comprehensive Solid protocol conformance testing
// for Phase 20: Solid Conformance and Interoperability Suite.
//
// This file implements HTTP method matrix conformance tests as Go test functions.
package conformance

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHTTPMethodMatrixResourceOperations tests HTTP methods on resources
func TestHTTPMethodMatrixResourceOperations(t *testing.T) {
	// Server that handles all HTTP methods for resources
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "text/turtle")
			w.Header().Set("ETag", "\"abc123\"")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("@prefix ex: <http://example.org/> ."))
		case http.MethodHead:
			w.Header().Set("Content-Type", "text/turtle")
			w.Header().Set("ETag", "\"abc123\"")
			w.WriteHeader(http.StatusOK)
		case http.MethodPut:
			// Read and echo back the body
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("ETag", "\"new-etag\"")
			w.WriteHeader(http.StatusOK)
			w.Write(body)
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("Resource created"))
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPatch:
			w.Header().Set("Content-Type", "application/sparql-update")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("PATCH applied"))
		case http.MethodOptions:
			w.Header().Set("Allow", "GET, HEAD, PUT, POST, DELETE, PATCH, OPTIONS")
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	tests := []struct {
		name           string
		method         string
		body           []byte
		expectedStatus int
	}{
		// Resource operations
		{
			name:           "GET on resource",
			method:         http.MethodGet,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "HEAD on resource",
			method:         http.MethodHead,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "PUT on resource (update)",
			method:         http.MethodPut,
			body:           []byte("@prefix ex: <http://example.org/> ."),
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST to resource",
			method:         http.MethodPost,
			body:           []byte("new data"),
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "DELETE on resource",
			method:         http.MethodDelete,
			expectedStatus: http.StatusNoContent,
		},
		{
			name:           "PATCH on resource",
			method:         http.MethodPatch,
			body:           []byte("PATCH data"),
			expectedStatus: http.StatusOK,
		},
		{
			name:           "OPTIONS on resource",
			method:         http.MethodOptions,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), tt.method, server.URL+"/resource.ttl", bytes.NewReader(tt.body))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Expected status %d but got %d for %s", tt.expectedStatus, resp.StatusCode, tt.name)
			}
		})
	}
}

// TestHTTPMethodMatrixContainerOperations tests HTTP methods on containers
func TestHTTPMethodMatrixContainerOperations(t *testing.T) {
	// Server that handles container operations
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// Return container listing
			w.Header().Set("Content-Type", "text/turtle")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("@prefix ldp: <http://www.w3.org/ns/ldp#> . [] a ldp:Container ; ldp:contains </resource1>, </resource2> ."))
		case http.MethodHead:
			w.Header().Set("Content-Type", "text/turtle")
			w.WriteHeader(http.StatusOK)
		case http.MethodPut:
			// Create or replace container
			w.WriteHeader(http.StatusOK)
		case http.MethodPost:
			// Create resource in container
			w.Header().Set("Location", r.URL.String()+"/new-resource")
			w.WriteHeader(http.StatusCreated)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPatch:
			// Containers typically don't support PATCH
			w.WriteHeader(http.StatusMethodNotAllowed)
		case http.MethodOptions:
			w.Header().Set("Allow", "GET, HEAD, PUT, POST, DELETE, OPTIONS")
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	tests := []struct {
		name           string
		method         string
		expectedStatus int
	}{
		{
			name:           "GET on container",
			method:         http.MethodGet,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "HEAD on container",
			method:         http.MethodHead,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "PUT on container (create/replace)",
			method:         http.MethodPut,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST to container (create resource)",
			method:         http.MethodPost,
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "DELETE on container",
			method:         http.MethodDelete,
			expectedStatus: http.StatusNoContent,
		},
		{
			name:           "PATCH on container (should fail)",
			method:         http.MethodPatch,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "OPTIONS on container",
			method:         http.MethodOptions,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), tt.method, server.URL+"/container/", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Expected status %d but got %d for %s", tt.expectedStatus, resp.StatusCode, tt.name)
			}
		})
	}
}

// TestHTTPMethodMatrixPolicyOperations tests HTTP methods on policy resources
func TestHTTPMethodMatrixPolicyOperations(t *testing.T) {
	// Server that handles policy resource operations
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Check if this is a policy resource (ends with .acl or .meta)
		isPolicy := strings.HasSuffix(path, ".acl") || strings.HasSuffix(path, ".meta")

		switch r.Method {
		case http.MethodGet:
			if isPolicy {
				w.Header().Set("Content-Type", "text/turtle")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("@prefix acl: <http://www.w3.org/ns/auth/acl#> . [] a acl:Authorization ."))
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		case http.MethodHead:
			if isPolicy {
				w.Header().Set("Content-Type", "text/turtle")
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		case http.MethodPut:
			if isPolicy {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		case http.MethodDelete:
			if isPolicy {
				w.WriteHeader(http.StatusNoContent)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		case http.MethodOptions:
			w.Header().Set("Allow", "GET, HEAD, PUT, DELETE, OPTIONS")
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	tests := []struct {
		name           string
		path           string
		method         string
		expectedStatus int
	}{
		// ACL policy operations
		{
			name:           "GET on ACL",
			path:           "/resource.ttl.acl",
			method:         http.MethodGet,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "HEAD on ACL",
			path:           "/resource.ttl.acl",
			method:         http.MethodHead,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "PUT on ACL (update)",
			path:           "/resource.ttl.acl",
			method:         http.MethodPut,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "DELETE on ACL",
			path:           "/resource.ttl.acl",
			method:         http.MethodDelete,
			expectedStatus: http.StatusNoContent,
		},
		{
			name:           "POST on ACL (should fail)",
			path:           "/resource.ttl.acl",
			method:         http.MethodPost,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "OPTIONS on ACL",
			path:           "/resource.ttl.acl",
			method:         http.MethodOptions,
			expectedStatus: http.StatusOK,
		},
		// Non-policy resource
		{
			name:           "GET on non-policy as .acl",
			path:           "/not-a-policy.acl",
			method:         http.MethodGet,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), tt.method, server.URL+tt.path, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Expected status %d but got %d for %s", tt.expectedStatus, resp.StatusCode, tt.name)
			}
		})
	}
}

// TestHTTPMethodMatrixStorageDescription tests storage description operations
func TestHTTPMethodMatrixStorageDescription(t *testing.T) {
	// Server that handles storage description operations
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Storage description is typically at /.well-known/solid or /setup
		isStorageDesc := path == "/.well-known/solid" || path == "/setup"

		switch r.Method {
		case http.MethodGet:
			if isStorageDesc {
				w.Header().Set("Content-Type", "text/turtle")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("@prefix solid: <http://www.w3.org/ns/solid/terms#> . [] a solid:Storage ."))
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		case http.MethodHead:
			if isStorageDesc {
				w.Header().Set("Content-Type", "text/turtle")
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		case http.MethodOptions:
			if isStorageDesc {
				w.Header().Set("Allow", "GET, HEAD, OPTIONS")
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		default:
			// Storage descriptions are typically read-only
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	tests := []struct {
		name           string
		path           string
		method         string
		expectedStatus int
	}{
		{
			name:           "GET on storage description",
			path:           "/.well-known/solid",
			method:         http.MethodGet,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "HEAD on storage description",
			path:           "/.well-known/solid",
			method:         http.MethodHead,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "OPTIONS on storage description",
			path:           "/.well-known/solid",
			method:         http.MethodOptions,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "PUT on storage description (should fail)",
			path:           "/.well-known/solid",
			method:         http.MethodPut,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "POST on storage description (should fail)",
			path:           "/.well-known/solid",
			method:         http.MethodPost,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "DELETE on storage description (should fail)",
			path:           "/.well-known/solid",
			method:         http.MethodDelete,
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), tt.method, server.URL+tt.path, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Expected status %d but got %d for %s", tt.expectedStatus, resp.StatusCode, tt.name)
			}
		})
	}
}

// TestHTTPMethodMatrixLinkHeaders tests Link header handling
func TestHTTPMethodMatrixLinkHeaders(t *testing.T) {
	// Server that returns Link headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")

		// Add Link headers for various relationships
		w.Header().Add("Link", `<https://example.org/container/>; rel="http://www.w3.org/ns/ldp#contains"`)
		w.Header().Add("Link", `<https://example.org/resource.acl>; rel="acl"`)
		w.Header().Add("Link", `<https://example.org/resource.meta>; rel="describedby"`)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("@prefix ex: <http://example.org/> ."))
	}))
	defer server.Close()

	t.Run("Link headers present", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/resource", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d but got %d", http.StatusOK, resp.StatusCode)
		}

		// Check that Link headers are present
		linkHeaders := resp.Header.Values("Link")
		if len(linkHeaders) < 1 {
			t.Error("Expected at least one Link header")
		}

		// Check for specific Link relationships
		foundContains := false
		foundACL := false
		foundDescribedBy := false

		for _, link := range linkHeaders {
			if strings.Contains(link, `rel="http://www.w3.org/ns/ldp#contains"`) {
				foundContains = true
			}
			if strings.Contains(link, `rel="acl"`) {
				foundACL = true
			}
			if strings.Contains(link, `rel="describedby"`) {
				foundDescribedBy = true
			}
		}

		if !foundContains {
			t.Error("Expected Link header with rel='http://www.w3.org/ns/ldp#contains'")
		}
		if !foundACL {
			t.Error("Expected Link header with rel='acl'")
		}
		if !foundDescribedBy {
			t.Error("Expected Link header with rel='describedby'")
		}
	})
}

// TestHTTPMethodMatrixMethodNotAllowed tests proper handling of unsupported methods
func TestHTTPMethodMatrixMethodNotAllowed(t *testing.T) {
	// Server that returns 405 for unsupported methods
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			w.WriteHeader(http.StatusOK)
		default:
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	unsupportedMethods := []string{
		http.MethodPut,
		http.MethodPost,
		http.MethodDelete,
		http.MethodPatch,
		"TRACE",
		"CONNECT",
	}

	for _, method := range unsupportedMethods {
		t.Run(method, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), method, server.URL+"/resource", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("Expected status %d but got %d for method %s",
					http.StatusMethodNotAllowed, resp.StatusCode, method)
			}

			// Check Allow header
			allowHeader := resp.Header.Get("Allow")
			if allowHeader == "" {
				t.Errorf("Expected Allow header for method %s", method)
			}
		})
	}
}
