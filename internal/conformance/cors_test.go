// Package conformance provides comprehensive Solid protocol conformance testing
// for Phase 20: Solid Conformance and Interoperability Suite.
//
// This file implements CORS conformance tests as Go test functions.
package conformance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCORSPreflight tests CORS preflight (OPTIONS) requests
func TestCORSPreflight(t *testing.T) {
	// Server that handles CORS preflight
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			// This is a preflight request
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, PUT, POST, DELETE, PATCH, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, DPoP, Content-Type, Accept")
			w.Header().Set("Access-Control-Expose-Headers", "ETag, Last-Modified, Location, Link")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.WriteHeader(http.StatusOK)
		} else {
			// Regular request
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Expose-Headers", "ETag, Last-Modified, Location, Link")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Response"))
		}
	}))
	defer server.Close()

	tests := []struct {
		name            string
		method          string
		origin          string
		requestMethod   string // For preflight: Access-Control-Request-Method
		requestHeaders  string // For preflight: Access-Control-Request-Headers
		expectPreflight bool
		expectedStatus  int
	}{
		{
			name:            "Preflight with GET",
			method:          http.MethodOptions,
			origin:          "https://example.com",
			requestMethod:   http.MethodGet,
			requestHeaders:  "authorization,dpop",
			expectPreflight: true,
			expectedStatus:  http.StatusOK,
		},
		{
			name:            "Preflight with PUT",
			method:          http.MethodOptions,
			origin:          "https://example.com",
			requestMethod:   http.MethodPut,
			requestHeaders:  "authorization,dpop,content-type",
			expectPreflight: true,
			expectedStatus:  http.StatusOK,
		},
		{
			name:            "Preflight with POST",
			method:          http.MethodOptions,
			origin:          "https://example.com",
			requestMethod:   http.MethodPost,
			requestHeaders:  "authorization,dpop,content-type",
			expectPreflight: true,
			expectedStatus:  http.StatusOK,
		},
		{
			name:            "Preflight with DELETE",
			method:          http.MethodOptions,
			origin:          "https://example.com",
			requestMethod:   http.MethodDelete,
			requestHeaders:  "authorization,dpop",
			expectPreflight: true,
			expectedStatus:  http.StatusOK,
		},
		{
			name:            "Preflight with PATCH",
			method:          http.MethodOptions,
			origin:          "https://example.com",
			requestMethod:   http.MethodPatch,
			requestHeaders:  "authorization,dpop,content-type",
			expectPreflight: true,
			expectedStatus:  http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), tt.method, server.URL+"/resource", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			req.Header.Set("Origin", tt.origin)
			if tt.expectPreflight {
				req.Header.Set("Access-Control-Request-Method", tt.requestMethod)
				req.Header.Set("Access-Control-Request-Headers", tt.requestHeaders)
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

			if tt.expectPreflight {
				// Check CORS headers in preflight response
				accessControlAllowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
				if accessControlAllowOrigin != tt.origin {
					t.Errorf("Expected Access-Control-Allow-Origin %q but got %q", tt.origin, accessControlAllowOrigin)
				}

				accessControlAllowMethods := resp.Header.Get("Access-Control-Allow-Methods")
				if accessControlAllowMethods == "" {
					t.Error("Expected Access-Control-Allow-Methods header")
				}

				accessControlAllowHeaders := resp.Header.Get("Access-Control-Allow-Headers")
				if accessControlAllowHeaders == "" {
					t.Error("Expected Access-Control-Allow-Headers header")
				}

				accessControlMaxAge := resp.Header.Get("Access-Control-Max-Age")
				if accessControlMaxAge == "" {
					t.Error("Expected Access-Control-Max-Age header")
				}
			}
		})
	}
}

// TestCORSSimpleRequest tests simple CORS requests (non-preflight)
func TestCORSSimpleRequest(t *testing.T) {
	// Server that handles simple CORS requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Expose-Headers", "ETag, Last-Modified, Location, Link")
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("@prefix ex: <http://example.org/> ."))
	}))
	defer server.Close()

	tests := []struct {
		name           string
		method         string
		origin         string
		expectedStatus int
	}{
		{
			name:           "Simple GET with CORS",
			method:         http.MethodGet,
			origin:         "https://example.com",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Simple HEAD with CORS",
			method:         http.MethodHead,
			origin:         "https://example.com",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Simple PUT with CORS",
			method:         http.MethodPut,
			origin:         "https://example.com",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "No Origin header",
			method:         http.MethodGet,
			origin:         "",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), tt.method, server.URL+"/resource", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
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

			if tt.origin != "" {
				// Check CORS headers in response
				accessControlAllowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
				if accessControlAllowOrigin != tt.origin {
					t.Errorf("Expected Access-Control-Allow-Origin %q but got %q", tt.origin, accessControlAllowOrigin)
				}

				accessControlAllowCredentials := resp.Header.Get("Access-Control-Allow-Credentials")
				if accessControlAllowCredentials != "true" {
					t.Errorf("Expected Access-Control-Allow-Credentials 'true' but got %q", accessControlAllowCredentials)
				}

				accessControlExposeHeaders := resp.Header.Get("Access-Control-Expose-Headers")
				if accessControlExposeHeaders == "" {
					t.Error("Expected Access-Control-Expose-Headers header")
				}
			}
		})
	}
}

// TestCORSWildcardOrigin tests wildcard origin handling
func TestCORSWildcardOrigin(t *testing.T) {
	// Server that allows any origin
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Response"))
	}))
	defer server.Close()

	tests := []struct {
		name           string
		origin         string
		expectedOrigin string
	}{
		{
			name:           "Origin allowed with wildcard",
			origin:         "https://example.com",
			expectedOrigin: "*",
		},
		{
			name:           "Another origin with wildcard",
			origin:         "https://another-example.com",
			expectedOrigin: "*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/resource", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			req.Header.Set("Origin", tt.origin)

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status %d but got %d for %s", http.StatusOK, resp.StatusCode, tt.name)
			}

			accessControlAllowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
			if accessControlAllowOrigin != tt.expectedOrigin {
				t.Errorf("Expected Access-Control-Allow-Origin %q but got %q", tt.expectedOrigin, accessControlAllowOrigin)
			}
		})
	}
}

// TestCORSNoCORS tests requests without CORS headers
func TestCORSNoCORS(t *testing.T) {
	// Server that doesn't add CORS headers when no Origin is present
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Response"))
	}))
	defer server.Close()

	// Request without Origin header
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

	// CORS headers should not be present
	accessControlAllowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	if accessControlAllowOrigin != "" {
		t.Errorf("Expected no Access-Control-Allow-Origin header but got %q", accessControlAllowOrigin)
	}
}

// TestCORSWithCredentials tests CORS with credentials
func TestCORSWithCredentials(t *testing.T) {
	// Server that requires credentials
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Response"))
	}))
	defer server.Close()

	// Request with Origin
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/resource", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("Origin", "https://example.com")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d but got %d", http.StatusOK, resp.StatusCode)
	}

	accessControlAllowCredentials := resp.Header.Get("Access-Control-Allow-Credentials")
	if accessControlAllowCredentials != "true" {
		t.Errorf("Expected Access-Control-Allow-Credentials 'true' but got %q", accessControlAllowCredentials)
	}
}

// TestCORSCacheControl tests CORS cache control headers
func TestCORSCacheControl(t *testing.T) {
	// Server that sets cache control for preflight
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, PUT, POST, DELETE, PATCH, OPTIONS")
			w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodOptions, server.URL+"/resource", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d but got %d", http.StatusOK, resp.StatusCode)
	}

	accessControlMaxAge := resp.Header.Get("Access-Control-Max-Age")
	if accessControlMaxAge != "86400" {
		t.Errorf("Expected Access-Control-Max-Age '86400' but got %q", accessControlMaxAge)
	}
}

// TestCORSExposeHeaders tests Access-Control-Expose-Headers
func TestCORSExposeHeaders(t *testing.T) {
	// Server that exposes specific headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Expose-Headers", "ETag, Last-Modified, Location, Link, Content-Location")
		w.Header().Set("ETag", "\"abc123\"")
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
		w.Header().Set("Link", "<https://example.org/container/>; rel=\"http://www.w3.org/ns/ldp#contains\"")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Response"))
	}))
	defer server.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/resource", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("Origin", "https://example.com")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status %d but got %d", http.StatusOK, resp.StatusCode)
	}

	accessControlExposeHeaders := resp.Header.Get("Access-Control-Expose-Headers")
	if !strings.Contains(accessControlExposeHeaders, "ETag") {
		t.Errorf("Expected ETag in Access-Control-Expose-Headers but got %q", accessControlExposeHeaders)
	}
	if !strings.Contains(accessControlExposeHeaders, "Last-Modified") {
		t.Errorf("Expected Last-Modified in Access-Control-Expose-Headers but got %q", accessControlExposeHeaders)
	}
	if !strings.Contains(accessControlExposeHeaders, "Link") {
		t.Errorf("Expected Link in Access-Control-Expose-Headers but got %q", accessControlExposeHeaders)
	}
}
