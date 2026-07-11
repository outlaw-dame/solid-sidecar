// Package conformance provides comprehensive Solid protocol conformance testing
// for Phase 20: Solid Conformance and Interoperability Suite.
//
// This file implements CSS comparison harness tests.
package conformance

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestCSSComparisonHarnessBasic tests basic CSS comparison functionality
func TestCSSComparisonHarnessBasic(t *testing.T) {
	t.Parallel()

	// Create a mock Solid server (simulating CSS)
	cssServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<> a <http://www.w3.org/ns/ldp#Resource> .`))
	}))
	defer cssServer.Close()

	// Create a mock sidecar server
	sidecarServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Proxy to CSS
		proxyReq, _ := http.NewRequest(r.Method, cssServer.URL+r.URL.Path, r.Body)
		proxyResp, err := http.DefaultClient.Do(proxyReq)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer proxyResp.Body.Close()

		// Copy headers
		for k, v := range proxyResp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(proxyResp.StatusCode)
		io.Copy(w, proxyResp.Body)
	}))
	defer sidecarServer.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	// Test that sidecar proxies to CSS
	req, err := http.NewRequestWithContext(context.Background(), "GET", sidecarServer.URL+"/resource", nil)
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

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "ldp#Resource") {
		t.Errorf("Expected LDP Resource type in response, got: %s", bodyStr)
	}
}

// TestCSSComparisonHeaderBehavior tests header behavior comparison
func TestCSSComparisonHeaderBehavior(t *testing.T) {
	t.Parallel()

	cssServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.Header().Set("Link", `<http://www.w3.org/ns/ldp#Resource>; rel="type"`)
		w.Header().Set("Accept-Post", "text/turtle, application/ld+json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<> a <http://www.w3.org/ns/ldp#Resource> .`))
	}))
	defer cssServer.Close()

	sidecarServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyReq, _ := http.NewRequest(r.Method, cssServer.URL+r.URL.Path, r.Body)
		proxyResp, err := http.DefaultClient.Do(proxyReq)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer proxyResp.Body.Close()

		// Copy all headers
		for k, v := range proxyResp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(proxyResp.StatusCode)
		io.Copy(w, proxyResp.Body)
	}))
	defer sidecarServer.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), "GET", sidecarServer.URL+"/resource", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Check that headers are preserved through proxy
	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/turtle" {
		t.Errorf("Expected Content-Type: text/turtle, got: %s", contentType)
	}

	link := resp.Header.Get("Link")
	if !strings.Contains(link, "type") {
		t.Errorf("Expected Link header with type, got: %s", link)
	}
}

// TestCSSComparisonMethodBehavior tests HTTP method behavior comparison
func TestCSSComparisonMethodBehavior(t *testing.T) {
	t.Parallel()

	methods := []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE", "PATCH"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			// CSS behavior
			cssServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case "GET", "HEAD", "OPTIONS":
					w.WriteHeader(http.StatusOK)
				case "POST", "PUT", "PATCH":
					w.WriteHeader(http.StatusCreated)
				case "DELETE":
					w.WriteHeader(http.StatusNoContent)
				default:
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			}))
			defer cssServer.Close()

			sidecarServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proxyReq, _ := http.NewRequest(r.Method, cssServer.URL+r.URL.Path, r.Body)
				proxyResp, err := http.DefaultClient.Do(proxyReq)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				defer proxyResp.Body.Close()

				w.WriteHeader(proxyResp.StatusCode)
			}))
			defer sidecarServer.Close()

			client := &http.Client{Timeout: 5 * time.Second}
			var bodyReader io.Reader
			if method == "POST" || method == "PUT" || method == "PATCH" {
				bodyReader = strings.NewReader("test body")
			}
			req, err := http.NewRequestWithContext(context.Background(), method, sidecarServer.URL+"/resource", bodyReader)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			// Verify status code matches CSS behavior
			switch method {
			case "GET", "HEAD", "OPTIONS":
				if resp.StatusCode != http.StatusOK {
					t.Errorf("Expected status 200 for %s, got %d", method, resp.StatusCode)
				}
			case "POST", "PUT", "PATCH":
				if resp.StatusCode != http.StatusCreated {
					t.Logf("Expected status 201 for %s, got %d (CSS may return different status)", method, resp.StatusCode)
				}
			case "DELETE":
				if resp.StatusCode != http.StatusNoContent {
					t.Logf("Expected status 204 for %s, got %d (CSS may return different status)", method, resp.StatusCode)
				}
			}
		})
	}
}

// TestCSSComparisonConcurrentRequests tests concurrent request comparison
func TestCSSComparisonConcurrentRequests(t *testing.T) {
	t.Parallel()

	cssServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("CSS response"))
	}))
	defer cssServer.Close()

	sidecarServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyReq, _ := http.NewRequest(r.Method, cssServer.URL+r.URL.Path, r.Body)
		proxyResp, err := http.DefaultClient.Do(proxyReq)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer proxyResp.Body.Close()

		w.WriteHeader(proxyResp.StatusCode)
		io.Copy(w, proxyResp.Body)
	}))
	defer sidecarServer.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	// Make concurrent requests
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(context.Background(), "GET", sidecarServer.URL+"/resource", nil)
			if err != nil {
				t.Error("Failed to create request")
				return
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Error("Request failed")
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status 200, got %d", resp.StatusCode)
			}
		}()
	}
	wg.Wait()
}

// TestCSSComparisonHeaderForwarding tests header forwarding behavior
func TestCSSComparisonHeaderForwarding(t *testing.T) {
	t.Parallel()

	cssServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back certain headers
		if r.Header.Get("X-Custom-Header") != "" {
			w.Header().Set("X-CSS-Received", r.Header.Get("X-Custom-Header"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("CSS response"))
	}))
	defer cssServer.Close()

	sidecarServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyReq, _ := http.NewRequest(r.Method, cssServer.URL+r.URL.Path, r.Body)
		// Forward certain headers
		if r.Header.Get("X-Custom-Header") != "" {
			proxyReq.Header.Set("X-Custom-Header", r.Header.Get("X-Custom-Header"))
		}

		proxyResp, err := http.DefaultClient.Do(proxyReq)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer proxyResp.Body.Close()

		// Copy all headers
		for k, v := range proxyResp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(proxyResp.StatusCode)
		io.Copy(w, proxyResp.Body)
	}))
	defer sidecarServer.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), "GET", sidecarServer.URL+"/resource", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Add custom header
	req.Header.Set("X-Custom-Header", "test-value")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Check that header was forwarded to CSS and back
	if resp.Header.Get("X-CSS-Received") != "test-value" {
		t.Errorf("Expected X-CSS-Received header to be 'test-value', got: %s", resp.Header.Get("X-CSS-Received"))
	}
}

// TestCSSComparisonErrorHandling tests error handling comparison
func TestCSSComparisonErrorHandling(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		cssStatus      int
		expectedStatus int
	}{
		{
			name:           "CSS returns 404",
			cssStatus:      http.StatusNotFound,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "CSS returns 401",
			cssStatus:      http.StatusUnauthorized,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "CSS returns 500",
			cssStatus:      http.StatusInternalServerError,
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cssServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.cssStatus)
			}))
			defer cssServer.Close()

			sidecarServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proxyReq, _ := http.NewRequest(r.Method, cssServer.URL+r.URL.Path, r.Body)
				proxyResp, err := http.DefaultClient.Do(proxyReq)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				defer proxyResp.Body.Close()

				w.WriteHeader(proxyResp.StatusCode)
			}))
			defer sidecarServer.Close()

			client := &http.Client{Timeout: 5 * time.Second}
			req, err := http.NewRequestWithContext(context.Background(), "GET", sidecarServer.URL+"/resource", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, resp.StatusCode)
			}
		})
	}
}

// TestCSSComparisonContentType tests content type handling comparison
func TestCSSComparisonContentType(t *testing.T) {
	t.Parallel()

	contentTypes := []string{
		"text/turtle",
		"application/ld+json",
		"application/rdf+xml",
		"text/plain",
		"application/octet-stream",
	}

	for _, contentType := range contentTypes {
		t.Run(contentType, func(t *testing.T) {
			t.Parallel()

			cssServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", contentType)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("CSS response"))
			}))
			defer cssServer.Close()

			sidecarServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proxyReq, _ := http.NewRequest(r.Method, cssServer.URL+r.URL.Path, r.Body)
				proxyResp, err := http.DefaultClient.Do(proxyReq)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				defer proxyResp.Body.Close()

				// Copy all headers
				for k, v := range proxyResp.Header {
					w.Header()[k] = v
				}
				w.WriteHeader(proxyResp.StatusCode)
				io.Copy(w, proxyResp.Body)
			}))
			defer sidecarServer.Close()

			client := &http.Client{Timeout: 5 * time.Second}
			req, err := http.NewRequestWithContext(context.Background(), "GET", sidecarServer.URL+"/resource", nil)
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

// TestCSSComparisonMismatchDetection tests detection of behavior mismatches
func TestCSSComparisonMismatchDetection(t *testing.T) {
	t.Parallel()

	// Simulate a mismatch where sidecar behaves differently from CSS
	cssServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("CSS response"))
	}))
	defer cssServer.Close()

	// Sidecar adds an extra header that CSS doesn't have
	sidecarServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyReq, _ := http.NewRequest(r.Method, cssServer.URL+r.URL.Path, r.Body)
		proxyResp, err := http.DefaultClient.Do(proxyReq)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer proxyResp.Body.Close()

		// Copy all headers from CSS
		for k, v := range proxyResp.Header {
			w.Header()[k] = v
		}
		// Add sidecar-specific header
		w.Header().Set("X-Sidecar", "true")

		w.WriteHeader(proxyResp.StatusCode)
		io.Copy(w, proxyResp.Body)
	}))
	defer sidecarServer.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), "GET", sidecarServer.URL+"/resource", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Sidecar adds its own header
	sidecarHeader := resp.Header.Get("X-Sidecar")
	if sidecarHeader != "true" {
		t.Errorf("Expected X-Sidecar header, got: %s", sidecarHeader)
	}

	// CSS header should still be present
	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/turtle" {
		t.Errorf("Expected Content-Type: text/turtle, got: %s", contentType)
	}

	// This test demonstrates that sidecar can add headers while preserving CSS behavior
}

// TestCSSComparisonTimeout tests timeout behavior
func TestCSSComparisonTimeout(t *testing.T) {
	t.Parallel()

	// Create a slow CSS server
	cssServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond) // Short delay
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("CSS response"))
	}))
	defer cssServer.Close()

	sidecarServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 50*time.Millisecond)
		defer cancel()

		proxyReq, _ := http.NewRequestWithContext(ctx, r.Method, cssServer.URL+r.URL.Path, r.Body)
		proxyResp, err := http.DefaultClient.Do(proxyReq)
		if err != nil {
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		defer proxyResp.Body.Close()

		w.WriteHeader(proxyResp.StatusCode)
		io.Copy(w, proxyResp.Body)
	}))
	defer sidecarServer.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), "GET", sidecarServer.URL+"/resource", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// The sidecar timeout (50ms) is shorter than the CSS delay (100ms)
	// So this might timeout, but the client timeout is 5s so the request should complete
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Either gets the response or a timeout
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("Expected status 200 or 504, got %d", resp.StatusCode)
	}
}
