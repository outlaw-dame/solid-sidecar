package safety

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCORSPreflight tests that OPTIONS requests with CORS preflight headers
// are handled correctly.
func TestCORSPreflight(t *testing.T) {
	policy := NewOriginPolicy([]string{"https://app.example"})
	handler := policy.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/resource", nil)
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Access-Control-Request-Method", "PUT")
	req.Header.Set("Access-Control-Request-Headers", "authorization, content-type")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should return 204 for preflight
	if rr.Code != http.StatusNoContent {
		t.Errorf("expected status 204 for preflight, got %d", rr.Code)
	}

	// Check CORS headers
	if rr.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Errorf("expected Access-Control-Allow-Origin header")
	}

	if rr.Header().Get("Access-Control-Allow-Methods") != "GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE" {
		t.Errorf("expected Access-Control-Allow-Methods header with all Solid methods")
	}

	if rr.Header().Get("Access-Control-Allow-Headers") != "Authorization, Content-Type, DPoP, Link, Prefer, Slug, If-Match, If-None-Match" {
		t.Errorf("expected Access-Control-Allow-Headers header with Solid headers")
	}

	if rr.Header().Get("Access-Control-Max-Age") != "600" {
		t.Errorf("expected Access-Control-Max-Age header")
	}

	// Body should be empty for preflight
	if rr.Body.Len() != 0 {
		t.Errorf("expected empty body for preflight, got %d bytes", rr.Body.Len())
	}
}

// TestCORSSimpleRequest tests that simple (non-preflight) CORS requests
// work correctly.
func TestCORSSimpleRequest(t *testing.T) {
	policy := NewOriginPolicy([]string{"https://app.example"})
	handler := policy.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response"))
	}))

	tests := []struct {
		name   string
		method string
	}{
		{"GET", http.MethodGet},
		{"POST", http.MethodPost},
		{"PUT", http.MethodPut},
		{"PATCH", http.MethodPatch},
		{"DELETE", http.MethodDelete},
		{"HEAD", http.MethodHead},
		{"OPTIONS", http.MethodOptions},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/resource", nil)
			req.Header.Set("Origin", "https://app.example")

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", rr.Code)
			}

			if rr.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
				t.Errorf("expected Access-Control-Allow-Origin header")
			}

			if rr.Header().Get("Vary") != "Origin" {
				t.Errorf("expected Vary: Origin header")
			}
		})
	}
}

// TestCORSWithoutOrigin tests that requests without Origin header pass through.
func TestCORSWithoutOrigin(t *testing.T) {
	policy := NewOriginPolicy([]string{"https://app.example"})
	handler := policy.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	// No Origin header

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Should not have CORS headers when no Origin
	if rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("expected no Access-Control-Allow-Origin header when no Origin")
	}
}

// TestCORSMultipleOrigins tests that multiple allowed origins work correctly.
func TestCORSMultipleOrigins(t *testing.T) {
	origins := []string{
		"https://app1.example",
		"https://app2.example",
		"https://app3.example",
	}
	policy := NewOriginPolicy(origins)
	handler := policy.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, origin := range origins {
		t.Run(origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/resource", nil)
			req.Header.Set("Origin", origin)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", rr.Code)
			}

			if rr.Header().Get("Access-Control-Allow-Origin") != origin {
				t.Errorf("expected Access-Control-Allow-Origin = %q, got %q", origin, rr.Header().Get("Access-Control-Allow-Origin"))
			}
		})
	}
}

// TestCORSRejectsMalformedOrigin tests that malformed Origin headers are rejected.
func TestCORSRejectsMalformedOrigin(t *testing.T) {
	policy := NewOriginPolicy([]string{"https://app.example"})
	handler := policy.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	malformedOrigins := []string{
		"",                      // Empty
		"not-a-valid-origin",    // Not a valid origin
		"http://localhost:8080", // Not in allowed list
		"https://evil.com",      // Not in allowed list
		"null",                  // null origin
	}

	for _, origin := range malformedOrigins {
		t.Run(origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/resource", nil)
			req.Header.Set("Origin", origin)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if origin == "" {
				// Empty origin should pass through
				if rr.Code != http.StatusOK {
					t.Errorf("expected status 200 for empty origin, got %d", rr.Code)
				}
			} else {
				// Other origins should be rejected
				if rr.Code != http.StatusForbidden {
					t.Errorf("expected status 403 for origin %q, got %d", origin, rr.Code)
				}
			}
		})
	}
}

// TestCORSWildcardOrigin tests the behavior with wildcard origin.
// Note: The current implementation doesn't support wildcard, but this test
// documents the expected behavior.
func TestCORSNoAllowedOrigins(t *testing.T) {
	// Empty allowed origins list means CORS is disabled
	policy := NewOriginPolicy([]string{})
	handler := policy.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Origin", "https://app.example")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should pass through without CORS headers
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	if rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("expected no CORS headers when no origins are configured")
	}
}

// TestCORSIntegrationWithSafetyHeaders tests that CORS works correctly
// with the SecurityHeaders middleware.
func TestCORSIntegrationWithSafetyHeaders(t *testing.T) {
	policy := NewOriginPolicy([]string{"https://app.example"})
	handler := SecurityHeaders(policy.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Origin", "https://app.example")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Check both CORS and security headers
	if rr.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Errorf("expected CORS header")
	}

	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("expected X-Content-Type-Options header")
	}
}
